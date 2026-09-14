package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http/httptrace"
	"regexp"
	"strconv"
	"time"

	utls "github.com/metacubex/utls"
)

const accountTLSProfileHeader = "X-Resin-TLS-Profile"
const accountTLSProfileCapacity = 103680

var accountTLSProfilePattern = regexp.MustCompile(`^v1:(0|[1-9][0-9]{0,5}):[a-f0-9]{64}$`)

type accountTLSProfile struct {
	ID    string
	Index int
}

type outboundIdentity struct {
	Platform string
	Account  string
	TLS      accountTLSProfile
}

func resolveAccountTLSProfile(raw, platform, account string, authenticated bool) (accountTLSProfile, *ProxyError) {
	if raw != "" {
		if !authenticated {
			return accountTLSProfile{}, ErrAuthRequired
		}
		match := accountTLSProfilePattern.FindStringSubmatch(raw)
		if match == nil {
			return accountTLSProfile{}, ErrInvalidTLSProfile
		}
		index, _ := strconv.Atoi(match[1])
		if index >= accountTLSProfileCapacity {
			return accountTLSProfile{}, ErrInvalidTLSProfile
		}
		return accountTLSProfile{ID: raw, Index: index}, nil
	}
	if account == "" {
		return accountTLSProfile{}, nil
	}
	digest := sha256.Sum256([]byte("resin-account-tls-v1:" + platform + "\x00" + account))
	index := int(binary.BigEndian.Uint32(digest[:4]) % accountTLSProfileCapacity)
	return accountTLSProfile{ID: fmt.Sprintf("v1:%d:%x", index, digest), Index: index}, nil
}

func tlsPermutation[T any](values []T, rank int) []T {
	remaining := append([]T(nil), values...)
	result := make([]T, 0, len(remaining))
	for len(remaining) > 0 {
		index := rank % len(remaining)
		rank /= len(remaining)
		result = append(result, remaining[index])
		remaining = append(remaining[:index], remaining[index+1:]...)
	}
	return result
}

// Cipher and group permutations are the v1 Metapi/curl wire contract. uTLS
// controls TLS 1.3 as well as TLS 1.2; crypto/tls ignores TLS 1.3 suite order.
func (profile accountTLSProfile) clientHello() *utls.ClientHelloSpec {
	legacy := tlsPermutation([]uint16{
		utls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		utls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		utls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		utls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	}, profile.Index%720)
	modern := tlsPermutation([]uint16{
		utls.TLS_AES_128_GCM_SHA256, utls.TLS_AES_256_GCM_SHA384, utls.TLS_CHACHA20_POLY1305_SHA256,
	}, (profile.Index/720)%6)
	curves := tlsPermutation([]utls.CurveID{
		utls.X25519, utls.CurveP256, utls.CurveP384, utls.CurveP521,
	}, profile.Index/4320)
	return &utls.ClientHelloSpec{
		TLSVersMin:         utls.VersionTLS12,
		TLSVersMax:         utls.VersionTLS13,
		CipherSuites:       append(modern, legacy...),
		CompressionMethods: []byte{0},
		Extensions: []utls.TLSExtension{
			&utls.SNIExtension{},
			&utls.ExtendedMasterSecretExtension{},
			&utls.RenegotiationInfoExtension{Renegotiation: utls.RenegotiateNever},
			&utls.SupportedCurvesExtension{Curves: curves},
			&utls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&utls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []utls.SignatureScheme{
				utls.ECDSAWithP256AndSHA256, utls.PSSWithSHA256, utls.PKCS1WithSHA256,
				utls.ECDSAWithP384AndSHA384, utls.PSSWithSHA384, utls.PKCS1WithSHA384,
				utls.ECDSAWithP521AndSHA512, utls.PSSWithSHA512, utls.PKCS1WithSHA512,
			}},
			// net/http cannot negotiate HTTP/2 through a non-crypto/tls.Conn.
			// Advertise the protocol this transport will actually speak.
			&utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}},
			&utls.StatusRequestExtension{},
			&utls.SCTExtension{},
			&utls.KeyShareExtension{KeyShares: []utls.KeyShare{{Group: curves[0]}}},
			&utls.SupportedVersionsExtension{Versions: []uint16{utls.VersionTLS13, utls.VersionTLS12}},
		},
	}
}

func dialAccountTLS(ctx context.Context, conn net.Conn, addr string, profile accountTLSProfile) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	client := utls.UClient(conn, &utls.Config{
		ServerName: host, MinVersion: utls.VersionTLS12,
		// No global or cross-account session ticket cache.
		SessionTicketsDisabled: true,
	}, utls.HelloCustom)
	if err := client.ApplyPreset(profile.clientHello()); err != nil {
		conn.Close()
		return nil, err
	}
	trace := httptrace.ContextClientTrace(ctx)
	if trace != nil && trace.TLSHandshakeStart != nil {
		trace.TLSHandshakeStart()
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	err = client.HandshakeContext(handshakeCtx)
	if trace != nil && trace.TLSHandshakeDone != nil {
		state := client.ConnectionState()
		trace.TLSHandshakeDone(tls.ConnectionState{
			Version: state.Version, HandshakeComplete: state.HandshakeComplete,
			CipherSuite: state.CipherSuite, NegotiatedProtocol: state.NegotiatedProtocol,
			ServerName: state.ServerName, PeerCertificates: state.PeerCertificates,
			VerifiedChains: state.VerifiedChains, DidResume: state.DidResume,
		}, err)
	}
	if err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}
