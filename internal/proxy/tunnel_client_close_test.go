package proxy

import (
	"io"
	"net"
	"testing"
	"time"
)

func tunnelTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	peer, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server, err := listener.Accept()
	if err != nil {
		peer.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close(); server.Close() })
	return server.(*net.TCPConn), peer.(*net.TCPConn)
}

func receiveTunnelResult(t *testing.T, results <-chan tunnelRelayResult) tunnelRelayResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(2 * time.Second):
		t.Fatal("tunnel failed to finish")
		return tunnelRelayResult{}
	}
}

func TestTunnelClientCloseBeforeResponseDoesNotInvalidateLease(t *testing.T) {
	for _, reset := range []bool{false, true} {
		name := "fin"
		if reset {
			name = "reset"
		}
		t.Run(name, func(t *testing.T) {
			client, peer := tunnelTCPPair(t)
			upstream, target := tunnelTCPPair(t)
			results := make(chan tunnelRelayResult, 1)
			go func() {
				results <- pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream},
					tunnelPumpOptions{requireBidirectionalTraffic: true, firstByteTimeout: time.Second})
			}()
			if _, err := peer.Write([]byte("client-hello")); err != nil {
				t.Fatal(err)
			}
			request := make([]byte, len("client-hello"))
			if _, err := io.ReadFull(target, request); err != nil {
				t.Fatal(err)
			}
			if reset {
				if err := peer.SetLinger(0); err != nil {
					t.Fatal(err)
				}
			}
			peer.Close()
			// The upstream observes the client's propagated EOF before replying
			// with its own FIN. This reproduces canceled browser subresources.
			if _, err := io.Copy(io.Discard, target); err != nil {
				t.Fatal(err)
			}
			target.Close()
			result := receiveTunnelResult(t, results)
			if !result.clientClosedFirst || shouldInvalidateTunnelLease(result) {
				t.Fatalf("client cancellation must be neutral to the route: %+v", result)
			}
			if _, known := result.passiveHealth(); known {
				t.Fatal("client cancellation must not update node health")
			}
			if result.netOK || result.proxyErr == nil || result.ingressBytes != 0 || result.egressBytes != int64(len(request)) {
				t.Fatalf("keep failed-request evidence and exact byte counts: %+v", result)
			}
		})
	}
}

func TestTunnelUpstreamEOFBeforeClientRemainsNodeFailure(t *testing.T) {
	client, peer := tunnelTCPPair(t)
	upstream, target := tunnelTCPPair(t)
	results := make(chan tunnelRelayResult, 1)
	go func() {
		results <- pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream},
			tunnelPumpOptions{requireBidirectionalTraffic: true, firstByteTimeout: time.Second})
	}()
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	request := make([]byte, len("request"))
	if _, err := io.ReadFull(target, request); err != nil {
		t.Fatal(err)
	}
	target.Close()
	if _, err := io.Copy(io.Discard, peer); err != nil {
		t.Fatal(err)
	}
	peer.Close()
	result := receiveTunnelResult(t, results)
	if result.netOK || result.clientClosedFirst || !shouldInvalidateTunnelLease(result) {
		t.Fatalf("upstream EOF must remain a real failure: %+v", result)
	}
	if success, known := result.passiveHealth(); !known || success {
		t.Fatal("upstream failure must report a negative health result")
	}
}

func TestTunnelClientHalfCloseStillReceivesDelayedResponse(t *testing.T) {
	client, peer := tunnelTCPPair(t)
	upstream, target := tunnelTCPPair(t)
	results := make(chan tunnelRelayResult, 1)
	go func() {
		results <- pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream},
			tunnelPumpOptions{requireBidirectionalTraffic: true, firstByteTimeout: time.Second})
	}()
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	request, err := io.ReadAll(target)
	if err != nil || string(request) != "request" {
		t.Fatalf("half-closed request: %q, %v", request, err)
	}
	time.Sleep(20 * time.Millisecond)
	if _, err := target.Write([]byte("response")); err != nil {
		t.Fatal(err)
	}
	target.Close()
	response, err := io.ReadAll(peer)
	if err != nil || string(response) != "response" {
		t.Fatalf("response after half-close: %q, %v", response, err)
	}
	result := receiveTunnelResult(t, results)
	if !result.netOK || result.clientClosedFirst || result.ingressBytes != int64(len(response)) {
		t.Fatalf("half-close must preserve the successful exchange: %+v", result)
	}
}

func TestTunnelClientHalfCloseDoesNotHideFirstByteTimeout(t *testing.T) {
	client, peer := tunnelTCPPair(t)
	upstream, target := tunnelTCPPair(t)
	results := make(chan tunnelRelayResult, 1)
	go func() {
		results <- pumpPreparedTunnelReader(client, client, &preparedTunnel{upstreamConn: upstream},
			tunnelPumpOptions{requireBidirectionalTraffic: true, firstByteTimeout: 50 * time.Millisecond})
	}()
	if _, err := peer.Write([]byte("request")); err != nil {
		t.Fatal(err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(target); err != nil {
		t.Fatal(err)
	}
	result := receiveTunnelResult(t, results)
	if result.clientClosedFirst || result.proxyErr != ErrUpstreamTimeout || !shouldInvalidateTunnelLease(result) {
		t.Fatalf("timeout after client half-close must remain a failure: %+v", result)
	}
	if success, known := result.passiveHealth(); !known || success {
		t.Fatal("first-byte timeout must report a negative health result")
	}
}

func TestTunnelPassiveHealthRetainsExistingSuccessfulSamples(t *testing.T) {
	result := tunnelRelayResult{netOK: true, clientClosedFirst: true}
	if success, known := result.passiveHealth(); !success || !known {
		t.Fatal("an existing SOCKS5 success must still report a positive health result")
	}
}
