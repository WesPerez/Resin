package outbound

import (
	"encoding/json"
	"testing"
)

func TestDeferredBuilderDoesNotConstructDNSOrLazyStart(t *testing.T) {
	b, err := NewSingboxBuilderWithConfig(SingboxBuilderConfig{DNSUpstreams: []string{"udp://127.0.0.1:9"}, DeferStart: true})
	if err != nil {
		t.Fatal(err)
	}
	if b.Started() || b.ctx != nil || b.dnsRouter != nil || b.dnsTransportManager != nil {
		t.Fatal("DNS service graph started before authority")
	}
	if _, err := b.Build(json.RawMessage(`{"type":"http","server":"127.0.0.1","server_port":1}`)); err == nil {
		t.Fatal("Build implicitly activated fenced builder")
	}
	// Close of an unstarted graph cannot create or start services.
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if b.Started() {
		t.Fatal("close started builder")
	}
}

func TestDeferredBuilderExplicitStartAndSingleLifecycle(t *testing.T) {
	b, err := NewSingboxBuilderWithConfig(SingboxBuilderConfig{DNSUpstreams: []string{"udp://127.0.0.1:9"}, DeferStart: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Start(); err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if !b.Started() {
		t.Fatal("explicit start failed")
	}
	if err := b.Start(); err == nil {
		t.Fatal("duplicate DNS lifecycle started")
	}
	ob, err := b.Build(json.RawMessage(`{"type":"http","server":"127.0.0.1","server_port":1}`))
	if err != nil {
		t.Fatal(err)
	}
	closeOutbound(ob)
}
