package geoip

import (
	"net/netip"
	"testing"
)

func TestStopUpdates_PreservesLookupUntilConsumersDrain(t *testing.T) {
	s := NewService(ServiceConfig{CacheDir: t.TempDir()})
	s.reader = &mockReader{country: "us"}
	ip := netip.MustParseAddr("203.0.113.9")
	want := s.Lookup(ip)
	if want == "" {
		t.Fatal("fixture reader must return a country")
	}
	s.StopUpdates()
	if got := s.Lookup(ip); got != want {
		t.Fatalf("update drain closed the active lookup consumer: %q", got)
	}
	s.CloseReader()
	if got := s.Lookup(ip); got != "" {
		t.Fatalf("reader was not closed: %q", got)
	}
}
