package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestConvertURIProducesOnlyOutbounds(t *testing.T) {
	input := "vless://00000000-0000-0000-0000-000000000001@example.com:443?security=tls&sni=cdn.example.com&type=ws&path=%2Fws#example"
	var output bytes.Buffer
	if err := convert(strings.NewReader(input), &output); err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(output.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Outbounds) != 1 || parsed.Outbounds[0]["type"] != "vless" {
		t.Fatal("expected one parsed VLESS outbound")
	}
	if parsed.Outbounds[0]["transport"].(map[string]any)["path"] != "/ws" {
		t.Fatal("transport options were lost")
	}
}

func TestRejectEmptyInvalidAndOversizedInputs(t *testing.T) {
	for _, input := range []string{"", "not a subscription", `{"outbounds":[]}`, strings.Repeat("x", maxInputBytes+1)} {
		var output bytes.Buffer
		if err := convert(strings.NewReader(input), &output); err == nil || output.Len() != 0 {
			t.Fatal("invalid input must fail without producing output")
		}
	}
}
