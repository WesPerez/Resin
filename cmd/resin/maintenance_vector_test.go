package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/Resinat/Resin/internal/model"
	"os"
	"testing"
)

// Actual Go model/tag/HTML-escaping output validates the shared frozen vector.
// Python tests consume the byte-identical file, not a guessed handoff digest.
func TestGoLeaseCanonicalSharedVectors(t *testing.T) {
	body, err := os.ReadFile("testdata/lease-canonical-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Version string `json:"version"`
		Vectors []struct {
			Leases    []model.Lease `json:"leases"`
			Canonical string        `json:"canonical"`
			SHA256    string        `json:"sha256"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(body, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Version != "resin-lease-seven/v1" || len(fixture.Vectors) != 2 {
		t.Fatal("invalid versioned vectors")
	}
	for _, v := range fixture.Vectors {
		actual, err := json.Marshal(v.Leases)
		if err != nil {
			t.Fatal(err)
		}
		if string(actual) != v.Canonical {
			t.Fatalf("actual Go JSON differs: %q", actual)
		}
		digest := sha256.Sum256(actual)
		got, err := canonicalLeaseDigest(v.Leases)
		if err != nil || got != v.SHA256 || hex.EncodeToString(digest[:]) != v.SHA256 {
			t.Fatal("actual Go SHA differs")
		}
	}
}
