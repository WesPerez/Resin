package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"sort"
	"unicode/utf8"

	"github.com/Resinat/Resin/internal/model"
)

func readonlyDB(path string) (*sql.DB, error) {
	u := url.URL{Scheme: "file", Path: path, RawQuery: "mode=ro"}
	return sql.Open("sqlite", u.String())
}

func offlineLeases(ctx context.Context, path string) ([]model.Lease, error) {
	db, err := readonlyDB(path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, `SELECT platform_id,account,node_hash,egress_ip,created_at_ns,expiry_ns,last_accessed_ns FROM leases ORDER BY platform_id,account`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []model.Lease{}
	for rows.Next() {
		var l model.Lease
		if err := rows.Scan(&l.PlatformID, &l.Account, &l.NodeHash, &l.EgressIP, &l.CreatedAtNs, &l.ExpiryNs, &l.LastAccessedNs); err != nil {
			return nil, err
		}
		result = append(result, l)
	}
	return result, rows.Err()
}

func canonicalLeaseDigest(leases []model.Lease) (string, error) {
	for _, lease := range leases {
		if !utf8.ValidString(lease.PlatformID) || !utf8.ValidString(lease.Account) ||
			!utf8.ValidString(lease.NodeHash) || !utf8.ValidString(lease.EgressIP) {
			return "", errors.New("lease identity contains invalid UTF-8")
		}
	}
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].PlatformID == leases[j].PlatformID {
			return leases[i].Account < leases[j].Account
		}
		return leases[i].PlatformID < leases[j].PlatformID
	})
	for i := 1; i < len(leases); i++ {
		if leases[i-1].PlatformID == leases[i].PlatformID && leases[i-1].Account == leases[i].Account {
			return "", errors.New("duplicate lease identity")
		}
	}
	if leases == nil {
		leases = []model.Lease{}
	}
	body, err := json.Marshal(leases)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
