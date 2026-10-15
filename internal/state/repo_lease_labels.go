package state

// LeaseDisplayNames reads the persisted labels for one platform. Labels survive
// lease renewal/expiry because they describe the same stable application key.
func (r *StateRepo) LeaseDisplayNames(platformID string) (map[string]string, error) {
	rows, err := r.db.Query("SELECT account, display_name FROM lease_display_names WHERE platform_id = ?", platformID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(map[string]string)
	for rows.Next() {
		var account, name string
		if err := rows.Scan(&account, &name); err != nil {
			return nil, err
		}
		result[account] = name
	}
	return result, rows.Err()
}

// SetLeaseDisplayName only updates strong-persist display metadata, never the
// router or its weak-persist lease cache. Empty names remove the override.
func (r *StateRepo) SetLeaseDisplayName(platformID, account, name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if name == "" {
		_, err := r.db.Exec("DELETE FROM lease_display_names WHERE platform_id = ? AND account = ?", platformID, account)
		return err
	}
	_, err := r.db.Exec(`INSERT INTO lease_display_names(platform_id, account, display_name)
		VALUES (?, ?, ?) ON CONFLICT(platform_id, account) DO UPDATE SET display_name = excluded.display_name`, platformID, account, name)
	return err
}
