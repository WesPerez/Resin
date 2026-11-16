-- Labels describe stable application identities, independently of lease lifetime.
-- Routing keys, cache leases and their timestamps are deliberately untouched.
CREATE TABLE lease_display_names (
    platform_id TEXT NOT NULL REFERENCES platforms(id) ON DELETE CASCADE,
    account TEXT NOT NULL,
    display_name TEXT NOT NULL,
    PRIMARY KEY (platform_id, account)
);
