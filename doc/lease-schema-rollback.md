# Schema-compatible rollback candidate

Based on production aad1b59b37702049fd60c29c2b3b0a96b6e9a8b2. The only runtime change is recognition/creation of state schema 10 and its independent lease_display_names table. Lease APIs, WebUI, routing and cache schema retain production behavior. Existing labels remain stored but are not displayed by this rollback image.

After the display-name release, do not deploy the original schema-9 image against the upgraded database and do not restore a pre-release state/cache snapshot. Use this candidate's CI-verified immutable digest through the existing blue/green deploy command, taking the usual online snapshot from the current active slot. This retains post-release persisted platform/lease state and labels, subject to the existing snapshot-to-cutover limitation (no live replication of subsequent lease changes).

Before reuse, the retired slot must have drained and the deployer must accept it as available. If not, keep the active service and resolve forward; never kill draining connections to accelerate rollback. Initial candidate failure before cutover leaves production untouched. Failure immediately after cutover follows the deployer's guarded rollback, which likewise has no bidirectional state replication.

Release gates: both candidate and rollback Verify/image jobs pass at exact SHAs; immutable image digests are recorded; schema-10 reopening preserves post-upgrade records and labels in hosted tests; deployment ledger has no pending/draining conflicts; coordinator grants the production IO/cutover window. This document is a plan, not evidence of a production rollback rehearsal.
