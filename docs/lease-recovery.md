# Lease recovery

Recovery keeps the original platform and account and uses the current healthy
platform pool. Candidate observations are optional preferences. Failure reports
retain generation CAS so old results cannot change a newer account binding.

Legacy route suffixes are accepted as aliases of the base account and do not pin
node, IP or connection lifetime. See [response recovery](response-recovery.md).
