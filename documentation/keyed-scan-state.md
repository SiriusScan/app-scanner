# Keyed scanner state

Legacy requests omit `state_mode` and use the shared `currentScan` record. A
producer that needs independently scheduled scans may instead set
`"state_mode":"keyed"` and create the existing base64-encoded ScanResult at
`scan:<id>` before publishing. The record's `id` must match the request. The
scanner requires compare-and-set support and never falls back to `currentScan`
for keyed requests. Control messages for these scans must include the same
`state_mode` and the exact `scan_id`. Unknown modes are rejected.

Keyed state separates execution and cancellation; it does not provide inventory
isolation. Host observations currently go to the existing global API. Do not use
this mode for subject-isolated inventory until scoped ingestion is available.
The producer owns initial state, retention and authorization of job and control
messages. The queue may redeliver, so producers must not reset active or terminal
records to dispatch duplicate jobs.
