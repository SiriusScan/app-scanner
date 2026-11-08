# Scan lifecycle safety

A queued network task retains its original scan ID, options, factory and context.
Starting a replacement cancels the old run; old queued tasks never borrow the new
run's context. Per-host port overrides do not mutate shared scan options.

All targets are expanded and deduplicated before any are queued. The complete
network work count is persisted before workers start. Invalid targets fail the
request without starting partial work. Cancellation and tool failures stop the
network run; late workers do not turn an unsuccessful scan into success. A network
failure leaves the overall scan running while other enabled scanners are active,
so their results can still be merged. The final aggregate remains failed.

Control messages require a nonempty exact `scan_id`, including force cancellation
and recovery after restart. The persisted ID is authoritative, including agent-only
scans and requests cancelled before network dequeue; the previous local network ID
is never used to reject cancellation of a newer authoritative scan. Untargeted
commands are rejected. Completed, failed,
cancelled and cancelling snapshots are preserved during progress updates.
Overall success requires every enabled sub-scan to succeed. Failed or cancelled
sub-scans are never aggregated as a successful overall scan.

## Atomic persistence contract

`ScanUpdater.UpdateForScan` requires the SDK's optional
`store.ValueCompareAndSetter` capability. The concrete Valkey store compares the
entire raw value and updates it atomically with `SET ... KEEPTTL`. Missing keys do
not match, preventing a deleted scan from being recreated by late work.

The updater retries contention at most eight times, rereading and validating the
scan ID and status each time. Modifiers must not have external side effects because
they can run repeatedly. Success events are emitted only after a committed update.
Corrupt/null state is returned as an error, never replaced with an empty scan.
Unknown top-level fields are preserved. Older custom store implementations without
CAS fail closed for scan-scoped writes; the legacy unscoped `Update` remains for
compatibility and is not used by scanner lifecycle code.

All components writing `currentScan` must use equivalent conditional updates.
An unconditional writer elsewhere can still overwrite a newer snapshot. The SDK
change must be released/pinned together with scanner, API and other writer changes;
a local module replacement does not update container image pins.

## Verification without real scans

Use `go test -short ./...`, `go test -race ./internal/scan`, and `go vet ./internal/scan`.
The lifecycle tests use fake tools, stores and loggers. Non-short legacy Nmap tests
require container fixtures and can launch actual scans; do not run them for unit QA.

The SDK's opt-in `TestCompareAndSetValueIntegration` uses only a fresh random key
with a 60-second TTL and deletes it afterward. Run it against a disposable/dev
Valkey with `SIRIUS_TEST_VALKEY_ADDR` explicitly set. It never accesses `currentScan`.

Cancellation is cooperative. The ping++ adapter checks context before/after its
underlying call, but an in-flight probe may finish before observing cancellation.
