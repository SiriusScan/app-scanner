# Keyed scanner state

Legacy requests omit `state_mode` and use the shared `currentScan` record. A
producer that needs independently scheduled scans sets `"state_mode":"keyed"`
and creates the existing base64-encoded ScanResult at `scan:<id>` before
publishing. The record's `id` must match the request. The scanner requires
compare-and-set support and never falls back to `currentScan` for keyed requests.
Control messages must include the exact scan ID and matching scope. The producer
owns state creation, retention, authorization and duplicate suppression.

The scanner accepts `sirius.scan.requested` and `sirius.scan.cancel.requested`
envelopes at spec and payload version `1.0` from the public go-api message
contract. Versioned payloads require keyed state. Unknown versions and malformed
envelopes are rejected. Legacy messages remain supported for global Community
use. Queues and their publishers must be trusted to authorize requested scopes
and exact-ID cancellation; the scanner does not authenticate individual users.

A non-global scope requires the full `SIRIUS_SCOPED_HOST_INGEST_URL` endpoint.
The scanner sends the standard `{host,source}` JSON body, the existing service
API key as `X-API-Key`, and the opaque subject as `X-Sirius-Resource-Subject`.
That endpoint must authenticate the scanner and use a trusted scope resolver
bound to the subject header. The Community handler factory is not mounted by
default. Configure an authenticated endpoint before accepting scoped requests;
without it scoped jobs are rejected before state changes. Scoped observations
never fall back to the global host endpoint. A failed submission marks the scan
failed. This contract alone does not authorize users or provide end-to-end
isolation without a trusted control plane and scoped Core API composition.
