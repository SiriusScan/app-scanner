# Reproducible dependency builds

The scanner pins the published github.com/SiriusScan/go-api module in go.mod.
It does not replace the SDK with a sibling checkout. Use GOWORK=off to verify
release builds without a parent workspace overriding that pin. For coordinated
SDK development, use an explicit local Go workspace instead of changing the
release dependency in go.mod.

The github.com/SiriusScan/ping++ module retains its existing ../ping++ replacement.
Its required v0.0.0 is not a published release. Production engine builds clone
SiriusScan/pingpp to that sibling path and pin it using PINGPP_COMMIT_SHA.
CI currently checks out master. For reproducible local verification, use a clean
sibling at 9508a16c40a49746feb7cab4b8c1c358246169b0, the production pin and
verified CI branch head at this change. Review future CI branch advances separately.

With that sibling and libpcap development headers installed, run:

    GOWORK=off go list -m github.com/SiriusScan/go-api
    GOWORK=off go test -race -short ./...
    GOWORK=off go vet ./...
    GOWORK=off go build ./...

These commands compile the scanner; they do not start it or dispatch scans.
Opt-in store integration tests require fresh disposable services. Do not point
them at production stores or databases.
