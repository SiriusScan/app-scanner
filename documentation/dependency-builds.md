# Reproducible dependency builds

The scanner pins published `github.com/SiriusScan/go-api` and
`github.com/SiriusScan/pingpp` modules in `go.mod` and records their
checksums in `go.sum`. A clean checkout needs Go 1.24, libpcap development
headers, and normal access to the Go module proxy and checksum database.

From the scanner checkout:

    GOWORK=off go mod download
    GOWORK=off go list -mod=readonly -m github.com/SiriusScan/go-api github.com/SiriusScan/pingpp
    GOWORK=off go test -mod=readonly -race -short ./...
    GOWORK=off go vet -mod=readonly ./...
    GOWORK=off go build -mod=readonly ./...

The short test suite uses offline fixtures. Opt-in store integration tests
require disposable services.

For coordinated local development, create a Go workspace outside the
repositories and add the scanner and any dependency checkout you want to edit.
Run release verification with `GOWORK=off` so it uses the committed module
versions.

When bumping pingpp, use a published full commit SHA or canonical release
version, regenerate `go.sum`, and record the resolved module version and
source commit for image provenance. The Sirius engine cutover is tracked in
[SiriusScan/Sirius#181](https://github.com/SiriusScan/Sirius/issues/181).
