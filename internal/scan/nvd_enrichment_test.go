package scan

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
)

type nvdRoundTripFunc func(*http.Request) (*http.Response, error)

func (f nvdRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type nvdStalledBody struct {
	ctx     context.Context
	entered chan struct{}
}

func (b *nvdStalledBody) Read([]byte) (int, error) {
	close(b.entered)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (b *nvdStalledBody) Close() error { return nil }

func installNVDTransport(t *testing.T, rt nvdRoundTripFunc) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = rt
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func nvdFindings() []sirius.Vulnerability {
	return []sirius.Vulnerability{
		{VID: "CVE-2024-0001", Title: "scanner evidence", Description: "original finding", RiskScore: 9.8},
		{VID: "CVE-2024-0002", Title: "second", Description: "second finding", RiskScore: 8.1},
		{VID: "CVE-2024-0003", Title: "third", Description: "third finding", RiskScore: 7.5},
	}
}

func TestNVDScanCancellationInterruptsEnrichment(t *testing.T) {
	for _, mode := range []string{"headers", "body"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{})
			var calls atomic.Int32
			installNVDTransport(t, func(r *http.Request) (*http.Response, error) {
				calls.Add(1)
				if mode == "headers" {
					close(entered)
					<-r.Context().Done()
					return nil, r.Context().Err()
				}
				return &http.Response{StatusCode: 200, Body: &nvdStalledBody{ctx: r.Context(), entered: entered}, Header: make(http.Header)}, nil
			})
			original := sirius.Host{IP: "192.0.2.1", Vulnerabilities: nvdFindings()}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				host sirius.Host
				err  error
			}
			done := make(chan outcome, 1)
			go func() {
				got, err := (&NmapStrategy{}).executeWithContext(ctx, original.IP, func(config nmap.ScanConfig) (sirius.Host, error) {
					if config.Ctx != ctx {
						t.Error("scan context not propagated")
					}
					return original, nil
				})
				done <- outcome{got, err}
			}()
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("NVD request did not start")
			}
			cancel()
			select {
			case got := <-done:
				if !errors.Is(got.err, context.Canceled) {
					t.Fatalf("got %v, want canceled scan", got.err)
				}
				if !reflect.DeepEqual(got.host, original) {
					t.Fatalf("findings lost on cancellation: %+v", got.host)
				}
				if calls.Load() != 1 {
					t.Fatalf("performed %d requests after cancellation", calls.Load())
				}
			case <-time.After(time.Second):
				t.Fatal("scan failed to stop during NVD enrichment")
			}
		})
	}
}

func TestNVDBudgetBoundsEntireEnrichmentAndPreservesFindings(t *testing.T) {
	var calls atomic.Int32
	installNVDTransport(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	original := nvdFindings()
	start := time.Now()
	got, err := enrichVulnerabilities(context.Background(), original, 25*time.Millisecond)
	if err != nil {
		t.Fatalf("optional enrichment budget failed scan: %v", err)
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("lost original findings: %+v", got)
	}
	if calls.Load() != 1 {
		t.Fatalf("per-CVE deadlines multiplied budget: %d calls", calls.Load())
	}
	if time.Since(start) > time.Second {
		t.Fatal("total enrichment budget not enforced")
	}
}

func TestNVDEnrichmentPreservesExistingMetadataOnMissingOrFailedLookup(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"empty", `{"vulnerabilities":[]}`, 200},
		{"no metrics", `{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001"}}]}`, 200},
		{"unavailable", `{}`, 503},
		{"malformed", `{`, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			installNVDTransport(t, func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})
			original := nvdFindings()[0]
			got := expandVulnerabilityWithContext(context.Background(), original)
			if !reflect.DeepEqual(got, original) {
				t.Fatalf("enrichment replaced existing evidence: %+v", got)
			}
		})
	}
}

func TestNVDEnrichmentSuccess(t *testing.T) {
	installNVDTransport(t, func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"vulnerabilities":[{"cve":{"id":"CVE-2024-0001","descriptions":[{"lang":"en","value":"NVD detail"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.2}}]}}}]}`)), Header: make(http.Header)}, nil
	})
	got := expandVulnerabilityWithContext(context.Background(), nvdFindings()[0])
	if got.Description != "NVD detail" || got.RiskScore != 7.2 {
		t.Fatalf("successful enrichment lost: %+v", got)
	}
}

func TestNVDEnrichmentAlreadyCanceledSkipsRequests(t *testing.T) {
	installNVDTransport(t, func(*http.Request) (*http.Response, error) { t.Fatal("unexpected lookup"); return nil, nil })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	original := nvdFindings()
	got, err := enrichVulnerabilities(ctx, original, nvdEnrichmentTimeout)
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, original) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestNVDScanCancellationImmediatelyAfterNmapSkipsEnrichment(t *testing.T) {
	installNVDTransport(t, func(*http.Request) (*http.Response, error) {
		t.Fatal("lookup after scan cancellation")
		return nil, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	original := sirius.Host{IP: "192.0.2.1", Vulnerabilities: nvdFindings()}
	got, err := (&NmapStrategy{}).executeWithContext(ctx, original.IP, func(nmap.ScanConfig) (sirius.Host, error) { cancel(); return original, nil })
	if !errors.Is(err, context.Canceled) || !reflect.DeepEqual(got, original) {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestNVDEnrichmentParentDeadlineFailsScanWithoutLosingFindings(t *testing.T) {
	var calls atomic.Int32
	installNVDTransport(t, func(r *http.Request) (*http.Response, error) {
		calls.Add(1)
		<-r.Context().Done()
		return nil, r.Context().Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	original := nvdFindings()
	got, err := enrichVulnerabilities(ctx, original, nvdEnrichmentTimeout)
	if !errors.Is(err, context.DeadlineExceeded) || !reflect.DeepEqual(got, original) {
		t.Fatalf("got %+v, %v", got, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("continued after caller deadline: %d", calls.Load())
	}
}
