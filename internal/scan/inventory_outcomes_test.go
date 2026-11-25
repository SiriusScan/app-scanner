package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

type inventoryRoundTripFunc func(*http.Request) (*http.Response, error)

func (f inventoryRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func inventoryFixtureClient(status int, body string) *http.Client {
	return &http.Client{Transport: inventoryRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: status,
			Body:       io.NopCloser(strings.NewReader(body)),
			Request:    req,
		}, nil
	})}
}

func trackedInventoryFixture(id string, total int) store.ScanResult {
	initial := activeTestScan(id, total)
	network := initial.SubScans["network"]
	network.Metadata = json.RawMessage(`{"unrelated":{"keep":true}}`)
	projectInventoryReports(&network, inventoryReportTally{}, inventoryAccountingStart)
	initial.SubScans["network"] = network
	return initial
}

func fixtureInventorySummary(t *testing.T, scan store.ScanResult) inventoryReportSummary {
	t.Helper()
	var metadata struct {
		Summary inventoryReportSummary `json:"inventory_reports"`
	}
	if err := json.Unmarshal(scan.SubScans["network"].Metadata, &metadata); err != nil || !metadata.Summary.valid() {
		t.Fatalf("invalid inventory summary: %s (%v)", scan.SubScans["network"].Metadata, err)
	}
	return metadata.Summary
}

func TestInventoryReportAcknowledgements(t *testing.T) {
	t.Setenv("SIRIUS_API_KEY_FILE", "")
	t.Setenv("SIRIUS_API_KEY", "fixture-key")
	const accepted = `{"message":"Host added successfully with source attribution","host_ip":"192.0.2.1","source":"fixture"}`
	for _, fixture := range []struct {
		name, body string
		status     int
		outcome    inventoryReportOutcome
	}{
		{"acknowledged Community report", accepted, http.StatusOK, inventoryReportAccepted},
		{"acknowledged enhanced report", strings.ReplaceAll(accepted, "with source attribution", "with enhanced SBOM data"), http.StatusOK, inventoryReportAccepted},
		{"failure with matching host and source", strings.ReplaceAll(accepted, "Host added successfully with source attribution", "validation failed"), http.StatusOK, inventoryReportHTTPUnconfirmed},
		{"denied success flag", accepted[:len(accepted)-1] + `,"success":false}`, http.StatusOK, inventoryReportHTTPUnconfirmed},
		{"different host", strings.ReplaceAll(accepted, "192.0.2.1", "192.0.2.2"), http.StatusOK, inventoryReportHTTPUnconfirmed},
		{"truncated response", accepted[:len(accepted)-1], http.StatusOK, inventoryReportHTTPUnconfirmed},
		{"error envelope", `{"message":"Host added successfully with source attribution","host_ip":"192.0.2.1","source":"fixture","error":"inert"}`, http.StatusOK, inventoryReportHTTPUnconfirmed},
		{"pending response", accepted, http.StatusAccepted, inventoryReportHTTPUnconfirmed},
		{"unexpected no content", "", http.StatusNoContent, inventoryReportHTTPUnconfirmed},
		{"rejection", "private fixture error", http.StatusForbidden, inventoryReportHTTPRejected},
		{"server error", "private fixture error", http.StatusInternalServerError, inventoryReportHTTPUnconfirmed},
		{"request timeout", "", http.StatusRequestTimeout, inventoryReportTimeout},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			sm := &ScanManager{ctx: context.Background(), apiBaseURL: "http://inventory.invalid", apiHTTPClient: inventoryFixtureClient(fixture.status, fixture.body)}
			var tally inventoryReportTally
			err := sm.submitHostWithSource(sirius.Host{IP: "192.0.2.1"}, "fixture", &tally)
			var want inventoryReportTally
			want[fixture.outcome] = 1
			if tally != want || (err == nil) != (fixture.status >= 200 && fixture.status < 300) {
				t.Fatalf("tally=%v, want=%v, submission error=%v", tally, want, err)
			}
		})
	}
	for _, fixture := range []struct {
		name string
		err  error
		want inventoryReportOutcome
	}{
		{"transport timeout", context.DeadlineExceeded, inventoryReportTimeout},
		{"transport failure", errors.New("inert transport error"), inventoryReportTransportError},
	} {
		t.Run(fixture.name, func(t *testing.T) {
			client := &http.Client{Transport: inventoryRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return nil, fixture.err
			})}
			sm := &ScanManager{ctx: context.Background(), apiBaseURL: "http://inventory.invalid", apiHTTPClient: client}
			var tally inventoryReportTally
			var want inventoryReportTally
			want[fixture.want] = 1
			if err := sm.submitHostWithSource(sirius.Host{IP: "192.0.2.1"}, "fixture", &tally); err == nil || tally != want {
				t.Fatalf("tally=%v, submission error=%v", tally, err)
			}
		})
	}

	t.Run("local setup failure", func(t *testing.T) {
		sm := &ScanManager{ctx: context.Background(), apiBaseURL: "http://invalid%"}
		var tally inventoryReportTally
		err := sm.submitHostWithSource(sirius.Host{IP: "192.0.2.1"}, "fixture", &tally)
		if err == nil || tally != (inventoryReportTally{inventoryReportLocalError: 1}) {
			t.Fatalf("tally=%v, submission error=%v", tally, err)
		}
	})

	req, err := http.NewRequest(http.MethodPost, "http://inventory.invalid/host/with-source", nil)
	if err != nil {
		t.Fatal(err)
	}
	redirected := req.Clone(context.Background())
	redirected.Response = &http.Response{StatusCode: http.StatusTemporaryRedirect}
	resp := &http.Response{StatusCode: http.StatusNoContent, Request: redirected}
	if got := inventoryResponseOutcome(req, resp, "", "", true); got != inventoryReportHTTPUnconfirmed {
		t.Fatalf("redirect was treated as scoped acknowledgement: %v", got)
	}
	resp.Request = req
	if got := inventoryResponseOutcome(req, resp, "", "", true); got != inventoryReportAccepted {
		t.Fatalf("expected scoped 204 acknowledgement, got %v", got)
	}
}

func TestInventoryReportRejectionKeepsLiveFindingAndProcessingCompletion(t *testing.T) {
	t.Setenv("SIRIUS_API_KEY_FILE", "")
	t.Setenv("SIRIUS_API_KEY", "fixture-key")
	sm, kv, _ := testManager(t, trackedInventoryFixture("scan-a", 1))
	sm.apiBaseURL = "http://inventory.invalid"
	sm.apiHTTPClient = inventoryFixtureClient(http.StatusForbidden, "private fixture error")
	host := sirius.Host{IP: "192.0.2.1", Vulnerabilities: []sirius.Vulnerability{{VID: "fixture-finding", Title: "Fixture"}}}
	var tally inventoryReportTally
	if err := sm.recordVulnerabilityResults(host, "fixture", &tally); err != nil {
		t.Fatal(err)
	}
	if err := sm.markHostComplete(host.IP, tally); err != nil {
		t.Fatal(err)
	}
	scan := readTestScan(t, kv)
	summary := fixtureInventorySummary(t, scan)
	if scan.Status != "completed" || len(scan.Vulnerabilities) != 1 || scan.Vulnerabilities[0].ID != "fixture-finding" ||
		!summary.Finalized || summary.Attempted != 1 || summary.Rejected != 1 || summary.Reasons.HTTPRejected != 1 {
		t.Fatalf("processing state or inventory summary is incorrect: %+v / %+v", scan, summary)
	}
	if strings.Contains(string(scan.SubScans["network"].Metadata), "private fixture error") {
		t.Fatal("raw response leaked into public scan status")
	}
}

func TestInventoryReportDeltasSurviveCASRetryAndParallelCompletion(t *testing.T) {
	sm, kv, _ := testManager(t, trackedInventoryFixture("scan-a", 3))
	conflict := &contendedStore{fakeKVStore: kv, beforeCAS: func() {
		updated := readTestScan(t, kv)
		network := updated.SubScans["network"]
		accepted := inventoryReportTally{inventoryReportAccepted: 1}
		projectInventoryReports(&network, accepted, inventoryAccountingPartial)
		network.Progress.Completed = 1
		updated.HostsCompleted = 1
		updated.SubScans["network"] = network
		if err := kv.SetValue(context.Background(), "currentScan", encodeTestScan(t, updated)); err != nil {
			t.Error(err)
		}
	}}
	sm.scanUpdater = NewScanUpdater(conflict)
	var workers sync.WaitGroup
	for i, tally := range []inventoryReportTally{{inventoryReportHTTPRejected: 1}, {inventoryReportTimeout: 1}} {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := sm.markHostComplete(fmt.Sprintf("192.0.2.%d", i+2), tally); err != nil {
				t.Error(err)
			}
		}()
	}
	workers.Wait()
	scan := readTestScan(t, kv)
	summary := fixtureInventorySummary(t, scan)
	if scan.Status != "completed" || scan.HostsCompleted != 3 || !summary.Finalized ||
		summary.Attempted != 3 || summary.Accepted != 1 || summary.Rejected != 1 || summary.Unknown != 1 ||
		!strings.Contains(string(scan.SubScans["network"].Metadata), `"unrelated":{"keep":true}`) {
		t.Fatalf("lost or duplicated a counter: %+v / %+v", scan, summary)
	}
}

func TestInventoryReportProjectionDoesNotFinalizeUnknownCoverage(t *testing.T) {
	initial := trackedInventoryFixture("scan-a", 1)
	t.Run("no report attempted", func(t *testing.T) {
		sm, kv, _ := testManager(t, initial)
		if err := sm.markHostComplete("192.0.2.1", inventoryReportTally{}); err != nil {
			t.Fatal(err)
		}
		summary := fixtureInventorySummary(t, readTestScan(t, kv))
		if !summary.Finalized || summary.Attempted != 0 || summary.Rejected != 0 {
			t.Fatalf("skipped stages generated an attempt: %+v", summary)
		}
	})
	t.Run("re-admitted ID", func(t *testing.T) {
		sm, kv, _ := testManager(t, initial)
		sm.scheduleTargets([]string{"192.0.2.1"})
		if err := sm.markHostComplete("192.0.2.1", inventoryReportTally{inventoryReportAccepted: 1}); err != nil {
			t.Fatal(err)
		}
		scan := readTestScan(t, kv)
		summary := fixtureInventorySummary(t, scan)
		if scan.Status != "completed" || summary.Finalized || !summary.Interrupted || summary.Accepted != 1 {
			t.Fatalf("interrupted accounting was presented as complete: %+v / %+v", scan, summary)
		}
	})
	t.Run("uncommitted progress", func(t *testing.T) {
		sm, kv, _ := testManager(t, initial)
		sm.scanUpdater = NewScanUpdater(&contendedStore{fakeKVStore: kv, alwaysConflict: true})
		err := sm.markHostComplete("192.0.2.1", inventoryReportTally{inventoryReportAccepted: 1})
		scan := readTestScan(t, kv)
		summary := fixtureInventorySummary(t, scan)
		if !errors.Is(err, ErrScanContention) || scan.HostsCompleted != 0 || summary.Attempted != 0 || summary.Finalized {
			t.Fatalf("uncommitted outcome was presented as complete: %+v / %+v / %v", scan, summary, err)
		}
	})
}
