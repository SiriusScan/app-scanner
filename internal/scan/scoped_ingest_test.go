package scan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

func TestScopedHostUsesExplicitEndpointAndSubject(t *testing.T) {
	t.Setenv("SIRIUS_API_KEY_FILE", "")
	t.Setenv("SIRIUS_API_KEY", "test-key")
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/trusted" || r.Header.Get("X-Sirius-Resource-Subject") != "alice" || r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("incorrect scoped request: %s %q", r.URL.Path, r.Header.Get("X-Sirius-Resource-Subject"))
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	sm := &ScanManager{ctx: context.Background(), apiBaseURL: "http://127.0.0.1:1", scopedIngestURL: srv.URL + "/trusted", subjectID: "alice", apiHTTPClient: srv.Client()}
	if err := sm.submitHostWithSource(sirius.Host{IP: "192.0.2.1"}, "fixture", &inventoryReportTally{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("calls=%d", calls)
	}
	snapshot := sm.executionSnapshot(context.Background(), "a", ScanOptions{})
	if snapshot.subjectID != "alice" || snapshot.scopedIngestURL != sm.scopedIngestURL {
		t.Fatal("scope lost in run snapshot")
	}
}

func TestScopedHostFailureMarksScanFailed(t *testing.T) {
	t.Setenv("SIRIUS_API_KEY_FILE", "")
	t.Setenv("SIRIUS_API_KEY", "test-key")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	kv := &fakeKVStore{data: map[string]string{"scan:a": encodeScopedScan(t, "a", "alice")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, cancel: cancel, currentScanID: "a", subjectID: "alice", scopedIngestURL: srv.URL, apiHTTPClient: srv.Client(), scanUpdater: &ScanUpdater{kvStore: kv, keyed: true, subjectID: "alice"}}
	if err := sm.submitHostWithSource(sirius.Host{IP: "192.0.2.1"}, "fixture", &inventoryReportTally{}); err == nil {
		t.Fatal("expected scoped ingest failure")
	}
	var persisted store.ScanResult
	if err := sm.scanUpdater.UpdateForScan(context.Background(), "a", func(s *store.ScanResult) error { persisted = *s; return nil }); err != nil {
		t.Fatal(err)
	}
	summary := fixtureInventorySummary(t, persisted)
	if persisted.Status != "failed" || summary.Attempted != 1 || summary.Unknown != 1 || summary.Finalized {
		t.Fatalf("status=%q, inventory=%+v", persisted.Status, summary)
	}
}
