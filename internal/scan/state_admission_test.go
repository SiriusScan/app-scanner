package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
)

func readKeyedTestScan(t *testing.T, kv *fakeKVStore, scanID string) (store.ScanResult, map[string]any) {
	t.Helper()
	value, err := kv.GetValue(context.Background(), "scan:"+scanID)
	if err != nil {
		t.Fatal(err)
	}
	data, err := base64.StdEncoding.DecodeString(value.Message.Value)
	if err != nil {
		t.Fatal(err)
	}
	var scan store.ScanResult
	if err := json.Unmarshal(data, &scan); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	return scan, fields
}

// A keyed job whose producer never pre-wrote state must create its own
// scoped state (with an active TTL) instead of being dropped.
func TestKeyedRunCreatesMissingScopedState(t *testing.T) {
	kv := &fakeKVStore{data: map[string]string{}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, kvStore: kv, scanUpdater: NewScanUpdater(kv)}
	run, err := sm.newKeyedRunForSubjectWithTargets("scan-1", "alice", []Target{{Value: "192.0.2.1", Type: SingleIP}})
	if err != nil {
		t.Fatal(err)
	}
	defer run.finishKeyedRun()
	scan, fields := readKeyedTestScan(t, kv, "scan-1")
	if scan.ID != "scan-1" || scan.Status != "running" || len(scan.Targets) != 1 || scan.Targets[0] != "192.0.2.1" || scan.StartTime == "" {
		t.Fatalf("self-created state incomplete: %+v", scan)
	}
	scope, _ := fields["resource_scope"].(map[string]any)
	if scope["owner_subject_id"] != "alice" {
		t.Fatalf("self-created state lost scope: %v", fields["resource_scope"])
	}
	if kv.expires["scan:scan-1"] != activeScanStateTTLSeconds {
		t.Fatalf("active TTL not set: %v", kv.expires)
	}
	// Terminal transition shrinks the TTL.
	if _, err := run.setScanStatus("scan-1", "cancelled"); err != nil {
		t.Fatal(err)
	}
	if kv.expires["scan:scan-1"] != terminalScanStateTTLSeconds {
		t.Fatalf("terminal TTL not set: %v", kv.expires)
	}
}

// A cancelling tombstone (a cancel that raced the job) must never be
// overwritten by self-creation: the scan settles cancelled, it does not run.
func TestKeyedRunDoesNotOverwriteCancellingTombstone(t *testing.T) {
	tombstone := activeTestScan("scan-1", 1)
	tombstone.Status = "cancelling"
	kv := &fakeKVStore{data: map[string]string{"scan:scan-1": encodeScopedTestScan(t, tombstone, "alice")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, kvStore: kv, scanUpdater: NewScanUpdater(kv)}
	if _, err := sm.newKeyedRunForSubject("scan-1", "alice"); err == nil {
		t.Fatal("cancelling scan started")
	}
	scan, _ := readKeyedTestScan(t, kv, "scan-1")
	if scan.Status != "cancelled" {
		t.Fatalf("tombstone not settled: %+v", scan)
	}
	if _, err := sm.newKeyedRunForSubject("scan-1", "bob"); err == nil {
		t.Fatal("foreign scope adopted existing state")
	}
}

func encodeScopedTestScan(t *testing.T, scan store.ScanResult, subject string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encodeTestScan(t, scan))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	fields["resource_scope"] = map[string]string{"owner_subject_id": subject}
	data, err = json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// A legacy job with no pre-written currentScan creates its own state.
func TestLegacyRunCreatesMissingState(t *testing.T) {
	kv := &fakeKVStore{data: map[string]string{}}
	logger := &memoryScanLogger{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, cancel: cancel, scanUpdater: NewScanUpdater(kv), kvStore: kv, logger: logger, toolFactory: NewScanToolFactory()}
	run, err := sm.newScanRunWithTargets("scan-1", []Target{{Value: "192.0.2.1", Type: SingleIP}})
	if err != nil {
		t.Fatal(err)
	}
	if run.currentScanID != "scan-1" {
		t.Fatalf("run identity lost: %q", run.currentScanID)
	}
	scan := readTestScan(t, kv)
	if scan.ID != "scan-1" || scan.Status != "running" || len(scan.Targets) != 1 || scan.Targets[0] != "192.0.2.1" {
		t.Fatalf("self-created legacy state incomplete: %+v", scan)
	}
}

// A legacy job may replace a terminal foreign scan in the slot, but never
// an active one (only a producer pre-write supersedes active work).
func TestLegacyRunReplacesOnlyTerminalForeignState(t *testing.T) {
	for _, status := range []string{"running", "cancelling"} {
		foreign := activeTestScan("scan-old", 1)
		foreign.Status = status
		sm, kv, _ := testManager(t, foreign)
		sm.currentScanID = ""
		if _, err := sm.newScanRun("scan-new"); err == nil {
			t.Fatalf("active foreign scan (%s) displaced without producer pre-write", status)
		}
		if got := readTestScan(t, kv); got.ID != "scan-old" || got.Status != status {
			t.Fatalf("foreign state mutated: %+v", got)
		}
	}
	for _, status := range []string{"completed", "failed", "cancelled"} {
		foreign := activeTestScan("scan-old", 1)
		foreign.Status = status
		sm, kv, _ := testManager(t, foreign)
		sm.currentScanID = ""
		run, err := sm.newScanRun("scan-new")
		if err != nil {
			t.Fatalf("terminal foreign scan (%s) not replaced: %v", status, err)
		}
		if run.currentScanID != "scan-new" {
			t.Fatalf("run identity lost: %q", run.currentScanID)
		}
		if got := readTestScan(t, kv); got.ID != "scan-new" || got.Status != "running" {
			t.Fatalf("replacement state wrong: %+v", got)
		}
	}
}
