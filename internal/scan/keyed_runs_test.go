package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestKeyedRunsRemainIndependent(t *testing.T) {
	kv := &fakeKVStore{data: map[string]string{
		"scan:a":      encodeTestScan(t, activeTestScan("a", 1)),
		"scan:b":      encodeTestScan(t, activeTestScan("b", 1)),
		"currentScan": encodeTestScan(t, activeTestScan("global", 1)),
	}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, kvStore: kv, scanUpdater: NewScanUpdater(kv)}
	a, err := sm.newKeyedRun("a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := sm.newKeyedRun("b")
	if err != nil {
		t.Fatal(err)
	}
	if a.ctx.Err() != nil || b.ctx.Err() != nil {
		t.Fatal("new run cancelled an existing run")
	}
	if _, err := sm.newKeyedRun("a"); err == nil {
		t.Fatal("duplicate accepted")
	}
	sm.cancelKeyedRun("a", "")
	if a.ctx.Err() == nil || b.ctx.Err() != nil {
		t.Fatal("cancellation affected wrong run")
	}
	// Missing keyed state is created from the job itself; it must never be
	// read out of the legacy global slot.
	missing, err := sm.newKeyedRun("missing")
	if err != nil {
		t.Fatalf("missing keyed state not self-created: %v", err)
	}
	created, _ := readKeyedTestScan(t, kv, "missing")
	if created.ID != "missing" || created.Status != "running" || len(created.Hosts) != 0 || len(created.SubScans) != 0 {
		t.Fatalf("self-created keyed state is not fresh: %+v", created)
	}
	missing.finishKeyedRun()
	globalRun, err := sm.newKeyedRun("global")
	if err != nil {
		t.Fatalf("keyed scan named like the global one not self-created: %v", err)
	}
	created, _ = readKeyedTestScan(t, kv, "global")
	if len(created.SubScans) != 0 {
		t.Fatalf("global currentScan state used for keyed scan: %+v", created)
	}
	if got := readTestScan(t, kv); got.ID != "global" || len(got.SubScans) == 0 {
		t.Fatalf("legacy global state mutated by keyed admission: %+v", got)
	}
	globalRun.finishKeyedRun()
	b.finishKeyedRun()
}

func TestRejectNonGlobalScope(t *testing.T) {
	msg := ScanMessage{ID: "scoped", Priority: 1, Targets: []Target{{Value: "192.0.2.1"}}}
	msg.ResourceScope.OwnerSubjectID = "subject-a"
	if err := (&ScanManager{}).validateScanMessage(&msg); err == nil {
		t.Fatal("non-global scope accepted")
	}
	msg.ResourceScope.OwnerSubjectID = ""
	if err := (&ScanManager{}).validateScanMessage(&msg); err != nil {
		t.Fatal(err)
	}
}

func TestKeyedCancellationRequiresMatchingLiveScope(t *testing.T) {
	kv := &fakeKVStore{data: map[string]string{"scan:a": encodeScopedScan(t, "a", "alice")}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm := &ScanManager{ctx: ctx, kvStore: kv}
	run, err := sm.newKeyedRunForSubject("a", "alice")
	if err != nil {
		t.Fatal(err)
	}
	sm.cancelKeyedRun("a", "bob")
	if run.ctx.Err() != nil {
		t.Fatal("wrong subject cancelled scan")
	}
	sm.cancelKeyedRun("a", "")
	if run.ctx.Err() != nil {
		t.Fatal("global control cancelled scoped scan")
	}
	sm.cancelKeyedRun("a", "alice")
	if run.ctx.Err() == nil {
		t.Fatal("matching subject did not cancel scan")
	}
}

func encodeScopedScan(t *testing.T, id, subject string) string {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encodeTestScan(t, activeTestScan(id, 1)))
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
func TestQueuedCancellationChecksPersistedScope(t *testing.T) {
	kv := &fakeKVStore{data: map[string]string{"scan:a": encodeScopedScan(t, "a", "alice")}}
	sm := &ScanManager{ctx: context.Background(), kvStore: kv}
	before := kv.data["scan:a"]
	sm.cancelKeyedRun("a", "bob")
	sm.cancelKeyedRun("a", "")
	if kv.data["scan:a"] != before {
		t.Fatal("wrong or absent subject mutated queued scan")
	}
	sm.cancelKeyedRun("a", "alice")
	if kv.data["scan:a"] == before {
		t.Fatal("matching scope did not cancel queued scan")
	}
	if _, err := sm.newKeyedRunForSubject("a", "bob"); err == nil {
		t.Fatal("wrong subject accepted")
	}
}
