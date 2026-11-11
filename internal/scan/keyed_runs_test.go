package scan

import (
	"context"
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
	sm.cancelKeyedRun("a")
	if a.ctx.Err() == nil || b.ctx.Err() != nil {
		t.Fatal("cancellation affected wrong run")
	}
	if _, err := sm.newKeyedRun("missing"); err == nil {
		t.Fatal("missing keyed state fell back to global")
	}
	if _, err := sm.newKeyedRun("global"); err == nil {
		t.Fatal("global state used for keyed scan")
	}
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
