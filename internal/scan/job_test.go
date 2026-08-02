package scan

import (
	"context"
	"testing"
)

func newTestManager() *ScanManager {
	return &ScanManager{
		jobs: make(map[string]*JobContext),
	}
}

func TestJobRegistry_RegisterAndGet(t *testing.T) {
	sm := newTestManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	job := &JobContext{
		ID:             "scan-a",
		OwnerSubjectID: "alice",
		Ctx:            ctx,
		Cancel:         cancel,
		HostsExpected:  2,
	}
	sm.registerJob(job)

	got := sm.GetJobContext("scan-a")
	if got == nil {
		t.Fatal("expected job to be registered")
	}
	if got.OwnerSubjectID != "alice" {
		t.Errorf("OwnerSubjectID = %q, want alice", got.OwnerSubjectID)
	}
	if sm.GetJobContext("scan-b") != nil {
		t.Error("unexpected job for unknown id")
	}
}

func TestCancelJob_ExactIDOnly(t *testing.T) {
	sm := newTestManager()

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	jobA := &JobContext{ID: "alice-scan", Ctx: ctxA, Cancel: cancelA}
	jobB := &JobContext{ID: "bob-scan", Ctx: ctxB, Cancel: cancelB}
	sm.registerJob(jobA)
	sm.registerJob(jobB)

	// Wrong ID must not cancel anything.
	if sm.CancelJob("missing-id") {
		t.Fatal("CancelJob(missing) should return false")
	}
	if ctxA.Err() != nil || ctxB.Err() != nil {
		t.Fatal("wrong ID cancel must not cancel any job")
	}

	// Empty ID must be ignored.
	if sm.CancelJob("") {
		t.Fatal("CancelJob(\"\") should return false")
	}
	if ctxA.Err() != nil || ctxB.Err() != nil {
		t.Fatal("empty ID cancel must not cancel any job")
	}

	// Exact Alice cancel must not touch Bob.
	if !sm.CancelJob("alice-scan") {
		t.Fatal("CancelJob(alice-scan) should succeed")
	}
	if ctxA.Err() == nil {
		t.Fatal("alice job context should be cancelled")
	}
	if ctxB.Err() != nil {
		t.Fatal("bob job must continue after alice cancel")
	}
	if !jobA.Cancelling() {
		t.Fatal("alice job should be marked IsCancelling")
	}
	if jobB.Cancelling() {
		t.Fatal("bob job must not be IsCancelling")
	}
}

func TestForceCancelJob_ExactIDOnly(t *testing.T) {
	sm := newTestManager()

	ctxA, cancelA := context.WithCancel(context.Background())
	ctxB, cancelB := context.WithCancel(context.Background())
	sm.registerJob(&JobContext{ID: "alice-scan", Ctx: ctxA, Cancel: cancelA})
	sm.registerJob(&JobContext{ID: "bob-scan", Ctx: ctxB, Cancel: cancelB})

	if sm.ForceCancelJob("wrong-id") {
		t.Fatal("ForceCancelJob(wrong) should return false")
	}
	if ctxA.Err() != nil || ctxB.Err() != nil {
		t.Fatal("mismatched force-stop must not proceed on other jobs")
	}

	if !sm.ForceCancelJob("bob-scan") {
		t.Fatal("ForceCancelJob(bob-scan) should succeed")
	}
	if ctxB.Err() == nil {
		t.Fatal("bob context should be cancelled")
	}
	if ctxA.Err() != nil {
		t.Fatal("alice must be untouched by bob force-stop")
	}
}

func TestCancelJob_Idempotent(t *testing.T) {
	sm := newTestManager()
	ctx, cancel := context.WithCancel(context.Background())
	sm.registerJob(&JobContext{ID: "scan-1", Ctx: ctx, Cancel: cancel})

	if !sm.CancelJob("scan-1") {
		t.Fatal("first cancel should succeed")
	}
	if sm.CancelJob("scan-1") {
		t.Fatal("second cancel should return false (already cancelling)")
	}
}

func TestUnregisterJob(t *testing.T) {
	sm := newTestManager()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sm.registerJob(&JobContext{ID: "scan-1", Ctx: ctx, Cancel: cancel})
	sm.unregisterJob("scan-1")
	if sm.GetJobContext("scan-1") != nil {
		t.Fatal("expected job to be unregistered")
	}
	if sm.activeJobCount() != 0 {
		t.Fatalf("activeJobCount = %d, want 0", sm.activeJobCount())
	}
}
