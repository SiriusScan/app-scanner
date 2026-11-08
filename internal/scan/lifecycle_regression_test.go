package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

type memoryScanLogger struct {
	mu        sync.Mutex
	completed []string
	events    []string
}

func (l *memoryScanLogger) LogScanEvent(_ string, event string, _ string, _ map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
}
func (*memoryScanLogger) LogScanError(string, string, string, string, error) {}
func (*memoryScanLogger) LogToolExecution(string, string, string, time.Duration, bool, map[string]interface{}) {
}
func (*memoryScanLogger) LogHostDiscovered(string, string, map[string]interface{})              {}
func (*memoryScanLogger) LogVulnerabilityScan(string, string, []map[string]interface{}, string) {}
func (*memoryScanLogger) LogScanStarted(string, []string, map[string]interface{})               {}
func (l *memoryScanLogger) LogScanCompleted(id string, _ map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.completed = append(l.completed, id)
}

func encodeTestScan(t *testing.T, scan store.ScanResult) string {
	t.Helper()
	data, err := json.Marshal(scan)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(data)
}
func readTestScan(t *testing.T, kv store.KVStore) store.ScanResult {
	t.Helper()
	value, err := kv.GetValue(context.Background(), "currentScan")
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
	return scan
}
func activeTestScan(id string, total int) store.ScanResult {
	return store.ScanResult{ID: id, Status: "running", SubScans: map[string]store.SubScan{
		"network": {Type: "network", Enabled: true, Status: "running", Progress: store.SubScanProgress{Total: total}},
	}}
}
func testManager(t *testing.T, initial store.ScanResult) (*ScanManager, *fakeKVStore, *memoryScanLogger) {
	t.Helper()
	kv := &fakeKVStore{data: map[string]string{"currentScan": encodeTestScan(t, initial)}}
	logger := &memoryScanLogger{}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	manager := &ScanManager{ctx: ctx, cancel: cancel, currentScanID: initial.ID, scanUpdater: NewScanUpdater(kv), kvStore: kv, logger: logger, toolFactory: NewScanToolFactory()}
	manager.workerPool = NewWorkerPool(1, manager)
	return manager, kv, logger
}

func TestLifecycleRejectsStaleAndUntargetedCancellation(t *testing.T) {
	for _, force := range []bool{false, true} {
		for _, requested := range []string{"", "scan-old"} {
			t.Run(fmt.Sprintf("force=%t/id=%q", force, requested), func(t *testing.T) {
				sm, kv, _ := testManager(t, activeTestScan("scan-new", 1))
				ctx, cancel := context.WithCancel(sm.ctx)
				defer cancel()
				sm.activeScanCtx, sm.activeScanCancel = ctx, cancel
				before, _ := kv.GetValue(sm.ctx, "currentScan")
				if force {
					sm.ForceStopCurrentScan(requested)
				} else {
					sm.CancelCurrentScan(requested)
				}
				after, _ := kv.GetValue(sm.ctx, "currentScan")
				if ctx.Err() != nil || before.Message.Value != after.Message.Value {
					t.Fatal("stale command affected newer scan")
				}
			})
		}
	}
}
func TestLifecycleCancellationAndStaleRecoveryAreScoped(t *testing.T) {
	for _, active := range []bool{false, true} {
		sm, kv, _ := testManager(t, activeTestScan("scan-a", 1))
		if active {
			sm.activeScanCtx, sm.activeScanCancel = context.WithCancel(sm.ctx)
		} else {
			sm.currentScanID = ""
		}
		sm.CancelCurrentScan("scan-a")
		scan := readTestScan(t, kv)
		if scan.Status != "cancelled" || scan.EndTime == "" || scan.SubScans["network"].Status != "cancelled" {
			t.Fatalf("not cancelled: %+v", scan)
		}
		if active && sm.activeScanCtx.Err() == nil {
			t.Fatal("scan context still live")
		}
		sm.ForceStopCurrentScan("scan-a")
		if readTestScan(t, kv).EndTime != scan.EndTime {
			t.Fatal("repeat cancellation rewrote terminal time")
		}
	}
	sm, kv, _ := testManager(t, activeTestScan("scan-new", 1))
	sm.currentScanID = ""
	sm.clearStaleScanData("scan-old")
	if readTestScan(t, kv).Status != "running" {
		t.Fatal("stale recovery cancelled replacement")
	}
}
func TestLifecycleLateWorkerCannotChangeReplacement(t *testing.T) {
	sm, kv, logger := testManager(t, activeTestScan("scan-new", 1))
	sm.currentScanID = "scan-old"
	before, _ := kv.GetValue(sm.ctx, "currentScan")
	if err := sm.markHostComplete("192.0.2.1"); !errors.Is(err, ErrScanMismatch) {
		t.Fatalf("got %v", err)
	}
	sm.updateScanStatus("failed")
	after, _ := kv.GetValue(sm.ctx, "currentScan")
	if before.Message.Value != after.Message.Value || len(logger.completed) != 0 {
		t.Fatal("late worker changed replacement")
	}
}
func TestLifecycleCompletionAggregatesSubscanOutcomes(t *testing.T) {
	for _, other := range []string{"running", "completed", "failed", "cancelled", "cancelling"} {
		t.Run(other, func(t *testing.T) {
			scan := activeTestScan("scan-a", 1)
			scan.SubScans["agent"] = store.SubScan{Enabled: true, Status: other}
			sm, kv, logger := testManager(t, scan)
			if err := sm.markHostComplete("192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			got := readTestScan(t, kv)
			want := other
			if other == "cancelling" {
				want = "running"
			}
			if got.Status != want {
				t.Fatalf("status=%s want=%s", got.Status, want)
			}
			if (len(logger.completed) == 1) != (want == "completed") {
				t.Fatal("false overall success event")
			}
			if got.SubScans["network"].Status != "completed" {
				t.Fatal("network not complete")
			}
		})
	}
}
func TestLifecycleWaitsForFullTargetSetAndDoesNotDoubleComplete(t *testing.T) {
	sm, kv, logger := testManager(t, activeTestScan("scan-a", 2))
	if err := sm.markHostComplete("192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if readTestScan(t, kv).Status != "running" {
		t.Fatal("premature completion")
	}
	if err := sm.markHostComplete("192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	final := readTestScan(t, kv)
	if err := sm.markHostComplete("192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	got := readTestScan(t, kv)
	if got.Status != "completed" || got.HostsCompleted != 2 || got.EndTime != final.EndTime || len(logger.completed) != 1 {
		t.Fatalf("unexpected final scan: %+v", got)
	}
}
func TestLifecycleAllTargetsPreparedBeforeScheduling(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-a", 0))
	ips, err := sm.prepareScanTargets([]Target{{Value: "192.0.2.1", Type: SingleIP}, {Value: "192.0.2.1", Type: SingleIP}, {Value: "192.0.2.2", Type: SingleIP}})
	if err != nil || len(ips) != 2 {
		t.Fatalf("ips=%v err=%v", ips, err)
	}
	sm.scheduleTargets(ips)
	if readTestScan(t, kv).SubScans["network"].Progress.Total != 2 {
		t.Fatal("full total missing before tasks start")
	}
	for i := 0; i < 2; i++ {
		task := <-sm.workerPool.tasks
		if task.run != sm {
			t.Fatal("task lost original run")
		}
	}
	if _, err := sm.prepareScanTargets([]Target{{Value: "192.0.2.1", Type: SingleIP}, {Value: "*.example.test", Type: DNSWildcard}}); err == nil {
		t.Fatal("invalid later target accepted")
	}
	if len(sm.workerPool.tasks) != 0 {
		t.Fatal("partially prepared request queued work")
	}
}
func TestLifecycleRunAndHostOptionsStayIsolated(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-a", 1))
	sm.currentScanID = ""
	a, err := sm.newScanRun("scan-a")
	if err != nil {
		t.Fatal(err)
	}
	a.currentScanOptions = ScanOptions{PortRange: "80", ScanTypes: []string{"vulnerability"}, ExcludePorts: []string{"22"}, FingerprintProbes: []string{"icmp"}}
	a.toolFactory.SetOptions(a.currentScanOptions)
	if _, err := sm.newScanRun("scan-a"); err == nil {
		t.Fatal("duplicate active scan accepted")
	}
	kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, activeTestScan("scan-b", 1)))
	b, err := sm.newScanRun("scan-b")
	if err != nil {
		t.Fatal(err)
	}
	b.currentScanOptions = ScanOptions{PortRange: "443"}
	if a.ctx.Err() == nil || b.ctx.Err() != nil || a.currentScanID != "scan-a" || a.currentScanOptions.PortRange != "80" {
		t.Fatal("replacement changed old run identity/options")
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			host := a.forHostPorts(fmt.Sprint(8000 + i))
			host.currentScanOptions.ScanTypes[0] = "changed"
			if host.toolFactory.CreateTool("vulnerability").(*NmapStrategy).PortRange != fmt.Sprint(8000+i) {
				t.Error("host port cross-talk")
			}
		}(i)
	}
	wg.Wait()
	if a.currentScanOptions.PortRange != "80" || a.currentScanOptions.ScanTypes[0] != "vulnerability" {
		t.Fatal("host changed shared options")
	}
}
func TestLifecycleCancelledQueuedTaskNeverBorrowsNewContext(t *testing.T) {
	sm, kv, logger := testManager(t, activeTestScan("scan-new", 1))
	oldCtx, cancel := context.WithCancel(sm.ctx)
	cancel()
	old := sm.executionSnapshot(oldCtx, "scan-old", ScanOptions{})
	current := sm.executionSnapshot(sm.ctx, "scan-new", ScanOptions{})
	sm.workerPool.tasks <- ScanTask{IP: "192.0.2.1", run: old}
	sm.workerPool.tasks <- ScanTask{IP: "192.0.2.2", run: current}
	// Both use empty fake profiles, so no real scanning or API calls occur.
	sm.workerPool.Start(sm.ctx)
	sm.workerPool.Stop()
	if got := readTestScan(t, kv); got.HostsCompleted != 1 || got.Status != "completed" {
		t.Fatalf("unexpected scan: %+v", got)
	}
	if len(logger.completed) != 1 || logger.completed[0] != "scan-new" {
		t.Fatal("old task completed newer run")
	}
}
func TestLifecycleConcurrentStartAndStaleControls(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-new", 1))
	sm.currentScanID = ""
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(2)
		go func() { defer wg.Done(); sm.newScanRun("scan-new") }()
		go func() {
			defer wg.Done()
			sm.ForceStopCurrentScan("scan-old")
			sm.GetActiveScanContext()
			sm.IsCancelling()
		}()
	}
	wg.Wait()
	if sm.GetActiveScanContext() == nil || sm.GetActiveScanContext().Err() != nil || readTestScan(t, kv).Status != "running" {
		t.Fatal("stale control stopped active run")
	}
}

type contendedStore struct {
	*fakeKVStore
	once           sync.Once
	beforeCAS      func()
	alwaysConflict bool
	attempts       int
}

func (s *contendedStore) CompareAndSetValue(ctx context.Context, key, expected, value string) (bool, error) {
	s.attempts++
	s.once.Do(func() {
		if s.beforeCAS != nil {
			s.beforeCAS()
		}
	})
	if s.alwaysConflict {
		return false, nil
	}
	return s.fakeKVStore.CompareAndSetValue(ctx, key, expected, value)
}
func TestLifecycleCASRevalidatesReplacementAndCancellation(t *testing.T) {
	for _, change := range []string{"replacement", "cancelled", "progress"} {
		t.Run(change, func(t *testing.T) {
			sm, kv, logger := testManager(t, activeTestScan("scan-a", 1))
			conflict := &contendedStore{fakeKVStore: kv}
			conflict.beforeCAS = func() {
				scan := readTestScan(t, kv)
				switch change {
				case "replacement":
					scan.ID = "scan-b"
				case "cancelled":
					scan.Status = "cancelled"
				case "progress":
					scan.SubScans["agent"] = store.SubScan{Enabled: true, Status: "running"}
				}
				kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, scan))
			}
			sm.scanUpdater = NewScanUpdater(conflict)
			err := sm.markHostComplete("192.0.2.1")
			got := readTestScan(t, kv)
			if change == "replacement" {
				if !errors.Is(err, ErrScanMismatch) || got.ID != "scan-b" || got.HostsCompleted != 0 {
					t.Fatalf("stale write: %+v / %v", got, err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			if change == "cancelled" && (got.Status != "cancelled" || got.HostsCompleted != 0) {
				t.Fatal("overwrote cancellation")
			}
			if change == "progress" && (got.Status != "running" || got.SubScans["agent"].Status != "running" || got.HostsCompleted != 1) {
				t.Fatal("lost concurrent progress")
			}
			if len(logger.completed) != 0 {
				t.Fatal("success logged before successful CAS")
			}
		})
	}
}
func TestLifecycleCASContentionIsBounded(t *testing.T) {
	_, kv, _ := testManager(t, activeTestScan("scan-a", 1))
	conflict := &contendedStore{fakeKVStore: kv, alwaysConflict: true}
	err := NewScanUpdater(conflict).UpdateForScan(context.Background(), "scan-a", func(scan *store.ScanResult) error { scan.HostsCompleted++; return nil })
	if !errors.Is(err, ErrScanContention) || conflict.attempts != maxScanUpdateAttempts || readTestScan(t, kv).HostsCompleted != 0 {
		t.Fatalf("unexpected contention result: %v / %d", err, conflict.attempts)
	}
}
func TestLifecycleUpdaterPreservesCorruptAndUnknownState(t *testing.T) {
	for _, raw := range []string{"not base64", base64.StdEncoding.EncodeToString([]byte("null")), base64.StdEncoding.EncodeToString([]byte("{bad")), base64.StdEncoding.EncodeToString([]byte("[]"))} {
		kv := &fakeKVStore{data: map[string]string{"currentScan": raw}}
		called := false
		err := NewScanUpdater(kv).UpdateForScan(context.Background(), "scan-a", func(*store.ScanResult) error { called = true; return nil })
		if err == nil || called || kv.data["currentScan"] != raw {
			t.Fatalf("corrupt state was modified: %v", err)
		}
	}
	raw := base64.StdEncoding.EncodeToString([]byte(`{"id":"scan-a","status":"running","future_field":{"keep":true}}`))
	kv := &fakeKVStore{data: map[string]string{"currentScan": raw}}
	err := NewScanUpdater(kv).UpdateForScan(context.Background(), "scan-a", func(scan *store.ScanResult) error { scan.Status = "cancelled"; return nil })
	if err != nil {
		t.Fatal(err)
	}
	data, _ := base64.StdEncoding.DecodeString(kv.data["currentScan"])
	var fields map[string]json.RawMessage
	json.Unmarshal(data, &fields)
	if string(fields["future_field"]) != `{"keep":true}` {
		t.Fatal("unknown field lost")
	}
}
func TestLifecycleCASConcurrentUpdatersDoNotLoseProgress(t *testing.T) {
	_, kv, _ := testManager(t, activeTestScan("scan-a", 100))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			updater := NewScanUpdater(kv)
			for j := 0; j < 25; j++ {
				for {
					err := updater.UpdateForScan(context.Background(), "scan-a", func(scan *store.ScanResult) error { scan.HostsCompleted++; return nil })
					if errors.Is(err, ErrScanContention) {
						continue
					}
					if err != nil {
						t.Error(err)
					}
					break
				}
			}
		}()
	}
	wg.Wait()
	if readTestScan(t, kv).HostsCompleted != 100 {
		t.Fatal("lost concurrent progress")
	}
}

func TestLifecycleCancelledReplacementStopsPreviousRun(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-a", 1))
	sm.currentScanID = ""
	old, err := sm.newScanRun("scan-a")
	if err != nil {
		t.Fatal(err)
	}
	replacement := activeTestScan("scan-b", 1)
	replacement.Status = "cancelled"
	kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, replacement))
	if _, err := sm.newScanRun("scan-b"); err == nil {
		t.Fatal("cancelled replacement started")
	}
	if old.ctx.Err() == nil {
		t.Fatal("old run continued after cancelled replacement")
	}
	if readTestScan(t, kv).Status != "cancelled" {
		t.Fatal("replacement cancellation lost")
	}
}
func TestLifecycleWorkerPoolStopUnblocksProducers(t *testing.T) {
	sm, _, _ := testManager(t, activeTestScan("scan-a", 1))
	// No workers run. Fill the buffer so every producer must wait or stop.
	for i := 0; i < cap(sm.workerPool.tasks); i++ {
		sm.workerPool.tasks <- ScanTask{}
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sm.workerPool.addTask(sm.ctx, ScanTask{run: sm}) {
				t.Error("queued into stopped full pool")
			}
		}()
	}
	sm.workerPool.Stop()
	sm.workerPool.Stop()
	wg.Wait()
	if sm.workerPool.addTask(sm.ctx, ScanTask{run: sm}) {
		t.Fatal("accepted task after stop")
	}
}

type failingTestFactory struct{ ctx context.Context }

func (*failingTestFactory) SetOptions(ScanOptions)                       {}
func (f *failingTestFactory) CreateTool(string) ScanStrategy             { return f }
func (f *failingTestFactory) CreateFingerprintTool() FingerprintStrategy { return f }
func (f *failingTestFactory) Execute(string) (sirius.Host, error)        { panic("context-free tool call") }
func (f *failingTestFactory) ExecuteWithContext(ctx context.Context, _ string) (sirius.Host, error) {
	f.ctx = ctx
	return sirius.Host{}, errors.New("fixture tool failure")
}
func (f *failingTestFactory) Fingerprint(string) (FingerprintResult, error) {
	panic("context-free fingerprint call")
}
func (f *failingTestFactory) FingerprintWithContext(ctx context.Context, _ string) (FingerprintResult, error) {
	f.ctx = ctx
	return FingerprintResult{}, errors.New("fixture fingerprint failure")
}
func TestLifecycleToolFailuresCannotCompleteSuccessfully(t *testing.T) {
	for _, scanType := range []string{"fingerprint", "enumeration"} {
		t.Run(scanType, func(t *testing.T) {
			sm, kv, logger := testManager(t, activeTestScan("scan-a", 1))
			factory := &failingTestFactory{}
			sm.toolFactory = factory
			sm.currentScanOptions = ScanOptions{ScanTypes: []string{scanType}}
			sm.scanIP(sm.ctx, "192.0.2.1")
			scan := readTestScan(t, kv)
			if factory.ctx != sm.ctx || sm.ctx.Err() == nil || scan.Status != "failed" || scan.SubScans["network"].Status != "failed" || len(logger.completed) != 0 {
				t.Fatalf("failure did not stop run: %+v", scan)
			}
		})
	}
}
func TestLifecycleInvalidRequestsNeverQueuePartialWork(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-a", 0))
	sm.currentScanID = ""
	msg := ScanMessage{ID: "scan-a", Priority: 1, Targets: []Target{{Value: "192.0.2.1", Type: SingleIP}, {Value: "*.example.test", Type: DNSWildcard}}}
	raw, _ := json.Marshal(msg)
	sm.handleMessage(string(raw))
	if readTestScan(t, kv).Status != "failed" || len(sm.workerPool.tasks) != 0 {
		t.Fatal("invalid target queued partial work or stayed running")
	}
	sm2, kv2, _ := testManager(t, activeTestScan("scan-b", 0))
	sm2.currentScanID = ""
	msg = ScanMessage{ID: "scan-old", Priority: 0}
	raw, _ = json.Marshal(msg)
	sm2.handleMessage(string(raw))
	if readTestScan(t, kv2).Status != "running" {
		t.Fatal("invalid stale request failed replacement")
	}
}

func TestLifecycleNetworkFailureWaitsForOtherScanners(t *testing.T) {
	for _, agentStatus := range []string{"pending", "running", "dispatching"} {
		t.Run(agentStatus, func(t *testing.T) {
			initial := activeTestScan("scan-a", 1)
			initial.SubScans["agent"] = store.SubScan{Type: "agent", Enabled: true, Status: agentStatus}
			sm, kv, logger := testManager(t, initial)
			sm.currentScanOptions = ScanOptions{ScanTypes: []string{"enumeration"}}
			sm.toolFactory = &failingTestFactory{}
			sm.scanIP(sm.ctx, "192.0.2.1")
			pending := readTestScan(t, kv)
			if pending.Status != "running" || pending.EndTime != "" || pending.SubScans["network"].Status != "failed" || pending.SubScans["agent"].Status != agentStatus || sm.ctx.Err() == nil {
				t.Fatalf("network failure blocked other scanner: %+v", pending)
			}
			// Model the other scanner's later CAS merge. Its terminal guard
			// must still admit the result and the final outcome must be failed.
			err := sm.scanUpdater.UpdateForScan(context.Background(), "scan-a", func(scan *store.ScanResult) error {
				if scanIsTerminal(scan.Status) {
					return errors.New("agent callback rejected by global terminal status")
				}
				agent := scan.SubScans["agent"]
				agent.Status = "completed"
				scan.SubScans["agent"] = agent
				scan.Hosts = append(scan.Hosts, store.HostEntry{ID: "192.0.2.2", IP: "192.0.2.2", Sources: []string{"agent"}})
				finishScanIfDone(scan)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			final := readTestScan(t, kv)
			if final.Status != "failed" || final.EndTime == "" || len(final.Hosts) != 1 || len(logger.completed) != 0 {
				t.Fatalf("lost agent results or false success: %+v", final)
			}
		})
	}
}

func TestLifecycleCancelsAuthoritativeAgentOnlyScanAfterNetworkRun(t *testing.T) {
	for _, force := range []bool{false, true} {
		t.Run(fmt.Sprintf("force=%t", force), func(t *testing.T) {
			sm, kv, _ := testManager(t, activeTestScan("network-old", 1))
			oldCtx, cancel := context.WithCancel(sm.ctx)
			defer cancel()
			sm.activeScanCtx, sm.activeScanCancel = oldCtx, cancel
			current := store.ScanResult{ID: "agent-new", Status: "cancelling", SubScans: map[string]store.SubScan{
				"network": {Enabled: false, Status: "pending"}, "agent": {Enabled: true, Status: "running"},
			}}
			kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, current))
			if force {
				sm.ForceStopCurrentScan("agent-new")
			} else {
				sm.CancelCurrentScan("agent-new")
			}
			got := readTestScan(t, kv)
			if got.ID != "agent-new" || got.Status != "cancelled" || got.EndTime == "" || oldCtx.Err() == nil {
				t.Fatalf("agent-only scan not cancelled: %+v", got)
			}
			if sm.GetActiveScanContext() != nil {
				t.Fatal("new agent scan borrowed obsolete network context")
			}
		})
	}
}
func TestLifecycleCancelsNewNetworkScanBeforeDequeue(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-old", 1))
	oldCtx, cancel := context.WithCancel(sm.ctx)
	defer cancel()
	sm.activeScanCtx, sm.activeScanCancel = oldCtx, cancel
	current := activeTestScan("scan-new", 1)
	current.Status = "cancelling"
	kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, current))
	sm.CancelCurrentScan("scan-new")
	if _, err := sm.newScanRun("scan-new"); err == nil {
		t.Fatal("cancelled queued scan started")
	}
	if got := readTestScan(t, kv); got.Status != "cancelled" || oldCtx.Err() == nil || len(sm.workerPool.tasks) != 0 {
		t.Fatalf("queued cancellation stuck: %+v", got)
	}
}
func TestLifecycleDequeueSettlesCancellingScanWithoutControl(t *testing.T) {
	for _, sameID := range []bool{false, true} {
		t.Run(fmt.Sprintf("sameID=%t", sameID), func(t *testing.T) {
			sm, kv, _ := testManager(t, activeTestScan("scan-old", 1))
			oldCtx, cancel := context.WithCancel(sm.ctx)
			defer cancel()
			sm.activeScanCtx, sm.activeScanCancel = oldCtx, cancel
			id := "scan-new"
			if sameID {
				id = "scan-old"
			}
			current := activeTestScan(id, 1)
			current.Status = "cancelling"
			kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, current))
			if _, err := sm.newScanRun(id); err == nil {
				t.Fatal("cancelling scan started")
			}
			if got := readTestScan(t, kv); got.Status != "cancelled" || oldCtx.Err() == nil {
				t.Fatalf("dequeue did not settle cancellation: %+v", got)
			}
		})
	}
}
func TestLifecycleCancellationRevalidatesAuthoritativeReplacement(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-old", 1))
	oldCtx, cancel := context.WithCancel(sm.ctx)
	defer cancel()
	sm.activeScanCtx, sm.activeScanCancel = oldCtx, cancel
	kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, activeTestScan("scan-new", 1)))
	conflict := &contendedStore{fakeKVStore: kv, beforeCAS: func() { kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, activeTestScan("scan-newer", 1))) }}
	sm.scanUpdater = NewScanUpdater(conflict)
	sm.CancelCurrentScan("scan-new")
	if got := readTestScan(t, kv); got.ID != "scan-newer" || got.Status != "running" || oldCtx.Err() != nil {
		t.Fatalf("stale authoritative cancellation affected replacement or unrelated context: %+v", got)
	}
}
func TestLifecycleStaleLocalCancellationCannotModifyNewerState(t *testing.T) {
	sm, kv, _ := testManager(t, activeTestScan("scan-old", 1))
	oldCtx, cancel := context.WithCancel(sm.ctx)
	defer cancel()
	sm.activeScanCtx, sm.activeScanCancel = oldCtx, cancel
	kv.SetValue(sm.ctx, "currentScan", encodeTestScan(t, activeTestScan("scan-new", 1)))
	sm.CancelCurrentScan("scan-old")
	if got := readTestScan(t, kv); got.ID != "scan-new" || got.Status != "running" || oldCtx.Err() == nil {
		t.Fatalf("local cancellation touched newer state: %+v", got)
	}
}

func TestLifecycleCancellationDoesNotMisreportTerminalOutcomes(t *testing.T) {
	for _, status := range []string{"completed", "failed", "cancelled"} {
		t.Run(status, func(t *testing.T) {
			initial := activeTestScan("scan-new", 1)
			initial.Status = status
			sm, kv, logger := testManager(t, initial)
			sm.currentScanID = "scan-old"
			sm.CancelCurrentScan("scan-new")
			if got := readTestScan(t, kv); got.Status != status || len(logger.events) != 0 {
				t.Fatalf("terminal outcome changed or cancellation falsely logged: %+v / %v", got, logger.events)
			}
		})
	}
}

func TestLifecycleCancellationRetriesUnsettledWrite(t *testing.T) {
	sm, kv, logger := testManager(t, activeTestScan("scan-a", 1))
	sm.activeScanCtx, sm.activeScanCancel = context.WithCancel(sm.ctx)
	conflict := &contendedStore{fakeKVStore: kv, alwaysConflict: true}
	sm.scanUpdater = NewScanUpdater(conflict)
	sm.CancelCurrentScan("scan-a")
	if readTestScan(t, kv).Status != "running" || sm.activeScanCtx.Err() == nil || len(logger.events) != 0 {
		t.Fatal("failed persistence misreported cancellation")
	}
	conflict.alwaysConflict = false
	sm.CancelCurrentScan("scan-a")
	if readTestScan(t, kv).Status != "cancelled" || len(logger.events) != 1 || logger.events[0] != "scan_cancelled" {
		t.Fatal("repeat cancellation did not settle previous failed write")
	}
}
