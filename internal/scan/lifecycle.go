package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

// These interfaces let lifecycle tests use only in-memory tools and log sinks.
type scanToolFactory interface {
	SetOptions(ScanOptions)
	CreateTool(string) ScanStrategy
	CreateFingerprintTool() FingerprintStrategy
}

type scanLogger interface {
	LogScanEvent(string, string, string, map[string]interface{})
	LogScanError(string, string, string, string, error)
	LogToolExecution(string, string, string, time.Duration, bool, map[string]interface{})
	LogHostDiscovered(string, string, map[string]interface{})
	LogVulnerabilityScan(string, string, []map[string]interface{}, string)
	LogScanStarted(string, []string, map[string]interface{})
	LogScanCompleted(string, map[string]interface{})
}

func cloneScanOptions(options ScanOptions) ScanOptions {
	options.ScanTypes = append([]string(nil), options.ScanTypes...)
	options.ExcludePorts = append([]string(nil), options.ExcludePorts...)
	options.FingerprintProbes = append([]string(nil), options.FingerprintProbes...)
	return options
}

// executionSnapshot deliberately does not copy mutexes or live coordinator
// state. A run's ID, options, factory and context never change after scheduling.
func (sm *ScanManager) executionSnapshot(ctx context.Context, scanID string, options ScanOptions) *ScanManager {
	plan := sm.admittedScanPlan
	plan.currentScanOptions = cloneScanOptions(options)
	factory := NewScanToolFactory()
	factory.SetOptions(cloneScanOptions(plan.currentScanOptions))
	return &ScanManager{
		ctx: ctx, currentScanID: scanID, admittedScanPlan: plan,
		toolFactory: factory, workerPool: sm.workerPool,
		scanUpdater: sm.scanUpdater,
		kvStore: sm.kvStore, apiBaseURL: sm.apiBaseURL,
		scopedIngestURL: sm.scopedIngestURL, subjectID: sm.subjectID,
		apiHTTPClient: sm.apiHTTPClient, logger: sm.logger,
	}
}

// initialScanResult is the state a queue job creates for itself when the
// producer did not pre-write any. Sub-scan progress is added by
// scheduleTargets once target expansion succeeds.
func initialScanResult(scanID string, targets []Target) store.ScanResult {
	values := make([]string, 0, len(targets))
	for _, target := range targets {
		values = append(values, target.Value)
	}
	return store.ScanResult{
		ID:              scanID,
		Status:          "running",
		Targets:         values,
		Hosts:           []store.HostEntry{},
		Vulnerabilities: []store.VulnerabilitySummary{},
		StartTime:       time.Now().Format(time.RFC3339),
	}
}

// admitLegacyState returns the authoritative status for scanID, creating
// state when the slot is empty or holds only a terminal scan. An active
// foreign scan still rejects the job: only a producer pre-write (which
// replaces the slot under the new ID) may supersede it.
func (sm *ScanManager) admitLegacyState(scanID string, targets []Target) (string, error) {
	initial := initialScanResult(scanID, targets)
	created, err := sm.scanUpdater.CreateInitial(sm.ctx, initial)
	if err != nil {
		return "", err
	}
	if created {
		return initial.Status, nil
	}
	for attempt := 0; attempt < maxScanUpdateAttempts; attempt++ {
		existing, raw, err := sm.scanUpdater.Peek(sm.ctx, scanID)
		if errors.Is(err, store.ErrKeyNotFound) {
			created, err := sm.scanUpdater.CreateInitial(sm.ctx, initial)
			if err != nil {
				return "", err
			}
			if created {
				return initial.Status, nil
			}
			continue
		}
		if err != nil {
			return "", err
		}
		if existing.ID == scanID {
			return existing.Status, nil
		}
		if !scanIsTerminal(existing.Status) {
			return "", ErrScanMismatch
		}
		swapped, err := sm.scanUpdater.ReplaceInitial(sm.ctx, raw, initial)
		if err != nil {
			return "", err
		}
		if swapped {
			return initial.Status, nil
		}
	}
	return "", ErrScanContention
}

// admitKeyedState returns the authoritative status for a keyed scan,
// creating scoped state from the envelope when absent. Pre-existing state
// keeps the fail-closed identity/scope validation of UpdateForScan, so a
// cancelling tombstone or a foreign scope is never adopted.
func admitKeyedState(ctx context.Context, updater *ScanUpdater, scanID string, targets []Target) (string, error) {
	initial := initialScanResult(scanID, targets)
	created, err := updater.CreateInitial(ctx, initial)
	if err != nil {
		return "", err
	}
	if created {
		return initial.Status, nil
	}
	var status string
	if err := updater.UpdateForScan(ctx, scanID, func(scan *store.ScanResult) error { status = scan.Status; return nil }); err != nil {
		return "", err
	}
	return status, nil
}

func (sm *ScanManager) newScanRun(scanID string) (*ScanManager, error) {
	return sm.newScanRunWithTargets(scanID, nil)
}

func (sm *ScanManager) newScanRunWithTargets(scanID string, targets []Target) (*ScanManager, error) {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	status, err := sm.admitLegacyState(scanID, targets)
	if err != nil {
		return nil, err
	}
	active := !scanIsTerminal(status) && status != "cancelling"
	if active && sm.currentScanID == scanID && sm.activeScanCtx != nil {
		return nil, fmt.Errorf("scan is already active")
	}
	if sm.activeScanCancel != nil {
		sm.activeScanCancel()
	}
	sm.currentScanID = scanID
	sm.activeScanCtx, sm.activeScanCancel = nil, nil
	// Even a replacement cancelled before dequeue supersedes the previous run.
	// No work has started for a cancelling request, so settle it now instead of
	// leaving it stuck until a delayed control command arrives.
	if status == "cancelling" {
		if _, err := sm.setScanStatus(scanID, "cancelled"); err != nil {
			return nil, err
		}
		sm.isCancelling = true
	}
	if !active {
		return nil, fmt.Errorf("scan is not active")
	}
	ctx, cancel := context.WithCancel(sm.ctx)
	sm.activeScanCtx, sm.activeScanCancel = ctx, cancel
	sm.isCancelling = false
	run := sm.executionSnapshot(ctx, scanID, ScanOptions{})
	run.cancel = cancel
	return run, nil
}

// newKeyedRun never consults currentScan. Missing scan:<id> state is
// created from the job itself; pre-existing state must still match the
// job's identity and scope or admission fails closed.
func (sm *ScanManager) newKeyedRun(scanID string) (*ScanManager, error) {
	return sm.newKeyedRunForSubject(scanID, "")
}

func (sm *ScanManager) newKeyedRunForSubject(scanID, subjectID string) (*ScanManager, error) {
	return sm.newKeyedRunForSubjectWithTargets(scanID, subjectID, nil)
}

func (sm *ScanManager) newKeyedRunForSubjectWithTargets(scanID, subjectID string, targets []Target) (*ScanManager, error) {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	if sm.keyedRuns == nil {
		sm.keyedRuns = make(map[string]*ScanManager)
	}
	if _, exists := sm.keyedRuns[scanID]; exists {
		return nil, fmt.Errorf("scan is already active")
	}
	updater := &ScanUpdater{kvStore: sm.kvStore, keyed: true, subjectID: subjectID}
	status, err := admitKeyedState(sm.ctx, updater, scanID, targets)
	if err != nil {
		return nil, err
	}
	if status == "cancelling" {
		run := &ScanManager{scanUpdater: updater}
		_, err := run.setScanStatus(scanID, "cancelled")
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("scan is not active")
	}
	if scanIsTerminal(status) {
		return nil, fmt.Errorf("scan is not active")
	}
	ctx, cancel := context.WithCancel(sm.ctx)
	run := sm.executionSnapshot(ctx, scanID, ScanOptions{})
	run.cancel, run.coordinator, run.scanUpdater = cancel, sm, updater
	run.subjectID = subjectID
	sm.keyedRuns[scanID] = run
	return run, nil
}

func (sm *ScanManager) finishKeyedRun() {
	if sm.coordinator == nil {
		return
	}
	c := sm.coordinator
	c.scanMutex.Lock()
	if c.keyedRuns[sm.currentScanID] == sm {
		delete(c.keyedRuns, sm.currentScanID)
	}
	c.scanMutex.Unlock()
	sm.cancel()
}

func (sm *ScanManager) cancelKeyedRun(scanID, subjectID string) {
	if scanID == "" {
		return
	}
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	run := sm.keyedRuns[scanID]
	if run != nil && run.subjectID != subjectID {
		return
	}
	updater := &ScanUpdater{kvStore: sm.kvStore, keyed: true, subjectID: subjectID}
	state := &ScanManager{scanUpdater: updater}
	if _, err := state.setScanStatus(scanID, "cancelled"); err != nil {
		return
	}
	if run != nil {
		run.cancel()
		delete(sm.keyedRuns, scanID)
	}
}

func (sm *ScanManager) forHostPorts(portList string) *ScanManager {
	options := sm.currentScanOptions
	if portList != "" {
		options.PortRange = portList
	}
	run := sm.executionSnapshot(sm.ctx, sm.currentScanID, options)
	run.cancel = sm.cancel
	return run
}

func scanIsTerminal(status string) bool {
	return status == "completed" || status == "failed" || status == "cancelled"
}

func finishScanIfDone(scan *store.ScanResult) {
	if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
		return
	}
	result := "completed"
	enabled := false
	for _, subScan := range scan.SubScans {
		if !subScan.Enabled {
			continue
		}
		enabled = true
		if !scanIsTerminal(subScan.Status) {
			return
		}
		if subScan.Status == "failed" {
			result = "failed"
		}
		if subScan.Status == "cancelled" && result != "failed" {
			result = "cancelled"
		}
	}
	if enabled {
		scan.Status = result
		scan.EndTime = time.Now().Format(time.RFC3339)
	}
}
