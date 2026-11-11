package scan

import (
	"context"
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
	options = cloneScanOptions(options)
	factory := NewScanToolFactory()
	factory.SetOptions(options)
	return &ScanManager{
		ctx: ctx, currentScanID: scanID, currentScanOptions: options,
		toolFactory: factory, workerPool: sm.workerPool,
		templateManager: sm.templateManager, scanUpdater: sm.scanUpdater,
		kvStore: sm.kvStore, apiBaseURL: sm.apiBaseURL,
		scopedIngestURL: sm.scopedIngestURL, subjectID: sm.subjectID,
		apiHTTPClient: sm.apiHTTPClient, logger: sm.logger,
	}
}

func (sm *ScanManager) newScanRun(scanID string) (*ScanManager, error) {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	var status string
	if err := sm.scanUpdater.UpdateForScan(sm.ctx, scanID, func(scan *store.ScanResult) error {
		status = scan.Status
		return nil
	}); err != nil {
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

// newKeyedRun never consults currentScan. The producer must create scan:<id>
// before publishing a keyed request; missing or mismatched state fails closed.
func (sm *ScanManager) newKeyedRun(scanID string) (*ScanManager, error) {
	return sm.newKeyedRunForSubject(scanID, "")
}

func (sm *ScanManager) newKeyedRunForSubject(scanID, subjectID string) (*ScanManager, error) {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	if sm.keyedRuns == nil {
		sm.keyedRuns = make(map[string]*ScanManager)
	}
	if _, exists := sm.keyedRuns[scanID]; exists {
		return nil, fmt.Errorf("scan is already active")
	}
	updater := &ScanUpdater{kvStore: sm.kvStore, keyed: true, subjectID: subjectID}
	var status string
	if err := updater.UpdateForScan(sm.ctx, scanID, func(scan *store.ScanResult) error { status = scan.Status; return nil }); err != nil {
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
	options := cloneScanOptions(sm.currentScanOptions)
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
