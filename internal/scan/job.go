package scan

import (
	"context"
	"sync"
)

// JobContext holds per-scan isolation state so concurrent jobs do not share
// options, cancel handles, or Valkey scratchpads.
type JobContext struct {
	ID             string
	OwnerSubjectID string
	Options        ScanOptions
	Ctx            context.Context
	Cancel         context.CancelFunc

	mu             sync.Mutex
	IsCancelling   bool
	HostsExpected  int
	HostsCompleted int
}

// IsOwned reports whether this job belongs to a Pro/class owner subject.
func (j *JobContext) IsOwned() bool {
	return j != nil && j.OwnerSubjectID != ""
}

// SetCancelling marks the job as cancelling under its mutex.
func (j *JobContext) SetCancelling() {
	if j == nil {
		return
	}
	j.mu.Lock()
	j.IsCancelling = true
	j.mu.Unlock()
}

// Cancelling reports whether the job is mid-cancel.
func (j *JobContext) Cancelling() bool {
	if j == nil {
		return false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.IsCancelling
}

// IncrementCompleted bumps completion accounting and returns (completed, expected).
func (j *JobContext) IncrementCompleted() (completed, expected int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.HostsCompleted++
	return j.HostsCompleted, j.HostsExpected
}

// registerJob adds a job to the manager registry. Replaces any prior entry with the same ID.
func (sm *ScanManager) registerJob(job *JobContext) {
	sm.jobsMu.Lock()
	defer sm.jobsMu.Unlock()
	if sm.jobs == nil {
		sm.jobs = make(map[string]*JobContext)
	}
	sm.jobs[job.ID] = job
}

// unregisterJob removes a job from the registry.
func (sm *ScanManager) unregisterJob(scanID string) {
	sm.jobsMu.Lock()
	defer sm.jobsMu.Unlock()
	delete(sm.jobs, scanID)
}

// GetJobContext returns the active JobContext for scanID, or nil if missing.
func (sm *ScanManager) GetJobContext(scanID string) *JobContext {
	sm.jobsMu.RLock()
	defer sm.jobsMu.RUnlock()
	if sm.jobs == nil {
		return nil
	}
	return sm.jobs[scanID]
}

// CancelJob cancels exactly the job identified by scanID.
// Missing IDs are ignored; a mismatched/wrong ID never cancels another job.
// Returns true if a cancel was initiated.
func (sm *ScanManager) CancelJob(scanID string) bool {
	if scanID == "" {
		return false
	}

	sm.jobsMu.RLock()
	job := sm.jobs[scanID]
	sm.jobsMu.RUnlock()
	if job == nil {
		return false
	}

	job.mu.Lock()
	if job.IsCancelling {
		job.mu.Unlock()
		return false
	}
	job.IsCancelling = true
	cancel := job.Cancel
	job.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return true
}

// ForceCancelJob force-cancels exactly the job identified by scanID.
// Unlike CancelJob, it proceeds even if IsCancelling is already set.
// Wrong/missing IDs never affect other jobs.
func (sm *ScanManager) ForceCancelJob(scanID string) bool {
	if scanID == "" {
		return false
	}

	sm.jobsMu.RLock()
	job := sm.jobs[scanID]
	sm.jobsMu.RUnlock()
	if job == nil {
		return false
	}

	job.mu.Lock()
	job.IsCancelling = true
	cancel := job.Cancel
	job.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	return true
}

// activeJobCount returns the number of registered jobs (for tests/diagnostics).
func (sm *ScanManager) activeJobCount() int {
	sm.jobsMu.RLock()
	defer sm.jobsMu.RUnlock()
	return len(sm.jobs)
}
