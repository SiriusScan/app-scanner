package scan

import (
	"context"
	"log/slog"
	"sync"
)

// ScanTask represents a single scanning task
type ScanTask struct {
	ScanID  string
	IP      string
	Options ScanOptions
}

// WorkerPool manages a pool of scanner workers
type WorkerPool struct {
	numWorkers int
	tasks      chan ScanTask
	manager    *ScanManager
	wg         sync.WaitGroup
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, manager *ScanManager) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		tasks:      make(chan ScanTask, 1000), // Buffer size for pending tasks
		manager:    manager,
	}
}

// Start initializes and starts the worker pool
func (wp *WorkerPool) Start(ctx context.Context) {
	// Start the workers
	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker(ctx, i)
	}
}

// Stop gracefully shuts down the worker pool
func (wp *WorkerPool) Stop() {
	close(wp.tasks)
	wp.wg.Wait()
}

// AddTask adds a new scanning task to the pool
func (wp *WorkerPool) AddTask(task ScanTask) {
	wp.tasks <- task
}

// worker processes tasks from the pool
func (wp *WorkerPool) worker(ctx context.Context, id int) {
	defer wp.wg.Done()

	slog.Info("worker started", "worker_id", id)

	for {
		select {
		case task, ok := <-wp.tasks:
			if !ok {
				slog.Info("worker shutting down", "worker_id", id)
				return
			}

			// Check if pool context is cancelled before processing
			if ctx.Err() != nil {
				slog.Debug("worker skipping task - context cancelled", "worker_id", id, "ip", task.IP)
				continue
			}

			// Prefer per-job context; fall back to pool context.
			scanCtx := ctx
			if task.ScanID != "" {
				if job := wp.manager.GetJobContext(task.ScanID); job != nil {
					if job.Ctx != nil {
						scanCtx = job.Ctx
					}
				} else {
					slog.Debug("worker skipping task - job not found",
						"worker_id", id, "scan_id", task.ScanID, "ip", task.IP)
					continue
				}
			} else if active := wp.manager.GetActiveScanContext(); active != nil {
				scanCtx = active
			}

			wp.manager.scanIP(scanCtx, task.ScanID, task.IP)

		case <-ctx.Done():
			slog.Info("worker context cancelled", "worker_id", id)
			return
		}
	}
}
