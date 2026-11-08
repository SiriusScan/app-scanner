package scan

import (
	"context"
	"log/slog"
	"sync"
)

// ScanTask represents a single scanning task
type ScanTask struct {
	IP      string
	Options ScanOptions
	run     *ScanManager
}

// WorkerPool manages a pool of scanner workers
type WorkerPool struct {
	numWorkers int
	tasks      chan ScanTask
	manager    *ScanManager
	wg         sync.WaitGroup
	enqueueMu  sync.RWMutex
	stopOnce   sync.Once
	stopping   chan struct{}
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(numWorkers int, manager *ScanManager) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		tasks:      make(chan ScanTask, 1000), // Buffer size for pending tasks
		manager:    manager,
		stopping:   make(chan struct{}),
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
	wp.stopOnce.Do(func() {
		// Wake blocked producers before waiting for their channel-send locks.
		close(wp.stopping)
		wp.enqueueMu.Lock()
		close(wp.tasks)
		wp.enqueueMu.Unlock()
	})
	wp.wg.Wait()
}

// AddTask accepts only tasks already bound to a scan run.
func (wp *WorkerPool) AddTask(task ScanTask) {
	if task.run != nil {
		wp.addTask(task.run.ctx, task)
	}
}

func (wp *WorkerPool) addTask(ctx context.Context, task ScanTask) bool {
	wp.enqueueMu.RLock()
	defer wp.enqueueMu.RUnlock()
	select {
	case <-wp.stopping:
		return false
	default:
	}
	if ctx.Err() != nil {
		return false
	}
	select {
	case wp.tasks <- task:
		return true
	case <-ctx.Done():
		return false
	case <-wp.stopping:
		return false
	}
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

			// Check if context is cancelled before processing
			if ctx.Err() != nil {
				slog.Debug("worker skipping task - context cancelled", "worker_id", id, "ip", task.IP)
				continue
			}

			// A queued task belongs to the run that created it, even after
			// cancellation or replacement. Never borrow a newer scan context.
			if task.run == nil || task.run.ctx.Err() != nil {
				continue
			}
			task.run.scanIP(task.run.ctx, task.IP)

		case <-ctx.Done():
			slog.Info("worker context cancelled", "worker_id", id)
			return
		}
	}
}
