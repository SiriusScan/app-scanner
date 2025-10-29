package scan

import (
	"context"
	"log"
	"sync"
)

// ScanTask represents a single scanning task
type ScanTask struct {
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

	log.Printf("Worker %d started", id)

	for {
		select {
		case task, ok := <-wp.tasks:
			if !ok {
				log.Printf("Worker %d shutting down", id)
				return
			}

			// Process the task
			wp.manager.scanIP(task.IP)

		case <-ctx.Done():
			log.Printf("Worker %d context cancelled", id)
			return
		}
	}
}
