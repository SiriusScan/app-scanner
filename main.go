// main.go
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/SiriusScan/app-scanner/internal/scan"
	"github.com/SiriusScan/go-api/sirius/store"
)

func main() {
	fmt.Println("🚀 Scanner service is starting...")

	// Create a new KVStore.
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("Error creating KV store: %v", err)
	}
	defer kvStore.Close()

	// Instantiate the scan tool factory.
	toolFactory := &scan.ScanToolFactory{}

	// Create the scan updater for KV store updates.
	scanUpdater := scan.NewScanUpdater(kvStore)

	// Create the scan manager.
	scanManager := scan.NewScanManager(kvStore, toolFactory, scanUpdater)

	// Begin listening for scan requests in a goroutine.
	go scanManager.ListenForScans()

	// Begin listening for cancel commands in a goroutine.
	go scanManager.ListenForCancelCommands()

	fmt.Println("✅ Scanner service is running")
	fmt.Println("   - Listening for scan requests on queue 'scan'")
	fmt.Println("   - Listening for control commands on queue 'scan_control'")

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	// Wait for shutdown signal
	sig := <-sigChan
	log.Printf("🛑 Received signal %v, initiating graceful shutdown...", sig)

	// Gracefully shut down the scan manager
	log.Println("Shutting down scan manager...")
	scanManager.Shutdown()

	log.Println("✅ Scanner service stopped gracefully")
}
