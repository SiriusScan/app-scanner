// main.go
package main

import (
	"fmt"
	"log"

	"github.com/SiriusScan/app-scanner/internal/scan"
	"github.com/SiriusScan/go-api/sirius/store"
)

func main() {
	fmt.Println("Scanner service is running...")

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

	// Begin listening for scan requests.
	scanManager.ListenForScans()

	// Block the main thread to keep the service running.
	select {}
}
