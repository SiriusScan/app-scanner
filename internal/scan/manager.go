package scan

import (
	"context"
	"encoding/json"
	"log"
	"strings"

	"github.com/SiriusScan/go-api/sirius/host"
	"github.com/SiriusScan/go-api/sirius/queue"
	"github.com/SiriusScan/go-api/sirius/store"
)

// ScanMessage represents the incoming scan request message.
type ScanMessage struct {
	Message string `json:"message"`
}

// ScanManager manages incoming scan requests and processes targets.
type ScanManager struct {
	kvStore     store.KVStore
	toolFactory *ScanToolFactory
	scanUpdater *ScanUpdater
}

// NewScanManager initializes a new ScanManager.
func NewScanManager(kv store.KVStore, factory *ScanToolFactory, updater *ScanUpdater) *ScanManager {
	return &ScanManager{
		kvStore:     kv,
		toolFactory: factory,
		scanUpdater: updater,
	}
}

// ListenForScans attaches the ScanManager to the "scan" queue.
func (sm *ScanManager) ListenForScans() {
	queue.Listen("scan", sm.handleMessage)
}

// handleMessage unmarshals the incoming message and launches processing.
func (sm *ScanManager) handleMessage(msg string) {
	log.Printf("Received scan request: %s", msg)

	var scanMsg ScanMessage
	if err := json.Unmarshal([]byte(msg), &scanMsg); err != nil {
		log.Printf("Invalid scan message: %v", err)
		return
	}

	// Convert comma-separated targets into a slice.
	targets := strings.Split(scanMsg.Message, ",")
	for _, target := range targets {
		trimmedTarget := strings.TrimSpace(target)
		go sm.processTarget(trimmedTarget)
	}
}

// processTarget runs the discovery scan followed by a vulnerability scan.
func (sm *ScanManager) processTarget(target string) {
	log.Printf("Processing target: %s", target)

	// ----------------------------
	// Discovery Phase.
	// ----------------------------
	discoveryStrategy := sm.toolFactory.CreateTool("discovery")
	discoveryResults, err := discoveryStrategy.Execute(target)
	if err != nil {
		log.Printf("Discovery scan failed for %s: %v", target, err)
		return
	}

	// Add discovered host to the database.
	if err := host.AddHost(discoveryResults); err != nil {
		log.Printf("Failed to add host %s: %v", discoveryResults.IP, err)
	}

	// Update KV store with the discovered host.
	if err := sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
		scan.Hosts = append(scan.Hosts, discoveryResults.IP)
		return nil
	}); err != nil {
		log.Printf("Failed to update scan with discovered host %s: %v", discoveryResults.IP, err)
	}

	// ----------------------------
	// Vulnerability Phase.
	// ----------------------------
	vulnStrategy := sm.toolFactory.CreateTool("vulnerability")
	vulnResults, err := vulnStrategy.Execute(discoveryResults.IP)
	if err != nil {
		log.Printf("Vulnerability scan failed for %s: %v", discoveryResults.IP, err)
		return
	}

	// Update host with vulnerability information.
	if err := host.AddHost(vulnResults); err != nil {
		log.Printf("Failed to update vulnerability info for %s: %v", vulnResults.IP, err)
		return
	}

	// Update KV store with vulnerability details.
	if err := sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
		scan.HostsCompleted++
		for _, vuln := range vulnResults.Vulnerabilities {
			severity := calculateSeverity(vuln.RiskScore)
			scan.Vulnerabilities = append(scan.Vulnerabilities, store.VulnerabilitySummary{
				ID:          vuln.VID,
				Severity:    severity,
				Title:       vuln.Title,
				Description: vuln.Description,
			})
		}
		return nil
	}); err != nil {
		log.Printf("Failed to update scan with vulnerabilities for host %s: %v", vulnResults.IP, err)
		return
	}

	log.Printf("Scan complete for target: %s", target)
}
