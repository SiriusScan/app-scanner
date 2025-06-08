package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/host"
	"github.com/SiriusScan/go-api/sirius/postgres"
	"github.com/SiriusScan/go-api/sirius/queue"
	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/vulnerability"
)

// Default number of worker goroutines
const DEFAULT_WORKERS = 10

// TargetType represents the type of scan target
type TargetType string

const (
	SingleIP    TargetType = "single_ip"
	IPRange     TargetType = "ip_range"
	CIDR        TargetType = "cidr"
	DNSName     TargetType = "dns_name"
	DNSWildcard TargetType = "dns_wildcard"
)

// Target represents a single scan target with its configuration
type Target struct {
	Value   string     `json:"value"`
	Type    TargetType `json:"type"`
	Timeout int        `json:"timeout,omitempty"` // Optional timeout in seconds
}

// Update ScanOptions struct to include all template fields
type ScanOptions struct {
	Template     ScanTemplate `json:"template"`      // Scan template to use
	PortRange    string       `json:"port_range"`    // Port range to scan
	Aggressive   bool         `json:"aggressive"`    // Whether to use aggressive scanning
	ExcludePorts []string     `json:"exclude_ports"` // Ports to exclude
	ScanTypes    []string     `json:"scan_types"`    // Types of scans to perform
	MaxRetries   int          `json:"max_retries"`   // Maximum number of retries
	Parallel     bool         `json:"parallel"`      // Whether to scan targets in parallel
}

// ScanMessage represents the incoming scan request message
type ScanMessage struct {
	ID          string      `json:"id"`           // Unique identifier for this scan
	Targets     []Target    `json:"targets"`      // List of targets to scan
	Options     ScanOptions `json:"options"`      // Scan configuration options
	Priority    int         `json:"priority"`     // Scan priority (1-5)
	CallbackURL string      `json:"callback_url"` // Optional webhook for scan completion
}

// ScanManager manages scan operations.
type ScanManager struct {
	workerPool         *WorkerPool
	ctx                context.Context
	cancel             context.CancelFunc
	currentScanID      string
	currentScanOptions ScanOptions
	nseSync            *nse.SyncManager
	scanStrategies     map[string]ScanStrategy
	options            *ScanOptions
	toolFactory        *ScanToolFactory
	scanUpdater        *ScanUpdater
	kvStore            store.KVStore
}

// NewScanManager creates a new ScanManager.
func NewScanManager(kvStore store.KVStore, toolFactory *ScanToolFactory, updater *ScanUpdater) *ScanManager {
	// Create a context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize NSE repository manager
	repoManager := nse.NewRepoManager("/opt/sirius/nse/sirius-nse", nse.NSERepoURL)

	// Initialize NSE sync manager
	syncManager := nse.NewSyncManager(repoManager, kvStore)

	sm := &ScanManager{
		kvStore:     kvStore,
		toolFactory: toolFactory,
		scanUpdater: updater,
		ctx:         ctx,
		cancel:      cancel,
		nseSync:     syncManager,
		scanStrategies: map[string]ScanStrategy{
			"discovery": &RustScanStrategy{},
			"nmap":      &NmapStrategy{},
		},
	}

	// Create and start the worker pool with 10 workers
	sm.workerPool = NewWorkerPool(DEFAULT_WORKERS, sm)
	sm.workerPool.Start(ctx)

	return sm
}

// ListenForScans attaches the ScanManager to the "scan" queue.
func (sm *ScanManager) ListenForScans() {
	// Sync NSE scripts before starting to listen for scans
	if err := sm.nseSync.Sync(sm.ctx); err != nil {
		log.Printf("Warning: failed to sync NSE scripts: %v", err)
	}

	queue.Listen("scan", sm.handleMessage)
}

// Update handleMessage to use DefaultTemplates
func (sm *ScanManager) handleMessage(msg string) {
	var scanMsg ScanMessage
	if err := json.Unmarshal([]byte(msg), &scanMsg); err != nil {
		log.Printf("Invalid scan message: %v", err)
		return
	}

	// Apply template defaults
	if defaults, ok := DefaultTemplates[scanMsg.Options.Template]; ok {
		options := defaults // Start with template defaults

		// Only override if explicitly set in request
		if scanMsg.Options.PortRange != "" {
			options.PortRange = scanMsg.Options.PortRange
		}
		if len(scanMsg.Options.ExcludePorts) > 0 {
			options.ExcludePorts = scanMsg.Options.ExcludePorts
		}
		if len(scanMsg.Options.ScanTypes) > 0 {
			options.ScanTypes = scanMsg.Options.ScanTypes
		}
		if scanMsg.Options.MaxRetries > 0 {
			options.MaxRetries = scanMsg.Options.MaxRetries
		}

		// Convert back to ScanOptions
		scanMsg.Options = ScanOptions{
			Template:     scanMsg.Options.Template,
			ScanTypes:    options.ScanTypes,
			PortRange:    options.PortRange,
			ExcludePorts: options.ExcludePorts,
			Aggressive:   options.Aggressive,
			MaxRetries:   options.MaxRetries,
			Parallel:     options.Parallel,
		}
	}

	// Continue with validation and processing
	if err := sm.validateScanMessage(&scanMsg); err != nil {
		log.Printf("Invalid scan configuration: %v", err)
		return
	}

	sm.currentScanOptions = scanMsg.Options
	sm.toolFactory.SetOptions(scanMsg.Options)

	// Process all targets
	for _, target := range scanMsg.Targets {
		sm.processTarget(target)
	}
}

// validateScanMessage performs validation on the scan message
func (sm *ScanManager) validateScanMessage(msg *ScanMessage) error {
	if len(msg.Targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	if msg.Priority < 1 || msg.Priority > 5 {
		return fmt.Errorf("invalid priority: must be between 1 and 5")
	}

	return nil
}

// processTarget runs the discovery scan followed by a vulnerability scan
func (sm *ScanManager) processTarget(target Target) {
	log.Printf("Processing target: %+v", target)

	// Convert target to appropriate format based on type
	targetIPs, err := sm.prepareTarget(target)
	if err != nil {
		log.Printf("Failed to prepare target %s: %v", target.Value, err)
		return
	}

	// Add each IP as a task to the worker pool
	for _, ip := range targetIPs {
		task := ScanTask{
			IP:      ip,
			Options: sm.currentScanOptions, // You'll need to add this field to ScanManager
		}
		sm.workerPool.AddTask(task)
	}
}

// scanIP performs the actual scanning of a single IP
func (sm *ScanManager) scanIP(ip string) {
	// Validate if this is a single IP before proceeding
	if net.ParseIP(ip) == nil {
		log.Printf("Warning: Expected single IP, got: %s", ip)
		return
	}

	// Only run enabled scan types
	for _, scanType := range sm.currentScanOptions.ScanTypes {
		switch scanType {
		case "enumeration":
			if err := sm.runEnumeration(ip); err != nil {
				log.Printf("Enumeration failed for %s: %v", ip, err)
			}
		case "discovery":
			if err := sm.runDiscovery(ip); err != nil {
				log.Printf("Discovery failed for %s: %v", ip, err)
			}
		case "vulnerability":
			if err := sm.runVulnerability(ip); err != nil {
				log.Printf("Vulnerability scan failed for %s: %v", ip, err)
			}
		}
	}
}

// markHostComplete updates the scan status for a completed host
func (sm *ScanManager) markHostComplete(ip string) error {
	return sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
		scan.HostsCompleted++
		// If all hosts are processed, mark scan as complete
		if scan.HostsCompleted >= len(scan.Hosts) {
			scan.Status = "completed"
			scan.EndTime = time.Now().Format(time.RFC3339)
		}
		return nil
	})
}

// runEnumeration performs the enumeration scan
func (sm *ScanManager) runEnumeration(ip string) error {
	enumStrategy := sm.toolFactory.CreateTool("enumeration")
	enumResults, err := enumStrategy.Execute(ip)
	if err != nil {
		return fmt.Errorf("port enumeration failed for %s: %v", ip, err)
	}

	// Update KV store with enumeration details but preserve existing data
	if err := sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
		if !contains(scan.Hosts, enumResults.IP) {
			scan.Hosts = append(scan.Hosts, enumResults.IP)
		}
		if scan.StartTime == "" {
			scan.StartTime = time.Now().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to update scan with enumeration results for host %s: %v", ip, err)
	}

	log.Printf("Enumeration results: %+v", enumResults)
	return nil // Remove markHostComplete call
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// runDiscovery performs the discovery scan
func (sm *ScanManager) runDiscovery(ip string) error {
	discoveryStrategy := sm.toolFactory.CreateTool("discovery")
	discoveryResults, err := discoveryStrategy.Execute(ip)
	if err != nil {
		return fmt.Errorf("discovery scan failed for %s: %v", ip, err)
	}

	log.Printf("Discovery scan completed for %s. Found %d ports.", ip, len(discoveryResults.Ports))

	// Only persist host if at least one port is found
	if len(discoveryResults.Ports) == 0 {
		log.Printf("No open ports found for %s, not persisting host.", discoveryResults.IP)
		return nil
	}

	err = host.AddHost(discoveryResults)
	if err != nil {
		log.Printf("Warning: Failed to add host %s to database: %v", discoveryResults.IP, err)
		log.Printf("Will continue scan without database persistence")
		// We don't return the error here since we want the scan to continue
		// even if database operations fail
	} else {
		log.Printf("Successfully added host %s to database", discoveryResults.IP)
	}

	// Update KV store with the discovered host.
	if err := sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
		if !contains(scan.Hosts, discoveryResults.IP) {
			scan.Hosts = append(scan.Hosts, discoveryResults.IP)
		}
		return nil
	}); err != nil {
		log.Printf("Warning: Failed to update scan results store for %s: %v", discoveryResults.IP, err)
		// Still continue with the scan
	}

	return nil
}

// runVulnerability performs the vulnerability scan
func (sm *ScanManager) runVulnerability(ip string) error {
	vulnStrategy := sm.toolFactory.CreateTool("vulnerability")
	vulnResults, err := vulnStrategy.Execute(ip)
	if err != nil {
		return fmt.Errorf("vulnerability scan failed for %s: %v", ip, err)
	}

	log.Printf("Found %d vulnerabilities for host %s", len(vulnResults.Vulnerabilities), ip)

	// 1. First save individual vulnerabilities to the database
	savedVulns := []sirius.Vulnerability{}
	for _, vuln := range vulnResults.Vulnerabilities {
		// Skip empty vulnerabilities
		if vuln.VID == "" {
			continue
		}

		// Add individual vulnerability to the database
		if err := vulnerability.AddVulnerability(vuln); err != nil {
			log.Printf("Warning: failed to add vulnerability %s to database: %v", vuln.VID, err)
		} else {
			log.Printf("Added vulnerability %s to database", vuln.VID)
			savedVulns = append(savedVulns, vuln)
		}
	}

	// 2. Get the existing host record
	existingHost, err := host.GetHost(ip)
	if err != nil {
		log.Printf("Warning: failed to get existing host %s from database: %v", ip, err)
		// Continue with vulnResults as the host might be new
	} else {
		// Keep important fields from existing host record
		if existingHost.HID != "" {
			vulnResults.HID = existingHost.HID
		}
		if existingHost.Hostname != "" {
			vulnResults.Hostname = existingHost.Hostname
		}
		if existingHost.OS != "" {
			vulnResults.OS = existingHost.OS
		}
		if existingHost.OSVersion != "" {
			vulnResults.OSVersion = existingHost.OSVersion
		}
	}

	// 3. Make sure the host has all the saved vulnerabilities
	vulnResults.Vulnerabilities = savedVulns

	// 4. Store the host
	if err := host.AddHost(vulnResults); err != nil {
		return fmt.Errorf("failed to update host with vulnerabilities for %s: %v", ip, err)
	}

	// 5. Verify associations were created - If AddHost didn't associate them, do it directly
	db := postgres.GetDB()

	// Skip direct database operations if database connection failed
	if db == nil {
		log.Printf("Warning: Database connection not available, skipping manual host-vulnerability association")
		return nil
	}

	// Get host ID using a safe query approach
	var hostID uint
	var hostFound bool

	// Find the host ID with proper nil check
	row := db.Table("hosts").Select("id").Where("ip = ?", ip).Row()
	if row == nil {
		log.Printf("Warning: No row returned for host %s query, skipping associations", ip)
	} else {
		err = row.Scan(&hostID)
		if err != nil {
			log.Printf("Error finding host ID for %s: %v", ip, err)
		} else {
			hostFound = true
		}
	}

	// Only proceed with vulnerability associations if we found the host
	if hostFound {
		log.Printf("Found host with ID %d, creating vulnerability associations", hostID)

		// For each vulnerability, ensure an association exists
		for _, vuln := range savedVulns {
			var vulnID uint
			var vulnFound bool

			// Get the vulnerability ID safely
			vulnRow := db.Table("vulnerabilities").Select("id").Where("v_id = ?", vuln.VID).Row()
			if vulnRow == nil {
				log.Printf("Warning: No row returned for vulnerability %s query", vuln.VID)
				continue
			}

			err = vulnRow.Scan(&vulnID)
			if err != nil {
				log.Printf("Error finding vulnerability ID for %s: %v", vuln.VID, err)
				continue
			} else {
				vulnFound = true
			}

			// Skip if vulnerability wasn't found
			if !vulnFound {
				continue
			}

			// Only proceed if we found both host and vulnerability IDs
			// Check if association already exists
			var count int64
			countResult := db.Table("host_vulnerabilities").Where("host_id = ? AND vulnerability_id = ?", hostID, vulnID).Count(&count)
			if countResult.Error != nil {
				log.Printf("Error checking for existing association: %v", countResult.Error)
				continue
			}

			// If association doesn't exist, create it
			if count == 0 {
				result := db.Exec("INSERT INTO host_vulnerabilities (host_id, vulnerability_id) VALUES (?, ?)",
					hostID, vulnID)
				if result.Error != nil {
					log.Printf("Error creating host-vulnerability association: %v", result.Error)
				} else {
					log.Printf("Added direct association between host %d and vulnerability %d", hostID, vulnID)
				}
			} else {
				log.Printf("Association already exists between host %d and vulnerability %d", hostID, vulnID)
			}
		}
	} else {
		log.Printf("Could not find host with IP %s in database, skipping vulnerability associations", ip)
	}

	log.Printf("Successfully processed host %s with %d vulnerabilities", ip, len(savedVulns))

	// Update KV store with vulnerability details
	if err := sm.scanUpdater.Update(context.Background(), func(scan *store.ScanResult) error {
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
		return fmt.Errorf("failed to update scan with vulnerabilities for host %s: %v", vulnResults.IP, err)
	}

	// Only mark host complete after vulnerability scan
	if err := sm.markHostComplete(ip); err != nil {
		return fmt.Errorf("failed to mark host completion: %v", err)
	}

	return nil
}

// prepareTarget converts the target into the appropriate format based on its type
func (sm *ScanManager) prepareTarget(target Target) ([]string, error) {
	switch target.Type {
	case SingleIP:
		if !validateIP(target.Value) {
			return nil, fmt.Errorf("invalid IP address: %s", target.Value)
		}
		return []string{target.Value}, nil

	case IPRange:
		return expandIPRange(target.Value)

	case CIDR:
		if !validateCIDR(target.Value) {
			return nil, fmt.Errorf("invalid CIDR notation: %s", target.Value)
		}
		return expandCIDR(target.Value)

	case DNSName:
		ips, err := net.LookupIP(target.Value)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %v", err)
		}
		result := make([]string, len(ips))
		for i, ip := range ips {
			result[i] = ip.String()
		}
		return result, nil

	case DNSWildcard:
		// TODO: Implement DNS wildcard resolution
		return nil, fmt.Errorf("DNS wildcard not yet implemented")

	default:
		return nil, fmt.Errorf("unknown target type: %s", target.Type)
	}
}

// Add a cleanup method to properly shut down the worker pool
func (sm *ScanManager) Shutdown() {
	sm.cancel()
	sm.workerPool.Stop()
}

// SetScanOptions configures the scan options.
func (m *ScanManager) SetScanOptions(options *ScanOptions) {
	m.options = options

	// Initialize protocols array for the NmapStrategy
	protocols := []string{}

	// If scan types include "smb", add it to the protocols list
	for _, scanType := range options.ScanTypes {
		if scanType == "smb" {
			protocols = append(protocols, "smb")
		}
	}

	// If no specific protocols were set or if we want all scripts, use wildcard
	if len(protocols) == 0 || containsAny(options.ScanTypes, "*") {
		protocols = []string{"*"}
	}

	// Set the protocols for Nmap scan strategy
	if strategy, ok := m.scanStrategies["nmap"].(*NmapStrategy); ok {
		strategy.Protocols = protocols
		log.Printf("NmapStrategy protocols set to: %v", strategy.Protocols)
	}
}

// Helper function to check if a slice contains a substring match
func containsAny(slice []string, target string) bool {
	for _, item := range slice {
		if strings.Contains(strings.ToLower(item), strings.ToLower(target)) {
			return true
		}
	}
	return false
}
