package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/queue"
	"github.com/SiriusScan/go-api/sirius/store"
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
	apiBaseURL         string // API base URL for source-aware submissions
	logger             *LoggingClient // Centralized logging client
}

// SourcedHostRequest represents the request structure for source-aware API submissions
type SourcedHostRequest struct {
	Host   sirius.Host       `json:"host"`
	Source models.ScanSource `json:"source"`
}

// NewScanManager creates a new ScanManager.
func NewScanManager(kvStore store.KVStore, toolFactory *ScanToolFactory, updater *ScanUpdater) *ScanManager {
	// Create a context that can be canceled
	ctx, cancel := context.WithCancel(context.Background())

	// Initialize NSE repository manager
	repoManager := nse.NewRepoManager("/opt/sirius/nse/sirius-nse", nse.NSERepoURL)

	// Initialize NSE sync manager
	syncManager := nse.NewSyncManager(repoManager, kvStore)

	// Get API base URL from environment or use default
	apiBaseURL := os.Getenv("SIRIUS_API_URL")
	if apiBaseURL == "" {
		apiBaseURL = "http://localhost:9001" // Default for development
	}

	sm := &ScanManager{
		kvStore:     kvStore,
		toolFactory: toolFactory,
		scanUpdater: updater,
		ctx:         ctx,
		cancel:      cancel,
		nseSync:     syncManager,
		apiBaseURL:  apiBaseURL,
		logger:      NewLoggingClient(),
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

// detectScannerVersion detects the version of scanning tools with enhanced error handling
func (sm *ScanManager) detectScannerVersion(toolName string) string {
	switch toolName {
	case "nmap":
		if output, err := exec.Command("nmap", "--version").Output(); err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 && strings.Contains(lines[0], "Nmap") {
				parts := strings.Fields(lines[0])
				if len(parts) >= 3 {
					version := parts[2]
					// Log version detection for audit purposes
					log.Printf("Detected nmap version: %s", version)
					return version
				}
			}
		} else {
			log.Printf("Warning: Failed to detect nmap version: %v", err)
		}
		return "unknown"
	case "rustscan":
		if output, err := exec.Command("rustscan", "--version").Output(); err == nil {
			version := strings.TrimSpace(string(output))
			if strings.Contains(version, "rustscan") {
				parts := strings.Fields(version)
				if len(parts) >= 2 {
					detectedVersion := parts[1]
					log.Printf("Detected rustscan version: %s", detectedVersion)
					return detectedVersion
				}
			}
		} else {
			log.Printf("Warning: Failed to detect rustscan version: %v", err)
		}
		return "unknown"
	case "naabu":
		if output, err := exec.Command("naabu", "-version").Output(); err == nil {
			version := strings.TrimSpace(string(output))
			log.Printf("Detected naabu version: %s", version)
			return version
		} else {
			log.Printf("Warning: Failed to detect naabu version: %v", err)
		}
		return "unknown"
	default:
		log.Printf("Warning: Unknown tool name for version detection: %s", toolName)
		return "unknown"
	}
}

// getSystemInfo captures system information for enhanced source attribution
func (sm *ScanManager) getSystemInfo() map[string]string {
	info := make(map[string]string)

	// Get OS information
	if output, err := exec.Command("uname", "-a").Output(); err == nil {
		info["system"] = strings.TrimSpace(string(output))
	}

	// Get hostname
	if hostname, err := os.Hostname(); err == nil {
		info["hostname"] = hostname
	}

	// Get current user
	if user := os.Getenv("USER"); user != "" {
		info["user"] = user
	}

	// Get Go version (for the scanner itself)
	info["go_version"] = runtime.Version()
	info["scanner_arch"] = runtime.GOARCH
	info["scanner_os"] = runtime.GOOS

	return info
}

// createScanSource creates a ScanSource with enhanced configuration details
func (sm *ScanManager) createScanSource(toolName string) models.ScanSource {
	version := sm.detectScannerVersion(toolName)
	systemInfo := sm.getSystemInfo()

	// Build comprehensive configuration string
	var configParts []string

	// Scan-specific configuration
	if sm.currentScanOptions.PortRange != "" {
		configParts = append(configParts, fmt.Sprintf("ports:%s", sm.currentScanOptions.PortRange))
	}
	if sm.currentScanOptions.Aggressive {
		configParts = append(configParts, "aggressive:true")
	}
	if len(sm.currentScanOptions.ScanTypes) > 0 {
		configParts = append(configParts, fmt.Sprintf("types:%s", strings.Join(sm.currentScanOptions.ScanTypes, ",")))
	}
	if len(sm.currentScanOptions.ExcludePorts) > 0 {
		configParts = append(configParts, fmt.Sprintf("exclude:%s", strings.Join(sm.currentScanOptions.ExcludePorts, ",")))
	}
	if sm.currentScanOptions.Template != "" {
		configParts = append(configParts, fmt.Sprintf("template:%s", sm.currentScanOptions.Template))
	}

	// System information for audit trail
	if hostname, ok := systemInfo["hostname"]; ok {
		configParts = append(configParts, fmt.Sprintf("host:%s", hostname))
	}
	if user, ok := systemInfo["user"]; ok {
		configParts = append(configParts, fmt.Sprintf("user:%s", user))
	}

	// Scanner metadata
	configParts = append(configParts, fmt.Sprintf("scanner_id:%s", sm.currentScanID))
	configParts = append(configParts, fmt.Sprintf("go_version:%s", systemInfo["go_version"]))

	config := strings.Join(configParts, ";")
	if config == "" {
		config = "default"
	}

	source := models.ScanSource{
		Name:    toolName,
		Version: version,
		Config:  config,
	}

	// Log source creation for debugging
	log.Printf("Created scan source: %s v%s with config: %s", source.Name, source.Version, source.Config)

	return source
}

// submitHostWithSource submits host data using the source-aware API endpoint
func (sm *ScanManager) submitHostWithSource(host sirius.Host, toolName string) error {
	source := sm.createScanSource(toolName)

	request := SourcedHostRequest{
		Host:   host,
		Source: source,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	url := fmt.Sprintf("%s/host/with-source", sm.apiBaseURL)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to submit host data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	log.Printf("Successfully submitted host %s with source %s (version %s)", host.IP, source.Name, source.Version)
	return nil
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
		sm.logger.LogScanError("unknown", "unknown", "message_parse_error", "Failed to parse scan message", err)
		return
	}

	// Log scan initiation
	sm.currentScanID = scanMsg.ID
	sm.logger.LogScanEvent(scanMsg.ID, "scan_initiated", "Scan request received", map[string]interface{}{
		"targets_count": len(scanMsg.Targets),
		"priority":      scanMsg.Priority,
		"template":      scanMsg.Options.Template,
		"scan_types":    scanMsg.Options.ScanTypes,
	})

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
		sm.logger.LogScanError(scanMsg.ID, "validation", "scan_validation_error", "Invalid scan configuration", err)
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

	// Log target processing start
	sm.logger.LogScanEvent(sm.currentScanID, "target_processing", "Target processing started", map[string]interface{}{
		"target_value": target.Value,
		"target_type":  target.Type,
		"timeout":      target.Timeout,
	})

	// Convert target to appropriate format based on type
	targetIPs, err := sm.prepareTarget(target)
	if err != nil {
		log.Printf("Failed to prepare target %s: %v", target.Value, err)
		sm.logger.LogScanError(sm.currentScanID, target.Value, "target_preparation_error", "Failed to prepare target", err)
		return
	}

	// Log target preparation success
	sm.logger.LogScanEvent(sm.currentScanID, "target_prepared", "Target prepared successfully", map[string]interface{}{
		"target_value": target.Value,
		"target_type":  target.Type,
		"ips_generated": len(targetIPs),
		"ips":          targetIPs,
	})

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
		
		// Log host completion
		sm.logger.LogScanEvent(sm.currentScanID, "host_completed", "Host scan completed", map[string]interface{}{
			"host_ip":          ip,
			"hosts_completed":  scan.HostsCompleted,
			"total_hosts":      len(scan.Hosts),
		})
		
		// If all hosts are processed, mark scan as complete
		if scan.HostsCompleted >= len(scan.Hosts) {
			scan.Status = "completed"
			scan.EndTime = time.Now().Format(time.RFC3339)
			
			// Log scan completion
			sm.logger.LogScanCompletion(sm.currentScanID, "all_targets", map[string]interface{}{
				"total_hosts":      len(scan.Hosts),
				"hosts_completed":  scan.HostsCompleted,
				"vulnerabilities_found": len(scan.Vulnerabilities),
				"scan_duration":    time.Since(time.Now()).String(), // This will be calculated properly in real implementation
			})
		}
		return nil
	})
}

// runEnumeration performs the enumeration scan
func (sm *ScanManager) runEnumeration(ip string) error {
	startTime := time.Now()
	enumStrategy := sm.toolFactory.CreateTool("enumeration")
	enumResults, err := enumStrategy.Execute(ip)
	duration := time.Since(startTime)
	
	if err != nil {
		sm.logger.LogToolExecution(sm.currentScanID, ip, "naabu", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("port enumeration failed for %s: %v", ip, err)
	}

	// Log tool execution success
	enumPorts := make([]int, len(enumResults.Ports))
	for i, port := range enumResults.Ports {
		enumPorts[i] = port.ID
	}
	sm.logger.LogToolExecution(sm.currentScanID, ip, "naabu", duration, true, map[string]interface{}{
		"ports_found": len(enumResults.Ports),
		"ports":       enumPorts,
	})

	// Submit host data to database if ports were found
	if len(enumResults.Ports) > 0 {
		// Determine the actual tool used based on scan type - enumeration uses Naabu
		toolName := "naabu"

		// Submit host data using the new source-aware API
		if err := sm.submitHostWithSource(enumResults, toolName); err != nil {
			log.Printf("Warning: failed to submit enumeration data via source-aware API: %v", err)
			log.Printf("This may indicate the API is not available or the endpoint is not implemented")
			log.Printf("Will continue scan without database persistence")
			// Continue execution even if database operations fail
		} else {
			log.Printf("Successfully added host %s with enumeration data using source-aware API", enumResults.IP)
		}
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
	startTime := time.Now()
	discoveryStrategy := sm.toolFactory.CreateTool("discovery")
	discoveryResults, err := discoveryStrategy.Execute(ip)
	duration := time.Since(startTime)
	
	if err != nil {
		sm.logger.LogToolExecution(sm.currentScanID, ip, "rustscan", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("discovery scan failed for %s: %v", ip, err)
	}

	log.Printf("Discovery scan completed for %s. Found %d ports.", ip, len(discoveryResults.Ports))

	// Log tool execution success
	toolPorts := make([]int, len(discoveryResults.Ports))
	for i, port := range discoveryResults.Ports {
		toolPorts[i] = port.ID
	}
	sm.logger.LogToolExecution(sm.currentScanID, ip, "rustscan", duration, true, map[string]interface{}{
		"ports_found": len(discoveryResults.Ports),
		"ports":       toolPorts,
	})

	// Only persist host if at least one port is found
	if len(discoveryResults.Ports) == 0 {
		log.Printf("No open ports found for %s, not persisting host.", discoveryResults.IP)
		sm.logger.LogScanEvent(sm.currentScanID, "no_ports_found", "No open ports found for host", map[string]interface{}{
			"host_ip": ip,
		})
		return nil
	}

	// Log host discovery
	discoveryPorts := make([]int, len(discoveryResults.Ports))
	for i, port := range discoveryResults.Ports {
		discoveryPorts[i] = port.ID
	}
	sm.logger.LogHostDiscovery(sm.currentScanID, ip, discoveryPorts, "rustscan")

	// Determine the actual tool used based on scan type - discovery uses RustScan
	toolName := "rustscan"

	// Submit host data using the new source-aware API
	if err := sm.submitHostWithSource(discoveryResults, toolName); err != nil {
		log.Printf("Warning: failed to submit host data via source-aware API: %v", err)
		log.Printf("This may indicate the API is not available or the endpoint is not implemented")
		log.Printf("Will continue scan without database persistence")
		// We don't return the error here since we want the scan to continue
		// even if database operations fail
	} else {
		log.Printf("Successfully added host %s to database using source-aware API", discoveryResults.IP)
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
	startTime := time.Now()
	vulnStrategy := sm.toolFactory.CreateTool("vulnerability")
	vulnResults, err := vulnStrategy.Execute(ip)
	duration := time.Since(startTime)
	
	if err != nil {
		sm.logger.LogToolExecution(sm.currentScanID, ip, "nmap", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("vulnerability scan failed for %s: %v", ip, err)
	}

	log.Printf("Found %d vulnerabilities for host %s", len(vulnResults.Vulnerabilities), ip)

	// Log tool execution success
	sm.logger.LogToolExecution(sm.currentScanID, ip, "nmap", duration, true, map[string]interface{}{
		"vulnerabilities_found": len(vulnResults.Vulnerabilities),
	})

	// Log vulnerability scan completion
	vulnerabilities := make([]map[string]interface{}, len(vulnResults.Vulnerabilities))
	for i, vuln := range vulnResults.Vulnerabilities {
		vulnerabilities[i] = map[string]interface{}{
			"id":          vuln.VID,
			"title":       vuln.Title,
			"risk_score":  vuln.RiskScore,
			"description": vuln.Description,
		}
	}
	sm.logger.LogVulnerabilityScan(sm.currentScanID, ip, vulnerabilities, "nmap")

	// Determine the actual tool used based on scan type - vulnerability uses Nmap
	toolName := "nmap"

	// Submit host data using the new source-aware API
	if err := sm.submitHostWithSource(vulnResults, toolName); err != nil {
		log.Printf("Warning: failed to submit host data via source-aware API: %v", err)
		log.Printf("This may indicate the API is not available or the endpoint is not implemented")
		return fmt.Errorf("failed to submit host data with source attribution: %v", err)
	}

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

	log.Printf("Successfully processed host %s with %d vulnerabilities using source-aware API", ip, len(vulnResults.Vulnerabilities))
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
