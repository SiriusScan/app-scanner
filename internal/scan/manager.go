package scan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/infraauth"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
	"github.com/SiriusScan/go-api/sirius/queue"
	"github.com/SiriusScan/go-api/sirius/store"
)

// Default number of worker goroutines
const DEFAULT_WORKERS = 10
const apiRequestTimeout = 15 * time.Second

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

// ScanOptions struct for scan configuration
type ScanOptions struct {
	TemplateID   string   `json:"template_id"`   // Template ID to use for scan
	PortRange    string   `json:"port_range"`    // Port range to scan
	Aggressive   bool     `json:"aggressive"`    // Whether to use aggressive scanning
	ExcludePorts []string `json:"exclude_ports"` // Ports to exclude
	ScanTypes    []string `json:"scan_types"`    // Types of scans to perform
	MaxRetries   int      `json:"max_retries"`   // Maximum number of retries
	Parallel     bool     `json:"parallel"`      // Whether to scan targets in parallel

	// Fingerprint options (ping++ integration)
	FingerprintProbes  []string `json:"fingerprint_probes,omitempty"`  // Probe types: icmp, tcp, arp, smb
	FingerprintTimeout string   `json:"fingerprint_timeout,omitempty"` // Per-probe timeout (e.g., "3s")
	DisableICMP        bool     `json:"disable_icmp,omitempty"`        // Disable ICMP for unprivileged mode
}

// ScanMessage represents the incoming scan request message
type ScanMessage struct {
	ID            string      `json:"id"`                   // Unique identifier for this scan
	Targets       []Target    `json:"targets"`              // List of targets to scan
	Options       ScanOptions `json:"options"`              // Scan configuration options
	Priority      int         `json:"priority"`             // Scan priority (1-5)
	CallbackURL   string      `json:"callback_url"`         // Optional webhook for scan completion
	StateMode     string      `json:"state_mode,omitempty"` // "keyed" uses scan:<id>; empty retains legacy state
	ResourceScope struct {
		OwnerSubjectID string `json:"owner_subject_id,omitempty"`
	} `json:"resource_scope,omitempty"`
}

// ScanManager manages scan operations.
type ScanManager struct {
	workerPool         *WorkerPool
	ctx                context.Context
	cancel             context.CancelFunc
	currentScanID      string
	currentScanOptions ScanOptions
	nseSync            *nse.SyncManager
	templateManager    *TemplateManager
	scanStrategies     map[string]ScanStrategy
	options            *ScanOptions
	toolFactory        scanToolFactory
	scanUpdater        *ScanUpdater
	kvStore            store.KVStore
	apiBaseURL         string       // API base URL for source-aware submissions
	apiHTTPClient      *http.Client // Shared HTTP client for API submissions
	logger             scanLogger   // Centralized logging client

	// Cancellation support
	activeScanCtx    context.Context    // Context for the currently running scan
	activeScanCancel context.CancelFunc // Cancel function for the current scan
	scanMutex        sync.Mutex         // Protects scan state during cancellation
	isCancelling     bool               // Flag to indicate cancellation in progress
	keyedRuns        map[string]*ScanManager
	coordinator      *ScanManager
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
	repoManager := nse.NewRepoManager(nse.NSEBasePath, nse.NSERepoURL)

	// Initialize NSE sync manager
	syncManager := nse.NewSyncManager(repoManager, kvStore)

	// Initialize template manager
	templateManager := NewTemplateManager(kvStore)

	// Get API base URL from environment or use default
	apiBaseURL := os.Getenv("SIRIUS_API_URL")
	if apiBaseURL == "" {
		apiBaseURL = "http://localhost:9001" // Default for development
		slog.Info("SIRIUS_API_URL not set, using default", "api_base_url", apiBaseURL)
	} else {
		slog.Info("Using SIRIUS_API_URL from environment", "api_base_url", apiBaseURL)
	}

	sm := &ScanManager{
		kvStore:         kvStore,
		toolFactory:     toolFactory,
		scanUpdater:     updater,
		ctx:             ctx,
		cancel:          cancel,
		nseSync:         syncManager,
		templateManager: templateManager,
		apiBaseURL:      apiBaseURL,
		apiHTTPClient:   &http.Client{Timeout: apiRequestTimeout},
		logger:          NewLoggingClient(),
		scanStrategies: map[string]ScanStrategy{
			"nmap": &NmapStrategy{},
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
					slog.Debug("Detected nmap version", "version", version)
					return version
				}
			}
		} else {
			slog.Warn("Failed to detect nmap version", "error", err)
		}
		return "unknown"
	case "naabu":
		if output, err := exec.Command("naabu", "-version").Output(); err == nil {
			version := strings.TrimSpace(string(output))
			slog.Debug("Detected naabu version", "version", version)
			return version
		} else {
			slog.Warn("Failed to detect naabu version", "error", err)
		}
		return "unknown"
	case "ping++":
		slog.Debug("ping++ is a library; no CLI version to detect")
		return "embedded"
	default:
		slog.Debug("No version detection available for tool", "tool_name", toolName)
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
	if sm.currentScanOptions.TemplateID != "" {
		configParts = append(configParts, fmt.Sprintf("template:%s", sm.currentScanOptions.TemplateID))
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
	slog.Info("Created scan source", "name", source.Name, "version", source.Version, "config", source.Config)

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
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	url := fmt.Sprintf("%s/host/with-source", sm.apiBaseURL)
	requestCtx, cancel := context.WithTimeout(sm.ctx, apiRequestTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	serviceKey, keyErr := infraauth.LoadSiriusAPIKey()
	if keyErr != nil {
		return fmt.Errorf("internal API key required for scanner API calls: %w", keyErr)
	}
	if serviceKey == "" {
		return fmt.Errorf("internal API key required for scanner API calls (empty key)")
	}
	req.Header.Set("X-API-Key", serviceKey)

	resp, err := sm.apiHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to submit host data to %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("API returned status %d for %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}

	slog.Debug("Successfully submitted host with source", "host_ip", host.IP, "source_name", source.Name, "source_version", source.Version)
	return nil
}

// submitFingerprintResult creates a minimal host record from fingerprint results and submits it to the API.
// This enables real-time host discovery visibility - operators see hosts as soon as they're detected alive.
func (sm *ScanManager) submitFingerprintResult(ip string, result FingerprintResult) error {
	// Create a minimal host with fingerprint data
	host := sirius.Host{
		IP: ip,
		OS: result.OSFamily,
	}

	// Add TTL info to OSVersion if available (provides useful context)
	if result.TTL > 0 {
		if confidence, ok := result.Details["confidence"]; ok {
			host.OSVersion = fmt.Sprintf("TTL:%d (%s confidence)", result.TTL, confidence)
		} else {
			host.OSVersion = fmt.Sprintf("TTL:%d", result.TTL)
		}
	}

	return sm.submitHostWithSource(host, "ping++")
}

// ListenForScans attaches the ScanManager to the "scan" queue.
// Uses ListenWithRetry for resilient connection handling — if RabbitMQ is
// unavailable at startup or drops the connection later, the listener will
// automatically reconnect with exponential backoff instead of crashing.
func (sm *ScanManager) ListenForScans() {
	// Sync NSE scripts before starting to listen for scans
	if err := sm.nseSync.Sync(sm.ctx); err != nil {
		slog.Warn("Failed to sync NSE scripts", "error", err)
	}

	// Initialize system templates
	if err := sm.templateManager.InitializeSystemTemplates(sm.ctx); err != nil {
		slog.Warn("Failed to initialize system templates", "error", err)
	}

	queue.ListenWithRetry(sm.ctx, "scan", sm.handleMessage)
}

// handleMessage processes incoming scan requests
func (sm *ScanManager) handleMessage(msg string) {
	scanMsg, err := decodeScanMessage([]byte(msg))
	if err != nil {
		slog.Error("Invalid scan message", "error", err)
		sm.logger.LogScanError("unknown", "unknown", "message_parse_error", "Failed to parse scan message", err)
		return
	}

	// Reject invalid/stale messages before replacing the active run. Every task
	// then retains this run's identity, options and cancellation context.
	if err := sm.validateScanMessage(&scanMsg); err != nil {
		slog.Error("Invalid scan configuration", "error", err)
		if scanMsg.ResourceScope.OwnerSubjectID != "" {
			return
		}
		if scanMsg.StateMode == "keyed" {
			state := &ScanManager{scanUpdater: &ScanUpdater{kvStore: sm.kvStore, keyed: true}}
			state.failScan(scanMsg.ID)
		} else if scanMsg.StateMode == "" {
			sm.failScan(scanMsg.ID)
		}
		return
	}
	var run *ScanManager
	err = nil
	if scanMsg.StateMode == "keyed" {
		run, err = sm.newKeyedRun(scanMsg.ID)
	} else {
		run, err = sm.newScanRun(scanMsg.ID)
	}
	if err != nil {
		slog.Warn("Ignoring scan request", "scan_id", scanMsg.ID, "error", err)
		return
	}
	run.handleScanMessage(scanMsg)
}

func (sm *ScanManager) handleScanMessage(scanMsg ScanMessage) {
	// Log scan initiation
	sm.logger.LogScanEvent(scanMsg.ID, "scan_initiated", "Scan request received", map[string]interface{}{
		"targets_count": len(scanMsg.Targets),
		"priority":      scanMsg.Priority,
		"template_id":   scanMsg.Options.TemplateID,
		"scan_types":    scanMsg.Options.ScanTypes,
	})

	// Resolve template if template ID provided
	if scanMsg.Options.TemplateID != "" {
		template, err := sm.templateManager.GetTemplate(sm.ctx, scanMsg.Options.TemplateID)
		if err != nil {
			slog.Error("Failed to get template", "template_id", scanMsg.Options.TemplateID, "error", err)
			sm.logger.LogScanError(scanMsg.ID, "template_resolution", "template_not_found", "Failed to resolve template", err)
			sm.updateScanStatus("failed")
			return
		}

		// Apply template options (user-provided options override template defaults)
		if scanMsg.Options.PortRange == "" {
			scanMsg.Options.PortRange = template.ScanOptions.PortRange
		}
		if len(scanMsg.Options.ScanTypes) == 0 {
			scanMsg.Options.ScanTypes = template.ScanOptions.ScanTypes
		}
		if len(scanMsg.Options.ExcludePorts) == 0 {
			scanMsg.Options.ExcludePorts = template.ScanOptions.ExcludePorts
		}
		if scanMsg.Options.MaxRetries == 0 {
			scanMsg.Options.MaxRetries = template.ScanOptions.MaxRetries
		}
		if !scanMsg.Options.Aggressive {
			scanMsg.Options.Aggressive = template.ScanOptions.Aggressive
		}
		if !scanMsg.Options.Parallel {
			scanMsg.Options.Parallel = template.ScanOptions.Parallel
		}

		slog.Info("Resolved template", "template_id", template.ID, "template_name", template.Name)
	}

	sm.currentScanOptions = cloneScanOptions(scanMsg.Options)
	sm.toolFactory.SetOptions(sm.currentScanOptions)

	// Expand and deduplicate every target before workers start. Incremental
	// totals let the first fast host complete a scan before later targets exist.
	targetIPs, err := sm.prepareScanTargets(scanMsg.Targets)
	if err != nil {
		slog.Error("Failed to prepare scan targets", "scan_id", sm.currentScanID, "error", err)
		sm.updateScanStatus("failed")
		return
	}
	sm.scheduleTargets(targetIPs)
}

// validateScanMessage performs validation on the scan message
func (sm *ScanManager) validateScanMessage(msg *ScanMessage) error {
	if msg.ResourceScope.OwnerSubjectID != "" {
		return fmt.Errorf("non-global resource scope is unsupported by scanner ingestion")
	}
	if msg.StateMode != "" && msg.StateMode != "keyed" {
		return fmt.Errorf("unsupported scan state mode")
	}
	if strings.TrimSpace(msg.ID) == "" {
		return fmt.Errorf("scan ID is required")
	}
	if len(msg.Targets) == 0 {
		return fmt.Errorf("no targets specified")
	}

	if msg.Priority < 1 || msg.Priority > 5 {
		return fmt.Errorf("invalid priority: must be between 1 and 5")
	}

	return nil
}

// prepareScanTargets validates the complete request before any work is queued.
func (sm *ScanManager) prepareScanTargets(targets []Target) ([]string, error) {
	seen := make(map[string]bool)
	var ips []string
	for _, target := range targets {
		if err := sm.ctx.Err(); err != nil {
			return nil, err
		}
		expanded, err := sm.prepareTarget(target)
		if err != nil {
			return nil, fmt.Errorf("target %q: %w", target.Value, err)
		}
		for _, ip := range expanded {
			if !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no target IPs resolved")
	}
	return ips, nil
}

func (sm *ScanManager) scheduleTargets(targetIPs []string) {
	if err := sm.scanUpdater.UpdateForScan(sm.ctx, sm.currentScanID, func(scan *store.ScanResult) error {
		if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
			return fmt.Errorf("scan is not active")
		}
		if scan.SubScans == nil {
			scan.SubScans = make(map[string]store.SubScan)
		}
		netScan := scan.SubScans["network"]
		netScan.Type, netScan.Enabled, netScan.Status = "network", true, "running"
		netScan.Progress.Total, netScan.Progress.Completed = len(targetIPs), 0
		scan.SubScans["network"] = netScan
		scan.HostsCompleted = 0
		if scan.StartTime == "" {
			scan.StartTime = time.Now().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		slog.Warn("Cannot schedule scan", "scan_id", sm.currentScanID, "error", err)
		sm.finishKeyedRun()
		return
	}
	sm.logger.LogScanStarted(sm.currentScanID, targetIPs, map[string]interface{}{
		"scan_types": sm.currentScanOptions.ScanTypes,
		"port_range": sm.currentScanOptions.PortRange,
	})
	for _, ip := range targetIPs {
		if !sm.workerPool.addTask(sm.ctx, ScanTask{IP: ip, Options: sm.currentScanOptions, run: sm}) {
			return
		}
	}
}

// scanIP performs the actual scanning of a single IP using a sequential pipeline
func (sm *ScanManager) scanIP(ctx context.Context, ip string) {
	defer func() {
		// Cancelled/replaced runs must not contribute progress or success.
		if ctx.Err() != nil {
			return
		}
		if err := sm.markHostComplete(ip); err != nil {
			slog.Warn("Failed to mark host completion", "ip", ip, "error", err)
		}
	}()

	// Check for cancellation before starting
	if ctx.Err() != nil {
		slog.Debug("Cancelled before scanning", "ip", ip)
		return
	}

	// Validate if this is a single IP before proceeding
	if net.ParseIP(ip) == nil {
		slog.Warn("Expected single IP", "got", ip)
		return
	}

	slog.Debug("Starting scan pipeline", "ip", ip, "types", sm.currentScanOptions.ScanTypes, "template_ports", sm.currentScanOptions.PortRange)

	// PHASE 0: Fingerprinting (ping++ - host liveness and OS detection)
	// Uses ping++ for ICMP/TCP probing and TTL-based OS detection.
	// Discovered hosts are immediately submitted to the API for real-time visibility.
	if contains(sm.currentScanOptions.ScanTypes, "fingerprint") {
		slog.Debug("Phase 0: Fingerprinting scan", "ip", ip)
		startTime := time.Now()
		fingerprintStrategy := sm.toolFactory.CreateFingerprintTool()
		result, err := fingerprintStrategy.FingerprintWithContext(ctx, ip)
		duration := time.Since(startTime)

		if err != nil {
			slog.Error("Fingerprinting failed", "ip", ip, "error", err)
			if ctx.Err() == nil {
				sm.updateScanStatus("failed")
			}
			sm.logger.LogToolExecution(sm.currentScanID, ip, "ping++", duration, false, map[string]interface{}{
				"error": err.Error(),
			})
		} else if !result.IsAlive {
			slog.Warn("Host appears to be down, skipping further scans", "ip", ip)
			sm.logger.LogToolExecution(sm.currentScanID, ip, "ping++", duration, true, map[string]interface{}{
				"is_alive": false,
			})
			slog.Debug("Scan completed for host down", "ip", ip)
			return
		} else {
			slog.Debug("Fingerprint result", "host", ip, "alive", result.IsAlive, "os", result.OSFamily, "ttl", result.TTL)

			// Log tool execution success
			sm.logger.LogToolExecution(sm.currentScanID, ip, "ping++", duration, true, map[string]interface{}{
				"is_alive":  result.IsAlive,
				"os_family": result.OSFamily,
				"ttl":       result.TTL,
			})

			// Submit discovered host to API for real-time visibility
			if err := sm.submitFingerprintResult(ip, result); err != nil {
				slog.Warn("Failed to submit fingerprint data via API",
					"scan_id", sm.currentScanID,
					"ip", ip,
					"error", err)
				// Continue execution even if API submission fails
			} else {
				slog.Debug("Successfully submitted fingerprint discovery", "ip", ip)
			}

			// Update KV store with discovered host
			hostWasNew := false
			if err := sm.scanUpdater.UpdateForScan(context.Background(), sm.currentScanID, func(scan *store.ScanResult) error {
				hostWasNew = false
				if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
					return nil
				}
				var isNew bool
				scan.Hosts, isNew = mergeHost(scan.Hosts, ip, "", "network")
				if isNew {
					hostWasNew = true
				}
				if scan.StartTime == "" {
					scan.StartTime = time.Now().Format(time.RFC3339)
				}
				return nil
			}); err != nil {
				hostWasNew = false
				slog.Warn("Failed to update KV store with fingerprint discovery",
					"scan_id", sm.currentScanID,
					"ip", ip,
					"error", err)
			}

			// Log host discovered event
			if hostWasNew && sm.ctx.Err() == nil {
				sm.logger.LogHostDiscovered(ip, sm.currentScanID, map[string]interface{}{
					"os_family":  result.OSFamily,
					"ttl":        result.TTL,
					"discovery":  "fingerprint",
					"tool":       "ping++",
					"is_alive":   result.IsAlive,
					"confidence": result.Details["confidence"],
					"hops":       result.Details["hops"],
				})
			}
		}
	}

	// Check for cancellation after fingerprint phase
	if ctx.Err() != nil {
		slog.Debug("Cancelled after fingerprint phase", "ip", ip)
		return
	}

	var discoveredPorts []int

	// PHASE 1: Port Enumeration (Naabu - fast, accurate port discovery)
	// Supports both "enumeration" and "port_scan" scan types for backward compatibility
	if contains(sm.currentScanOptions.ScanTypes, "enumeration") || contains(sm.currentScanOptions.ScanTypes, "port_scan") {
		slog.Debug("Phase 1: Port enumeration scan", "ip", ip)
		ports, err := sm.runEnumeration(ctx, ip)
		if err != nil {
			slog.Error("Enumeration failed", "ip", ip, "error", err)
			if ctx.Err() == nil {
				sm.updateScanStatus("failed")
			}
		} else if len(ports) > 0 {
			discoveredPorts = ports
			slog.Debug("Enumeration found ports", "ip", ip, "count", len(ports), "ports", ports)
		} else {
			slog.Warn("Enumeration found no open ports", "ip", ip)
		}
	}

	// Check for cancellation after enumeration phase
	if ctx.Err() != nil {
		slog.Debug("Cancelled after enumeration phase", "ip", ip)
		return
	}

	// PHASE 2: Vulnerability Scanning (Nmap - uses discovered ports ONLY)
	if contains(sm.currentScanOptions.ScanTypes, "vulnerability") {
		slog.Debug("Phase 2: Vulnerability scan", "ip", ip)

		// Determine which ports to scan
		var portList string
		if len(discoveredPorts) > 0 {
			// Use discovered ports from discovery/enumeration
			portList = portsToString(discoveredPorts)
			slog.Debug("Using discovered ports", "ip", ip, "count", len(discoveredPorts), "port_list", portList)
		} else if sm.currentScanOptions.PortRange != "" {
			// Fallback to template port range if no ports discovered
			portList = sm.currentScanOptions.PortRange
			slog.Warn("No ports discovered, falling back to template port_range", "port_list", portList)
		} else {
			// No ports discovered and no template range - skip
			slog.Warn("No ports discovered and no port_range specified, skipping vulnerability scan", "ip", ip)
			slog.Debug("Scan completed", "ip", ip)
			return
		}

		// Run vulnerability scan with specific ports
		if err := sm.runVulnerabilityWithPorts(ctx, ip, portList); err != nil {
			slog.Error("Vulnerability scan failed", "ip", ip, "error", err)
			if ctx.Err() == nil {
				sm.updateScanStatus("failed")
			}
		} else {
			slog.Debug("Vulnerability scan completed", "ip", ip)
		}
	}

	slog.Debug("Scan pipeline completed", "ip", ip)
}

// markHostComplete accounts for one scheduled network target.
func (sm *ScanManager) markHostComplete(ip string) error {
	var updated *store.ScanResult
	err := sm.scanUpdater.UpdateForScan(context.Background(), sm.currentScanID, func(scan *store.ScanResult) error {
		updated = nil
		if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
			return nil
		}
		netScan, ok := scan.SubScans["network"]
		if !ok || scanIsTerminal(netScan.Status) || netScan.Progress.Total <= 0 {
			return nil
		}
		if scan.HostsCompleted >= netScan.Progress.Total {
			return nil
		}
		scan.HostsCompleted++
		netScan.Progress.Completed = scan.HostsCompleted
		if scan.HostsCompleted == netScan.Progress.Total {
			netScan.Status = "completed"
		}
		scan.SubScans["network"] = netScan
		finishScanIfDone(scan)
		updated = scan
		return nil
	})
	if err != nil {
		return err
	}
	if updated != nil {
		sm.logger.LogScanEvent(sm.currentScanID, "host_completed", "Host scan completed", map[string]interface{}{
			"host_ip": ip, "hosts_completed": updated.HostsCompleted, "total_hosts": len(updated.Hosts),
		})
		if updated.Status == "completed" {
			sm.logger.LogScanCompleted(sm.currentScanID, map[string]interface{}{
				"hosts_discovered": len(updated.Hosts), "hosts_completed": updated.HostsCompleted,
				"vulnerabilities_found": len(updated.Vulnerabilities), "total_hosts": len(updated.Hosts),
			})
			sm.finishKeyedRun()
		}
	}
	return nil
}

// runEnumeration performs the enumeration scan
func (sm *ScanManager) runEnumeration(ctx context.Context, ip string) ([]int, error) {
	startTime := time.Now()
	enumStrategy := sm.toolFactory.CreateTool("enumeration")
	enumResults, err := enumStrategy.ExecuteWithContext(ctx, ip)
	duration := time.Since(startTime)

	if err != nil {
		sm.logger.LogToolExecution(sm.currentScanID, ip, "naabu", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("port enumeration failed for %s: %w", ip, err)
	}

	// Extract enumerated ports
	enumeratedPorts := make([]int, len(enumResults.Ports))
	for i, port := range enumResults.Ports {
		enumeratedPorts[i] = port.Number
	}

	// Log tool execution success
	sm.logger.LogToolExecution(sm.currentScanID, ip, "naabu", duration, true, map[string]interface{}{
		"ports_found": len(enumeratedPorts),
		"ports":       enumeratedPorts,
	})

	// Submit host data to database if ports were found
	if len(enumResults.Ports) > 0 {
		// Determine the actual tool used based on scan type - enumeration uses Naabu
		toolName := "naabu"

		// Submit host data using the new source-aware API
		if err := sm.submitHostWithSource(enumResults, toolName); err != nil {
			slog.Warn("Failed to submit enumeration data via source-aware API",
				"scan_id", sm.currentScanID,
				"ip", ip,
				"error", err)
			slog.Debug("API may be unavailable or endpoint not implemented; continuing without database persistence")
			// Continue execution even if database operations fail
		} else {
			slog.Debug("Successfully added host with enumeration data using source-aware API", "ip", enumResults.IP)
		}
	}

	// Update KV store with enumeration details but preserve existing data
	// Guard: only add host if enumResults.IP is non-empty (naabu returns empty Host{} when host is down)
	hostWasNew := false
	if enumResults.IP != "" {
		if err := sm.scanUpdater.UpdateForScan(context.Background(), sm.currentScanID, func(scan *store.ScanResult) error {
			hostWasNew = false
			if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
				return nil
			}
			var isNew bool
			scan.Hosts, isNew = mergeHost(scan.Hosts, enumResults.IP, "", "network")
			if isNew {
				hostWasNew = true
			}
			if scan.StartTime == "" {
				scan.StartTime = time.Now().Format(time.RFC3339)
			}
			return nil
		}); err != nil {
			slog.Error("Failed to merge enumeration results into current scan state",
				"scan_id", sm.currentScanID,
				"ip", ip,
				"error", err)
			return nil, fmt.Errorf("failed to update scan with enumeration results for host %s: %w", ip, err)
		}

		// Log host discovered event (new event system)
		if hostWasNew {
			sm.logger.LogHostDiscovered(enumResults.IP, sm.currentScanID, map[string]interface{}{
				"ports_found": len(enumeratedPorts),
				"os":          enumResults.OS,
			})
		}
	}

	slog.Debug("Enumeration results", "ip", enumResults.IP, "hostname", enumResults.Hostname, "ports", len(enumResults.Ports), "services", len(enumResults.Services), "os", enumResults.OS)
	return enumeratedPorts, nil // Return enumerated ports for pipeline
}

// portsToString converts []int{80, 443, 445} to "80,443,445"
func portsToString(ports []int) string {
	strPorts := make([]string, len(ports))
	for i, port := range ports {
		strPorts[i] = strconv.Itoa(port)
	}
	return strings.Join(strPorts, ",")
}

// runVulnerability performs the vulnerability scan
func (sm *ScanManager) runVulnerability(ctx context.Context, ip string) error {
	return sm.runVulnerabilityWithPorts(ctx, ip, "")
}

// runVulnerabilityWithPorts performs vulnerability scan with optional port override
func (sm *ScanManager) runVulnerabilityWithPorts(ctx context.Context, ip string, portList string) error {
	startTime := time.Now()

	// Port overrides are host-local. Mutating the shared options races with
	// other workers and can attribute one host's port list to another host.
	sm = sm.forHostPorts(portList)

	// Get script list from template if template ID is provided
	var scriptList []string
	if sm.currentScanOptions.TemplateID != "" {
		scripts, err := sm.templateManager.ResolveScripts(sm.ctx, sm.currentScanOptions.TemplateID)
		if err != nil {
			slog.Warn("Failed to resolve scripts from template", "error", err)
		} else {
			scriptList = scripts
			slog.Info("Resolved scripts from template", "count", len(scriptList), "template_id", sm.currentScanOptions.TemplateID)
		}
	}

	// Create vulnerability tool with script list
	vulnStrategy := sm.toolFactory.CreateTool("vulnerability")

	// If we have an nmap strategy, configure it with scripts and the current port range
	if nmapStrat, ok := vulnStrategy.(*NmapStrategy); ok {
		// Set scripts if available
		if len(scriptList) > 0 {
			nmapStrat.ScriptList = scriptList
		}
		// CRITICAL: Update the port range from currentScanOptions (which may have been overridden)
		nmapStrat.PortRange = sm.currentScanOptions.PortRange
		slog.Debug("Configured Nmap strategy", "script_count", len(scriptList), "port_range", nmapStrat.PortRange)
	}

	vulnResults, err := vulnStrategy.ExecuteWithContext(ctx, ip)
	duration := time.Since(startTime)

	if err != nil {
		sm.logger.LogToolExecution(sm.currentScanID, ip, "nmap", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("vulnerability scan failed for %s: %w", ip, err)
	}

	slog.Debug("Found vulnerabilities for host", "ip", ip, "count", len(vulnResults.Vulnerabilities))

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

	// Submit host data using the new source-aware API. If submission fails
	// we degrade gracefully and continue the rest of the scan; the KV-store
	// update below still records vulnerabilities so the scan UI is not blocked
	// by an unhealthy or not-yet-implemented API endpoint. See
	// SHA-AUDIT-2026-04.md for the original rationale (formerly an inline sed
	// patch in sirius-engine/Dockerfile).
	if err := sm.submitHostWithSource(vulnResults, toolName); err != nil {
		slog.Error("Failed to submit host data via source-aware API", "error", err)
		slog.Debug("API may be unavailable or endpoint not implemented")
		slog.Warn("Will continue scan without source-attributed persistence", "error", err)
	}

	// Update KV store with vulnerability details
	if err := sm.scanUpdater.UpdateForScan(context.Background(), sm.currentScanID, func(scan *store.ScanResult) error {
		if scanIsTerminal(scan.Status) || scan.Status == "cancelling" {
			return nil
		}
		// Profiles may run Nmap without fingerprinting or enumeration. Record
		// that discovered host too, even when there are no vulnerabilities.
		scan.Hosts, _ = mergeHost(scan.Hosts, vulnResults.IP, vulnResults.Hostname, "network")
		for _, vuln := range vulnResults.Vulnerabilities {
			severity := calculateSeverity(vuln.RiskScore)
			scan.Vulnerabilities = append(scan.Vulnerabilities, store.VulnerabilitySummary{
				ID:          vuln.VID,
				Severity:    severity,
				Title:       vuln.Title,
				Description: vuln.Description,
				RiskScore:   vuln.RiskScore,
				ScanSource:  "network",
				HostID:      vulnResults.IP,
			})
		}
		return nil
	}); err != nil {
		return fmt.Errorf("failed to update scan with vulnerabilities for host %s: %w", vulnResults.IP, err)
	}

	slog.Debug("Successfully processed host with vulnerabilities using source-aware API", "ip", ip, "vulnerability_count", len(vulnResults.Vulnerabilities))
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
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
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

// GetActiveScanContext returns the context for the currently running scan.
// Returns nil if no scan is active.
func (sm *ScanManager) GetActiveScanContext() context.Context {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	return sm.activeScanCtx
}

// IsCancelling returns whether a cancellation is in progress
func (sm *ScanManager) IsCancelling() bool {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	return sm.isCancelling
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
		slog.Debug("NmapStrategy protocols set", "protocols", strategy.Protocols)
	}
}

// ControlMessage represents a control command for the scanner
type ControlMessage struct {
	Action    string `json:"action"`    // Action to perform (e.g., "cancel")
	ScanID    string `json:"scan_id"`   // Required: exact scan to cancel
	Timestamp string `json:"timestamp"` // When the command was issued
	StateMode string `json:"state_mode,omitempty"`
}

// ListenForCancelCommands starts listening for scan control commands on the scan_control queue.
// This allows external systems (like the API) to cancel running scans.
// Uses ListenWithRetry for resilient connection handling.
func (sm *ScanManager) ListenForCancelCommands() {
	slog.Info("Starting scan control listener on queue", "queue", "scan_control")
	queue.ListenWithRetry(sm.ctx, "scan_control", sm.handleControlMessage)
}

// handleControlMessage processes incoming control commands
func (sm *ScanManager) handleControlMessage(msg string) {
	cmd, err := decodeControlMessage([]byte(msg))
	if err != nil {
		slog.Error("Invalid control message", "error", err)
		return
	}

	slog.Debug("Received control command", "action", cmd.Action, "scan_id", cmd.ScanID, "timestamp", cmd.Timestamp)
	if cmd.StateMode == "keyed" {
		if cmd.Action == "cancel" || cmd.Action == "force_cancel" {
			sm.cancelKeyedRun(cmd.ScanID)
		}
		return
	}
	if cmd.StateMode != "" {
		return
	}

	switch cmd.Action {
	case "cancel":
		sm.CancelCurrentScan(cmd.ScanID)
	case "force_cancel":
		sm.ForceStopCurrentScan(cmd.ScanID)
	default:
		slog.Warn("Unknown control action", "action", cmd.Action)
	}
}

// CancelCurrentScan cancels only the explicitly identified scan. Untargeted
// commands are rejected because delayed queue delivery could hit a later scan.
func (sm *ScanManager) CancelCurrentScan(scanID string) { sm.cancelScan(scanID, false) }

func (sm *ScanManager) ForceStopCurrentScan(scanID string) { sm.cancelScan(scanID, true) }

func (sm *ScanManager) cancelScan(scanID string, force bool) {
	sm.scanMutex.Lock()
	defer sm.scanMutex.Unlock()
	if scanID == "" {
		slog.Warn("Ignoring untargeted cancellation")
		return
	}
	sameLocalRun := sm.currentScanID == scanID
	if sameLocalRun && sm.activeScanCancel != nil {
		// An exact local match may always stop its own work, even if storage
		// has since advanced or is unavailable. Never stop a different run yet.
		sm.isCancelling = true
		sm.activeScanCancel()
	}
	// The persisted ID is authoritative. Agent-only scans and requests queued
	// before dequeue have no matching local network run. CAS validates the ID
	// and preserves a replacement if it changes while cancellation is written.
	changed, err := sm.setScanStatus(scanID, "cancelled")
	if err != nil {
		return
	}
	if !sameLocalRun {
		// A verified newer authoritative scan supersedes any leftover local
		// network work. It is safe to stop that obsolete context, not to reuse it.
		if sm.activeScanCancel != nil {
			sm.activeScanCancel()
		}
		sm.currentScanID = scanID
		sm.activeScanCtx, sm.activeScanCancel = nil, nil
	}
	sm.isCancelling = true
	// Repeated cancellation retries failed writes but never reports a new
	// cancellation for a terminal scan whose persisted outcome did not change.
	if !changed {
		return
	}
	event := "scan_cancelled"
	if force {
		event = "scan_force_stopped"
	}
	sm.logger.LogScanEvent(scanID, event, "Scan was cancelled by user", map[string]interface{}{"scan_id": scanID})
}

func (sm *ScanManager) updateScanStatus(status string) {
	sm.setScanStatus(sm.currentScanID, status)
	if status == "failed" && sm.cancel != nil {
		sm.cancel()
		sm.finishKeyedRun()
	}
}

func (sm *ScanManager) failScan(scanID string) { sm.setScanStatus(scanID, "failed") }

func (sm *ScanManager) setScanStatus(scanID, status string) (bool, error) {
	changed := false
	err := sm.scanUpdater.UpdateForScan(context.Background(), scanID, func(scan *store.ScanResult) error {
		changed = false
		if scanIsTerminal(scan.Status) {
			return nil
		}
		if scan.Status == "cancelling" && status != "cancelled" {
			return nil
		}
		if status == "failed" {
			// A network failure stops this run, not the other enabled scanners.
			// Keep accepting their results until every sub-scan is terminal.
			if scan.SubScans == nil {
				scan.SubScans = make(map[string]store.SubScan)
			}
			netScan, exists := scan.SubScans["network"]
			if exists && scanIsTerminal(netScan.Status) {
				return nil
			}
			changed = true
			netScan.Type, netScan.Enabled, netScan.Status = "network", true, "failed"
			scan.SubScans["network"] = netScan
			scan.Status = "running"
			finishScanIfDone(scan)
			return nil
		}
		changed = scan.Status != status
		scan.Status = status
		if status == "cancelled" {
			scan.EndTime = time.Now().Format(time.RFC3339)
			if netScan, ok := scan.SubScans["network"]; ok && !scanIsTerminal(netScan.Status) {
				netScan.Status = status
				scan.SubScans["network"] = netScan
			}
		}
		return nil
	})
	if err != nil {
		slog.Warn("Failed to update scan status", "scan_id", scanID, "status", status, "error", err)
	}
	return changed && err == nil, err
}

// Stale recovery uses the same injected store and identity check as active work.
// Corrupt state is left intact for diagnosis rather than deleting an unknown scan.
func (sm *ScanManager) clearStaleScanData(scanID string) { sm.setScanStatus(scanID, "cancelled") }

// decodeBase64 decodes a base64 string
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
