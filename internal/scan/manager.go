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

// Default number of worker goroutines (shared pool across concurrent jobs).
const DEFAULT_WORKERS = 24
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
	ID             string      `json:"id"`                         // Unique identifier for this scan
	OwnerSubjectID string      `json:"owner_subject_id,omitempty"` // Pro/class owner; empty = Community legacy
	Targets        []Target    `json:"targets"`                    // List of targets to scan
	Options        ScanOptions `json:"options"`                    // Scan configuration options
	Priority       int         `json:"priority"`                   // Scan priority (1-5)
	CallbackURL    string      `json:"callback_url"`               // Optional webhook for scan completion
}

// ScanManager manages scan operations.
type ScanManager struct {
	workerPool      *WorkerPool
	ctx             context.Context
	cancel          context.CancelFunc
	nseSync         *nse.SyncManager
	templateManager *TemplateManager
	scanStrategies  map[string]ScanStrategy
	options         *ScanOptions
	toolFactory     *ScanToolFactory
	scanUpdater     *ScanUpdater
	kvStore         store.KVStore
	apiBaseURL      string         // API base URL for source-aware submissions
	apiHTTPClient   *http.Client   // Shared HTTP client for API submissions
	logger          *LoggingClient // Centralized logging client

	// Concurrent per-job isolation
	jobs   map[string]*JobContext
	jobsMu sync.RWMutex
}

// SourcedHostRequest represents the request structure for source-aware API submissions
type SourcedHostRequest struct {
	Host           sirius.Host       `json:"host"`
	Source         models.ScanSource `json:"source"`
	OwnerSubjectID string            `json:"owner_subject_id,omitempty"`
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
		jobs:            make(map[string]*JobContext),
		scanStrategies: map[string]ScanStrategy{
			"nmap": &NmapStrategy{},
		},
	}

	// Create and start the shared worker pool
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
func (sm *ScanManager) createScanSource(toolName, scanID string, opts ScanOptions) models.ScanSource {
	version := sm.detectScannerVersion(toolName)
	systemInfo := sm.getSystemInfo()

	// Build comprehensive configuration string
	var configParts []string

	// Scan-specific configuration
	if opts.PortRange != "" {
		configParts = append(configParts, fmt.Sprintf("ports:%s", opts.PortRange))
	}
	if opts.Aggressive {
		configParts = append(configParts, "aggressive:true")
	}
	if len(opts.ScanTypes) > 0 {
		configParts = append(configParts, fmt.Sprintf("types:%s", strings.Join(opts.ScanTypes, ",")))
	}
	if len(opts.ExcludePorts) > 0 {
		configParts = append(configParts, fmt.Sprintf("exclude:%s", strings.Join(opts.ExcludePorts, ",")))
	}
	if opts.TemplateID != "" {
		configParts = append(configParts, fmt.Sprintf("template:%s", opts.TemplateID))
	}

	// System information for audit trail
	if hostname, ok := systemInfo["hostname"]; ok {
		configParts = append(configParts, fmt.Sprintf("host:%s", hostname))
	}
	if user, ok := systemInfo["user"]; ok {
		configParts = append(configParts, fmt.Sprintf("user:%s", user))
	}

	// Scanner metadata
	configParts = append(configParts, fmt.Sprintf("scanner_id:%s", scanID))
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
func (sm *ScanManager) submitHostWithSource(host sirius.Host, toolName, scanID string, opts ScanOptions) error {
	source := sm.createScanSource(toolName, scanID, opts)

	ownerSubjectID := ""
	if job := sm.GetJobContext(scanID); job != nil {
		ownerSubjectID = job.OwnerSubjectID
	}

	request := SourcedHostRequest{
		Host:           host,
		Source:         source,
		OwnerSubjectID: ownerSubjectID,
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
func (sm *ScanManager) submitFingerprintResult(ip string, result FingerprintResult, scanID string, opts ScanOptions) error {
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

	return sm.submitHostWithSource(host, "ping++", scanID, opts)
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

// handleMessage processes incoming scan requests.
// Work runs in a new goroutine so the Rabbit listener can accept concurrent jobs.
func (sm *ScanManager) handleMessage(msg string) {
	var scanMsg ScanMessage
	if err := json.Unmarshal([]byte(msg), &scanMsg); err != nil {
		slog.Error("Invalid scan message", "error", err)
		sm.logger.LogScanError("unknown", "unknown", "message_parse_error", "Failed to parse scan message", err)
		return
	}

	sm.logger.LogScanEvent(scanMsg.ID, "scan_initiated", "Scan request received", map[string]interface{}{
		"targets_count":    len(scanMsg.Targets),
		"priority":         scanMsg.Priority,
		"template_id":      scanMsg.Options.TemplateID,
		"scan_types":       scanMsg.Options.ScanTypes,
		"owner_subject_id": scanMsg.OwnerSubjectID,
	})

	// Resolve template if template ID provided
	if scanMsg.Options.TemplateID != "" {
		template, err := sm.templateManager.GetTemplate(sm.ctx, scanMsg.Options.TemplateID)
		if err != nil {
			slog.Error("Failed to get template", "template_id", scanMsg.Options.TemplateID, "error", err)
			sm.logger.LogScanError(scanMsg.ID, "template_resolution", "template_not_found", "Failed to resolve template", err)
			sm.failJobEarly(scanMsg.ID, scanMsg.OwnerSubjectID, "failed")
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

	if err := sm.validateScanMessage(&scanMsg); err != nil {
		slog.Error("Invalid scan configuration", "error", err)
		sm.logger.LogScanError(scanMsg.ID, "validation", "scan_validation_error", "Invalid scan configuration", err)
		return
	}

	// Expand all targets before registering so we can enforce the per-job cap.
	var allIPs []string
	targetValues := make([]string, 0, len(scanMsg.Targets))
	for _, target := range scanMsg.Targets {
		targetValues = append(targetValues, target.Value)
		ips, err := sm.prepareTarget(target)
		if err != nil {
			slog.Error("Failed to prepare target", "target_value", target.Value, "error", err)
			sm.logger.LogScanError(scanMsg.ID, target.Value, "target_preparation_error", "Failed to prepare target", err)
			sm.failJobEarly(scanMsg.ID, scanMsg.OwnerSubjectID, "failed")
			return
		}
		allIPs = append(allIPs, ips...)
	}

	if len(allIPs) > MaxExpandedTargetsPerJob {
		err := fmt.Errorf("expanded target count %d exceeds per-job cap of %d", len(allIPs), MaxExpandedTargetsPerJob)
		slog.Error("Scan rejected: target cap exceeded", "scan_id", scanMsg.ID, "count", len(allIPs), "cap", MaxExpandedTargetsPerJob)
		sm.logger.LogScanError(scanMsg.ID, "validation", "target_cap_exceeded", err.Error(), err)
		sm.failJobEarly(scanMsg.ID, scanMsg.OwnerSubjectID, "failed")
		return
	}

	jobCtx, jobCancel := context.WithCancel(sm.ctx)
	job := &JobContext{
		ID:             scanMsg.ID,
		OwnerSubjectID: scanMsg.OwnerSubjectID,
		Options:        scanMsg.Options,
		Ctx:            jobCtx,
		Cancel:         jobCancel,
		HostsExpected:  len(allIPs),
	}
	sm.registerJob(job)

	if err := sm.initializeJobValkey(job, targetValues); err != nil {
		slog.Error("Failed to initialize job Valkey state", "scan_id", job.ID, "error", err)
		sm.unregisterJob(job.ID)
		jobCancel()
		return
	}

	// Critical: return quickly so ListenWithRetry can accept overlapping jobs.
	go sm.executeJob(job, allIPs, targetValues)
}

// executeJob enqueues expanded IPs onto the shared worker pool for a registered job.
func (sm *ScanManager) executeJob(job *JobContext, ips []string, targetValues []string) {
	if job == nil {
		return
	}

	sm.logger.LogScanEvent(job.ID, "target_prepared", "Targets prepared successfully", map[string]interface{}{
		"ips_generated": len(ips),
		"targets":       targetValues,
	})

	if err := sm.applyScanUpdate(job.ID, false, func(scan *store.ScanResult) error {
		if scan.SubScans == nil {
			scan.SubScans = make(map[string]store.SubScan)
		}
		netScan, ok := scan.SubScans["network"]
		if !ok {
			netScan = store.SubScan{
				Type:    "network",
				Enabled: true,
				Status:  "running",
				Progress: store.SubScanProgress{
					Label: "hosts",
				},
			}
		}
		netScan.Progress.Total += len(ips)
		scan.SubScans["network"] = netScan
		if scan.StartTime == "" {
			scan.StartTime = time.Now().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		slog.Warn("Failed to update expected network target count",
			"scan_id", job.ID,
			"count", len(ips),
			"error", err)
	}

	sm.logger.LogScanStarted(job.ID, ips, map[string]interface{}{
		"scan_types": job.Options.ScanTypes,
		"port_range": job.Options.PortRange,
	})

	if len(ips) == 0 {
		sm.unregisterJob(job.ID)
		return
	}

	for _, ip := range ips {
		sm.workerPool.AddTask(ScanTask{
			ScanID:  job.ID,
			IP:      ip,
			Options: job.Options,
		})
	}
}

// failJobEarly writes a terminal failure status for a job that never registered workers.
func (sm *ScanManager) failJobEarly(scanID, ownerSubjectID, status string) {
	if scanID == "" {
		return
	}
	ctx := context.Background()
	_ = sm.scanUpdater.UpdateScan(ctx, scanID, func(scan *store.ScanResult) error {
		scan.ID = scanID
		scan.Status = status
		scan.EndTime = time.Now().Format(time.RFC3339)
		return nil
	})
	if ownerSubjectID == "" {
		_ = sm.scanUpdater.Update(ctx, func(scan *store.ScanResult) error {
			scan.Status = status
			scan.EndTime = time.Now().Format(time.RFC3339)
			return nil
		})
	} else {
		_ = sm.kvStore.SetValue(ctx, ScanStatusKey(scanID), status)
	}
}

// initializeJobValkey ensures scan:state:<id> exists and writes owned-scan keys when applicable.
func (sm *ScanManager) initializeJobValkey(job *JobContext, targets []string) error {
	ctx := context.Background()

	if err := sm.scanUpdater.UpdateScan(ctx, job.ID, func(scan *store.ScanResult) error {
		if scan.ID == "" {
			scan.ID = job.ID
		}
		if scan.Status == "" {
			scan.Status = "running"
		}
		if len(scan.Targets) == 0 {
			scan.Targets = targets
		}
		if scan.StartTime == "" {
			scan.StartTime = time.Now().Format(time.RFC3339)
		}
		if scan.Hosts == nil {
			scan.Hosts = []store.HostEntry{}
		}
		if scan.Vulnerabilities == nil {
			scan.Vulnerabilities = []store.VulnerabilitySummary{}
		}
		if scan.SubScans == nil {
			scan.SubScans = map[string]store.SubScan{
				"network": {
					Type:    "network",
					Enabled: true,
					Status:  "running",
					Progress: store.SubScanProgress{
						Label: "hosts",
					},
				},
			}
		}
		return nil
	}); err != nil {
		return err
	}

	if job.IsOwned() {
		if err := sm.kvStore.SetValue(ctx, ScanOwnerKey(job.ID), job.OwnerSubjectID); err != nil {
			return fmt.Errorf("set scan owner: %w", err)
		}
		if err := sm.kvStore.SetValue(ctx, ScanLatestKey(job.OwnerSubjectID), job.ID); err != nil {
			return fmt.Errorf("set scan latest: %w", err)
		}
		if err := sm.kvStore.SetValue(ctx, ScanStatusKey(job.ID), "running"); err != nil {
			return fmt.Errorf("set scan status: %w", err)
		}
		// Owned/class jobs do not require writing global currentScan.
		return nil
	}

	// Community legacy path: also mirror into currentScan when missing/empty fields.
	_ = sm.scanUpdater.Update(ctx, func(scan *store.ScanResult) error {
		if scan.ID == "" {
			scan.ID = job.ID
		}
		if scan.Status == "" {
			scan.Status = "running"
		}
		if scan.StartTime == "" {
			scan.StartTime = time.Now().Format(time.RFC3339)
		}
		return nil
	})
	return nil
}

// applyScanUpdate writes scan:state:<id>; for legacy (empty owner) also mirrors to currentScan.
// When skipIfCancelling is true, result merges are skipped for cancelling jobs (fail closed).
func (sm *ScanManager) applyScanUpdate(scanID string, skipIfCancelling bool, modifier func(*store.ScanResult) error) error {
	job := sm.GetJobContext(scanID)
	if skipIfCancelling && job != nil && job.Cancelling() {
		return nil
	}

	ctx := context.Background()
	if err := sm.scanUpdater.UpdateScan(ctx, scanID, modifier); err != nil {
		return err
	}

	// Legacy Community path: re-read keyed state and copy into currentScan so
	// relative modifiers are not applied twice.
	if job == nil || !job.IsOwned() {
		if err := sm.mirrorStateToCurrentScan(ctx, scanID); err != nil {
			slog.Debug("Legacy currentScan mirror failed", "scan_id", scanID, "error", err)
		}
	}
	return nil
}

// mirrorStateToCurrentScan copies scan:state:<id> onto the legacy currentScan key.
func (sm *ScanManager) mirrorStateToCurrentScan(ctx context.Context, scanID string) error {
	resp, err := sm.kvStore.GetValue(ctx, ScanStateKey(scanID))
	if err != nil {
		return err
	}
	return sm.kvStore.SetValue(ctx, LegacyCurrentScanKey, resp.Message.Value)
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

// scanIP performs the actual scanning of a single IP using a sequential pipeline.
// Options and cancel context come from the JobContext for scanID.
func (sm *ScanManager) scanIP(ctx context.Context, scanID, ip string) {
	job := sm.GetJobContext(scanID)
	if job == nil {
		slog.Debug("scanIP skipped — job not registered", "scan_id", scanID, "ip", ip)
		return
	}
	opts := job.Options

	defer func() {
		// NOTE: cancellation short-circuit intentionally disabled. Preserved
		// from a long-standing inline-sed patch in sirius-engine/Dockerfile;
		// removing it requires understanding why markHostComplete must run
		// even after the context is cancelled. See SHA-AUDIT-2026-04.md.
		if false && ctx.Err() != nil {
			return
		}
		if err := sm.markHostComplete(scanID, ip); err != nil {
			slog.Warn("Failed to mark host completion", "scan_id", scanID, "ip", ip, "error", err)
		}
	}()

	// Check for cancellation before starting
	if ctx.Err() != nil {
		slog.Debug("Cancelled before scanning", "scan_id", scanID, "ip", ip)
		return
	}

	// Validate if this is a single IP before proceeding
	if net.ParseIP(ip) == nil {
		slog.Warn("Expected single IP", "got", ip)
		return
	}

	slog.Debug("Starting scan pipeline", "scan_id", scanID, "ip", ip, "types", opts.ScanTypes, "template_ports", opts.PortRange)

	// PHASE 0: Fingerprinting (ping++ - host liveness and OS detection)
	if contains(opts.ScanTypes, "fingerprint") {
		slog.Debug("Phase 0: Fingerprinting scan", "ip", ip)
		startTime := time.Now()
		fingerprintStrategy := CreateFingerprintToolWithOptions(opts)
		result, err := fingerprintStrategy.Fingerprint(ip)
		duration := time.Since(startTime)

		if err != nil {
			slog.Error("Fingerprinting failed", "ip", ip, "error", err)
			sm.logger.LogToolExecution(scanID, ip, "ping++", duration, false, map[string]interface{}{
				"error": err.Error(),
			})
		} else if !result.IsAlive {
			slog.Warn("Host appears to be down, skipping further scans", "ip", ip)
			sm.logger.LogToolExecution(scanID, ip, "ping++", duration, true, map[string]interface{}{
				"is_alive": false,
			})
			slog.Debug("Scan completed for host down", "ip", ip)
			return
		} else {
			slog.Debug("Fingerprint result", "host", ip, "alive", result.IsAlive, "os", result.OSFamily, "ttl", result.TTL)

			sm.logger.LogToolExecution(scanID, ip, "ping++", duration, true, map[string]interface{}{
				"is_alive":  result.IsAlive,
				"os_family": result.OSFamily,
				"ttl":       result.TTL,
			})

			if err := sm.submitFingerprintResult(ip, result, scanID, opts); err != nil {
				slog.Warn("Failed to submit fingerprint data via API",
					"scan_id", scanID,
					"ip", ip,
					"error", err)
			} else {
				slog.Debug("Successfully submitted fingerprint discovery", "ip", ip)
			}

			hostWasNew := false
			if err := sm.applyScanUpdate(scanID, true, func(scan *store.ScanResult) error {
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
				slog.Warn("Failed to update KV store with fingerprint discovery",
					"scan_id", scanID,
					"ip", ip,
					"error", err)
			}

			if hostWasNew {
				sm.logger.LogHostDiscovered(ip, scanID, map[string]interface{}{
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

	if ctx.Err() != nil {
		slog.Debug("Cancelled after fingerprint phase", "ip", ip)
		return
	}

	var discoveredPorts []int

	if contains(opts.ScanTypes, "enumeration") || contains(opts.ScanTypes, "port_scan") {
		slog.Debug("Phase 1: Port enumeration scan", "ip", ip)
		ports, err := sm.runEnumeration(ctx, scanID, ip, opts)
		if err != nil {
			slog.Error("Enumeration failed", "ip", ip, "error", err)
		} else if len(ports) > 0 {
			discoveredPorts = ports
			slog.Debug("Enumeration found ports", "ip", ip, "count", len(ports), "ports", ports)
		} else {
			slog.Warn("Enumeration found no open ports", "ip", ip)
		}
	}

	if ctx.Err() != nil {
		slog.Debug("Cancelled after enumeration phase", "ip", ip)
		return
	}

	if contains(opts.ScanTypes, "vulnerability") {
		slog.Debug("Phase 2: Vulnerability scan", "ip", ip)

		var portList string
		if len(discoveredPorts) > 0 {
			portList = portsToString(discoveredPorts)
			slog.Debug("Using discovered ports", "ip", ip, "count", len(discoveredPorts), "port_list", portList)
		} else if opts.PortRange != "" {
			portList = opts.PortRange
			slog.Warn("No ports discovered, falling back to template port_range", "port_list", portList)
		} else {
			slog.Warn("No ports discovered and no port_range specified, skipping vulnerability scan", "ip", ip)
			slog.Debug("Scan completed", "ip", ip)
			return
		}

		if err := sm.runVulnerabilityWithPorts(ctx, scanID, ip, portList, opts); err != nil {
			slog.Error("Vulnerability scan failed", "ip", ip, "error", err)
		} else {
			slog.Debug("Vulnerability scan completed", "ip", ip)
		}
	}

	slog.Debug("Scan pipeline completed", "ip", ip)
}

// markHostComplete updates the scan status for a completed host.
func (sm *ScanManager) markHostComplete(scanID, ip string) error {
	job := sm.GetJobContext(scanID)
	completed, expected := 0, 0
	if job != nil {
		completed, expected = job.IncrementCompleted()
		if job.Cancelling() {
			// Terminal writers fail closed after cancel; just finish accounting.
			if expected > 0 && completed >= expected {
				sm.unregisterJob(scanID)
			}
			return nil
		}
	}

	var becameComplete bool
	err := sm.applyScanUpdate(scanID, true, func(scan *store.ScanResult) error {
		scan.HostsCompleted++
		totalExpected := 0

		if netScan, ok := scan.SubScans["network"]; ok {
			netScan.Progress.Completed = scan.HostsCompleted
			totalExpected = netScan.Progress.Total
			scan.SubScans["network"] = netScan
		}

		sm.logger.LogScanEvent(scanID, "host_completed", "Host scan completed", map[string]interface{}{
			"host_ip":         ip,
			"hosts_completed": scan.HostsCompleted,
			"total_hosts":     len(scan.Hosts),
		})

		networkHostCount := 0
		for _, h := range scan.Hosts {
			for _, src := range h.Sources {
				if src == "network" {
					networkHostCount++
					break
				}
			}
		}

		if totalExpected == 0 {
			totalExpected = networkHostCount
		}
		if expected > totalExpected {
			totalExpected = expected
		}
		if totalExpected < scan.HostsCompleted {
			totalExpected = scan.HostsCompleted
		}

		if scan.HostsCompleted >= totalExpected && totalExpected > 0 {
			if netScan, ok := scan.SubScans["network"]; ok {
				netScan.Status = "completed"
				netScan.Progress.Total = totalExpected
				netScan.Progress.Completed = totalExpected
				scan.SubScans["network"] = netScan
			}

			sm.logger.LogScanCompleted(scanID, map[string]interface{}{
				"hosts_discovered":      len(scan.Hosts),
				"hosts_completed":       scan.HostsCompleted,
				"vulnerabilities_found": len(scan.Vulnerabilities),
				"total_hosts":           len(scan.Hosts),
			})

			allDone := true
			for _, ss := range scan.SubScans {
				if ss.Enabled && ss.Status != "completed" && ss.Status != "failed" {
					allDone = false
					break
				}
			}
			if allDone {
				scan.Status = "completed"
				scan.EndTime = time.Now().Format(time.RFC3339)
				becameComplete = true
			}
		}
		return nil
	})

	if becameComplete || (expected > 0 && completed >= expected) {
		if job != nil && job.IsOwned() {
			_ = sm.kvStore.SetValue(context.Background(), ScanStatusKey(scanID), "completed")
		}
		sm.unregisterJob(scanID)
	}
	return err
}

// runEnumeration performs the enumeration scan
func (sm *ScanManager) runEnumeration(ctx context.Context, scanID, ip string, opts ScanOptions) ([]int, error) {
	startTime := time.Now()
	enumStrategy := CreateToolWithOptions(opts, "enumeration")
	enumResults, err := enumStrategy.ExecuteWithContext(ctx, ip)
	duration := time.Since(startTime)

	if err != nil {
		sm.logger.LogToolExecution(scanID, ip, "naabu", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return nil, fmt.Errorf("port enumeration failed for %s: %w", ip, err)
	}

	enumeratedPorts := make([]int, len(enumResults.Ports))
	for i, port := range enumResults.Ports {
		enumeratedPorts[i] = port.Number
	}

	sm.logger.LogToolExecution(scanID, ip, "naabu", duration, true, map[string]interface{}{
		"ports_found": len(enumeratedPorts),
		"ports":       enumeratedPorts,
	})

	if len(enumResults.Ports) > 0 {
		toolName := "naabu"
		if err := sm.submitHostWithSource(enumResults, toolName, scanID, opts); err != nil {
			slog.Warn("Failed to submit enumeration data via source-aware API",
				"scan_id", scanID,
				"ip", ip,
				"error", err)
			slog.Debug("API may be unavailable or endpoint not implemented; continuing without database persistence")
		} else {
			slog.Debug("Successfully added host with enumeration data using source-aware API", "ip", enumResults.IP)
		}
	}

	hostWasNew := false
	if enumResults.IP != "" {
		if err := sm.applyScanUpdate(scanID, true, func(scan *store.ScanResult) error {
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
			slog.Error("Failed to merge enumeration results into scan state",
				"scan_id", scanID,
				"ip", ip,
				"error", err)
			return nil, fmt.Errorf("failed to update scan with enumeration results for host %s: %w", ip, err)
		}

		if hostWasNew {
			sm.logger.LogHostDiscovered(enumResults.IP, scanID, map[string]interface{}{
				"ports_found": len(enumeratedPorts),
				"os":          enumResults.OS,
			})
		}
	}

	slog.Debug("Enumeration results", "ip", enumResults.IP, "hostname", enumResults.Hostname, "ports", len(enumResults.Ports), "services", len(enumResults.Services), "os", enumResults.OS)
	return enumeratedPorts, nil
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
func (sm *ScanManager) runVulnerability(ctx context.Context, scanID, ip string, opts ScanOptions) error {
	return sm.runVulnerabilityWithPorts(ctx, scanID, ip, "", opts)
}

// runVulnerabilityWithPorts performs vulnerability scan with optional port override.
// opts is a job-local copy; portList overrides PortRange without mutating shared state.
func (sm *ScanManager) runVulnerabilityWithPorts(ctx context.Context, scanID, ip, portList string, opts ScanOptions) error {
	startTime := time.Now()

	localOpts := opts
	if portList != "" {
		slog.Debug("Overriding port range", "ip", ip, "original", opts.PortRange, "port_list", portList)
		localOpts.PortRange = portList
	}

	var scriptList []string
	if localOpts.TemplateID != "" {
		scripts, err := sm.templateManager.ResolveScripts(sm.ctx, localOpts.TemplateID)
		if err != nil {
			slog.Warn("Failed to resolve scripts from template", "error", err)
		} else {
			scriptList = scripts
			slog.Info("Resolved scripts from template", "count", len(scriptList), "template_id", localOpts.TemplateID)
		}
	}

	vulnStrategy := CreateToolWithOptions(localOpts, "vulnerability")

	if nmapStrat, ok := vulnStrategy.(*NmapStrategy); ok {
		if len(scriptList) > 0 {
			nmapStrat.ScriptList = scriptList
		}
		nmapStrat.PortRange = localOpts.PortRange
		slog.Debug("Configured Nmap strategy", "script_count", len(scriptList), "port_range", nmapStrat.PortRange)
	}

	vulnResults, err := vulnStrategy.ExecuteWithContext(ctx, ip)
	duration := time.Since(startTime)

	if err != nil {
		sm.logger.LogToolExecution(scanID, ip, "nmap", duration, false, map[string]interface{}{
			"error": err.Error(),
		})
		return fmt.Errorf("vulnerability scan failed for %s: %w", ip, err)
	}

	slog.Debug("Found vulnerabilities for host", "ip", ip, "count", len(vulnResults.Vulnerabilities))

	sm.logger.LogToolExecution(scanID, ip, "nmap", duration, true, map[string]interface{}{
		"vulnerabilities_found": len(vulnResults.Vulnerabilities),
	})

	vulnerabilities := make([]map[string]interface{}, len(vulnResults.Vulnerabilities))
	for i, vuln := range vulnResults.Vulnerabilities {
		vulnerabilities[i] = map[string]interface{}{
			"id":          vuln.VID,
			"title":       vuln.Title,
			"risk_score":  vuln.RiskScore,
			"description": vuln.Description,
		}
	}
	sm.logger.LogVulnerabilityScan(scanID, ip, vulnerabilities, "nmap")

	toolName := "nmap"

	if err := sm.submitHostWithSource(vulnResults, toolName, scanID, localOpts); err != nil {
		slog.Error("Failed to submit host data via source-aware API", "error", err)
		slog.Debug("API may be unavailable or endpoint not implemented")
		slog.Warn("Will continue scan without source-attributed persistence", "error", err)
	}

	if err := sm.applyScanUpdate(scanID, true, func(scan *store.ScanResult) error {
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

// GetActiveScanContext returns the context of any active job (legacy helper).
// Prefer GetJobContext(scanID) for concurrent jobs. Returns nil if none active.
func (sm *ScanManager) GetActiveScanContext() context.Context {
	sm.jobsMu.RLock()
	defer sm.jobsMu.RUnlock()
	for _, job := range sm.jobs {
		if job != nil && job.Ctx != nil {
			return job.Ctx
		}
	}
	return nil
}

// IsCancelling reports whether any registered job is mid-cancel (legacy helper).
// Prefer JobContext.Cancelling() for a specific scanID.
func (sm *ScanManager) IsCancelling() bool {
	sm.jobsMu.RLock()
	defer sm.jobsMu.RUnlock()
	for _, job := range sm.jobs {
		if job != nil && job.Cancelling() {
			return true
		}
	}
	return false
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
	ScanID    string `json:"scan_id"`   // Optional: specific scan to cancel
	Timestamp string `json:"timestamp"` // When the command was issued
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
	var cmd ControlMessage
	if err := json.Unmarshal([]byte(msg), &cmd); err != nil {
		slog.Error("Invalid control message", "error", err)
		return
	}

	slog.Debug("Received control command", "action", cmd.Action, "scan_id", cmd.ScanID, "timestamp", cmd.Timestamp)

	switch cmd.Action {
	case "cancel":
		sm.CancelCurrentScan(cmd.ScanID)
	case "force_cancel":
		sm.ForceStopCurrentScan(cmd.ScanID)
	default:
		slog.Warn("Unknown control action", "action", cmd.Action)
	}
}

// CancelCurrentScan cancels exactly the job identified by scanID.
// Missing or empty IDs are ignored; other jobs are never cancelled.
func (sm *ScanManager) CancelCurrentScan(scanID string) {
	if scanID == "" {
		slog.Warn("Cancel request missing scan_id, ignoring")
		return
	}

	job := sm.GetJobContext(scanID)
	if job == nil {
		slog.Warn("No active job to cancel", "scan_id", scanID)
		sm.clearStaleScanData(scanID)
		return
	}

	if !sm.CancelJob(scanID) {
		slog.Warn("Scan is already being cancelled", "scan_id", scanID)
		return
	}

	slog.Debug("Cancelling scan", "scan_id", scanID)
	sm.updateJobScanStatus(scanID, job, "cancelling")

	sm.logger.LogScanEvent(scanID, "scan_cancelled", "Scan was cancelled by user", map[string]interface{}{
		"scan_id":   scanID,
		"timestamp": time.Now().Format(time.RFC3339),
	})

	slog.Debug("Scan has been cancelled", "scan_id", scanID)
}

// ForceStopCurrentScan force-stops exactly the job identified by scanID.
// Mismatched IDs must not proceed against a different job.
func (sm *ScanManager) ForceStopCurrentScan(scanID string) {
	slog.Debug("Force stop requested for scan", "scan_id", scanID)

	if scanID == "" {
		slog.Warn("Force stop missing scan_id, ignoring")
		return
	}

	job := sm.GetJobContext(scanID)
	if job == nil {
		slog.Warn("No active job context to force stop, clearing stale data", "scan_id", scanID)
		sm.clearStaleScanData(scanID)
		return
	}

	if !sm.ForceCancelJob(scanID) {
		slog.Warn("Force cancel failed", "scan_id", scanID)
		return
	}

	sm.updateJobScanStatus(scanID, job, "cancelled")

	sm.logger.LogScanEvent(scanID, "scan_force_stopped", "Scan was force stopped by user", map[string]interface{}{
		"scan_id":   scanID,
		"timestamp": time.Now().Format(time.RFC3339),
	})

	slog.Debug("Force stop completed for scan", "scan_id", scanID)
}

// updateJobScanStatus writes status for a job (keyed state + owned status key / legacy currentScan).
func (sm *ScanManager) updateJobScanStatus(scanID string, job *JobContext, status string) {
	ctx := context.Background()

	// Status writes are allowed during cancel (not a result merge).
	if err := sm.scanUpdater.UpdateScan(ctx, scanID, func(scan *store.ScanResult) error {
		scan.Status = status
		if status == "cancelled" || status == "cancelling" {
			scan.EndTime = time.Now().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		slog.Warn("Failed to update keyed scan status", "scan_id", scanID, "status", status, "error", err)
	}

	if job != nil && job.IsOwned() {
		if err := sm.kvStore.SetValue(ctx, ScanStatusKey(scanID), status); err != nil {
			slog.Warn("Failed to set scan:status key", "scan_id", scanID, "status", status, "error", err)
		}
		return
	}

	// Legacy Community path
	if err := sm.scanUpdater.Update(ctx, func(scan *store.ScanResult) error {
		scan.Status = status
		if status == "cancelled" || status == "cancelling" {
			scan.EndTime = time.Now().Format(time.RFC3339)
		}
		return nil
	}); err != nil {
		slog.Warn("Failed to update legacy scan status", "status", status, "error", err)
	}
}

// clearStaleScanData marks any stale scan in ValKey as cancelled.
// Prefers scan:state:<id> when scanID is known; also clears legacy currentScan.
func (sm *ScanManager) clearStaleScanData(scanID string) {
	ctx := context.Background()

	if scanID != "" {
		_ = sm.scanUpdater.UpdateScan(ctx, scanID, func(scan *store.ScanResult) error {
			scan.Status = "cancelled"
			scan.EndTime = time.Now().Format(time.RFC3339)
			return nil
		})
		_ = sm.kvStore.SetValue(ctx, ScanStatusKey(scanID), "cancelled")
	}

	resp, err := sm.kvStore.GetValue(ctx, LegacyCurrentScanKey)
	if err != nil {
		slog.Debug("No stale legacy currentScan data found in ValKey")
		return
	}

	decodedBytes, err := decodeBase64(resp.Message.Value)
	if err != nil {
		slog.Warn("Stale data is not valid base64, deleting key")
		_ = sm.kvStore.DeleteValue(ctx, LegacyCurrentScanKey)
		return
	}

	var scanResult map[string]interface{}
	if err := json.Unmarshal(decodedBytes, &scanResult); err != nil {
		slog.Warn("Stale data is not valid JSON, deleting key")
		_ = sm.kvStore.DeleteValue(ctx, LegacyCurrentScanKey)
		return
	}

	// Only clear legacy key if it matches the requested scan (or scanID empty).
	if scanID != "" {
		if id, _ := scanResult["id"].(string); id != "" && id != scanID {
			return
		}
	}

	scanResult["status"] = "cancelled"
	scanResult["end_time"] = time.Now().Format(time.RFC3339)

	updatedJSON, _ := json.Marshal(scanResult)
	encodedValue := encodeBase64(updatedJSON)

	if err := sm.kvStore.SetValue(ctx, LegacyCurrentScanKey, encodedValue); err != nil {
		slog.Warn("Failed to update stale scan status", "error", err)
		return
	}

	slog.Debug("Cleared stale scan data from ValKey (marked as cancelled)", "scan_id", scanID)
}

// decodeBase64 decodes a base64 string
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
