package scan

// Valkey key helpers for per-job scan state (Pro multi-user isolation).

const (
	// MaxExpandedTargetsPerJob caps expanded IPs per scan job.
	MaxExpandedTargetsPerJob = 32
	// LegacyCurrentScanKey is the Community single-admin scratchpad key.
	LegacyCurrentScanKey = "currentScan"
)

// ScanStateKey returns the Valkey key for a scan's ScanResult document.
func ScanStateKey(scanID string) string {
	return "scan:state:" + scanID
}

// ScanOwnerKey returns the Valkey key storing the immutable owner subject for a scan.
func ScanOwnerKey(scanID string) string {
	return "scan:owner:" + scanID
}

// ScanLatestKey returns the Valkey key for an owner's latest scan ID.
func ScanLatestKey(ownerSubjectID string) string {
	return "scan:latest:" + ownerSubjectID
}

// ScanStatusKey returns the Valkey key for a scan's lightweight status string.
func ScanStatusKey(scanID string) string {
	return "scan:status:" + scanID
}
