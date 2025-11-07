package scan

import (
	"time"

	"github.com/SiriusScan/go-api/sirius/logging"
)

// LoggingClient wraps the SDK LoggingClient for App Scanner convenience
type LoggingClient struct {
	client *logging.LoggingClient
}

// NewLoggingClient creates a new logging client using the SDK
func NewLoggingClient() *LoggingClient {
	return &LoggingClient{
		client: logging.NewLoggingClient(),
	}
}

// LogScanEvent logs a general event related to a scan
func (lc *LoggingClient) LogScanEvent(scanID, eventType, message string, metadata map[string]interface{}) {
	lc.client.LogScanEvent(scanID, eventType, message, metadata)
}

// LogScanError logs an error related to a scan
func (lc *LoggingClient) LogScanError(scanID, target, errorCode, message string, err error) {
	lc.client.LogScanError(scanID, target, errorCode, message, err)
}

// LogToolExecution logs the execution of an external scanning tool
func (lc *LoggingClient) LogToolExecution(scanID, target, tool string, duration time.Duration, success bool, metadata map[string]interface{}) {
	lc.client.LogToolExecution(scanID, target, tool, duration, success, metadata)
}

// LogHostDiscovery logs when a new host is discovered
func (lc *LoggingClient) LogHostDiscovery(scanID, hostIP string, ports []int, toolUsed string) {
	lc.client.LogHostDiscovery(scanID, hostIP, ports, toolUsed)
}

// LogVulnerabilityScan logs the results of a vulnerability scan
func (lc *LoggingClient) LogVulnerabilityScan(scanID, hostIP string, vulnerabilities []map[string]interface{}, toolUsed string) {
	lc.client.LogVulnerabilityScan(scanID, hostIP, vulnerabilities, toolUsed)
}

// LogScanCompletion logs the overall completion of a scan
func (lc *LoggingClient) LogScanCompletion(scanID, target string, metadata map[string]interface{}) {
	lc.client.LogScanCompletion(scanID, target, metadata)
}

// Close gracefully shuts down the logging client
func (lc *LoggingClient) Close() error {
	return lc.client.Close()
}

// LogScanStarted logs when a scan starts (new convenience method)
func (lc *LoggingClient) LogScanStarted(scanID string, targets []string, options map[string]interface{}) {
	lc.client.LogScanStarted(scanID, targets, options)
}

// LogScanCompleted logs when a scan completes successfully (new convenience method)
func (lc *LoggingClient) LogScanCompleted(scanID string, stats map[string]interface{}) {
	lc.client.LogScanCompleted(scanID, stats)
}

// LogHostDiscovered logs when a new host is discovered (new convenience method)
func (lc *LoggingClient) LogHostDiscovered(hostIP, scanID string, metadata map[string]interface{}) {
	lc.client.LogHostDiscovered(hostIP, scanID, metadata)
}

// LogVulnerabilityFound logs when vulnerabilities are found (new convenience method)
func (lc *LoggingClient) LogVulnerabilityFound(vulnID, hostIP, severity string, metadata map[string]interface{}) {
	lc.client.LogVulnerabilityFound(vulnID, hostIP, severity, metadata)
}

// LogEvent logs a structured event with all event fields (new convenience method)
func (lc *LoggingClient) LogEvent(service, subcomponent, eventType, severity, title, description string, entityType, entityID string, metadata map[string]interface{}) {
	lc.client.LogEvent(service, subcomponent, eventType, severity, title, description, entityType, entityID, metadata)
}
