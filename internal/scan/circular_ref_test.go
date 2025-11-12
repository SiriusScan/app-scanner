package scan

import (
	"encoding/json"
	"testing"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/postgres/models"
)

// TestHostSerialization tests that sirius.Host can be marshaled without circular references
func TestHostSerialization(t *testing.T) {
	t.Log("\n🔍 Testing Scanner Host Serialization")

	// Create a test host with ports and vulnerabilities
	host := sirius.Host{
		IP:       "192.168.1.1",
		Hostname: "test-host",
		OS:       "Linux",
		OSVersion: "Ubuntu 22.04",
		Ports: []sirius.Port{
			{Number: 22, Protocol: "tcp", State: "open"},
			{Number: 80, Protocol: "tcp", State: "open"},
			{Number: 443, Protocol: "tcp", State: "open"},
		},
		Vulnerabilities: []sirius.Vulnerability{
			{VID: "CVE-2024-1234", Title: "Test Vuln", Description: "Test Description", RiskScore: 7.5},
		},
	}

	t.Logf("Test host: %s with %d ports, %d vulnerabilities", host.IP, len(host.Ports), len(host.Vulnerabilities))

	// Test 1: Direct host serialization
	t.Log("\n=== Test 1: Direct Host Serialization ===")
	jsonBytes, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("❌ CIRCULAR REFERENCE: Failed to marshal sirius.Host: %v", err)
	}
	t.Logf("✅ Host marshaled successfully: %d bytes", len(jsonBytes))

	// Verify JSON structure
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("❌ Failed to unmarshal JSON: %v", err)
	}
	t.Logf("✅ JSON is valid with %d top-level keys", len(jsonMap))

	// Test 2: SourcedHostRequest serialization (mimics submitHostWithSource)
	t.Log("\n=== Test 2: SourcedHostRequest Serialization ===")
	source := models.ScanSource{
		Name:    "test-scanner",
		Version: "1.0.0",
		Config:  "test-config",
	}

	request := SourcedHostRequest{
		Host:   host,
		Source: source,
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("❌ CIRCULAR REFERENCE: Failed to marshal SourcedHostRequest: %v", err)
	}
	t.Logf("✅ SourcedHostRequest marshaled successfully: %d bytes", len(requestJSON))

	// Test 3: Metadata serialization (mimics logging operations)
	t.Log("\n=== Test 3: Metadata Serialization ===")
	metadata := map[string]interface{}{
		"scan_id":     "test-scan-123",
		"host_ip":     host.IP,
		"ports_found": len(host.Ports),
		"os":          host.OS,
		// Don't include the full host object in metadata!
	}

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("❌ Failed to marshal metadata: %v", err)
	}
	t.Logf("✅ Metadata marshaled successfully: %d bytes", len(metadataJSON))

	// Test 4: Full log entry simulation (mimics LogEntry marshaling)
	t.Log("\n=== Test 4: Log Entry Simulation ===")
	logEntry := map[string]interface{}{
		"id":           "log_123",
		"timestamp":    "2024-01-01T00:00:00Z",
		"service":      "sirius-scanner",
		"subcomponent": "scan-manager",
		"level":        "info",
		"message":      "Host discovered",
		"metadata":     metadata,
	}

	logJSON, err := json.Marshal(logEntry)
	if err != nil {
		t.Fatalf("❌ Failed to marshal log entry: %v", err)
	}
	t.Logf("✅ Log entry marshaled successfully: %d bytes", len(logJSON))

	t.Log("\n============================================================")
	t.Log("✅ ALL SERIALIZATION TESTS PASSED - NO CIRCULAR REFERENCES")
	t.Log("============================================================")
}

// TestPortsSerialization specifically tests ports array serialization
func TestPortsSerialization(t *testing.T) {
	t.Log("\n🔍 Testing Ports Array Serialization")

	ports := []sirius.Port{
		{Number: 22, Protocol: "tcp", State: "open"},
		{Number: 80, Protocol: "tcp", State: "open"},
		{Number: 443, Protocol: "tcp", State: "open"},
		{Number: 3306, Protocol: "tcp", State: "closed"},
		{Number: 8080, Protocol: "tcp", State: "filtered"},
	}

	jsonBytes, err := json.Marshal(ports)
	if err != nil {
		t.Fatalf("❌ Failed to marshal ports: %v", err)
	}

	t.Logf("✅ Ports marshaled successfully: %d bytes", len(jsonBytes))

	// Verify deserialization
	var deserializedPorts []sirius.Port
	if err := json.Unmarshal(jsonBytes, &deserializedPorts); err != nil {
		t.Fatalf("❌ Failed to unmarshal ports: %v", err)
	}

	if len(deserializedPorts) != len(ports) {
		t.Errorf("❌ Port count mismatch: expected %d, got %d", len(ports), len(deserializedPorts))
	}

	t.Logf("✅ Deserialized %d ports correctly", len(deserializedPorts))
}

// TestVulnerabilitiesSerialization specifically tests vulnerabilities array serialization
func TestVulnerabilitiesSerialization(t *testing.T) {
	t.Log("\n🔍 Testing Vulnerabilities Array Serialization")

	vulns := []sirius.Vulnerability{
		{VID: "CVE-2024-1234", Title: "SQL Injection", Description: "Critical SQL injection vulnerability", RiskScore: 9.8},
		{VID: "CVE-2024-5678", Title: "XSS", Description: "Cross-site scripting vulnerability", RiskScore: 6.5},
		{VID: "CVE-2024-9012", Title: "Path Traversal", Description: "Directory traversal vulnerability", RiskScore: 7.2},
	}

	jsonBytes, err := json.Marshal(vulns)
	if err != nil {
		t.Fatalf("❌ Failed to marshal vulnerabilities: %v", err)
	}

	t.Logf("✅ Vulnerabilities marshaled successfully: %d bytes", len(jsonBytes))

	// Verify deserialization
	var deserializedVulns []sirius.Vulnerability
	if err := json.Unmarshal(jsonBytes, &deserializedVulns); err != nil {
		t.Fatalf("❌ Failed to unmarshal vulnerabilities: %v", err)
	}

	if len(deserializedVulns) != len(vulns) {
		t.Errorf("❌ Vulnerability count mismatch: expected %d, got %d", len(vulns), len(deserializedVulns))
	}

	t.Logf("✅ Deserialized %d vulnerabilities correctly", len(deserializedVulns))
}

// TestComplexHostSerialization tests a host with many relationships
func TestComplexHostSerialization(t *testing.T) {
	t.Log("\n🔍 Testing Complex Host Serialization")

	// Create a host with lots of data
	host := sirius.Host{
		IP:        "10.0.0.1",
		Hostname:  "complex-test-host.local",
		OS:        "Linux",
		OSVersion: "Ubuntu 22.04 LTS",
		HID:       "host-12345",
		Ports:     make([]sirius.Port, 0, 100),
		Vulnerabilities: make([]sirius.Vulnerability, 0, 50),
	}

	// Add 100 ports
	for i := 1; i <= 100; i++ {
		host.Ports = append(host.Ports, sirius.Port{
			Number:   i * 100,
			Protocol: "tcp",
			State:    "open",
		})
	}

	// Add 50 vulnerabilities
	for i := 1; i <= 50; i++ {
		host.Vulnerabilities = append(host.Vulnerabilities, sirius.Vulnerability{
			VID:         string(rune(2024 + i)),
			Title:       "Test Vulnerability",
			Description: "Test Description",
			RiskScore:   float64(i % 10),
		})
	}

	t.Logf("Complex host: %d ports, %d vulnerabilities", len(host.Ports), len(host.Vulnerabilities))

	// This is the critical test - large host with many relationships
	jsonBytes, err := json.Marshal(host)
	if err != nil {
		t.Fatalf("❌ CIRCULAR REFERENCE: Failed to marshal complex host: %v", err)
	}

	t.Logf("✅ Complex host marshaled successfully: %d bytes", len(jsonBytes))

	// Verify JSON structure
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("❌ Failed to unmarshal complex host JSON: %v", err)
	}

	portsArray, ok := jsonMap["ports"].([]interface{})
	if !ok {
		t.Fatal("❌ Ports not found or wrong type in JSON")
	}
	t.Logf("✅ Ports in JSON: %d", len(portsArray))

	vulnsArray, ok := jsonMap["vulnerabilities"].([]interface{})
	if !ok {
		t.Fatal("❌ Vulnerabilities not found or wrong type in JSON")
	}
	t.Logf("✅ Vulnerabilities in JSON: %d", len(vulnsArray))
}





