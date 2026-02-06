package scan

import (
	"testing"
	"time"
)

func TestScanToolFactory_CreateTool(t *testing.T) {
	factory := &ScanToolFactory{}

	// Test enumeration scan type (uses Naabu)
	tool := factory.CreateTool("enumeration")
	if tool == nil {
		t.Errorf("Expected tool for 'enumeration', got nil")
	}

	// Test port_scan alias (should also work)
	tool = factory.CreateTool("port_scan")
	if tool == nil {
		t.Errorf("Expected tool for 'port_scan', got nil")
	}

	// Test vulnerability scan type (uses Nmap)
	tool = factory.CreateTool("vulnerability")
	if tool == nil {
		t.Errorf("Expected tool for 'vulnerability', got nil")
	}

	// Test unknown scan type
	tool = factory.CreateTool("unknown")
	if tool != nil {
		t.Errorf("Expected nil for unknown scan type, got %v", tool)
	}
}

func TestScanToolFactory_CreateFingerprintTool(t *testing.T) {
	factory := &ScanToolFactory{}

	// Test fingerprint strategy creation with default options
	fingerprintTool := factory.CreateFingerprintTool()
	if fingerprintTool == nil {
		t.Errorf("Expected fingerprint tool, got nil")
	}

	// Verify it's a PingPlusPlusAdapter
	adapter, ok := fingerprintTool.(*PingPlusPlusAdapter)
	if !ok {
		t.Errorf("Expected PingPlusPlusAdapter, got %T", fingerprintTool)
	}

	// Verify default options are applied
	opts := adapter.Options()
	if len(opts.ProbeTypes) != 2 {
		t.Errorf("Expected 2 default probe types, got %d", len(opts.ProbeTypes))
	}
	if opts.Timeout != DefaultFingerprintTimeout {
		t.Errorf("Expected default timeout %v, got %v", DefaultFingerprintTimeout, opts.Timeout)
	}
	if opts.DisableICMP {
		t.Errorf("Expected DisableICMP=false by default")
	}
}

func TestScanToolFactory_CreateFingerprintTool_CustomOptions(t *testing.T) {
	factory := &ScanToolFactory{}

	// Set custom options
	factory.SetOptions(ScanOptions{
		FingerprintProbes:  []string{"tcp", "smb"},
		FingerprintTimeout: "5s",
		DisableICMP:        true,
	})

	fingerprintTool := factory.CreateFingerprintTool()
	if fingerprintTool == nil {
		t.Errorf("Expected fingerprint tool, got nil")
	}

	adapter, ok := fingerprintTool.(*PingPlusPlusAdapter)
	if !ok {
		t.Errorf("Expected PingPlusPlusAdapter, got %T", fingerprintTool)
	}

	// Verify custom options are applied
	opts := adapter.Options()
	if len(opts.ProbeTypes) != 2 || opts.ProbeTypes[0] != "tcp" || opts.ProbeTypes[1] != "smb" {
		t.Errorf("Expected probe types [tcp, smb], got %v", opts.ProbeTypes)
	}
	if opts.Timeout != 5*time.Second {
		t.Errorf("Expected timeout 5s, got %v", opts.Timeout)
	}
	if !opts.DisableICMP {
		t.Errorf("Expected DisableICMP=true")
	}
}

func TestScanToolFactory_CreateFingerprintTool_InvalidTimeout(t *testing.T) {
	factory := &ScanToolFactory{}

	// Set invalid timeout - should fall back to default
	factory.SetOptions(ScanOptions{
		FingerprintTimeout: "invalid",
	})

	fingerprintTool := factory.CreateFingerprintTool()
	if fingerprintTool == nil {
		t.Errorf("Expected fingerprint tool, got nil")
	}

	adapter, ok := fingerprintTool.(*PingPlusPlusAdapter)
	if !ok {
		t.Errorf("Expected PingPlusPlusAdapter, got %T", fingerprintTool)
	}

	// Verify default timeout is used when invalid
	opts := adapter.Options()
	if opts.Timeout != DefaultFingerprintTimeout {
		t.Errorf("Expected default timeout %v for invalid input, got %v", DefaultFingerprintTimeout, opts.Timeout)
	}
}

func TestPingPlusPlusAdapter_Creation(t *testing.T) {
	// Test default adapter creation
	adapter := NewPingPlusPlusAdapter()
	if adapter == nil {
		t.Errorf("Expected adapter, got nil")
	}

	opts := adapter.Options()
	if len(opts.ProbeTypes) == 0 {
		t.Errorf("Expected default probe types")
	}
	if opts.Timeout == 0 {
		t.Errorf("Expected default timeout")
	}
}

func TestPingPlusPlusAdapter_CustomOptions(t *testing.T) {
	opts := FingerprintOptions{
		ProbeTypes:  []string{"icmp"},
		Timeout:     10 * time.Second,
		DisableICMP: false,
	}

	adapter := NewPingPlusPlusAdapterWithOptions(opts)
	if adapter == nil {
		t.Errorf("Expected adapter, got nil")
	}

	resultOpts := adapter.Options()
	if len(resultOpts.ProbeTypes) != 1 || resultOpts.ProbeTypes[0] != "icmp" {
		t.Errorf("Expected probe types [icmp], got %v", resultOpts.ProbeTypes)
	}
	if resultOpts.Timeout != 10*time.Second {
		t.Errorf("Expected timeout 10s, got %v", resultOpts.Timeout)
	}
}

func TestPingPlusPlusAdapter_DefaultsForEmptyOptions(t *testing.T) {
	// Empty options should get defaults applied
	adapter := NewPingPlusPlusAdapterWithOptions(FingerprintOptions{})
	if adapter == nil {
		t.Errorf("Expected adapter, got nil")
	}

	opts := adapter.Options()
	if len(opts.ProbeTypes) == 0 {
		t.Errorf("Expected default probe types for empty options")
	}
	if opts.Timeout == 0 {
		t.Errorf("Expected default timeout for empty options")
	}
}