package scan

import "testing"

func TestScanToolFactory_CreateTool(t *testing.T) {
	factory := &ScanToolFactory{}

	tool := factory.CreateTool("discovery")
	if tool == nil {
		t.Errorf("Expected tool for 'discovery', got nil")
	}

	tool = factory.CreateTool("vulnerability")
	if tool == nil {
		t.Errorf("Expected tool for 'vulnerability', got nil")
	}

	tool = factory.CreateTool("unknown")
	if tool != nil {
		t.Errorf("Expected nil for unknown scan type, got %v", tool)
	}
}