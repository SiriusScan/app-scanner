package scan

import "log"

// ScanToolFactory creates scan strategies based on the scan type.
type ScanToolFactory struct{}

// CreateTool returns a ScanStrategy based on the provided scan type.
func (f *ScanToolFactory) CreateTool(scanType string) ScanStrategy {
	switch scanType {
	case "discovery":
		return &RustScanStrategy{}
	case "vulnerability":
		return &NmapStrategy{}
	default:
		log.Printf("No valid scan strategy for type: %s", scanType)
		return nil
	}
}