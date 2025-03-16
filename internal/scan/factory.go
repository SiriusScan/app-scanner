package scan

import "log"

// ScanToolFactory creates scan strategies based on the scan type.
type ScanToolFactory struct {
	currentOptions ScanOptions
}

func NewScanToolFactory() *ScanToolFactory {
	return &ScanToolFactory{}
}

func (f *ScanToolFactory) SetOptions(opts ScanOptions) {
	f.currentOptions = opts
}

// CreateTool returns a ScanStrategy based on the provided scan type.
func (f *ScanToolFactory) CreateTool(toolType string) ScanStrategy {
	switch toolType {
	case "enumeration":
		return &NaabuStrategy{
			Ports:   f.currentOptions.PortRange,
			Retries: f.currentOptions.MaxRetries,
		}
	case "discovery":
		return &RustScanStrategy{}
	case "vulnerability":
		// Create NmapStrategy with protocols
		nmapStrategy := &NmapStrategy{
			Protocols: []string{"*"}, // Default to all protocols
		}

		// Check if SMB scanning is requested
		for _, scanType := range f.currentOptions.ScanTypes {
			if scanType == "smb" {
				// If SMB is specifically requested, focus on SMB protocol
				nmapStrategy.Protocols = []string{"smb"}
				log.Printf("Setting NmapStrategy to focus on SMB protocol")
				break
			}
		}

		return nmapStrategy
	default:
		log.Printf("No valid scan strategy for type: %s", toolType)
		return nil
	}
}
