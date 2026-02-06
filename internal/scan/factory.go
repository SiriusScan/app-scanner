package scan

import (
	"log"
	"time"
)

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
	case "enumeration", "port_scan":
		// Both "enumeration" and "port_scan" use Naabu for port discovery
		return &NaabuStrategy{
			Ports:   f.currentOptions.PortRange,
			Retries: f.currentOptions.MaxRetries,
		}
	case "vulnerability":
		// Create NmapStrategy with protocols and port range
		nmapStrategy := &NmapStrategy{
			Protocols: []string{"*"},              // Default to all protocols
			PortRange: f.currentOptions.PortRange, // Pass port range from template
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
	case "fingerprint":
		// Fingerprint strategy is handled differently since it has a separate interface.
		// The manager uses CreateFingerprintTool() for this scan type.
		// This case is here for completeness but should not be used directly.
		log.Printf("Warning: fingerprint type requested via CreateTool - use CreateFingerprintTool instead")
		return nil
	default:
		log.Printf("No valid scan strategy for type: %s", toolType)
		return nil
	}
}

// CreateFingerprintTool returns a FingerprintStrategy for host fingerprinting.
// This is separate from CreateTool because FingerprintStrategy has a different interface.
// Uses ping++ for real ICMP/TCP probing and TTL-based OS detection.
func (f *ScanToolFactory) CreateFingerprintTool() FingerprintStrategy {
	// Build fingerprint options from scan options
	opts := DefaultFingerprintOptions()

	// Apply custom probe types if specified
	if len(f.currentOptions.FingerprintProbes) > 0 {
		opts.ProbeTypes = f.currentOptions.FingerprintProbes
	}

	// Parse and apply timeout if specified
	if f.currentOptions.FingerprintTimeout != "" {
		if timeout, err := time.ParseDuration(f.currentOptions.FingerprintTimeout); err == nil {
			opts.Timeout = timeout
		} else {
			log.Printf("Warning: invalid fingerprint timeout '%s', using default: %v",
				f.currentOptions.FingerprintTimeout, DefaultFingerprintTimeout)
		}
	}

	// Apply ICMP disable flag
	opts.DisableICMP = f.currentOptions.DisableICMP

	return NewPingPlusPlusAdapterWithOptions(opts)
}
