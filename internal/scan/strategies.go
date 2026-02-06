package scan

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/SiriusScan/app-scanner/modules/naabu"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/nvd"
	"github.com/SiriusScan/go-api/sirius"
)

// ScanStrategy defines an interface for executing a scan on a target.
// The Execute method accepts a context for cancellation support.
type ScanStrategy interface {
	Execute(target string) (sirius.Host, error)
	// ExecuteWithContext performs the scan with cancellation support
	ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error)
}

// NmapStrategy implements vulnerability scanning using Nmap.
type NmapStrategy struct {
	Protocols  []string // Deprecated: use ScriptList
	ScriptList []string // Explicit list of scripts to run
	PortRange  string   // Port range to scan (from template)
}

// Execute performs the vulnerability scan using Nmap and expands vulnerability details.
// This is a convenience method that uses context.Background().
func (n *NmapStrategy) Execute(target string) (sirius.Host, error) {
	return n.ExecuteWithContext(context.Background(), target)
}

// ExecuteWithContext performs the vulnerability scan with cancellation support.
func (n *NmapStrategy) ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error) {
	log.Printf("Starting vulnerability scan on target: %s", target)

	// Check for cancellation before starting
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled before starting")
	}

	// Create a scan config with context
	config := nmap.ScanConfig{
		Target:    target,
		PortRange: n.PortRange, // Pass port range from template
		Ctx:       ctx,         // Pass context for cancellation
	}

	// Use explicit script list if provided, otherwise fall back to protocols
	if len(n.ScriptList) > 0 {
		config.ScriptList = n.ScriptList
		log.Printf("Using explicit script list with %d scripts", len(n.ScriptList))
	} else if len(n.Protocols) > 0 {
		config.Protocols = n.Protocols
		log.Printf("Using protocol-based script selection: %v", n.Protocols)
	} else {
		// Default to all protocols
		config.Protocols = []string{"*"}
		log.Printf("Using default wildcard scan")
	}

	// Log port range being used
	if n.PortRange != "" {
		log.Printf("Using template port range: %s", n.PortRange)
	}

	results, err := nmap.ScanWithConfig(config)
	if err != nil {
		return sirius.Host{}, err
	}

	// Check for cancellation after scan
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled")
	}

	// Expand vulnerability details using NVD.
	expandedVulns := make([]sirius.Vulnerability, 0)
	for _, vuln := range results.Vulnerabilities {
		expanded := expandVulnerability(vuln)
		expandedVulns = append(expandedVulns, expanded)
	}
	results.Vulnerabilities = expandedVulns

	log.Printf("Final vulnerability count for %s: %d", target, len(results.Vulnerabilities))
	return results, nil
}

// expandVulnerability supplements vulnerability details with NVD info.
func expandVulnerability(vuln sirius.Vulnerability) sirius.Vulnerability {
	trimmed := strings.TrimSpace(vuln.VID)
	if !strings.HasPrefix(trimmed, "CVE-") {
		// Ensure the ID is properly formatted
		trimmed = "CVE-" + trimmed
	}

	// Ensure vuln.VID matches the properly formatted CVE ID for consistency
	vuln.VID = trimmed

	// Set a meaningful title if it's missing
	if vuln.Title == "" || vuln.Title == vuln.VID {
		vuln.Title = trimmed
	}

	// Try to get details from NVD API
	cveDetails, err := nvd.GetCVE(trimmed)
	if err != nil {
		// Log error but continue with basic vuln info
		log.Printf("Error getting CVE details for %s: %v", trimmed, err)

		// Set minimal details for the vulnerability
		vuln.Description = fmt.Sprintf("No description available for %s. Detected during scan.", trimmed)

		// Set a default risk score if none is available
		if vuln.RiskScore <= 0 {
			vuln.RiskScore = 5.0 // Medium risk as default
		}

		return vuln
	}

	// If we have details, update the vulnerability with them
	if len(cveDetails.Descriptions) > 0 {
		for _, desc := range cveDetails.Descriptions {
			// Prefer English description
			if desc.Lang == "en" {
				vuln.Description = desc.Value
				break
			}
		}

		// If no English description was found, use the first one
		if vuln.Description == "" && len(cveDetails.Descriptions) > 0 {
			vuln.Description = cveDetails.Descriptions[0].Value
		}
	}

	// If still no description, set a default
	if vuln.Description == "" {
		vuln.Description = fmt.Sprintf("No description available for %s. Detected during scan.", trimmed)
	}

	// Set the risk score from the CVSS data if available
	if len(cveDetails.Metrics.CvssMetricV31) > 0 {
		vuln.RiskScore = cveDetails.Metrics.CvssMetricV31[0].CvssData.BaseScore
	} else if len(cveDetails.Metrics.CvssMetricV30) > 0 {
		vuln.RiskScore = cveDetails.Metrics.CvssMetricV30[0].CvssData.BaseScore
	} else if len(cveDetails.Metrics.CvssMetricV2) > 0 {
		vuln.RiskScore = cveDetails.Metrics.CvssMetricV2[0].CvssData.BaseScore
	} else {
		// Default risk score if none available
		vuln.RiskScore = 5.0 // Medium risk as default
	}

	return vuln
}

// NaabuStrategy implements port enumeration using Naabu
type NaabuStrategy struct {
	Ports   string
	Retries int
}

// Execute performs port enumeration using Naabu.
// This is a convenience method that uses context.Background().
func (n *NaabuStrategy) Execute(target string) (sirius.Host, error) {
	return n.ExecuteWithContext(context.Background(), target)
}

// ExecuteWithContext performs port enumeration with cancellation support.
func (n *NaabuStrategy) ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error) {
	// Check for cancellation before starting
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled before starting")
	}

	host, err := naabu.Scan(target, naabu.ScanConfig{
		PortRange: n.Ports,
		Retries:   n.Retries,
		Ctx:       ctx, // Pass context for cancellation
	})
	if errors.Is(err, naabu.ErrHostDown) {
		log.Printf("Host %s appears down (no open ports found by NAABU), skipping further scans.", target)
		return sirius.Host{}, nil
	}
	if err != nil {
		return sirius.Host{}, err
	}
	return host, nil
}

// FingerprintResult contains the results of a fingerprint scan.
// This struct is used by both the FingerprintStrategy interface and the ping++ adapter.
type FingerprintResult struct {
	IsAlive  bool              // Whether the host is alive/reachable
	OSFamily string            // Detected OS family (e.g., "windows", "linux", "unknown")
	TTL      int               // TTL value from ICMP response
	Details  map[string]string // Additional fingerprint details (confidence, hops, etc.)
}

// FingerprintStrategy defines an interface for host fingerprinting operations.
// The default implementation uses ping++ for ICMP/TCP probing and TTL-based OS detection.
//
// Implementations:
//   - PingPlusPlusAdapter: Real fingerprinting using ping++ (see pingpp_adapter.go)
//
// Configuration options are available via ScanOptions:
//   - FingerprintProbes: probe types (icmp, tcp, arp, smb)
//   - FingerprintTimeout: per-probe timeout
//   - DisableICMP: for unprivileged execution
type FingerprintStrategy interface {
	Fingerprint(target string) (FingerprintResult, error)
	// FingerprintWithContext performs fingerprinting with cancellation support
	FingerprintWithContext(ctx context.Context, target string) (FingerprintResult, error)
}
