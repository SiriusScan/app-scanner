package scan

import (
	"errors"
	"fmt"
	"log"
	"strings"

	"github.com/SiriusScan/app-scanner/modules/naabu"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/app-scanner/modules/rustscan"
	"github.com/SiriusScan/go-api/nvd"
	"github.com/SiriusScan/go-api/sirius"
)

// ScanStrategy defines an interface for executing a scan on a target.
type ScanStrategy interface {
	Execute(target string) (sirius.Host, error)
}

// RustScanStrategy implements discovery scanning using RustScan.
type RustScanStrategy struct{}

// Execute performs the discovery scan using RustScan.
func (r *RustScanStrategy) Execute(target string) (sirius.Host, error) {
	log.Printf("Executing discovery scan on target: %s", target)
	return rustscan.Scan(target)
}

// NmapStrategy implements vulnerability scanning using Nmap.
type NmapStrategy struct {
	Protocols []string
}

// Execute performs the vulnerability scan using Nmap and expands vulnerability details.
func (n *NmapStrategy) Execute(target string) (sirius.Host, error) {
	log.Printf("Starting vulnerability scan on target: %s", target)

	// Create a scan config with protocols if they're available
	config := nmap.ScanConfig{
		Target: target,
	}

	// Add protocols if available
	if len(n.Protocols) > 0 {
		config.Protocols = n.Protocols
	} else {
		// Default to all protocols
		config.Protocols = []string{"*"}
	}

	results, err := nmap.ScanWithConfig(config)
	if err != nil {
		return sirius.Host{}, err
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

// Update NaabuStrategy to use the new module
type NaabuStrategy struct {
	Ports   string
	Retries int
}

func (n *NaabuStrategy) Execute(target string) (sirius.Host, error) {
	host, err := naabu.Scan(target, naabu.ScanConfig{
		PortRange: n.Ports,
		Retries:   n.Retries,
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
