package scan

import (
	"log"
	"strings"

	"github.com/SiriusScan/go-api/nvd"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/app-scanner/modules/rustscan"
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
type NmapStrategy struct{}

// Execute performs the vulnerability scan using Nmap and expands vulnerability details.
func (n *NmapStrategy) Execute(target string) (sirius.Host, error) {
	log.Printf("Executing vulnerability scan on target: %s", target)
	results, err := nmap.Scan(target)
	if err != nil {
		return sirius.Host{}, err
	}

	// Expand vulnerability details using NVD.
	for i, vuln := range results.Vulnerabilities {
		results.Vulnerabilities[i] = expandVulnerability(vuln)
	}

	return results, nil
}

// expandVulnerability supplements vulnerability details with NVD info.
func expandVulnerability(vuln sirius.Vulnerability) sirius.Vulnerability {
	trimmed := strings.TrimSpace(vuln.Title)
	cveID := "CVE-" + trimmed
	cveDetails, err := nvd.GetCVE(cveID)
	if err != nil {
		log.Printf("Error getting CVE details for %s: %v", cveID, err)
		return vuln
	}

	if len(cveDetails.Descriptions) > 0 {
		vuln.Description = cveDetails.Descriptions[0].Value
	} else {
		vuln.Description = "No description available."
	}

	if len(cveDetails.Metrics.CvssMetricV31) > 0 {
		vuln.RiskScore = cveDetails.Metrics.CvssMetricV31[0].CvssData.BaseScore
	} else {
		vuln.RiskScore = 0.0
	}
	return vuln
}