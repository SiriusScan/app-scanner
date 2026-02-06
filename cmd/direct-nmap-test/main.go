// direct-nmap-test/main.go - Test Nmap scanning directly without dependencies on scan package
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	defaultTarget = "192.168.123.148"
	nseBasePath   = "/opt/sirius/nse"
)

func main() {
	// Parse command-line arguments
	var target string
	var testSMB bool
	var verbose bool
	flag.StringVar(&target, "target", defaultTarget, "Target IP to scan")
	flag.BoolVar(&testSMB, "smb", false, "Test for SMB vulnerabilities specifically")
	flag.BoolVar(&verbose, "verbose", false, "Enable verbose output")
	flag.Parse()

	fmt.Println("🚀 Starting Direct Nmap Test")
	fmt.Printf("📌 Target: %s\n", target)

	// Ensure base directory exists
	fmt.Printf("🔧 Ensuring directory exists: %s\n", nseBasePath)
	if err := os.MkdirAll(nseBasePath, 0755); err != nil {
		log.Fatalf("Failed to create NSE base directory: %v", err)
	}

	// Initialize ValKey store for NSE script sync
	fmt.Println("🔌 Connecting to ValKey...")
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("❌ Failed to initialize ValKey store: %v", err)
	}
	defer kvStore.Close()

	// Initialize NSE repository
	repoPath := fmt.Sprintf("%s/sirius-nse", nseBasePath)
	repoManager := nse.NewRepoManager(repoPath, nse.NSERepoURL)
	syncManager := nse.NewSyncManager(repoManager, kvStore)

	fmt.Println("🔄 Syncing NSE scripts...")
	if err := syncManager.Sync(context.Background()); err != nil {
		log.Fatalf("Failed to sync NSE scripts: %v", err)
	}
	fmt.Println("✅ NSE scripts synced successfully")

	// Create scan configuration
	config := nmap.ScanConfig{
		Target: target,
	}

	// Set protocols based on flags
	if testSMB {
		config.Protocols = []string{"smb"}
		fmt.Println("🎯 Focusing scan on SMB protocols")
	} else {
		config.Protocols = []string{"*"}
		fmt.Println("🎯 Running full vulnerability scan")
	}

	// Run the scan
	fmt.Println("\n🔍 Running Nmap scan...")
	results, err := nmap.ScanWithConfig(config)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print results
	printScanResults(results)

	// Check for SMB vulnerabilities if requested
	if testSMB {
		smbVulns := filterSMBVulnerabilities(results.Vulnerabilities)
		if len(smbVulns) > 0 {
			fmt.Printf("\n🎯 Found %d SMB vulnerabilities!\n", len(smbVulns))
			for i, vuln := range smbVulns {
				fmt.Printf("  %d. %s - %s (Score: %.1f)\n", i+1, vuln.VID, vuln.Title, vuln.RiskScore)
			}
		} else {
			fmt.Println("\n❌ No SMB vulnerabilities found!")
		}
	}

	fmt.Println("\n✨ Direct Nmap test completed")
}

func printScanResults(results sirius.Host) {
	fmt.Printf("\nScan Results for %s:\n", results.IP)

	if len(results.Ports) > 0 {
		fmt.Printf("\nPorts (%d):\n", len(results.Ports))
		for _, port := range results.Ports {
			fmt.Printf("- %d/%s: %s\n", port.Number, port.Protocol, port.State)
		}
	}

	if len(results.Services) > 0 {
		fmt.Printf("\nServices (%d):\n", len(results.Services))
		for _, service := range results.Services {
			fmt.Printf("- Port %d: %s %s\n", service.Port, service.Product, service.Version)
		}
	}

	if len(results.Vulnerabilities) > 0 {
		fmt.Printf("\nVulnerabilities (%d):\n", len(results.Vulnerabilities))
		for i, vuln := range results.Vulnerabilities {
			fmt.Printf("%d. %s: %s (Score: %.1f)\n", i+1, vuln.VID, vuln.Title, vuln.RiskScore)
			if len(vuln.Description) > 100 {
				fmt.Printf("   Description: %s...\n", vuln.Description[:100])
			} else {
				fmt.Printf("   Description: %s\n", vuln.Description)
			}
			fmt.Println()
		}
	}
}

func filterSMBVulnerabilities(vulns []sirius.Vulnerability) []sirius.Vulnerability {
	var smbVulns []sirius.Vulnerability
	for _, vuln := range vulns {
		// Check for MS17-010, EternalBlue, or SMB related terms
		if contains(vuln.VID, "CVE-2017-0143") ||
			contains(vuln.VID, "CVE-2017-0144") ||
			contains(vuln.VID, "CVE-2017-0145") ||
			contains(vuln.VID, "CVE-2017-0146") ||
			contains(vuln.VID, "CVE-2017-0147") ||
			contains(vuln.VID, "CVE-2017-0148") ||
			contains(vuln.Title, "MS17-010") ||
			contains(vuln.Title, "EternalBlue") ||
			contains(vuln.Title, "SMB") ||
			contains(vuln.Description, "MS17-010") ||
			contains(vuln.Description, "EternalBlue") ||
			contains(vuln.Description, "SMBv1") {
			smbVulns = append(smbVulns, vuln)
		}
	}
	return smbVulns
}

func contains(s, substr string) bool {
	return s != "" && substr != "" && strings.Contains(s, substr)
}
