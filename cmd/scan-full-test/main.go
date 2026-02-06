package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/app-scanner/internal/scan"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/host"
	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/vulnerability"
)

const (
	defaultTarget = "192.168.123.148"
	nseBasePath   = "/opt/sirius/nse"
)

func main() {
	// Parse command-line arguments
	var target string
	var testSMB bool
	var testVulnerabilities bool
	var debug bool
	flag.StringVar(&target, "target", defaultTarget, "Target IP to scan")
	flag.BoolVar(&testSMB, "smb", false, "Test for SMB vulnerabilities specifically")
	flag.BoolVar(&testVulnerabilities, "vulns", true, "Test for all vulnerabilities")
	flag.BoolVar(&debug, "debug", false, "Enable debug logging")
	flag.Parse()

	fmt.Println("🚀 Starting Full Scan Pipeline Test")
	fmt.Printf("📌 Target: %s\n", target)

	// Connect to ValKey store
	fmt.Println("🔌 Connecting to ValKey...")
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("❌ Failed to initialize ValKey store: %v", err)
	}
	defer kvStore.Close()

	// Initialize NSE repository
	fmt.Printf("🔧 Setting up NSE repository at %s\n", nseBasePath)
	if err := os.MkdirAll(nseBasePath, 0755); err != nil {
		log.Fatalf("Failed to create NSE base directory: %v", err)
	}

	repoManager := nse.NewRepoManager(fmt.Sprintf("%s/sirius-nse", nseBasePath), nse.NSERepoURL)
	syncManager := nse.NewSyncManager(repoManager, kvStore)

	fmt.Println("🔄 Syncing NSE scripts...")
	if err := syncManager.Sync(context.Background()); err != nil {
		log.Fatalf("Failed to sync NSE scripts: %v", err)
	}
	fmt.Println("✅ NSE scripts synced successfully")

	// Perform discovery scan directly without using ScanManager
	fmt.Println("\n🔍 Running port discovery scan...")
	discoveryResults, err := runDiscovery(target)
	if err != nil {
		log.Fatalf("Discovery scan failed: %v", err)
	}

	fmt.Printf("✅ Discovery scan completed: found %d ports and %d services\n",
		len(discoveryResults.Ports), len(discoveryResults.Services))
	printScanResults(discoveryResults)

	// Only run vulnerability scan if requested
	if testVulnerabilities || testSMB {
		fmt.Println("\n🔍 Running vulnerability scan...")
		vulnResults, err := runVulnerability(target, testSMB, debug)
		if err != nil {
			log.Fatalf("Vulnerability scan failed: %v", err)
		}

		// Print vulnerabilities
		fmt.Printf("✅ Vulnerability scan completed: found %d vulnerabilities\n",
			len(vulnResults.Vulnerabilities))
		printScanResults(vulnResults)

		// Check for SMB vulnerabilities
		if testSMB {
			smbVulns := filterSMBVulnerabilities(vulnResults.Vulnerabilities)
			if len(smbVulns) > 0 {
				fmt.Printf("🎯 Found %d SMB vulnerabilities!\n", len(smbVulns))
				for i, vuln := range smbVulns {
					fmt.Printf("  %d. %s - %s (Score: %.1f)\n", i+1, vuln.VID, vuln.Title, vuln.RiskScore)
				}
			} else {
				fmt.Println("❌ No SMB vulnerabilities found!")
			}
		}

		// Store the results in the database if available
		if storeInDB(vulnResults) {
			fmt.Println("✅ Results stored in database successfully")
		}
	}

	fmt.Println("\n✨ Full scan pipeline test completed")
}

// runDiscovery performs port discovery directly using Naabu
func runDiscovery(target string) (sirius.Host, error) {
	// Create and use the NaabuStrategy directly for port discovery
	strategy := &scan.NaabuStrategy{
		Ports:   "", // Use default port range
		Retries: 3,
	}
	return strategy.Execute(target)
}

// runVulnerability performs vulnerability scanning directly
func runVulnerability(target string, testSMB bool, debug bool) (sirius.Host, error) {
	// Create the NmapStrategy directly
	strategy := &scan.NmapStrategy{
		Protocols: []string{"*"}, // Default to all protocols
	}

	// If testing SMB, override protocols
	if testSMB {
		strategy.Protocols = []string{"smb"}
		fmt.Println("🎯 Focusing scan on SMB protocols")
	}

	// For debug mode, use direct nmap module for more verbose output
	if debug {
		fmt.Println("🔍 Running in debug mode with direct Nmap module")
		config := nmap.ScanConfig{
			Target:    target,
			Protocols: strategy.Protocols,
		}
		return nmap.ScanWithConfig(config)
	}

	return strategy.Execute(target)
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
		// Check for MS17-010, EternalBlue, or SMB related terms in title or description
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

func storeInDB(results sirius.Host) bool {
	// Attempt to store the results in the database
	// This is optional and won't fail the test if it fails
	err := host.AddHost(results)
	if err != nil {
		fmt.Printf("Warning: Failed to add host to database: %v\n", err)
		return false
	}

	// Store vulnerabilities individually
	for _, vuln := range results.Vulnerabilities {
		if err := vulnerability.AddVulnerability(vuln); err != nil {
			fmt.Printf("Warning: Failed to add vulnerability %s to database: %v\n", vuln.VID, err)
		}
	}

	return true
}
