package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	defaultTarget = "192.168.123.119"
	dockerNSEBase = "/opt/sirius/nse"
)

func ensureDirectory(path string) error {
	fmt.Printf("🔧 Ensuring directory exists: %s\n", path)
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}

func main() {
	// Parse command-line arguments
	var target string
	var testSmb bool
	flag.StringVar(&target, "target", defaultTarget, "Target IP to scan")
	flag.BoolVar(&testSmb, "smb", false, "Test only SMB vulnerabilities")
	flag.Parse()

	fmt.Println("🚀 Starting NSE Scan Test")
	fmt.Printf("📌 Target: %s\n", target)
	fmt.Printf("📌 Docker NSE Base Path: %s\n", dockerNSEBase)

	if testSmb {
		fmt.Println("🔍 Testing SMB vulnerabilities only")
	} else {
		fmt.Println("🔍 Testing all vulnerabilities")
	}

	// Ensure NSE base directory exists
	if err := ensureDirectory(dockerNSEBase); err != nil {
		log.Fatalf("Failed to create NSE base directory: %v", err)
	}

	// Initialize ValKey store
	fmt.Println("🔌 Connecting to ValKey at sirius-valkey:6379...")
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("❌ Failed to initialize ValKey store: %v\n💡 Tip: Check if ValKey service is running and accessible", err)
	}
	defer kvStore.Close()

	// Initialize repository manager
	repoPath := fmt.Sprintf("%s/sirius-nse", dockerNSEBase)
	repoManager := nse.NewRepoManager(repoPath, nse.NSERepoURL)
	fmt.Printf("🔧 Created RepoManager for path: %s\n", repoPath)

	// Initialize sync manager
	syncManager := nse.NewSyncManager(repoManager, kvStore)
	fmt.Println("🔄 Created SyncManager")

	// Sync NSE scripts
	fmt.Println("\n🔄 Syncing NSE scripts...")
	if err := syncManager.Sync(context.Background()); err != nil {
		log.Fatalf("Failed to sync NSE scripts: %v", err)
	}
	fmt.Println("✅ NSE scripts synced successfully")

	// Get manifest for script selection
	manifest, err := repoManager.GetManifest()
	if err != nil {
		log.Fatalf("Failed to get manifest: %v", err)
	}

	// Create script selector
	_ = nse.NewScriptSelector(manifest) // We don't need to use this directly anymore
	fmt.Printf("📄 Loaded manifest with %d scripts\n", len(manifest.Scripts))

	// Create scan configuration
	var config nmap.ScanConfig
	if testSmb {
		// Test SMB vulnerability specifically
		config = nmap.ScanConfig{
			Target:    target,
			Protocols: []string{"smb"},
		}
	} else {
		// Build script flag for all protocols
		config = nmap.ScanConfig{
			Target:    target,
			Protocols: []string{"*"},
		}
	}

	// Execute Nmap scan
	fmt.Printf("\n🔍 Starting Nmap scan against %s...\n", target)
	results, err := nmap.ScanWithConfig(config)
	if err != nil {
		log.Fatalf("Scan failed: %v", err)
	}

	// Print results
	printScanResults(results)
}

func printScanResults(host sirius.Host) {
	fmt.Printf("\nScan Results for %s:\n", host.IP)

	if len(host.Ports) > 0 {
		fmt.Printf("\nPorts (%d):\n", len(host.Ports))
		for _, port := range host.Ports {
			fmt.Printf("- %d/%s: %s\n", port.Number, port.Protocol, port.State)
		}
	}

	if len(host.Services) > 0 {
		fmt.Printf("\nServices (%d):\n", len(host.Services))
		for _, service := range host.Services {
			fmt.Printf("- Port %d: %s %s\n", service.Port, service.Product, service.Version)
		}
	}

	if len(host.Vulnerabilities) > 0 {
		fmt.Printf("\nVulnerabilities (%d):\n", len(host.Vulnerabilities))
		for i, vuln := range host.Vulnerabilities {
			fmt.Printf("%d. %s: %s (Score: %.1f)\n", i+1, vuln.VID, vuln.Title, vuln.RiskScore)

			// Print a truncated description if it's too long
			if len(vuln.Description) > 100 {
				fmt.Printf("   Description: %s...\n", vuln.Description[:100])
			} else {
				fmt.Printf("   Description: %s\n", vuln.Description)
			}
			fmt.Println()
		}
	} else {
		fmt.Println("No vulnerabilities found.")
	}
}
