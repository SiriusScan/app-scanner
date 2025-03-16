// nmap/nmap.go
package nmap

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/lair-framework/go-nmap"
)

// ScanConfig holds configuration for the Nmap scan
type ScanConfig struct {
	Target    string   // Target to scan
	Protocols []string // Protocols to select scripts for
}

// Scan is a function variable that can be overridden for testing.
var Scan = scanImpl

// scanImpl is the default implementation of the Nmap scan.
func scanImpl(target string) (sirius.Host, error) {
	return ScanWithConfig(ScanConfig{Target: target})
}

// ScanWithConfig performs an Nmap scan with the provided configuration
func ScanWithConfig(config ScanConfig) (sirius.Host, error) {
	// Initialize an empty sirius.Host object
	host := sirius.Host{}

	// Execute Nmap and capture stdout
	output, err := executeNmapWithConfig(config)
	if err != nil {
		return host, err
	}

	// Process the XML data
	host, err = processNmapOutput(string(output))
	if err != nil {
		return host, err
	}

	return host, nil
}

func executeNmapWithConfig(config ScanConfig) (string, error) {
	// Get script selector
	repoManager := nse.NewRepoManager("/opt/sirius/nse/sirius-nse", nse.NSERepoURL)
	manifest, err := repoManager.GetManifest()
	if err != nil {
		return "", fmt.Errorf("failed to get NSE manifest: %w", err)
	}

	scriptSelector := nse.NewScriptSelector(manifest)

	// Add SMB protocol if we have any protocols and port 445 is likely to be scanned
	protocols := append([]string{}, config.Protocols...)
	if len(protocols) > 0 && (containsAny(protocols, "smb") || containsAny(protocols, "*")) {
		// Add "smb" if not already included and we're doing a focused scan
		if !containsAny(protocols, "smb") && !containsAny(protocols, "*") {
			protocols = append(protocols, "smb")
			fmt.Println("🔄 Added SMB protocol for script selection")
		}
	}

	scriptFlag, err := scriptSelector.BuildNmapScriptFlag(protocols...)
	if err != nil {
		return "", fmt.Errorf("failed to build script flag: %w", err)
	}

	fmt.Printf("🔍 Script flag: %s\n", scriptFlag)

	// Check if scripts exist and log their content type
	scriptPaths := []string{
		"/opt/sirius/nse/sirius-nse/scripts/smb-vuln-ms17-010.nse",
		"/usr/share/nmap/scripts/smb-vuln-ms17-010.nse",
	}

	for _, scriptPath := range scriptPaths {
		if _, err := os.Stat(scriptPath); err == nil {
			// File exists
			fmt.Printf("✅ Script exists: %s\n", scriptPath)

			// Read the first 20 bytes to check format
			data, err := os.ReadFile(scriptPath)
			if err != nil {
				fmt.Printf("⚠️ Cannot read script: %s - %v\n", scriptPath, err)
			} else {
				preview := string(data)
				if len(preview) > 30 {
					preview = preview[:30] + "..."
				}
				fmt.Printf("📄 Script preview: %s\n", preview)
			}
		} else {
			fmt.Printf("❌ Script not found: %s\n", scriptPath)
		}
	}

	// Potential script args file locations
	argsFilePaths := []string{
		"/opt/sirius/nse/sirius-nse/scripts/args.txt", // Docker NSE path
		"/app-scanner/scripts/args.txt",               // Docker app-scanner path
		"scripts/args.txt",                            // Local path
	}

	// Find the first args file that exists
	var argsFilePath string
	for _, path := range argsFilePaths {
		if _, err := os.Stat(path); err == nil {
			argsFilePath = path
			break
		}
	}

	// Build Nmap command with dynamic script selection
	args := []string{
		"-T4", // Timing template (higher is faster)
		"-sV", // Version detection
		"-Pn", // Treat all hosts as online
	}

	// Determine port specification
	// For SMB vulnerability scanning, we need to include port 445
	// but for general scans, we should use a wider port range
	portSpec := "1-1000" // Default port range
	if containsAny(protocols, "smb") || strings.Contains(scriptFlag, "smb-vuln") {
		// When any protocol includes SMB or when using SMB scripts, ensure port 445 is included
		if len(protocols) > 0 && containsAny(protocols, "*") {
			// For full scans, include common ports with SMB
			portSpec = "21-25,80,135,139,443,445,3389,1-1000"
			fmt.Println("🎯 Running full port scan including SMB port 445")
		} else {
			// For targeted SMB scans, focus on common Windows/SMB ports
			portSpec = "135,139,445,3389"
			fmt.Println("🎯 Targeting common Windows/SMB ports: 135, 139, 445, 3389")
		}
	} else {
		// Even for general scans, ensure port 445 is included for SMB scans
		portSpec = "1-1000,445"
		fmt.Println("🎯 Using default port range: 1-1000 plus SMB port 445")
	}

	// Add port specification
	args = append(args, "-p", portSpec)

	// Add script flag - don't hardcode smb-vuln-ms17-010, use the dynamic scriptFlag
	args = append(args, "--script", scriptFlag)

	// Prevent duplicate vulners references
	if strings.Count(scriptFlag, "vulners") > 1 {
		// Remove duplicate vulners entries
		parts := strings.Split(scriptFlag, ",")
		seen := make(map[string]bool)
		var unique []string

		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if !seen[trimmed] {
				seen[trimmed] = true
				unique = append(unique, trimmed)
			}
		}

		scriptFlag = strings.Join(unique, ",")
		fmt.Println("🔍 Removed duplicate script entries from flag")
	}

	// Add script args file if found
	if argsFilePath != "" {
		args = append(args, "--script-args-file", argsFilePath)
		fmt.Printf("📝 Using script args file: %s\n", argsFilePath)
	} else {
		fmt.Println("⚠️ No script args file found, using defaults")
	}

	// Add target and output format
	args = append(args, config.Target, "-oX", "-", "-v") // Added verbosity flag

	fmt.Printf("🔍 Executing Nmap with args: %v\n", args)
	cmd := exec.Command("nmap", args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("error executing Nmap: %w\nStderr: %s", err, stderr.String())
	}

	// Log raw output for debugging
	rawOutput := stdout.String()
	fmt.Println("======== RAW NMAP OUTPUT ========")
	if len(rawOutput) > 500 {
		fmt.Println(rawOutput[:500] + "... (truncated)")
	} else {
		fmt.Println(rawOutput)
	}
	fmt.Println("=================================")

	// Log stderr if not empty
	stderrOutput := stderr.String()
	if stderrOutput != "" {
		fmt.Println("======== NMAP STDERR ========")
		fmt.Println(stderrOutput)
		fmt.Println("=============================")
	}

	return rawOutput, nil
}

// ScriptResult represents the parsed output of an NSE script
type ScriptResult struct {
	ID       string            `json:"id"`       // Script ID
	Output   string            `json:"output"`   // Raw script output
	Elements map[string]string `json:"elements"` // Structured elements from script
}

func processNmapOutput(output string) (sirius.Host, error) {
	host := sirius.Host{}

	var nmapRun nmap.NmapRun
	if err := xml.Unmarshal([]byte(output), &nmapRun); err != nil {
		return host, fmt.Errorf("Error unmarshalling XML: %v", err)
	}

	if len(nmapRun.Hosts) == 0 {
		return host, fmt.Errorf("No hosts found in Nmap XML data")
	}

	nmapHost := nmapRun.Hosts[0]

	// Process basic host information
	if len(nmapHost.Addresses) > 0 {
		var ip string
		for _, address := range nmapHost.Addresses {
			if address.AddrType == "ipv4" || address.AddrType == "ipv6" {
				ip = address.Addr
				break
			}
		}
		host.IP = ip
	}

	if len(nmapHost.Os.OsMatches) > 0 && len(nmapHost.Os.OsMatches[0].OsClasses) > 0 {
		host.OS = nmapHost.Os.OsMatches[0].Name
		host.OSVersion = nmapHost.Os.OsMatches[0].OsClasses[0].OsGen
	}

	if len(nmapHost.Hostnames) > 0 {
		host.Hostname = nmapHost.Hostnames[0].Name
	}

	// Process ports and services
	var ports []sirius.Port
	var services []sirius.Service
	for _, port := range nmapHost.Ports {
		p := sirius.Port{
			ID:       port.PortId,
			Protocol: port.Protocol,
			State:    port.State.State,
		}
		ports = append(ports, p)

		// Extract service information
		if port.Service.Name != "" {
			service := sirius.Service{
				Port:    port.PortId,
				Product: port.Service.Name,
				Version: port.Service.Version,
			}
			services = append(services, service)
		}

		// Process script outputs for the port
		for _, script := range port.Scripts {
			result := parseScriptOutput(script)

			// Handle vulnerability information from scripts
			if vulns := extractVulnerabilities(result); len(vulns) > 0 {
				host.Vulnerabilities = append(host.Vulnerabilities, vulns...)
			}
		}
	}
	host.Ports = ports
	host.Services = services

	// Process host-level script outputs
	for _, script := range nmapHost.HostScripts {
		result := parseScriptOutput(script)

		// Handle vulnerability information from host scripts
		if vulns := extractVulnerabilities(result); len(vulns) > 0 {
			host.Vulnerabilities = append(host.Vulnerabilities, vulns...)
		}
	}

	// Deduplicate vulnerabilities
	host.Vulnerabilities = deduplicateVulnerabilities(host.Vulnerabilities)

	return host, nil
}

// parseScriptOutput processes the output of an NSE script and returns a structured result
func parseScriptOutput(script nmap.Script) ScriptResult {
	result := ScriptResult{
		ID:       script.Id,
		Output:   script.Output,
		Elements: make(map[string]string),
	}

	// Parse structured elements from the output
	// NSE scripts often output key-value pairs in the format "key: value"
	lines := strings.Split(script.Output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if parts := strings.SplitN(line, ":", 2); len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			result.Elements[key] = value
		}
	}

	return result
}

// extractVulnerabilities processes script output to find vulnerabilities
func extractVulnerabilities(result ScriptResult) []sirius.Vulnerability {
	var vulns []sirius.Vulnerability

	// Log the script result for debugging
	fmt.Printf("📋 Processing script result: %s\n", result.ID)

	// Check if this is an SMB vulnerability script
	if strings.HasPrefix(result.ID, "smb-vuln") {
		// For SMB vulnerability scripts, specially handle the output
		if strings.Contains(result.Output, "VULNERABLE") || strings.Contains(result.Output, "vulnerable") {
			// Extract CVEs from the output
			cves := extractCVEsFromText(result.Output)
			if len(cves) > 0 {
				for _, cve := range cves {
					vuln := sirius.Vulnerability{
						VID:         cve,
						Title:       cve, // Just use the CVE ID as the title
						Description: result.Output,
						RiskScore:   7.5, // Default high severity for SMB vulnerabilities
					}
					vulns = append(vulns, vuln)
				}
			} else {
				// If no CVEs found but still vulnerable, create a generic entry
				vuln := sirius.Vulnerability{
					VID:         fmt.Sprintf("%s-vulnerability", result.ID),
					Title:       fmt.Sprintf("SMB Vulnerability: %s", result.ID),
					Description: result.Output,
					RiskScore:   7.5, // Default high severity
				}
				vulns = append(vulns, vuln)
			}
		}
	} else if result.ID == "vulners" {
		// Process vulners script output
		vulns = append(vulns, extractVulnersVulnerabilities(result)...)
	} else {
		// For all other scripts
		// Look for CVE patterns in script output
		if cves := extractCVEsFromText(result.Output); len(cves) > 0 {
			for _, cve := range cves {
				// Extract additional information from the output
				severity := 5.0 // Default medium severity

				// Try to extract severity from the output
				if strings.Contains(result.Output, "VULNERABLE") || strings.Contains(result.Output, "vulnerable") {
					// Set a higher severity for confirmed vulnerabilities
					severity = 7.5 // Default high severity for confirmed vulnerabilities
				}

				vuln := sirius.Vulnerability{
					VID:         cve,
					Title:       cve, // Just use the CVE ID as the title
					Description: result.Output,
					RiskScore:   severity,
				}

				vulns = append(vulns, vuln)
			}
		}
	}

	fmt.Printf("🔍 Found %d vulnerabilities from script %s\n", len(vulns), result.ID)
	return vulns
}

// extractVulnersVulnerabilities processes vulners script output specifically
func extractVulnersVulnerabilities(result ScriptResult) []sirius.Vulnerability {
	var vulns []sirius.Vulnerability

	// Extract CVEs from vulners output
	cves := extractCVEsFromText(result.Output)
	for _, cve := range cves {
		// Try to get structured info from the elements
		var description string
		if desc, ok := result.Elements[cve]; ok {
			description = desc
		} else {
			description = result.Output
		}

		vulns = append(vulns, sirius.Vulnerability{
			VID:         cve,
			Title:       cve, // Just use the CVE ID as the title
			Description: description,
			RiskScore:   5.0, // Default medium severity
		})
	}

	return vulns
}

// extractCVEsFromText finds CVE IDs in text using regex
func extractCVEsFromText(text string) []string {
	// Match standard CVE format: CVE-YYYY-NNNNN
	standardPattern := regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

	// Match CVE IDs that might be prefixed with "CVE:" or similar
	prefixedPattern := regexp.MustCompile(`(?i)CVE[:=]\s*(CVE-\d{4}-\d{4,})`)

	// Find all matches
	matches := standardPattern.FindAllString(text, -1)

	// Find prefixed matches and extract the actual CVE ID
	prefixedMatches := prefixedPattern.FindAllStringSubmatch(text, -1)
	for _, match := range prefixedMatches {
		if len(match) >= 2 {
			matches = append(matches, match[1])
		}
	}

	// Deduplicate CVEs
	seen := make(map[string]bool)
	var unique []string
	for _, cve := range matches {
		// Normalize to uppercase
		cve = strings.ToUpper(cve)
		if !seen[cve] {
			seen[cve] = true
			unique = append(unique, cve)
		}
	}

	return unique
}

// deduplicateVulnerabilities removes duplicate vulnerabilities based on VID
func deduplicateVulnerabilities(vulns []sirius.Vulnerability) []sirius.Vulnerability {
	seen := make(map[string]bool)
	var unique []sirius.Vulnerability

	for _, vuln := range vulns {
		if !seen[vuln.VID] {
			seen[vuln.VID] = true
			unique = append(unique, vuln)
		}
	}

	return unique
}

// containsAny checks if any of the strings in the list contains the target substring
func containsAny(list []string, target string) bool {
	for _, item := range list {
		if strings.Contains(strings.ToLower(item), strings.ToLower(target)) {
			return true
		}
	}
	return false
}
