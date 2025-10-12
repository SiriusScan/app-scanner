package nse

import (
	"path/filepath"
	"strings"
)

// ScriptSelector handles the selection of NSE scripts based on protocols
type ScriptSelector struct {
	manifest *Manifest
}

// NewScriptSelector creates a new ScriptSelector instance
func NewScriptSelector(manifest *Manifest) *ScriptSelector {
	return &ScriptSelector{
		manifest: manifest,
	}
}

// SelectScripts returns a list of script paths that match the given protocols
// If no protocols are provided, returns scripts marked with "*" protocol
func (s *ScriptSelector) SelectScripts(protocols ...string) []string {
	var selectedScripts []string

	for _, script := range s.manifest.Scripts {
		// Include scripts that match any of the protocols or have "*" protocol
		if script.Protocol == "*" || containsProtocol(protocols, script.Protocol) {
			scriptPath := filepath.Join(NSEBasePath, script.Path)
			selectedScripts = append(selectedScripts, scriptPath)
		}
	}

	return selectedScripts
}

// BuildNmapScriptFlag constructs the --script flag value for Nmap command
// It returns both the flag and any error that occurred during construction
func (s *ScriptSelector) BuildNmapScriptFlag(protocols ...string) (string, error) {
	// Directly use script IDs for Nmap rather than full paths
	var scriptIDs []string

	// Check if this is a wildcard scan (all protocols)
	isWildcardScan := containsProtocol(protocols, "*")

	// Track blacklist statistics
	blacklistCount := 0
	blacklistReasons := make(map[string]int)

	// For wildcard scans, skip manifest iteration - we'll use curated essential scripts only
	if !isWildcardScan {
		// For each script in manifest, check if it matches the protocols
		for id, script := range s.manifest.Scripts {
			// Ensure script ID doesn't have .nse extension
			scriptID := strings.TrimSuffix(id, ".nse")

			// Check blacklist first
			if isBlacklisted, reason := IsBlacklisted(scriptID); isBlacklisted {
				blacklistCount++
				blacklistReasons[reason]++
				continue
			}

			// Include scripts that match any of the protocols or have "*" protocol
			if script.Protocol == "*" || containsProtocol(protocols, script.Protocol) {
				scriptIDs = append(scriptIDs, scriptID)
			}
		}
	} else {
		// For wildcard scans, count blacklisted scripts for stats
		for id, _ := range s.manifest.Scripts {
			scriptID := strings.TrimSuffix(id, ".nse")
			if isBlacklisted, reason := IsBlacklisted(scriptID); isBlacklisted {
				blacklistCount++
				blacklistReasons[reason]++
			}
		}
	}

	// Log blacklist statistics if any scripts were filtered
	if blacklistCount > 0 {
		println("🚫 Filtered", blacklistCount, "blacklisted scripts")
	}

	// For wildcard scans, use ONLY high-value CVE detection scripts
	// This dramatically reduces scan time (206 scripts = 87min, 10 scripts = ~4min)
	if isWildcardScan {
		essentialScripts := []string{
			// TOP PRIORITY: CVE Detection
			"vulners",           // Comprehensive CVE database lookup (HIGHEST VALUE)
			
			// Service Identification (needed for context)
			"banner",            // Basic banner grabbing
			"http-title",        // HTTP service identification
			"ssl-cert",          // SSL certificate info
			
			// Critical Vulnerabilities
			"smb-vuln-ms17-010", // EternalBlue (critical SMB vulnerability)
			"http-shellshock",   // Shellshock vulnerability
			"http-vuln-cve2017-5638", // Apache Struts RCE
			
			// Service Discovery
			"http-enum",         // HTTP path enumeration
			"smb-os-discovery",  // SMB OS detection
			"ftp-anon",          // Anonymous FTP access
		}

		// Add all essential scripts to the list
		scriptIDs = essentialScripts
		
		println("🎯 Wildcard scan - using minimal high-value CVE detection scripts")
	}

	if len(scriptIDs) == 0 {
		// If no scripts selected, include vulners as fallback
		return "vulners", nil
	}

	// Use script names only (no paths) to avoid duplicate script IDs
	// Nmap will search its default paths (/usr/local/share/nmap/scripts/)
	scriptList := strings.Join(scriptIDs, ",")

	// Log the final script count for debugging
	println("🎯  Vulnerability scan with", len(scriptIDs), "scripts")

	return scriptList, nil
}

// isPriorityProtocol determines if a protocol should be included in wildcard scans
func isPriorityProtocol(protocol string) bool {
	priorityProtocols := map[string]bool{
		"http":     true,
		"https":    true,
		"ssh":      true,
		"smb":      true,
		"ftp":      true,
		"smtp":     true,
		"dns":      true,
		"mysql":    true,
		"postgres": true,
	}
	return priorityProtocols[strings.ToLower(protocol)]
}

// prioritizeScripts selects the most important scripts from a larger set
func prioritizeScripts(scriptIDs []string, maxCount int) []string {
	// Define priority keywords for script importance
	priorityKeywords := []string{
		"vuln",    // Vulnerability detection
		"cve",     // CVE-specific
		"exploit", // Exploits
		"auth",    // Authentication issues
		"brute",   // Brute force detection
		"anon",    // Anonymous access
		"enum",    // Enumeration
	}

	var priorityScripts []string
	var otherScripts []string

	// Separate into priority and other
	for _, scriptID := range scriptIDs {
		isPriority := false
		lowerID := strings.ToLower(scriptID)
		for _, keyword := range priorityKeywords {
			if strings.Contains(lowerID, keyword) {
				isPriority = true
				break
			}
		}

		if isPriority {
			priorityScripts = append(priorityScripts, scriptID)
		} else {
			otherScripts = append(otherScripts, scriptID)
		}
	}

	// Take all priority scripts first, then fill remaining with others
	result := priorityScripts
	remaining := maxCount - len(result)
	if remaining > 0 && len(otherScripts) > 0 {
		if remaining > len(otherScripts) {
			remaining = len(otherScripts)
		}
		result = append(result, otherScripts[:remaining]...)
	} else if len(result) > maxCount {
		// Even priority scripts exceed limit, truncate
		result = result[:maxCount]
	}

	return result
}

// containsProtocol checks if the protocol list contains a specific protocol
func containsProtocol(protocols []string, target string) bool {
	for _, p := range protocols {
		if strings.EqualFold(p, target) {
			return true
		}
	}
	return false
}

// containsScriptID checks if the script ID list contains a specific script ID (partial match)
func containsScriptID(scriptIDs []string, target string) bool {
	for _, id := range scriptIDs {
		if strings.Contains(strings.ToLower(id), strings.ToLower(target)) {
			return true
		}
	}
	return false
}

// GetScriptsByProtocol returns a map of protocols to their associated scripts
func (s *ScriptSelector) GetScriptsByProtocol() map[string][]Script {
	protocolScripts := make(map[string][]Script)

	for _, script := range s.manifest.Scripts {
		protocol := script.Protocol
		if protocol == "" {
			protocol = "unknown"
		}
		protocolScripts[protocol] = append(protocolScripts[protocol], script)
	}

	return protocolScripts
}
