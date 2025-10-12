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

	// For each script in manifest, check if it matches the protocols
	for id, script := range s.manifest.Scripts {
		// Skip wildcard scripts when doing a wildcard scan to avoid overload
		// We'll add curated scripts instead
		if isWildcardScan && script.Protocol == "*" {
			continue
		}

		// Include scripts that match any of the protocols or have "*" protocol
		if script.Protocol == "*" || containsProtocol(protocols, script.Protocol) || isWildcardScan {
			// For wildcard scans, only include scripts from priority protocols
			if isWildcardScan && !isPriorityProtocol(script.Protocol) {
				continue
			}

			// Ensure script ID doesn't have .nse extension
			scriptID := strings.TrimSuffix(id, ".nse")
			scriptIDs = append(scriptIDs, scriptID)
		}
	}

	// For wildcard scans, add curated essential scripts
	if isWildcardScan {
		essentialScripts := []string{
			"vulners",           // CVE detection
			"http-title",        // HTTP service identification
			"http-enum",         // HTTP enumeration
			"ssh-hostkey",       // SSH key fingerprinting
			"ssl-cert",          // SSL certificate info
			"banner",            // Basic banner grabbing
			"smb-vuln-ms17-010", // Critical SMB vulnerability
			"smb-os-discovery",  // SMB OS detection
			"ftp-anon",          // Anonymous FTP
		}

		for _, script := range essentialScripts {
			if !containsScriptID(scriptIDs, script) {
				scriptIDs = append(scriptIDs, script)
			}
		}

		println("🌐 Wildcard scan detected - using curated essential script set")
	}

	// Always add the SMB vulnerability script for critical security checks
	const smbScript = "smb-vuln-ms17-010"
	if !containsScriptID(scriptIDs, smbScript) {
		scriptIDs = append(scriptIDs, smbScript)
	}

	if len(scriptIDs) == 0 {
		// If no scripts selected, include vulners as fallback
		return "vulners", nil
	}

	// Limit total scripts to prevent overload
	maxScripts := 50 // Reasonable limit to prevent timeout/overload
	if len(scriptIDs) > maxScripts {
		println("⚠️  Warning: Script count", len(scriptIDs), "exceeds maximum of", maxScripts, "- truncating to priority scripts")
		scriptIDs = prioritizeScripts(scriptIDs, maxScripts)
	}

	// Prepend full path to each script ID for Nmap 7.80 compatibility
	// (Nmap 7.80 doesn't support --script-path, so we use absolute paths)
	var scriptPaths []string
	for _, scriptID := range scriptIDs {
		scriptPaths = append(scriptPaths, "/opt/sirius/nse/sirius-nse/scripts/"+scriptID+".nse")
	}

	// Join script paths with commas
	scriptList := strings.Join(scriptPaths, ",")

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
