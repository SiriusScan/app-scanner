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

	// For each script in manifest, check if it matches the protocols
	for id, script := range s.manifest.Scripts {
		// Include scripts that match any of the protocols or have "*" protocol
		if script.Protocol == "*" || containsProtocol(protocols, script.Protocol) || containsProtocol(protocols, "*") {
			// Ensure script ID doesn't have .nse extension
			scriptID := strings.TrimSuffix(id, ".nse")
			scriptIDs = append(scriptIDs, scriptID)
		}
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

	// Join script IDs with commas
	scriptList := strings.Join(scriptIDs, ",")

	// Log the final script list for debugging
	if len(protocols) > 0 && protocols[0] == "smb" {
		// This is an SMB-specific scan
		println("🎯 SMB vulnerability scan with scripts:", scriptList)
	} else {
		// This is a general scan
		println("🎯 General vulnerability scan including scripts:", scriptList)
	}

	return scriptList, nil
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
