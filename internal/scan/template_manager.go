package scan

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

// TemplateManager manages scan templates in ValKey
type TemplateManager struct {
	kvStore store.KVStore
}

// NewTemplateManager creates a new TemplateManager instance
func NewTemplateManager(kvStore store.KVStore) *TemplateManager {
	return &TemplateManager{
		kvStore: kvStore,
	}
}

// GetTemplate retrieves a template by ID
func (tm *TemplateManager) GetTemplate(ctx context.Context, id string) (*Template, error) {
	key := TemplateKeyPrefix + id
	resp, err := tm.kvStore.GetValue(ctx, key)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil, fmt.Errorf("template '%s' not found", id)
		}
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	var template Template
	if err := json.Unmarshal([]byte(resp.Message.Value), &template); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template: %w", err)
	}

	return &template, nil
}

// CreateTemplate creates a new template
func (tm *TemplateManager) CreateTemplate(ctx context.Context, template *Template) error {
	// Validate template
	if err := tm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	// Set timestamps
	now := time.Now()
	template.CreatedAt = now
	template.UpdatedAt = now

	// Marshal template to JSON
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	// Store template in ValKey
	key := TemplateKeyPrefix + template.ID
	if err := tm.kvStore.SetValue(ctx, key, string(templateJSON)); err != nil {
		return fmt.Errorf("failed to store template: %w", err)
	}

	// Add to template list
	if err := tm.addToTemplateList(ctx, template.ID); err != nil {
		return fmt.Errorf("failed to add template to list: %w", err)
	}

	// If system template, add to system templates list
	if template.Type == SystemTemplate {
		if err := tm.addToSystemTemplatesList(ctx, template.ID); err != nil {
			return fmt.Errorf("failed to add to system templates list: %w", err)
		}
	}

	log.Printf("Created template: %s (%s)", template.Name, template.ID)
	return nil
}

// UpdateTemplate updates an existing template
func (tm *TemplateManager) UpdateTemplate(ctx context.Context, template *Template) error {
	// Check if template exists
	existing, err := tm.GetTemplate(ctx, template.ID)
	if err != nil {
		return fmt.Errorf("template not found: %w", err)
	}

	// Cannot modify system templates
	if existing.Type == SystemTemplate {
		return fmt.Errorf("cannot modify system template '%s'", template.ID)
	}

	// Validate template
	if err := tm.validateTemplate(template); err != nil {
		return fmt.Errorf("invalid template: %w", err)
	}

	// Preserve creation time, update modification time
	template.CreatedAt = existing.CreatedAt
	template.UpdatedAt = time.Now()
	template.Type = CustomTemplate // Ensure it stays custom

	// Marshal template to JSON
	templateJSON, err := json.Marshal(template)
	if err != nil {
		return fmt.Errorf("failed to marshal template: %w", err)
	}

	// Store template in ValKey
	key := TemplateKeyPrefix + template.ID
	if err := tm.kvStore.SetValue(ctx, key, string(templateJSON)); err != nil {
		return fmt.Errorf("failed to update template: %w", err)
	}

	log.Printf("Updated template: %s (%s)", template.Name, template.ID)
	return nil
}

// DeleteTemplate deletes a template (only custom templates can be deleted)
func (tm *TemplateManager) DeleteTemplate(ctx context.Context, id string) error {
	// Check if template exists
	template, err := tm.GetTemplate(ctx, id)
	if err != nil {
		return fmt.Errorf("template not found: %w", err)
	}

	// Cannot delete system templates
	if template.Type == SystemTemplate {
		return fmt.Errorf("cannot delete system template '%s'", id)
	}

	// Delete template from ValKey
	key := TemplateKeyPrefix + id
	if err := tm.kvStore.DeleteValue(ctx, key); err != nil {
		return fmt.Errorf("failed to delete template: %w", err)
	}

	// Remove from template list
	if err := tm.removeFromTemplateList(ctx, id); err != nil {
		log.Printf("Warning: failed to remove template from list: %v", err)
	}

	log.Printf("Deleted template: %s (%s)", template.Name, id)
	return nil
}

// ListTemplates retrieves all templates
func (tm *TemplateManager) ListTemplates(ctx context.Context) ([]Template, error) {
	// Get template list
	resp, err := tm.kvStore.GetValue(ctx, TemplateListKey)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			// No templates yet
			return []Template{}, nil
		}
		return nil, fmt.Errorf("failed to get template list: %w", err)
	}

	var templateList TemplateList
	if err := json.Unmarshal([]byte(resp.Message.Value), &templateList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal template list: %w", err)
	}

	// Retrieve each template
	templates := make([]Template, 0, len(templateList.Templates))
	for _, id := range templateList.Templates {
		template, err := tm.GetTemplate(ctx, id)
		if err != nil {
			log.Printf("Warning: failed to get template %s: %v", id, err)
			continue
		}
		templates = append(templates, *template)
	}

	return templates, nil
}

// ResolveScripts returns the list of enabled scripts for a template
func (tm *TemplateManager) ResolveScripts(ctx context.Context, templateID string) ([]string, error) {
	template, err := tm.GetTemplate(ctx, templateID)
	if err != nil {
		return nil, fmt.Errorf("failed to get template: %w", err)
	}

	return template.EnabledScripts, nil
}

// Common port sets for templates (used as fallback when discovery finds nothing)
const (
	// Top 100 most common ports - reasonable fallback for most scans
	top100Ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080," +
		"1,7,9,13,17,19,26,37,49,79,81,82,83,84,85,88,89,90,99,100,106,109,113,119,125,144,146,161,163," +
		"179,199,211,212,222,254,255,256,259,264,280,301,306,311,340,366,389,406,407,416,417,425,427,443," +
		"444,445,458,464,465,481,497,500,512,513,514,515,524,541,543,544,545,548,554,555,563,587,593,616,617,625,631,636"

	// Top 20 critical ports - minimal fallback for quick scans
	top20Ports = "21,22,23,25,53,80,110,139,143,443,445,993,995,3306,3389,5432,5900,8080,8443,8888"
)

// InitializeSystemTemplates creates the default system templates if they don't exist
func (tm *TemplateManager) InitializeSystemTemplates(ctx context.Context) error {
	log.Println("Initializing system templates...")

	systemTemplates := []Template{
		{
			ID:          "high-risk",
			Name:        "High Risk Scan",
			Description: "Focused scan targeting critical vulnerabilities. Uses discovery to find open ports, then runs high-value vulnerability scripts.",
			Type:        SystemTemplate,
			EnabledScripts: []string{
				// Critical CVE Detection
				"vulners", // CVE database matching (highest value)

				// Critical SMB Vulnerabilities
				"smb-vuln-ms17-010.nse", // EternalBlue (WannaCry)
				"smb-vuln-ms08-067.nse", // Critical SMB RCE

				// Critical SSL/TLS Vulnerabilities
				"ssl-heartbleed.nse",    // Heartbleed
				"ssl-poodle.nse",        // POODLE attack
				"ssl-ccs-injection.nse", // CCS Injection

				// Critical HTTP Vulnerabilities
				"http-shellshock.nse",        // Shellshock (bash RCE)
				"http-vuln-cve2017-5638.nse", // Apache Struts RCE

				// Service Identification
				"banner.nse",           // Service version detection
				"http-title.nse",       // HTTP server identification
				"ssl-cert.nse",         // SSL certificate information
				"smb-os-discovery.nse", // SMB OS and version

				// Common Misconfigurations
				"ftp-anon.nse",        // Anonymous FTP access
				"smb-enum-shares.nse", // SMB share enumeration
			},
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"fingerprint", "enumeration", "vulnerability"},
				PortRange:  "", // Let discovery find open ports
				Aggressive: true,
				MaxRetries: 2,
				Parallel:   true,
			},
		},
		{
			ID:             "all",
			Name:           "All Scripts Scan",
			Description:    "Comprehensive scan using all available scripts against discovered ports. Thorough but time-intensive.",
			Type:           SystemTemplate,
			EnabledScripts: []string{"*"}, // Special marker for "all scripts"
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"fingerprint", "enumeration", "discovery", "vulnerability"},
				PortRange:  top100Ports, // Fallback only if discovery finds nothing
				Aggressive: true,
				MaxRetries: 3,
				Parallel:   false, // Sequential for thoroughness
			},
		},
		{
			ID:          "quick",
			Name:        "Quick Scan",
			Description: "Fast reconnaissance scan with essential scripts. Best for rapid assessment of common services.",
			Type:        SystemTemplate,
			EnabledScripts: []string{
				// Essential vulnerability detection
				"vulners", // CVE database matching

				// Basic service identification
				"banner.nse",     // Service banners
				"http-title.nse", // HTTP server info
				"ssl-cert.nse",   // SSL certificate

				// Quick common issue checks
				"ftp-anon.nse",      // Anonymous FTP
				"smb-protocols.nse", // SMB version
			},
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"fingerprint", "enumeration", "vulnerability"},
				PortRange:  top20Ports, // Small fallback for speed
				Aggressive: false,
				MaxRetries: 1,
				Parallel:   true,
			},
		},
	}

	// Load all NSE scripts from manifest to replace "*" wildcard
	allScripts, err := tm.loadAllNSEScripts(ctx)
	if err != nil {
		log.Printf("Warning: failed to load NSE scripts for 'all' template: %v", err)
		log.Println("'All Scripts' template will use wildcard - may not work correctly")
	} else {
		// Replace "*" wildcard with actual script list
		for i := range systemTemplates {
			if systemTemplates[i].ID == "all" && len(systemTemplates[i].EnabledScripts) == 1 && systemTemplates[i].EnabledScripts[0] == "*" {
				systemTemplates[i].EnabledScripts = allScripts
				log.Printf("Loaded %d NSE scripts for 'All Scripts' template", len(allScripts))
				break
			}
		}
	}

	// Create each system template
	for _, template := range systemTemplates {
		// Check if template already exists
		existing, err := tm.GetTemplate(ctx, template.ID)
		if err == nil && existing != nil {
			log.Printf("System template '%s' already exists, skipping", template.ID)
			continue
		}

		if err := tm.CreateTemplate(ctx, &template); err != nil {
			return fmt.Errorf("failed to create system template '%s': %w", template.ID, err)
		}
		log.Printf("Created system template: %s", template.Name)
	}

	log.Println("System templates initialized successfully")
	return nil
}

// loadAllNSEScripts loads all NSE script IDs from the manifest
func (tm *TemplateManager) loadAllNSEScripts(ctx context.Context) ([]string, error) {
	// Try to get NSE manifest from ValKey
	manifestKey := "nse:manifest"
	resp, err := tm.kvStore.GetValue(ctx, manifestKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get NSE manifest from ValKey: %w", err)
	}

	// Parse manifest JSON
	var manifest struct {
		Scripts map[string]interface{} `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(resp.Message.Value), &manifest); err != nil {
		return nil, fmt.Errorf("failed to parse NSE manifest: %w", err)
	}

	// Extract all script IDs (keys from the scripts map)
	scriptIDs := make([]string, 0, len(manifest.Scripts))
	for scriptID := range manifest.Scripts {
		scriptIDs = append(scriptIDs, scriptID)
	}

	if len(scriptIDs) == 0 {
		return nil, fmt.Errorf("no scripts found in NSE manifest")
	}

	return scriptIDs, nil
}

// validateTemplate validates template fields
func (tm *TemplateManager) validateTemplate(template *Template) error {
	if template.ID == "" {
		return fmt.Errorf("template ID is required")
	}
	if template.Name == "" {
		return fmt.Errorf("template name is required")
	}
	if len(template.EnabledScripts) == 0 {
		return fmt.Errorf("template must have at least one enabled script")
	}
	if len(template.ScanOptions.ScanTypes) == 0 {
		return fmt.Errorf("template must have at least one scan type")
	}
	return nil
}

// addToTemplateList adds a template ID to the global template list
func (tm *TemplateManager) addToTemplateList(ctx context.Context, id string) error {
	// Get current list
	var templateList TemplateList
	resp, err := tm.kvStore.GetValue(ctx, TemplateListKey)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("failed to get template list: %w", err)
		}
		// List doesn't exist yet, create new
		templateList = TemplateList{Templates: []string{}}
	} else {
		if err := json.Unmarshal([]byte(resp.Message.Value), &templateList); err != nil {
			return fmt.Errorf("failed to unmarshal template list: %w", err)
		}
	}

	// Check if already in list
	for _, tid := range templateList.Templates {
		if tid == id {
			return nil // Already in list
		}
	}

	// Add to list
	templateList.Templates = append(templateList.Templates, id)

	// Save updated list
	listJSON, err := json.Marshal(templateList)
	if err != nil {
		return fmt.Errorf("failed to marshal template list: %w", err)
	}

	if err := tm.kvStore.SetValue(ctx, TemplateListKey, string(listJSON)); err != nil {
		return fmt.Errorf("failed to update template list: %w", err)
	}

	return nil
}

// removeFromTemplateList removes a template ID from the global template list
func (tm *TemplateManager) removeFromTemplateList(ctx context.Context, id string) error {
	// Get current list
	resp, err := tm.kvStore.GetValue(ctx, TemplateListKey)
	if err != nil {
		return fmt.Errorf("failed to get template list: %w", err)
	}

	var templateList TemplateList
	if err := json.Unmarshal([]byte(resp.Message.Value), &templateList); err != nil {
		return fmt.Errorf("failed to unmarshal template list: %w", err)
	}

	// Remove from list
	newList := make([]string, 0, len(templateList.Templates))
	for _, tid := range templateList.Templates {
		if tid != id {
			newList = append(newList, tid)
		}
	}
	templateList.Templates = newList

	// Save updated list
	listJSON, err := json.Marshal(templateList)
	if err != nil {
		return fmt.Errorf("failed to marshal template list: %w", err)
	}

	if err := tm.kvStore.SetValue(ctx, TemplateListKey, string(listJSON)); err != nil {
		return fmt.Errorf("failed to update template list: %w", err)
	}

	return nil
}

// addToSystemTemplatesList adds a template ID to the system templates list
func (tm *TemplateManager) addToSystemTemplatesList(ctx context.Context, id string) error {
	// Get current list
	var templateList TemplateList
	resp, err := tm.kvStore.GetValue(ctx, SystemTemplatesListKey)
	if err != nil {
		if !strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("failed to get system templates list: %w", err)
		}
		// List doesn't exist yet, create new
		templateList = TemplateList{Templates: []string{}}
	} else {
		if err := json.Unmarshal([]byte(resp.Message.Value), &templateList); err != nil {
			return fmt.Errorf("failed to unmarshal system templates list: %w", err)
		}
	}

	// Check if already in list
	for _, tid := range templateList.Templates {
		if tid == id {
			return nil // Already in list
		}
	}

	// Add to list
	templateList.Templates = append(templateList.Templates, id)

	// Save updated list
	listJSON, err := json.Marshal(templateList)
	if err != nil {
		return fmt.Errorf("failed to marshal system templates list: %w", err)
	}

	if err := tm.kvStore.SetValue(ctx, SystemTemplatesListKey, string(listJSON)); err != nil {
		return fmt.Errorf("failed to update system templates list: %w", err)
	}

	return nil
}

