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

// InitializeSystemTemplates creates the default system templates if they don't exist
func (tm *TemplateManager) InitializeSystemTemplates(ctx context.Context) error {
	log.Println("Initializing system templates...")

	systemTemplates := []Template{
		{
			ID:          "high-risk",
			Name:        "High Risk Scan",
			Description: "Focused scan with critical vulnerability detection scripts. Targets high-impact vulnerabilities and common attack vectors.",
			Type:        SystemTemplate,
			EnabledScripts: []string{
				// Critical CVE Detection
				"vulners", // CVE database matching (highest value) - NO .nse extension

				// Critical SMB Vulnerabilities
				"smb-vuln-ms17-010.nse", // EternalBlue (WannaCry)
				"smb-vuln-ms08-067.nse", // Critical SMB RCE

				// Critical SSL/TLS Vulnerabilities
				"ssl-heartbleed.nse",    // Heartbleed (critical)
				"ssl-poodle.nse",        // POODLE attack
				"ssl-ccs-injection.nse", // CCS Injection

				// Critical HTTP Vulnerabilities
				"http-shellshock.nse",        // Shellshock (bash RCE)
				"http-vuln-cve2017-5638.nse", // Apache Struts RCE
				"http-vuln-cve2017-5689.nse", // Intel AMT RCE
				"http-vuln-cve2015-1635.nse", // HTTP.sys RCE
				"http-vuln-cve2014-3704.nse", // Drupalgeddon
				"http-vuln-cve2012-1823.nse", // PHP-CGI RCE

				// Service Identification & Enumeration
				"banner.nse",            // Service version detection
				"http-title.nse",        // HTTP server identification
				"ssl-cert.nse",          // SSL certificate information
				"http-enum.nse",         // HTTP path enumeration
				"smb-os-discovery.nse",  // SMB OS and version
				"smb-protocols.nse",     // SMB protocol detection
				"smb-security-mode.nse", // SMB security configuration

				// Common Misconfigurations
				"ftp-anon.nse",         // Anonymous FTP access
				"smb-enum-shares.nse",  // SMB share enumeration
				"http-auth.nse",        // HTTP authentication
				"ssh-auth-methods.nse", // SSH authentication methods
			},
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"enumeration", "discovery", "vulnerability"},
				PortRange:  "1-10000",
				Aggressive: true,
				MaxRetries: 3,
				Parallel:   true,
			},
		},
		{
			ID:             "all",
			Name:           "All Scripts Scan",
			Description:    "Comprehensive scan using all available scripts. This is the most thorough but slowest scan option.",
			Type:           SystemTemplate,
			EnabledScripts: []string{"*"}, // Special marker for "all scripts"
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"enumeration", "discovery", "vulnerability"},
				PortRange:  "1-65535",
				Aggressive: true,
				MaxRetries: 3,
				Parallel:   false, // Sequential for thoroughness
			},
		},
		{
			ID:          "quick",
			Name:        "Quick Scan",
			Description: "Fast scan with essential vulnerability detection. Best for rapid assessment and initial reconnaissance.",
			Type:        SystemTemplate,
			EnabledScripts: []string{
				// Essential vulnerability detection
				"vulners", // CVE database matching (most valuable single script) - NO .nse extension

				// Basic service identification
				"banner.nse",     // Service banners
				"http-title.nse", // HTTP server info
				"ssl-cert.nse",   // SSL certificate (minimal overhead)

				// Quick wins for common issues
				"ftp-anon.nse",      // Anonymous FTP (fast check)
				"smb-protocols.nse", // SMB version (fast check)
			},
			ScanOptions: TemplateOptions{
				ScanTypes:  []string{"enumeration", "vulnerability"},
				PortRange:  top500Ports,
				Aggressive: false,
				MaxRetries: 2,
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

// Top 500 most common ports (reused from old templates.go)
const top500Ports = "80,23,443,21,22,25,3389,110,445,139,143,53,135,3306,8080,1723,111,995,993,5900,1025,587,8888,199,1720,465,548,113,81,6001,10000,514,5060,179,1026,2000,8443,8000,32768,554,26,1433,49152,2001,515,8008,49154,1027,5666,646,5000,5631,631,49153,8081,2049,88,79,5800,106,2121,1110,49155,6000,513,990,5357,427,49156,543,544,5101,144,7,389,8009,3128,444,9999,5009,7070,5190,3000,5432,1900,3986,13,1029,9,5051,6646,49157,1028,873,1755,2717,4899,9100,119,37,1000,3001,5001,82,10010,1030,9090,2107,1024,2103,6004,1801,5050,19,8031,1041,255,1049,1048,2967,1053,3703,1056,1065,1064,1054,17,808,3689,1031,1044,1071,5901,100,9102,8010,2869,1039,5120,4001,9000,2105,636,1038,2601,1,7000,1066,1069,625,311,280,254,4000,1993,1761,5003,2002,2005,1998,1032,1050,6112,3690,1521,2161,6002,1080,2401,4045,902,7937,787,1058,2383,32771,1033,1040,1059,50000,5555,10001,1494,593,2301,3,1,3268,7938,1234,1022,1074,8002,1036,1035,9001,1037,464,497,1935,6666,2003,6543,1352,24,3269,1111,407,500,20,2006,3260,15000,1218,1034,4444,264,2004,33,1042,42510,999,3052,1023,1068,222,7100,888,4827,1999,563,1717,2008,992,32770,32772,7001,8082,2007,740,5550,2009,5801,1043,512,2701,7019,50001,1700,4662,2065,2010,42,9535,2602,3333,161,5100,5002,2604,4002,6059,1047,8192,8193,2702,6789,9595,1051,9594,9593,16993,16992,5226,5225,32769,3283,1052,8194,1055,1062,9415,8701,8652,8651,8089,65389,65000,64680,64623,55600,55555,52869,35500,33354,23502,20828,1311,1060,4443,730,731,709,1067,13782,5902,366,9050,1002,85,5500,5431,1864,1863,8085,51103,49999,45100,10243,49,3495,6667,90,475,27000,1503,6881,1500,8021,340,78,5566,8088,2222,9071,8899,6005,9876,1501,5102,32774,32773,9101,5679,163,648,146,1666,901,83,9207,8001,8083,5004,3476,8084,5214,14238,12345,912,30,2605,2030,6,541,8007,3005,4,1248,2500,880,306,4242,1097,9009,2525,1086,1088,8291,52822,6101,900,7200,2809,395,800,32775,12000,1083,211,987,705,20005,711,13783,6969,3071,5269,5222,1085,1046,5987,5989,5988,2190,11967,8600,3766,7627,8087,30000,9010,7741,14000,3367,1099,1098,3031,2718,6580,15002,4129,6901,3827,3580,2144,9900,8181,3801,1718,2811,9080,2135,1045,2399,3017,10002,1148,9002,8873,2875,9011,5718,8086,3998,2607,11110,4126,5911,5910,9618,2381,1096,3300,3351,1073,8333,3784,5633,15660,6123,3211,1078,3659,3551,2260,2160,2100,16001,3325,3323,1104,9968,9503,9502,9485,9290,9220,8994,8649,8222,7911,7625,7106,65129,63331,6156,6129,60020,5962,5961,5960,5959,5925,5877,5825,5810,58080,57294,50800"
