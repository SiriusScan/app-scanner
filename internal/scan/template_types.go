package scan

import "time"

// TemplateType represents whether a template is system-defined or user-created
type TemplateType string

const (
	SystemTemplate TemplateType = "system"
	CustomTemplate TemplateType = "custom"
)

// Template represents a scan configuration template
type Template struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	Type           TemplateType    `json:"type"`
	EnabledScripts []string        `json:"enabled_scripts"`
	ScanOptions    TemplateOptions `json:"scan_options"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// TemplateOptions defines the scan configuration for a template
type TemplateOptions struct {
	ScanTypes    []string `json:"scan_types"`
	PortRange    string   `json:"port_range"`
	Aggressive   bool     `json:"aggressive"`
	MaxRetries   int      `json:"max_retries"`
	Parallel     bool     `json:"parallel"`
	ExcludePorts []string `json:"exclude_ports,omitempty"`
}

// TemplateList represents a list of template IDs
type TemplateList struct {
	Templates []string `json:"templates"`
}

// ValKey key constants for template storage
const (
	TemplateKeyPrefix      = "scan:template:"
	TemplateListKey        = "scan:template:list"
	SystemTemplatesListKey = "scan:system-templates"
)



