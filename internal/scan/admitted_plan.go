package scan

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// admittedScanPlan is set before scheduling and shared read-only by the run.
// A host's port override is applied to a copy of the original options.
type admittedScanPlan struct {
	currentScanOptions ScanOptions
	scriptSelection    []string
	agentOnly          bool
	digest             string
}

type templateAdmissionError struct {
	templateID string
	cause      error
}

func (e *templateAdmissionError) Error() string {
	return fmt.Sprintf("cannot admit template %q: %v", e.templateID, e.cause)
}

func (e *templateAdmissionError) Unwrap() error { return e.cause }

type templateLookup func(context.Context, string) (*Template, error)

func resolveScanPlan(ctx context.Context, options ScanOptions, lookup templateLookup) (admittedScanPlan, error) {
	var plan admittedScanPlan
	if err := ctx.Err(); err != nil {
		return plan, err
	}
	if options.TemplateID != "" {
		template, err := lookup(ctx, options.TemplateID)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return plan, ctxErr
		}
		if err != nil {
			return plan, &templateAdmissionError{templateID: options.TemplateID, cause: err}
		}
		if template == nil || template.ID != options.TemplateID {
			return plan, &templateAdmissionError{templateID: options.TemplateID, cause: fmt.Errorf("template ID does not match the request")}
		}

		options = applyTemplateDefaults(options, template.ScanOptions)
		agent := template.ScanOptions.AgentScan
		plan.agentOnly = len(options.ScanTypes) == 0 && agent != nil && agent.Enabled
		if !plan.agentOnly {
			if err := validateNamedNetworkPlan(options.ScanTypes, template.EnabledScripts); err != nil {
				return plan, &templateAdmissionError{templateID: options.TemplateID, cause: err}
			}
		}
		plan.scriptSelection = append([]string(nil), template.EnabledScripts...)
	}
	plan.currentScanOptions = cloneScanOptions(options)

	// Use a fixed representation of the effective options and preserve slice
	// order. Descriptive metadata and the host-local port override are excluded.
	encoded, err := json.Marshal(struct {
		Options   ScanOptions `json:"options"`
		Scripts   []string    `json:"scripts"`
		AgentOnly bool        `json:"agent_only"`
	}{plan.currentScanOptions, plan.scriptSelection, plan.agentOnly})
	if err != nil {
		return admittedScanPlan{}, fmt.Errorf("encode admitted scan plan: %w", err)
	}
	plan.digest = fmt.Sprintf("sha256:%x", sha256.Sum256(encoded))
	return plan, nil
}

func applyTemplateDefaults(options ScanOptions, defaults TemplateOptions) ScanOptions {
	if options.PortRange == "" {
		options.PortRange = defaults.PortRange
	}
	if len(options.ScanTypes) == 0 {
		options.ScanTypes = defaults.ScanTypes
	}
	if len(options.ExcludePorts) == 0 {
		options.ExcludePorts = defaults.ExcludePorts
	}
	if options.MaxRetries == 0 {
		options.MaxRetries = defaults.MaxRetries
	}
	options.Aggressive = options.Aggressive || defaults.Aggressive
	options.Parallel = options.Parallel || defaults.Parallel
	return options
}

func validateNamedNetworkPlan(scanTypes, selection []string) error {
	if contains(scanTypes, "vulnerability") {
		if len(selection) == 0 {
			return fmt.Errorf("vulnerability phase requires an explicit script selection")
		}
		for _, script := range selection {
			if strings.TrimSpace(script) == "" {
				return fmt.Errorf("script selection contains a blank entry")
			}
		}
		return nil
	}
	if contains(scanTypes, "fingerprint") || contains(scanTypes, "enumeration") || contains(scanTypes, "port_scan") {
		return nil
	}
	return fmt.Errorf("template has no supported network phase")
}
