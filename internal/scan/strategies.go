package scan

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/SiriusScan/app-scanner/modules/naabu"
	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
)

// ScanStrategy defines an interface for executing a scan on a target.
// The Execute method accepts a context for cancellation support.
type ScanStrategy interface {
	Execute(target string) (sirius.Host, error)
	// ExecuteWithContext performs the scan with cancellation support
	ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error)
}

// NmapStrategy implements vulnerability scanning using Nmap.
type NmapStrategy struct {
	Protocols  []string // Deprecated: use ScriptList
	ScriptList []string // Explicit list of scripts to run
	PortRange  string   // Port range to scan (from template)
}

// Execute performs the vulnerability scan using Nmap and expands vulnerability details.
// This is a convenience method that uses context.Background().
func (n *NmapStrategy) Execute(target string) (sirius.Host, error) {
	return n.ExecuteWithContext(context.Background(), target)
}

// ExecuteWithContext performs the vulnerability scan with cancellation support.
func (n *NmapStrategy) ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error) {
	return n.executeWithContext(ctx, target, nmap.ScanWithConfig)
}

func (n *NmapStrategy) executeWithContext(ctx context.Context, target string, scan func(nmap.ScanConfig) (sirius.Host, error)) (sirius.Host, error) {
	slog.Info("starting vulnerability scan", "target", target)

	// Check for cancellation before starting
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled before starting: %w", ctx.Err())
	}

	// Create a scan config with context
	config := nmap.ScanConfig{
		Target:    target,
		PortRange: n.PortRange, // Pass port range from template
		Ctx:       ctx,         // Pass context for cancellation
	}

	// Use explicit script list if provided, otherwise fall back to protocols
	if len(n.ScriptList) > 0 {
		config.ScriptList = n.ScriptList
		slog.Debug("using explicit script list", "script_count", len(n.ScriptList))
	} else if len(n.Protocols) > 0 {
		config.Protocols = n.Protocols
		slog.Debug("using protocol-based script selection", "protocols", n.Protocols)
	} else {
		// Default to all protocols
		config.Protocols = []string{"*"}
		slog.Debug("using default wildcard scan")
	}

	// Log port range being used
	if n.PortRange != "" {
		slog.Debug("using template port range", "port_range", n.PortRange)
	}

	results, err := scan(config)
	if err != nil {
		return sirius.Host{}, err
	}

	// Check for cancellation after scan
	if ctx.Err() != nil {
		return results, fmt.Errorf("scan cancelled: %w", ctx.Err())
	}

	// Findings are scanner evidence as reported by the tools (vulners
	// carries its own CVSS scores). No external enrichment happens on the
	// scan path: it cannot delay or drop persistence, and unknown scores
	// stay unknown instead of being fabricated.
	results.Vulnerabilities = normalizeVulnerabilities(results.Vulnerabilities)

	slog.Info("vulnerability scan complete", "target", target, "vuln_count", len(results.Vulnerabilities))
	return results, nil
}

// normalizeVulnerabilities trims IDs and fills identity fields only. It
// never invents a description or score the scanner did not report.
func normalizeVulnerabilities(vulns []sirius.Vulnerability) []sirius.Vulnerability {
	normalized := append([]sirius.Vulnerability{}, vulns...)
	for i, vuln := range normalized {
		vuln.VID = strings.TrimSpace(vuln.VID)
		if vuln.Title == "" {
			vuln.Title = vuln.VID
		}
		if vuln.CVEID == "" && strings.HasPrefix(vuln.VID, "CVE-") {
			vuln.CVEID = vuln.VID
		}
		if vuln.CVSSScore == 0 && vuln.RiskScore > 0 {
			vuln.CVSSScore = vuln.RiskScore
		}
		normalized[i] = vuln
	}
	return normalized
}

// NaabuStrategy implements port enumeration using Naabu
type NaabuStrategy struct {
	Ports   string
	Retries int
}

// Execute performs port enumeration using Naabu.
// This is a convenience method that uses context.Background().
func (n *NaabuStrategy) Execute(target string) (sirius.Host, error) {
	return n.ExecuteWithContext(context.Background(), target)
}

// ExecuteWithContext performs port enumeration with cancellation support.
func (n *NaabuStrategy) ExecuteWithContext(ctx context.Context, target string) (sirius.Host, error) {
	// Check for cancellation before starting
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled before starting")
	}

	host, err := naabu.Scan(target, naabu.ScanConfig{
		PortRange: n.Ports,
		Retries:   n.Retries,
		Ctx:       ctx, // Pass context for cancellation
	})
	if errors.Is(err, naabu.ErrHostDown) {
		slog.Info("host appears down, skipping further scans", "target", target)
		return sirius.Host{}, nil
	}
	if err != nil {
		return sirius.Host{}, err
	}
	return host, nil
}

// FingerprintResult contains the results of a fingerprint scan.
// This struct is used by both the FingerprintStrategy interface and the ping++ adapter.
type FingerprintResult struct {
	IsAlive  bool              // Whether the host is alive/reachable
	OSFamily string            // Detected OS family (e.g., "windows", "linux", "unknown")
	TTL      int               // TTL value from ICMP response
	Details  map[string]string // Additional fingerprint details (confidence, hops, etc.)
}

// FingerprintStrategy defines an interface for host fingerprinting operations.
// The default implementation uses ping++ for ICMP/TCP probing and TTL-based OS detection.
//
// Implementations:
//   - PingPlusPlusAdapter: Real fingerprinting using ping++ (see pingpp_adapter.go)
//
// Configuration options are available via ScanOptions:
//   - FingerprintProbes: probe types (icmp, tcp, arp, smb)
//   - FingerprintTimeout: per-probe timeout
//   - DisableICMP: for unprivileged execution
type FingerprintStrategy interface {
	Fingerprint(target string) (FingerprintResult, error)
	// FingerprintWithContext performs fingerprinting with cancellation support
	FingerprintWithContext(ctx context.Context, target string) (FingerprintResult, error)
}
