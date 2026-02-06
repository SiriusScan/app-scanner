// Package scan provides the PingPlusPlusAdapter which integrates ping++ as the
// fingerprinting engine for the app-scanner pipeline.
package scan

import (
	"context"
	"fmt"
	"time"

	"github.com/SiriusScan/ping++/integration/appscanner"
)

// DefaultFingerprintProbes are the default probe types for fingerprinting.
// This matches the ping++ CLI defaults which include SSH, HTTP, and SMB probes
// for accurate OS detection (especially Windows detection via SMB/SSH banners).
var DefaultFingerprintProbes = []string{"icmp", "tcp", "ssh", "http", "smb"}

// DefaultFingerprintTimeout is the default timeout for fingerprint probes.
const DefaultFingerprintTimeout = 3 * time.Second

// FingerprintOptions contains configuration for fingerprint scanning.
type FingerprintOptions struct {
	// ProbeTypes specifies which probes to use (icmp, tcp, arp, smb)
	ProbeTypes []string

	// Timeout is the per-probe timeout duration
	Timeout time.Duration

	// DisableICMP disables ICMP probing (for unprivileged mode)
	DisableICMP bool
}

// DefaultFingerprintOptions returns sensible defaults for fingerprinting.
func DefaultFingerprintOptions() FingerprintOptions {
	return FingerprintOptions{
		ProbeTypes:  DefaultFingerprintProbes,
		Timeout:     DefaultFingerprintTimeout,
		DisableICMP: false,
	}
}

// PingPlusPlusAdapter wraps the ping++ PingPlusPlusStrategy to implement
// the app-scanner FingerprintStrategy interface.
//
// This adapter:
// - Converts between ping++ and app-scanner result types
// - Provides configuration options for probe types and timeouts
// - Handles the interface bridging without circular imports
type PingPlusPlusAdapter struct {
	strategy *appscanner.PingPlusPlusStrategy
	options  FingerprintOptions
}

// NewPingPlusPlusAdapter creates a new adapter with default options.
func NewPingPlusPlusAdapter() *PingPlusPlusAdapter {
	opts := DefaultFingerprintOptions()
	return &PingPlusPlusAdapter{
		strategy: appscanner.NewStrategyWithOptions(
			opts.ProbeTypes,
			opts.Timeout,
			opts.DisableICMP,
		),
		options: opts,
	}
}

// NewPingPlusPlusAdapterWithOptions creates a new adapter with custom options.
func NewPingPlusPlusAdapterWithOptions(opts FingerprintOptions) *PingPlusPlusAdapter {
	// Apply defaults for unset values
	if len(opts.ProbeTypes) == 0 {
		opts.ProbeTypes = DefaultFingerprintProbes
	}
	if opts.Timeout == 0 {
		opts.Timeout = DefaultFingerprintTimeout
	}

	return &PingPlusPlusAdapter{
		strategy: appscanner.NewStrategyWithOptions(
			opts.ProbeTypes,
			opts.Timeout,
			opts.DisableICMP,
		),
		options: opts,
	}
}

// Fingerprint performs host fingerprinting using ping++.
// This method implements the FingerprintStrategy interface.
// This is a convenience method that uses context.Background().
func (a *PingPlusPlusAdapter) Fingerprint(target string) (FingerprintResult, error) {
	return a.FingerprintWithContext(context.Background(), target)
}

// FingerprintWithContext performs host fingerprinting with cancellation support.
// This method implements the FingerprintStrategy interface.
func (a *PingPlusPlusAdapter) FingerprintWithContext(ctx context.Context, target string) (FingerprintResult, error) {
	// Check for cancellation before starting
	if ctx.Err() != nil {
		return FingerprintResult{}, fmt.Errorf("fingerprint cancelled before starting: %w", ctx.Err())
	}

	// Call ping++ strategy
	pingResult, err := a.strategy.Fingerprint(target)
	if err != nil {
		return FingerprintResult{}, err
	}

	// Check for cancellation after scan
	if ctx.Err() != nil {
		return FingerprintResult{}, fmt.Errorf("fingerprint cancelled: %w", ctx.Err())
	}

	// Convert ping++ result to app-scanner result
	return FingerprintResult{
		IsAlive:  pingResult.IsAlive,
		OSFamily: pingResult.OSFamily,
		TTL:      pingResult.TTL,
		Details:  pingResult.Details,
	}, nil
}

// Options returns the current fingerprint options.
func (a *PingPlusPlusAdapter) Options() FingerprintOptions {
	return a.options
}
