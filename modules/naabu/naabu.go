package naabu

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/SiriusScan/go-api/sirius"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/naabu/v2/pkg/result"
	"github.com/projectdiscovery/naabu/v2/pkg/runner"
)

var ErrHostDown = errors.New("host appears to be down (no open ports found)")

// Scan is a function variable that can be overridden for testing
var Scan = scanImpl

// ScanConfig holds the configuration for the Naabu scan
type ScanConfig struct {
	PortRange string
	Retries   int
	Ctx       context.Context // Context for cancellation support
}

// scanImpl is the default implementation of the Naabu scan
func scanImpl(target string, config ScanConfig) (sirius.Host, error) {
	// Validate if target is a single IP
	if ip := net.ParseIP(target); ip == nil {
		return sirius.Host{}, fmt.Errorf("naabu scan requires a single IP address, got: %s", target)
	}

	// Ensure context is set (use background if not provided for backward compatibility)
	ctx := config.Ctx
	if ctx == nil {
		ctx = context.Background()
	}

	// Check for cancellation before starting
	if ctx.Err() != nil {
		return sirius.Host{}, fmt.Errorf("scan cancelled before starting: %w", ctx.Err())
	}

	var results []sirius.Port
	options := runner.Options{
		Host:              goflags.StringSlice{target},
		ScanType:          "c",
		Ports:             config.PortRange,
		Timeout:           150,
		Rate:              500,
		Debug:             false,
		Verbose:           false,
		Retries:           config.Retries,
		WarmUpTime:        5,
		Interface:         "",
		Threads:           10,
		Stream:            false,
		EnableProgressBar: false,
		OnResult: func(hr *result.HostResult) {
			for _, p := range hr.Ports {
				results = append(results, sirius.Port{
					Number:   p.Port,
					Protocol: "tcp",
					State:    "open",
				})
			}
		},
	}

	naabuRunner, err := runner.NewRunner(&options)
	if err != nil {
		return sirius.Host{}, fmt.Errorf("failed to create naabu runner: %v", err)
	}
	defer naabuRunner.Close()

	// Use the provided context for cancellation support
	if err := naabuRunner.RunEnumeration(ctx); err != nil {
		// Check if it was a cancellation
		if ctx.Err() != nil {
			return sirius.Host{}, fmt.Errorf("naabu scan cancelled: %w", ctx.Err())
		}
		return sirius.Host{}, fmt.Errorf("naabu enumeration failed: %v", err)
	}

	if len(results) == 0 {
		return sirius.Host{}, ErrHostDown
	}

	return sirius.Host{
		IP:    target,
		Ports: results,
	}, nil
}
