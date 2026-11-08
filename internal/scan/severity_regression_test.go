package scan

import (
	"math"
	"testing"
)

func TestCalculateSeverityCVSSBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		score    float64
		expected string
	}{
		{"zero", 0, "informational"},
		{"positive fraction", 0.1, "low"},
		{"low midpoint", 1.5, "low"},
		{"low upper boundary", 3.9, "low"},
		{"medium lower boundary", 4.0, "medium"},
		{"medium midpoint", 5.5, "medium"},
		{"medium upper boundary", 6.9, "medium"},
		{"high lower boundary", 7.0, "high"},
		{"high midpoint", 8.5, "high"},
		{"high upper boundary", 8.9, "high"},
		{"critical lower boundary", 9.0, "critical"},
		{"critical midpoint", 9.5, "critical"},
		{"maximum", 10.0, "critical"},
		{"negative", -0.1, "informational"},
		{"above maximum", 10.1, "informational"},
		{"NaN", math.NaN(), "informational"},
		{"positive infinity", math.Inf(1), "informational"},
		{"negative infinity", math.Inf(-1), "informational"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if actual := calculateSeverity(tt.score); actual != tt.expected {
				t.Errorf("calculateSeverity(%v) = %q; want %q", tt.score, actual, tt.expected)
			}
		})
	}
}
