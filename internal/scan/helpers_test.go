package scan

import "testing"

// TestCalculateSeverity tests the calculateSeverity helper function.
func TestCalculateSeverity(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{0.5, "informational"},
		{1.5, "low"},
		{3.5, "medium"},
		{5.5, "high"},
		{8.5, "critical"},
		{9.5, "informational"}, // default falls back to informational
	}

	for _, tt := range tests {
		actual := calculateSeverity(tt.score)
		if actual != tt.expected {
			t.Errorf("calculateSeverity(%f) = %s; expected %s", tt.score, actual, tt.expected)
		}
	}
}