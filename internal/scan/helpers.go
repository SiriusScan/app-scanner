package scan

// calculateSeverity maps a risk score to a severity string.
func calculateSeverity(score float64) string {
	switch {
	case score < 1.0:
		return "informational"
	case score < 3.0:
		return "low"
	case score < 5.0:
		return "medium"
	case score < 7.0:
		return "high"
	case score < 9.0:
		return "critical"
	default:
		return "informational"
	}
}