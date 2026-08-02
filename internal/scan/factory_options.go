package scan

// CreateToolWithOptions builds a ScanStrategy using the provided options without
// mutating the shared factory options (safe for concurrent jobs).
func CreateToolWithOptions(opts ScanOptions, toolType string) ScanStrategy {
	f := &ScanToolFactory{currentOptions: opts}
	return f.CreateTool(toolType)
}

// CreateFingerprintToolWithOptions builds a FingerprintStrategy using the
// provided options without mutating the shared factory options.
func CreateFingerprintToolWithOptions(opts ScanOptions) FingerprintStrategy {
	f := &ScanToolFactory{currentOptions: opts}
	return f.CreateFingerprintTool()
}
