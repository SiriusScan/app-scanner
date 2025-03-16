package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
)

const (
	dockerNSEBase = "/opt/sirius/nse"
)

// ScriptContent is a simplified version of the ValKey content structure
type ScriptContent struct {
	Content string `json:"content"`
}

// fixScript checks if a script file is in JSON format and extracts the Lua content
func fixScript(path string) error {
	fmt.Printf("Checking script: %s\n", path)

	// Read the file
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	content := string(data)
	trimmedContent := strings.TrimSpace(content)

	// Check if content looks like JSON (starts with '{')
	if len(trimmedContent) > 0 && trimmedContent[0] == '{' {
		fmt.Printf("📦 File appears to be in JSON format: %s\n", path)

		// Try to parse as JSON
		var scriptContent ScriptContent
		err := json.Unmarshal(data, &scriptContent)
		if err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}

		if scriptContent.Content == "" {
			return fmt.Errorf("no content field in JSON")
		}

		// Write the content back to the file
		fmt.Printf("✅ Fixing script: %s\n", path)
		err = os.WriteFile(path, []byte(scriptContent.Content), 0644)
		if err != nil {
			return fmt.Errorf("failed to write fixed content: %w", err)
		}

		return nil
	}

	// Not JSON, no need to fix
	fmt.Printf("✅ Script already in correct format: %s\n", path)
	return nil
}

func fixAllScripts(baseDir string) error {
	// Find all .nse files
	var scriptPaths []string
	err := filepath.Walk(baseDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".nse") {
			scriptPaths = append(scriptPaths, path)
		}

		return nil
	})

	if err != nil {
		return fmt.Errorf("failed to walk directory: %w", err)
	}

	// Fix each script
	for _, path := range scriptPaths {
		if err := fixScript(path); err != nil {
			fmt.Printf("⚠️ Error fixing script %s: %v\n", path, err)
		}
	}

	return nil
}

func main() {
	fmt.Println("🔧 NSE Script Format Fixer")

	repoDir := filepath.Join(dockerNSEBase, "sirius-nse", "scripts")
	fmt.Printf("🔍 Scanning directory: %s\n", repoDir)

	// Check if directory exists
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		log.Fatalf("❌ Directory does not exist: %s", repoDir)
	}

	// Fix all scripts
	if err := fixAllScripts(repoDir); err != nil {
		log.Fatalf("❌ Failed to fix scripts: %v", err)
	}

	fmt.Println("✅ All scripts checked and fixed if needed")
}
