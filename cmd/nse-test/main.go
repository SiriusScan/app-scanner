package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	// Base directory for NSE scripts in Docker
	dockerNSEBase = "/opt/sirius/nse"
)

// Legacy directories to clean up (incorrect locations)
var legacyDirs = []string{
	"/opt/sirius-nse",
}

func ensureDirectory(path string) error {
	fmt.Printf("🔧 Ensuring directory exists: %s\n", path)
	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", path, err)
	}
	return nil
}

func cleanupLegacy() {
	fmt.Printf("🧹 Cleaning up legacy NSE directories...\n")
	for _, dir := range legacyDirs {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Printf("⚠️  Warning: Failed to clean up legacy directory %s: %v\n", dir, err)
		} else {
			fmt.Printf("✨ Cleaned up legacy directory: %s\n", dir)
		}
	}
}

func loadRepositoryList() (*nse.RepositoryList, error) {
	data, err := os.ReadFile("internal/nse/manifest.json")
	if err != nil {
		return nil, fmt.Errorf("failed to read repository list: %w", err)
	}

	var repoList nse.RepositoryList
	if err := json.Unmarshal(data, &repoList); err != nil {
		return nil, fmt.Errorf("failed to parse repository list: %w", err)
	}

	return &repoList, nil
}

func main() {
	fmt.Println("🚀 Starting NSE Test Program")
	fmt.Printf("📌 Docker NSE Base Path: %s\n", dockerNSEBase)

	// Clean up legacy directories
	fmt.Println("🧹 Cleaning up legacy NSE directories...")
	cleanupLegacy()
	fmt.Println("🧹 Cleaned up main NSE directory for fresh test")

	// Ensure NSE base directory exists
	fmt.Printf("🔧 Ensuring directory exists: %s\n", dockerNSEBase)
	if err := os.MkdirAll(dockerNSEBase, 0755); err != nil {
		log.Fatalf("Failed to create NSE base directory: %v", err)
	}

	// Initialize ValKey store
	fmt.Println("🔌 Connecting to ValKey at sirius-valkey:6379...")
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("❌ Failed to initialize ValKey store: %v\n💡 Tip: Check if ValKey service is running and accessible", err)
	}
	defer kvStore.Close()

	// Test ValKey connection
	fmt.Println("🔍 Testing ValKey connection with key: nse-test-connection")
	ctx := context.Background()
	testKey := "nse-test-connection"
	testValue := "test-value"

	// Try to set a test value
	if err := kvStore.SetValue(ctx, testKey, testValue); err != nil {
		log.Fatalf("❌ Failed to set test value in ValKey: %v\n💡 Tip: Check if ValKey service is running and accessible", err)
	}

	// Try to get the test value back
	resp, err := kvStore.GetValue(ctx, testKey)
	if err != nil {
		log.Fatalf("❌ Failed to get test value from ValKey: %v\n💡 Tip: Check ValKey connectivity", err)
	}

	fmt.Printf("✅ ValKey test successful - got response: %+v\n", resp)

	// Load repository list
	repoList, err := loadRepositoryList()
	if err != nil {
		log.Fatalf("Failed to load repository list: %v", err)
	}
	fmt.Printf("📋 Loaded repository list with %d repositories\n\n", len(repoList.Repositories))

	// Process each repository
	for _, repo := range repoList.Repositories {
		fmt.Printf("🔄 Processing repository: %s\n", repo.Name)
		repoPath := filepath.Join(dockerNSEBase, repo.Name)
		repoManager := nse.NewRepoManager(repoPath, repo.URL)
		fmt.Printf("🔧 Created RepoManager for path: %s\n", repoPath)

		syncManager := nse.NewSyncManager(repoManager, kvStore)
		fmt.Println("🔄 Created SyncManager")

		// Set up repository
		fmt.Println("\n🔍 Setting up repository...")
		if err := repoManager.EnsureRepo(); err != nil {
			log.Fatalf("Failed to set up repository: %v", err)
		}
		fmt.Println("✅ Repository setup successful")

		// Load and display manifest
		fmt.Println("\n🔍 Loading manifest...")
		manifest, err := repoManager.GetManifest()
		if err != nil {
			log.Fatalf("Failed to get manifest: %v", err)
		}

		fmt.Printf("📄 Loaded manifest from repository:\n")
		fmt.Printf("   Name: %s\n", manifest.Name)
		fmt.Printf("   Version: %s\n", manifest.Version)
		fmt.Printf("   Description: %s\n", manifest.Description)
		fmt.Printf("   Scripts: %d\n\n", len(manifest.Scripts))

		fmt.Println("   Scripts details:")
		for id, script := range manifest.Scripts {
			fmt.Printf("   - %s:\n", id)
			fmt.Printf("     Path: %s\n", script.Path)
			fmt.Printf("     Protocol: %s\n", script.Protocol)
		}

		// Try to sync
		fmt.Println("\n🔍 Syncing manifests...")
		if err := syncManager.Sync(context.Background()); err != nil {
			fmt.Printf("❌ Failed to sync: %v\n", err)
			fmt.Println("💡 Tip: Check ValKey connectivity and script permissions")
		} else {
			fmt.Println("✅ Sync successful")
		}
	}

	fmt.Println("\n✨ Test program completed")
	fmt.Println("🧹 Cleaning up legacy NSE directories...")
	cleanupLegacy()
}
