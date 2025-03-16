package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	dockerNSEBase = "/opt/sirius/nse"
)

func main() {
	fmt.Println("🔄 NSE Manifest Reset Tool")

	// Parse command line flags
	force := flag.Bool("force", false, "Force complete reset of ValKey manifest")
	flag.Parse()

	// Initialize ValKey store
	fmt.Println("🔌 Connecting to ValKey...")
	kvStore, err := store.NewValkeyStore()
	if err != nil {
		log.Fatalf("❌ Failed to initialize ValKey store: %v", err)
	}
	defer kvStore.Close()

	ctx := context.Background()

	// If force flag is used, delete the manifest key
	if *force {
		fmt.Println("🗑️ Skipping existing ValKey manifests...")
		// We can't delete directly, so we'll overwrite with empty values
		emptyManifest := &nse.Manifest{
			Name:        "empty",
			Version:     "0.0.0",
			Description: "Empty manifest for reset",
			Scripts:     make(map[string]nse.Script),
		}

		// Create sync manager
		repoPath := filepath.Join(dockerNSEBase, "sirius-nse")
		repoManager := nse.NewRepoManager(repoPath, nse.NSERepoURL)
		syncManager := nse.NewSyncManager(repoManager, kvStore)

		// Reset the manifests with empty ones
		if err := syncManager.UpdateValKeyManifest(ctx, emptyManifest); err != nil {
			fmt.Printf("⚠️ Warning: Failed to reset manifest: %v\n", err)
		} else {
			fmt.Println("✅ Existing manifest reset")
		}
	}

	// Load repository list from local manifest
	fmt.Println("📂 Loading repository list...")
	data, err := os.ReadFile("internal/nse/manifest.json")
	if err != nil {
		log.Fatalf("❌ Failed to read repository list: %v", err)
	}

	var repoList nse.RepositoryList
	if err := json.Unmarshal(data, &repoList); err != nil {
		log.Fatalf("❌ Failed to parse repository list: %v", err)
	}

	fmt.Printf("📋 Found %d repositories\n", len(repoList.Repositories))

	// Process each repository
	for _, repo := range repoList.Repositories {
		fmt.Printf("\n🔄 Processing repository: %s\n", repo.Name)
		repoPath := filepath.Join(dockerNSEBase, repo.Name)

		// Create repo manager
		repoManager := nse.NewRepoManager(repoPath, repo.URL)

		// Ensure repo exists and is up to date
		fmt.Println("🔄 Updating repository...")
		if err := repoManager.EnsureRepo(); err != nil {
			log.Fatalf("❌ Failed to ensure repository: %v", err)
		}

		// Read manifest from repository
		fmt.Println("📄 Loading manifest from repository...")
		manifest, err := repoManager.GetManifest()
		if err != nil {
			log.Fatalf("❌ Failed to read manifest: %v", err)
		}

		fmt.Printf("📋 Found %d scripts in repository manifest\n", len(manifest.Scripts))
		for id := range manifest.Scripts {
			fmt.Printf("  - %s\n", id)
		}

		// Create sync manager
		syncManager := nse.NewSyncManager(repoManager, kvStore)

		// Force update ValKey with repository manifest
		fmt.Println("🔄 Updating ValKey manifest...")
		if err := syncManager.UpdateValKeyManifest(ctx, manifest); err != nil {
			log.Fatalf("❌ Failed to update ValKey manifest: %v", err)
		}

		fmt.Println("✅ ValKey manifest updated successfully")

		// Sync all scripts
		fmt.Println("🔄 Syncing scripts...")
		for id, script := range manifest.Scripts {
			fmt.Printf("  - Syncing %s...\n", id)
			if err := syncManager.SyncScriptContent(id, script); err != nil {
				fmt.Printf("⚠️ Warning: Failed to sync script %s: %v\n", id, err)
			}
		}
	}

	fmt.Println("\n✅ Reset completed successfully")
	fmt.Println("🔍 Run the nse-test command to verify the changes")
}
