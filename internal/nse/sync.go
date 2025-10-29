package nse

// Modify to use the new manifest.json file and sync with the repo and valkey

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	scriptContentPrefix = "nse:script"
)

// SyncManager handles synchronization between local NSE scripts and ValKey store
type SyncManager struct {
	repoManager *RepoManager
	kvStore     store.KVStore
}

// NewSyncManager creates a new SyncManager instance
func NewSyncManager(repoManager *RepoManager, kvStore store.KVStore) *SyncManager {
	return &SyncManager{
		repoManager: repoManager,
		kvStore:     kvStore,
	}
}

// loadRepositories loads the repository list, prioritizing ValKey over local manifest
func (sm *SyncManager) loadRepositories(ctx context.Context) (*RepositoryList, error) {
	// Try to get repository list from ValKey first
	resp, err := sm.kvStore.GetValue(ctx, ValKeyRepoManifestKey)
	if err != nil {
		// Check for key not found errors (valkey nil message or "not found")
		if strings.Contains(err.Error(), "valkey nil message") || strings.Contains(err.Error(), "not found") {
			// Load built-in repository list
			log.Printf("No repository manifest found in ValKey, loading built-in manifest")
			builtInList, err := LoadRepositoryList("internal/nse/manifest.json")
			if err != nil {
				return nil, fmt.Errorf("failed to load built-in repository list: %v", err)
			}

			// Initialize ValKey with built-in list
			manifestJSON, err := json.Marshal(builtInList)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal repository list: %v", err)
			}

			if err := sm.kvStore.SetValue(ctx, ValKeyRepoManifestKey, string(manifestJSON)); err != nil {
				return nil, fmt.Errorf("failed to initialize ValKey repository manifest: %v", err)
			}

			log.Printf("Successfully initialized ValKey repository manifest")
			return builtInList, nil
		}
		return nil, fmt.Errorf("failed to get repository manifest from ValKey: %v", err)
	}

	// Parse ValKey response
	var repoList RepositoryList
	if err := json.Unmarshal([]byte(resp.Message.Value), &repoList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal repository manifest from ValKey: %v", err)
	}

	return &repoList, nil
}

// Sync synchronizes the local NSE scripts with the ValKey store
func (sm *SyncManager) Sync(ctx context.Context) error {
	// Load repositories from ValKey or initialize from built-in list
	repoList, err := sm.loadRepositories(ctx)
	if err != nil {
		return fmt.Errorf("failed to load repositories: %v", err)
	}

	// Process each repository
	for _, repo := range repoList.Repositories {
		log.Printf("Processing repository: %s", repo.Name)

		// Create a new repo manager for this repository
		repoPath := filepath.Join(sm.repoManager.BasePath, "..", repo.Name)
		repoManager := NewRepoManager(repoPath, repo.URL)

		// Check if repository already exists and has a manifest (development/volume mount scenario)
		if repoManager.isGitRepo() {
			log.Printf("Repository %s already exists, using local copy", repo.Name)
		} else {
			// Ensure repository is cloned (production scenario)
			if err := repoManager.EnsureRepo(); err != nil {
				log.Printf("Warning: failed to ensure repository %s: %v", repo.Name, err)
				continue
			}
		}

		// Get local manifest from repository
		localManifest, err := repoManager.GetManifest()
		if err != nil {
			log.Printf("Warning: failed to get manifest from repository %s: %v", repo.Name, err)
			continue
		}

		// Get ValKey manifest (global source of truth)
		globalManifest, err := sm.getValKeyManifest(ctx)
		if err != nil {
			if err.Error() == "key not found" {
				// If no global manifest exists, initialize it with local manifest
				fmt.Printf("📝 No manifest found in ValKey, initializing with local manifest: %s\n", localManifest.Name)
				if err := sm.updateValKeyManifest(ctx, localManifest); err != nil {
					log.Printf("Warning: failed to initialize ValKey manifest for %s: %v", repo.Name, err)
					continue
				}
				fmt.Println("✅ Successfully initialized ValKey manifest")
				globalManifest = localManifest
			} else {
				log.Printf("Warning: failed to get ValKey manifest for %s: %v", repo.Name, err)
				continue
			}
		}

		// Merge manifests with global taking precedence
		mergedManifest := sm.mergeManifests(globalManifest, localManifest)

		// Update ValKey with merged manifest
		if err := sm.updateValKeyManifest(ctx, mergedManifest); err != nil {
			log.Printf("Warning: failed to update ValKey manifest for %s: %v", repo.Name, err)
			continue
		}

		// Sync each script's content
		for id, script := range mergedManifest.Scripts {
			fmt.Printf("🔄 Syncing script: %s\n", id)
			if err := sm.syncScriptContent(id, script); err != nil {
				log.Printf("Warning: failed to sync script %s: %v", id, err)
				continue
			}
			fmt.Printf("✅ Successfully synced script: %s\n", id)
		}
	}

	return nil
}

// mergeManifests merges two manifests with global taking precedence
// But ensures new scripts from local are added to the merged result
func (sm *SyncManager) mergeManifests(global, local *Manifest) *Manifest {
	fmt.Printf("📋 Merging manifests: Global (%d scripts) + Local (%d scripts)\n",
		len(global.Scripts), len(local.Scripts))

	merged := &Manifest{
		Name:        global.Name,        // Use global name
		Version:     global.Version,     // Use global version
		Description: global.Description, // Use global description
		Scripts:     make(map[string]Script),
	}

	// First, add all local scripts
	for id, script := range local.Scripts {
		merged.Scripts[id] = script
		if _, exists := global.Scripts[id]; !exists {
			fmt.Printf("📦 Found new script in repository: %s\n", id)
		}
	}

	// Then overlay global scripts (taking precedence for existing scripts)
	for id, script := range global.Scripts {
		merged.Scripts[id] = script
	}

	fmt.Printf("📋 Merged manifest now contains %d scripts\n", len(merged.Scripts))
	return merged
}

// extractScriptContent ensures we're storing proper Lua script content, not JSON
func extractScriptContent(content string) string {
	// Check if content looks like JSON (starts with '{')
	if strings.TrimSpace(content)[0] == '{' {
		// Try to parse as JSON
		var jsonContent struct {
			Content string `json:"content"`
		}
		err := json.Unmarshal([]byte(content), &jsonContent)
		if err == nil && jsonContent.Content != "" {
			// Found valid content field in JSON
			return jsonContent.Content
		}
	}
	// Return as-is if not JSON or couldn't parse
	return content
}

// syncScriptContent synchronizes a single script's content
func (sm *SyncManager) syncScriptContent(id string, script Script) error {
	// Get script content from ValKey first (highest priority)
	globalContent, err := sm.getScriptContent(context.Background(), id)
	if err != nil && err.Error() != "key not found" {
		return fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	// If we have global content, use it
	if globalContent != "" {
		// Extract the actual script content from potentially JSON-wrapped content
		scriptContent := extractScriptContent(globalContent)

		// Write global content to local file
		scriptPath := filepath.Join(sm.repoManager.BasePath, script.Path)
		if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
			return fmt.Errorf("failed to create script directory: %w", err)
		}

		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
			return fmt.Errorf("failed to write script file: %w", err)
		}
		return nil
	}

	// If no global content, read from local file
	scriptPath := filepath.Join(sm.repoManager.BasePath, script.Path)
	localContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read local script: %w", err)
	}

	// Create new script content
	newContent := &ScriptContent{
		Content: string(localContent),
		Metadata: Metadata{
			Author:      "System",
			Tags:        []string{script.Protocol},
			Description: fmt.Sprintf("NSE script for %s protocol", script.Protocol),
		},
		UpdatedAt: time.Now().Unix(),
	}

	// Update ValKey with local content
	if err := sm.updateScriptContent(context.Background(), id, newContent); err != nil {
		return fmt.Errorf("failed to update script content in ValKey: %w", err)
	}

	return nil
}

// getValKeyManifest retrieves the manifest from ValKey store
func (sm *SyncManager) getValKeyManifest(ctx context.Context) (*Manifest, error) {
	resp, err := sm.kvStore.GetValue(ctx, ValKeyManifestKey)
	if err != nil {
		if strings.Contains(err.Error(), "valkey nil message") {
			// Initialize empty manifest if it doesn't exist
			log.Printf("No manifest found in ValKey, initializing empty manifest")
			emptyManifest := &Manifest{
				Scripts: make(map[string]Script),
			}
			err = sm.updateValKeyManifest(ctx, emptyManifest)
			if err != nil {
				return nil, fmt.Errorf("failed to initialize empty manifest: %v", err)
			}
			return emptyManifest, nil
		}
		return nil, fmt.Errorf("failed to get manifest from ValKey: %v", err)
	}

	var manifest Manifest
	err = json.Unmarshal([]byte(resp.Message.Value), &manifest)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal manifest: %v", err)
	}

	if manifest.Scripts == nil {
		manifest.Scripts = make(map[string]Script)
	}

	return &manifest, nil
}

// updateValKeyManifest updates the manifest in ValKey store
func (sm *SyncManager) updateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	// First marshal the manifest to JSON
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// Store the JSON string directly
	if err := sm.kvStore.SetValue(ctx, ValKeyManifestKey, string(manifestJSON)); err != nil {
		return fmt.Errorf("failed to update ValKey manifest: %w", err)
	}

	return nil
}

// getScriptContent retrieves a script's content from the KV store
func (sm *SyncManager) getScriptContent(ctx context.Context, scriptName string) (string, error) {
	resp, err := sm.kvStore.GetValue(ctx, fmt.Sprintf("%s:%s", scriptContentPrefix, scriptName))
	if err != nil {
		if strings.Contains(err.Error(), "valkey nil message") {
			// Script content doesn't exist in ValKey yet
			log.Printf("No content found in ValKey for script %s", scriptName)
			return "", nil
		}
		return "", fmt.Errorf("failed to get script content from ValKey: %v", err)
	}

	return resp.Message.Value, nil
}

// updateScriptContent updates a script's content in the KV store
func (sm *SyncManager) updateScriptContent(ctx context.Context, scriptID string, content *ScriptContent) error {
	key := ValKeyScriptPrefix + scriptID

	// First marshal the content to JSON
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return fmt.Errorf("failed to marshal script content: %w", err)
	}

	// Store the JSON string directly
	if err := sm.kvStore.SetValue(ctx, key, string(contentJSON)); err != nil {
		return fmt.Errorf("failed to set script content in ValKey: %w", err)
	}

	return nil
}

// UpdateScriptFromUI updates a script's content and metadata from the UI
func (sm *SyncManager) UpdateScriptFromUI(ctx context.Context, scriptID string, content *ScriptContent) error {
	// Validate that the script exists in the manifest
	manifest, err := sm.repoManager.GetManifest()
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	script, exists := manifest.Scripts[scriptID]
	if !exists {
		return fmt.Errorf("script %s not found in manifest", scriptID)
	}

	// Update the script content in ValKey
	if err := sm.updateScriptContent(ctx, scriptID, content); err != nil {
		return fmt.Errorf("failed to update script content: %w", err)
	}

	// Create script directory and write the updated content to the local file
	scriptPath := filepath.Join(NSEBasePath, script.Path)
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		return fmt.Errorf("failed to create script directory: %w", err)
	}

	if err := os.WriteFile(scriptPath, []byte(content.Content), 0644); err != nil {
		return fmt.Errorf("failed to write script file: %w", err)
	}

	return nil
}

func (sm *SyncManager) syncScript(ctx context.Context, scriptName string, script Script) error {
	// Get script content from ValKey
	globalContent, err := sm.getScriptContent(ctx, scriptName)
	if err != nil {
		return fmt.Errorf("failed to get script content from ValKey: %v", err)
	}

	// If script doesn't exist in ValKey, read from local and update ValKey
	if globalContent == "" {
		localContent, err := os.ReadFile(filepath.Join(sm.repoManager.BasePath, script.Path))
		if err != nil {
			return fmt.Errorf("failed to read local script: %v", err)
		}

		err = sm.updateScriptContent(ctx, scriptName, &ScriptContent{Content: string(localContent)})
		if err != nil {
			return fmt.Errorf("failed to update script content in ValKey: %v", err)
		}
		return nil
	}

	// Update local script with ValKey content
	err = os.WriteFile(filepath.Join(sm.repoManager.BasePath, script.Path), []byte(globalContent), 0644)
	if err != nil {
		return fmt.Errorf("failed to write script content: %v", err)
	}

	return nil
}

// SyncScriptContent synchronizes a single script's content
func (sm *SyncManager) SyncScriptContent(id string, script Script) error {
	return sm.syncScriptContent(id, script)
}

// UpdateValKeyManifest updates the manifest in ValKey store
func (sm *SyncManager) UpdateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	return sm.updateValKeyManifest(ctx, manifest)
}
