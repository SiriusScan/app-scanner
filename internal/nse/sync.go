package nse

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

// builtInRepositoryManifest stores the default repository manifest independent of process CWD.
//
//go:embed manifest.json
var builtInRepositoryManifest []byte

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
			slog.Info("no repository manifest found in ValKey, loading built-in manifest")
			builtInList, err := sm.loadBuiltInRepositoryList()
			if err != nil {
				return nil, fmt.Errorf("failed to load built-in repository list: %w", err)
			}

			// Initialize ValKey with built-in list
			manifestJSON, err := json.Marshal(builtInList)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal repository list: %w", err)
			}

			if err := sm.kvStore.SetValue(ctx, ValKeyRepoManifestKey, string(manifestJSON)); err != nil {
				return nil, fmt.Errorf("failed to initialize ValKey repository manifest: %w", err)
			}

			slog.Info("successfully initialized ValKey repository manifest")
			return builtInList, nil
		}
		return nil, fmt.Errorf("failed to get repository manifest from ValKey: %w", err)
	}

	// Parse ValKey response
	var repoList RepositoryList
	if err := json.Unmarshal([]byte(resp.Message.Value), &repoList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal repository manifest from ValKey: %w", err)
	}

	return &repoList, nil
}

func (sm *SyncManager) loadBuiltInRepositoryList() (*RepositoryList, error) {
	var repoList RepositoryList
	if err := json.Unmarshal(builtInRepositoryManifest, &repoList); err != nil {
		return nil, fmt.Errorf("failed to parse embedded repository list: %w", err)
	}
	return &repoList, nil
}

// Sync synchronizes the local NSE scripts with the ValKey store.
// Hard-cut behavior: the scanner only accepts a canonical local git repository state.
func (sm *SyncManager) Sync(ctx context.Context) error {
	// Load repositories from ValKey or initialize from built-in list
	repoList, err := sm.loadRepositories(ctx)
	if err != nil {
		return fmt.Errorf("failed to load repositories: %w", err)
	}

	// Process each repository
	for _, repo := range repoList.Repositories {
		slog.Info("processing repository", "repo", repo.Name)

		// Create a new repo manager for this repository
		repoPath := filepath.Join(sm.repoManager.BasePath, "..", repo.Name)
		repoManager := NewRepoManager(repoPath, repo.URL)
		manifestPath := filepath.Join(repoPath, ManifestFile)

		// Hard-cut: require canonical git repository layout at the configured path.
		if !repoManager.isGitRepo() {
			return fmt.Errorf("repository %q is not a git repository at %q", repo.Name, repoPath)
		}

		// Ensure a manifest exists in the canonical repository before continuing.
		if _, err := os.Stat(manifestPath); err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("repository manifest not found for %q at %q", repo.Name, manifestPath)
			}
			return fmt.Errorf("failed to check repository manifest for %q at %q: %w", repo.Name, manifestPath, err)
		}

		// Get local manifest from repository
		localManifest, err := repoManager.GetManifest()
		if err != nil {
			return fmt.Errorf("failed to get manifest from repository %q: %w", repo.Name, err)
		}

		// Persist local manifest as the canonical manifest in ValKey.
		if err := sm.updateValKeyManifest(ctx, localManifest); err != nil {
			return fmt.Errorf("failed to update ValKey manifest for %q: %w", repo.Name, err)
		}

		// Sync each script's content.
		var synced, failed int
		for id, script := range localManifest.Scripts {
			if err := sm.syncScriptContent(repoManager.BasePath, id, script); err != nil {
				failed++
				slog.Debug("failed to sync script", "script_id", id, "error", err)
				continue
			}
			synced++
		}
		slog.Info("script sync complete", "repo", repo.Name,
			"synced", synced, "failed", failed, "total", len(localManifest.Scripts))
	}

	return nil
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
func (sm *SyncManager) syncScriptContent(repoBasePath, id string, script Script) error {
	// Canonicalize the script ID for all KV operations so the on-disk
	// manifest entry (which may include a .nse extension) maps to the same
	// key shape the UI looks up. Source of truth lives in the shared
	// go-api/sirius/store/templates package.
	canonicalID := templates.CanonicalScriptID(id)

	// Get script content from ValKey first (highest priority)
	globalContent, err := sm.getScriptContent(context.Background(), canonicalID)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		return fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	// If we have global content, use it
	if globalContent != "" {
		// Extract the actual script content from potentially JSON-wrapped content
		scriptContent := extractScriptContent(globalContent)

		// Write global content to local file
		scriptPath := filepath.Join(repoBasePath, script.Path)
		if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
			return fmt.Errorf("failed to create script directory: %w", err)
		}

		if err := os.WriteFile(scriptPath, []byte(scriptContent), 0644); err != nil {
			return fmt.Errorf("failed to write script file: %w", err)
		}
		return nil
	}

	// If no global content, read from local file
	scriptPath := filepath.Join(repoBasePath, script.Path)
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
	if err := sm.updateScriptContent(context.Background(), canonicalID, newContent); err != nil {
		return fmt.Errorf("failed to update script content in ValKey: %w", err)
	}

	return nil
}

// updateValKeyManifest updates the manifest in ValKey store. Script map keys
// are rewritten to their canonical form (no .nse extension, no path prefix)
// so the UI's canonicalized lookups resolve to the same identifiers the
// scanner uses for nse:script:* content keys. Each entry's Path field is
// preserved unchanged because it represents the on-disk file location.
func (sm *SyncManager) updateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	canonicalManifest := *manifest
	if len(manifest.Scripts) > 0 {
		canonicalScripts := make(map[string]Script, len(manifest.Scripts))
		for id, script := range manifest.Scripts {
			canonicalID := templates.CanonicalScriptID(id)
			if existing, ok := canonicalScripts[canonicalID]; ok {
				slog.Warn("duplicate canonical script id in manifest; keeping first entry",
					"canonical_id", canonicalID,
					"kept_path", existing.Path,
					"discarded_path", script.Path,
				)
				continue
			}
			canonicalScripts[canonicalID] = script
		}
		canonicalManifest.Scripts = canonicalScripts
	}

	// First marshal the manifest to JSON
	manifestJSON, err := json.Marshal(&canonicalManifest)
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
	resp, err := sm.kvStore.GetValue(ctx, templates.NseScriptKey(scriptName))
	if err != nil {
		if strings.Contains(err.Error(), "valkey nil message") {
			// Script content doesn't exist in ValKey yet
			slog.Debug("no content found in ValKey for script", "script_id", scriptName)
			return "", nil
		}
		return "", fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	return resp.Message.Value, nil
}

// updateScriptContent updates a script's content in the KV store
func (sm *SyncManager) updateScriptContent(ctx context.Context, scriptID string, content *ScriptContent) error {
	// Translate to the shared envelope (identical wire shape) and let
	// the templates helper handle key construction + canonicalization.
	rec := &templates.NseScriptRecord{
		Content: content.Content,
		Metadata: templates.NseScriptMeta{
			Author:      content.Metadata.Author,
			Tags:        content.Metadata.Tags,
			Description: content.Metadata.Description,
		},
		UpdatedAt: content.UpdatedAt,
	}
	if err := templates.WriteNseScript(ctx, sm.kvStore, scriptID, rec); err != nil {
		return fmt.Errorf("failed to set script content in ValKey: %w", err)
	}
	return nil
}

// UpdateScriptFromUI updates a script's content and metadata from the UI.
// The incoming scriptID may be the canonical id ("foo") or the legacy
// extension form ("foo.nse"); both resolve to the same Valkey key.
func (sm *SyncManager) UpdateScriptFromUI(ctx context.Context, scriptID string, content *ScriptContent) error {
	canonicalID := templates.CanonicalScriptID(scriptID)

	// Validate that the script exists in the manifest. Look up by canonical
	// id, and fall back to the raw id to tolerate manifests that haven't
	// been re-synced into canonical form yet.
	manifest, err := sm.repoManager.GetManifest()
	if err != nil {
		return fmt.Errorf("failed to get manifest: %w", err)
	}

	script, exists := manifest.Scripts[canonicalID]
	if !exists {
		script, exists = manifest.Scripts[scriptID]
	}
	if !exists {
		return fmt.Errorf("script %s not found in manifest", scriptID)
	}

	// Update the script content in ValKey
	if err := sm.updateScriptContent(ctx, canonicalID, content); err != nil {
		return fmt.Errorf("failed to update script content: %w", err)
	}

	// Create script directory and write the updated content to the local file
	scriptPath := filepath.Join(sm.repoManager.BasePath, script.Path)
	if err := os.MkdirAll(filepath.Dir(scriptPath), 0755); err != nil {
		return fmt.Errorf("failed to create script directory: %w", err)
	}

	if err := os.WriteFile(scriptPath, []byte(content.Content), 0644); err != nil {
		return fmt.Errorf("failed to write script file: %w", err)
	}

	return nil
}

// SyncScriptContent synchronizes a single script's content
func (sm *SyncManager) SyncScriptContent(id string, script Script) error {
	return sm.syncScriptContent(sm.repoManager.BasePath, id, script)
}

// UpdateValKeyManifest updates the manifest in ValKey store
func (sm *SyncManager) UpdateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	return sm.updateValKeyManifest(ctx, manifest)
}
