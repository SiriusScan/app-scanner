package nse

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

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
		if missingCatalogKey(err) {
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

			updater, err := atomicUpdater(sm.kvStore)
			if err != nil {
				return nil, err
			}
			value := string(manifestJSON)
			created, err := updater.CompareAndSwapValues(ctx,
				map[string]*string{ValKeyRepoManifestKey: nil},
				map[string]*string{ValKeyRepoManifestKey: &value})
			if err != nil {
				return nil, fmt.Errorf("failed to initialize ValKey repository manifest: %w", err)
			}
			if !created {
				return sm.loadRepositories(ctx)
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

// Sync publishes one coherent catalog across all configured repositories. It
// never replaces UI-owned or unclassified legacy entries, and honors deletions.
func (sm *SyncManager) Sync(ctx context.Context) error {
	return sm.syncCatalog(ctx)
}

// extractScriptContent accepts legacy raw Lua or a JSON script envelope.
// Reject corrupt envelopes instead of treating their JSON as executable Lua.
func extractScriptContent(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", fmt.Errorf("script content is empty or whitespace-only")
	}

	// Objects and arrays that fail to parse are still malformed records, not
	// raw Lua. Valid JSON scalars are not script bodies either.
	if trimmed[0] == '{' || trimmed[0] == '[' || json.Valid([]byte(trimmed)) {
		var envelope struct {
			Content *string `json:"content"`
		}
		if err := json.Unmarshal([]byte(trimmed), &envelope); err != nil {
			return "", fmt.Errorf("invalid script content envelope: %w", err)
		}
		if envelope.Content == nil || strings.TrimSpace(*envelope.Content) == "" {
			return "", fmt.Errorf("script content envelope must contain a non-empty content string")
		}
		return *envelope.Content, nil
	}

	// Preserve formatting of valid legacy scripts and extracted bodies.
	return content, nil
}

// syncScriptContent synchronizes a single script's content
func (sm *SyncManager) syncScriptContent(repoBasePath, id string, script Script) error {
	return sm.syncOneScriptContent(context.Background(), repoBasePath, id, script)
}

// updateValKeyManifest safely merges one repository without replacing entries
// owned by the UI or other repositories. Sync is preferred because it publishes
// all configured repositories and their initial content in one transaction.
func (sm *SyncManager) updateValKeyManifest(ctx context.Context, manifest *Manifest) error {
	return sm.mergeRepositoryManifest(ctx, manifest)
}

// getScriptContent retrieves a script's content from the KV store
func (sm *SyncManager) getScriptContent(ctx context.Context, scriptName string) (string, error) {
	resp, err := sm.kvStore.GetValue(ctx, templates.NseScriptKey(scriptName))
	if err != nil {
		if missingCatalogKey(err) {
			// Script content doesn't exist in ValKey yet
			slog.Debug("no content found in ValKey for script", "script_id", scriptName)
			return "", nil
		}
		return "", fmt.Errorf("failed to get script content from ValKey: %w", err)
	}

	// A present but empty value is corrupt, not an absent record. Do not
	// replace it with local content or overwrite a known-good local script.
	if strings.TrimSpace(resp.Message.Value) == "" {
		return "", fmt.Errorf("script %q has empty or whitespace-only ValKey content", scriptName)
	}
	return resp.Message.Value, nil
}

// updateScriptContent updates a script's content in the KV store
func (sm *SyncManager) updateScriptContent(ctx context.Context, scriptID string, content *ScriptContent) error {
	return sm.writeGuardedContent(ctx, scriptID, content, false)
}

func (sm *SyncManager) createScriptContent(ctx context.Context, scriptID string, content *ScriptContent) error {
	return sm.writeGuardedContent(ctx, scriptID, content, true)
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

	scriptPath, err := safeScriptPath(sm.repoManager.BasePath, script.Path)
	if err != nil {
		return err
	}
	// Update the script content in ValKey
	if err := sm.updateScriptContent(ctx, canonicalID, content); err != nil {
		return fmt.Errorf("failed to update script content: %w", err)
	}

	if err := writeScriptFile(scriptPath, content.Content); err != nil {
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
