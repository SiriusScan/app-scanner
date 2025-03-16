package nse

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

var errNotFound = errors.New("key not found")

// mockKVStore implements store.KVStore for testing
type mockKVStore struct {
	data map[string]string
}

func (m *mockKVStore) GetValue(ctx context.Context, key string) (store.ValkeyResponse, error) {
	if val, ok := m.data[key]; ok {
		return store.ValkeyResponse{
			Message: store.ValkeyValue{Value: val},
			Type:    "string",
		}, nil
	}
	return store.ValkeyResponse{}, errNotFound
}

func (m *mockKVStore) SetValue(ctx context.Context, key string, value string) error {
	m.data[key] = value
	return nil
}

func (m *mockKVStore) Close() error {
	return nil
}

// mockGitOps implements GitOperations for testing
type mockGitOps struct {
	cloneCalled bool
	fetchCalled bool
	resetCalled bool
	shouldFail  bool
}

func (m *mockGitOps) Clone(repoURL, targetPath string) error {
	m.cloneCalled = true
	if m.shouldFail {
		return errors.New("mock clone failure")
	}
	return nil
}

func (m *mockGitOps) Fetch(repoPath string) error {
	m.fetchCalled = true
	if m.shouldFail {
		return errors.New("mock fetch failure")
	}
	return nil
}

func (m *mockGitOps) Reset(repoPath string) error {
	m.resetCalled = true
	if m.shouldFail {
		return errors.New("mock reset failure")
	}
	return nil
}

func TestNSEIntegration(t *testing.T) {
	// Create temporary directories for testing
	tmpDir, err := os.MkdirTemp("", "nse-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a test manifest file
	manifestContent := RepositoryList{
		Repositories: []Repository{
			{
				Name: "sirius-nse",
				URL:  "https://github.com/SiriusScan/sirius-nse.git",
			},
		},
	}
	manifestData, err := json.Marshal(manifestContent)
	if err != nil {
		t.Fatalf("Failed to marshal manifest: %v", err)
	}
	manifestPath := filepath.Join(tmpDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		t.Fatalf("Failed to write manifest file: %v", err)
	}

	// Create mock KV store
	kvStore := &mockKVStore{
		data: make(map[string]string),
	}

	// Create mock Git operations
	mockGit := &mockGitOps{}

	// Create repo manager with mock Git ops
	repoManager := NewRepoManager(filepath.Join(tmpDir, "sirius-nse"), manifestContent.Repositories[0].URL)
	repoManager.SetGitOps(mockGit)

	// Create sync manager
	syncManager := NewSyncManager(repoManager, kvStore)

	// Test repository setup
	t.Run("Repository Setup", func(t *testing.T) {
		if err := repoManager.EnsureRepo(); err != nil {
			t.Errorf("Failed to ensure repository: %v", err)
		}

		if !mockGit.cloneCalled {
			t.Error("Clone was not called")
		}
	})

	// Test repository update
	t.Run("Repository Update", func(t *testing.T) {
		// Reset mock
		mockGit.cloneCalled = false
		mockGit.fetchCalled = false
		mockGit.resetCalled = false

		// Create .git directory to simulate existing repo
		gitDir := filepath.Join(tmpDir, "sirius-nse", ".git")
		if err := os.MkdirAll(gitDir, 0755); err != nil {
			t.Fatalf("Failed to create .git directory: %v", err)
		}

		if err := repoManager.EnsureRepo(); err != nil {
			t.Errorf("Failed to update repository: %v", err)
		}

		if mockGit.cloneCalled {
			t.Error("Clone was called for existing repository")
		}
		if !mockGit.fetchCalled {
			t.Error("Fetch was not called")
		}
		if !mockGit.resetCalled {
			t.Error("Reset was not called")
		}
	})

	// Test error handling
	t.Run("Error Handling", func(t *testing.T) {
		// Reset mock and set it to fail
		mockGit.shouldFail = true
		mockGit.cloneCalled = false
		mockGit.fetchCalled = false
		mockGit.resetCalled = false

		if err := repoManager.EnsureRepo(); err == nil {
			t.Error("Expected error, got nil")
		}
	})

	// Test ValKey synchronization
	t.Run("ValKey Sync", func(t *testing.T) {
		ctx := context.Background()

		// Sync should work even when ValKey is empty
		if err := syncManager.Sync(ctx); err != nil {
			t.Fatalf("Failed initial sync: %v", err)
		}

		// Verify manifest was stored in ValKey
		resp, err := kvStore.GetValue(ctx, ValKeyManifestKey)
		if err != nil {
			t.Fatalf("Failed to get manifest from ValKey: %v", err)
		}

		var storedManifest Manifest
		if err := json.Unmarshal([]byte(resp.Message.Value), &storedManifest); err != nil {
			t.Fatalf("Failed to unmarshal stored manifest: %v", err)
		}

		if storedManifest.Name != "sirius-nse" {
			t.Errorf("Expected stored manifest name 'sirius-nse', got %s", storedManifest.Name)
		}

		// Verify script content was stored
		manifest, _ := repoManager.GetManifest()
		for id, script := range manifest.Scripts {
			resp, err := kvStore.GetValue(ctx, ValKeyScriptPrefix+id)
			if err != nil {
				t.Errorf("Failed to get script content for %s: %v", id, err)
				continue
			}

			var content ScriptContent
			if err := json.Unmarshal([]byte(resp.Message.Value), &content); err != nil {
				t.Errorf("Failed to unmarshal script content for %s: %v", id, err)
				continue
			}

			// Verify metadata was set correctly
			if content.Metadata.Author != "Unknown" {
				t.Errorf("Expected default author 'Unknown', got %s", content.Metadata.Author)
			}
			if !contains(content.Metadata.Tags, script.Protocol) {
				t.Errorf("Expected protocol %s in tags, got %v", script.Protocol, content.Metadata.Tags)
			}
		}
	})

	// Test script content updates
	t.Run("Script Content Updates", func(t *testing.T) {
		ctx := context.Background()
		manifest, _ := repoManager.GetManifest()
		scriptID := "vulners"
		script, exists := manifest.Scripts[scriptID]
		if !exists {
			t.Fatal("Vulners script not found in manifest")
		}

		// Update script content via UI
		newContent := &ScriptContent{
			Content: "-- Updated test content",
			Metadata: Metadata{
				Author:      "Test Author",
				Tags:        []string{"test", "updated"},
				Description: "Updated description",
			},
			UpdatedAt: time.Now().Unix(),
		}

		if err := syncManager.UpdateScriptFromUI(ctx, scriptID, newContent); err != nil {
			t.Fatalf("Failed to update script content: %v", err)
		}

		// Verify content was updated in ValKey
		resp, err := kvStore.GetValue(ctx, ValKeyScriptPrefix+scriptID)
		if err != nil {
			t.Fatalf("Failed to get updated script content: %v", err)
		}

		var storedContent ScriptContent
		if err := json.Unmarshal([]byte(resp.Message.Value), &storedContent); err != nil {
			t.Fatalf("Failed to unmarshal updated script content: %v", err)
		}

		if storedContent.Content != newContent.Content {
			t.Error("Script content was not updated correctly")
		}
		if storedContent.Metadata.Author != newContent.Metadata.Author {
			t.Error("Script metadata was not updated correctly")
		}

		// Verify content was updated in local file
		localPath := filepath.Join(NSEBasePath, script.Path)
		localContent, err := os.ReadFile(localPath)
		if err != nil {
			t.Fatalf("Failed to read local script file: %v", err)
		}

		if string(localContent) != newContent.Content {
			t.Error("Local script file was not updated correctly")
		}
	})
}

// Helper function to check if a slice contains a string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}
