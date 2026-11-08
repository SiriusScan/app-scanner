package nse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
)

var errNotFound = errors.New("key not found")

// inMemoryKVStore is an interface-complete KVStore implementation for tests.
type inMemoryKVStore struct {
	data map[string]string
	ttl  map[string]int
}

func newInMemoryKVStore() *inMemoryKVStore {
	return &inMemoryKVStore{
		data: make(map[string]string),
		ttl:  make(map[string]int),
	}
}

func (m *inMemoryKVStore) GetValue(ctx context.Context, key string) (store.ValkeyResponse, error) {
	if val, ok := m.data[key]; ok {
		return store.ValkeyResponse{
			Message: store.ValkeyValue{Value: val},
			Type:    "string",
		}, nil
	}
	return store.ValkeyResponse{}, errNotFound
}

func (m *inMemoryKVStore) SetValue(ctx context.Context, key string, value string) error {
	m.data[key] = value
	return nil
}

func (m *inMemoryKVStore) SetValueWithTTL(ctx context.Context, key, value string, ttlSeconds int) error {
	m.data[key] = value
	m.ttl[key] = ttlSeconds
	return nil
}

func (m *inMemoryKVStore) GetTTL(ctx context.Context, key string) (int, error) {
	if ttl, ok := m.ttl[key]; ok {
		return ttl, nil
	}
	return -1, nil
}

func (m *inMemoryKVStore) SetExpire(ctx context.Context, key string, ttlSeconds int) error {
	if _, ok := m.data[key]; !ok {
		return errNotFound
	}
	m.ttl[key] = ttlSeconds
	return nil
}

func (m *inMemoryKVStore) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	keys := make([]string, 0)
	if pattern == "*" {
		for key := range m.data {
			keys = append(keys, key)
		}
		return keys, nil
	}

	prefix := strings.TrimSuffix(pattern, "*")
	for key := range m.data {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *inMemoryKVStore) DeleteValue(ctx context.Context, key string) error {
	delete(m.data, key)
	delete(m.ttl, key)
	return nil
}

func (m *inMemoryKVStore) Close() error {
	return nil
}

func TestNSESyncAndUpdate(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "nse-test-*")
	if err != nil {
		t.Fatalf("failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoRoot := filepath.Join(tmpDir, "sirius-nse")
	scriptDir := filepath.Join(repoRoot, "scripts")
	gitDir := filepath.Join(repoRoot, ".git")
	if err := os.MkdirAll(scriptDir, 0755); err != nil {
		t.Fatalf("failed to create script directory: %v", err)
	}
	if err := os.MkdirAll(gitDir, 0755); err != nil {
		t.Fatalf("failed to create .git directory: %v", err)
	}

	scriptID := "vulners"
	scriptPath := "scripts/vulners.nse"
	initialScript := "-- initial test script content"
	if err := os.WriteFile(filepath.Join(repoRoot, scriptPath), []byte(initialScript), 0644); err != nil {
		t.Fatalf("failed to write test script: %v", err)
	}

	manifest := Manifest{
		Name:        "sirius-nse",
		Version:     "0.1.0",
		Description: "test manifest",
		Scripts: map[string]Script{
			scriptID: {
				Name:     "vulners",
				Path:     scriptPath,
				Protocol: "*",
			},
		},
	}
	manifestData, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("failed to marshal manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(repoRoot, ManifestFile), manifestData, 0644); err != nil {
		t.Fatalf("failed to write manifest file: %v", err)
	}

	builtInRepoList := RepositoryList{
		Repositories: []Repository{
			{
				Name: "sirius-nse",
				URL:  "https://github.com/SiriusScan/sirius-nse.git",
			},
		},
	}
	repoListData, err := json.Marshal(builtInRepoList)
	if err != nil {
		t.Fatalf("failed to marshal repository list: %v", err)
	}

	kvStore := newInMemoryKVStore()
	ctx := context.Background()
	if err := kvStore.SetValue(ctx, ValKeyRepoManifestKey, string(repoListData)); err != nil {
		t.Fatalf("failed to preload repository list: %v", err)
	}

	repoManager := NewRepoManager(repoRoot, "https://github.com/SiriusScan/sirius-nse.git")
	syncManager := NewSyncManager(repoManager, kvStore)

	t.Run("Sync writes canonical manifest and script content", func(t *testing.T) {
		if err := syncManager.Sync(ctx); err != nil {
			t.Fatalf("sync failed: %v", err)
		}

		manifestResp, err := kvStore.GetValue(ctx, ValKeyManifestKey)
		if err != nil {
			t.Fatalf("failed to read manifest from kv store: %v", err)
		}

		var persisted Manifest
		if err := json.Unmarshal([]byte(manifestResp.Message.Value), &persisted); err != nil {
			t.Fatalf("failed to unmarshal persisted manifest: %v", err)
		}

		if persisted.Name != manifest.Name {
			t.Fatalf("unexpected manifest name: got %q want %q", persisted.Name, manifest.Name)
		}

		contentResp, err := kvStore.GetValue(ctx, ValKeyScriptPrefix+scriptID)
		if err != nil {
			t.Fatalf("failed to read script content from kv store: %v", err)
		}

		var persistedContent ScriptContent
		if err := json.Unmarshal([]byte(contentResp.Message.Value), &persistedContent); err != nil {
			t.Fatalf("failed to unmarshal persisted script content: %v", err)
		}

		if persistedContent.Content != initialScript {
			t.Fatalf("unexpected script content: got %q want %q", persistedContent.Content, initialScript)
		}
		if persistedContent.Metadata.Author != "System" {
			t.Fatalf("unexpected default author: got %q want %q", persistedContent.Metadata.Author, "System")
		}
	})

	t.Run("UpdateScriptFromUI updates kv store and local file", func(t *testing.T) {
		updated := &ScriptContent{
			Content: "-- updated test content",
			Metadata: Metadata{
				Author:      "Test Author",
				Tags:        []string{"test", "updated"},
				Description: "Updated description",
			},
			UpdatedAt: time.Now().Unix(),
		}

		if err := syncManager.UpdateScriptFromUI(ctx, scriptID, updated); err != nil {
			t.Fatalf("update script from ui failed: %v", err)
		}

		contentResp, err := kvStore.GetValue(ctx, ValKeyScriptPrefix+scriptID)
		if err != nil {
			t.Fatalf("failed to read updated script content from kv store: %v", err)
		}

		var persistedContent ScriptContent
		if err := json.Unmarshal([]byte(contentResp.Message.Value), &persistedContent); err != nil {
			t.Fatalf("failed to unmarshal updated script content: %v", err)
		}

		if persistedContent.Content != updated.Content {
			t.Fatalf("unexpected updated script content: got %q want %q", persistedContent.Content, updated.Content)
		}
		if persistedContent.Metadata.Author != updated.Metadata.Author {
			t.Fatalf("unexpected updated author: got %q want %q", persistedContent.Metadata.Author, updated.Metadata.Author)
		}

		localContent, err := os.ReadFile(filepath.Join(repoRoot, scriptPath))
		if err != nil {
			t.Fatalf("failed to read updated local script: %v", err)
		}

		if string(localContent) != updated.Content {
			t.Fatalf("unexpected local script content: got %q want %q", string(localContent), updated.Content)
		}
	})
}

func (m *inMemoryKVStore) CompareAndSwapValues(ctx context.Context, expected map[string]*string, updates map[string]*string) (bool, error) {

	if err := ctx.Err(); err != nil {
		return false, err
	}
	for key, want := range expected {
		actual, exists := m.data[key]
		if want == nil && exists || want != nil && (!exists || *want != actual) {
			return false, nil
		}
	}
	for key, value := range updates {
		if _, ok := expected[key]; !ok {
			return false, fmt.Errorf("unguarded update")
		}
		if value == nil {
			delete(m.data, key)
		} else {
			m.data[key] = *value
		}
	}
	return true, nil
}
