package nse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

func TestCanonicalScriptID(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain id", "bar", "bar"},
		{"with extension", "acarsd-info.nse", "acarsd-info"},
		{"path with extension", "scripts/foo/bar.nse", "bar"},
		{"path no extension", "scripts/foo/bar", "bar"},
		{"wildcard preserved", "*", "*"},
		{"empty preserved", "", ""},
		{"upper extension preserved", "BAR.NSE", "BAR.NSE"},
		{"mixed case extension preserved", "Baz.Nse", "Baz.Nse"},
		{"trailing slash drops to empty segment", "scripts/", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := templates.CanonicalScriptID(tc.in)
			if got != tc.want {
				t.Errorf("templates.CanonicalScriptID(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// mockKVStore is an in-memory KVStore for verifying writes performed by the
// scanner sync path. It implements store.KVStore.
type mockKVStore struct {
	mu     sync.Mutex
	values map[string]string
}

func newMockKVStore() *mockKVStore {
	return &mockKVStore{values: make(map[string]string)}
}

func (m *mockKVStore) SetValue(_ context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.values[key] = value
	return nil
}

func (m *mockKVStore) SetValueWithTTL(_ context.Context, key, value string, _ int) error {
	return m.SetValue(context.Background(), key, value)
}

func (m *mockKVStore) GetValue(_ context.Context, key string) (store.ValkeyResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.values[key]
	if !ok {
		return store.ValkeyResponse{}, errors.New("valkey nil message: key '" + key + "' not found")
	}
	return store.ValkeyResponse{Message: store.ValkeyValue{Value: v}}, nil
}

func (m *mockKVStore) GetTTL(_ context.Context, _ string) (int, error)     { return -1, nil }
func (m *mockKVStore) SetExpire(_ context.Context, _ string, _ int) error  { return nil }
func (m *mockKVStore) DeleteValue(_ context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.values, key)
	return nil
}

func (m *mockKVStore) ListKeys(_ context.Context, pattern string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0)
	for k := range m.values {
		if pattern == "*" || pattern == "" || strings.HasPrefix(k, strings.TrimSuffix(pattern, "*")) {
			out = append(out, k)
		}
	}
	return out, nil
}

func (m *mockKVStore) Close() error { return nil }

// snapshot returns a copy of the current key/value store for assertions.
func (m *mockKVStore) snapshot() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]string, len(m.values))
	for k, v := range m.values {
		out[k] = v
	}
	return out
}

// writeRepoFixture builds a minimal git-style repository on disk with a
// manifest.json and matching script files so SyncManager.Sync() can run
// end-to-end against the local repository code path.
func writeRepoFixture(t *testing.T, dir, repoName string, scripts map[string]string) string {
	t.Helper()
	repoPath := filepath.Join(dir, repoName)
	scriptsDir := filepath.Join(repoPath, "scripts")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		t.Fatalf("mkdir scripts: %v", err)
	}
	// Initialize a git repo so isGitRepo() returns true.
	if err := os.MkdirAll(filepath.Join(repoPath, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	manifest := Manifest{
		Name:        repoName,
		Version:     "0.0.1",
		Description: "fixture",
		Scripts:     make(map[string]Script, len(scripts)),
	}

	for id, content := range scripts {
		filename := id
		if !strings.HasSuffix(filename, ".nse") {
			filename = filename + ".nse"
		}
		scriptPath := filepath.Join("scripts", filename)
		if err := os.WriteFile(filepath.Join(repoPath, scriptPath), []byte(content), 0o644); err != nil {
			t.Fatalf("write script %s: %v", id, err)
		}
		manifest.Scripts[id] = Script{
			Name:     strings.TrimSuffix(filename, ".nse"),
			Path:     scriptPath,
			Protocol: "*",
		}
	}

	manifestPath := filepath.Join(repoPath, ManifestFile)
	data, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := os.WriteFile(manifestPath, data, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return repoPath
}

// TestSync_WritesCanonicalKeys verifies that SyncManager.Sync writes
// nse:script:<canonical-id> keys (no .nse suffix) and that the persisted
// nse:manifest entries are also keyed by canonical id.
func TestSync_WritesCanonicalKeys(t *testing.T) {
	tmp := t.TempDir()

	// Build two fixtures with the same logical id expressed differently to
	// also exercise the canonicalization path inside updateValKeyManifest.
	// Manifest IDs mirror what sirius-nse ships today: <name>.nse keys with
	// matching scripts/<name>.nse paths. The "already-canonical" entry has
	// no extension to confirm extension-less ids round-trip unchanged.
	repoName := "sirius-nse"
	scripts := map[string]string{
		"acarsd-info.nse":   "-- acarsd lua",
		"bar-baz.nse":       "-- bar-baz lua",
		"already-canonical": "-- canonical lua",
	}
	repoPath := writeRepoFixture(t, tmp, repoName, scripts)

	// Sync builds per-repo paths via filepath.Join(BasePath, "..", repo.Name).
	// Setting BasePath to <tmp>/placeholder makes ".." == <tmp>, so the
	// per-repo lookup resolves to <tmp>/sirius-nse i.e. repoPath.
	mgr := NewRepoManager(filepath.Join(tmp, "placeholder"), "https://example.invalid/sirius-nse.git")
	_ = repoPath

	kv := newMockKVStore()

	// Pre-seed the repository manifest in the KV store so loadRepositories
	// short-circuits to the configured single-repo entry.
	repoList := RepositoryList{Repositories: []Repository{{Name: repoName, URL: "https://example.invalid/sirius-nse.git"}}}
	repoListJSON, err := json.Marshal(&repoList)
	if err != nil {
		t.Fatalf("marshal repo list: %v", err)
	}
	if err := kv.SetValue(context.Background(), ValKeyRepoManifestKey, string(repoListJSON)); err != nil {
		t.Fatalf("seed repo manifest: %v", err)
	}

	sm := NewSyncManager(mgr, kv)
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatalf("Sync returned error: %v", err)
	}

	snap := kv.snapshot()

	// Every nse:script:* key must be canonical (no .nse suffix, no path).
	for k := range snap {
		if !strings.HasPrefix(k, "nse:script:") {
			continue
		}
		id := strings.TrimPrefix(k, "nse:script:")
		if strings.Contains(id, "/") {
			t.Errorf("script key %q contains path segment after canonicalization", k)
		}
		if strings.HasSuffix(id, ".nse") {
			t.Errorf("script key %q retained legacy .nse suffix", k)
		}
	}

	// Manifest map keys must be canonical too.
	manifestRaw, ok := snap[ValKeyManifestKey]
	if !ok {
		t.Fatalf("manifest key %q missing from KV store", ValKeyManifestKey)
	}
	var stored Manifest
	if err := json.Unmarshal([]byte(manifestRaw), &stored); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	wantIDs := []string{"acarsd-info", "bar-baz", "already-canonical"}
	for _, id := range wantIDs {
		if _, found := stored.Scripts[id]; !found {
			t.Errorf("canonical id %q missing from persisted manifest; got keys %v", id, mapKeys(stored.Scripts))
		}
	}
	for id := range stored.Scripts {
		if strings.HasSuffix(id, ".nse") || strings.Contains(id, "/") {
			t.Errorf("manifest map key %q is not canonical", id)
		}
	}

	// Confirm the content keys exist for the canonical ids and contain the
	// expected script body wrapped in the ScriptContent envelope.
	for _, id := range wantIDs {
		key := "nse:script:" + id
		raw, found := snap[key]
		if !found {
			t.Errorf("expected KV key %q missing", key)
			continue
		}
		var content ScriptContent
		if err := json.Unmarshal([]byte(raw), &content); err != nil {
			t.Errorf("unmarshal %q: %v", key, err)
			continue
		}
		if content.Content == "" {
			t.Errorf("script content for %q is empty", id)
		}
	}
}

func mapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Compile-time check that mockKVStore satisfies the store.KVStore contract.
var _ store.KVStore = (*mockKVStore)(nil)

// avoid unused-import warnings if the test is trimmed.
var _ = fmt.Sprintf
