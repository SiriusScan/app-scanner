package nse

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

func catalogFixture(t *testing.T, repos map[string]map[string]string) (*SyncManager, *mockKVStore, string) {
	t.Helper()
	dir := t.TempDir()
	list := RepositoryList{Repositories: []Repository{}}
	for name, scripts := range repos {
		writeRepoFixture(t, dir, name, scripts)
		list.Repositories = append(list.Repositories, Repository{Name: name})
	}
	kv := newMockKVStore()
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	kv.SetValue(context.Background(), ValKeyRepoManifestKey, string(data))
	return NewSyncManager(NewRepoManager(filepath.Join(dir, "placeholder"), ""), kv), kv, dir
}

func decodeCatalog(t *testing.T, kv *mockKVStore) (map[string]json.RawMessage, map[string]json.RawMessage, map[string]bool) {
	t.Helper()
	value := kv.snapshot()[ValKeyManifestKey]
	root, entries, _, deleted, err := readCatalog(&value)
	if err != nil {
		t.Fatal(err)
	}
	return root, entries, deleted
}

func TestCatalogPreservesCustomEntriesAndEveryRepository(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one.nse": "-- one"}, "beta": {"two": "-- two"}})
	original := `{"name":"UI catalog","extension":{"keep":1},"scripts":{"custom":{"name":"custom","path":"scripts/custom/custom.nse","protocol":"http","extra":{"keep":2},"source":{"type":"custom"}},"legacy":{"name":"legacy","path":"legacy.nse","protocol":"*","future":true}}}`
	custom := `{"content":"-- custom","custom":true,"metadata":{"future":true}}`
	kv.SetValue(context.Background(), ValKeyManifestKey, original)
	kv.SetValue(context.Background(), templates.NseScriptKey("custom"), custom)
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, entries, _ := decodeCatalog(t, kv)
	if len(entries) != 4 {
		t.Fatalf("catalog lost entries: %s", kv.snapshot()[ValKeyManifestKey])
	}
	if string(root["extension"]) != "{\"keep\":1}" || string(root["name"]) != `"UI catalog"` {
		t.Fatalf("root metadata lost: %v", root)
	}
	var old Manifest
	json.Unmarshal([]byte(original), &old)
	if !strings.Contains(string(entries["custom"]), `"extra":{"keep":2}`) || !strings.Contains(string(entries["legacy"]), `"future":true`) {
		t.Fatalf("custom metadata lost: %v", entries)
	}
	for id, repo := range map[string]string{"one": "alpha", "two": "beta"} {
		source, err := entrySource(entries[id])
		if err != nil || source.Repository != repo || source.Type != "repository" {
			t.Fatalf("ownership %s: %+v %v", id, source, err)
		}
	}
	if kv.snapshot()[templates.NseScriptKey("custom")] != custom {
		t.Fatal("custom content changed")
	}
}

func TestCatalogPrunesOnlyOwnedEntriesAndRetainsOverrides(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one", "removed": "-- remove"}})
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	root, entries, _ := decodeCatalog(t, kv)
	entries["legacy"] = json.RawMessage(`{"name":"legacy","path":"legacy.nse","protocol":"*"}`)
	root["scripts"], _ = json.Marshal(entries)
	data, _ := json.Marshal(root)
	kv.SetValue(context.Background(), ValKeyManifestKey, string(data))
	writeRepoFixture(t, dir, "alpha", map[string]string{"one": "-- one"})
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, _ = decodeCatalog(t, kv)
	if _, exists := entries["removed"]; exists {
		t.Fatal("stale owned index entry survived")
	}
	if _, exists := entries["legacy"]; !exists {
		t.Fatal("unclassified legacy entry was pruned")
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("removed")]; !exists {
		t.Fatal("possible user override was deleted")
	}
	kv.SetValue(context.Background(), ValKeyRepoManifestKey, `{"repositories":[]}`)
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, _ = decodeCatalog(t, kv)
	if len(entries) != 1 || entries["legacy"] == nil {
		t.Fatalf("removed repo pruning = %v", entries)
	}
}

func TestCatalogHonorsDeletionMarkers(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"gone": "-- original file", "keep": "-- keep"}})
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{},"deletedScripts":{"gone":true},"future":1}`)
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, deleted := decodeCatalog(t, kv)
	if entries["gone"] != nil || !deleted["gone"] || entries["keep"] == nil {
		t.Fatalf("deletion resurrected: %v %v", entries, deleted)
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("gone")]; exists {
		t.Fatal("deleted content resurrected")
	}
	body, _ := os.ReadFile(filepath.Join(dir, "alpha/scripts/gone.nse"))
	if string(body) != "-- original file" {
		t.Fatal("deleted catalog entry changed local file")
	}
}

func TestCatalogDuplicateIDsAndInvalidRepositoriesFailBeforeWrites(t *testing.T) {
	for name, repos := range map[string]map[string]map[string]string{
		"two repositories":        {"alpha": {"same.nse": "-- alpha"}, "beta": {"same": "-- beta"}},
		"same repository aliases": {"alpha": {"same.nse": "-- alpha", "same": "-- alias"}},
	} {
		t.Run(name, func(t *testing.T) {
			sm, kv, _ := catalogFixture(t, repos)
			before := kv.snapshot()
			if err := sm.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("expected duplicate failure: %v", err)
			}
			if !reflect.DeepEqual(before, kv.snapshot()) {
				t.Fatal("failure partially published catalog")
			}
		})
	}
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}, "beta": {"two": "-- two"}})
	os.WriteFile(filepath.Join(dir, "beta/manifest.json"), []byte(`{"scripts":`), 0644)
	before := kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil {
		t.Fatal("invalid repo accepted")
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("partial repository catalog published")
	}
}

func TestCatalogCorruptManifestFailsClosed(t *testing.T) {
	for _, raw := range []string{"", `null`, `{"scripts":[]}`, `{"scripts":{"one":null}}`, `{"scripts":{"one":{},"one.nse":{}}}`, `{"scripts":{},"deletedScripts":{"one":false}}`, `{"scripts":{"one":{}},"deletedScripts":{"one":true}}`} {
		t.Run(raw, func(t *testing.T) {
			sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
			kv.SetValue(context.Background(), ValKeyManifestKey, raw)
			before := kv.snapshot()
			if err := sm.Sync(context.Background()); err == nil {
				t.Fatal("corrupt manifest accepted")
			}
			if !reflect.DeepEqual(before, kv.snapshot()) {
				t.Fatal("corrupt manifest replaced")
			}
		})
	}
}

type interleavingCatalogStore struct {
	*mockKVStore
	beforeCommit func()
	attempts     int
}

func (s *interleavingCatalogStore) CompareAndSwapValues(ctx context.Context, expected map[string]*string, updates map[string]*string) (bool, error) {
	s.attempts++
	if s.beforeCommit != nil {
		action := s.beforeCommit
		s.beforeCommit = nil
		action()
	}
	return s.mockKVStore.CompareAndSwapValues(ctx, expected, updates)
}

func TestCatalogConcurrentCreateIsNotLost(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
	raced := &interleavingCatalogStore{mockKVStore: kv}
	raced.beforeCommit = func() {
		kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"custom":{"name":"mine","path":"custom.nse","protocol":"http","source":{"type":"custom"}}}}`)
		kv.SetValue(context.Background(), templates.NseScriptKey("custom"), `{"content":"-- mine"}`)
	}
	sm.kvStore = raced
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, _ := decodeCatalog(t, kv)
	if entries["custom"] == nil || entries["one"] == nil || raced.attempts != 2 {
		t.Fatalf("lost concurrent create or no retry: %v %d", entries, raced.attempts)
	}
}

func TestCatalogConcurrentDeleteIsNotResurrected(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"gone": "-- gone"}})
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"gone":{"name":"gone","path":"scripts/gone.nse","protocol":"*","source":{"type":"repository","repository":"alpha"}}}}`)
	raced := &interleavingCatalogStore{mockKVStore: kv}
	raced.beforeCommit = func() {
		kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{},"deletedScripts":{"gone":true}}`)
		kv.DeleteValue(context.Background(), templates.NseScriptKey("gone"))
	}
	sm.kvStore = raced
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, deleted := decodeCatalog(t, kv)
	if entries["gone"] != nil || !deleted["gone"] {
		t.Fatal("delete was lost")
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("gone")]; exists {
		t.Fatal("deleted content resurrected")
	}
}

func TestCatalogConcurrentEditWinsOverSeed(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- local"}})
	raced := &interleavingCatalogStore{mockKVStore: kv}
	raced.beforeCommit = func() {
		kv.SetValue(context.Background(), templates.NseScriptKey("one"), `{"content":"-- edited","unknown":true}`)
	}
	sm.kvStore = raced
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if kv.snapshot()[templates.NseScriptKey("one")] != `{"content":"-- edited","unknown":true}` {
		t.Fatal("concurrent body was overwritten")
	}
	body, _ := os.ReadFile(filepath.Join(dir, "alpha/scripts/one.nse"))
	if string(body) != "-- edited" {
		t.Fatalf("local body stale: %q", body)
	}
}

func TestCatalogConcurrentRepositoryRemovalWins(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
	raced := &interleavingCatalogStore{mockKVStore: kv}
	raced.beforeCommit = func() { kv.SetValue(context.Background(), ValKeyRepoManifestKey, `{"repositories":[]}`) }
	sm.kvStore = raced
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, entries, _ := decodeCatalog(t, kv)
	if len(entries) != 0 {
		t.Fatal("removed repository was republished")
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("one")]; exists {
		t.Fatal("removed repository content was seeded")
	}
}

func TestCatalogDoesNotRepairMissingCustomBodyFromRepository(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- unrelated repo body"}})
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"one":{"name":"my script","source":{"type":"custom"}}}}`)
	if err := sm.Sync(context.Background()); err == nil {
		t.Fatal("missing custom body silently repaired")
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("one")]; exists {
		t.Fatal("custom body replaced from repo")
	}
}

func TestCatalogRejectsUnsupportedAtomicStore(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
	sm.kvStore = struct{ store.KVStore }{kv}
	before := kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil {
		t.Fatal("unsupported atomic store accepted")
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("fallback wrote non-atomically")
	}
}

func TestCatalogGuardedHelpersRespectDeletion(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"gone": "-- gone"}})
	sm.repoManager.BasePath = filepath.Join(dir, "alpha")
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{},"deletedScripts":{"gone":true}}`)
	if err := sm.createScriptContent(context.Background(), "gone", &ScriptContent{Content: "-- body"}); err == nil {
		t.Fatal("helper resurrected body")
	}
	if err := sm.UpdateValKeyManifest(context.Background(), &Manifest{Name: "alpha", Scripts: map[string]Script{"gone": {Name: "gone"}}}); err != nil {
		t.Fatal(err)
	}
	_, entries, deleted := decodeCatalog(t, kv)
	if entries["gone"] != nil || !deleted["gone"] {
		t.Fatal("helper lost tombstone")
	}
	if _, exists := kv.snapshot()[templates.NseScriptKey("gone")]; exists {
		t.Fatal("helper resurrected content")
	}
	if err := sm.UpdateValKeyManifest(context.Background(), &Manifest{Name: "empty", Scripts: map[string]Script{}}); err == nil {
		t.Fatal("unsafe reset accepted")
	}
}

func TestCatalogCancelledDoesNotWrite(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
	before := kv.snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := sm.Sync(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not propagated: %v", err)
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("cancelled sync wrote state")
	}
}

func TestCatalogMigratesLegacyBodyWithoutLosingOverride(t *testing.T) {
	for _, legacyEntry := range []bool{false, true} {
		t.Run(map[bool]string{true: "legacy custom entry", false: "legacy body before catalog"}[legacyEntry], func(t *testing.T) {
			sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one.nse": "-- repository default"}})
			if legacyEntry {
				kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"one.nse":{"name":"custom legacy","source":{"type":"custom"}}}}`)
			}
			original := `{"content":"-- legacy override","extra":{"keep":true}}`
			kv.SetValue(context.Background(), ValKeyScriptPrefix+"one.nse", original)
			if err := sm.Sync(context.Background()); err != nil {
				t.Fatal(err)
			}
			snap := kv.snapshot()
			if snap[templates.NseScriptKey("one")] != original {
				t.Fatal("legacy override overwritten")
			}
			if _, exists := snap[ValKeyScriptPrefix+"one.nse"]; exists {
				t.Fatal("legacy body was not migrated")
			}
			body, _ := os.ReadFile(filepath.Join(dir, "alpha/scripts/one.nse"))
			if string(body) != "-- legacy override" {
				t.Fatalf("wrong body %q", body)
			}
		})
	}
}

func TestCatalogRejectsAmbiguousBodies(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one.nse": "-- default"}})
	kv.SetValue(context.Background(), templates.NseScriptKey("one"), `{"content":"-- canonical"}`)
	kv.SetValue(context.Background(), ValKeyScriptPrefix+"one.nse", `{"content":"-- legacy","custom":true,"metadata":{"future":true}}`)
	before := kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("expected ambiguity error: %v", err)
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("ambiguous body overwritten")
	}
}

func TestCatalogRejectsSymlinkScriptPaths(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- default"}})
	target := filepath.Join(t.TempDir(), "outside.nse")
	os.WriteFile(target, []byte("-- outside"), 0644)
	scriptPath := filepath.Join(dir, "alpha/scripts/one.nse")
	os.Remove(scriptPath)
	os.Symlink(target, scriptPath)
	before := kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection: %v", err)
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("unsafe script published")
	}
	body, _ := os.ReadFile(target)
	if string(body) != "-- outside" {
		t.Fatal("symlink target modified")
	}
}

func TestCatalogRejectsNonIdempotentIDs(t *testing.T) {
	sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {"one.nse.nse": "-- unsafe identity"}})
	before := kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil {
		t.Fatal("non-idempotent repository ID accepted")
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("ambiguous identity mutated store")
	}
	sm, kv, _ = catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- one"}})
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"bad.nse.nse":{}}}`)
	before = kv.snapshot()
	if err := sm.Sync(context.Background()); err == nil {
		t.Fatal("non-idempotent global ID accepted")
	}
	if !reflect.DeepEqual(before, kv.snapshot()) {
		t.Fatal("invalid global identity mutated store")
	}
}

func TestCatalogDirectUpdateMigratesLegacyBody(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one.nse": "-- local"}})
	sm.repoManager.BasePath = filepath.Join(dir, "alpha")
	kv.SetValue(context.Background(), ValKeyManifestKey, `{"scripts":{"one.nse":{"name":"one"}}}`)
	kv.SetValue(context.Background(), ValKeyScriptPrefix+"one.nse", `{"content":"-- legacy","custom":true,"metadata":{"future":true}}`)
	if err := sm.UpdateScriptFromUI(context.Background(), "one.nse", &ScriptContent{Content: "-- edited"}); err != nil {
		t.Fatal(err)
	}
	snap := kv.snapshot()
	if _, exists := snap[ValKeyScriptPrefix+"one.nse"]; exists {
		t.Fatal("duplicate legacy body remains")
	}
	var body ScriptContent
	json.Unmarshal([]byte(snap[templates.NseScriptKey("one")]), &body)
	if body.Content != "-- edited" {
		t.Fatal("update lost")
	}
	if !strings.Contains(snap[templates.NseScriptKey("one")], `"custom":true`) || !strings.Contains(snap[templates.NseScriptKey("one")], `"future":true`) {
		t.Fatal("direct update lost unknown fields")
	}

	if err := sm.Sync(context.Background()); err != nil {
		t.Fatalf("update poisoned next sync: %v", err)
	}
}

func TestCatalogMergeUsesConfiguredOwnerNotDisplayName(t *testing.T) {
	sm, kv, dir := catalogFixture(t, map[string]map[string]string{"alpha": {"one": "-- local"}})
	sm.repoManager.BasePath = filepath.Join(dir, "alpha")
	manifest := &Manifest{Name: "Repository Display Name", Scripts: map[string]Script{"one": {Name: "one", Path: "scripts/one.nse", Protocol: "*"}}}
	if err := sm.UpdateValKeyManifest(context.Background(), manifest); err != nil {
		t.Fatal(err)
	}
	_, entries, _ := decodeCatalog(t, kv)
	source, err := entrySource(entries["one"])
	if err != nil || source.Repository != "alpha" {
		t.Fatalf("wrong provenance %+v / %v", source, err)
	}
	if err := sm.Sync(context.Background()); err != nil {
		t.Fatalf("merge poisoned sync: %v", err)
	}
}

func TestCatalogRejectsIDsUnsupportedByUI(t *testing.T) {
	for _, id := range []string{"*", " bad ", "bad\\name", "bad:name"} {
		t.Run(id, func(t *testing.T) {
			sm, kv, _ := catalogFixture(t, map[string]map[string]string{"alpha": {id: "-- script"}})
			before := kv.snapshot()
			if err := sm.Sync(context.Background()); err == nil {
				t.Fatal("scanner published ID the UI rejects")
			}
			if !reflect.DeepEqual(before, kv.snapshot()) {
				t.Fatal("invalid ID changed catalog")
			}
		})
	}
}
