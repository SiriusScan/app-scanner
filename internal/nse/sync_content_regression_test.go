package nse

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

func TestSyncScriptContentRejectsInvalidRecords(t *testing.T) {
	records := map[string]string{
		"empty":               "",
		"spaces":              "   ",
		"line breaks":         "\t\r\n",
		"unicode whitespace":  "\u2003\u00a0",
		"empty envelope":      `{"content":"","metadata":{"author":"test"}}`,
		"whitespace envelope": `{"content":" \t\r\n\u2003"}`,
		"missing content":     `{"metadata":{"author":"test"}}`,
		"null content":        `{"content":null}`,
		"wrong content type":  `{"content":42}`,
		"malformed envelope":  `{"content":"-- script"`,
		"trailing data":       `{"content":"-- script"} garbage`,
		"array":               `[{"content":"-- script"}]`,
		"null":                `null`,
		"JSON string":         `"-- script"`,
	}
	for name, record := range records {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			script := Script{Path: "scripts/example.nse", Protocol: "http"}
			scriptPath := filepath.Join(dir, script.Path)
			original := "-- known good script\naction = function() return 'original' end\n"
			if err := os.MkdirAll(filepath.Dir(scriptPath), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(scriptPath, []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			kv := newMockKVStore()
			key := templates.NseScriptKey("example")
			if err := kv.SetValue(context.Background(), key, record); err != nil {
				t.Fatal(err)
			}
			sm := NewSyncManager(NewRepoManager(dir, ""), kv)
			if err := sm.syncScriptContent(dir, "example.nse", script); err == nil {
				t.Error("expected invalid record error")
			}
			got, err := os.ReadFile(scriptPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != original {
				t.Errorf("existing script changed to %q", got)
			}
			if got := kv.snapshot()[key]; got != record {
				t.Errorf("invalid record was overwritten: %q", got)
			}
		})
	}
}

func TestSyncScriptContentPreservesValidBodies(t *testing.T) {
	body := "\n-- original formatting\naction = function() return 'ok' end\n\t"
	envelope, err := json.Marshal(ScriptContent{Content: body})
	if err != nil {
		t.Fatal(err)
	}
	for name, record := range map[string]string{"raw Lua": body, "JSON envelope": " \n" + string(envelope)} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			script := Script{Path: "scripts/example.nse"}
			kv := newMockKVStore()
			key := templates.NseScriptKey("example")
			if err := kv.SetValue(context.Background(), key, record); err != nil {
				t.Fatal(err)
			}
			sm := NewSyncManager(NewRepoManager(dir, ""), kv)
			if err := sm.syncScriptContent(dir, "scripts/example.nse", script); err != nil {
				t.Fatal(err)
			}
			got, err := os.ReadFile(filepath.Join(dir, script.Path))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != body {
				t.Errorf("script formatting changed: got %q, want %q", got, body)
			}
			if got := kv.snapshot()[key]; got != record {
				t.Errorf("stored record changed: %q", got)
			}
		})
	}
}

func TestSyncScriptContentInvalidRecordDoesNotCreateFile(t *testing.T) {
	dir := t.TempDir()
	kv := newMockKVStore()
	if err := kv.SetValue(context.Background(), templates.NseScriptKey("bad"), `{"content":""}`); err != nil {
		t.Fatal(err)
	}
	sm := NewSyncManager(NewRepoManager(dir, ""), kv)
	if err := sm.syncScriptContent(dir, "bad", Script{Path: "scripts/bad.nse"}); err == nil {
		t.Fatal("expected validation error")
	}
	if _, err := os.Stat(filepath.Join(dir, "scripts")); !os.IsNotExist(err) {
		t.Errorf("invalid record created script directory: %v", err)
	}
}

func TestSyncReportsInvalidRecordsAndContinues(t *testing.T) {
	dir := t.TempDir()
	repoName := "fixture-nse"
	repoPath := writeRepoFixture(t, dir, repoName, map[string]string{"bad": "-- keep good local version", "good": "-- old version"})
	kv := newMockKVStore()
	repos, err := json.Marshal(RepositoryList{Repositories: []Repository{{Name: repoName}}})
	if err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		ValKeyRepoManifestKey:          string(repos),
		templates.NseScriptKey("bad"):  `{"content":""}`,
		templates.NseScriptKey("good"): `{"content":"-- updated version"}`,
	} {
		if err := kv.SetValue(context.Background(), key, value); err != nil {
			t.Fatal(err)
		}
	}
	sm := NewSyncManager(NewRepoManager(filepath.Join(dir, "placeholder"), ""), kv)
	err = sm.Sync(context.Background())
	if err == nil || !strings.Contains(err.Error(), "bad") || !strings.Contains(err.Error(), repoName) {
		t.Errorf("expected error identifying failed repository and script, got %v", err)
	}
	for id, want := range map[string]string{"bad": "-- keep good local version", "good": "-- updated version"} {
		got, err := os.ReadFile(filepath.Join(repoPath, "scripts", id+".nse"))
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Errorf("script %s = %q, want %q", id, got, want)
		}
	}
}

type failingContentKVStore struct {
	*mockKVStore
	readError error
}

func (s *failingContentKVStore) GetValue(context.Context, string) (store.ValkeyResponse, error) {
	return store.ValkeyResponse{}, s.readError
}

func TestSyncScriptContentReadFailurePreservesFilesAndStore(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "example.nse")
	original := "-- keep this script"
	if err := os.WriteFile(path, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	readError := errors.New("store unavailable")
	kv := &failingContentKVStore{mockKVStore: newMockKVStore(), readError: readError}
	sm := NewSyncManager(NewRepoManager(dir, ""), kv)
	if err := sm.syncScriptContent(dir, "example", Script{Path: "example.nse"}); !errors.Is(err, readError) {
		t.Errorf("expected wrapped store error, got %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("script changed: %q", got)
	}
	if got := kv.snapshot(); len(got) != 0 {
		t.Errorf("store changed: %v", got)
	}
}

func TestExtractScriptContentRejectsBlankInput(t *testing.T) {
	for _, input := range []string{"", " ", "\t\r\n", "\u2003\u00a0"} {
		content, err := extractScriptContent(input)
		if err == nil || content != "" {
			t.Errorf("extractScriptContent(%q) = %q, %v; want empty content and error", input, content, err)
		}
	}
}

func TestSyncScriptContentMissingRecordInitializesFromLocal(t *testing.T) {
	for _, missingError := range []error{errors.New("key not found"), errors.New("valkey nil message")} {
		t.Run(missingError.Error(), func(t *testing.T) {
			dir := t.TempDir()
			original := "-- local script\naction = function() return 'local' end\n"
			if err := os.WriteFile(filepath.Join(dir, "example.nse"), []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			kv := &failingContentKVStore{mockKVStore: newMockKVStore(), readError: missingError}
			sm := NewSyncManager(NewRepoManager(dir, ""), kv)
			if err := sm.syncScriptContent(dir, "example.nse", Script{Path: "example.nse"}); err != nil {
				t.Fatal(err)
			}
			var record ScriptContent
			if err := json.Unmarshal([]byte(kv.snapshot()[templates.NseScriptKey("example")]), &record); err != nil {
				t.Fatal(err)
			}
			if record.Content != original {
				t.Errorf("stored content = %q, want %q", record.Content, original)
			}
		})
	}
}
