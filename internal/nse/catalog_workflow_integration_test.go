package nse

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

// TestNSECatalogWorkflow is an opt-in scanner phase for the cross-component
// disposable-Valkey harness in Sirius/sirius-ui/scripts/test-nse-workflow.sh.
// It never launches Nmap or contacts repository remotes. The fresh store must
// contain an independently generated marker supplied by the harness.
func TestNSECatalogWorkflow(t *testing.T) {
	address := os.Getenv("SIRIUS_TEST_NSE_WORKFLOW_ADDR")
	if address == "" {
		t.Skip("requires disposable NSE workflow Valkey")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() || port == "6379" {
		t.Fatal("workflow store must use a non-default loopback port")
	}
	token := os.Getenv("SIRIUS_TEST_NSE_WORKFLOW_TOKEN")
	if len(token) < 24 {
		t.Fatal("workflow isolation token is required")
	}
	t.Setenv("VALKEY_ADDR", address)
	kv, err := store.NewValkeyStore()
	if err != nil {
		t.Fatal(err)
	}
	defer kv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	marker, err := kv.GetValue(ctx, "sirius:test:nse-workflow:marker")
	if err != nil || marker.Message.Value != token {
		t.Fatal("disposable workflow store marker does not match")
	}
	dir := t.TempDir()
	alpha := writeRepoFixture(t, dir, "alpha", map[string]string{"demo.NSE": "-- uppercase repository default", "lower.nse": "-- lower repository default"})
	writeRepoFixture(t, dir, "beta", map[string]string{"other.nse": "-- other repository default"})
	manager := NewSyncManager(NewRepoManager(filepath.Join(dir, "placeholder"), ""), kv)
	switch phase := os.Getenv("SIRIUS_TEST_NSE_WORKFLOW_PHASE"); phase {
	case "seed":
		if _, err := kv.GetValue(ctx, ValKeyManifestKey); !errors.Is(err, store.ErrKeyNotFound) {
			t.Fatal("seed requires a fresh catalog")
		}
		repositories := `{"repositories":[{"name":"alpha","url":"https://example.invalid/alpha"},{"name":"beta","url":"https://example.invalid/beta"}]}`
		updater, err := atomicUpdater(kv)
		if err != nil {
			t.Fatal(err)
		}
		ok, err := updater.CompareAndSwapValues(ctx, map[string]*string{ValKeyRepoManifestKey: nil, ValKeyManifestKey: nil}, map[string]*string{ValKeyRepoManifestKey: &repositories})
		if err != nil || !ok {
			t.Fatalf("seed repository config: %t %v", ok, err)
		}
		if err := manager.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		raw, err := readCatalogValue(ctx, kv, ValKeyManifestKey)
		if err != nil {
			t.Fatal(err)
		}
		_, entries, _, _, err := readCatalog(raw)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"demo.NSE", "lower", "other"} {
			if entries[id] == nil {
				t.Fatalf("initial catalog missing %q", id)
			}
		}
		if len(entries) != 3 {
			t.Fatalf("wrong initial catalog: %v", entries)
		}
	case "sync":
		before, err := readCatalogValue(ctx, kv, ValKeyManifestKey)
		if err != nil {
			t.Fatal(err)
		}
		_, oldEntries, _, oldDeleted, err := readCatalog(before)
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		after, err := readCatalogValue(ctx, kv, ValKeyManifestKey)
		if err != nil {
			t.Fatal(err)
		}
		_, entries, _, deleted, err := readCatalog(after)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(oldDeleted, deleted) {
			t.Fatal("scanner changed deletion markers")
		}
		for id, body := range oldEntries {
			source, err := entrySource(body)
			if err != nil {
				t.Fatal(err)
			}
			if source.Type != "repository" && !reflect.DeepEqual(body, entries[id]) {
				t.Fatalf("scanner changed custom/legacy entry %q", id)
			}
		}
		for id := range deleted {
			if entries[id] != nil {
				t.Fatalf("scanner resurrected deleted entry %q", id)
			}
			if _, err := kv.GetValue(ctx, templates.NseScriptKey(id)); !errors.Is(err, store.ErrKeyNotFound) {
				t.Fatalf("deleted body %q exists: %v", id, err)
			}
		}
		if !deleted["lower"] {
			value, err := kv.GetValue(ctx, templates.NseScriptKey("lower"))
			if err != nil {
				t.Fatal(err)
			}
			var record ScriptContent
			if err := json.Unmarshal([]byte(value.Message.Value), &record); err != nil {
				t.Fatal(err)
			}
			local, err := os.ReadFile(filepath.Join(alpha, "scripts/lower.nse"))
			if err != nil {
				t.Fatal(err)
			}
			if string(local) != record.Content {
				t.Fatalf("local script does not match stored UI/REST content: %q != %q", local, record.Content)
			}
		}
	case "collision":
		writeRepoFixture(t, dir, "beta", map[string]string{"lower": "-- conflicting body", "other.nse": "-- other"})
		before := workflowSnapshot(t, ctx, kv)
		if err := manager.Sync(ctx); err == nil || !strings.Contains(err.Error(), "duplicate canonical script ID") {
			t.Fatalf("expected collision rejection: %v", err)
		}
		after := workflowSnapshot(t, ctx, kv)
		if !reflect.DeepEqual(before, after) {
			t.Fatal("collision partially mutated shared catalog")
		}
	default:
		t.Fatalf("unknown workflow phase %q", phase)
	}
}

func workflowSnapshot(t *testing.T, ctx context.Context, kv store.KVStore) map[string]string {
	t.Helper()
	keys, err := kv.ListKeys(ctx, "nse:*")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := make(map[string]string, len(keys))
	for _, key := range keys {
		value, err := kv.GetValue(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		snapshot[key] = value.Message.Value
	}
	return snapshot
}
