package nse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/SiriusScan/go-api/sirius/store"
	"github.com/SiriusScan/go-api/sirius/store/templates"
)

const catalogAttempts = 8

var catalogIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)

type catalogSource struct {
	Type       string `json:"type"`
	Repository string `json:"repository,omitempty"`
}

type catalogScript struct {
	repository string
	basePath   string
	rawID      string
	script     Script
}

type scriptFile struct{ path, content string }

func atomicUpdater(kv store.KVStore) (store.AtomicValueUpdater, error) {
	updater, ok := kv.(store.AtomicValueUpdater)
	if !ok {
		return nil, fmt.Errorf("NSE store does not support atomic catalog updates")
	}
	return updater, nil
}

func missingCatalogKey(err error) bool {
	// The exact legacy errors support older in-memory adapters without treating
	// an arbitrary transport error containing "not found" as confirmed absence.
	return errors.Is(err, store.ErrKeyNotFound) || err != nil && (err.Error() == "key not found" || err.Error() == "valkey nil message")
}

func readCatalogValue(ctx context.Context, kv store.KVStore, key string) (*string, error) {
	response, err := kv.GetValue(ctx, key)
	if missingCatalogKey(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &response.Message.Value, nil
}

func catalogObject(raw []byte, label string) (map[string]json.RawMessage, error) {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, fmt.Errorf("invalid %s: expected JSON object", label)
	}
	return value, nil
}

func readCatalog(raw *string) (map[string]json.RawMessage, map[string]json.RawMessage, map[string]string, map[string]bool, error) {
	root := make(map[string]json.RawMessage)
	entries := make(map[string]json.RawMessage)
	ids := make(map[string]string)
	deleted := make(map[string]bool)
	if raw == nil {
		return root, entries, ids, deleted, nil
	}
	var err error
	root, err = catalogObject([]byte(*raw), "NSE manifest")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if scripts, ok := root["scripts"]; ok {
		entries, err = catalogObject(scripts, "NSE manifest scripts")
		if err != nil {
			return nil, nil, nil, nil, err
		}
	}
	for id, entry := range entries {
		canonical := templates.CanonicalScriptID(id)
		if !catalogIDPattern.MatchString(canonical) || templates.CanonicalScriptID(canonical) != canonical {
			return nil, nil, nil, nil, fmt.Errorf("empty canonical script ID %q", id)
		}
		if other, found := ids[canonical]; found {
			return nil, nil, nil, nil, fmt.Errorf("ambiguous script IDs %q and %q", other, id)
		}
		if _, err := catalogObject(entry, "script "+id); err != nil {
			return nil, nil, nil, nil, err
		}
		ids[canonical] = id
	}
	if data, ok := root["deletedScripts"]; ok {
		if err := json.Unmarshal(data, &deleted); err != nil || deleted == nil {
			return nil, nil, nil, nil, fmt.Errorf("invalid NSE deletion markers")
		}
		for id, value := range deleted {
			if !value || !catalogIDPattern.MatchString(id) || templates.CanonicalScriptID(id) != id {
				return nil, nil, nil, nil, fmt.Errorf("invalid NSE deletion marker %q", id)
			}
			if _, exists := ids[id]; exists {
				return nil, nil, nil, nil, fmt.Errorf("NSE script %q is both present and deleted", id)
			}
		}
	}
	return root, entries, ids, deleted, nil
}

func entrySource(raw json.RawMessage) (catalogSource, error) {
	entry, err := catalogObject(raw, "script entry")
	if err != nil {
		return catalogSource{}, err
	}
	var source catalogSource
	if data, ok := entry["source"]; ok {
		if err := json.Unmarshal(data, &source); err != nil || source.Type == "" {
			return source, fmt.Errorf("invalid NSE script ownership")
		}
		if source.Type == "repository" && source.Repository == "" {
			return source, fmt.Errorf("repository ownership requires a repository name")
		}
	}
	return source, nil
}

// collectCatalog validates every repository before publishing any script data.
// Global script IDs are unique: collisions fail rather than select a random map
// entry or silently let the last configured repository win.
func (sm *SyncManager) collectCatalog(repositories *RepositoryList) (map[string]catalogScript, *Manifest, error) {
	scripts := make(map[string]catalogScript)
	seen := make(map[string]bool)
	var first *Manifest
	for _, repo := range repositories.Repositories {
		if repo.Name == "" || repo.Name == "." || repo.Name == ".." || filepath.Base(repo.Name) != repo.Name || strings.Contains(repo.Name, `\`) {
			return nil, nil, fmt.Errorf("invalid repository name %q", repo.Name)
		}
		if seen[repo.Name] {
			return nil, nil, fmt.Errorf("duplicate repository name %q", repo.Name)
		}
		seen[repo.Name] = true
		repoPath := filepath.Join(sm.repoManager.BasePath, "..", repo.Name)
		manager := NewRepoManager(repoPath, repo.URL)
		if !manager.isGitRepo() {
			return nil, nil, fmt.Errorf("repository %q is not a git repository at %q", repo.Name, repoPath)
		}
		manifest, err := manager.GetManifest()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get manifest from repository %q: %w", repo.Name, err)
		}
		if manifest.Scripts == nil {
			return nil, nil, fmt.Errorf("repository %q has no scripts object", repo.Name)
		}
		if first == nil {
			first = manifest
		}
		for id, script := range manifest.Scripts {
			canonical := templates.CanonicalScriptID(id)
			if !catalogIDPattern.MatchString(canonical) || templates.CanonicalScriptID(canonical) != canonical {
				return nil, nil, fmt.Errorf("repository %q has empty script ID", repo.Name)
			}
			if other, exists := scripts[canonical]; exists {
				return nil, nil, fmt.Errorf("duplicate canonical script ID %q in repositories %q and %q", canonical, other.repository, repo.Name)
			}
			if _, err := safeScriptPath(repoPath, script.Path); err != nil {
				return nil, nil, fmt.Errorf("repository %q script %q: %w", repo.Name, id, err)
			}
			scripts[canonical] = catalogScript{repository: repo.Name, basePath: repoPath, rawID: id, script: script}
		}
	}
	return scripts, first, nil
}

func safeScriptPath(base, path string) (string, error) {
	clean := filepath.Clean(path)
	if path == "" || filepath.IsAbs(path) || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("script path %q escapes its repository", path)
	}
	// Existing symlink components are not safe execution destinations, even
	// when the lexical path is beneath the repository. Reject them rather
	// than follow a link into another repository or outside the checkout.
	current := base
	if info, err := os.Lstat(current); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("repository path is a symlink")
	}
	for _, component := range strings.Split(clean, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("script path %q contains a symlink", path)
		}
	}
	return filepath.Join(base, clean), nil
}

func (sm *SyncManager) syncCatalog(ctx context.Context) error {
	updater, err := atomicUpdater(sm.kvStore)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < catalogAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := sm.loadRepositories(ctx); err != nil {
			return err
		}
		repoRaw, err := readCatalogValue(ctx, sm.kvStore, ValKeyRepoManifestKey)
		if err != nil {
			return err
		}
		if repoRaw == nil {
			continue
		}
		var repositories RepositoryList
		if err := json.Unmarshal([]byte(*repoRaw), &repositories); err != nil || repositories.Repositories == nil {
			return fmt.Errorf("invalid NSE repository list")
		}
		candidates, first, err := sm.collectCatalog(&repositories)
		if err != nil {
			return err
		}
		manifestRaw, err := readCatalogValue(ctx, sm.kvStore, ValKeyManifestKey)
		if err != nil {
			return fmt.Errorf("read NSE manifest: %w", err)
		}
		root, entries, ids, deleted, err := readCatalog(manifestRaw)
		if err != nil {
			return err
		}
		expected := map[string]*string{ValKeyRepoManifestKey: repoRaw, ValKeyManifestKey: manifestRaw}
		updates := make(map[string]*string)
		var files []scriptFile
		var failures []error

		// Prune only entries explicitly owned by the scanner. Legacy/custom entries
		// and all content envelopes survive removal from a repository; retained
		// content may be a user override, so repository sync never deletes it.
		for id, rawID := range ids {
			source, err := entrySource(entries[rawID])
			if err != nil {
				return fmt.Errorf("script %q: %w", id, err)
			}
			candidate, found := candidates[id]
			if source.Type == "repository" && (!found || candidate.repository != source.Repository) {
				if found {
					return fmt.Errorf("script %q changes repository ownership from %q to %q", id, source.Repository, candidate.repository)
				}
				delete(entries, rawID)
				delete(ids, id)
			}
		}
		sorted := make([]string, 0, len(candidates))
		for id := range candidates {
			sorted = append(sorted, id)
		}
		sort.Strings(sorted)
		for _, id := range sorted {
			if deleted[id] {
				continue
			}
			candidate := candidates[id]
			key := templates.NseScriptKey(id)
			content, contentKey, err := sm.readCandidateContent(ctx, id, []string{candidate.rawID, ids[id]}, expected)
			if err != nil {
				return fmt.Errorf("read script %q: %w", id, err)
			}
			var body string
			if content != nil {
				body, err = extractScriptContent(*content)
			} else {
				// A missing custom/legacy body is not permission to replace it
				// with an unrelated repository script sharing the same ID.
				if rawID, exists := ids[id]; exists {
					source, sourceErr := entrySource(entries[rawID])
					if sourceErr != nil {
						return sourceErr
					}
					if source.Type != "repository" {
						failures = append(failures, fmt.Errorf("repository %q script %q: custom or unclassified content is missing", candidate.repository, id))
						continue
					}
				}
				path, pathErr := safeScriptPath(candidate.basePath, candidate.script.Path)
				if pathErr != nil {
					return pathErr
				}
				var data []byte
				data, err = os.ReadFile(path)
				if err == nil {
					body = string(data)
					if strings.TrimSpace(body) == "" {
						err = fmt.Errorf("local script is empty")
					}
				}
				if err == nil {
					record, marshalErr := json.Marshal(ScriptContent{Content: body, Metadata: Metadata{Author: "System", Tags: []string{candidate.script.Protocol}, Description: fmt.Sprintf("NSE script for %s protocol", candidate.script.Protocol)}, UpdatedAt: time.Now().Unix()})
					if marshalErr != nil {
						return marshalErr
					}
					value := string(record)
					updates[key] = &value
				}
			}
			if err != nil {
				failures = append(failures, fmt.Errorf("repository %q script %q: %w", candidate.repository, id, err))
				continue
			}
			// Migrate a legacy body only after validation and in the same CAS
			// as its canonical destination and the catalog publication.
			if content != nil && contentKey != key {
				updates[key] = content
				updates[contentKey] = nil
			}
			rawID, exists := ids[id]
			entry := make(map[string]json.RawMessage)
			source := catalogSource{}
			if exists {
				entry, _ = catalogObject(entries[rawID], "script")
				source, err = entrySource(entries[rawID])
				if err != nil {
					return err
				}
			}
			// Never reinterpret protocol or content flags as ownership. An unmarked
			// existing entry could be a user-created script with the same ID.
			if !exists || source.Type == "repository" {
				fields := map[string]any{"name": candidate.script.Name, "path": candidate.script.Path, "protocol": candidate.script.Protocol, "source": catalogSource{Type: "repository", Repository: candidate.repository}}
				for key, value := range fields {
					entry[key], _ = json.Marshal(value)
				}
				raw, err := json.Marshal(entry)
				if err != nil {
					return err
				}
				if exists {
					delete(entries, rawID)
				}
				entries[id] = raw
			}
			path, err := safeScriptPath(candidate.basePath, candidate.script.Path)
			if err != nil {
				return err
			}
			files = append(files, scriptFile{path: path, content: body})
		}
		if manifestRaw == nil && first != nil {
			root["name"], _ = json.Marshal(first.Name)
			root["version"], _ = json.Marshal(first.Version)
			root["description"], _ = json.Marshal(first.Description)
		}
		root["scripts"], err = json.Marshal(entries)
		if err != nil {
			return err
		}
		data, err := json.Marshal(root)
		if err != nil {
			return err
		}
		value := string(data)
		updates[ValKeyManifestKey] = &value
		committed, err := updater.CompareAndSwapValues(ctx, expected, updates)
		if err != nil {
			return fmt.Errorf("publish NSE catalog: %w", err)
		}
		if !committed {
			continue
		} // A UI edit/delete or repository change won. Reread.
		for _, file := range files {
			if err := writeScriptFile(file.path, file.content); err != nil {
				failures = append(failures, err)
			}
		}
		return errors.Join(failures...)
	}
	return fmt.Errorf("NSE catalog changed during synchronization; retry later")
}

// Readers see either the old or complete new file, never a truncated script.
func writeScriptFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".nse-sync-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	if _, err = temp.WriteString(content); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Chmod(0644); err != nil {
		temp.Close()
		return err
	}
	if err = temp.Close(); err != nil {
		return err
	}
	return os.Rename(temp.Name(), path)
}

// Older direct content helpers use the same manifest guard as UI/REST writers.
// They cannot restore a deleted body or replace a concurrent edit with a stale
// read. A failed CAS is returned to the caller rather than blindly retried.
func (sm *SyncManager) writeGuardedContent(ctx context.Context, id string, content *ScriptContent, create bool) error {
	updater, err := atomicUpdater(sm.kvStore)
	if err != nil {
		return err
	}
	if content == nil || strings.TrimSpace(content.Content) == "" {
		return fmt.Errorf("script content is empty")
	}
	id = templates.CanonicalScriptID(id)
	if !catalogIDPattern.MatchString(id) || templates.CanonicalScriptID(id) != id {
		return fmt.Errorf("empty script ID")
	}
	manifest, err := readCatalogValue(ctx, sm.kvStore, ValKeyManifestKey)
	if err != nil {
		return err
	}
	_, _, ids, deleted, err := readCatalog(manifest)
	if err != nil {
		return err
	}
	if deleted[id] {
		return fmt.Errorf("script %q was deleted", id)
	}
	if !create {
		if _, exists := ids[id]; !exists {
			return fmt.Errorf("script %q is not in the catalog", id)
		}
	}
	key := templates.NseScriptKey(id)
	expected := map[string]*string{ValKeyManifestKey: manifest}
	current, sourceKey, err := sm.readCandidateContent(ctx, id, []string{ids[id]}, expected)
	if err != nil {
		return err
	}
	if create && current != nil {
		return fmt.Errorf("script %q changed during synchronization", id)
	}
	value, err := json.Marshal(content)
	if err != nil {
		return err
	}
	if !create && current != nil {
		if _, err := extractScriptContent(*current); err != nil {
			return err
		}
		if strings.HasPrefix(strings.TrimSpace(*current), "{") {
			original, err := catalogObject([]byte(*current), "script content")
			if err != nil {
				return err
			}
			incoming, _ := catalogObject(value, "script update")
			metadata := make(map[string]json.RawMessage)
			if data, ok := original["metadata"]; ok {
				metadata, err = catalogObject(data, "script metadata")
				if err != nil {
					return err
				}
			}
			fields, _ := catalogObject(incoming["metadata"], "script metadata update")
			for key, data := range fields {
				metadata[key] = data
			}
			incoming["metadata"], _ = json.Marshal(metadata)
			for key, data := range incoming {
				original[key] = data
			}
			if _, hasRESTTimestamp := original["updated_at"]; hasRESTTimestamp {
				original["updated_at"] = incoming["updatedAt"]
			}
			value, err = json.Marshal(original)
			if err != nil {
				return err
			}
		}
	}
	encoded := string(value)
	updates := map[string]*string{key: &encoded}
	if sourceKey != "" && sourceKey != key {
		updates[sourceKey] = nil
	}
	ok, err := updater.CompareAndSwapValues(ctx, expected, updates)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("script %q changed during synchronization", id)
	}
	return nil
}

// This compatibility helper is additive only. It must not be used as a reset:
// removing all catalog provenance would erase custom entries and tombstones.
func (sm *SyncManager) mergeRepositoryManifest(ctx context.Context, manifest *Manifest) error {
	if manifest == nil || manifest.Name == "" || len(manifest.Scripts) == 0 {
		return fmt.Errorf("empty NSE manifest replacement is unsafe; use Sync to reconcile repositories")
	}
	updater, err := atomicUpdater(sm.kvStore)
	if err != nil {
		return err
	}
	owner := filepath.Base(filepath.Clean(sm.repoManager.BasePath))
	repoRaw, err := readCatalogValue(ctx, sm.kvStore, ValKeyRepoManifestKey)
	if err != nil {
		return err
	}
	if repoRaw == nil {
		return fmt.Errorf("repository configuration is required for manifest merge")
	}
	var repositories RepositoryList
	if err := json.Unmarshal([]byte(*repoRaw), &repositories); err != nil {
		return err
	}
	owned := false
	for _, repository := range repositories.Repositories {
		if repository.Name == owner {
			owned = true
		}
	}
	if !owned {
		return fmt.Errorf("repository path %q has no configured owner", sm.repoManager.BasePath)
	}

	incoming := make(map[string]Script)
	for id, script := range manifest.Scripts {
		canonical := templates.CanonicalScriptID(id)
		if !catalogIDPattern.MatchString(canonical) || templates.CanonicalScriptID(canonical) != canonical {
			return fmt.Errorf("empty canonical script ID")
		}
		if _, exists := incoming[canonical]; exists {
			return fmt.Errorf("duplicate canonical script ID %q", canonical)
		}
		incoming[canonical] = script
	}
	for attempt := 0; attempt < catalogAttempts; attempt++ {
		raw, err := readCatalogValue(ctx, sm.kvStore, ValKeyManifestKey)
		if err != nil {
			return err
		}
		root, entries, ids, deleted, err := readCatalog(raw)
		if err != nil {
			return err
		}
		for id, script := range incoming {
			if deleted[id] {
				continue
			}
			rawID, exists := ids[id]
			entry := make(map[string]json.RawMessage)
			if exists {
				source, err := entrySource(entries[rawID])
				if err != nil {
					return err
				}
				if source.Type != "repository" {
					continue
				}
				if source.Repository != owner {
					return fmt.Errorf("script %q belongs to repository %q", id, source.Repository)
				}
				entry, _ = catalogObject(entries[rawID], "script")
				delete(entries, rawID)
			}
			for key, value := range map[string]any{"name": script.Name, "path": script.Path, "protocol": script.Protocol, "source": catalogSource{Type: "repository", Repository: owner}} {
				entry[key], _ = json.Marshal(value)
			}
			entries[id], _ = json.Marshal(entry)
		}
		if raw == nil {
			root["name"], _ = json.Marshal(manifest.Name)
			root["version"], _ = json.Marshal(manifest.Version)
			root["description"], _ = json.Marshal(manifest.Description)
		}
		root["scripts"], _ = json.Marshal(entries)
		encoded, err := json.Marshal(root)
		if err != nil {
			return err
		}
		value := string(encoded)
		ok, err := updater.CompareAndSwapValues(ctx, map[string]*string{ValKeyManifestKey: raw, ValKeyRepoManifestKey: repoRaw}, map[string]*string{ValKeyManifestKey: &value})
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return fmt.Errorf("NSE catalog changed during manifest update; retry later")
}

func (sm *SyncManager) readCandidateContent(ctx context.Context, id string, aliases []string, expected map[string]*string) (*string, string, error) {
	keys := []string{templates.NseScriptKey(id)}
	seen := map[string]bool{keys[0]: true}
	for _, alias := range aliases {
		if alias == "" {
			continue
		}
		key := ValKeyScriptPrefix + alias
		if !seen[key] {
			keys = append(keys, key)
			seen[key] = true
		}
	}
	var content *string
	var source string
	for _, key := range keys {
		value, err := readCatalogValue(ctx, sm.kvStore, key)
		if err != nil {
			return nil, "", err
		}
		expected[key] = value
		if value != nil {
			if content != nil {
				return nil, "", fmt.Errorf("ambiguous canonical and legacy content for %q", id)
			}
			content, source = value, key
		}
	}
	return content, source, nil
}

func (sm *SyncManager) syncOneScriptContent(ctx context.Context, repoBasePath, rawID string, script Script) error {
	updater, err := atomicUpdater(sm.kvStore)
	if err != nil {
		return err
	}
	id := templates.CanonicalScriptID(rawID)
	if !catalogIDPattern.MatchString(id) || templates.CanonicalScriptID(id) != id {
		return fmt.Errorf("empty script ID")
	}
	path, err := safeScriptPath(repoBasePath, script.Path)
	if err != nil {
		return err
	}
	for attempt := 0; attempt < catalogAttempts; attempt++ {
		manifest, err := readCatalogValue(ctx, sm.kvStore, ValKeyManifestKey)
		if err != nil {
			return err
		}
		_, entries, ids, deleted, err := readCatalog(manifest)
		if err != nil {
			return err
		}
		if deleted[id] {
			return fmt.Errorf("script %q was deleted", id)
		}
		expected := map[string]*string{ValKeyManifestKey: manifest}
		content, sourceKey, err := sm.readCandidateContent(ctx, id, []string{rawID, ids[id]}, expected)
		if err != nil {
			return err
		}
		key := templates.NseScriptKey(id)
		updates := make(map[string]*string)
		var body string
		if content != nil {
			body, err = extractScriptContent(*content)
			if err != nil {
				return err
			}
			if sourceKey != key {
				updates[key] = content
				updates[sourceKey] = nil
			}
		} else {
			if entryID, exists := ids[id]; exists {
				source, err := entrySource(entries[entryID])
				if err != nil {
					return err
				}
				if source.Type != "repository" {
					return fmt.Errorf("custom or unclassified script %q is missing content", id)
				}
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			body = string(data)
			if strings.TrimSpace(body) == "" {
				return fmt.Errorf("local script %q is empty", id)
			}
			encoded, err := json.Marshal(ScriptContent{Content: body, Metadata: Metadata{Author: "System", Tags: []string{script.Protocol}, Description: fmt.Sprintf("NSE script for %s protocol", script.Protocol)}, UpdatedAt: time.Now().Unix()})
			if err != nil {
				return err
			}
			value := string(encoded)
			updates[key] = &value
		}
		ok, err := updater.CompareAndSwapValues(ctx, expected, updates)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		return writeScriptFile(path, body)
	}
	return fmt.Errorf("script %q changed during synchronization; retry later", id)
}
