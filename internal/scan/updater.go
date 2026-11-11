package scan

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/SiriusScan/go-api/sirius/store"
)

var ErrScanMismatch = errors.New("current scan does not match requested scan")
var ErrScanContention = errors.New("current scan changed too often during update")

const maxScanUpdateAttempts = 8

// ScanUpdater serializes updates made by this scanner. Cross-process writers
// also need a store-level compare-and-set contract; this mutex alone is not one.
type ScanUpdater struct {
	kvStore   store.KVStore
	mu        sync.Mutex
	keyed     bool
	subjectID string
}

func NewScanUpdater(kv store.KVStore) *ScanUpdater { return &ScanUpdater{kvStore: kv} }

// Update is retained for callers without a scan identity. Scanner lifecycle
// operations must use UpdateForScan so late work cannot update another scan.
func (su *ScanUpdater) Update(ctx context.Context, modifier func(*store.ScanResult) error) error {
	return su.update(ctx, "", modifier)
}

func (su *ScanUpdater) UpdateForScan(ctx context.Context, scanID string, modifier func(*store.ScanResult) error) error {
	if scanID == "" {
		return fmt.Errorf("scan ID is required")
	}
	return su.update(ctx, scanID, modifier)
}

func (su *ScanUpdater) update(ctx context.Context, scanID string, modifier func(*store.ScanResult) error) error {
	su.mu.Lock()
	defer su.mu.Unlock()
	cas, atomic := su.kvStore.(store.ValueCompareAndSetter)
	if scanID != "" && !atomic {
		return fmt.Errorf("scan updates require atomic compare-and-set support")
	}
	key := "currentScan"
	if su.keyed {
		if scanID == "" {
			return fmt.Errorf("scan ID is required for keyed state")
		}
		key = "scan:" + scanID
	}
	for attempt := 0; attempt < maxScanUpdateAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		val, err := su.kvStore.GetValue(ctx, key)
		if err != nil {
			return fmt.Errorf("error getting current scan: %w", err)
		}
		decodedJSON, err := base64.StdEncoding.DecodeString(val.Message.Value)
		if err != nil {
			return fmt.Errorf("error decoding Base64: %w", err)
		}
		if su.keyed {
			var record struct {
				Scope *struct {
					OwnerSubjectID string `json:"owner_subject_id"`
				} `json:"resource_scope"`
			}
			if err := json.Unmarshal(decodedJSON, &record); err != nil {
				return fmt.Errorf("invalid keyed scope: %w", err)
			}
			owner := ""
			if record.Scope != nil {
				owner = record.Scope.OwnerSubjectID
			}
			if owner != su.subjectID {
				return fmt.Errorf("keyed scan scope mismatch")
			}
		}
		var scan *store.ScanResult
		if err := json.Unmarshal(decodedJSON, &scan); err != nil {
			return fmt.Errorf("error decoding current scan: %w", err)
		}
		if scan == nil {
			return fmt.Errorf("current scan is null")
		}
		if scanID != "" && scan.ID != scanID {
			return ErrScanMismatch
		}
		before, err := json.Marshal(scan)
		if err != nil {
			return err
		}
		// Modifiers may run again on contention; external side effects belong
		// after UpdateForScan returns successfully, never in the modifier.
		if err := modifier(scan); err != nil {
			return fmt.Errorf("error applying modifier: %w", err)
		}
		updatedJSON, err := json.Marshal(scan)
		if err != nil {
			return fmt.Errorf("error marshalling updated scan: %w", err)
		}
		if bytes.Equal(before, updatedJSON) {
			return nil
		}
		// Preserve fields added by other components that this SDK does not know.
		var fields, oldFields, newFields map[string]json.RawMessage
		if err := json.Unmarshal(decodedJSON, &fields); err != nil {
			return err
		}
		if err := json.Unmarshal(before, &oldFields); err != nil {
			return err
		}
		if err := json.Unmarshal(updatedJSON, &newFields); err != nil {
			return err
		}
		for key := range oldFields {
			delete(fields, key)
		}
		for key, value := range newFields {
			fields[key] = value
		}
		updatedJSON, err = json.Marshal(fields)
		if err != nil {
			return err
		}
		encoded := base64.StdEncoding.EncodeToString(updatedJSON)
		if atomic {
			swapped, err := cas.CompareAndSetValue(ctx, key, val.Message.Value, encoded)
			if err != nil {
				return fmt.Errorf("error updating scan in KV store: %w", err)
			}
			if !swapped {
				continue
			}
		} else if err := su.kvStore.SetValue(ctx, key, encoded); err != nil {
			return fmt.Errorf("error updating scan in KV store: %w", err)
		}
		return nil
	}
	return ErrScanContention
}
