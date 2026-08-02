package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/SiriusScan/go-api/sirius/store"
)

// ScanUpdater handles updates to scan results in the KV store.
type ScanUpdater struct {
	kvStore store.KVStore
	mu      sync.Mutex
}

// NewScanUpdater initializes a new ScanUpdater.
func NewScanUpdater(kv store.KVStore) *ScanUpdater {
	return &ScanUpdater{kvStore: kv}
}

// Update retrieves the legacy currentScan, applies the modifier function, and writes it back.
// Kept for Community backward compatibility and existing tests.
func (su *ScanUpdater) Update(ctx context.Context, modifier func(*store.ScanResult) error) error {
	return su.updateKey(ctx, LegacyCurrentScanKey, modifier, false)
}

// UpdateScan retrieves scan:state:<scanID>, applies the modifier, and writes it back.
// Missing keys start from an empty ScanResult (created on first write).
func (su *ScanUpdater) UpdateScan(ctx context.Context, scanID string, modifier func(*store.ScanResult) error) error {
	if scanID == "" {
		return fmt.Errorf("scanID is required for UpdateScan")
	}
	return su.updateKey(ctx, ScanStateKey(scanID), modifier, true)
}

func (su *ScanUpdater) updateKey(ctx context.Context, key string, modifier func(*store.ScanResult) error, createIfMissing bool) error {
	su.mu.Lock()
	defer su.mu.Unlock()

	var scan store.ScanResult
	val, err := su.kvStore.GetValue(ctx, key)
	if err != nil {
		if !createIfMissing {
			return fmt.Errorf("error getting current scan: %w", err)
		}
		scan = store.ScanResult{}
	} else {
		decodedJSON, err := base64.StdEncoding.DecodeString(val.Message.Value)
		if err != nil {
			return fmt.Errorf("error decoding Base64: %w", err)
		}
		if err := json.Unmarshal(decodedJSON, &scan); err != nil {
			// If unmarshalling fails, initialize an empty scan.
			scan = store.ScanResult{}
		}
	}

	if err := modifier(&scan); err != nil {
		return fmt.Errorf("error applying modifier: %w", err)
	}

	updatedJSON, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("error marshalling updated scan: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(updatedJSON)
	if err := su.kvStore.SetValue(ctx, key, encoded); err != nil {
		return fmt.Errorf("error updating scan in KV store: %w", err)
	}

	return nil
}
