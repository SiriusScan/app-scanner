package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/SiriusScan/go-api/sirius/store"
)

// ScanUpdater handles updates to the current scan in the KV store.
type ScanUpdater struct {
	kvStore store.KVStore
}

// NewScanUpdater initializes a new ScanUpdater.
func NewScanUpdater(kv store.KVStore) *ScanUpdater {
	return &ScanUpdater{kvStore: kv}
}

// Update retrieves the current scan, applies the modifier function, and writes it back.
func (su *ScanUpdater) Update(ctx context.Context, modifier func(*store.ScanResult) error) error {
	val, err := su.kvStore.GetValue(ctx, "currentScan")
	if err != nil {
		return fmt.Errorf("error getting current scan: %w", err)
	}

	decodedJSON, err := base64.StdEncoding.DecodeString(val.Message.Value)
	if err != nil {
		return fmt.Errorf("error decoding Base64: %w", err)
	}

	var scan store.ScanResult
	if err := json.Unmarshal(decodedJSON, &scan); err != nil {
		// If unmarshalling fails, initialize an empty scan.
		scan = store.ScanResult{}
	}

	if err := modifier(&scan); err != nil {
		return fmt.Errorf("error applying modifier: %w", err)
	}

	updatedJSON, err := json.Marshal(scan)
	if err != nil {
		return fmt.Errorf("error marshalling updated scan: %w", err)
	}

	encoded := base64.StdEncoding.EncodeToString(updatedJSON)
	if err := su.kvStore.SetValue(ctx, "currentScan", encoded); err != nil {
		return fmt.Errorf("error updating scan in KV store: %w", err)
	}

	return nil
}