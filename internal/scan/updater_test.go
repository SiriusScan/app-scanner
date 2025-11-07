package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
)

// fakeKVStore is a fake implementation of the KVStore interface for testing.
type fakeKVStore struct {
	data map[string]string
}

// GetValue returns the value associated with the key.
func (f *fakeKVStore) GetValue(ctx context.Context, key string) (store.ValkeyResponse, error) {
	val, ok := f.data[key]
	if !ok {
		return store.ValkeyResponse{}, errors.New("key not found")
	}
	var resp store.ValkeyResponse
	resp.Message.Value = val
	return resp, nil
}

// SetValue sets the key to the specified value.
func (f *fakeKVStore) SetValue(ctx context.Context, key string, value string) error {
	f.data[key] = value
	return nil
}

// DeleteValue removes the key from the store.
func (f *fakeKVStore) DeleteValue(ctx context.Context, key string) error {
	delete(f.data, key)
	return nil
}

// GetTTL returns the TTL for a key (stub implementation).
func (f *fakeKVStore) GetTTL(ctx context.Context, key string) (int, error) {
	if _, ok := f.data[key]; ok {
		return -1, nil // -1 means no expiration
	}
	return -2, errors.New("key not found") // -2 means key doesn't exist
}

// ListKeys returns all keys matching the pattern (stub implementation).
func (f *fakeKVStore) ListKeys(ctx context.Context, pattern string) ([]string, error) {
	keys := make([]string, 0, len(f.data))
	for k := range f.data {
		keys = append(keys, k)
	}
	return keys, nil
}

// SetExpire sets an expiration time on a key (stub implementation).
func (f *fakeKVStore) SetExpire(ctx context.Context, key string, ttl int) error {
	// In a real implementation, this would set TTL. For testing, we just verify the key exists.
	if _, ok := f.data[key]; !ok {
		return errors.New("key not found")
	}
	return nil
}

// SetValueWithTTL sets a key with an expiration time (stub implementation).
func (f *fakeKVStore) SetValueWithTTL(ctx context.Context, key string, value string, ttl int) error {
	f.data[key] = value
	// In a real implementation, this would also set TTL. For testing, we just store the value.
	return nil
}

// Close is a stub for the Close method.
func (f *fakeKVStore) Close() error {
	return nil
}

// TestScanUpdater_Update verifies that the ScanUpdater correctly applies a modifier function.
func TestScanUpdater_Update(t *testing.T) {
	// Create an initial ScanResult with no hosts.
	initialScanResult := store.ScanResult{
		Hosts:           []string{},
		HostsCompleted:  0,
		Vulnerabilities: []store.VulnerabilitySummary{},
	}
	initialJSON, err := json.Marshal(initialScanResult)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(initialJSON)

	// Initialize the fake KV store with the encoded initial scan.
	fakeStore := &fakeKVStore{
		data: map[string]string{
			"currentScan": encoded,
		},
	}

	// Create a ScanUpdater with the fake KV store.
	updater := NewScanUpdater(fakeStore)

	// Define a modifier function that adds a host.
	modifier := func(scan *store.ScanResult) error {
		scan.Hosts = append(scan.Hosts, "192.168.1.1")
		scan.HostsCompleted = 1
		return nil
	}

	// Apply the update.
	if err := updater.Update(context.Background(), modifier); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Retrieve and decode the updated value.
	resp, err := fakeStore.GetValue(context.Background(), "currentScan")
	if err != nil {
		t.Fatalf("GetValue failed: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.Message.Value)
	if err != nil {
		t.Fatalf("Decoding failed: %v", err)
	}

	var updatedScan store.ScanResult
	if err := json.Unmarshal(decoded, &updatedScan); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	// Verify that the host was added.
	if len(updatedScan.Hosts) != 1 || updatedScan.Hosts[0] != "192.168.1.1" {
		t.Errorf("Expected hosts to contain '192.168.1.1', got %v", updatedScan.Hosts)
	}
	if updatedScan.HostsCompleted != 1 {
		t.Errorf("Expected HostsCompleted to be 1, got %d", updatedScan.HostsCompleted)
	}
}
