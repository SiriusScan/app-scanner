package scan

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/SiriusScan/go-api/sirius/store"
)

func TestLateWorkerCompletionPreservesUnsuccessfulStatus(t *testing.T) {
	for _, status := range []string{"cancelling", "cancelled", "failed"} {
		t.Run(status, func(t *testing.T) {
			initial := store.ScanResult{Status: status, EndTime: "2026-11-07T23:10:47Z"}
			raw, err := json.Marshal(initial)
			if err != nil {
				t.Fatal(err)
			}
			encoded := base64.StdEncoding.EncodeToString(raw)
			kv := &fakeKVStore{data: map[string]string{"currentScan": encoded}}
			sm := &ScanManager{scanUpdater: NewScanUpdater(kv)}
			if err := sm.markHostComplete("192.0.2.1"); err != nil {
				t.Fatal(err)
			}
			resp, err := kv.GetValue(context.Background(), "currentScan")
			if err != nil {
				t.Fatal(err)
			}
			if resp.Message.Value != encoded {
				t.Fatal("late worker changed unsuccessful scan status, timestamp, or progress")
			}
		})
	}
}
