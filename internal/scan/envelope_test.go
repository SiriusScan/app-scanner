package scan

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/SiriusScan/go-api/sirius/contracts/message"
	"github.com/SiriusScan/go-api/sirius/identity"
	"github.com/SiriusScan/go-api/sirius/scope"
)

func envelopeTestData(t *testing.T, kind string, payload any, subject string) []byte {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	e := message.Envelope{SpecVersion: message.SpecVersion, ID: "event-1", Type: kind, Source: "test", SchemaVersion: "1.0", CreatedAt: time.Now().UTC(), Payload: raw}
	if subject != "" {
		s := scope.ForSubject(identity.SubjectID(subject))
		e.ResourceScope = &s
	}
	out, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestEnvelopeAndLegacyDecoding(t *testing.T) {
	job := message.ScanJob{ScanID: "a", Targets: []message.ScanTarget{{Value: "192.0.2.1", Type: "single_ip"}}, StateMode: "keyed"}
	raw := envelopeTestData(t, message.ScanRequested, job, "")
	got, err := decodeScanMessage(raw)
	if err != nil || got.ID != "a" || got.StateMode != "keyed" || got.Priority != 1 {
		t.Fatalf("job %+v: %v", got, err)
	}
	scoped, err := decodeScanMessage(envelopeTestData(t, message.ScanRequested, job, "subject"))
	if err != nil || scoped.ResourceScope.OwnerSubjectID != "subject" {
		t.Fatalf("scope not propagated: %+v, %v", scoped, err)
	}
	if err := (&ScanManager{}).validateScanMessage(&scoped); err == nil {
		t.Fatal("accepted scoped job without endpoint")
	}
	if err := (&ScanManager{scopedIngestURL: "https://example.test/ingest"}).validateScanMessage(&scoped); err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	_ = json.Unmarshal(raw, &fields)
	fields["spec_version"] = "2.0"
	invalid, _ := json.Marshal(fields)
	if _, err := decodeScanMessage(invalid); err == nil {
		t.Fatal("accepted unsupported version")
	}
	delete(fields, "spec_version")
	invalid, _ = json.Marshal(fields)
	if _, err := decodeScanMessage(invalid); err == nil {
		t.Fatal("accepted envelope without version")
	}
	legacy, err := decodeScanMessage([]byte(`{"id":"legacy","priority":1,"targets":[{"value":"192.0.2.1","type":"single_ip"}]}`))
	if err != nil || legacy.ID != "legacy" || legacy.StateMode != "" {
		t.Fatalf("legacy %+v: %v", legacy, err)
	}
	ctrl := message.ScanControl{ScanID: "a", Action: "cancel", StateMode: "keyed"}
	c, err := decodeControlMessage(envelopeTestData(t, message.ScanCancelRequested, ctrl, ""))
	if err != nil || c.ScanID != "a" || c.StateMode != "keyed" {
		t.Fatalf("control %+v: %v", c, err)
	}
	c, err = decodeControlMessage(envelopeTestData(t, message.ScanCancelRequested, ctrl, "subject"))
	if err != nil || c.SubjectID != "subject" {
		t.Fatalf("scope not propagated: %+v %v", c, err)
	}
}
