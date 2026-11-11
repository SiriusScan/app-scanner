package scan

import (
	"encoding/json"
	"fmt"

	"github.com/SiriusScan/go-api/sirius/contracts/message"
)

// decodeEnvelope detects envelopes even when a required version was omitted,
// so malformed envelopes cannot silently downgrade into legacy messages.
func decodeEnvelope(raw []byte) (*message.Envelope, bool, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, false, err
	}
	if fields == nil {
		return nil, false, fmt.Errorf("message must be an object")
	}
	if rawScope, ok := fields["resource_scope"]; ok && string(rawScope) != "null" {
		var requested struct {
			OwnerSubjectID string `json:"owner_subject_id"`
		}
		if err := json.Unmarshal(rawScope, &requested); err != nil {
			return nil, false, fmt.Errorf("invalid resource scope: %w", err)
		}
		if requested.OwnerSubjectID != "" {
			return nil, false, fmt.Errorf("non-global scope unsupported by scanner ingestion")
		}
	}
	_, versioned := fields["spec_version"]
	if _, payload := fields["payload"]; !versioned && !payload {
		return nil, false, nil
	}
	var env message.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, true, err
	}
	if env.ResourceScope != nil && !env.ResourceScope.IsGlobal() {
		return nil, true, fmt.Errorf("non-global scope unsupported by scanner ingestion")
	}
	return &env, true, nil
}

func decodeScanMessage(raw []byte) (ScanMessage, error) {
	var result ScanMessage
	env, versioned, err := decodeEnvelope(raw)
	if err != nil {
		return result, err
	}
	if !versioned {
		err = json.Unmarshal(raw, &result)
		return result, err
	}
	job, err := env.ValidateScanJob()
	if err != nil {
		return result, err
	}
	if job.StateMode != "keyed" {
		return result, fmt.Errorf("versioned scan jobs require keyed state")
	}
	if err := json.Unmarshal(env.Payload, &result); err != nil {
		return result, err
	}
	result.ID = job.ScanID
	if result.Priority == 0 {
		result.Priority = 1
	}
	return result, nil
}

func decodeControlMessage(raw []byte) (ControlMessage, error) {
	var result ControlMessage
	env, versioned, err := decodeEnvelope(raw)
	if err != nil {
		return result, err
	}
	if !versioned {
		err = json.Unmarshal(raw, &result)
		return result, err
	}
	control, err := env.ValidateScanControl()
	if err != nil {
		return result, err
	}
	if control.StateMode != "keyed" {
		return result, fmt.Errorf("versioned scan control requires keyed state")
	}
	result.ScanID, result.Action, result.StateMode = control.ScanID, control.Action, control.StateMode
	return result, nil
}
