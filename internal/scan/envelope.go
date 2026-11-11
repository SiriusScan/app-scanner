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
	_, versioned := fields["spec_version"]
	_, payload := fields["payload"]
	if rawScope, ok := fields["resource_scope"]; ok && string(rawScope) != "null" && !versioned && !payload {
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
	if !versioned && !payload {
		return nil, false, nil
	}
	var env message.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, true, err
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
	if env.ResourceScope != nil {
		result.ResourceScope.OwnerSubjectID = string(env.ResourceScope.OwnerSubjectID)
	}
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
	if env.ResourceScope != nil {
		result.SubjectID = string(env.ResourceScope.OwnerSubjectID)
	}
	return result, nil
}
