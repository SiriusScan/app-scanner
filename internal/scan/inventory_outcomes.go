package scan

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/SiriusScan/go-api/sirius/store"
)

const (
	inventoryReportMetadataKey = "inventory_reports"
	inventoryReportVersion     = 1
	inventoryResponseLimit     = 4096
	maxInventoryReportCount    = 1<<53 - 1
)

type inventoryReportOutcome int

const (
	inventoryReportAccepted inventoryReportOutcome = iota
	inventoryReportLocalError
	inventoryReportHTTPRejected
	inventoryReportTimeout
	inventoryReportTransportError
	inventoryReportHTTPUnconfirmed
	inventoryReportOutcomeCount
)

type inventoryReportTally [inventoryReportOutcomeCount]uint64

type inventoryReportAccounting int

const (
	inventoryAccountingStart inventoryReportAccounting = iota
	inventoryAccountingPartial
	inventoryAccountingFinal
)

type inventoryReportSummary struct {
	Version     int                     `json:"version"`
	Attempted   uint64                  `json:"attempted"`
	Accepted    uint64                  `json:"accepted"`
	Rejected    uint64                  `json:"rejected"`
	Unknown     uint64                  `json:"unknown"`
	Finalized   bool                    `json:"finalized"`
	Interrupted bool                    `json:"interrupted,omitempty"`
	Reasons     *inventoryReportReasons `json:"reasons,omitempty"`
}

type inventoryReportReasons struct {
	LocalError      uint64 `json:"local_error,omitempty"`
	HTTPRejected    uint64 `json:"http_rejected,omitempty"`
	Timeout         uint64 `json:"timeout,omitempty"`
	TransportError  uint64 `json:"transport_error,omitempty"`
	HTTPUnconfirmed uint64 `json:"http_unconfirmed,omitempty"`
}

func inventoryTransportOutcome(err error) inventoryReportOutcome {
	var timeout interface{ Timeout() bool }
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &timeout) && timeout.Timeout()) {
		return inventoryReportTimeout
	}
	return inventoryReportTransportError
}

func inventoryResponseOutcome(request *http.Request, response *http.Response, hostIP, source string, scoped bool) inventoryReportOutcome {
	// A redirect or unrelated success response gives no acknowledgement for
	// the original write. Preserve the caller's existing HTTP return behavior.
	if response.Request == nil || response.Request.Response != nil ||
		response.Request.Method != request.Method || response.Request.URL.String() != request.URL.String() {
		return inventoryReportHTTPUnconfirmed
	}
	if response.StatusCode == http.StatusRequestTimeout {
		return inventoryReportTimeout
	}
	switch response.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusRequestEntityTooLarge:
		return inventoryReportHTTPRejected
	}
	if scoped && response.StatusCode == http.StatusNoContent {
		return inventoryReportAccepted
	}
	if scoped || response.StatusCode != http.StatusOK {
		return inventoryReportHTTPUnconfirmed
	}

	// The Community sourced endpoint acknowledges a synchronous save with
	// this JSON object. The scoped endpoint above uses a bodyless 204 instead.
	var acknowledgement struct {
		Message string          `json:"message"`
		HostIP  string          `json:"host_ip"`
		Source  string          `json:"source"`
		Error   json.RawMessage `json:"error"`
		Success *bool           `json:"success"`
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, inventoryResponseLimit+1))
	if err != nil {
		return inventoryTransportOutcome(err)
	}
	if len(body) > inventoryResponseLimit ||
		json.Unmarshal(body, &acknowledgement) != nil ||
		acknowledgement.HostIP != hostIP || acknowledgement.Source != source ||
		len(acknowledgement.Error) != 0 || (acknowledgement.Success != nil && !*acknowledgement.Success) {
		return inventoryReportHTTPUnconfirmed
	}
	switch acknowledgement.Message {
	case "Host added successfully with source attribution", "Host added successfully with enhanced SBOM data":
		return inventoryReportAccepted
	default:
		return inventoryReportHTTPUnconfirmed
	}
}

// projectInventoryReports runs inside the same retryable CAS modifier as
// network progress or a network failure. The target tally belongs to one
// caller. Re-evaluating the modifier adds it to the latest committed value.
func projectInventoryReports(subScan *store.SubScan, tally inventoryReportTally, accounting inventoryReportAccounting) {
	var metadata map[string]json.RawMessage
	if len(subScan.Metadata) != 0 && json.Unmarshal(subScan.Metadata, &metadata) != nil {
		return
	}

	summary := inventoryReportSummary{Version: inventoryReportVersion}
	if previous, exists := metadata[inventoryReportMetadataKey]; exists {
		prior, valid := decodeInventoryReportSummary(previous)
		if !valid {
			return
		}
		summary = prior
		if accounting == inventoryAccountingStart {
			// An interrupted execution may have sent reports without committing
			// their counters. Preserve known counts and keep coverage provisional.
			summary.Interrupted = true
		}
	} else if accounting != inventoryAccountingStart {
		// A completion without a tracked start cannot establish full coverage.
		summary.Interrupted = true
	}

	var attempted uint64
	for _, count := range tally {
		attempted += count
	}
	if attempted > maxInventoryReportCount-summary.Attempted {
		return
	}
	summary.Attempted += attempted
	summary.Accepted += tally[inventoryReportAccepted]
	rejected := tally[inventoryReportLocalError] + tally[inventoryReportHTTPRejected]
	unknown := tally[inventoryReportTimeout] + tally[inventoryReportTransportError] + tally[inventoryReportHTTPUnconfirmed]
	summary.Rejected += rejected
	summary.Unknown += unknown
	if rejected+unknown != 0 {
		if summary.Reasons == nil {
			summary.Reasons = &inventoryReportReasons{}
		}
		summary.Reasons.LocalError += tally[inventoryReportLocalError]
		summary.Reasons.HTTPRejected += tally[inventoryReportHTTPRejected]
		summary.Reasons.Timeout += tally[inventoryReportTimeout]
		summary.Reasons.TransportError += tally[inventoryReportTransportError]
		summary.Reasons.HTTPUnconfirmed += tally[inventoryReportHTTPUnconfirmed]
	}
	summary.Finalized = accounting == inventoryAccountingFinal && !summary.Interrupted

	raw, err := json.Marshal(summary)
	if err != nil {
		return
	}
	if metadata == nil {
		metadata = make(map[string]json.RawMessage)
	}
	metadata[inventoryReportMetadataKey] = raw
	if next, err := json.Marshal(metadata); err == nil {
		subScan.Metadata = next
	}
}

func decodeInventoryReportSummary(raw json.RawMessage) (inventoryReportSummary, bool) {
	var summary inventoryReportSummary
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return summary, false
	}
	for _, key := range []string{"version", "attempted", "accepted", "rejected", "unknown", "finalized"} {
		if value := fields[key]; len(value) == 0 || string(value) == "null" {
			return summary, false
		}
	}
	if string(fields["interrupted"]) == "null" {
		return summary, false
	}
	if rawReasons, ok := fields["reasons"]; ok {
		var reasons map[string]json.RawMessage
		if json.Unmarshal(rawReasons, &reasons) != nil || reasons == nil {
			return summary, false
		}
		for name, value := range reasons {
			switch name {
			case "local_error", "http_rejected", "timeout", "transport_error", "http_unconfirmed":
				if string(value) == "null" {
					return summary, false
				}
			default:
				return summary, false
			}
		}
	}
	if err := json.Unmarshal(raw, &summary); err != nil {
		return summary, false
	}
	return summary, summary.valid()
}

func (summary inventoryReportSummary) valid() bool {
	if summary.Version != inventoryReportVersion ||
		(summary.Interrupted && summary.Finalized) ||
		summary.Attempted > maxInventoryReportCount ||
		summary.Accepted > summary.Attempted ||
		summary.Rejected > summary.Attempted ||
		summary.Unknown > summary.Attempted ||
		summary.Attempted != summary.Accepted+summary.Rejected+summary.Unknown {
		return false
	}
	reasons := summary.Reasons
	if reasons == nil {
		return summary.Rejected == 0 && summary.Unknown == 0
	}
	return reasons.LocalError <= summary.Rejected && reasons.HTTPRejected <= summary.Rejected &&
		reasons.Timeout <= summary.Unknown && reasons.TransportError <= summary.Unknown &&
		reasons.HTTPUnconfirmed <= summary.Unknown &&
		reasons.LocalError+reasons.HTTPRejected == summary.Rejected &&
		reasons.Timeout+reasons.TransportError+reasons.HTTPUnconfirmed == summary.Unknown
}
