package scan

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/SiriusScan/app-scanner/modules/nmap"
	"github.com/SiriusScan/go-api/sirius"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The scan path must perform no external enrichment lookups: findings are
// the scanner's own evidence, scores included, exactly as reported.
func TestVulnerabilityScanUsesScannerEvidenceOnly(t *testing.T) {
	var calls atomic.Int32
	previous := http.DefaultTransport
	http.DefaultTransport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("external lookup on scan path")
	})
	t.Cleanup(func() { http.DefaultTransport = previous })

	original := sirius.Host{IP: "192.0.2.1", Vulnerabilities: []sirius.Vulnerability{
		{VID: "CVE-2024-0001", Title: "CVE-2024-0001", Description: "cpe:/a:apache:http_server:2.4.49 CVE-2024-0001 9.8 https://vulners.com/cve/CVE-2024-0001", CVEID: "CVE-2024-0001", CVSSScore: 9.8, RiskScore: 9.8},
		{VID: "CVE-2024-0002", Title: "CVE-2024-0002", Description: "scanner evidence without a score", CVEID: "CVE-2024-0002"},
	}}
	got, err := (&NmapStrategy{}).executeWithContext(context.Background(), original.IP, func(nmap.ScanConfig) (sirius.Host, error) {
		return original, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatalf("scan performed %d external lookups", calls.Load())
	}
	if !reflect.DeepEqual(got, original) {
		t.Fatalf("findings changed on scan path:\n got %+v\nwant %+v", got, original)
	}
	// An unknown score stays unknown; it is never presented as medium.
	if got.Vulnerabilities[1].RiskScore != 0 || calculateSeverity(got.Vulnerabilities[1].RiskScore) != "informational" {
		t.Fatalf("unknown score fabricated: %+v", got.Vulnerabilities[1])
	}
}

func TestNormalizeVulnerabilitiesFillsIdentityOnly(t *testing.T) {
	got := normalizeVulnerabilities([]sirius.Vulnerability{
		{VID: " CVE-2024-0001 ", RiskScore: 7.5},
		{VID: "smb-vuln-ms17-010-vulnerability", Title: "SMB Vulnerability: smb-vuln-ms17-010", Description: "state: VULNERABLE"},
	})
	if got[0].VID != "CVE-2024-0001" || got[0].Title != "CVE-2024-0001" || got[0].CVEID != "CVE-2024-0001" || got[0].CVSSScore != 7.5 {
		t.Fatalf("identity fields not filled: %+v", got[0])
	}
	// Non-CVE script IDs must not be rewritten into fake CVE IDs.
	if got[1].VID != "smb-vuln-ms17-010-vulnerability" || got[1].CVEID != "" || got[1].Description != "state: VULNERABLE" || got[1].RiskScore != 0 {
		t.Fatalf("script finding rewritten: %+v", got[1])
	}
}
