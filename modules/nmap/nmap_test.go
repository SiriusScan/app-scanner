package nmap

import (
	"os"
	"testing"

	"github.com/SiriusScan/app-scanner/internal/nse"
	"github.com/SiriusScan/go-api/sirius"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockNmapScan replaces the real Nmap scan for testing
func mockNmapScan(target string) (sirius.Host, error) {
	// Return a predefined host for testing
	return sirius.Host{
		IP: target,
		Services: []sirius.Service{
			{
				Port:    80,
				Product: "nginx",
				Version: "1.18.0",
			},
		},
	}, nil
}

func TestScanWithConfig(t *testing.T) {
	// Store the original scan function
	originalScan := Scan
	defer func() { Scan = originalScan }()

	// Replace with mock for testing
	Scan = mockNmapScan

	tests := []struct {
		name    string
		config  ScanConfig
		wantIP  string
		wantErr bool
	}{
		{
			name: "basic scan",
			config: ScanConfig{
				Target:    "192.168.1.1",
				Protocols: []string{"http"},
			},
			wantIP:  "192.168.1.1",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ScanWithConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantIP, got.IP)
		})
	}
}

func TestProcessNmapOutput(t *testing.T) {
	// Sample Nmap XML output
	xmlOutput := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun>
  <host>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0"/>
        <script id="vulners" output="
CVE-2021-23017: Some vulnerability
CVE-2021-23018: Another vulnerability
        "/>
      </port>
    </ports>
  </host>
</nmaprun>`

	t.Run("process valid output", func(t *testing.T) {
		host, err := processNmapOutput(xmlOutput)
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", host.IP)
		assert.Len(t, host.Services, 1)
		assert.Equal(t, 80, host.Services[0].Port)
		assert.Equal(t, "nginx", host.Services[0].Product)
		assert.Equal(t, "1.18.0", host.Services[0].Version)

		// Check vulnerabilities
		assert.GreaterOrEqual(t, len(host.Vulnerabilities), 2)
		foundCVEs := make(map[string]bool)
		for _, vuln := range host.Vulnerabilities {
			foundCVEs[vuln.VID] = true
		}
		assert.True(t, foundCVEs["CVE-2021-23017"])
		assert.True(t, foundCVEs["CVE-2021-23018"])
	})

	t.Run("process invalid output", func(t *testing.T) {
		_, err := processNmapOutput("invalid xml")
		assert.Error(t, err)
	})
}

func TestExtractVulnerabilities(t *testing.T) {
	tests := []struct {
		name   string
		result ScriptResult
		want   int // number of expected vulnerabilities
	}{
		{
			name: "vulners script with multiple CVEs",
			result: ScriptResult{
				ID:     "vulners",
				Output: "CVE-2021-1234\nCVE-2021-5678",
			},
			want: 2,
		},
		{
			name: "http-vuln-cve script",
			result: ScriptResult{
				ID:     "http-vuln-cve",
				Output: "Found vulnerability: CVE-2021-9999",
			},
			want: 1,
		},
		{
			name: "script with no CVEs",
			result: ScriptResult{
				ID:     "other-script",
				Output: "No vulnerabilities found",
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vulns := extractVulnerabilities(tt.result)
			assert.Len(t, vulns, tt.want)
		})
	}
}

func TestDeduplicateVulnerabilities(t *testing.T) {
	vulns := []sirius.Vulnerability{
		{VID: "CVE-2021-1234", Title: "First"},
		{VID: "CVE-2021-1234", Title: "Duplicate"},
		{VID: "CVE-2021-5678", Title: "Second"},
	}

	result := deduplicateVulnerabilities(vulns)
	assert.Len(t, result, 2)

	// Check that we kept the first occurrence
	foundFirst := false
	foundSecond := false
	for _, v := range result {
		if v.VID == "CVE-2021-1234" && v.Title == "First" {
			foundFirst = true
		}
		if v.VID == "CVE-2021-5678" {
			foundSecond = true
		}
	}
	assert.True(t, foundFirst)
	assert.True(t, foundSecond)
}

func TestExecuteNmapWithConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  ScanConfig
		wantErr bool
	}{
		{
			name: "valid config with protocols",
			config: ScanConfig{
				Target:    "localhost",
				Protocols: []string{"http", "https"},
			},
			wantErr: false,
		},
		{
			name: "empty target",
			config: ScanConfig{
				Target: "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, err := executeNmapWithConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, output)
		})
	}
}

// Integration test that uses actual NSE scripts
func TestNmapIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config := ScanConfig{
		Target:    "localhost",
		Protocols: []string{"http"},
	}

	host, err := ScanWithConfig(config)
	require.NoError(t, err)
	assert.NotEmpty(t, host.IP)
}

// createTestManifest creates a temporary manifest file for testing
func createTestManifest(t *testing.T) string {
	t.Helper()

	content := []byte(`{
		"name": "sirius-nse-test",
		"version": "0.1.0",
		"description": "Test NSE scripts",
		"scripts": {
			"vulners": {
				"name": "vulners",
				"path": "/usr/share/nmap/scripts/vulners.nse",
				"protocol": "*"
			}
		}
	}`)

	tmpDir := t.TempDir()
	manifestPath := tmpDir + "/manifest.json"

	err := os.WriteFile(manifestPath, content, 0644)
	require.NoError(t, err, "Failed to create test manifest")

	// Create a symlink to the vulners script if it doesn't exist in the test directory
	scriptPath := "/usr/share/nmap/scripts/vulners.nse"
	if _, err := os.Stat(scriptPath); err == nil {
		err = os.MkdirAll(tmpDir+"/scripts", 0755)
		require.NoError(t, err, "Failed to create scripts directory")
		err = os.Symlink(scriptPath, tmpDir+"/scripts/vulners.nse")
		if err != nil && !os.IsExist(err) {
			require.NoError(t, err, "Failed to create symlink")
		}
	}

	return tmpDir
}

// TestNmapNSEIntegration tests the full integration of Nmap with NSE scripts
func TestNmapNSEIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping NSE integration test in short mode")
	}

	// Create a temporary manifest for testing
	repoPath := createTestManifest(t)
	t.Logf("Created test repo at: %s", repoPath)

	// Set up the repo manager with the test manifest
	repoManager := nse.NewRepoManager(repoPath, "")
	_, err := repoManager.GetManifest()
	require.NoError(t, err, "Failed to get manifest")

	tests := []struct {
		name      string
		config    ScanConfig
		wantPort  int
		wantProto string
	}{
		{
			name: "http scan with vulners",
			config: ScanConfig{
				Target:    "scanme.nmap.org", // Using nmap's test server
				Protocols: []string{"http"},
			},
			wantPort:  80,
			wantProto: "tcp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a new config with the manifest path
			config := tt.config

			host, err := ScanWithConfig(config)
			require.NoError(t, err, "ScanWithConfig should not error")

			// Verify basic host information
			assert.NotEmpty(t, host.IP, "Host IP should not be empty")

			// Check that we found the expected port
			foundPort := false
			for _, port := range host.Ports {
				if port.Number == tt.wantPort && port.Protocol == tt.wantProto {
					foundPort = true
					break
				}
			}
			assert.True(t, foundPort, "Expected port %d/%s not found", tt.wantPort, tt.wantProto)

			// Verify service detection
			foundService := false
			for _, service := range host.Services {
				if service.Port == tt.wantPort {
					foundService = true
					assert.NotEmpty(t, service.Product, "Service product should be detected")
					break
				}
			}
			assert.True(t, foundService, "Service for port %d not found", tt.wantPort)

			// Check for vulnerabilities
			if len(host.Vulnerabilities) > 0 {
				t.Logf("Found %d vulnerabilities", len(host.Vulnerabilities))
				for _, vuln := range host.Vulnerabilities {
					assert.NotEmpty(t, vuln.VID, "Vulnerability ID should not be empty")
					assert.NotEmpty(t, vuln.Description, "Vulnerability description should not be empty")
					t.Logf("Found vulnerability: %s", vuln.VID)
				}
			}
		})
	}
}
