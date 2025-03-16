package nse

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScriptSelector(t *testing.T) {
	// Create a test manifest
	manifest := &Manifest{
		Name:        "test-manifest",
		Version:     "1.0.0",
		Description: "Test manifest",
		Scripts: map[string]Script{
			"http-test": {
				Name:     "http-test",
				Path:     "scripts/http-test.nse",
				Protocol: "http",
			},
			"ftp-test": {
				Name:     "ftp-test",
				Path:     "scripts/ftp-test.nse",
				Protocol: "ftp",
			},
			"universal": {
				Name:     "universal",
				Path:     "scripts/universal.nse",
				Protocol: "*",
			},
		},
	}

	selector := NewScriptSelector(manifest)

	t.Run("SelectScripts", func(t *testing.T) {
		tests := []struct {
			name      string
			protocols []string
			want      int // Expected number of scripts
		}{
			{
				name:      "No protocols",
				protocols: []string{},
				want:      1, // Should only get universal script
			},
			{
				name:      "Single protocol",
				protocols: []string{"http"},
				want:      2, // Should get http-test and universal
			},
			{
				name:      "Multiple protocols",
				protocols: []string{"http", "ftp"},
				want:      3, // Should get all scripts
			},
			{
				name:      "Non-existent protocol",
				protocols: []string{"smtp"},
				want:      1, // Should only get universal script
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				scripts := selector.SelectScripts(tt.protocols...)
				if len(scripts) != tt.want {
					t.Errorf("SelectScripts() got %d scripts, want %d", len(scripts), tt.want)
				}

				// Verify paths are absolute
				for _, script := range scripts {
					if !filepath.IsAbs(script) {
						t.Errorf("Script path %s is not absolute", script)
					}
				}
			})
		}
	})

	t.Run("BuildNmapScriptFlag", func(t *testing.T) {
		tests := []struct {
			name      string
			protocols []string
			wantErr   bool
		}{
			{
				name:      "No protocols",
				protocols: []string{},
				wantErr:   false,
			},
			{
				name:      "Single protocol",
				protocols: []string{"http"},
				wantErr:   false,
			},
			{
				name:      "Multiple protocols",
				protocols: []string{"http", "ftp"},
				wantErr:   false,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				flag, err := selector.BuildNmapScriptFlag(tt.protocols...)
				if (err != nil) != tt.wantErr {
					t.Errorf("BuildNmapScriptFlag() error = %v, wantErr %v", err, tt.wantErr)
					return
				}

				if !tt.wantErr {
					// Verify vulners is always included
					if !strings.Contains(flag, "vulners") {
						t.Error("BuildNmapScriptFlag() result does not contain vulners script")
					}
				}
			})
		}
	})

	t.Run("GetScriptsByProtocol", func(t *testing.T) {
		protocolScripts := selector.GetScriptsByProtocol()

		// Check HTTP scripts
		if len(protocolScripts["http"]) != 1 {
			t.Errorf("Expected 1 HTTP script, got %d", len(protocolScripts["http"]))
		}

		// Check FTP scripts
		if len(protocolScripts["ftp"]) != 1 {
			t.Errorf("Expected 1 FTP script, got %d", len(protocolScripts["ftp"]))
		}

		// Check universal scripts
		if len(protocolScripts["*"]) != 1 {
			t.Errorf("Expected 1 universal script, got %d", len(protocolScripts["*"]))
		}
	})
}
