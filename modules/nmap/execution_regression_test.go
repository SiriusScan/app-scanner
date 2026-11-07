package nmap

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Use a local fake executable: these regressions must never probe the network.
func TestNmapArgumentsPathAndProfileFailure(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "absolute_arguments_path"
		if fail {
			name = "script_failure_is_not_successful_fallback"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			oldWD, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(root); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chdir(oldWD) })
			argsPath := filepath.Join(root, "modules", "nmap", "args", "args.txt")
			if err := os.MkdirAll(filepath.Dir(argsPath), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(argsPath, []byte("http.max-connections=1\n"), 0600); err != nil {
				t.Fatal(err)
			}
			capture := filepath.Join(root, "calls")
			t.Setenv("NMAP_TEST_CALLS", capture)
			t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
			script := "#!/bin/sh\nprintf '%s\\n' CALL \"$@\" >> \"$NMAP_TEST_CALLS\"\n"
			if fail {
				script += "echo 'NSE: failed to initialize the script engine' >&2\nexit 1\n"
			} else {
				script += "printf '<nmaprun/>\\n'\n"
			}
			if err := os.WriteFile(filepath.Join(root, "nmap"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			_, err = executeNmapWithConfig(ScanConfig{
				Target: "192.0.2.1", PortRange: "22", ScriptList: []string{"banner"}, Ctx: context.Background(),
			})
			if fail && err == nil {
				t.Fatal("script initialization failure was reported as success")
			}
			if !fail && err != nil {
				t.Fatal(err)
			}
			calls, err := os.ReadFile(capture)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Count(string(calls), "CALL\n") != 1 {
				t.Fatalf("expected one execution of requested profile, got %s", calls)
			}
			if !strings.Contains(string(calls), "--script-args-file\n"+argsPath+"\n") {
				t.Fatalf("expected absolute arguments path %q, got %s", argsPath, calls)
			}
		})
	}
}
