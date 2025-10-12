# NSE Scan Test Executor

This tool performs real Nmap vulnerability scans using NSE scripts against a specified target for integration testing.

## Purpose

The NSE Scan Test executor provides end-to-end testing of the NSE integration by:

- Running complete Nmap scans with NSE script selection
- Testing against a real target (`192.168.123.119` by default)
- Verifying script selection based on protocols
- Processing and displaying scan results including:
  - Port discovery
  - Service detection
  - Vulnerability identification

## Usage

### In Docker Container

```bash
# Run the test directly
docker exec -it sirius-engine go run cmd/nse-scan-test/main.go

# Build and run the binary
docker exec -it sirius-engine /bin/bash -c "cd /app-scanner && go build -o bin/nse-scan-test cmd/nse-scan-test/main.go && ./bin/nse-scan-test"

# Run with a custom target
docker exec -it sirius-engine go run cmd/nse-scan-test/main.go --target 192.168.123.120
```

### Locally

```bash
# Run the test directly
go run cmd/nse-scan-test/main.go

# Build and run the binary
go build -o bin/nse-scan-test cmd/nse-scan-test/main.go
./bin/nse-scan-test
```

## Configuration

### Test Target

The default test target is `192.168.123.119`. You can modify this in the code or pass a custom target with the `--target` flag.

### Script Arguments

The test uses Nmap script arguments from:

- `/app-scanner/nmap-args/args.txt` (in Docker)
- `nmap-args/args.txt` (local development)

Example args.txt content:

```
# Nmap Script Arguments
vulners.showall=true
http.useragent=Mozilla/5.0 (compatible; SiriusScan)
timeout=10s
```

### Directories

- Docker NSE Base: `/opt/sirius/nse`
- NSE Repository: `/opt/sirius/nse/sirius-nse`
- Scripts Directory: `/app-scanner/scripts`

## Output

The scan test provides detailed output:

1. **Setup Information**:

   - Target IP
   - NSE Base Path
   - ValKey connection status
   - Script synchronization

2. **Scan Results**:
   - Host information (IP, hostname, OS)
   - Open ports with state
   - Detected services with versions
   - Discovered vulnerabilities with CVE IDs and descriptions

## Troubleshooting

Common issues and solutions:

1. **Nmap Execution Errors**:

   - Ensure Nmap is installed in the container (`nmap --version`)
   - Check script paths and arguments syntax
   - Verify the test target is reachable (`ping 192.168.123.119`)

2. **No Vulnerabilities Found**:

   - Verify the target has known vulnerabilities
   - Check that NSE scripts are properly synced
   - Ensure vulners.nse script is working correctly

3. **Script Argument Issues**:
   - Verify args.txt file exists and is correctly formatted
   - Check syntax of script arguments

## Integration

This test serves as an end-to-end integration test for:

- NSE repository management (`nse.RepoManager`)
- Script synchronization (`nse.SyncManager`)
- Script selection (`nse.ScriptSelector`)
- Nmap execution (`nmap.ScanWithConfig`)
- Result parsing and processing

## See Also

- [NSE Test](../nse-test/README.md) - For testing basic NSE initialization without scans
