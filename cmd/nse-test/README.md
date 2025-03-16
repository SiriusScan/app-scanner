# NSE Test Executor

This tool verifies the NSE (Nmap Script Engine) initialization, repository management, and script synchronization with ValKey.

## Purpose

The NSE Test executor performs the following functions:

- Verifies proper directory structure for NSE scripts
- Cleans up legacy NSE directories
- Initializes and tests the ValKey connection
- Loads the repository list from manifest
- Ensures NSE script repositories are cloned and up-to-date
- Synchronizes scripts between the local filesystem and ValKey
- Validates manifest parsing and script selection

## Usage

### In Docker Container

```bash
# Run the test directly
docker exec -it sirius-engine go run cmd/nse-test/main.go

# Build and run the binary
docker exec -it sirius-engine /bin/bash -c "cd /app-scanner && go build -o bin/nse-test cmd/nse-test/main.go && ./bin/nse-test"
```

### Locally

```bash
# Run the test directly
go run cmd/nse-test/main.go

# Build and run the binary
go build -o bin/nse-test cmd/nse-test/main.go
./bin/nse-test
```

## Configuration

The test executor uses these directories:

- Docker NSE Base: `/opt/sirius/nse`
- Legacy directories (cleaned up): `/opt/sirius-nse` and others
- Repository manifest: `/app-scanner/internal/nse/manifest.json`

## Output

The test provides detailed feedback with emojis for better visibility:

- 🚀 - Starting test program
- 🧹 - Cleaning legacy directories
- 🔌 - Connecting to ValKey
- 🔄 - Processing repositories
- ✅ - Successful operations
- ❌ - Failed operations

## Troubleshooting

Common issues and solutions:

1. **ValKey Connection Failures**:

   - Check if ValKey service is running (`docker ps | grep valkey`)
   - Verify network connectivity to `sirius-valkey:6379`

2. **Repository Setup Issues**:

   - Ensure git is installed in the container
   - Check network connectivity for git cloning
   - Verify directory permissions in `/opt/sirius/nse`

3. **Script Sync Failures**:
   - Check ValKey connectivity and permissions
   - Ensure proper JSON format in manifest files
   - Verify script file permissions

## See Also

- [NSE Scan Test](../nse-scan-test/README.md) - For testing NSE integration with real Nmap scans
