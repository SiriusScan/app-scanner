# NSE Manifest Reset Tool

This tool resets and refreshes the ValKey manifest from the repository to handle updates.

## Purpose

The NSE Manifest Reset tool addresses the issue where new scripts added to the repository are not reflected in the ValKey manifest. It:

- Forces a refresh of the git repository to get the latest changes
- Resets the ValKey manifest with the current repository contents
- Re-syncs all scripts to ensure they're up to date
- Helps troubleshoot manifest synchronization issues

## Usage

### In Docker Container

```bash
# Run a simple reset
docker exec -it sirius-engine go run cmd/nse-reset/main.go

# Run with complete reset of ValKey manifest
docker exec -it sirius-engine go run cmd/nse-reset/main.go --force
```

### Locally

```bash
# Run a simple reset
go run cmd/nse-reset/main.go

# Run with complete reset of ValKey manifest
go run cmd/nse-reset/main.go --force
```

## Flags

- `--force`: Completely resets the ValKey manifest before syncing (useful when the manifest is corrupted)

## When to Use

Use this tool when:

1. You've added new scripts to the repository but they don't appear in scans
2. The ValKey manifest is out of sync with the repository
3. You've made significant changes to scripts and want to ensure they're properly synced
4. You suspect corruption in the ValKey manifest

## Output

The reset tool provides detailed feedback:

- 🔄 Operations in progress
- ✅ Successful operations
- ⚠️ Warnings that don't prevent completion
- ❌ Critical errors that stop execution

## After Running

After running the reset tool, you should:

1. Run the NSE test program to verify the scripts are properly synced
2. Run a scan test to ensure the scripts are working correctly

## See Also

- [NSE Test](../nse-test/README.md) - For verifying script synchronization
- [NSE Scan Test](../nse-scan-test/README.md) - For testing scanning with the scripts
