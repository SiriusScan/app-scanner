# Scanner Test Utilities

This directory contains test utilities and development tools for the Sirius Scanner.

## Utilities Overview

| Utility             | Purpose                     | Status |
| ------------------- | --------------------------- | ------ |
| `direct-nmap-test/` | Manual Nmap testing         | Active |
| `nse-fix-scripts/`  | Fix NSE script issues       | Active |
| `nse-reset/`        | Reset NSE repository        | Active |
| `nse-scan-test/`    | Test NSE script execution   | Active |
| `nse-test/`         | Test NSE sync functionality | Active |
| `scan-full-test/`   | Full scan pipeline test     | Active |
| `validate-nse-fix/` | Validate NSE script fixes   | Active |

## Utility Details

### `direct-nmap-test/`

**Purpose:** Direct testing of the Nmap integration without the full scan pipeline.

**Usage:**

```bash
go run cmd/direct-nmap-test/main.go -target 192.168.1.100
```

**Options:**

- `-target` - IP address to scan (default: 192.168.123.148)
- `-ports` - Port range to scan (default: from template)

### `nse-fix-scripts/`

**Purpose:** Utility for fixing common NSE script issues in the sirius-nse repository.

**Usage:**

```bash
go run cmd/nse-fix-scripts/main.go
```

**See:** `nse-fix-scripts/README.md` for detailed documentation.

### `nse-reset/`

**Purpose:** Reset the NSE repository to a clean state, useful after corrupted downloads or sync issues.

**Usage:**

```bash
go run cmd/nse-reset/main.go
```

**See:** `nse-reset/README.md` for detailed documentation.

### `nse-scan-test/`

**Purpose:** Test NSE script execution with specific protocols and targets.

**Usage:**

```bash
go run cmd/nse-scan-test/main.go -target 192.168.1.100 -protocols smb
```

**Options:**

- `-target` - IP address to scan
- `-protocols` - Protocols to test (e.g., smb, http, ssl)

**See:** `nse-scan-test/README.md` for detailed documentation.

### `nse-test/`

**Purpose:** Test the NSE synchronization functionality, ensuring scripts are properly synced from the sirius-nse repository.

**Usage:**

```bash
go run cmd/nse-test/main.go
```

**See:** `nse-test/README.md` for detailed documentation.

### `scan-full-test/`

**Purpose:** Full end-to-end test of the scan pipeline, including port enumeration and vulnerability scanning.

**Usage:**

```bash
go run cmd/scan-full-test/main.go -target 192.168.1.100
```

**Options:**

- `-target` - IP address to scan (default: 192.168.123.148)
- `-smb` - Focus on SMB vulnerabilities
- `-vulns` - Enable vulnerability scanning (default: true)
- `-debug` - Enable debug logging

**Pipeline:**

1. Port Discovery (Naabu)
2. Vulnerability Scanning (Nmap + NSE)

### `validate-nse-fix/`

**Purpose:** Validate that NSE script fixes were applied correctly.

**Usage:**

```bash
go run cmd/validate-nse-fix/main.go
```

## Common Workflows

### Testing a Full Scan

```bash
# Start with full pipeline test
go run cmd/scan-full-test/main.go -target 192.168.1.100 -debug

# If NSE issues occur, try:
go run cmd/validate-nse-fix/main.go
go run cmd/nse-fix-scripts/main.go

# Reset NSE if corrupted:
go run cmd/nse-reset/main.go
```

### Debugging Nmap Issues

```bash
# Direct Nmap test (bypasses pipeline)
go run cmd/direct-nmap-test/main.go -target 192.168.1.100

# Check NSE sync
go run cmd/nse-test/main.go
```

### Testing Protocol-Specific Scans

```bash
# Test SMB scanning
go run cmd/nse-scan-test/main.go -target 192.168.1.100 -protocols smb

# Test HTTP scanning
go run cmd/nse-scan-test/main.go -target 192.168.1.100 -protocols http
```

## Development Notes

- All utilities share the same module dependencies from `go.mod`
- Utilities are designed for development/testing, not production use
- Most utilities require a running ValKey instance for state management
- Some utilities require access to the sirius-nse repository

## Related Documentation

- [../README.md](../README.md) - Scanner overview
- [../SCAN-TYPES.md](../SCAN-TYPES.md) - Scan type reference
- [../PORT-RANGE-OPTIMIZATION.md](../PORT-RANGE-OPTIMIZATION.md) - Port range recommendations
