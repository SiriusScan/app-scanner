# Sirius Vulnerability Scanner

**General-purpose network vulnerability scanner** with sequential port discovery pipeline.

## Architecture

The scanner uses a **three-phase scanning pipeline**:

```
Discovery (RustScan) → Enumeration (Naabu) → Vulnerability (Nmap)
     ↓                       ↓                        ↓
 Find open ports      Detailed enumeration     Scan discovered ports
```

### Key Features

✅ **Port Discovery Pipeline** - Nmap only scans ports discovered by RustScan/Naabu  
✅ **Protocol Agnostic** - No hardcoded protocol-specific logic  
✅ **Template-Based** - Customizable scan profiles with NSE scripts  
✅ **Source Attribution** - Complete audit trail of scan tools and configurations  
✅ **Parallel Execution** - Worker pool for concurrent host scanning

## Quick Start

### Running a Scan

```bash
# Scanner runs automatically in sirius-engine container
docker logs -f sirius-engine

# Trigger scan via UI:
# http://localhost:3000/scanner → Select template → Start scan
```

### Scan Types

| Scan Type       | Tool     | Purpose                    |
| --------------- | -------- | -------------------------- |
| `enumeration`   | Naabu    | Fast port enumeration      |
| `discovery`     | RustScan | Host and service discovery |
| `vulnerability` | Nmap+NSE | Vulnerability scanning     |

**See:** [SCAN-TYPES.md](SCAN-TYPES.md) for detailed information.

## Port Discovery Pipeline

### How It Works

1. **Discovery Phase** (if enabled):

   - RustScan quickly finds open ports
   - Example: discovers [80, 443, 445, 3389]

2. **Enumeration Phase** (if enabled):

   - Naabu performs detailed port enumeration
   - Merges results with discovery phase

3. **Vulnerability Phase**:
   - Nmap scans ONLY discovered ports
   - Falls back to template `port_range` if no ports discovered
   - Skips scan if no ports and no template range

**See:** [PORT-PIPELINE-IMPLEMENTED.md](PORT-PIPELINE-IMPLEMENTED.md) for architecture details.

## Creating Scan Templates

### Recommended: With Discovery

```json
{
  "name": "Web Application Scan",
  "type": "custom",
  "scan_options": {
    "scan_types": ["discovery", "vulnerability"],
    "port_range": "", // Empty - uses discovered ports
    "parallel": true
  },
  "enabled_scripts": ["http-vuln-*", "ssl-*"]
}
```

**Benefits:**

- ✅ Only scans open ports (fast!)
- ✅ No wasted time on closed ports
- ✅ Adapts to target configuration

### Alternative: Without Discovery

```json
{
  "name": "SMB Direct Scan",
  "type": "custom",
  "scan_options": {
    "scan_types": ["vulnerability"],
    "port_range": "139,445", // Explicit ports
    "parallel": true
  },
  "enabled_scripts": ["smb-vuln-*", "smb2-*"]
}
```

**Use when:**

- You know exact ports to scan
- Targeting specific services
- Fastest for known configurations

**See:** [PORT-RANGE-OPTIMIZATION.md](PORT-RANGE-OPTIMIZATION.md) for port recommendations by protocol.

## Performance

### Port Pipeline vs Traditional

| Approach                                 | Ports Scanned      | Scan Time   |
| ---------------------------------------- | ------------------ | ----------- |
| **Port Pipeline** (discovery → vuln)     | 4 discovered ports | ~1 minute   |
| **Traditional** (vuln only with 1-65535) | All 65,535 ports   | ~30 minutes |

**Result: 30x faster for typical scans**

## Development

### Project Structure

```
app-scanner/
├── cmd/              # Test utilities
├── internal/
│   ├── scan/        # Core scanning logic
│   │   ├── manager.go      # Scan orchestration
│   │   ├── factory.go      # Tool factory
│   │   ├── strategies.go   # Scan strategies
│   │   └── worker_pool.go  # Parallel execution
│   ├── nse/         # NSE script management
│   └── templates/   # Template management
├── modules/
│   ├── nmap/        # Nmap integration
│   ├── rustscan/    # RustScan integration
│   └── naabu/       # Naabu integration
└── pkg/
    ├── models/      # Data models
    ├── queue/       # RabbitMQ integration
    └── store/       # ValKey integration
```

### Building

```bash
# In container
docker exec sirius-engine bash -c "cd /app-scanner && go build ."

# Local (requires Go 1.21+)
cd /Users/oz/Projects/Sirius-Project/minor-projects/app-scanner
go build .
```

### Testing

```bash
# Run specific test
go run cmd/scan-full-test/main.go

# Validate NSE scripts
go run cmd/validate-nse-fix/main.go
```

## Configuration

### Environment Variables

```bash
# RabbitMQ
RABBITMQ_HOST=sirius-rabbitmq
RABBITMQ_PORT=5672
RABBITMQ_QUEUE=scan_requests

# ValKey (Redis)
VALKEY_ADDR=sirius-valkey:6379

# API
GO_API_URL=http://sirius-go-api:8080

# Scanning
NMAP_PATH=/usr/bin/nmap
NSE_SCRIPTS_DIR=/opt/sirius/nse/sirius-nse
```

## Troubleshooting

### Scans Taking Too Long

**Symptom:** Scan runs for 10+ minutes  
**Cause:** Scanning too many ports  
**Solution:**

1. Enable `discovery` scan type to find open ports first
2. Use protocol-specific port ranges (see [PORT-RANGE-OPTIMIZATION.md](PORT-RANGE-OPTIMIZATION.md))
3. Avoid `port_range: "1-65535"` unless necessary

### No Ports Discovered

**Symptom:** "No ports discovered and no port_range - skipping"  
**Cause:** Target has no open ports OR discovery failed  
**Solution:**

1. Verify target is accessible: `docker exec sirius-engine ping <target>`
2. Check firewall rules
3. Add fallback `port_range` in template

### Nmap Errors

**Symptom:** "failed to build script flag" or "no port range specified"  
**Cause:** Template misconfiguration  
**Solution:**

1. Ensure template has `enabled_scripts` or `port_range`
2. Check NSE scripts are valid: `go run cmd/validate-nse-fix/main.go`
3. Review scanner logs: `docker logs sirius-engine`

## Documentation

- [SCAN-TYPES.md](SCAN-TYPES.md) - Canonical scan types reference
- [PORT-RANGE-OPTIMIZATION.md](PORT-RANGE-OPTIMIZATION.md) - Port range recommendations
- [PORT-PIPELINE-IMPLEMENTED.md](PORT-PIPELINE-IMPLEMENTED.md) - Architecture deep dive
- [ARCHITECTURAL-FIX-PORT-PIPELINE.md](ARCHITECTURAL-FIX-PORT-PIPELINE.md) - Technical implementation details

## Key Design Principles

1. **General Purpose** - No protocol-specific hardcoded logic
2. **Discovery-Driven** - Nmap scans discovered ports, not arbitrary ranges
3. **Template-Based** - Users control scan behavior via templates
4. **Performance-Focused** - Only scan what's necessary
5. **Observable** - Comprehensive logging and audit trails

---

**Built with:** Go, Nmap, RustScan, Naabu, RabbitMQ, ValKey
