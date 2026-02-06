# Scanner Scan Types Reference

**Version:** 2.0  
**Last Updated:** 2026-01-24

## Overview

The Sirius Scanner supports four distinct scan types, each using specific tools and methodologies. **These are the canonical names that MUST be used in templates and API requests.**

## Canonical Scan Types

### 1. `fingerprint`

**Tool:** ping++ (placeholder)  
**Purpose:** Host liveness and OS detection  
**Description:** Determines if a host is alive and identifies its operating system family using TTL-based detection and protocol probing.

**When to use:**

- Pre-scan host validation
- Skip scanning dead hosts early
- OS-specific scan optimization

**Characteristics:**

- 📍 Host liveness detection
- 🖥️ TTL-based OS detection
- ⚡ Very fast (ICMP/TCP probes)
- 🚫 Skips dead hosts immediately

**Status:** Placeholder implementation - full ping++ integration coming soon.

**Example usage:**

```json
{
  "scan_options": {
    "scan_types": ["fingerprint", "enumeration", "vulnerability"],
    "port_range": ""
  }
}
```

### 2. `enumeration` / `port_scan`

**Tool:** NAABU  
**Purpose:** Fast port enumeration  
**Description:** Quickly identifies open ports on a target using NAABU's efficient scanning engine.

**When to use:**

- Initial reconnaissance
- Large IP ranges where speed matters
- When you only need to know which ports are open

**Characteristics:**

- ⚡ Fastest scan type
- 🎯 Port-focused (no service detection)
- 📊 Minimal resource usage
- ✅ Scales well to many hosts

**Note:** `port_scan` is an alias for `enumeration` for backward compatibility.

**Example usage:**

```json
{
  "scan_options": {
    "scan_types": ["enumeration"],
    "port_range": "1-1000"
  }
}
```

### 3. `vulnerability`

**Tool:** Nmap + NSE Scripts  
**Purpose:** Deep vulnerability scanning  
**Description:** Executes Nmap with NSE scripts to identify security vulnerabilities, outdated services, and misconfigurations.

**When to use:**

- Security assessments
- Vulnerability identification
- Compliance scanning
- Detailed service enumeration

**Characteristics:**

- 🔬 Deep security analysis
- 🛡️ CVE identification
- 📋 NSE script execution
- ⏱️ Slower but thorough
- 🎯 Requires known open ports

**Example usage:**

```json
{
  "scan_options": {
    "scan_types": ["vulnerability"],
    "port_range": "80,443,445,3389"
  }
}
```

## Common Scan Type Combinations

### Quick Assessment

```json
{
  "scan_types": ["enumeration", "vulnerability"],
  "port_range": "1-1000"
}
```

Fast port scan followed by targeted vulnerability assessment.

### Comprehensive Scan

```json
{
  "scan_types": ["fingerprint", "enumeration", "vulnerability"],
  "port_range": ""
}
```

Full reconnaissance: check host liveness, enumerate ports, scan for vulnerabilities.

### Vulnerability-Only

```json
{
  "scan_types": ["vulnerability"],
  "port_range": "445"
}
```

Target specific known ports for in-depth vulnerability scanning.

## Scan Type Execution Order

When multiple scan types are specified, they execute in sequence:

0. **fingerprint** (if specified) - Check if host is alive
1. **enumeration/port_scan** (if specified) - Find open ports
2. **vulnerability** (if specified) - Scan for vulnerabilities

Each phase can inform the next (e.g., fingerprint skips dead hosts, enumeration finds ports for vulnerability scanning).

## Port Range Interaction

Each scan type respects the `port_range` setting from the template:

| Scan Type       | Port Range Usage                            |
| --------------- | ------------------------------------------- |
| `fingerprint`   | N/A (uses ICMP/TCP probes)                  |
| `enumeration`   | NAABU scans specified ports                 |
| `vulnerability` | Nmap scans specified ports with NSE scripts |

## Invalid Scan Type Names

**DO NOT USE:**

- ❌ `discovery` → Removed (was RustScan)
- ❌ `service-detection` → Use `enumeration`
- ❌ `vuln-scan` → Use `vulnerability`
- ❌ `nmap` → Use `vulnerability`
- ❌ `naabu` → Use `enumeration`

**Why strict naming?**

- Ensures consistent behavior
- Enables proper tool routing
- Prevents configuration errors
- Makes logs clear and searchable

## System Template Examples

### Quick Template

```json
{
  "id": "quick",
  "name": "Quick Scan",
  "scan_options": {
    "scan_types": ["enumeration", "vulnerability"],
    "port_range": "top500"
  }
}
```

### High-Risk Template

```json
{
  "id": "high-risk",
  "name": "High Risk Scan",
  "scan_options": {
    "scan_types": ["fingerprint", "enumeration", "vulnerability"],
    "port_range": ""
  }
}
```

### All Template

```json
{
  "id": "all",
  "name": "Comprehensive Scan",
  "scan_options": {
    "scan_types": ["fingerprint", "enumeration", "vulnerability"],
    "port_range": "1-65535"
  }
}
```

## API Integration

### Creating Templates

**Correct:**

```typescript
POST /api/templates
{
  "name": "My Custom Template",
  "scan_options": {
    "scan_types": ["enumeration", "vulnerability"],
    "port_range": "1-1000"
  }
}
```

**Incorrect:**

```typescript
POST /api/templates
{
  "name": "My Custom Template",
  "scan_options": {
    "scan_types": ["discovery", "vuln-scan"], // ❌ WRONG - discovery removed
    "port_range": "1-1000"
  }
}
```

### Triggering Scans

**Correct:**

```typescript
POST /api/scans
{
  "targets": ["192.168.1.100"],
  "options": {
    "template_id": "high-risk",
    "scan_types": ["vulnerability"] // Override template if needed
  }
}
```

## Validation

The scanner validates scan types and will **reject** unrecognized names:

**Valid:**
✅ `fingerprint`  
✅ `enumeration`  
✅ `port_scan`  
✅ `vulnerability`

**Invalid:**
❌ `discovery` (removed)  
❌ Any other string value

**Error behavior:**

- Unknown scan types are logged as warnings
- Scan continues but skips invalid types
- Check logs for `⚠️ Unknown scan type` messages

## UI Integration

When building UI components for template creation:

```typescript
// types/scanner.ts
export enum ScanType {
  FINGERPRINT = "fingerprint",
  ENUMERATION = "enumeration",
  PORT_SCAN = "port_scan",
  VULNERABILITY = "vulnerability",
}

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  [ScanType.FINGERPRINT]: "Host Fingerprinting (ping++)",
  [ScanType.ENUMERATION]: "Port Enumeration (NAABU)",
  [ScanType.PORT_SCAN]: "Port Scan (NAABU)",
  [ScanType.VULNERABILITY]: "Vulnerability Scan (Nmap + NSE)",
};

export const SCAN_TYPE_DESCRIPTIONS: Record<ScanType, string> = {
  [ScanType.FINGERPRINT]: "Check host liveness and detect OS family",
  [ScanType.ENUMERATION]: "Fast port scanning to identify open ports",
  [ScanType.PORT_SCAN]: "Alias for enumeration",
  [ScanType.VULNERABILITY]:
    "Deep security scanning for vulnerabilities and CVEs",
};
```

```tsx
// UI Component
<Select label="Scan Types" multiple>
  <Option value="fingerprint">
    <strong>Host Fingerprinting</strong>
    <small>
      Check host liveness and OS detection with ping++ (coming soon)
    </small>
  </Option>
  <Option value="enumeration">
    <strong>Port Enumeration</strong>
    <small>Fast port scanning with NAABU</small>
  </Option>
  <Option value="vulnerability">
    <strong>Vulnerability Scan</strong>
    <small>Deep security scanning with Nmap + NSE</small>
  </Option>
</Select>
```

## Troubleshooting

### Scan Not Executing

**Symptom:** Scan completes instantly, no tool output

**Check:**

```bash
docker logs sirius-engine | grep "Unknown scan type"
```

**If you see:**

```
⚠️ Unknown scan type 'discovery' for 192.168.1.100
```

**Solution:** Update template to use new scan types (`discovery` has been removed).

### Port Range Ignored

**Symptom:** Scanner uses different ports than specified

**Check:**

1. Verify `port_range` is set in template
2. Check scan type is recognized (not skipped)
3. View Nmap command in logs for actual ports used

**Solution:** Ensure scan types are valid and port range follows format `"1-1000"` or `"80,443,8080"`.

## Testing

### Verify Scan Types

```bash
# Create test template
curl -X POST http://localhost:9001/api/templates \
  -H "Content-Type: application/json" \
  -d '{
    "id": "test-scan-types",
    "name": "Test Scan Types",
    "scan_options": {
      "scan_types": ["fingerprint", "enumeration", "vulnerability"],
      "port_range": "80,443"
    }
  }'

# Trigger scan
curl -X POST http://localhost:9001/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targets": [{"value": "192.168.1.100", "type": "single_ip"}],
    "options": {"template_id": "test-scan-types"}
  }'

# Check logs for execution
docker logs sirius-engine | grep "Phase"

# Expected output:
#   📍 Phase 0: Fingerprinting scan on 192.168.1.100
#   🔍 Phase 1: Port enumeration scan on 192.168.1.100
#   🎯 Phase 2: Vulnerability scan on 192.168.1.100
```

## Future Enhancements

### ping++ Integration (Coming Soon)

The `fingerprint` scan type will be fully implemented with the ping++ tool:

- ICMP ping probes for host liveness
- TTL-based OS detection (64=Linux/Mac, 128=Windows)
- TCP SYN probes for firewall-blocked ICMP
- SMB enumeration for Windows hosts (port 445)
- Template-based modular detection

### Other Potential Additions

1. **Scan Type Profiles**
   - Predefined combinations (quick, thorough, paranoid)
   - User-friendly names mapping to canonical types

2. **Conditional Execution**
   - Run `vulnerability` only if `enumeration` finds ports
   - Smart skip logic based on previous phases

3. **Custom Scan Types**
   - Allow plugins to register new scan types
   - Extensible scan type system

## References

- **NAABU**: https://github.com/projectdiscovery/naabu
- **Nmap**: https://nmap.org/
- **NSE Scripts**: https://nmap.org/book/nse.html
- **ping++**: /Users/oz/Projects/Sirius-Project/minor-projects/ping++ (in development)

## Changelog

### 2026-01-24 (v2.0)

- Removed `discovery` scan type (RustScan removed)
- Added `fingerprint` scan type placeholder for ping++
- Added `port_scan` as alias for `enumeration`
- Updated scan pipeline to Naabu-only for port discovery
- Updated examples and UI integration code

### 2025-10-25 (v1.0)

- Initial documentation
- Defined three canonical scan types
- Added UI integration examples
- Documented validation rules
