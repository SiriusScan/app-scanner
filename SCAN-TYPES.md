# Scanner Scan Types Reference

**Version:** 1.0  
**Last Updated:** 2025-10-25

## Overview

The Sirius Scanner supports three distinct scan types, each using specific tools and methodologies. **These are the canonical names that MUST be used in templates and API requests.**

## Canonical Scan Types

### 1. `enumeration`

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

**Example usage:**

```json
{
  "scan_options": {
    "scan_types": ["enumeration"],
    "port_range": "1-1000"
  }
}
```

### 2. `discovery`

**Tool:** RustScan  
**Purpose:** Host and service discovery  
**Description:** Discovers active hosts, open ports, and attempts basic service identification.

**When to use:**

- Comprehensive host discovery
- Service identification needed
- Balanced speed vs. detail
- Unknown network topology

**Characteristics:**

- 🔍 Host discovery + port scanning
- 🏷️ Basic service detection
- ⚡ Fast (faster than Nmap)
- 🎯 Good for initial reconnaissance

**Example usage:**

```json
{
  "scan_options": {
    "scan_types": ["discovery"],
    "port_range": "1-10000"
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
  "scan_types": ["enumeration", "discovery", "vulnerability"],
  "port_range": "1-10000"
}
```

Full reconnaissance: enumerate ports, discover services, scan for vulnerabilities.

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

1. **enumeration** (if specified)
2. **discovery** (if specified)
3. **vulnerability** (if specified)

Each phase can inform the next (e.g., enumeration finds ports for discovery).

## Port Range Interaction

Each scan type respects the `port_range` setting from the template:

| Scan Type       | Port Range Usage                            |
| --------------- | ------------------------------------------- |
| `enumeration`   | NAABU scans specified ports                 |
| `discovery`     | RustScan scans specified ports              |
| `vulnerability` | Nmap scans specified ports with NSE scripts |

## Invalid Scan Type Names

**DO NOT USE:**

- ❌ `service-detection` → Use `discovery`
- ❌ `vuln-scan` → Use `vulnerability`
- ❌ `port-scan` → Use `enumeration`
- ❌ `nmap` → Use `vulnerability`
- ❌ `rustscan` → Use `discovery`
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
    "scan_types": ["enumeration", "discovery", "vulnerability"],
    "port_range": "1-10000"
  }
}
```

### All Template

```json
{
  "id": "all",
  "name": "Comprehensive Scan",
  "scan_options": {
    "scan_types": ["enumeration", "discovery", "vulnerability"],
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
    "scan_types": ["service-detection", "vuln-scan"], // ❌ WRONG
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
✅ `enumeration`  
✅ `discovery`  
✅ `vulnerability`

**Invalid:**
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
  ENUMERATION = "enumeration",
  DISCOVERY = "discovery",
  VULNERABILITY = "vulnerability",
}

export const SCAN_TYPE_LABELS: Record<ScanType, string> = {
  [ScanType.ENUMERATION]: "Port Enumeration (NAABU)",
  [ScanType.DISCOVERY]: "Service Discovery (RustScan)",
  [ScanType.VULNERABILITY]: "Vulnerability Scan (Nmap + NSE)",
};

export const SCAN_TYPE_DESCRIPTIONS: Record<ScanType, string> = {
  [ScanType.ENUMERATION]: "Fast port scanning to identify open ports",
  [ScanType.DISCOVERY]: "Discover hosts and services with basic identification",
  [ScanType.VULNERABILITY]:
    "Deep security scanning for vulnerabilities and CVEs",
};
```

```tsx
// UI Component
<Select label="Scan Types" multiple>
  <Option value="enumeration">
    <strong>Port Enumeration</strong>
    <small>Fast port scanning with NAABU</small>
  </Option>
  <Option value="discovery">
    <strong>Service Discovery</strong>
    <small>Host and service discovery with RustScan</small>
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
⚠️ Unknown scan type 'service-detection' for 192.168.1.100
```

**Solution:** Update template to use canonical scan type names.

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
      "scan_types": ["enumeration", "discovery", "vulnerability"],
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
docker logs sirius-engine | grep "Running scan type"

# Expected output:
#   → Running scan type 'enumeration' for 192.168.1.100
#   → Running scan type 'discovery' for 192.168.1.100
#   → Running scan type 'vulnerability' for 192.168.1.100
```

## Future Enhancements

Potential additions to scan type system:

1. **Scan Type Profiles**

   - Predefined combinations (quick, thorough, paranoid)
   - User-friendly names mapping to canonical types

2. **Conditional Execution**

   - Run `vulnerability` only if `discovery` finds services
   - Smart skip logic based on previous phases

3. **Parallel Execution**

   - Run multiple scan types simultaneously
   - Requires careful resource management

4. **Custom Scan Types**
   - Allow plugins to register new scan types
   - Extensible scan type system

## References

- **NAABU**: https://github.com/projectdiscovery/naabu
- **RustScan**: https://github.com/RustScan/RustScan
- **Nmap**: https://nmap.org/
- **NSE Scripts**: https://nmap.org/book/nse.html

## Changelog

### 2025-10-25

- Initial documentation
- Defined three canonical scan types
- Added UI integration examples
- Documented validation rules
