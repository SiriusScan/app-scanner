# Scanner Port Range Optimization Guide

## The Problem

**Default port range `1-65535` causes extremely slow scans:**
- Full port scan takes 30+ minutes per host
- Most services run on well-known ports
- Protocol-specific scans don't need all ports

## Recommended Port Ranges by Scan Type

### SMB/Windows Scanning
```json
{
  "port_range": "135,139,445,3389"
}
```
**Ports:**
- `135` - MS RPC
- `139` - NetBIOS Session Service
- `445` - SMB over TCP (primary)
- `3389` - RDP (Remote Desktop)

**Scan time:** ~30 seconds vs 30+ minutes

### Web Application Scanning
```json
{
  "port_range": "80,443,8080,8443"
}
```
**Ports:**
- `80` - HTTP
- `443` - HTTPS
- `8080` - Alternative HTTP
- `8443` - Alternative HTTPS

### Database Scanning
```json
{
  "port_range": "1433,3306,5432,5984,6379,9200,27017"
}
```
**Ports:**
- `1433` - MS SQL Server
- `3306` - MySQL
- `5432` - PostgreSQL
- `5984` - CouchDB
- `6379` - Redis
- `9200` - Elasticsearch
- `27017` - MongoDB

### Common Services
```json
{
  "port_range": "21,22,23,25,53,80,110,143,443,445,3389"
}
```
**Ports:**
- `21` - FTP
- `22` - SSH
- `23` - Telnet
- `25` - SMTP
- `53` - DNS
- `80` - HTTP
- `110` - POP3
- `143` - IMAP
- `443` - HTTPS
- `445` - SMB
- `3389` - RDP

### Fast Discovery (Top 1000 Ports)
```json
{
  "port_range": "1-1000"
}
```
**Use case:** Quick host discovery
**Scan time:** ~2-5 minutes

### Full Scan (Use Sparingly)
```json
{
  "port_range": "1-65535"
}
```
**⚠️ Warning:** Only use for comprehensive audits
**Scan time:** 30+ minutes per host

## Performance Impact

| Port Range | Ports Scanned | Approximate Time |
|------------|---------------|------------------|
| `445` | 1 | ~5 seconds |
| `135,139,445,3389` | 4 | ~30 seconds |
| `1-1000` | 1,000 | ~2-5 minutes |
| `1-10000` | 10,000 | ~10-15 minutes |
| `1-65535` | 65,535 | ~30-60 minutes |

## When Scans Hang

**Symptoms:**
- Scan runs for 10+ minutes
- No results returned
- High CPU usage

**Causes:**
1. ❌ Port range too broad (`1-65535`)
2. ❌ Target ports are filtered/blocked
3. ❌ NSE scripts timing out on non-responsive ports

**Solutions:**
1. ✅ Use protocol-specific port ranges
2. ✅ Quick test with minimal ports first
3. ✅ Check if target ports are open: `nmap -Pn -p <ports> <target>`

## Example: SMB Scan Optimization

### ❌ Before (Slow)
```json
{
  "name": "SMB Vulns",
  "scan_options": {
    "port_range": "1-65535",
    "scan_types": ["discovery", "vulnerability"]
  },
  "enabled_scripts": ["smb-*"]
}
```
**Result:** 30+ minute scan, most ports irrelevant

### ✅ After (Fast)
```json
{
  "name": "SMB Vulns",
  "scan_options": {
    "port_range": "135,139,445,3389",
    "scan_types": ["discovery", "vulnerability"]
  },
  "enabled_scripts": ["smb-*"]
}
```
**Result:** ~30 second scan, focused on SMB ports

## UI Improvements Needed

**Current:** Default template uses `1-65535`
**Proposed:** Smart defaults based on selected scripts

```typescript
// When user selects SMB scripts → suggest "135,139,445,3389"
// When user selects HTTP scripts → suggest "80,443,8080,8443"
// When user selects database scripts → suggest relevant DB ports
```

## Migration Script for Existing Templates

```bash
#!/bin/bash
# Fix overly-broad port ranges in existing templates

VALKEY_CLI="docker exec sirius-valkey valkey-cli"

# Update all SMB templates
for key in $($VALKEY_CLI KEYS "scan:template:*"); do
    template=$($VALKEY_CLI GET "$key")
    
    # Check if template uses SMB scripts and full port range
    if echo "$template" | grep -q "smb-" && echo "$template" | grep -q '"port_range": "1-65535"'; then
        echo "Fixing: $key"
        updated=$(echo "$template" | sed 's/"port_range": "1-65535"/"port_range": "135,139,445,3389"/')
        echo "$updated" | $VALKEY_CLI -x SET "$key"
    fi
done
```

---

**Related Documentation:**
- [SCAN-TYPES.md](SCAN-TYPES.md) - Canonical scan types
- [SCANNING-FIXES-SUMMARY.md](SCANNING-FIXES-SUMMARY.md) - Recent fixes

