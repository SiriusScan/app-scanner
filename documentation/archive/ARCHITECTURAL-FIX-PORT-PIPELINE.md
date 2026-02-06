# CRITICAL: Port Discovery → Vulnerability Scanning Pipeline

## The Fundamental Problem

**Current Architecture (BROKEN):**

```go
// scanIP in manager.go - lines 434-451
for _, scanType := range sm.currentScanOptions.ScanTypes {
    switch scanType {
    case "enumeration":
        sm.runEnumeration(ip)  // Finds ports [80, 443, 445] ✅
    case "discovery":
        sm.runDiscovery(ip)    // Finds ports [80, 443, 445] ✅
    case "vulnerability":
        sm.runVulnerability(ip) // Scans ports "1-65535" ❌❌❌
    }
}
```

**Each scan type runs INDEPENDENTLY with NO data flow between them!**

### What Currently Happens

1. **RustScan/Naabu** discovers open ports: `[80, 443, 445]`

   - Stores results in database ✅
   - Stores results in ValKey ✅
   - Returns results... **but nothing uses them** ❌

2. **Nmap vulnerability scan** runs with:
   ```go
   // Line 644: Uses template's port_range
   nmapStrat.PortRange = sm.currentScanOptions.PortRange // "1-65535" ❌
   ```
   - **Ignores discovered ports completely** ❌
   - Scans all 65,535 ports (30+ minutes) ❌
   - Wastes time on closed ports ❌

## The Correct Architecture

**Port Discovery → Vulnerability Pipeline:**

```
┌─────────────────┐
│  1. Discovery   │
│  (RustScan)     │ → Finds: [80, 443, 445, 3389]
└────────┬────────┘
         │ discovered_ports
         ▼
┌─────────────────┐
│ 2. Enumeration  │
│    (Naabu)      │ → Enriches: [80→HTTP, 443→HTTPS, 445→SMB, 3389→RDP]
└────────┬────────┘
         │ enriched_ports
         ▼
┌─────────────────┐
│ 3. Vulnerability│
│     (Nmap)      │ → Scans ONLY: 80,443,445,3389 (30 seconds) ✅
└─────────────────┘
```

## Required Changes

### Change 1: Make `scanIP` Sequential with Port Pipeline

**Current (WRONG):**

```go
// Each scan type is independent
for _, scanType := range sm.currentScanOptions.ScanTypes {
    switch scanType {
    case "discovery":
        sm.runDiscovery(ip)
    case "vulnerability":
        sm.runVulnerability(ip) // Doesn't know about discovered ports!
    }
}
```

**Fixed (CORRECT):**

```go
// Sequential pipeline: discovery → enumeration → vulnerability
func (sm *ScanManager) scanIP(ip string) {
    var discoveredPorts []int

    // Phase 1: Port Discovery
    if contains(sm.currentScanOptions.ScanTypes, "discovery") {
        ports, err := sm.runDiscovery(ip)
        if err == nil && len(ports) > 0 {
            discoveredPorts = ports
            log.Printf("✅ Discovered %d open ports for %s", len(ports), ip)
        }
    }

    // Phase 2: Port Enumeration (enriches discovery)
    if contains(sm.currentScanOptions.ScanTypes, "enumeration") {
        ports, err := sm.runEnumeration(ip)
        if err == nil && len(ports) > 0 {
            // Merge or replace discovered ports
            if len(discoveredPorts) == 0 {
                discoveredPorts = ports
            }
            log.Printf("✅ Enumerated %d ports for %s", len(ports), ip)
        }
    }

    // Phase 3: Vulnerability Scanning (ONLY on discovered ports)
    if contains(sm.currentScanOptions.ScanTypes, "vulnerability") {
        if len(discoveredPorts) > 0 {
            // Convert ports to string: "80,443,445,3389"
            portList := portsToString(discoveredPorts)
            log.Printf("🎯 Vulnerability scan will target discovered ports: %s", portList)

            // Override template's port_range with discovered ports
            sm.runVulnerabilityWithPorts(ip, portList)
        } else {
            log.Printf("⚠️  No ports discovered, skipping vulnerability scan for %s", ip)
        }
    }
}
```

### Change 2: Update `runDiscovery` to Return Discovered Ports

**Current:**

```go
func (sm *ScanManager) runDiscovery(ip string) error {
    discoveryResults, err := discoveryStrategy.Execute(ip)
    // Stores results but doesn't return them
    return nil
}
```

**Fixed:**

```go
func (sm *ScanManager) runDiscovery(ip string) ([]int, error) {
    discoveryResults, err := discoveryStrategy.Execute(ip)
    if err != nil {
        return nil, err
    }

    // Extract port IDs
    ports := make([]int, len(discoveryResults.Ports))
    for i, port := range discoveryResults.Ports {
        ports[i] = port.ID
    }

    return ports, nil
}
```

### Change 3: Update `runVulnerability` to Accept Specific Ports

**Current:**

```go
func (sm *ScanManager) runVulnerability(ip string) error {
    // Uses template's port_range (e.g., "1-65535")
    vulnStrategy := sm.toolFactory.CreateTool("vulnerability")
    vulnResults, err := vulnStrategy.Execute(ip)
    // ...
}
```

**Fixed:**

```go
func (sm *ScanManager) runVulnerabilityWithPorts(ip string, portList string) error {
    // Override port range with discovered ports
    originalPortRange := sm.currentScanOptions.PortRange
    sm.currentScanOptions.PortRange = portList

    log.Printf("🎯 Scanning %s on discovered ports: %s (template had: %s)",
        ip, portList, originalPortRange)

    vulnStrategy := sm.toolFactory.CreateTool("vulnerability")
    vulnResults, err := vulnStrategy.Execute(ip)

    // Restore original port range
    sm.currentScanOptions.PortRange = originalPortRange

    return err
}
```

### Change 4: Add Helper Functions

```go
// portsToString converts []int{80, 443, 445} to "80,443,445"
func portsToString(ports []int) string {
    strPorts := make([]string, len(ports))
    for i, port := range ports {
        strPorts[i] = strconv.Itoa(port)
    }
    return strings.Join(strPorts, ",")
}

// contains checks if a slice contains a string
func contains(slice []string, item string) bool {
    for _, s := range slice {
        if s == item {
            return true
        }
    }
    return false
}
```

## Performance Impact

### Before (Current)

```
Discovery: Finds [80, 443, 445, 3389] in 30 seconds
Vulnerability: Scans 1-65535 in 30+ minutes ❌
Total: ~31 minutes
```

### After (Fixed)

```
Discovery: Finds [80, 443, 445, 3389] in 30 seconds
Vulnerability: Scans 80,443,445,3389 in 30 seconds ✅
Total: ~1 minute (31x faster!)
```

## Template Implications

**After this fix, templates should:**

- ✅ **NOT specify `port_range` for vulnerability scans** (use discovered ports)
- ✅ **Specify `port_range` ONLY for standalone enumeration** (when no discovery phase)
- ✅ **Focus on `enabled_scripts`** for protocol-specific vulnerability checks

**Example template (SMB):**

```json
{
  "name": "SMB Vulns",
  "scan_options": {
    "scan_types": ["discovery", "vulnerability"],
    "port_range": "", // Empty! Use discovered ports ✅
    "parallel": true
  },
  "enabled_scripts": ["smb-vuln-*", "smb2-*"]
}
```

**If user wants standalone vuln scan without discovery:**

```json
{
  "name": "SMB Vulns (Direct)",
  "scan_options": {
    "scan_types": ["vulnerability"],
    "port_range": "139,445", // ✅ Only specify when NO discovery phase
    "parallel": true
  },
  "enabled_scripts": ["smb-vuln-*"]
}
```

## Fallback Behavior

**If no ports discovered:**

1. ✅ Skip vulnerability scan (log warning)
2. OR use template's `port_range` as fallback
3. OR use protocol-specific defaults based on scripts

**Proposed logic:**

```go
if len(discoveredPorts) > 0 {
    // Use discovered ports (best)
    portList = portsToString(discoveredPorts)
} else if sm.currentScanOptions.PortRange != "" {
    // Fallback to template port_range
    portList = sm.currentScanOptions.PortRange
    log.Printf("⚠️  No ports discovered, using template port_range: %s", portList)
} else {
    // Skip vulnerability scan
    log.Printf("⚠️  No ports discovered and no port_range specified, skipping vulnerability scan")
    return nil
}
```

## Migration Path

1. ✅ **Implement port pipeline** in backend
2. ✅ **Update existing templates** to remove `port_range` for vuln scans
3. ✅ **Update UI** to hide `port_range` when `vulnerability` scan includes `discovery`
4. ✅ **Test with real targets** to verify performance improvement

## Files to Modify

1. `internal/scan/manager.go`

   - Refactor `scanIP()` to sequential pipeline
   - Update `runDiscovery()` to return ports
   - Update `runEnumeration()` to return ports
   - Create `runVulnerabilityWithPorts()` method
   - Add helper functions

2. `internal/scan/factory.go`

   - Update `CreateTool()` to accept optional port override

3. UI Templates
   - Update template editor to explain port_range behavior
   - Add tooltip: "Leave empty to use discovered ports"

---

**This is the CORRECT fix. The UI default change was just a band-aid.**
