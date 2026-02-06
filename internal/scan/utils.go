package scan

import (
	"fmt"
	"net"
	"strings"
)

// ============================================================================
// String/Slice Helpers
// ============================================================================

// contains checks if a string slice contains a specific string
func contains(slice []string, str string) bool {
	for _, s := range slice {
		if s == str {
			return true
		}
	}
	return false
}

// containsAny checks if any item in a slice contains the target string (case-insensitive)
func containsAny(slice []string, target string) bool {
	for _, item := range slice {
		if strings.Contains(strings.ToLower(item), strings.ToLower(target)) {
			return true
		}
	}
	return false
}

// ============================================================================
// Severity Calculation
// ============================================================================

// calculateSeverity maps a risk score to a severity string.
func calculateSeverity(score float64) string {
	switch {
	case score < 1.0:
		return "informational"
	case score < 3.0:
		return "low"
	case score < 5.0:
		return "medium"
	case score < 7.0:
		return "high"
	case score < 9.0:
		return "critical"
	default:
		return "informational"
	}
}

// ============================================================================
// Network/IP Helpers
// ============================================================================

// expandCIDR takes a CIDR notation string and returns a list of IP addresses
func expandCIDR(cidr string) ([]string, error) {
	// Parse CIDR notation
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("invalid CIDR notation: %v", err)
	}

	// Get network details
	network := ipnet.IP.Mask(ipnet.Mask)
	broadcast := getLastIP(network, ipnet.Mask)

	// Calculate total addresses
	ones, bits := ipnet.Mask.Size()
	numAddresses := 1 << uint(bits-ones)

	// For very large networks, implement a safety check
	if numAddresses > 65536 { // Limit to /16 networks
		return nil, fmt.Errorf("CIDR range too large: %d addresses", numAddresses)
	}

	// Generate all IP addresses in the range
	var result []string
	for currentIP := network; !currentIP.Equal(broadcast); currentIP = getNextIP(currentIP) {
		// Skip network address
		if currentIP.Equal(network) {
			continue
		}
		result = append(result, currentIP.String())
	}

	return result, nil
}

// getNextIP returns the next IP address in sequence
func getNextIP(ip net.IP) net.IP {
	nextIP := make(net.IP, len(ip))
	copy(nextIP, ip)

	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] != 0 {
			break
		}
	}

	return nextIP
}

// getLastIP calculates the last IP address in a network
func getLastIP(network net.IP, mask net.IPMask) net.IP {
	lastIP := make(net.IP, len(network))
	copy(lastIP, network)

	for i := range mask {
		lastIP[i] |= ^mask[i]
	}

	return lastIP
}

// expandIPRange takes a range like "192.168.1.1-192.168.1.255" and returns a list of IPs
func expandIPRange(ipRange string) ([]string, error) {
	// Split the range into start and end IPs
	parts := strings.Split(ipRange, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid IP range format, expected start-end, got: %s", ipRange)
	}

	startIP := net.ParseIP(strings.TrimSpace(parts[0]))
	endIP := net.ParseIP(strings.TrimSpace(parts[1]))

	if startIP == nil || endIP == nil {
		return nil, fmt.Errorf("invalid IP address in range: %s", ipRange)
	}

	// Ensure start IP is less than end IP
	if !isIPLessThan(startIP, endIP) {
		return nil, fmt.Errorf("start IP must be less than end IP")
	}

	// Calculate number of IPs in range
	numIPs := ipToUint32(endIP) - ipToUint32(startIP) + 1
	if numIPs > 65536 { // Limit to reasonable range
		return nil, fmt.Errorf("IP range too large: %d addresses", numIPs)
	}

	var result []string
	for currentIP := startIP; !currentIP.Equal(endIP); currentIP = getNextIP(currentIP) {
		result = append(result, currentIP.String())
	}
	result = append(result, endIP.String()) // Add the last IP

	return result, nil
}

// isIPLessThan compares two IP addresses
func isIPLessThan(ip1, ip2 net.IP) bool {
	return ipToUint32(ip1) < ipToUint32(ip2)
}

// ipToUint32 converts an IPv4 address to uint32
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// validateIP checks if a string is a valid IP address
func validateIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

// validateCIDR checks if a string is valid CIDR notation
func validateCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}
