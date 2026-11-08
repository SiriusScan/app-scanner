package scan

import "testing"

func TestExpandCIDRAddressLimit(t *testing.T) {
	for _, cidr := range []string{
		"invalid", "192.0.2.0/33", "0.0.0.0/0", "10.0.0.0/15",
		"::/0", "2001:db8::/64", "2001:db8::/65", "2001:db8::/96", "2001:db8::/111",
	} {
		t.Run(cidr, func(t *testing.T) {
			ips, err := expandCIDR(cidr)
			if err == nil || ips != nil {
				t.Fatalf("expandCIDR(%q) returned %d addresses and error %v; want nil and an error", cidr, len(ips), err)
			}
		})
	}
}

func TestExpandCIDRBoundedNetworks(t *testing.T) {
	// Preserve the existing exclusion of the first and last address while
	// testing that both address families accept exactly the allowed size.
	tests := []struct {
		cidr        string
		count       int
		first, last string
	}{
		{"192.0.2.5/30", 2, "192.0.2.5", "192.0.2.6"},
		{"10.0.0.0/16", 65534, "10.0.0.1", "10.0.255.254"},
		{"2001:db8::/126", 2, "2001:db8::1", "2001:db8::2"},
		{"2001:db8::/112", 65534, "2001:db8::1", "2001:db8::fffe"},
	}
	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			ips, err := expandCIDR(tt.cidr)
			if err != nil {
				t.Fatal(err)
			}
			if len(ips) != tt.count {
				t.Fatalf("got %d addresses; want %d", len(ips), tt.count)
			}
			if ips[0] != tt.first || ips[len(ips)-1] != tt.last {
				t.Fatalf("got endpoints %q and %q; want %q and %q", ips[0], ips[len(ips)-1], tt.first, tt.last)
			}
		})
	}
}

func TestExpandIPRangeRejectsInvalidOrOversizedRanges(t *testing.T) {
	for _, value := range []string{
		"invalid", "192.0.2.1-invalid", "192.0.2.1-192.0.2.2-192.0.2.3",
		"192.0.2.2-192.0.2.1", "192.0.2.1-192.0.2.1",
		"0.0.0.0-255.255.255.255", "0.0.0.0-0.1.0.0",
		"2001:db8::1-2001:db8::2", "::1-0.0.0.1", "0.0.0.1-::1",
	} {
		t.Run(value, func(t *testing.T) {
			ips, err := expandIPRange(value)
			if err == nil || ips != nil {
				t.Fatalf("expandIPRange(%q) returned %d addresses and error %v; want nil and an error", value, len(ips), err)
			}
		})
	}
}

func TestExpandIPRangeBoundaries(t *testing.T) {
	tests := []struct {
		value       string
		count       int
		first, last string
	}{
		{"192.0.2.1-192.0.2.2", 2, "192.0.2.1", "192.0.2.2"},
		{" 192.0.2.254 - 192.0.3.1 ", 4, "192.0.2.254", "192.0.3.1"},
		{"0.0.0.0-0.0.255.255", 65536, "0.0.0.0", "0.0.255.255"},
		{"255.255.255.254-255.255.255.255", 2, "255.255.255.254", "255.255.255.255"},
		{"::ffff:192.0.2.1-::ffff:192.0.2.2", 2, "192.0.2.1", "192.0.2.2"},
	}
	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			ips, err := expandIPRange(tt.value)
			if err != nil {
				t.Fatal(err)
			}
			if len(ips) != tt.count {
				t.Fatalf("got %d addresses; want %d", len(ips), tt.count)
			}
			if ips[0] != tt.first || ips[len(ips)-1] != tt.last {
				t.Fatalf("got endpoints %q and %q; want %q and %q", ips[0], ips[len(ips)-1], tt.first, tt.last)
			}
		})
	}
}
