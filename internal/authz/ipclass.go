package authz

import "net/netip"

// nonPublic lists IPv4 ranges that are never public external addresses:
// "this network", private, shared (carrier NAT), loopback, link-local, IETF
// protocol assignments, benchmarking, multicast, reserved, and broadcast.
// The RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24,
// 203.0.113.0/24) are deliberately absent: the mock environment uses them as
// its external addresses, as the specification's demo does.
var nonPublic = [...]netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
}

// PublicExternal reports whether a is a public IPv4 address outside every
// internal range the inventory lists.
func PublicExternal(a netip.Addr, internal []netip.Prefix) bool {
	if !a.Is4() || a.Zone() != "" {
		return false
	}
	for _, p := range nonPublic {
		if p.Contains(a) {
			return false
		}
	}
	for _, p := range internal {
		if p.Contains(a) {
			return false
		}
	}
	return true
}
