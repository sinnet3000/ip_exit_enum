package discovery

import "net/netip"

// cgnatPrefix is the shared address space reserved for carrier-grade NAT
// (RFC 6598). These addresses are not public egress addresses, although
// netip.Addr.IsGlobalUnicast reports them as global unicast.
var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

// normalizeEgressAddr validates an address observed from an untrusted HTTP or
// STUN service and returns its canonical public form. IPv4-mapped IPv6
// addresses are unmapped so both protocols report the same representation.
//
// Documentation ranges (for example 203.0.113.0/24) remain valid: this
// validator rejects non-public address space, not test fixtures.
func normalizeEgressAddr(addr netip.Addr) (netip.Addr, bool) {
	if !addr.IsValid() {
		return netip.Addr{}, false
	}

	addr = addr.Unmap()
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return netip.Addr{}, false
	}
	if addr.Is4() && cgnatPrefix.Contains(addr) {
		return netip.Addr{}, false
	}

	return addr, true
}

// normalizeEgressIP parses and validates a candidate address, returning its
// canonical string form when it is a public egress address.
func normalizeEgressIP(candidate string) (string, bool) {
	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return "", false
	}
	addr, ok := normalizeEgressAddr(addr)
	if !ok {
		return "", false
	}
	return addr.String(), true
}
