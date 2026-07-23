// Package netpolicy identifies network destinations that require explicit
// operator approval because they commonly expose machine credentials or
// cloud control-plane data.
package netpolicy

import "net/netip"

var sensitiveServiceAddresses = map[netip.Addr]struct{}{
	netip.MustParseAddr("100.100.100.200"): {},
	netip.MustParseAddr("168.63.129.16"):   {},
	netip.MustParseAddr("169.254.169.254"): {},
	netip.MustParseAddr("169.254.170.2"):   {},
	netip.MustParseAddr("fd00:ec2::254"):   {},
}

// IsSensitiveServiceAddress reports whether address is a well-known cloud
// metadata, workload-credential, or platform service endpoint.
func IsSensitiveServiceAddress(address netip.Addr) bool {
	_, sensitive := sensitiveServiceAddresses[address.Unmap()]
	return sensitive
}
