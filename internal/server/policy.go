package server

import "net/netip"

func forbiddenIP(ip netip.Addr) bool {
	return !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast()
}

// DestinationAllowed exposes the default destination policy for validation and tests.
func DestinationAllowed(ip netip.Addr, allowPrivate bool) bool {
	return allowPrivate || !forbiddenIP(ip.Unmap())
}
