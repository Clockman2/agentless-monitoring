package netpolicy

import (
	"net/netip"
	"testing"
)

func TestIsSensitiveServiceAddress(t *testing.T) {
	for _, value := range []string{
		"100.100.100.200",
		"168.63.129.16",
		"169.254.169.254",
		"169.254.170.2",
		"fd00:ec2::254",
	} {
		if !IsSensitiveServiceAddress(netip.MustParseAddr(value)) {
			t.Errorf("%s was not recognized as sensitive", value)
		}
	}
	if IsSensitiveServiceAddress(netip.MustParseAddr("203.0.113.10")) {
		t.Fatal("documentation address was recognized as sensitive")
	}
}
