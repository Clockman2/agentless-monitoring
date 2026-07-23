package discovery

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
)

func TestParseTargetAcceptsPublicIPv4CIDR(t *testing.T) {
	target, err := ParseTarget("192.168.20.99/30")
	if err != nil {
		t.Fatalf("ParseTarget() error = %v", err)
	}
	if got := target.Canonical; got != "192.168.20.96/30" {
		t.Fatalf("canonical target = %q, want 192.168.20.96/30", got)
	}
	if len(target.Addresses) != 2 || target.Addresses[0].String() != "192.168.20.97" {
		t.Fatalf("addresses = %#v", target.Addresses)
	}

	publicTarget, err := ParseTarget("203.0.113.0/30")
	if err != nil {
		t.Fatalf("ParseTarget(public) error = %v", err)
	}
	if publicTarget.Canonical != "203.0.113.0/30" || len(publicTarget.Addresses) != 2 {
		t.Fatalf("public target = %#v", publicTarget)
	}
}

func TestParseTargetAcceptsSingleAddressAndInclusiveRange(t *testing.T) {
	single, err := ParseTarget("198.51.100.25")
	if err != nil || single.Canonical != "198.51.100.25" || len(single.Addresses) != 1 {
		t.Fatalf("single target = %#v, error = %v", single, err)
	}
	ranged, err := ParseTarget("198.51.100.25–198.51.100.27")
	if err != nil {
		t.Fatalf("ParseTarget(range) error = %v", err)
	}
	if ranged.Canonical != "198.51.100.25-198.51.100.27" || len(ranged.Addresses) != 3 || ranged.Addresses[2].String() != "198.51.100.27" {
		t.Fatalf("range target = %#v", ranged)
	}
}

func TestParseTargetRejectsUnsafeOrOversizedTargets(t *testing.T) {
	for _, value := range []string{
		"192.168.0.0/23",
		"198.51.100.0-198.51.101.0",
		"198.51.100.27-198.51.100.25",
		"2001:db8::/120",
		"224.0.0.1",
		"0.0.0.0",
		"not-a-target",
	} {
		if _, err := ParseTarget(value); !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("ParseTarget(%q) error = %v, want ErrInvalidTarget", value, err)
		}
	}
}

func TestScannerReportsResponsiveAddressesAndOpenPorts(t *testing.T) {
	openAddress := netip.MustParseAddr("192.168.30.10")
	refusedAddress := netip.MustParseAddr("192.168.30.11")
	inactiveAddress := netip.MustParseAddr("192.168.30.12")
	scanner := &Scanner{
		workers: 2,
		ports:   []uint16{22, 443},
		probe: func(_ context.Context, address netip.Addr, port uint16) (bool, bool) {
			switch {
			case address == openAddress && port == 443:
				return true, true
			case address == refusedAddress:
				return true, false
			default:
				return false, false
			}
		},
	}

	results := make(map[netip.Addr]Result)
	var mutex sync.Mutex
	err := scanner.Scan(context.Background(), []netip.Addr{openAddress, refusedAddress, inactiveAddress}, func(result Result) error {
		mutex.Lock()
		defer mutex.Unlock()
		results[result.Address] = result
		return nil
	})
	if err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if !results[openAddress].Responsive || results[openAddress].DetectedPort == nil || *results[openAddress].DetectedPort != 443 {
		t.Fatalf("open result = %#v", results[openAddress])
	}
	if !results[refusedAddress].Responsive || results[refusedAddress].DetectedPort != nil {
		t.Fatalf("refused result = %#v", results[refusedAddress])
	}
	if results[inactiveAddress].Responsive {
		t.Fatalf("inactive result = %#v", results[inactiveAddress])
	}
}
