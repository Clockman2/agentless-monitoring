package discovery

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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
		ports:   []uint16{22, 80, 443},
		probe: func(_ context.Context, address netip.Addr, port uint16) bool {
			return address == openAddress && (port == 22 || port == 443)
		},
		identityProbe: func(_ context.Context, address netip.Addr, ports []uint16) []Fingerprint {
			if address == openAddress && slices.Equal(ports, []uint16{22, 443}) {
				return []Fingerprint{{Kind: fingerprintSSH, Value: "SHA256:test"}}
			}
			return nil
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
	if !results[openAddress].Responsive || !slices.Equal(results[openAddress].OpenPorts, []uint16{22, 443}) {
		t.Fatalf("open result = %#v", results[openAddress])
	}
	if !slices.Equal(results[openAddress].Fingerprints, []Fingerprint{{Kind: fingerprintSSH, Value: "SHA256:test"}}) {
		t.Fatalf("open fingerprints = %#v", results[openAddress].Fingerprints)
	}
	if results[refusedAddress].Responsive || len(results[refusedAddress].OpenPorts) != 0 {
		t.Fatalf("refused result = %#v", results[refusedAddress])
	}
	if results[inactiveAddress].Responsive {
		t.Fatalf("inactive result = %#v", results[inactiveAddress])
	}
}

func TestCommonTCPPortsIncludeCPanelAndWHM(t *testing.T) {
	for _, port := range []uint16{953, 2082, 2083, 2086, 2087, 2089, 2095, 2096} {
		if !slices.Contains(commonTCPPorts, port) {
			t.Errorf("commonTCPPorts does not include %d", port)
		}
	}
}

func TestScannerBoundsConcurrentIdentityProbes(t *testing.T) {
	var active, maximum atomic.Int32
	scanner := &Scanner{
		workers:       8,
		ports:         []uint16{22},
		identitySlots: make(chan struct{}, 2),
		probe: func(context.Context, netip.Addr, uint16) bool {
			return true
		},
		identityProbe: func(context.Context, netip.Addr, []uint16) []Fingerprint {
			current := active.Add(1)
			defer active.Add(-1)
			for {
				observed := maximum.Load()
				if current <= observed || maximum.CompareAndSwap(observed, current) {
					break
				}
			}
			time.Sleep(10 * time.Millisecond)
			return nil
		},
	}
	addresses := make([]netip.Addr, 0, 8)
	for value := 1; value <= 8; value++ {
		addresses = append(addresses, netip.MustParseAddr(fmt.Sprintf("192.0.2.%d", value)))
	}
	if err := scanner.Scan(context.Background(), addresses, func(Result) error { return nil }); err != nil {
		t.Fatalf("Scan() error = %v", err)
	}
	if got := maximum.Load(); got > 2 {
		t.Fatalf("maximum concurrent identity probes = %d, want at most 2", got)
	}
}
