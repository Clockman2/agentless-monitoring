package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	minimumPrefixBits = 24
	maximumAddresses  = 256
	defaultWorkers    = 32
	probeTimeout      = 450 * time.Millisecond
)

var ErrInvalidTarget = errors.New("discovery target must be a single IPv4 address, an IPv4 CIDR of /24 or smaller, or an inclusive IPv4 range containing at most 256 addresses")

var commonTCPPorts = []uint16{
	21, 22, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
	2082, 2083, 2086, 2087, 2095, 2096, 3306, 3389, 8006, 8080, 8443,
}

type Target struct {
	Canonical string
	Addresses []netip.Addr
}

type Result struct {
	Address    netip.Addr
	Responsive bool
	OpenPorts  []uint16
}

type ProbeFunc func(context.Context, netip.Addr, uint16) bool

type Scanner struct {
	probe   ProbeFunc
	ports   []uint16
	workers int
}

func NewScanner() *Scanner {
	return &Scanner{probe: tcpProbe, ports: slices.Clone(commonTCPPorts), workers: defaultWorkers}
}

func ParseTarget(value string) (Target, error) {
	value = strings.TrimSpace(value)
	if address, err := netip.ParseAddr(value); err == nil {
		if !scannableIPv4(address) {
			return Target{}, ErrInvalidTarget
		}
		return Target{Canonical: address.String(), Addresses: []netip.Addr{address}}, nil
	}
	if start, end, ok := splitAddressRange(value); ok {
		return targetFromRange(start, end)
	}
	return targetFromPrefix(value)
}

func targetFromPrefix(value string) (Target, error) {
	prefix, err := netip.ParsePrefix(value)
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() < minimumPrefixBits || prefix.Bits() > 32 {
		return Target{}, ErrInvalidTarget
	}
	prefix = prefix.Masked()
	if !scannableIPv4(prefix.Addr()) {
		return Target{}, ErrInvalidTarget
	}

	addresses := make([]netip.Addr, 0, maximumAddresses)
	for address := prefix.Addr(); address.IsValid() && prefix.Contains(address); address = address.Next() {
		addresses = append(addresses, address)
		if len(addresses) > maximumAddresses {
			return Target{}, ErrInvalidTarget
		}
	}
	if prefix.Bits() <= 30 && len(addresses) >= 2 {
		addresses = addresses[1 : len(addresses)-1]
	}
	if len(addresses) == 0 {
		return Target{}, ErrInvalidTarget
	}
	return Target{Canonical: prefix.String(), Addresses: addresses}, nil
}

func splitAddressRange(value string) (netip.Addr, netip.Addr, bool) {
	for _, separator := range []string{"-", "–", "—"} {
		parts := strings.Split(value, separator)
		if len(parts) != 2 {
			continue
		}
		start, startErr := netip.ParseAddr(strings.TrimSpace(parts[0]))
		end, endErr := netip.ParseAddr(strings.TrimSpace(parts[1]))
		if startErr == nil && endErr == nil {
			return start, end, true
		}
	}
	return netip.Addr{}, netip.Addr{}, false
}

func targetFromRange(start, end netip.Addr) (Target, error) {
	if !scannableIPv4(start) || !scannableIPv4(end) || start.Compare(end) > 0 {
		return Target{}, ErrInvalidTarget
	}
	addresses := make([]netip.Addr, 0, maximumAddresses)
	for address := start; ; address = address.Next() {
		addresses = append(addresses, address)
		if len(addresses) > maximumAddresses {
			return Target{}, ErrInvalidTarget
		}
		if address == end {
			break
		}
	}
	return Target{
		Canonical: start.String() + "-" + end.String(),
		Addresses: addresses,
	}, nil
}

func scannableIPv4(address netip.Addr) bool {
	return address.Is4() && !address.IsUnspecified() && !address.IsMulticast()
}

func LocalCIDRs() []string {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var suggestions []string
	for _, networkInterface := range interfaces {
		if networkInterface.Flags&net.FlagUp == 0 || networkInterface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, err := networkInterface.Addrs()
		if err != nil {
			continue
		}
		for _, rawAddress := range addresses {
			prefix, err := netip.ParsePrefix(rawAddress.String())
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			if !prefix.Addr().IsPrivate() && !prefix.Addr().IsLinkLocalUnicast() {
				continue
			}
			bits := max(prefix.Bits(), minimumPrefixBits)
			value := netip.PrefixFrom(prefix.Addr(), bits).Masked().String()
			if _, exists := seen[value]; exists {
				continue
			}
			seen[value] = struct{}{}
			suggestions = append(suggestions, value)
		}
	}
	slices.Sort(suggestions)
	return suggestions
}

func (s *Scanner) Scan(ctx context.Context, addresses []netip.Addr, consume func(Result) error) error {
	if len(addresses) == 0 || len(addresses) > maximumAddresses {
		return fmt.Errorf("address count must be between 1 and %d", maximumAddresses)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan netip.Addr)
	results := make(chan Result)
	workerCount := min(s.workers, len(addresses))
	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for address := range jobs {
				result := s.probeAddress(ctx, address)
				select {
				case results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, address := range addresses {
			select {
			case jobs <- address:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	var consumeErr error
	for result := range results {
		if consumeErr != nil {
			continue
		}
		if err := consume(result); err != nil {
			consumeErr = err
			cancel()
		}
	}
	if consumeErr != nil {
		return consumeErr
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Scanner) probeAddress(ctx context.Context, address netip.Addr) Result {
	result := Result{Address: address}
	for _, port := range s.ports {
		if s.probe(ctx, address, port) {
			result.Responsive = true
			result.OpenPorts = append(result.OpenPorts, port)
		}
		if ctx.Err() != nil {
			return result
		}
	}
	return result
}

func tcpProbe(ctx context.Context, address netip.Addr, port uint16) bool {
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", net.JoinHostPort(address.String(), fmt.Sprint(port)))
	if err == nil {
		_ = connection.Close()
		return true
	}
	return false
}
