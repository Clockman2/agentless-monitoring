package discovery

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	fingerprintSSH = "ssh-host-key"
	fingerprintTLS = "tls-certificate"

	identityProbeTimeout = 2 * time.Second
)

var errHostKeyCaptured = errors.New("SSH host key captured")

type Fingerprint struct {
	Kind  string
	Value string
}

type IdentityProbeFunc func(context.Context, netip.Addr, []uint16) []Fingerprint

func probeIdentity(ctx context.Context, address netip.Addr, openPorts []uint16) []Fingerprint {
	var fingerprints []Fingerprint
	if slices.Contains(openPorts, 22) {
		if value, ok := sshHostIdentityFingerprint(ctx, address, 22); ok {
			fingerprints = append(fingerprints, Fingerprint{Kind: fingerprintSSH, Value: value})
		}
	}
	for _, port := range []uint16{2087, 2083, 2096, 443, 8443, 465, 993, 995} {
		if !slices.Contains(openPorts, port) {
			continue
		}
		if value, ok := tlsCertificateFingerprint(ctx, address, port); ok {
			fingerprints = append(fingerprints, Fingerprint{
				Kind: fingerprintTLS, Value: fmt.Sprintf("%d:%s", port, value),
			})
		}
		break
	}
	return fingerprints
}

func sshHostIdentityFingerprint(ctx context.Context, address netip.Addr, port uint16) (string, bool) {
	algorithmGroups := [][]string{
		{ssh.KeyAlgoED25519},
		{ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521},
		{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA},
	}
	keys := make(map[string]string, len(algorithmGroups))
	for _, algorithms := range algorithmGroups {
		value, ok := captureSSHHostKey(ctx, address, port, algorithms)
		if !ok {
			continue
		}
		keyType, _, _ := strings.Cut(value, "=")
		keys[keyType] = value
	}
	if len(keys) == 0 {
		return "", false
	}
	values := make([]string, 0, len(keys))
	for _, value := range keys {
		values = append(values, value)
	}
	slices.Sort(values)
	sum := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(sum[:]), true
}

func captureSSHHostKey(
	ctx context.Context,
	address netip.Addr,
	port uint16,
	algorithms []string,
) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, identityProbeTimeout)
	defer cancel()

	target := net.JoinHostPort(address.String(), fmt.Sprint(port))
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", target)
	if err != nil {
		return "", false
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(identityProbeTimeout))

	var fingerprint string
	config := &ssh.ClientConfig{
		User:              "agentless-monitoring-discovery",
		ClientVersion:     "SSH-2.0-AgentlessMonitoring",
		HostKeyAlgorithms: algorithms,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			fingerprint = key.Type() + "=" + ssh.FingerprintSHA256(key)
			return errHostKeyCaptured
		},
	}
	_, _, _, _ = ssh.NewClientConn(connection, target, config)
	return fingerprint, fingerprint != ""
}

func tlsCertificateFingerprint(ctx context.Context, address netip.Addr, port uint16) (string, bool) {
	probeCtx, cancel := context.WithTimeout(ctx, identityProbeTimeout)
	defer cancel()

	target := net.JoinHostPort(address.String(), fmt.Sprint(port))
	connection, err := (&net.Dialer{}).DialContext(probeCtx, "tcp", target)
	if err != nil {
		return "", false
	}
	defer connection.Close()

	// Discovery hashes the presented certificate as an identity signal. It does
	// not trust the endpoint or send credentials, so CA and hostname validation
	// are intentionally not part of this fingerprint-only handshake.
	tlsConnection := tls.Client(connection, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec -- certificate trust is not asserted
		MinVersion:         tls.VersionTLS12,
	})
	if err := tlsConnection.HandshakeContext(probeCtx); err != nil {
		return "", false
	}
	certificates := tlsConnection.ConnectionState().PeerCertificates
	if len(certificates) == 0 {
		return "", false
	}
	sum := sha256.Sum256(certificates[0].Raw)
	return hex.EncodeToString(sum[:]), true
}

func normalizedFingerprints(fingerprints []Fingerprint) []Fingerprint {
	unique := make(map[string]Fingerprint, len(fingerprints))
	for _, fingerprint := range fingerprints {
		fingerprint.Kind = strings.TrimSpace(fingerprint.Kind)
		fingerprint.Value = strings.TrimSpace(fingerprint.Value)
		if !validFingerprint(fingerprint) {
			continue
		}
		unique[fingerprint.Kind+"\x00"+fingerprint.Value] = fingerprint
	}
	result := make([]Fingerprint, 0, len(unique))
	for _, fingerprint := range unique {
		result = append(result, fingerprint)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Kind == result[j].Kind {
			return result[i].Value < result[j].Value
		}
		return result[i].Kind < result[j].Kind
	})
	return result
}

func validFingerprint(fingerprint Fingerprint) bool {
	if fingerprint.Kind != fingerprintSSH && fingerprint.Kind != fingerprintTLS {
		return false
	}
	return fingerprint.Value != "" && len(fingerprint.Value) <= 160 &&
		!strings.ContainsAny(fingerprint.Value, ",=\x00\r\n")
}

func parseFingerprints(value string) []Fingerprint {
	var fingerprints []Fingerprint
	for _, field := range strings.Split(value, ",") {
		kind, fingerprintValue, ok := strings.Cut(field, "=")
		if ok {
			fingerprints = append(fingerprints, Fingerprint{Kind: kind, Value: fingerprintValue})
		}
	}
	return normalizedFingerprints(fingerprints)
}

func classifyIdentityGroups(devices []Device) {
	for index := range devices {
		devices[index].IdentityHint = identityDefaultHint(devices[index])
	}

	sshGroups := matchingFingerprintGroups(devices, fingerprintSSH, nil)
	assignedSSH := make(map[int]struct{})
	for groupIndex, group := range sshGroups {
		signal := "SSH host key match"
		if groupSharesFingerprint(devices, group, fingerprintTLS) {
			signal = "SSH host key + TLS certificate match"
		}
		hint := fmt.Sprintf(
			"Likely same VM — host group %d (%d IPs; %s)",
			groupIndex+1, len(group), signal,
		)
		for _, deviceIndex := range group {
			devices[deviceIndex].IdentityHint = hint
			assignedSSH[deviceIndex] = struct{}{}
		}
	}

	tlsGroups := matchingFingerprintGroups(devices, fingerprintTLS, nil)
	for _, group := range tlsGroups {
		hint := fmt.Sprintf(
			"Possible shared host/service (%d IPs; TLS certificate match only)",
			len(group),
		)
		if groupHasDifferentSSHKeys(devices, group) {
			hint = fmt.Sprintf(
				"Shared TLS certificate across %d IPs; SSH host keys differ",
				len(group),
			)
		}
		for _, deviceIndex := range group {
			if _, alreadyAssigned := assignedSSH[deviceIndex]; alreadyAssigned {
				continue
			}
			devices[deviceIndex].IdentityHint = hint
		}
	}
}

func identityDefaultHint(device Device) string {
	if len(device.Fingerprints) == 0 {
		return "Not enough identity data"
	}
	return "Unique host fingerprint in this scan"
}

func matchingFingerprintGroups(devices []Device, kind string, excluded map[int]struct{}) [][]int {
	byValue := make(map[string][]int)
	for index, device := range devices {
		if _, skip := excluded[index]; skip {
			continue
		}
		for _, fingerprint := range device.Fingerprints {
			if fingerprint.Kind == kind {
				byValue[fingerprint.Value] = append(byValue[fingerprint.Value], index)
			}
		}
	}

	var groups [][]int
	for _, group := range byValue {
		if len(group) > 1 {
			slices.Sort(group)
			groups = append(groups, group)
		}
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i][0] < groups[j][0] })
	return groups
}

func groupSharesFingerprint(devices []Device, group []int, kind string) bool {
	if len(group) < 2 {
		return false
	}
	values := fingerprintValues(devices[group[0]], kind)
	for _, deviceIndex := range group[1:] {
		values = intersectStrings(values, fingerprintValues(devices[deviceIndex], kind))
		if len(values) == 0 {
			return false
		}
	}
	return len(values) > 0
}

func groupHasDifferentSSHKeys(devices []Device, group []int) bool {
	keys := make(map[string]struct{})
	for _, deviceIndex := range group {
		values := fingerprintValues(devices[deviceIndex], fingerprintSSH)
		if len(values) == 0 {
			return false
		}
		for _, value := range values {
			keys[value] = struct{}{}
		}
	}
	return len(keys) > 1
}

func fingerprintValues(device Device, kind string) []string {
	var values []string
	for _, fingerprint := range device.Fingerprints {
		if fingerprint.Kind == kind {
			values = append(values, fingerprint.Value)
		}
	}
	return values
}

func intersectStrings(first, second []string) []string {
	allowed := make(map[string]struct{}, len(second))
	for _, value := range second {
		allowed[value] = struct{}{}
	}
	var result []string
	for _, value := range first {
		if _, ok := allowed[value]; ok {
			result = append(result, value)
		}
	}
	return result
}
