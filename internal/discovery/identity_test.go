package discovery

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestClassifyIdentityGroups(t *testing.T) {
	devices := []Device{
		{
			Address: "192.0.2.1",
			Fingerprints: []Fingerprint{
				{Kind: fingerprintSSH, Value: "SHA256:same-key"},
				{Kind: fingerprintTLS, Value: "2087:same-certificate"},
			},
		},
		{
			Address: "192.0.2.2",
			Fingerprints: []Fingerprint{
				{Kind: fingerprintSSH, Value: "SHA256:same-key"},
				{Kind: fingerprintTLS, Value: "2087:same-certificate"},
			},
		},
		{
			Address: "192.0.2.3",
			Fingerprints: []Fingerprint{
				{Kind: fingerprintSSH, Value: "SHA256:different-key"},
				{Kind: fingerprintTLS, Value: "2087:shared-certificate"},
			},
		},
		{
			Address: "192.0.2.4",
			Fingerprints: []Fingerprint{
				{Kind: fingerprintSSH, Value: "SHA256:another-key"},
				{Kind: fingerprintTLS, Value: "2087:shared-certificate"},
			},
		},
		{Address: "192.0.2.5", Fingerprints: []Fingerprint{{Kind: fingerprintTLS, Value: "443:tls-only"}}},
		{Address: "192.0.2.6", Fingerprints: []Fingerprint{{Kind: fingerprintTLS, Value: "443:tls-only"}}},
		{Address: "192.0.2.7", Fingerprints: []Fingerprint{{Kind: fingerprintSSH, Value: "SHA256:unique"}}},
		{Address: "192.0.2.8"},
	}

	classifyIdentityGroups(devices)

	if got := devices[0].IdentityHint; got != "Likely same VM — host group 1 (2 IPs; SSH host key + TLS certificate match)" {
		t.Fatalf("same VM hint = %q", got)
	}
	if devices[1].IdentityHint != devices[0].IdentityHint {
		t.Fatalf("same VM hints differ: %q and %q", devices[0].IdentityHint, devices[1].IdentityHint)
	}
	for _, index := range []int{2, 3} {
		if got := devices[index].IdentityHint; got != "Shared TLS certificate across 2 IPs; SSH host keys differ" {
			t.Fatalf("conflicting identity hint %d = %q", index, got)
		}
	}
	for _, index := range []int{4, 5} {
		if got := devices[index].IdentityHint; got != "Possible shared host/service (2 IPs; TLS certificate match only)" {
			t.Fatalf("TLS-only identity hint %d = %q", index, got)
		}
	}
	if got := devices[6].IdentityHint; got != "Unique host fingerprint in this scan" {
		t.Fatalf("unique identity hint = %q", got)
	}
	if got := devices[7].IdentityHint; got != "Not enough identity data" {
		t.Fatalf("missing identity hint = %q", got)
	}
}

func TestSSHHostKeyFingerprint(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		t.Fatalf("create host key signer: %v", err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		config := &ssh.ServerConfig{NoClientAuth: true}
		config.AddHostKey(signer)
		_, _, _, _ = ssh.NewServerConn(connection, config)
	}()

	address, port := splitListenerAddress(t, listener.Addr().String())
	got, ok := captureSSHHostKey(context.Background(), address, port, []string{ssh.KeyAlgoED25519})
	if !ok {
		t.Fatal("SSH fingerprint was not captured")
	}
	if want := signer.PublicKey().Type() + "=" + ssh.FingerprintSHA256(signer.PublicKey()); got != want {
		t.Fatalf("SSH fingerprint = %q, want %q", got, want)
	}
	<-done
}

func TestTLSCertificateFingerprint(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()

	address, port := splitListenerAddress(t, server.Listener.Addr().String())
	first, ok := tlsCertificateFingerprint(context.Background(), address, port)
	if !ok || len(first) != 64 {
		t.Fatalf("TLS fingerprint = %q, captured = %t", first, ok)
	}
	second, ok := tlsCertificateFingerprint(context.Background(), address, port)
	if !ok || second != first {
		t.Fatalf("second TLS fingerprint = %q, want %q", second, first)
	}
}

func splitListenerAddress(t *testing.T, value string) (netip.Addr, uint16) {
	t.Helper()
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	address, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		t.Fatalf("parse listener address: %v", err)
	}
	portValue, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	return address, uint16(portValue)
}
