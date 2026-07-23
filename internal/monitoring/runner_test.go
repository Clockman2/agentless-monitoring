package monitoring

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/machines"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestRunTCP(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	runner := NewRunner()
	runner.dialContext = func(context.Context, string, string) (net.Conn, error) { return server, nil }

	result := runner.Run(context.Background(), machines.Machine{
		Target: "127.0.0.1", CheckType: machines.CheckTCP, Port: 443, Timeout: time.Second,
	})
	if result.Status != machines.StatusHealthy {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunHTTP(t *testing.T) {
	runner := NewRunner()
	runner.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Hostname() != "10.0.0.10" {
			t.Fatalf("request host = %q", request.URL.Hostname())
		}
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	result := runner.Run(context.Background(), machines.Machine{
		Target: "10.0.0.10", CheckType: machines.CheckHTTP, Port: 8080, Path: "/health", Timeout: time.Second,
	})
	if result.Status != machines.StatusHealthy || result.Summary != "HTTP status 204" {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunAllowsPublicUnicastTarget(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	runner := NewRunner()
	runner.dialContext = func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" || address != "203.0.113.10:443" {
			t.Fatalf("dial target = %s %s", network, address)
		}
		return server, nil
	}
	result := runner.Run(context.Background(), machines.Machine{
		Target: "203.0.113.10", CheckType: machines.CheckTCP, Port: 443, Timeout: time.Second,
	})
	if result.Status != machines.StatusHealthy {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunBlocksNonUnicastTarget(t *testing.T) {
	result := NewRunner().Run(context.Background(), machines.Machine{
		Target: "224.0.0.1", CheckType: machines.CheckTCP, Port: 443, Timeout: time.Second,
	})
	if result.Status != machines.StatusCritical || result.ErrorCategory != "configuration" || !strings.Contains(result.Summary, "not a valid unicast") {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunBlocksSensitiveServiceTargetByDefault(t *testing.T) {
	result := NewRunner().Run(context.Background(), machines.Machine{
		Target: "169.254.169.254", CheckType: machines.CheckTCP, Port: 80, Timeout: time.Second,
	})
	if result.Status != machines.StatusCritical || result.ErrorCategory != "configuration" ||
		!strings.Contains(result.Summary, "blocked by network policy") {
		t.Fatalf("result = %#v", result)
	}
}

func TestRunAllowsSensitiveServiceTargetWithOverride(t *testing.T) {
	server, client := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	runner := NewRunnerWithOptions(RunnerOptions{AllowSensitiveTargets: true})
	runner.dialContext = func(context.Context, string, string) (net.Conn, error) {
		return server, nil
	}
	result := runner.Run(context.Background(), machines.Machine{
		Target: "169.254.169.254", CheckType: machines.CheckTCP, Port: 80, Timeout: time.Second,
	})
	if result.Status != machines.StatusHealthy {
		t.Fatalf("result = %#v", result)
	}
}

func TestSameEndpointIncludesEffectivePort(t *testing.T) {
	address := netip.MustParseAddr("192.0.2.10")
	for _, test := range []struct {
		raw  string
		want bool
	}{
		{raw: "http://192.0.2.10/next", want: true},
		{raw: "http://192.0.2.10:80/next", want: true},
		{raw: "http://192.0.2.10:2375/next", want: false},
		{raw: "https://192.0.2.10/next", want: false},
		{raw: "http://192.0.2.11/next", want: false},
	} {
		endpoint, err := url.Parse(test.raw)
		if err != nil {
			t.Fatalf("parse %q: %v", test.raw, err)
		}
		if got := sameEndpoint(endpoint, address, "http", 80); got != test.want {
			t.Errorf("sameEndpoint(%q) = %t, want %t", test.raw, got, test.want)
		}
	}
}

func TestRunHTTPClassifiesUnexpectedStatus(t *testing.T) {
	runner := NewRunner()
	runner.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 503, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})
	result := runner.Run(context.Background(), machines.Machine{
		Target: "10.0.0.10", CheckType: machines.CheckHTTP, Port: 8080, Path: "/health", Timeout: time.Second,
	})
	if result.Status != machines.StatusCritical || result.ErrorCategory != "http_status" {
		t.Fatalf("result = %#v", result)
	}
}
