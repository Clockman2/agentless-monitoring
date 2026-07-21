package monitoring

import (
	"context"
	"io"
	"net"
	"net/http"
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

func TestRunBlocksPublicTarget(t *testing.T) {
	result := NewRunner().Run(context.Background(), machines.Machine{
		Target: "192.0.2.10", CheckType: machines.CheckTCP, Port: 443, Timeout: time.Second,
	})
	if result.Status != machines.StatusCritical || result.ErrorCategory != "configuration" || !strings.Contains(result.Summary, "outside allowed") {
		t.Fatalf("result = %#v", result)
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
