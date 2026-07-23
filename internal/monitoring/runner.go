// Package monitoring executes bounded, agentless health checks.
package monitoring

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/machines"
	"github.com/Clockman2/agentless-monitoring/internal/netpolicy"
)

type Result struct {
	Status        machines.Status
	Summary       string
	ResponseTime  time.Duration
	ErrorCategory string
}

type Runner struct {
	dialContext           func(context.Context, string, string) (net.Conn, error)
	client                *http.Client
	allowSensitiveTargets bool
}

type RunnerOptions struct {
	AllowSensitiveTargets bool
}

func NewRunner() *Runner {
	return NewRunnerWithOptions(RunnerOptions{})
}

func NewRunnerWithOptions(options RunnerOptions) *Runner {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &Runner{
		dialContext: dialer.DialContext, client: &http.Client{Transport: transport},
		allowSensitiveTargets: options.AllowSensitiveTargets,
	}
}

func (r *Runner) Run(ctx context.Context, machine machines.Machine) Result {
	address, err := netip.ParseAddr(machine.Target)
	if err != nil || !allowedTarget(address) {
		return Result{Status: machines.StatusCritical, Summary: "target is not a valid unicast address", ErrorCategory: "configuration"}
	}
	if !r.allowSensitiveTargets && netpolicy.IsSensitiveServiceAddress(address) {
		return Result{Status: machines.StatusCritical, Summary: "target is blocked by network policy", ErrorCategory: "configuration"}
	}
	ctx, cancel := context.WithTimeout(ctx, machine.Timeout)
	defer cancel()
	started := time.Now()

	switch machine.CheckType {
	case machines.CheckTCP:
		connection, err := r.dialContext(ctx, "tcp", net.JoinHostPort(machine.Target, fmt.Sprint(machine.Port)))
		if err != nil {
			return failedResult(started, err, "network")
		}
		_ = connection.Close()
		return Result{Status: machines.StatusHealthy, Summary: "TCP connection succeeded", ResponseTime: time.Since(started)}
	case machines.CheckHTTP, machines.CheckHTTPS:
		return r.runHTTP(ctx, machine, address, started)
	default:
		return Result{Status: machines.StatusCritical, Summary: "unsupported check type", ErrorCategory: "configuration"}
	}
}

func (r *Runner) runHTTP(ctx context.Context, machine machines.Machine, targetAddress netip.Addr, started time.Time) Result {
	scheme := string(machine.CheckType)
	endpoint := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(machine.Target, fmt.Sprint(machine.Port)), machine.Path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return failedResult(started, err, "configuration")
	}
	client := *r.client
	client.CheckRedirect = func(next *http.Request, previous []*http.Request) error {
		if len(previous) >= 3 || !sameEndpoint(next.URL, targetAddress, scheme, machine.Port) {
			return fmt.Errorf("redirect left the monitored endpoint")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return failedResult(started, err, "network")
	}
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return Result{Status: machines.StatusCritical, Summary: fmt.Sprintf("HTTP status %d", response.StatusCode), ResponseTime: time.Since(started), ErrorCategory: "http_status"}
	}
	return Result{Status: machines.StatusHealthy, Summary: fmt.Sprintf("HTTP status %d", response.StatusCode), ResponseTime: time.Since(started)}
}

func sameEndpoint(endpoint *url.URL, address netip.Addr, scheme string, port uint16) bool {
	redirectAddress, err := netip.ParseAddr(endpoint.Hostname())
	if err != nil || redirectAddress != address || endpoint.Scheme != scheme {
		return false
	}
	redirectPort := endpoint.Port()
	if redirectPort == "" {
		switch endpoint.Scheme {
		case "http":
			redirectPort = "80"
		case "https":
			redirectPort = "443"
		default:
			return false
		}
	}
	return redirectPort == fmt.Sprint(port)
}

func allowedTarget(address netip.Addr) bool {
	return address.IsGlobalUnicast() || address.IsLoopback() || address.IsLinkLocalUnicast()
}

func failedResult(started time.Time, err error, category string) Result {
	return Result{Status: machines.StatusCritical, Summary: err.Error(), ResponseTime: time.Since(started), ErrorCategory: category}
}
