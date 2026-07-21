// Package monitoring executes bounded, agentless health checks.
package monitoring

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/machines"
)

type Result struct {
	Status       machines.Status
	Summary      string
	ResponseTime time.Duration
}

type Runner struct {
	dialContext func(context.Context, string, string) (net.Conn, error)
	client      *http.Client
}

func NewRunner() *Runner {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy:             nil,
		DialContext:       dialer.DialContext,
		TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
		DisableKeepAlives: true,
	}
	return &Runner{dialContext: dialer.DialContext, client: &http.Client{Transport: transport}}
}

func (r *Runner) Run(ctx context.Context, machine machines.Machine) Result {
	address, err := netip.ParseAddr(machine.Target)
	if err != nil || !allowedTarget(address) {
		return Result{Status: machines.StatusCritical, Summary: "target is outside allowed local address ranges"}
	}
	ctx, cancel := context.WithTimeout(ctx, machine.Timeout)
	defer cancel()
	started := time.Now()

	switch machine.CheckType {
	case machines.CheckTCP:
		connection, err := r.dialContext(ctx, "tcp", net.JoinHostPort(machine.Target, fmt.Sprint(machine.Port)))
		if err != nil {
			return failedResult(started, err)
		}
		_ = connection.Close()
		return Result{Status: machines.StatusHealthy, Summary: "TCP connection succeeded", ResponseTime: time.Since(started)}
	case machines.CheckHTTP, machines.CheckHTTPS:
		return r.runHTTP(ctx, machine, started)
	default:
		return Result{Status: machines.StatusCritical, Summary: "unsupported check type"}
	}
}

func (r *Runner) runHTTP(ctx context.Context, machine machines.Machine, started time.Time) Result {
	scheme := string(machine.CheckType)
	endpoint := fmt.Sprintf("%s://%s%s", scheme, net.JoinHostPort(machine.Target, fmt.Sprint(machine.Port)), machine.Path)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return failedResult(started, err)
	}
	client := *r.client
	client.CheckRedirect = func(next *http.Request, previous []*http.Request) error {
		if len(previous) >= 3 || next.URL.Hostname() != machine.Target || next.URL.Scheme != scheme {
			return fmt.Errorf("redirect left the monitored endpoint")
		}
		return nil
	}
	response, err := client.Do(request)
	if err != nil {
		return failedResult(started, err)
	}
	_ = response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 {
		return Result{Status: machines.StatusCritical, Summary: fmt.Sprintf("HTTP status %d", response.StatusCode), ResponseTime: time.Since(started)}
	}
	return Result{Status: machines.StatusHealthy, Summary: fmt.Sprintf("HTTP status %d", response.StatusCode), ResponseTime: time.Since(started)}
}

func allowedTarget(address netip.Addr) bool {
	return address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast()
}

func failedResult(started time.Time, err error) Result {
	return Result{Status: machines.StatusCritical, Summary: err.Error(), ResponseTime: time.Since(started)}
}
