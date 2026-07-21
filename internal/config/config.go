// Package config loads and validates application runtime configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

const (
	listenAddressEnv   = "AGENTLESS_MONITORING_LISTEN_ADDRESS"
	shutdownTimeoutEnv = "AGENTLESS_MONITORING_SHUTDOWN_TIMEOUT"

	defaultListenAddress   = "127.0.0.1:8080"
	defaultShutdownTimeout = 10 * time.Second
	maximumShutdownTimeout = 5 * time.Minute
)

// Config contains the process-level settings needed to start the application.
type Config struct {
	ListenAddress   string
	ShutdownTimeout time.Duration
}

// Load reads configuration from the environment and applies secure defaults.
func Load() (Config, error) {
	return load(os.LookupEnv)
}

// Validate ensures that configured values are safe and usable.
func (c Config) Validate() error {
	if err := validateListenAddress(c.ListenAddress); err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}
	if c.ShutdownTimeout > maximumShutdownTimeout {
		return fmt.Errorf("shutdown timeout must not exceed %s", maximumShutdownTimeout)
	}
	return nil
}

func load(lookupEnv func(string) (string, bool)) (Config, error) {
	cfg := Config{
		ListenAddress:   defaultListenAddress,
		ShutdownTimeout: defaultShutdownTimeout,
	}

	if value, ok := lookupEnv(listenAddressEnv); ok {
		cfg.ListenAddress = value
	}
	if value, ok := lookupEnv(shutdownTimeoutEnv); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", shutdownTimeoutEnv, err)
		}
		cfg.ShutdownTimeout = duration
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validateListenAddress(address string) error {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be an IP address and port: %w", err)
	}
	if host == "" {
		return fmt.Errorf("host must be explicit")
	}
	if net.ParseIP(host) == nil {
		return fmt.Errorf("host %q must be an IPv4 or IPv6 address", host)
	}

	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}
