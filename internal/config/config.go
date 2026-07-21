// Package config loads and validates application runtime configuration.
package config

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	listenAddressEnv         = "AGENTLESS_MONITORING_LISTEN_ADDRESS"
	databasePathEnv          = "AGENTLESS_MONITORING_DATABASE_PATH"
	secureCookiesEnv         = "AGENTLESS_MONITORING_SECURE_COOKIES"
	shutdownTimeoutEnv       = "AGENTLESS_MONITORING_SHUTDOWN_TIMEOUT"
	monitoringWorkersEnv     = "AGENTLESS_MONITORING_WORKERS"
	schedulerPollIntervalEnv = "AGENTLESS_MONITORING_POLL_INTERVAL"

	defaultListenAddress         = "127.0.0.1:8080"
	defaultDatabasePath          = "data/agentless-monitoring.db"
	defaultShutdownTimeout       = 10 * time.Second
	maximumShutdownTimeout       = 5 * time.Minute
	defaultMonitoringWorkers     = 4
	defaultSchedulerPollInterval = 2 * time.Second
	maximumMonitoringWorkers     = 64
)

// Config contains the process-level settings needed to start the application.
type Config struct {
	ListenAddress         string
	DatabasePath          string
	SecureCookies         bool
	ShutdownTimeout       time.Duration
	MonitoringWorkers     int
	SchedulerPollInterval time.Duration
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
	if strings.TrimSpace(c.DatabasePath) == "" {
		return fmt.Errorf("database path must not be empty")
	}
	if strings.ContainsRune(c.DatabasePath, '\x00') {
		return fmt.Errorf("database path must not contain a null byte")
	}
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("shutdown timeout must be positive")
	}
	if c.ShutdownTimeout > maximumShutdownTimeout {
		return fmt.Errorf("shutdown timeout must not exceed %s", maximumShutdownTimeout)
	}
	if c.MonitoringWorkers < 1 || c.MonitoringWorkers > maximumMonitoringWorkers {
		return fmt.Errorf("monitoring workers must be between 1 and %d", maximumMonitoringWorkers)
	}
	if c.SchedulerPollInterval < 500*time.Millisecond || c.SchedulerPollInterval > time.Minute {
		return fmt.Errorf("monitoring poll interval must be between 500ms and 1m")
	}
	return nil
}

func load(lookupEnv func(string) (string, bool)) (Config, error) {
	cfg := Config{
		ListenAddress:         defaultListenAddress,
		DatabasePath:          defaultDatabasePath,
		ShutdownTimeout:       defaultShutdownTimeout,
		MonitoringWorkers:     defaultMonitoringWorkers,
		SchedulerPollInterval: defaultSchedulerPollInterval,
	}

	if value, ok := lookupEnv(listenAddressEnv); ok {
		cfg.ListenAddress = value
	}
	if value, ok := lookupEnv(databasePathEnv); ok {
		cfg.DatabasePath = value
	}
	if value, ok := lookupEnv(secureCookiesEnv); ok {
		secureCookies, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, fmt.Errorf("%s must be true or false", secureCookiesEnv)
		}
		cfg.SecureCookies = secureCookies
	}
	if value, ok := lookupEnv(shutdownTimeoutEnv); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", shutdownTimeoutEnv, err)
		}
		cfg.ShutdownTimeout = duration
	}
	if value, ok := lookupEnv(monitoringWorkersEnv); ok {
		workers, err := strconv.Atoi(value)
		if err != nil {
			return Config{}, fmt.Errorf("%s must be a number", monitoringWorkersEnv)
		}
		cfg.MonitoringWorkers = workers
	}
	if value, ok := lookupEnv(schedulerPollIntervalEnv); ok {
		duration, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("%s: %w", schedulerPollIntervalEnv, err)
		}
		cfg.SchedulerPollInterval = duration
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
