package config

import (
	"strings"
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	cfg, err := load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}

	if cfg.ListenAddress != defaultListenAddress {
		t.Errorf("ListenAddress = %q, want %q", cfg.ListenAddress, defaultListenAddress)
	}
	if cfg.DatabasePath != defaultDatabasePath {
		t.Errorf("DatabasePath = %q, want %q", cfg.DatabasePath, defaultDatabasePath)
	}
	if cfg.ShutdownTimeout != defaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, defaultShutdownTimeout)
	}
}

func TestLoadOverrides(t *testing.T) {
	values := map[string]string{
		listenAddressEnv:   "0.0.0.0:9090",
		databasePathEnv:    "testdata/monitoring.db",
		secureCookiesEnv:   "true",
		shutdownTimeoutEnv: "30s",
	}
	cfg, err := load(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatalf("load overrides: %v", err)
	}

	if cfg.ListenAddress != "0.0.0.0:9090" {
		t.Errorf("ListenAddress = %q, want 0.0.0.0:9090", cfg.ListenAddress)
	}
	if cfg.DatabasePath != "testdata/monitoring.db" {
		t.Errorf("DatabasePath = %q, want testdata/monitoring.db", cfg.DatabasePath)
	}
	if !cfg.SecureCookies {
		t.Error("SecureCookies = false, want true")
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %s, want 30s", cfg.ShutdownTimeout)
	}
}

func TestLoadRejectsInvalidEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		values  map[string]string
		wantErr string
	}{
		{
			name:    "missing port",
			values:  map[string]string{listenAddressEnv: "127.0.0.1"},
			wantErr: "must be an IP address and port",
		},
		{
			name:    "hostname",
			values:  map[string]string{listenAddressEnv: "example.invalid:8080"},
			wantErr: "must be an IPv4 or IPv6 address",
		},
		{
			name:    "invalid port",
			values:  map[string]string{listenAddressEnv: "127.0.0.1:70000"},
			wantErr: "port must be between 1 and 65535",
		},
		{
			name:    "invalid duration",
			values:  map[string]string{shutdownTimeoutEnv: "later"},
			wantErr: shutdownTimeoutEnv,
		},
		{
			name:    "invalid secure cookie setting",
			values:  map[string]string{secureCookiesEnv: "sometimes"},
			wantErr: secureCookiesEnv,
		},
		{
			name:    "empty database path",
			values:  map[string]string{databasePathEnv: " "},
			wantErr: "database path must not be empty",
		},
		{
			name:    "database path with null byte",
			values:  map[string]string{databasePathEnv: "data/monitoring\x00.db"},
			wantErr: "database path must not contain a null byte",
		},
		{
			name:    "excessive duration",
			values:  map[string]string{shutdownTimeoutEnv: "6m"},
			wantErr: "must not exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := load(func(key string) (string, bool) {
				value, ok := tt.values[key]
				return value, ok
			})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAcceptsIPv6(t *testing.T) {
	cfg := Config{
		ListenAddress:   "[::1]:8080",
		DatabasePath:    "data/test.db",
		ShutdownTimeout: time.Second,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
