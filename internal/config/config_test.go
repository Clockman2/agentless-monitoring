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
	if cfg.ShutdownTimeout != defaultShutdownTimeout {
		t.Errorf("ShutdownTimeout = %s, want %s", cfg.ShutdownTimeout, defaultShutdownTimeout)
	}
}

func TestLoadOverrides(t *testing.T) {
	values := map[string]string{
		listenAddressEnv:   "0.0.0.0:9090",
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
	cfg := Config{ListenAddress: "[::1]:8080", ShutdownTimeout: time.Second}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}
