package server

import (
	"strconv"
	"testing"
	"time"
)

func TestLoginLimiter(t *testing.T) {
	limiter := newLoginLimiter()
	for attempt := 0; attempt < accountLoginAttempts; attempt++ {
		if !limiter.allow("192.0.2.10", "admin") {
			t.Fatalf("attempt %d was unexpectedly rejected", attempt+1)
		}
	}
	if limiter.allow("192.0.2.10", "admin") {
		t.Fatal("attempt beyond the limit was accepted")
	}
	limiter.reset("192.0.2.10", "admin")
	if !limiter.allow("192.0.2.10", "admin") {
		t.Fatal("attempt after reset was rejected")
	}
}

func TestLoginLimiterAppliesIndependentSourceLimit(t *testing.T) {
	limiter := newLoginLimiter()
	for attempt := 0; attempt < sourceLoginAttempts; attempt++ {
		if !limiter.allow("192.0.2.10", "user-"+strconv.Itoa(attempt)) {
			t.Fatalf("source attempt %d was unexpectedly rejected", attempt+1)
		}
	}
	if limiter.allow("192.0.2.10", "another-user") {
		t.Fatal("attempt beyond the source limit was accepted")
	}
}

func TestLoginLimiterBoundsStoredKeys(t *testing.T) {
	limiter := newLoginLimiter()
	for index := 0; index < maximumLimiterKeys+100; index++ {
		value := strconv.Itoa(index)
		limiter.allow("source-"+value, "user-"+value)
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	limiter.lastSweep = time.Time{}
	limiter.sweep(limiter.now())
	if len(limiter.sources) > maximumLimiterKeys || len(limiter.accounts) > maximumLimiterKeys {
		t.Fatalf("limiter sizes = %d/%d", len(limiter.sources), len(limiter.accounts))
	}
}
