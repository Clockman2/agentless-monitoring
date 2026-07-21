package server

import "testing"

func TestLoginLimiter(t *testing.T) {
	limiter := newLoginLimiter()
	for attempt := 0; attempt < loginAttempts; attempt++ {
		if !limiter.allow("192.0.2.10") {
			t.Fatalf("attempt %d was unexpectedly rejected", attempt+1)
		}
	}
	if limiter.allow("192.0.2.10") {
		t.Fatal("attempt beyond the limit was accepted")
	}
	limiter.reset("192.0.2.10")
	if !limiter.allow("192.0.2.10") {
		t.Fatal("attempt after reset was rejected")
	}
}
