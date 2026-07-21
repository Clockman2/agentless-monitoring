package server

import (
	"sync"
	"time"
)

const (
	loginWindow   = time.Minute
	loginAttempts = 5
)

type loginLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	now      func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{attempts: make(map[string][]time.Time), now: time.Now}
}

func (l *loginLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	cutoff := now.Add(-loginWindow)
	recent := l.attempts[key][:0]
	for _, attempt := range l.attempts[key] {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	if len(recent) >= loginAttempts {
		l.attempts[key] = recent
		return false
	}
	l.attempts[key] = append(recent, now)
	return true
}

func (l *loginLimiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
