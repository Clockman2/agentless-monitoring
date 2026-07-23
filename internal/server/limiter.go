package server

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

const (
	sourceLoginWindow    = time.Minute
	sourceLoginAttempts  = 20
	accountLoginWindow   = 5 * time.Minute
	accountLoginAttempts = 10
	maximumLimiterKeys   = 4096
	limiterSweepInterval = time.Minute
)

type attemptRecord struct {
	attempts []time.Time
	lastSeen time.Time
}

type loginLimiter struct {
	mu        sync.Mutex
	sources   map[string]attemptRecord
	accounts  map[string]attemptRecord
	lastSweep time.Time
	now       func() time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		sources:  make(map[string]attemptRecord),
		accounts: make(map[string]attemptRecord),
		now:      time.Now,
	}
}

func (l *loginLimiter) allow(source, username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweep(now)
	sourceAllowed := allowAttempt(l.sources, source, sourceLoginWindow, sourceLoginAttempts, now)
	accountAllowed := allowAttempt(l.accounts, accountKey(username), accountLoginWindow, accountLoginAttempts, now)
	return sourceAllowed && accountAllowed
}

func (l *loginLimiter) reset(source, username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.sources, source)
	delete(l.accounts, accountKey(username))
}

func (l *loginLimiter) sweep(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < limiterSweepInterval {
		return
	}
	removeExpired(l.sources, now.Add(-sourceLoginWindow))
	removeExpired(l.accounts, now.Add(-accountLoginWindow))
	evictOldest(l.sources)
	evictOldest(l.accounts)
	l.lastSweep = now
}

func allowAttempt(records map[string]attemptRecord, key string, window time.Duration, limit int, now time.Time) bool {
	if _, exists := records[key]; !exists && len(records) >= maximumLimiterKeys {
		return false
	}
	record := records[key]
	cutoff := now.Add(-window)
	recent := record.attempts[:0]
	for _, attempt := range record.attempts {
		if attempt.After(cutoff) {
			recent = append(recent, attempt)
		}
	}
	record.lastSeen = now
	if len(recent) >= limit {
		record.attempts = recent
		records[key] = record
		return false
	}
	record.attempts = append(recent, now)
	records[key] = record
	return true
}

func removeExpired(records map[string]attemptRecord, cutoff time.Time) {
	for key, record := range records {
		if record.lastSeen.Before(cutoff) {
			delete(records, key)
		}
	}
}

func evictOldest(records map[string]attemptRecord) {
	for len(records) > maximumLimiterKeys {
		var oldestKey string
		var oldestTime time.Time
		for key, record := range records {
			if oldestKey == "" || record.lastSeen.Before(oldestTime) {
				oldestKey = key
				oldestTime = record.lastSeen
			}
		}
		delete(records, oldestKey)
	}
}

func accountKey(username string) string {
	normalized := strings.ToLower(strings.TrimSpace(username))
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
