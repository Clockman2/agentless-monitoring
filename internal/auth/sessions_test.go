package auth

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"
)

func TestSessionLifecycle(t *testing.T) {
	store, db := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return now }

	user, err := store.CreateAdministrator(ctx, "session.admin", "a secure test password")
	if err != nil {
		t.Fatalf("CreateAdministrator() error = %v", err)
	}
	token, created, err := store.CreateSession(ctx, user.ID, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession() error = %v", err)
	}
	if token == "" || created.CSRFToken == "" {
		t.Fatal("session credentials are empty")
	}

	tokenHash := sha256.Sum256([]byte(token))
	var storedHash []byte
	if err := db.QueryRow("SELECT token_hash FROM sessions").Scan(&storedHash); err != nil {
		t.Fatalf("read token hash: %v", err)
	}
	if string(storedHash) != string(tokenHash[:]) {
		t.Fatal("database token hash does not match SHA-256 token hash")
	}
	if string(storedHash) == token {
		t.Fatal("database contains the raw session token")
	}

	loaded, err := store.SessionByToken(ctx, token)
	if err != nil {
		t.Fatalf("SessionByToken() error = %v", err)
	}
	if loaded.User.ID != user.ID || loaded.CSRFToken != created.CSRFToken {
		t.Fatalf("loaded session = %#v", loaded)
	}

	store.now = func() time.Time { return now.Add(2 * time.Hour) }
	if _, err := store.SessionByToken(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expired session error = %v, want ErrInvalidSession", err)
	}

	store.now = func() time.Time { return now }
	if err := store.DeleteSession(ctx, token); err != nil {
		t.Fatalf("DeleteSession() error = %v", err)
	}
	if _, err := store.SessionByToken(ctx, token); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("deleted session error = %v, want ErrInvalidSession", err)
	}
}

func TestCreateSessionRejectsInvalidDuration(t *testing.T) {
	store, _ := newTestStore(t)
	if _, _, err := store.CreateSession(context.Background(), 1, maximumSessionTTL+time.Second); err == nil {
		t.Fatal("CreateSession() accepted an excessive duration")
	}
}
