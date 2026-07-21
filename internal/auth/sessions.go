package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

const (
	SessionDuration   = 12 * time.Hour
	maximumSessionTTL = 30 * 24 * time.Hour
	tokenBytes        = 32
)

var ErrInvalidSession = errors.New("invalid or expired session")

// Session is the server-side state associated with an authentication cookie.
type Session struct {
	User      User
	CSRFToken string
	ExpiresAt time.Time
}

// CreateSession creates a random bearer token and stores only its SHA-256 hash.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, Session, error) {
	if ttl <= 0 || ttl > maximumSessionTTL {
		return "", Session{}, fmt.Errorf("session duration must be positive and not exceed %s", maximumSessionTTL)
	}

	user, err := s.userByID(ctx, userID)
	if err != nil {
		return "", Session{}, err
	}
	token, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	csrfToken, err := randomToken()
	if err != nil {
		return "", Session{}, err
	}
	tokenHash := sha256.Sum256([]byte(token))
	now := s.now().UTC()
	expiresAt := now.Add(ttl)

	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at <= ?", now.Format(time.RFC3339Nano)); err != nil {
		return "", Session{}, fmt.Errorf("clean expired sessions: %w", err)
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (user_id, token_hash, csrf_token, expires_at)
		VALUES (?, ?, ?, ?)
	`, userID, tokenHash[:], csrfToken, expiresAt.Format(time.RFC3339Nano)); err != nil {
		return "", Session{}, fmt.Errorf("create session: %w", err)
	}

	return token, Session{User: user, CSRFToken: csrfToken, ExpiresAt: expiresAt}, nil
}

// SessionByToken resolves a bearer token to an active, unexpired session.
func (s *Store) SessionByToken(ctx context.Context, token string) (Session, error) {
	if token == "" || len(token) > 256 {
		return Session{}, ErrInvalidSession
	}
	tokenHash := sha256.Sum256([]byte(token))
	now := s.now().UTC().Format(time.RFC3339Nano)

	var session Session
	var expiresAt string
	err := s.db.QueryRowContext(ctx, `
		SELECT users.id, users.username, users.role, sessions.csrf_token, sessions.expires_at
		FROM sessions
		JOIN users ON users.id = sessions.user_id
		WHERE sessions.token_hash = ?
		  AND sessions.expires_at > ?
		  AND users.active = 1
	`, tokenHash[:], now).Scan(
		&session.User.ID,
		&session.User.Username,
		&session.User.Role,
		&session.CSRFToken,
		&expiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrInvalidSession
	}
	if err != nil {
		return Session{}, fmt.Errorf("read session: %w", err)
	}
	session.ExpiresAt, err = time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("parse session expiry: %w", err)
	}
	return session, nil
}

// DeleteSession invalidates a bearer token immediately.
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	if token == "" || len(token) > 256 {
		return nil
	}
	tokenHash := sha256.Sum256([]byte(token))
	if _, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token_hash = ?", tokenHash[:]); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

func randomToken() (string, error) {
	buffer := make([]byte, tokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", fmt.Errorf("generate secure token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
