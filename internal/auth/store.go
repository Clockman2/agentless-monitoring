// Package auth provides user authentication and server-side sessions.
package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	AdministratorRole = "administrator"
)

var (
	ErrAlreadyInitialized = errors.New("administrator account already exists")
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrInvalidUsername    = errors.New("invalid username")

	usernamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$`)
)

// User is an authenticated application user.
type User struct {
	ID       int64
	Username string
	Role     string
}

// Store persists users, authentication audit events, and sessions.
type Store struct {
	db             *sql.DB
	now            func() time.Time
	passwordParams passwordParams
}

// NewStore creates an authentication store backed by the application database.
func NewStore(db *sql.DB) *Store {
	return &Store{
		db:             db,
		now:            time.Now,
		passwordParams: productionPasswordParams,
	}
}

// Initialized reports whether the first user account has been created.
func (s *Store) Initialized(ctx context.Context) (bool, error) {
	var initialized bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users)").Scan(&initialized); err != nil {
		return false, fmt.Errorf("check authentication setup: %w", err)
	}
	return initialized, nil
}

// CreateAdministrator atomically creates the first administrator account.
func (s *Store) CreateAdministrator(ctx context.Context, username, password string) (User, error) {
	initialized, err := s.Initialized(ctx)
	if err != nil {
		return User{}, err
	}
	if initialized {
		return User{}, ErrAlreadyInitialized
	}

	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) {
		return User{}, fmt.Errorf("%w: must be 3-64 characters using letters, numbers, dot, dash, or underscore", ErrInvalidUsername)
	}
	if err := validateNewPassword(password); err != nil {
		return User{}, err
	}

	passwordHash, err := hashPassword(password, s.passwordParams)
	if err != nil {
		return User{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return User{}, fmt.Errorf("begin administrator setup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var alreadyInitialized bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM users)").Scan(&alreadyInitialized); err != nil {
		return User{}, fmt.Errorf("check administrator setup: %w", err)
	}
	if alreadyInitialized {
		return User{}, ErrAlreadyInitialized
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO users (username, password_hash, role)
		VALUES (?, ?, ?)
	`, username, passwordHash, AdministratorRole)
	if err != nil {
		return User{}, fmt.Errorf("create administrator: %w", err)
	}
	userID, err := result.LastInsertId()
	if err != nil {
		return User{}, fmt.Errorf("read administrator ID: %w", err)
	}
	if err := insertAuditEvent(ctx, tx, &userID, "user.created", "success", "user", strconv.FormatInt(userID, 10)); err != nil {
		return User{}, err
	}
	if err := tx.Commit(); err != nil {
		return User{}, fmt.Errorf("commit administrator setup: %w", err)
	}

	return User{ID: userID, Username: username, Role: AdministratorRole}, nil
}

// Authenticate verifies credentials and records the outcome in the audit log.
func (s *Store) Authenticate(ctx context.Context, username, password string) (User, error) {
	username = strings.TrimSpace(username)
	if !usernamePattern.MatchString(username) || len(password) > maximumPasswordBytes {
		burnPasswordAttempt(password, s.passwordParams)
		if err := s.recordLogin(ctx, nil, "failure"); err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}

	var user User
	var passwordHash string
	err := s.db.QueryRowContext(ctx, `
		SELECT id, username, role, password_hash
		FROM users
		WHERE username = ? AND active = 1
	`, username).Scan(&user.ID, &user.Username, &user.Role, &passwordHash)
	if errors.Is(err, sql.ErrNoRows) {
		burnPasswordAttempt(password, s.passwordParams)
		if err := s.recordLogin(ctx, nil, "failure"); err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		return User{}, fmt.Errorf("read user credentials: %w", err)
	}

	valid, err := verifyPassword(password, passwordHash)
	if err != nil {
		return User{}, fmt.Errorf("verify stored password hash: %w", err)
	}
	if !valid {
		if err := s.recordLogin(ctx, &user.ID, "failure"); err != nil {
			return User{}, err
		}
		return User{}, ErrInvalidCredentials
	}
	if err := s.recordLogin(ctx, &user.ID, "success"); err != nil {
		return User{}, err
	}
	return user, nil
}

func (s *Store) userByID(ctx context.Context, userID int64) (User, error) {
	var user User
	if err := s.db.QueryRowContext(ctx, `
		SELECT id, username, role FROM users WHERE id = ? AND active = 1
	`, userID).Scan(&user.ID, &user.Username, &user.Role); err != nil {
		return User{}, fmt.Errorf("read session user: %w", err)
	}
	return user, nil
}

func (s *Store) recordLogin(ctx context.Context, userID *int64, outcome string) error {
	if err := insertAuditEvent(ctx, s.db, userID, "user.login", outcome, "", ""); err != nil {
		return err
	}
	return nil
}

type queryExecer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func insertAuditEvent(ctx context.Context, db queryExecer, userID *int64, action, outcome, objectType, objectID string) error {
	if _, err := db.ExecContext(ctx, `
		INSERT INTO audit_events (actor_user_id, action, object_type, object_id, outcome)
		VALUES (?, ?, NULLIF(?, ''), NULLIF(?, ''), ?)
	`, userID, action, objectType, objectID, outcome); err != nil {
		return fmt.Errorf("record authentication audit event: %w", err)
	}
	return nil
}
