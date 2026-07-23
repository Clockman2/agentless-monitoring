package auth

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestCreateAdministratorAndAuthenticate(t *testing.T) {
	store, db := newTestStore(t)
	ctx := context.Background()

	initialized, err := store.Initialized(ctx)
	if err != nil {
		t.Fatalf("Initialized() error = %v", err)
	}
	if initialized {
		t.Fatal("fresh store is already initialized")
	}

	created, err := store.CreateAdministrator(ctx, " admin.user ", "a secure test password")
	if err != nil {
		t.Fatalf("CreateAdministrator() error = %v", err)
	}
	if created.Username != "admin.user" || created.Role != AdministratorRole {
		t.Fatalf("created user = %#v", created)
	}

	var storedHash string
	if err := db.QueryRow("SELECT password_hash FROM users WHERE id = ?", created.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read password hash: %v", err)
	}
	if storedHash == "a secure test password" {
		t.Fatal("database contains the plaintext password")
	}

	authenticated, err := store.Authenticate(ctx, "ADMIN.USER", "a secure test password", "192.0.2.10")
	if err != nil {
		t.Fatalf("Authenticate() error = %v", err)
	}
	if authenticated.ID != created.ID {
		t.Errorf("authenticated user ID = %d, want %d", authenticated.ID, created.ID)
	}

	if _, err := store.Authenticate(ctx, "admin.user", "wrong password", "192.0.2.10"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v, want ErrInvalidCredentials", err)
	}
	if _, err := store.CreateAdministrator(ctx, "second.admin", "another secure password"); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second administrator error = %v, want ErrAlreadyInitialized", err)
	}

	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount != 3 {
		t.Errorf("audit event count = %d, want 3", auditCount)
	}
	var sourceIP string
	if err := db.QueryRow(`
		SELECT source_ip FROM audit_events
		WHERE action = 'user.login' ORDER BY id DESC LIMIT 1
	`).Scan(&sourceIP); err != nil {
		t.Fatalf("read login source IP: %v", err)
	}
	if sourceIP != "192.0.2.10" {
		t.Errorf("login source IP = %q, want 192.0.2.10", sourceIP)
	}
}

func newTestStore(t *testing.T) (*Store, *sql.DB) {
	t.Helper()

	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "auth.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Store{
		db: db, now: time.Now, passwordParams: testPasswordParams,
		passwordSlots: make(chan struct{}, maximumConcurrentPasswordOperations),
	}, db
}
