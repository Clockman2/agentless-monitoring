package storage

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestOpenCreatesSecureMigratedDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "monitoring.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat database: %v", err)
	}
	if got := info.Mode().Perm(); got != databaseFileMode {
		t.Errorf("database permissions = %o, want %o", got, databaseFileMode)
	}

	assertTableExists(t, db, "users")
	assertTableExists(t, db, "audit_events")
	assertTableExists(t, db, "sessions")

	var migrationCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&migrationCount); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migrationCount != 2 {
		t.Errorf("migration count = %d, want 2", migrationCount)
	}

	var foreignKeys int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
		t.Fatalf("read foreign_keys pragma: %v", err)
	}
	if foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, want 1", foreignKeys)
	}

	if _, err := db.Exec(`
		INSERT INTO audit_events (actor_user_id, action, outcome)
		VALUES (999, 'test.action', 'success')
	`); err == nil {
		t.Error("foreign key violation unexpectedly succeeded")
	}
}

func TestOpenAppliesMigrationsOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "monitoring.db")

	db, err := Open(context.Background(), path)
	if err != nil {
		t.Fatalf("first Open() error = %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close first database: %v", err)
	}

	db, err = Open(context.Background(), path)
	if err != nil {
		t.Fatalf("second Open() error = %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM schema_migrations").Scan(&count); err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if count != 2 {
		t.Errorf("migration count = %d, want 2", count)
	}
}

func TestOpenRejectsSymbolicLink(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real.db")
	if err := os.WriteFile(realPath, nil, databaseFileMode); err != nil {
		t.Fatalf("create target: %v", err)
	}
	linkPath := filepath.Join(directory, "link.db")
	if err := os.Symlink(realPath, linkPath); err != nil {
		t.Fatalf("create symbolic link: %v", err)
	}

	if _, err := Open(context.Background(), linkPath); err == nil {
		t.Fatal("Open() unexpectedly accepted a symbolic link")
	}
}

func assertTableExists(t *testing.T, db *sql.DB, name string) {
	t.Helper()

	var count int
	if err := db.QueryRow(
		"SELECT COUNT(*) FROM sqlite_schema WHERE type = 'table' AND name = ?",
		name,
	).Scan(&count); err != nil {
		t.Fatalf("check table %s: %v", name, err)
	}
	if count != 1 {
		t.Errorf("table %s count = %d, want 1", name, count)
	}
}
