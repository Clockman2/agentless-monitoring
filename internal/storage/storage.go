// Package storage owns the application's SQLite connection and schema.
package storage

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

const (
	databaseFileMode = 0o600
	databaseDirMode  = 0o700
)

// Open prepares a SQLite database, applies connection safety settings, and
// runs all pending schema migrations.
func Open(ctx context.Context, path string) (*sql.DB, error) {
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve database path: %w", err)
	}

	if err := ensureDatabaseFile(absolutePath); err != nil {
		return nil, err
	}

	dsn := (&url.URL{Scheme: "file", Path: absolutePath}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	if err := configure(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

func ensureDatabaseFile(path string) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, databaseDirMode); err != nil {
		return fmt.Errorf("create database directory: %w", err)
	}

	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("database path must not be a symbolic link")
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect database path: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, databaseFileMode)
	if err != nil {
		return fmt.Errorf("create database file: %w", err)
	}
	info, err = file.Stat()
	if err != nil {
		_ = file.Close()
		return fmt.Errorf("inspect database file: %w", err)
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return fmt.Errorf("database path must be a regular file")
	}
	if err := file.Chmod(databaseFileMode); err != nil {
		_ = file.Close()
		return fmt.Errorf("secure database file permissions: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close database file: %w", err)
	}
	return nil
}

func configure(ctx context.Context, db *sql.DB) error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
	}
	for _, statement := range pragmas {
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure database: %w", err)
		}
	}
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}
