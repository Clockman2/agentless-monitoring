package main

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestCreateInitialAdministrator(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "bootstrap.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	store := auth.NewStore(db)
	var output bytes.Buffer
	if err := createInitialAdministrator(
		context.Background(),
		store,
		"bootstrap.admin",
		bytes.NewBufferString("a secure bootstrap password\na secure bootstrap password\n"),
		&output,
	); err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	initialized, err := store.Initialized(context.Background())
	if err != nil || !initialized {
		t.Fatalf("initialized = %t, error = %v", initialized, err)
	}
}

func TestCreateInitialAdministratorRejectsMismatch(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "bootstrap.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	err = createInitialAdministrator(
		context.Background(),
		auth.NewStore(db),
		"bootstrap.admin",
		bytes.NewBufferString("first secure password\nsecond secure password\n"),
		&bytes.Buffer{},
	)
	if err == nil {
		t.Fatal("mismatched passwords were accepted")
	}
}
