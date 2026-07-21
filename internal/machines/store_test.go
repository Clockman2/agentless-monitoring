package machines

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestCreateListAndSummarize(t *testing.T) {
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "machines.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	authStore := auth.NewStore(db)
	user, err := authStore.CreateAdministrator(context.Background(), "machine.admin", "a secure test password")
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	store := NewStore(db)
	created, err := store.Create(context.Background(), user.ID, CreateInput{
		Name: " Gateway ", Target: "192.0.2.10", Description: "POC target",
		CheckType: CheckTCP, Port: 443, Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created.Name != "Gateway" || created.Status != StatusUnknown || created.Port != 443 {
		t.Fatalf("created machine = %#v", created)
	}

	listed, err := store.List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if len(listed) != 1 || listed[0].ID != created.ID {
		t.Fatalf("listed machines = %#v", listed)
	}
	summary, err := store.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary() error = %v", err)
	}
	if summary.Total != 1 || summary.Unknown != 1 {
		t.Fatalf("summary = %#v", summary)
	}

	var auditCount int
	if err := db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE action = 'machine.created'").Scan(&auditCount); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if auditCount != 1 {
		t.Errorf("machine audit event count = %d, want 1", auditCount)
	}

	if _, err := store.Create(context.Background(), user.ID, CreateInput{
		Name: "Duplicate", Target: "192.0.2.10", CheckType: CheckTCP, Port: 443,
	}); err != ErrDuplicate {
		t.Fatalf("duplicate error = %v, want ErrDuplicate", err)
	}
}

func TestCreateRejectsHostnameAndInvalidPort(t *testing.T) {
	tests := []CreateInput{
		{Name: "DNS target", Target: "example.invalid", CheckType: CheckTCP, Port: 443},
		{Name: "Bad port", Target: "127.0.0.1", CheckType: CheckTCP, Port: 70000},
	}
	for _, input := range tests {
		if _, err := validateCreateInput(input); err == nil {
			t.Errorf("validateCreateInput(%#v) unexpectedly succeeded", input)
		}
	}
}
