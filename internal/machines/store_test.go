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
	if created.CheckInterval != time.Minute || created.FailureThreshold != 3 || created.RecoveryThreshold != 1 {
		t.Fatalf("created check policy = %#v", created)
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

	if err := store.RecordResult(context.Background(), user.ID, created.CheckID, StatusHealthy, 23*time.Millisecond, "TCP connection succeeded"); err != nil {
		t.Fatalf("RecordResult() error = %v", err)
	}
	listed, err = store.List(context.Background())
	if err != nil {
		t.Fatalf("List() after result error = %v", err)
	}
	if listed[0].Status != StatusHealthy || listed[0].ResponseTimeMS == nil || *listed[0].ResponseTimeMS != 23 {
		t.Fatalf("machine after result = %#v", listed[0])
	}
	summary, err = store.Summary(context.Background())
	if err != nil {
		t.Fatalf("Summary() after result error = %v", err)
	}
	if summary.Healthy != 1 || summary.Unknown != 0 {
		t.Fatalf("summary after result = %#v", summary)
	}
	results, err := store.ListResults(context.Background(), created.CheckID, 10)
	if err != nil {
		t.Fatalf("ListResults() error = %v", err)
	}
	if len(results) != 1 || results[0].Worker != "manual" || results[0].Summary != "TCP connection succeeded" {
		t.Fatalf("check results = %#v", results)
	}
	due, err := store.ListDue(context.Background(), time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("ListDue() error = %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("immediately due checks = %#v", due)
	}
	due, err = store.ListDue(context.Background(), time.Now().UTC().Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("ListDue() future error = %v", err)
	}
	if len(due) != 1 || due[0].CheckID != created.CheckID {
		t.Fatalf("future due checks = %#v", due)
	}

	for attempt := 1; attempt <= 2; attempt++ {
		if err := store.RecordScheduledResult(context.Background(), created.CheckID, StatusCritical, 40*time.Millisecond, "network", "connection refused", "worker-1"); err != nil {
			t.Fatalf("RecordScheduledResult(failure %d) error = %v", attempt, err)
		}
	}
	listed, err = store.List(context.Background())
	if err != nil {
		t.Fatalf("List() below threshold error = %v", err)
	}
	if listed[0].Status != StatusHealthy || listed[0].ConsecutiveFailures != 2 {
		t.Fatalf("machine below failure threshold = %#v", listed[0])
	}
	if err := store.RecordScheduledResult(context.Background(), created.CheckID, StatusCritical, 40*time.Millisecond, "network", "connection refused", "worker-1"); err != nil {
		t.Fatalf("RecordScheduledResult(threshold failure) error = %v", err)
	}
	listed, err = store.List(context.Background())
	if err != nil {
		t.Fatalf("List() at threshold error = %v", err)
	}
	if listed[0].Status != StatusCritical || listed[0].ConsecutiveFailures != 3 {
		t.Fatalf("machine at failure threshold = %#v", listed[0])
	}
	if err := store.RecordScheduledResult(context.Background(), created.CheckID, StatusHealthy, 12*time.Millisecond, "", "connection restored", "worker-2"); err != nil {
		t.Fatalf("RecordScheduledResult(recovery) error = %v", err)
	}
	listed, err = store.List(context.Background())
	if err != nil {
		t.Fatalf("List() after recovery error = %v", err)
	}
	if listed[0].Status != StatusHealthy || listed[0].ConsecutiveFailures != 0 || listed[0].ConsecutiveSuccesses != 1 {
		t.Fatalf("machine after recovery = %#v", listed[0])
	}
	results, err = store.ListResults(context.Background(), created.CheckID, 10)
	if err != nil {
		t.Fatalf("ListResults() after threshold sequence error = %v", err)
	}
	if len(results) != 5 || results[1].ErrorCategory != "network" || results[0].Worker != "worker-2" {
		t.Fatalf("threshold history = %#v", results)
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
