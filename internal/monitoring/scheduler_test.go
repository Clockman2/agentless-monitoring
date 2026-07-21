package monitoring

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/machines"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

type fixedRunner struct {
	result Result
}

func (r fixedRunner) Run(context.Context, machines.Machine) Result { return r.result }

func TestSchedulerRunsDueCheckOnceAndStops(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "scheduler.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := auth.NewStore(db).CreateAdministrator(ctx, "scheduler.admin", "a secure test password")
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	store := machines.NewStore(db)
	machine, err := store.Create(ctx, user.ID, machines.CreateInput{
		Name: "Scheduled target", Target: "127.0.0.1", CheckType: machines.CheckTCP,
		Port: 443, CheckInterval: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("create machine: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	scheduler := NewScheduler(store, fixedRunner{result: Result{
		Status: machines.StatusHealthy, Summary: "scheduled success", ResponseTime: 8 * time.Millisecond,
	}}, SchedulerOptions{Workers: 2, PollInterval: 10 * time.Millisecond})
	done := make(chan struct{})
	go func() {
		defer close(done)
		scheduler.Run(runCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		results, err := store.ListResults(ctx, machine.CheckID, 10)
		if err != nil {
			t.Fatalf("list scheduled results: %v", err)
		}
		if len(results) == 1 {
			if results[0].Worker != "check-worker-01" && results[0].Worker != "check-worker-02" {
				t.Fatalf("scheduled worker = %q", results[0].Worker)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("scheduler did not stop after cancellation")
	}
	results, err := store.ListResults(ctx, machine.CheckID, 10)
	if err != nil {
		t.Fatalf("list final scheduled results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("scheduled result count = %d, want 1", len(results))
	}
	stats := scheduler.Stats()
	if stats.Running || stats.WorkerCount != 2 || stats.InFlight != 0 || stats.LastCompletedAt == nil {
		t.Fatalf("scheduler stats = %#v", stats)
	}
}
