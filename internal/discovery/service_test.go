package discovery

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestServiceCompletesBackgroundScan(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "service.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	user, err := auth.NewStore(db).CreateAdministrator(ctx, "service.admin", "a secure test password")
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}

	store := NewStore(db)
	service := NewService(ctx, store, nil)
	service.scanner = &Scanner{
		workers: 2,
		ports:   []uint16{443},
		probe: func(context.Context, netip.Addr, uint16) (bool, bool) {
			return false, false
		},
	}
	job, err := service.Start(ctx, user.ID, "192.168.40.0/30")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		job, err = store.Job(ctx, job.ID)
		if err != nil {
			t.Fatalf("Job() error = %v", err)
		}
		if job.Status == JobCompleted {
			if job.ProcessedAddresses != 2 || job.ResponsiveHosts != 0 {
				t.Fatalf("completed job = %#v", job)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("job did not complete: %#v", job)
}
