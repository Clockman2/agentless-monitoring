package discovery

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestDiscoveryLifecycleAndImport(t *testing.T) {
	ctx := context.Background()
	db, err := storage.Open(ctx, filepath.Join(t.TempDir(), "discovery.db"))
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	user, err := auth.NewStore(db).CreateAdministrator(ctx, "discovery.admin", "a secure test password")
	if err != nil {
		t.Fatalf("create administrator: %v", err)
	}
	store := NewStore(db)
	job, err := store.CreateJob(ctx, user.ID, "192.168.50.0/30", 2)
	if err != nil {
		t.Fatalf("CreateJob() error = %v", err)
	}
	if err := store.MarkRunning(ctx, job.ID); err != nil {
		t.Fatalf("MarkRunning() error = %v", err)
	}
	if err := store.RecordProbe(ctx, job.ID, "192.168.50.1", []uint16{2083, 22, 443, 2083}); err != nil {
		t.Fatalf("RecordProbe(active) error = %v", err)
	}
	if err := store.RecordProbe(ctx, job.ID, "", nil); err != nil {
		t.Fatalf("RecordProbe(inactive) error = %v", err)
	}
	if err := store.Complete(ctx, job.ID); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	job, err = store.Job(ctx, job.ID)
	if err != nil {
		t.Fatalf("Job() error = %v", err)
	}
	if job.Status != JobCompleted || job.ProcessedAddresses != 2 || job.ResponsiveHosts != 1 {
		t.Fatalf("completed job = %#v", job)
	}
	devices, err := store.ListDevices(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListDevices() error = %v", err)
	}
	if len(devices) != 1 || devices[0].DetectedPort == nil || *devices[0].DetectedPort != 443 ||
		devices[0].OpenPortsText != "22, 443, 2083" || devices[0].GuessedType != "cPanel/WHM server" {
		t.Fatalf("devices = %#v", devices)
	}

	count, err := store.ImportDevices(ctx, user.ID, job.ID, []int64{devices[0].ID, devices[0].ID}, "Servers")
	if err != nil {
		t.Fatalf("ImportDevices() error = %v", err)
	}
	if count != 1 {
		t.Fatalf("imported count = %d, want 1", count)
	}
	groups, err := store.ListGroups(ctx)
	if err != nil {
		t.Fatalf("ListGroups() error = %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "Servers" || groups[0].MachineCount != 1 {
		t.Fatalf("groups = %#v", groups)
	}

	devices, err = store.ListDevices(ctx, job.ID)
	if err != nil {
		t.Fatalf("ListDevices() after import error = %v", err)
	}
	if devices[0].Status != "imported" || devices[0].MachineID == nil {
		t.Fatalf("imported device = %#v", devices[0])
	}
	var checkType string
	var checkPort int
	if err := db.QueryRow("SELECT check_type, port FROM checks WHERE machine_id = ?", *devices[0].MachineID).Scan(&checkType, &checkPort); err != nil {
		t.Fatalf("read imported check: %v", err)
	}
	if checkType != "https" || checkPort != 443 {
		t.Fatalf("imported check = %s:%d, want https:443", checkType, checkPort)
	}
}

func TestImportDevicesValidatesSelectionAndGroup(t *testing.T) {
	store := &Store{}
	if _, err := store.ImportDevices(context.Background(), 1, 1, nil, "Servers"); err != ErrNoDevices {
		t.Fatalf("empty selection error = %v, want ErrNoDevices", err)
	}
	if _, err := store.ImportDevices(context.Background(), 1, 1, []int64{1}, " "); err != ErrInvalidGroup {
		t.Fatalf("blank group error = %v, want ErrInvalidGroup", err)
	}
}
