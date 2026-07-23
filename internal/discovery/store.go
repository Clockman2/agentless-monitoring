// Package discovery finds responsive devices on bounded local IPv4 networks.
package discovery

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type JobStatus string

const (
	JobPending   JobStatus = "pending"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
)

var (
	ErrInvalidGroup = errors.New("group name must be 1-100 printable characters")
	ErrNoDevices    = errors.New("select at least one discovered device")
)

type Job struct {
	ID                 int64
	Target             string
	Status             JobStatus
	TotalAddresses     int
	ProcessedAddresses int
	ResponsiveHosts    int
	Error              string
	CreatedAt          string
}

type Device struct {
	ID            int64
	JobID         int64
	Address       string
	DetectedPort  *uint16
	OpenPorts     []uint16
	OpenPortsText string
	Status        string
	MachineID     *int64
	DiscoveredAt  string
}

type Group struct {
	ID           int64
	Name         string
	MachineCount int
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) CreateJob(ctx context.Context, actorUserID int64, target string, total int) (Job, error) {
	result, err := s.db.ExecContext(ctx, `
		INSERT INTO discovery_jobs (target_cidr, total_addresses, created_by)
		VALUES (?, ?, ?)
	`, target, total, actorUserID)
	if err != nil {
		return Job{}, fmt.Errorf("create discovery job: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return Job{}, fmt.Errorf("read discovery job ID: %w", err)
	}
	return s.Job(ctx, id)
}

func (s *Store) Job(ctx context.Context, id int64) (Job, error) {
	var job Job
	err := s.db.QueryRowContext(ctx, `
		SELECT id, target_cidr, status, total_addresses, processed_addresses,
		       responsive_hosts, COALESCE(error, ''), created_at
		FROM discovery_jobs WHERE id = ?
	`, id).Scan(
		&job.ID, &job.Target, &job.Status, &job.TotalAddresses,
		&job.ProcessedAddresses, &job.ResponsiveHosts, &job.Error, &job.CreatedAt,
	)
	if err != nil {
		return Job{}, fmt.Errorf("read discovery job: %w", err)
	}
	return job, nil
}

func (s *Store) ListJobs(ctx context.Context) ([]Job, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, target_cidr, status, total_addresses, processed_addresses,
		       responsive_hosts, COALESCE(error, ''), created_at
		FROM discovery_jobs ORDER BY id DESC LIMIT 20
	`)
	if err != nil {
		return nil, fmt.Errorf("list discovery jobs: %w", err)
	}
	defer rows.Close()

	var jobs []Job
	for rows.Next() {
		var job Job
		if err := rows.Scan(
			&job.ID, &job.Target, &job.Status, &job.TotalAddresses,
			&job.ProcessedAddresses, &job.ResponsiveHosts, &job.Error, &job.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan discovery job: %w", err)
		}
		jobs = append(jobs, job)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate discovery jobs: %w", err)
	}
	return jobs, nil
}

func (s *Store) MarkRunning(ctx context.Context, id int64) error {
	return s.updateJobStatus(ctx, id, JobRunning, "", "started_at = CURRENT_TIMESTAMP")
}

func (s *Store) RecordProbe(ctx context.Context, jobID int64, address string, openPorts []uint16) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin discovery result: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	responsive := 0
	if address != "" {
		responsive = 1
		ports := normalizedPorts(openPorts)
		var primaryPort any
		if port, ok := preferredPort(ports); ok {
			primaryPort = int(port)
		}
		var deviceID int64
		err := tx.QueryRowContext(ctx, `
			INSERT INTO discovered_devices (job_id, address, detected_port)
			VALUES (?, ?, ?)
			ON CONFLICT(job_id, address) DO UPDATE SET detected_port = excluded.detected_port
			RETURNING id
		`, jobID, address, primaryPort).Scan(&deviceID)
		if err != nil {
			return fmt.Errorf("record discovered device: %w", err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM discovered_device_ports WHERE device_id = ?", deviceID); err != nil {
			return fmt.Errorf("replace discovered ports: %w", err)
		}
		for _, port := range ports {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO discovered_device_ports (device_id, port) VALUES (?, ?)
			`, deviceID, int(port)); err != nil {
				return fmt.Errorf("record discovered port: %w", err)
			}
		}
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE discovery_jobs
		SET processed_addresses = processed_addresses + 1,
		    responsive_hosts = responsive_hosts + ?
		WHERE id = ? AND status = 'running'
	`, responsive, jobID)
	if err != nil {
		return fmt.Errorf("update discovery progress: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit discovery result: %w", err)
	}
	return nil
}

func (s *Store) Complete(ctx context.Context, id int64) error {
	return s.updateJobStatus(ctx, id, JobCompleted, "", "completed_at = CURRENT_TIMESTAMP")
}

func (s *Store) Fail(ctx context.Context, id int64, cause error) error {
	message := "discovery failed"
	if cause != nil {
		message = cause.Error()
	}
	if len(message) > 500 {
		message = message[:500]
	}
	return s.updateJobStatus(ctx, id, JobFailed, message, "completed_at = CURRENT_TIMESTAMP")
}

func (s *Store) updateJobStatus(ctx context.Context, id int64, status JobStatus, message, timestampSet string) error {
	query := `UPDATE discovery_jobs SET status = ?, error = NULL, ` + timestampSet + ` WHERE id = ?`
	arguments := []any{status, id}
	if message != "" {
		query = `UPDATE discovery_jobs SET status = ?, error = ?, ` + timestampSet + ` WHERE id = ?`
		arguments = []any{status, message, id}
	}
	result, err := s.db.ExecContext(ctx, query, arguments...)
	if err != nil {
		return fmt.Errorf("update discovery job status: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) ListDevices(ctx context.Context, jobID int64) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT devices.id, devices.job_id, devices.address, devices.detected_port,
		       devices.status, devices.machine_id, devices.discovered_at,
		       COALESCE(group_concat(ports.port), '')
		FROM discovered_devices AS devices
		LEFT JOIN discovered_device_ports AS ports ON ports.device_id = devices.id
		WHERE devices.job_id = ?
		GROUP BY devices.id
		ORDER BY devices.address
	`, jobID)
	if err != nil {
		return nil, fmt.Errorf("list discovered devices: %w", err)
	}
	defer rows.Close()

	var devices []Device
	for rows.Next() {
		var device Device
		var port, machineID sql.NullInt64
		var openPorts string
		if err := rows.Scan(
			&device.ID, &device.JobID, &device.Address, &port,
			&device.Status, &machineID, &device.DiscoveredAt, &openPorts,
		); err != nil {
			return nil, fmt.Errorf("scan discovered device: %w", err)
		}
		if port.Valid {
			value := uint16(port.Int64)
			device.DetectedPort = &value
		}
		if machineID.Valid {
			value := machineID.Int64
			device.MachineID = &value
		}
		device.OpenPorts = parsePorts(openPorts)
		device.OpenPortsText = formatPorts(device.OpenPorts)
		devices = append(devices, device)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate discovered devices: %w", err)
	}
	return devices, nil
}

func (s *Store) ListGroups(ctx context.Context) ([]Group, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT groups.id, groups.name, COUNT(machine_groups.machine_id)
		FROM groups
		LEFT JOIN machine_groups ON machine_groups.group_id = groups.id
		GROUP BY groups.id, groups.name
		ORDER BY groups.name COLLATE NOCASE
	`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	var groups []Group
	for rows.Next() {
		var group Group
		if err := rows.Scan(&group.ID, &group.Name, &group.MachineCount); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, rows.Err()
}

func (s *Store) ImportDevices(ctx context.Context, actorUserID, jobID int64, deviceIDs []int64, groupName string) (int, error) {
	groupName = strings.TrimSpace(groupName)
	if len(groupName) == 0 || len(groupName) > 100 || strings.ContainsFunc(groupName, unicode.IsControl) {
		return 0, ErrInvalidGroup
	}
	if len(deviceIDs) == 0 {
		return 0, ErrNoDevices
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin device import: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO groups (name) VALUES (?)
		ON CONFLICT(name) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
	`, groupName); err != nil {
		return 0, fmt.Errorf("create discovery group: %w", err)
	}
	var groupID int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM groups WHERE name = ? COLLATE NOCASE", groupName).Scan(&groupID); err != nil {
		return 0, fmt.Errorf("read discovery group: %w", err)
	}

	imported := 0
	for _, deviceID := range uniquePositiveIDs(deviceIDs) {
		var address string
		var port sql.NullInt64
		var status string
		if err := tx.QueryRowContext(ctx, `
			SELECT address, detected_port, status
			FROM discovered_devices WHERE id = ? AND job_id = ?
		`, deviceID, jobID).Scan(&address, &port, &status); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return 0, fmt.Errorf("read device for import: %w", err)
		}
		if status == "imported" {
			continue
		}

		checkType, checkPort := checkForDetectedPort(port)
		machineID, err := findOrCreateMachine(ctx, tx, address, checkType, checkPort)
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO machine_groups (machine_id, group_id) VALUES (?, ?)
			ON CONFLICT(machine_id, group_id) DO NOTHING
		`, machineID, groupID); err != nil {
			return 0, fmt.Errorf("assign machine group: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE discovered_devices SET status = 'imported', machine_id = ? WHERE id = ?
		`, machineID, deviceID); err != nil {
			return 0, fmt.Errorf("mark discovered device imported: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_events (actor_user_id, action, object_type, object_id, outcome)
			VALUES (?, 'discovery.device_imported', 'machine', ?, 'success')
		`, actorUserID, strconv.FormatInt(machineID, 10)); err != nil {
			return 0, fmt.Errorf("record device import audit event: %w", err)
		}
		imported++
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit device import: %w", err)
	}
	return imported, nil
}

func uniquePositiveIDs(ids []int64) []int64 {
	seen := make(map[int64]struct{}, len(ids))
	result := make([]int64, 0, len(ids))
	for _, id := range ids {
		if id < 1 {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

func normalizedPorts(ports []uint16) []uint16 {
	unique := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port != 0 {
			unique[port] = struct{}{}
		}
	}
	result := make([]uint16, 0, len(unique))
	for port := range unique {
		result = append(result, port)
	}
	slices.Sort(result)
	return result
}

func preferredPort(ports []uint16) (uint16, bool) {
	for _, preferred := range []uint16{443, 80, 22} {
		if slices.Contains(ports, preferred) {
			return preferred, true
		}
	}
	if len(ports) == 0 {
		return 0, false
	}
	return ports[0], true
}

func parsePorts(value string) []uint16 {
	var ports []uint16
	for _, field := range strings.Split(value, ",") {
		port, err := strconv.ParseUint(field, 10, 16)
		if err == nil && port != 0 {
			ports = append(ports, uint16(port))
		}
	}
	return normalizedPorts(ports)
}

func formatPorts(ports []uint16) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.FormatUint(uint64(port), 10))
	}
	return strings.Join(values, ", ")
}

func checkForDetectedPort(port sql.NullInt64) (string, int) {
	if !port.Valid {
		return "tcp", 22
	}
	switch port.Int64 {
	case 80:
		return "http", 80
	case 443:
		return "https", 443
	default:
		return "tcp", int(port.Int64)
	}
}

func findOrCreateMachine(ctx context.Context, tx *sql.Tx, address, checkType string, port int) (int64, error) {
	var machineID int64
	err := tx.QueryRowContext(ctx, `
		SELECT machines.id
		FROM machines JOIN checks ON checks.machine_id = machines.id
		WHERE machines.target = ? AND checks.check_type = ? AND checks.port = ? AND checks.path = '/'
		LIMIT 1
	`, address, checkType, port).Scan(&machineID)
	if err == nil {
		return machineID, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("find existing discovered machine: %w", err)
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO machines (display_name, target, description)
		VALUES (?, ?, 'Added by local network discovery')
	`, address, address)
	if err != nil {
		return 0, fmt.Errorf("create discovered machine: %w", err)
	}
	machineID, err = result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("read discovered machine ID: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO checks (machine_id, check_type, port, path, timeout_ms)
		VALUES (?, ?, ?, '/', ?)
	`, machineID, checkType, port, (5 * time.Second).Milliseconds()); err != nil {
		return 0, fmt.Errorf("create discovered machine check: %w", err)
	}
	return machineID, nil
}
