// Package machines manages monitored machines and their health checks.
package machines

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusCritical Status = "critical"
	StatusUnknown  Status = "unknown"
	StatusDisabled Status = "disabled"
)

type CheckType string

const (
	CheckTCP   CheckType = "tcp"
	CheckHTTP  CheckType = "http"
	CheckHTTPS CheckType = "https"
)

var (
	ErrDuplicate    = errors.New("a matching machine check already exists")
	ErrInvalidInput = errors.New("invalid machine configuration")
)

type Machine struct {
	ID                   int64
	Name                 string
	Target               string
	Description          string
	Status               Status
	CheckID              int64
	CheckType            CheckType
	Port                 uint16
	Path                 string
	Timeout              time.Duration
	LastCheckedAt        *time.Time
	ResponseTimeMS       *int64
	LastError            string
	CheckInterval        time.Duration
	FailureThreshold     int
	RecoveryThreshold    int
	ConsecutiveFailures  int
	ConsecutiveSuccesses int
}

type CreateInput struct {
	Name              string
	Target            string
	Description       string
	CheckType         CheckType
	Port              int
	Path              string
	Timeout           time.Duration
	CheckInterval     time.Duration
	FailureThreshold  int
	RecoveryThreshold int
}

type CheckResult struct {
	ID             int64
	CheckID        int64
	Status         Status
	ResponseTimeMS int64
	ErrorCategory  string
	Summary        string
	Worker         string
	CheckedAt      time.Time
}

type Summary struct {
	Total    int
	Healthy  int
	Critical int
	Unknown  int
}

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func (s *Store) Create(ctx context.Context, actorUserID int64, input CreateInput) (Machine, error) {
	input, err := validateCreateInput(input)
	if err != nil {
		return Machine{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Machine{}, fmt.Errorf("begin machine creation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var duplicate bool
	if err := tx.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM machines
			JOIN checks ON checks.machine_id = machines.id
			WHERE machines.target = ? AND checks.check_type = ?
			  AND checks.port = ? AND checks.path = ?
		)
	`, input.Target, input.CheckType, input.Port, input.Path).Scan(&duplicate); err != nil {
		return Machine{}, fmt.Errorf("check duplicate machine: %w", err)
	}
	if duplicate {
		return Machine{}, ErrDuplicate
	}

	result, err := tx.ExecContext(ctx, `
		INSERT INTO machines (display_name, target, description)
		VALUES (?, ?, ?)
	`, input.Name, input.Target, input.Description)
	if err != nil {
		return Machine{}, fmt.Errorf("create machine: %w", err)
	}
	machineID, err := result.LastInsertId()
	if err != nil {
		return Machine{}, fmt.Errorf("read machine ID: %w", err)
	}

	result, err = tx.ExecContext(ctx, `
		INSERT INTO checks (
			machine_id, check_type, port, path, timeout_ms,
			check_interval_seconds, failure_threshold, recovery_threshold
		)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, machineID, input.CheckType, input.Port, input.Path, input.Timeout.Milliseconds(),
		int(input.CheckInterval.Seconds()), input.FailureThreshold, input.RecoveryThreshold)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return Machine{}, ErrDuplicate
		}
		return Machine{}, fmt.Errorf("create machine check: %w", err)
	}
	checkID, err := result.LastInsertId()
	if err != nil {
		return Machine{}, fmt.Errorf("read check ID: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_events (actor_user_id, action, object_type, object_id, outcome)
		VALUES (?, 'machine.created', 'machine', ?, 'success')
	`, actorUserID, strconv.FormatInt(machineID, 10)); err != nil {
		return Machine{}, fmt.Errorf("record machine audit event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Machine{}, fmt.Errorf("commit machine creation: %w", err)
	}

	return Machine{
		ID: machineID, Name: input.Name, Target: input.Target, Description: input.Description,
		Status: StatusUnknown, CheckID: checkID, CheckType: input.CheckType,
		Port: uint16(input.Port), Path: input.Path, Timeout: input.Timeout,
		CheckInterval: input.CheckInterval, FailureThreshold: input.FailureThreshold,
		RecoveryThreshold: input.RecoveryThreshold,
	}, nil
}

func (s *Store) List(ctx context.Context) ([]Machine, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT machines.id, machines.display_name, machines.target, machines.description,
		       machines.status, checks.id, checks.check_type, checks.port, checks.path,
		       checks.timeout_ms, checks.last_checked_at, checks.response_time_ms,
		       COALESCE(checks.last_error, ''), checks.check_interval_seconds,
		       checks.failure_threshold, checks.recovery_threshold,
		       checks.consecutive_failures, checks.consecutive_successes
		FROM machines
		JOIN checks ON checks.machine_id = machines.id
		WHERE machines.enabled = 1 AND checks.enabled = 1
		ORDER BY machines.display_name COLLATE NOCASE, machines.id
	`)
	if err != nil {
		return nil, fmt.Errorf("list machines: %w", err)
	}
	defer rows.Close()

	var machines []Machine
	for rows.Next() {
		var machine Machine
		var port, timeoutMS, intervalSeconds int
		var checkedAt sql.NullString
		var responseTime sql.NullInt64
		if err := rows.Scan(
			&machine.ID, &machine.Name, &machine.Target, &machine.Description,
			&machine.Status, &machine.CheckID, &machine.CheckType, &port, &machine.Path,
			&timeoutMS, &checkedAt, &responseTime, &machine.LastError, &intervalSeconds,
			&machine.FailureThreshold, &machine.RecoveryThreshold,
			&machine.ConsecutiveFailures, &machine.ConsecutiveSuccesses,
		); err != nil {
			return nil, fmt.Errorf("scan machine: %w", err)
		}
		machine.Port = uint16(port)
		machine.Timeout = time.Duration(timeoutMS) * time.Millisecond
		machine.CheckInterval = time.Duration(intervalSeconds) * time.Second
		if checkedAt.Valid {
			parsed, err := time.Parse(time.RFC3339Nano, checkedAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse machine check time: %w", err)
			}
			machine.LastCheckedAt = &parsed
		}
		if responseTime.Valid {
			value := responseTime.Int64
			machine.ResponseTimeMS = &value
		}
		machines = append(machines, machine)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate machines: %w", err)
	}
	return machines, nil
}

func (s *Store) ListDue(ctx context.Context, now time.Time, limit int) ([]Machine, error) {
	if limit < 1 {
		return nil, nil
	}
	all, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	due := make([]Machine, 0, min(limit, len(all)))
	for _, machine := range all {
		if machine.LastCheckedAt != nil && machine.LastCheckedAt.Add(machine.CheckInterval).After(now) {
			continue
		}
		due = append(due, machine)
		if len(due) == limit {
			break
		}
	}
	return due, nil
}

func (s *Store) Summary(ctx context.Context) (Summary, error) {
	var summary Summary
	if err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*),
		       COALESCE(SUM(status = 'healthy'), 0),
		       COALESCE(SUM(status = 'critical'), 0),
		       COALESCE(SUM(status = 'unknown'), 0)
		FROM machines WHERE enabled = 1
	`).Scan(&summary.Total, &summary.Healthy, &summary.Critical, &summary.Unknown); err != nil {
		return Summary{}, fmt.Errorf("summarize machines: %w", err)
	}
	return summary, nil
}

func (s *Store) GetByCheckID(ctx context.Context, checkID int64) (Machine, error) {
	machines, err := s.List(ctx)
	if err != nil {
		return Machine{}, err
	}
	for _, machine := range machines {
		if machine.CheckID == checkID {
			return machine, nil
		}
	}
	return Machine{}, sql.ErrNoRows
}

func (s *Store) RecordResult(ctx context.Context, actorUserID, checkID int64, status Status, elapsed time.Duration, summary string) error {
	return s.recordResult(ctx, &actorUserID, checkID, status, elapsed, "", summary, "manual")
}

func (s *Store) RecordScheduledResult(ctx context.Context, checkID int64, status Status, elapsed time.Duration, errorCategory, summary, worker string) error {
	return s.recordResult(ctx, nil, checkID, status, elapsed, errorCategory, summary, worker)
}

func (s *Store) recordResult(ctx context.Context, actorUserID *int64, checkID int64, status Status, elapsed time.Duration, errorCategory, summary, worker string) error {
	if status != StatusHealthy && status != StatusCritical {
		return fmt.Errorf("invalid check result status")
	}
	if elapsed < 0 {
		elapsed = 0
	}
	errorCategory = strings.TrimSpace(errorCategory)
	if len(errorCategory) > 50 {
		errorCategory = errorCategory[:50]
	}
	summary = strings.TrimSpace(summary)
	if summary == "" {
		summary = "check completed without a summary"
	}
	if len(summary) > 500 {
		summary = summary[:500]
	}
	worker = strings.TrimSpace(worker)
	if worker == "" {
		worker = "monitoring-worker"
	}
	if len(worker) > 100 {
		worker = worker[:100]
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin check result: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var machineID int64
	var currentStatus Status
	var failures, successes, failureThreshold, recoveryThreshold int
	if err := tx.QueryRowContext(ctx, `
		SELECT machine_id, status, consecutive_failures, consecutive_successes,
		       failure_threshold, recovery_threshold
		FROM checks WHERE id = ? AND enabled = 1
	`, checkID).Scan(
		&machineID, &currentStatus, &failures, &successes,
		&failureThreshold, &recoveryThreshold,
	); err != nil {
		return fmt.Errorf("read check state: %w", err)
	}

	nextStatus := currentStatus
	if status == StatusHealthy {
		successes++
		failures = 0
		if successes >= recoveryThreshold {
			nextStatus = StatusHealthy
		}
	} else {
		failures++
		successes = 0
		if failures >= failureThreshold {
			nextStatus = StatusCritical
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO check_results (
			check_id, status, response_time_ms, error_category, summary, worker, checked_at
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, checkID, status, elapsed.Milliseconds(), errorCategory, summary, worker, now); err != nil {
		return fmt.Errorf("record check history: %w", err)
	}
	result, err := tx.ExecContext(ctx, `
		UPDATE checks
		SET status = ?, last_checked_at = ?, response_time_ms = ?, last_error = ?,
		    consecutive_failures = ?, consecutive_successes = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND enabled = 1
	`, nextStatus, now, elapsed.Milliseconds(), nullableError(status, summary),
		failures, successes, checkID)
	if err != nil {
		return fmt.Errorf("record check result: %w", err)
	}
	if affected, _ := result.RowsAffected(); affected != 1 {
		return sql.ErrNoRows
	}
	var machineStatus Status
	if err := tx.QueryRowContext(ctx, `
		SELECT CASE
			WHEN SUM(status = 'critical') > 0 THEN 'critical'
			WHEN SUM(status = 'unknown') > 0 THEN 'unknown'
			WHEN COUNT(*) > 0 AND SUM(status = 'healthy') = COUNT(*) THEN 'healthy'
			ELSE 'unknown'
		END
		FROM checks WHERE machine_id = ? AND enabled = 1
	`, machineID).Scan(&machineStatus); err != nil {
		return fmt.Errorf("calculate machine status: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE machines SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, machineStatus, machineID); err != nil {
		return fmt.Errorf("update machine status: %w", err)
	}
	if actorUserID != nil {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO audit_events (actor_user_id, action, object_type, object_id, outcome)
			VALUES (?, 'check.executed', 'check', ?, 'success')
		`, *actorUserID, strconv.FormatInt(checkID, 10)); err != nil {
			return fmt.Errorf("record check audit event: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) ListResults(ctx context.Context, checkID int64, limit int) ([]CheckResult, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, check_id, status, response_time_ms, error_category, summary, worker, checked_at
		FROM check_results WHERE check_id = ? ORDER BY id DESC LIMIT ?
	`, checkID, limit)
	if err != nil {
		return nil, fmt.Errorf("list check results: %w", err)
	}
	defer rows.Close()

	var results []CheckResult
	for rows.Next() {
		var result CheckResult
		var checkedAt string
		if err := rows.Scan(
			&result.ID, &result.CheckID, &result.Status, &result.ResponseTimeMS,
			&result.ErrorCategory, &result.Summary, &result.Worker, &checkedAt,
		); err != nil {
			return nil, fmt.Errorf("scan check result: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, checkedAt)
		if err != nil {
			return nil, fmt.Errorf("parse check result time: %w", err)
		}
		result.CheckedAt = parsed
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate check results: %w", err)
	}
	return results, nil
}

func nullableError(status Status, summary string) any {
	if status == StatusHealthy {
		return nil
	}
	return summary
}

func validateCreateInput(input CreateInput) (CreateInput, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.Target = strings.TrimSpace(input.Target)
	input.Description = strings.TrimSpace(input.Description)
	input.Path = strings.TrimSpace(input.Path)
	if len(input.Name) == 0 || len(input.Name) > 100 || strings.ContainsFunc(input.Name, unicode.IsControl) {
		return CreateInput{}, fmt.Errorf("%w: name must be 1-100 printable characters", ErrInvalidInput)
	}
	address, err := netip.ParseAddr(input.Target)
	if err != nil {
		return CreateInput{}, fmt.Errorf("%w: target must be a literal IPv4 or IPv6 address", ErrInvalidInput)
	}
	input.Target = address.String()
	if len(input.Description) > 500 || strings.ContainsFunc(input.Description, unicode.IsControl) {
		return CreateInput{}, fmt.Errorf("%w: description must be at most 500 printable characters", ErrInvalidInput)
	}
	if input.CheckType != CheckTCP && input.CheckType != CheckHTTP && input.CheckType != CheckHTTPS {
		return CreateInput{}, fmt.Errorf("%w: unsupported check type", ErrInvalidInput)
	}
	if input.Port < 1 || input.Port > 65535 {
		return CreateInput{}, fmt.Errorf("%w: port must be between 1 and 65535", ErrInvalidInput)
	}
	if input.Path == "" {
		input.Path = "/"
	}
	if !strings.HasPrefix(input.Path, "/") || len(input.Path) > 256 || strings.ContainsAny(input.Path, "\r\n") {
		return CreateInput{}, fmt.Errorf("%w: HTTP path must begin with / and contain at most 256 characters", ErrInvalidInput)
	}
	if input.Timeout == 0 {
		input.Timeout = 5 * time.Second
	}
	if input.Timeout < 100*time.Millisecond || input.Timeout > 30*time.Second {
		return CreateInput{}, fmt.Errorf("%w: timeout must be between 100ms and 30s", ErrInvalidInput)
	}
	if input.CheckInterval == 0 {
		input.CheckInterval = time.Minute
	}
	if input.CheckInterval < 10*time.Second || input.CheckInterval > 24*time.Hour {
		return CreateInput{}, fmt.Errorf("%w: check interval must be between 10 seconds and 24 hours", ErrInvalidInput)
	}
	if input.FailureThreshold == 0 {
		input.FailureThreshold = 3
	}
	if input.FailureThreshold < 1 || input.FailureThreshold > 20 {
		return CreateInput{}, fmt.Errorf("%w: failure threshold must be between 1 and 20", ErrInvalidInput)
	}
	if input.RecoveryThreshold == 0 {
		input.RecoveryThreshold = 1
	}
	if input.RecoveryThreshold < 1 || input.RecoveryThreshold > 20 {
		return CreateInput{}, fmt.Errorf("%w: recovery threshold must be between 1 and 20", ErrInvalidInput)
	}
	return input, nil
}
