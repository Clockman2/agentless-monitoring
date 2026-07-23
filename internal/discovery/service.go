package discovery

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync/atomic"
	"time"
)

var ErrScanInProgress = errors.New("a discovery scan is already running")

type Service struct {
	ctx     context.Context
	store   *Store
	scanner *Scanner
	logger  *slog.Logger
	running atomic.Bool
}

func NewService(ctx context.Context, store *Store, logger *slog.Logger) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{ctx: ctx, store: store, scanner: NewScanner(), logger: logger}
}

func (s *Service) Start(ctx context.Context, actorUserID int64, targetText string) (Job, error) {
	target, err := ParseTarget(targetText)
	if err != nil {
		return Job{}, err
	}
	if !s.running.CompareAndSwap(false, true) {
		return Job{}, ErrScanInProgress
	}
	job, err := s.store.CreateJob(ctx, actorUserID, target.Canonical, len(target.Addresses))
	if err != nil {
		s.running.Store(false)
		return Job{}, err
	}
	go s.run(job.ID, target.Addresses)
	return job, nil
}

func (s *Service) run(jobID int64, addresses []netip.Addr) {
	defer s.running.Store(false)
	if err := s.store.MarkRunning(s.ctx, jobID); err != nil {
		s.recordFailure(jobID, err)
		return
	}
	err := s.scanner.Scan(s.ctx, addresses, func(result Result) error {
		if result.Responsive {
			return s.store.RecordProbe(s.ctx, jobID, result.Address.String(), result.DetectedPort)
		}
		return s.store.RecordProbe(s.ctx, jobID, "", nil)
	})
	if err != nil {
		s.recordFailure(jobID, err)
		return
	}
	if err := s.store.Complete(s.ctx, jobID); err != nil {
		s.logger.Error("discovery completion failed", "job_id", jobID, "error", err)
	}
}

func (s *Service) recordFailure(jobID int64, cause error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.store.Fail(ctx, jobID, cause); err != nil {
		s.logger.Error("discovery failure could not be recorded", "job_id", jobID, "error", err)
	}
}
