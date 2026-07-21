package monitoring

import (
	"context"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/machines"
)

type SchedulerOptions struct {
	Workers      int
	PollInterval time.Duration
	Logger       *slog.Logger
}

type SchedulerStats struct {
	Running         bool
	WorkerCount     int
	QueueDepth      int
	InFlight        int
	LastCompletedAt *time.Time
	LastError       string
}

type checkRunner interface {
	Run(context.Context, machines.Machine) Result
}

type Scheduler struct {
	store        *machines.Store
	runner       checkRunner
	workers      int
	pollInterval time.Duration
	logger       *slog.Logger
	jobs         chan machines.Machine
	running      atomic.Bool
	mutex        sync.RWMutex
	inFlight     map[int64]struct{}
	lastComplete *time.Time
	lastError    string
}

func NewScheduler(store *machines.Store, runner checkRunner, options SchedulerOptions) *Scheduler {
	if options.Workers < 1 {
		options.Workers = 4
	}
	if options.PollInterval <= 0 {
		options.PollInterval = 2 * time.Second
	}
	if options.Logger == nil {
		options.Logger = slog.Default()
	}
	return &Scheduler{
		store: store, runner: runner, workers: options.Workers,
		pollInterval: options.PollInterval, logger: options.Logger,
		jobs:     make(chan machines.Machine, options.Workers*2),
		inFlight: make(map[int64]struct{}),
	}
}

func (s *Scheduler) Run(ctx context.Context) {
	if !s.running.CompareAndSwap(false, true) {
		return
	}
	defer s.running.Store(false)

	var workers sync.WaitGroup
	workers.Add(s.workers)
	for workerNumber := 1; workerNumber <= s.workers; workerNumber++ {
		workerName := "check-worker-" + formatWorkerNumber(workerNumber)
		go func() {
			defer workers.Done()
			s.runWorker(ctx, workerName)
		}()
	}

	s.dispatch(ctx)
	ticker := time.NewTicker(s.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			close(s.jobs)
			workers.Wait()
			return
		case <-ticker.C:
			s.dispatch(ctx)
		}
	}
}

func (s *Scheduler) dispatch(ctx context.Context) {
	due, err := s.store.ListDue(ctx, time.Now().UTC(), s.workers*4)
	if err != nil {
		s.recordError("load due checks", err)
		return
	}
	for _, machine := range due {
		if !s.acquire(machine.CheckID) {
			continue
		}
		select {
		case s.jobs <- machine:
		case <-ctx.Done():
			s.release(machine.CheckID)
			return
		}
	}
}

func (s *Scheduler) runWorker(ctx context.Context, workerName string) {
	for machine := range s.jobs {
		result := s.runner.Run(ctx, machine)
		if ctx.Err() == nil {
			err := s.store.RecordScheduledResult(
				ctx, machine.CheckID, result.Status, result.ResponseTime,
				result.ErrorCategory, result.Summary, workerName,
			)
			if err != nil {
				s.recordError("persist scheduled check", err)
			} else {
				s.recordCompletion()
			}
		}
		s.release(machine.CheckID)
	}
}

func (s *Scheduler) acquire(checkID int64) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if _, exists := s.inFlight[checkID]; exists {
		return false
	}
	s.inFlight[checkID] = struct{}{}
	return true
}

func (s *Scheduler) release(checkID int64) {
	s.mutex.Lock()
	delete(s.inFlight, checkID)
	s.mutex.Unlock()
}

func (s *Scheduler) recordCompletion() {
	now := time.Now().UTC()
	s.mutex.Lock()
	s.lastComplete = &now
	s.lastError = ""
	s.mutex.Unlock()
}

func (s *Scheduler) recordError(operation string, err error) {
	s.logger.Error("monitoring scheduler failed", "operation", operation, "error", err)
	s.mutex.Lock()
	s.lastError = operation + ": " + err.Error()
	s.mutex.Unlock()
}

func (s *Scheduler) Stats() SchedulerStats {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	stats := SchedulerStats{
		Running: s.running.Load(), WorkerCount: s.workers, QueueDepth: len(s.jobs),
		InFlight: len(s.inFlight), LastError: s.lastError,
	}
	if s.lastComplete != nil {
		value := *s.lastComplete
		stats.LastCompletedAt = &value
	}
	return stats
}

func formatWorkerNumber(value int) string {
	if value < 10 {
		return "0" + strconv.Itoa(value)
	}
	return strconv.Itoa(value)
}
