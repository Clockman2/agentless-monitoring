package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/term"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/config"
	"github.com/Clockman2/agentless-monitoring/internal/discovery"
	"github.com/Clockman2/agentless-monitoring/internal/machines"
	"github.com/Clockman2/agentless-monitoring/internal/monitoring"
	"github.com/Clockman2/agentless-monitoring/internal/server"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("configuration is invalid", "error", err)
		os.Exit(1)
	}

	listenAddress := flag.String("listen", cfg.ListenAddress, "HTTP listen address")
	databasePath := flag.String("database", cfg.DatabasePath, "SQLite database path")
	createAdmin := flag.Bool("create-admin", false, "create the initial administrator and exit")
	adminUsername := flag.String("username", "", "administrator username for -create-admin")
	flag.Parse()
	cfg.ListenAddress = *listenAddress
	cfg.DatabasePath = *databasePath

	if err := cfg.Validate(); err != nil {
		logger.Error("configuration is invalid", "error", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := storage.Open(ctx, cfg.DatabasePath)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("database close failed", "error", err)
		}
	}()

	authStore := auth.NewStore(db)
	if *createAdmin {
		if err := createInitialAdministrator(ctx, authStore, *adminUsername, os.Stdin, os.Stdout); err != nil {
			logger.Error("administrator bootstrap failed", "error", err)
			os.Exit(1)
		}
		logger.Info("initial administrator created")
		return
	}

	discoveryStore := discovery.NewStore(db)
	machineStore := machines.NewStore(db)
	checkRunner := monitoring.NewRunner()
	scheduler := monitoring.NewScheduler(machineStore, checkRunner, monitoring.SchedulerOptions{
		Workers: cfg.MonitoringWorkers, PollInterval: cfg.SchedulerPollInterval, Logger: logger,
	})
	app := server.New(server.Options{
		Address:        cfg.ListenAddress,
		Version:        version,
		Logger:         logger,
		AuthStore:      authStore,
		MachineStore:   machineStore,
		CheckRunner:    checkRunner,
		DiscoveryStore: discoveryStore,
		Discovery:      discovery.NewService(ctx, discoveryStore, logger),
		Scheduler:      scheduler,
		SecureCookies:  cfg.SecureCookies,
		AllowWebSetup:  cfg.AllowWebSetup,
	})
	go scheduler.Run(ctx)

	errCh := make(chan error, 1)
	go func() {
		logger.Info("HTTP server starting", "address", cfg.ListenAddress, "version", version)
		errCh <- app.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("HTTP server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := app.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}

	logger.Info("shutdown complete")
}

type passwordInput struct {
	input  io.Reader
	output io.Writer
	reader *bufio.Reader
}

func createInitialAdministrator(ctx context.Context, store *auth.Store, username string, input io.Reader, output io.Writer) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("-username is required with -create-admin")
	}
	passwords := passwordInput{input: input, output: output, reader: bufio.NewReader(input)}
	password, err := passwords.read("Password: ")
	if err != nil {
		return err
	}
	confirmation, err := passwords.read("Confirm password: ")
	if err != nil {
		return err
	}
	if password != confirmation {
		return fmt.Errorf("passwords do not match")
	}
	_, err = store.CreateAdministrator(ctx, username, password)
	return err
}

func (p *passwordInput) read(prompt string) (string, error) {
	if _, err := fmt.Fprint(p.output, prompt); err != nil {
		return "", fmt.Errorf("write password prompt: %w", err)
	}
	if file, ok := p.input.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		_, _ = fmt.Fprintln(p.output)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(value), nil
	}
	value, err := p.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(value, "\r\n"), nil
}
