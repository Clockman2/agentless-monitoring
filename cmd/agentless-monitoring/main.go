package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/config"
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
	flag.Parse()
	cfg.ListenAddress = *listenAddress

	if err := cfg.Validate(); err != nil {
		logger.Error("configuration is invalid", "error", err)
		os.Exit(1)
	}

	db, err := storage.Open(context.Background(), cfg.DatabasePath)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer func() {
		if err := db.Close(); err != nil {
			logger.Error("database close failed", "error", err)
		}
	}()

	app := server.New(server.Options{
		Address:       cfg.ListenAddress,
		Version:       version,
		Logger:        logger,
		AuthStore:     auth.NewStore(db),
		MachineStore:  machines.NewStore(db),
		CheckRunner:   monitoring.NewRunner(),
		SecureCookies: cfg.SecureCookies,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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
