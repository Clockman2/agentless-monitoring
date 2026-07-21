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

	"github.com/Clockman2/agentless-monitoring/internal/config"
	"github.com/Clockman2/agentless-monitoring/internal/server"
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

	app := server.New(cfg.ListenAddress, version, logger)

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
