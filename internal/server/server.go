package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

// Server hosts the monitoring platform's HTTP endpoints.
type Server struct {
	httpServer *http.Server
}

// New creates a server with conservative timeouts and the application's routes.
func New(address, version string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler(version))

	return &Server{
		httpServer: &http.Server{
			Addr:              address,
			Handler:           requestLogger(logger, mux),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
		},
	}
}

// ListenAndServe starts accepting HTTP connections.
func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func healthHandler(version string) http.HandlerFunc {
	type response struct {
		Status  string `json:"status"`
		Version string `json:"version"`
	}

	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(response{Status: "ok", Version: version})
	}
}

func requestLogger(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		logger.Info("HTTP request",
			"method", r.Method,
			"path", r.URL.Path,
			"duration", time.Since(started),
		)
	})
}
