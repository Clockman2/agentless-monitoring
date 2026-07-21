package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
)

const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 15 * time.Second
	idleTimeout       = 60 * time.Second
)

// Server hosts the monitoring platform's HTTP endpoints.
type Server struct {
	httpServer    *http.Server
	authStore     *auth.Store
	secureCookies bool
	version       string
	logger        *slog.Logger
	loginLimiter  *loginLimiter
}

// Options contains the dependencies and settings required by the HTTP server.
type Options struct {
	Address       string
	Version       string
	Logger        *slog.Logger
	AuthStore     *auth.Store
	SecureCookies bool
}

// New creates a server with conservative timeouts and the application's routes.
func New(options Options) *Server {
	server := &Server{
		authStore:     options.AuthStore,
		secureCookies: options.SecureCookies,
		version:       options.Version,
		logger:        options.Logger,
		loginLimiter:  newLoginLimiter(),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthHandler(options.Version))

	server.httpServer = &http.Server{
		Addr:              options.Address,
		Handler:           requestLogger(options.Logger, securityHeaders(mux)),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
	return server
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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
