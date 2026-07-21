package server

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"html/template"
	"net"
	"net/http"
	"time"

	"github.com/Clockman2/agentless-monitoring/internal/discovery"
	"github.com/Clockman2/agentless-monitoring/internal/machines"
)

const (
	sessionCookieName = "agentless_monitoring_session"
	formCSRFCookie    = "agentless_monitoring_form_csrf"
	maximumFormBytes  = 32 * 1024
	formCSRFDuration  = 10 * time.Minute
)

//go:embed templates/*.html assets/*.css
var webFiles embed.FS

var pageTemplates = map[string]*template.Template{
	"setup":       template.Must(template.ParseFS(webFiles, "templates/setup.html")),
	"login":       template.Must(template.ParseFS(webFiles, "templates/login.html")),
	"dashboard":   template.Must(template.ParseFS(webFiles, "templates/dashboard.html")),
	"machine_new": template.Must(template.ParseFS(webFiles, "templates/machine_new.html")),
	"discovery":   template.Must(template.ParseFS(webFiles, "templates/discovery.html")),
}

type pageData struct {
	Title             string
	Version           string
	Username          string
	CSRFToken         string
	Error             string
	Summary           machines.Summary
	Machines          []machines.Machine
	Message           string
	DiscoveryJobs     []discovery.Job
	DiscoveryJob      *discovery.Job
	DiscoveredDevices []discovery.Device
	DiscoveryRunning  bool
	Groups            []discovery.Group
	SuggestedCIDRs    []string
}

func (s *Server) renderAuthPage(w http.ResponseWriter, r *http.Request, status int, name, message string) {
	csrfToken, err := randomWebToken()
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     formCSRFCookie,
		Value:    csrfToken,
		Path:     "/",
		MaxAge:   int(formCSRFDuration.Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
	title := "Sign in"
	if name == "setup" {
		title = "Initial setup"
	}
	s.renderPage(w, status, name, pageData{Title: title, Version: s.version, CSRFToken: csrfToken, Error: message})
}

func (s *Server) renderPage(w http.ResponseWriter, status int, name string, data pageData) {
	tmpl, ok := pageTemplates[name]
	if !ok {
		http.Error(w, "template unavailable", http.StatusInternalServerError)
		return
	}
	var output bytes.Buffer
	if err := tmpl.Execute(&output, data); err != nil {
		s.logger.Error("template rendering failed", "template", name, "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = output.WriteTo(w)
}

func (s *Server) stylesheet(w http.ResponseWriter, _ *http.Request) {
	contents, err := webFiles.ReadFile("assets/app.css")
	if err != nil {
		http.Error(w, "asset unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(contents)
}

func (s *Server) parseForm(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maximumFormBytes)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form submission", http.StatusBadRequest)
		return false
	}
	return true
}

func (s *Server) validateFormCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(formCSRFCookie)
	if err != nil {
		return false
	}
	return tokensEqual(cookie.Value, r.FormValue("csrf_token"))
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		MaxAge:   int(time.Until(expiresAt).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies,
		SameSite: http.SameSiteStrictMode,
	})
}

func clearCookie(w http.ResponseWriter, name string, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	})
}

func randomWebToken() (string, error) {
	buffer := make([]byte, 32)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func tokensEqual(first, second string) bool {
	if len(first) != len(second) || len(first) == 0 {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(first), []byte(second)) == 1
}

func clientAddress(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, err error) {
	s.logger.Error("HTTP request failed", "method", r.Method, "path", r.URL.Path, "error", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}
