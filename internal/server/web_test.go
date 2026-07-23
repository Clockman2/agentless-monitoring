package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
	"github.com/Clockman2/agentless-monitoring/internal/discovery"
	"github.com/Clockman2/agentless-monitoring/internal/machines"
	"github.com/Clockman2/agentless-monitoring/internal/monitoring"
	"github.com/Clockman2/agentless-monitoring/internal/storage"
)

func TestAdministratorSetupAndLogoutFlow(t *testing.T) {
	app, authStore := newWebTestServer(t, true)

	response := serveRequest(app, http.MethodGet, "/", nil)
	assertRedirect(t, response, "/setup")

	response = serveRequest(app, http.MethodGet, "/setup", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("setup status = %d, want 200", response.Code)
	}
	formCookie := findCookie(t, response.Result(), app.formCSRFCookieName())
	if !formCookie.HttpOnly || !formCookie.Secure || formCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("form CSRF cookie flags = %#v", formCookie)
	}
	if !strings.HasPrefix(formCookie.Name, "__Host-") {
		t.Fatalf("secure form cookie name = %q, want __Host- prefix", formCookie.Name)
	}

	form := url.Values{
		"csrf_token":            {formCookie.Value},
		"username":              {"poc.admin"},
		"password":              {"a secure POC password"},
		"password_confirmation": {"a secure POC password"},
	}
	request := formRequest(http.MethodPost, "/setup", form)
	request.AddCookie(formCookie)
	response = serve(app, request)
	assertRedirect(t, response, "/dashboard")

	sessionCookie := findCookie(t, response.Result(), app.sessionCookieName())
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags = %#v", sessionCookie)
	}
	if !strings.HasPrefix(sessionCookie.Name, "__Host-") {
		t.Fatalf("secure session cookie name = %q, want __Host- prefix", sessionCookie.Name)
	}
	session, err := authStore.SessionByToken(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("resolve created session: %v", err)
	}

	request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusOK {
		t.Fatalf("dashboard status = %d, want 200", response.Code)
	}
	if !strings.Contains(response.Body.String(), "poc.admin") {
		t.Fatal("dashboard does not contain the authenticated username")
	}
	machineForm := url.Values{
		"csrf_token": {session.CSRFToken}, "name": {"POC Gateway"}, "target": {"127.0.0.1"},
		"check_type": {"tcp"}, "port": {"1"}, "path": {"/"},
	}
	request = formRequest(http.MethodPost, "/machines", machineForm)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	assertRedirect(t, response, "/dashboard")

	request = httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if !strings.Contains(response.Body.String(), "POC Gateway") {
		t.Fatal("dashboard does not contain the created machine")
	}
	machinesList, err := app.machineStore.List(context.Background())
	if err != nil || len(machinesList) != 1 {
		t.Fatalf("created machines = %#v, error = %v", machinesList, err)
	}
	request = formRequest(http.MethodPost, "/checks/"+strconv.FormatInt(machinesList[0].CheckID, 10)+"/run", url.Values{
		"csrf_token": {session.CSRFToken},
	})
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	assertRedirect(t, response, "/dashboard")

	request = httptest.NewRequest(http.MethodGet, "/checks/"+strconv.FormatInt(machinesList[0].CheckID, 10)+"/history", nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Recent results") || !strings.Contains(response.Body.String(), "manual") {
		t.Fatalf("check history response = %d", response.Code)
	}

	request = formRequest(http.MethodPost, "/logout", url.Values{"csrf_token": {"forged"}})
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("forged logout status = %d, want 403", response.Code)
	}
	if _, err := authStore.SessionByToken(context.Background(), sessionCookie.Value); err != nil {
		t.Fatalf("forged logout invalidated session: %v", err)
	}

	logoutForm := url.Values{"csrf_token": {session.CSRFToken}}
	request = formRequest(http.MethodPost, "/logout", logoutForm)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	assertRedirect(t, response, "/login")
	if _, err := authStore.SessionByToken(context.Background(), sessionCookie.Value); !errors.Is(err, auth.ErrInvalidSession) {
		t.Fatalf("session after logout error = %v, want ErrInvalidSession", err)
	}

	response = serveRequest(app, http.MethodGet, "/login", nil)
	loginCSRF := findCookie(t, response.Result(), app.formCSRFCookieName())
	request = formRequest(http.MethodPost, "/login", url.Values{
		"csrf_token": {loginCSRF.Value},
		"username":   {"poc.admin"},
		"password":   {"a secure POC password"},
	})
	request.AddCookie(loginCSRF)
	response = serve(app, request)
	assertRedirect(t, response, "/dashboard")
}

func TestLoginRejectsInvalidCSRF(t *testing.T) {
	app, _ := newWebTestServer(t, false)
	response := serveRequest(app, http.MethodGet, "/login", nil)
	assertRedirect(t, response, "/setup")

	request := formRequest(http.MethodPost, "/setup", url.Values{
		"csrf_token": {"forged"},
		"username":   {"poc.admin"},
		"password":   {"a secure POC password"},
	})
	response = serve(app, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("forged setup status = %d, want 403", response.Code)
	}
}

func TestWebSetupDisabledByDefault(t *testing.T) {
	app, _ := newWebTestServer(t, false)
	app.allowWebSetup = false

	response := serveRequest(app, http.MethodGet, "/setup", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("setup status = %d, want 404", response.Code)
	}
	response = serveRequest(app, http.MethodGet, "/", nil)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("root status = %d, want 503", response.Code)
	}
}

func TestClientAddressUsesOnlyTrustedForwardingChain(t *testing.T) {
	app, _ := newWebTestServer(t, false)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "127.0.0.1:4321"
	request.Header.Set("X-Forwarded-For", "198.51.100.10, 10.0.0.5")

	if got := app.clientAddress(request); got != "127.0.0.1" {
		t.Fatalf("untrusted forwarding address = %q, want peer address", got)
	}
	app.trustedProxies = []netip.Prefix{
		netip.MustParsePrefix("127.0.0.1/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
	}
	if got := app.clientAddress(request); got != "198.51.100.10" {
		t.Fatalf("trusted forwarding address = %q, want client address", got)
	}
}

func TestUnknownRouteDoesNotRotateSetupCSRF(t *testing.T) {
	app, _ := newWebTestServer(t, false)
	response := serveRequest(app, http.MethodGet, "/setup", nil)
	csrfCookie := findCookie(t, response.Result(), app.formCSRFCookieName())

	response = serveRequest(app, http.MethodGet, "/favicon.ico", nil)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unknown route status = %d, want 404", response.Code)
	}
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == app.formCSRFCookieName() {
			t.Fatal("unknown route unexpectedly rotated the setup CSRF cookie")
		}
	}
	if csrfCookie.Value == "" {
		t.Fatal("setup CSRF cookie was empty")
	}
}

func TestDiscoveryReviewAndGroupImportFlow(t *testing.T) {
	app, authStore := newWebTestServer(t, false)
	response := serveRequest(app, http.MethodGet, "/setup", nil)
	setupCSRF := findCookie(t, response.Result(), app.formCSRFCookieName())
	request := formRequest(http.MethodPost, "/setup", url.Values{
		"csrf_token":            {setupCSRF.Value},
		"username":              {"discovery.admin"},
		"password":              {"a secure discovery password"},
		"password_confirmation": {"a secure discovery password"},
	})
	request.AddCookie(setupCSRF)
	response = serve(app, request)
	sessionCookie := findCookie(t, response.Result(), app.sessionCookieName())
	session, err := authStore.SessionByToken(context.Background(), sessionCookie.Value)
	if err != nil {
		t.Fatalf("resolve session: %v", err)
	}

	request = httptest.NewRequest(http.MethodGet, "/discovery", nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), `name="authorized"`) {
		t.Fatalf("discovery form response = %d %q", response.Code, response.Body.String())
	}
	jobs, err := app.discoveryStore.ListJobs(context.Background())
	if err != nil {
		t.Fatalf("list jobs before scan: %v", err)
	}
	if len(jobs) != 0 {
		t.Fatalf("discovery page created jobs: %#v", jobs)
	}
	request = formRequest(http.MethodPost, "/discovery/scans", url.Values{
		"csrf_token": {session.CSRFToken}, "target": {"203.0.112.0/23"},
	})
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "at most 256 addresses") {
		t.Fatalf("oversized discovery response = %d %q", response.Code, response.Body.String())
	}

	job, err := app.discoveryStore.CreateJob(context.Background(), session.User.ID, "192.168.70.10/32", 1)
	if err != nil {
		t.Fatalf("create discovery job: %v", err)
	}
	if err := app.discoveryStore.MarkRunning(context.Background(), job.ID); err != nil {
		t.Fatalf("mark discovery running: %v", err)
	}
	if err := app.discoveryStore.RecordProbe(
		context.Background(),
		job.ID,
		"192.168.70.10",
		[]uint16{22, 443, 2083},
		[]discovery.Fingerprint{{Kind: "ssh-host-key", Value: "SHA256:web-test"}},
	); err != nil {
		t.Fatalf("record discovered device: %v", err)
	}
	if err := app.discoveryStore.Complete(context.Background(), job.ID); err != nil {
		t.Fatalf("complete discovery: %v", err)
	}
	devices, err := app.discoveryStore.ListDevices(context.Background(), job.ID)
	if err != nil || len(devices) != 1 {
		t.Fatalf("discovered devices = %#v, error = %v", devices, err)
	}

	request = httptest.NewRequest(http.MethodGet, "/discovery?job="+strconv.FormatInt(job.ID, 10), nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "192.168.70.10") ||
		!strings.Contains(response.Body.String(), "22, 443, 2083") ||
		!strings.Contains(response.Body.String(), "cPanel/WHM server") ||
		!strings.Contains(response.Body.String(), "Unique host fingerprint in this scan") ||
		!strings.Contains(response.Body.String(), "data-select-all-devices") {
		t.Fatalf("discovery page response = %d", response.Code)
	}

	request = formRequest(http.MethodPost, "/discovery/jobs/"+strconv.FormatInt(job.ID, 10)+"/import", url.Values{
		"csrf_token": {session.CSRFToken}, "device_id": {strconv.FormatInt(devices[0].ID, 10)}, "group_name": {"Lab servers"},
	})
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	assertRedirect(t, response, "/discovery?job="+strconv.FormatInt(job.ID, 10)+"&imported=1")

	request = httptest.NewRequest(http.MethodGet, "/discovery?job="+strconv.FormatInt(job.ID, 10), nil)
	request.AddCookie(sessionCookie)
	response = serve(app, request)
	if !strings.Contains(response.Body.String(), "Lab servers") || !strings.Contains(response.Body.String(), "imported") {
		t.Fatalf("discovery page does not show imported group/device")
	}
}

func newWebTestServer(t *testing.T, secureCookies bool) (*Server, *auth.Store) {
	t.Helper()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	authStore := auth.NewStore(db)
	machineStore := machines.NewStore(db)
	discoveryStore := discovery.NewStore(db)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	app := New(Options{
		Address:        "127.0.0.1:0",
		Version:        "test-version",
		Logger:         logger,
		AuthStore:      authStore,
		MachineStore:   machineStore,
		CheckRunner:    monitoring.NewRunner(),
		DiscoveryStore: discoveryStore,
		Discovery:      discovery.NewService(context.Background(), discoveryStore, logger),
		SecureCookies:  secureCookies,
		AllowWebSetup:  true,
	})
	return app, authStore
}

func formRequest(method, target string, values url.Values) *http.Request {
	request := httptest.NewRequest(method, target, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.RemoteAddr = "192.0.2.10:12345"
	return request
}

func serveRequest(app *Server, method, target string, body io.Reader) *httptest.ResponseRecorder {
	return serve(app, httptest.NewRequest(method, target, body))
}

func serve(app *Server, request *http.Request) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	app.httpServer.Handler.ServeHTTP(response, request)
	return response
}

func findCookie(t *testing.T, response *http.Response, name string) *http.Cookie {
	t.Helper()
	for _, cookie := range response.Cookies() {
		if cookie.Name == name && cookie.MaxAge >= 0 {
			return cookie
		}
	}
	t.Fatalf("cookie %q not found", name)
	return nil
}

func assertRedirect(t *testing.T, response *httptest.ResponseRecorder, location string) {
	t.Helper()
	if response.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", response.Code)
	}
	if got := response.Header().Get("Location"); got != location {
		t.Fatalf("Location = %q, want %q", got, location)
	}
}
