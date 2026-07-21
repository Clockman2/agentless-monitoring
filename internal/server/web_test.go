package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
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
	formCookie := findCookie(t, response.Result(), formCSRFCookie)
	if !formCookie.HttpOnly || !formCookie.Secure || formCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("form CSRF cookie flags = %#v", formCookie)
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

	sessionCookie := findCookie(t, response.Result(), sessionCookieName)
	if !sessionCookie.HttpOnly || !sessionCookie.Secure || sessionCookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie flags = %#v", sessionCookie)
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
	loginCSRF := findCookie(t, response.Result(), formCSRFCookie)
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

func newWebTestServer(t *testing.T, secureCookies bool) (*Server, *auth.Store) {
	t.Helper()
	db, err := storage.Open(context.Background(), filepath.Join(t.TempDir(), "web.db"))
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	authStore := auth.NewStore(db)
	app := New(Options{
		Address:       "127.0.0.1:0",
		Version:       "test-version",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		AuthStore:     authStore,
		SecureCookies: secureCookies,
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
