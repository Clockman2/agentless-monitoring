package server

import (
	"errors"
	"net/http"

	"github.com/Clockman2/agentless-monitoring/internal/auth"
)

func (s *Server) registerWebRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /", s.rootHandler)
	mux.HandleFunc("GET /setup", s.setupPage)
	mux.HandleFunc("POST /setup", s.setupSubmit)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("GET /dashboard", s.dashboardPage)
	mux.HandleFunc("POST /logout", s.logoutSubmit)
	mux.HandleFunc("GET /assets/app.css", s.stylesheet)
}

func (s *Server) rootHandler(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.authStore.Initialized(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !initialized {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, _, ok := s.requestSession(r); !ok {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) setupPage(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.authStore.Initialized(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if initialized {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderAuthPage(w, r, http.StatusOK, "setup", "")
}

func (s *Server) setupSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) || !s.validateFormCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	clearCookie(w, formCSRFCookie, s.secureCookies)

	if r.FormValue("password") != r.FormValue("password_confirmation") {
		s.renderAuthPage(w, r, http.StatusBadRequest, "setup", "Passwords do not match.")
		return
	}
	user, err := s.authStore.CreateAdministrator(r.Context(), r.FormValue("username"), r.FormValue("password"))
	if errors.Is(err, auth.ErrAlreadyInitialized) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if errors.Is(err, auth.ErrInvalidUsername) || errors.Is(err, auth.ErrInvalidPassword) {
		s.renderAuthPage(w, r, http.StatusBadRequest, "setup", err.Error())
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}

	token, session, err := s.authStore.CreateSession(r.Context(), user.ID, auth.SessionDuration)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setSessionCookie(w, token, session.ExpiresAt)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.authStore.Initialized(r.Context())
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	if !initialized {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}
	if _, _, ok := s.requestSession(r); ok {
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
		return
	}
	s.renderAuthPage(w, r, http.StatusOK, "login", "")
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.parseForm(w, r) || !s.validateFormCSRF(r) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	clearCookie(w, formCSRFCookie, s.secureCookies)

	client := clientAddress(r)
	if !s.loginLimiter.allow(client) {
		s.renderAuthPage(w, r, http.StatusTooManyRequests, "login", "Too many login attempts. Try again shortly.")
		return
	}
	user, err := s.authStore.Authenticate(r.Context(), r.FormValue("username"), r.FormValue("password"))
	if errors.Is(err, auth.ErrInvalidCredentials) {
		s.renderAuthPage(w, r, http.StatusUnauthorized, "login", "Invalid username or password.")
		return
	}
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.loginLimiter.reset(client)

	token, session, err := s.authStore.CreateSession(r.Context(), user.ID, auth.SessionDuration)
	if err != nil {
		s.internalError(w, r, err)
		return
	}
	s.setSessionCookie(w, token, session.ExpiresAt)
	http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
}

func (s *Server) dashboardPage(w http.ResponseWriter, r *http.Request) {
	_, session, ok := s.requestSession(r)
	if !ok {
		clearCookie(w, sessionCookieName, s.secureCookies)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderPage(w, http.StatusOK, "dashboard", pageData{
		Title:     "Dashboard",
		Version:   s.version,
		Username:  session.User.Username,
		CSRFToken: session.CSRFToken,
	})
}

func (s *Server) logoutSubmit(w http.ResponseWriter, r *http.Request) {
	token, session, ok := s.requestSession(r)
	if !ok {
		clearCookie(w, sessionCookieName, s.secureCookies)
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !s.parseForm(w, r) || !tokensEqual(r.FormValue("csrf_token"), session.CSRFToken) {
		http.Error(w, "invalid form token", http.StatusForbidden)
		return
	}
	if err := s.authStore.DeleteSession(r.Context(), token); err != nil {
		s.internalError(w, r, err)
		return
	}
	clearCookie(w, sessionCookieName, s.secureCookies)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) requestSession(r *http.Request) (string, auth.Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", auth.Session{}, false
	}
	session, err := s.authStore.SessionByToken(r.Context(), cookie.Value)
	if err != nil {
		if !errors.Is(err, auth.ErrInvalidSession) {
			s.logger.Error("session lookup failed", "error", err)
		}
		return "", auth.Session{}, false
	}
	return cookie.Value, session, true
}
