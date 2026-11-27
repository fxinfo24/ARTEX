package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// guardKey is the signing key these tests mint sessions with.
var guardKey = []byte("webui-guard-test-key")

func guardServer() *Server {
	return &Server{jwtKey: guardKey}
}

// guardHandler is the inner SPA handler: reaching it means the guard let the
// request through.
func guardHandler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("app"))
	})
}

func mintSession(t *testing.T, key []byte, version int64) string {
	t.Helper()
	tok, err := signJWTVersion(key, version)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return tok
}

func mintExpired(t *testing.T, key []byte) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, sessionClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "ARTEX",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}).SignedString(key)
	if err != nil {
		t.Fatalf("sign expired token: %v", err)
	}
	return tok
}

func TestWebuiAuthGuard(t *testing.T) {
	valid := mintSession(t, guardKey, 0)
	cases := []struct {
		name     string
		method   string
		path     string
		cookie   string
		wantCode int
		wantLoc  string
	}{
		{"console page without session", http.MethodGet, "/function/tasks", "", http.StatusTemporaryRedirect, "/login"},
		{"console page trailing slash", http.MethodGet, "/function/tasks/", "", http.StatusTemporaryRedirect, "/login"},
		{"root without session", http.MethodGet, "/", "", http.StatusTemporaryRedirect, "/login"},
		{"system page without session", http.MethodGet, "/system/settings", "", http.StatusTemporaryRedirect, "/login"},
		{"console page with session", http.MethodGet, "/function/tasks", valid, http.StatusOK, ""},
		{"system page with session", http.MethodGet, "/system/settings", valid, http.StatusOK, ""},
		{"login is public", http.MethodGet, "/login", "", http.StatusOK, ""},
		{"setup is public", http.MethodGet, "/setup", "", http.StatusOK, ""},
		{"login with session moves on", http.MethodGet, "/login", valid, http.StatusTemporaryRedirect, "/function/tasks"},
		{"setup with session moves on", http.MethodGet, "/setup/", valid, http.StatusTemporaryRedirect, "/function/tasks"},
		{"asset is not a page", http.MethodGet, "/_next/static/chunks/a.js", "", http.StatusOK, ""},
		{"favicon is not a page", http.MethodGet, "/favicon.ico", "", http.StatusOK, ""},
		{"expired session", http.MethodGet, "/function/tasks", mintExpired(t, guardKey), http.StatusTemporaryRedirect, "/login"},
		{"foreign signature", http.MethodGet, "/function/tasks", mintSession(t, []byte("other-key"), 0), http.StatusTemporaryRedirect, "/login"},
		{"not a page request", http.MethodPost, "/function/tasks", "", http.StatusOK, ""},
	}

	h := guardServer().webuiAuthGuard(guardHandler(t))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: sessionCookie, Value: tc.cookie})
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantCode {
				t.Fatalf("%s %s: status = %d, want %d", tc.method, tc.path, rec.Code, tc.wantCode)
			}
			if tc.wantLoc != "" {
				if got := rec.Header().Get("Location"); got != tc.wantLoc {
					t.Fatalf("%s %s: Location = %q, want %q", tc.method, tc.path, got, tc.wantLoc)
				}
			}
		})
	}
}

// A session token in the query string must not open a page: that form belongs to
// the API (SSE), and a URL-borne token leaks into logs, history and referrers.
func TestWebuiAuthGuardIgnoresQueryToken(t *testing.T) {
	valid := mintSession(t, guardKey, 0)
	req := httptest.NewRequest(http.MethodGet, "/function/tasks?token="+valid, nil)
	rec := httptest.NewRecorder()
	guardServer().webuiAuthGuard(guardHandler(t)).ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "/login" {
		t.Fatalf("query token opened the page: status=%d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

// A password change bumps the stored version; tokens minted under the old one
// are no longer sessions, so the page must not be served.
func TestWebuiAuthGuardRejectsStalePasswordVersion(t *testing.T) {
	s := guardServer()
	s.pwdVersion.Store(2)
	req := httptest.NewRequest(http.MethodGet, "/function/tasks", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: mintSession(t, guardKey, 1)})
	rec := httptest.NewRecorder()
	s.webuiAuthGuard(guardHandler(t)).ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("stale password version served a page: status=%d", rec.Code)
	}
}

// When the password counter could not be read the process cannot tell a live
// session from a revoked one, so nothing is served until login reads it again.
func TestWebuiAuthGuardRejectsWhenPasswordStateUnreadable(t *testing.T) {
	s := guardServer()
	s.pwdState.Store(pwdUnreadable)
	req := httptest.NewRequest(http.MethodGet, "/function/tasks", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: mintSession(t, guardKey, 0)})
	rec := httptest.NewRecorder()
	s.webuiAuthGuard(guardHandler(t)).ServeHTTP(rec, req)
	if rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("unreadable password state served a page: status=%d", rec.Code)
	}
}
