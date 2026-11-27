package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

func TestPasswordVersionClaim(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	legacy, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := signJWTVersion(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	current, err := signJWTVersion(key, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyJWT(legacy, key, 0) {
		t.Fatal("before any password change a token must be accepted")
	}
	if verifyJWT(legacy, key, 2) || verifyJWT(previous, key, 2) {
		t.Fatal("a token from an older password version must be rejected")
	}
	if !verifyJWT(current, key, 2) {
		t.Fatal("a token carrying the current version must be accepted")
	}
	// Two signatures in the same second still differ by version.
	newest, err := signJWTVersion(key, 3)
	if err != nil {
		t.Fatal(err)
	}
	if verifyJWT(current, key, 3) {
		t.Fatal("two changes in the same second must not leave the older token valid")
	}
	if !verifyJWT(newest, key, 3) {
		t.Fatal("the newest version must be accepted")
	}
}

// authTestServer builds a Server whose password keys are unique to one test, with
// fresh login and password-change limiters, so tests never share stored state.
func authTestServer(t *testing.T) *Server {
	t.Helper()
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	// Registered first so it runs last: the settings cleanup below needs the pool.
	t.Cleanup(func() { m.Close() })
	stamp := time.Now().UnixNano()
	s := &Server{
		m:              m,
		jwtKey:         []byte("0123456789abcdef0123456789abcdef"),
		loginLimit:     newLoginLimiter(time.Now),
		pwdLimit:       newLoginLimiter(time.Now),
		authHashKey:    fmt.Sprintf("test.password_hash.%d", stamp),
		authVersionKey: fmt.Sprintf("test.password_version.%d", stamp),
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1 OR key=$2`, s.authHashKey, s.authVersionKey)
	})
	return s
}

// initPassword sets the first password through the setup path and returns the
// session token it issues.
func initPassword(t *testing.T, s *Server, password string) string {
	t.Helper()
	s.setupToken = "setup-ok"
	w := httptest.NewRecorder()
	body := fmt.Sprintf(`{"password":%q,"setup_token":"setup-ok"}`, password)
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(body)))
	if w.Code != 200 {
		t.Fatalf("init status=%d body=%s", w.Code, w.Body.String())
	}
	var issued struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &issued); err != nil || issued.Token == "" {
		t.Fatalf("init token: %v body=%s", err, w.Body.String())
	}
	if !s.sessionOK(issued.Token) {
		t.Fatal("token from init was rejected")
	}
	return issued.Token
}

// changePassword posts a change as the caller holding token.
func changePassword(s *Server, token, oldPW, newPW string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"old_password":%q,"new_password":%q}`, oldPW, newPW)
	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.authChangePassword(w, req)
	return w
}

// login posts a login attempt and returns the recorder.
func login(s *Server, username, password string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"username":%q,"password":%q}`, username, password)
	w := httptest.NewRecorder()
	s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(body)))
	return w
}

// TestChangePasswordRevokesOldToken: a successful change ends the session that
// asked for it and hands back one for the new version, and only the new password
// logs in afterwards.
func TestChangePasswordRevokesOldToken(t *testing.T) {
	s := authTestServer(t)
	issued := initPassword(t, s, "correct-horse-1")

	w := changePassword(s, issued, "correct-horse-1", "correct-horse-2")
	if w.Code != 200 {
		t.Fatalf("change status=%d body=%s", w.Code, w.Body.String())
	}
	if s.sessionOK(issued) {
		t.Fatal("token from before the password change is still accepted")
	}
	var replaced struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &replaced); err != nil || replaced.Token == "" {
		t.Fatalf("change-password returned no replacement token: %v body=%s", err, w.Body.String())
	}
	if replaced.Token == issued {
		t.Fatal("replacement token is the revoked one")
	}
	if !s.sessionOK(replaced.Token) {
		t.Fatal("replacement token from change-password was rejected")
	}

	reached := false
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	})).ServeHTTP(httptest.NewRecorder(), requestWithToken("GET", "/api/tasks", issued))
	if reached {
		t.Fatal("revoked token reached a protected handler")
	}

	if w := login(s, "ARTEX", "correct-horse-2"); w.Code != 200 {
		t.Fatalf("login with the new password: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := login(s, "ARTEX", "correct-horse-1"); w.Code == 200 {
		t.Fatal("the old password still logs in after a successful change")
	}
}

// TestChangePasswordKeepsSessionWhenSaveFails covers what a client sees when the
// rotation cannot be stored: the request fails, and nothing about the session may
// move. The 500 must not carry a replacement token — a console that stored one
// would throw away a working session — and the same token must still authorize
// both a protected route and a console page.
func TestChangePasswordKeepsSessionWhenSaveFails(t *testing.T) {
	s := authTestServer(t)
	issued := initPassword(t, s, "correct-horse-1")

	// RotatePassword commits the hash and the counter together, so a non-numeric
	// counter aborts the whole rotation.
	if _, err := s.m.pg.Exec(`UPDATE settings SET value='not-a-number' WHERE key=$1`, s.authVersionKey); err != nil {
		t.Fatal(err)
	}
	before := s.pwdVersion.Load()

	w := changePassword(s, issued, "correct-horse-1", "correct-horse-2")
	if w.Code != 500 {
		t.Fatalf("failed save status=%d want 500 body=%s", w.Code, w.Body.String())
	}
	var failed struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &failed); err != nil {
		t.Fatalf("failure body is not JSON: %v %s", err, w.Body.String())
	}
	if failed.Token != "" {
		t.Fatalf("a failed save returned a replacement token %q; a client would overwrite its working session with it", failed.Token)
	}
	if s.pwdVersion.Load() != before {
		t.Fatalf("version moved from %d to %d after a failed save", before, s.pwdVersion.Load())
	}
	if !s.sessionOK(issued) {
		t.Fatal("a failed save revoked the current token")
	}

	reached := false
	s.requireAuth(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached = true
	})).ServeHTTP(httptest.NewRecorder(), requestWithToken("GET", "/api/tasks", issued))
	if !reached {
		t.Fatal("the session no longer reaches a protected route after a failed save")
	}

	pageReached := false
	guard := s.webuiAuthGuard(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		pageReached = true
		rw.WriteHeader(http.StatusOK)
	}))
	pageReq := httptest.NewRequest("GET", "/function/tasks", nil)
	pageReq.AddCookie(&http.Cookie{Name: sessionCookie, Value: issued})
	pageRec := httptest.NewRecorder()
	guard.ServeHTTP(pageRec, pageReq)
	if !pageReached || pageRec.Code != http.StatusOK {
		t.Fatalf("console page after a failed save: reached=%v status=%d location=%q",
			pageReached, pageRec.Code, pageRec.Header().Get("Location"))
	}

	if w := login(s, "ARTEX", "correct-horse-1"); w.Code != 200 {
		t.Fatalf("old password rejected after a failed save: status=%d body=%s", w.Code, w.Body.String())
	}
	if w := login(s, "ARTEX", "correct-horse-2"); w.Code == 200 {
		t.Fatal("the new password was stored even though the rotation failed")
	}
}

// TestLoginFailureReturns401WithMessage pins the contract the console depends on:
// a rejected login answers 401 with the generic message (neither the username nor
// the password is named, so the reply cannot be used to enumerate accounts), it
// carries no token, and it leaves an unrelated session alone.
func TestLoginFailureReturns401WithMessage(t *testing.T) {
	s := authTestServer(t)
	issued := initPassword(t, s, "correct-horse-1")

	const wantMessage = "Incorrect username or password"
	for _, tc := range []struct{ name, username, password string }{
		{"wrong password", "ARTEX", "not-the-password"},
		{"wrong username", "somebody", "correct-horse-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := login(s, tc.username, tc.password)
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d want 401 body=%s", w.Code, w.Body.String())
			}
			var body struct {
				Error string `json:"error"`
				Token string `json:"token"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not JSON: %v %s", err, w.Body.String())
			}
			if body.Error != wantMessage {
				t.Fatalf("error=%q want %q", body.Error, wantMessage)
			}
			if body.Token != "" {
				t.Fatalf("a rejected login returned a token %q", body.Token)
			}
			if !s.sessionOK(issued) {
				t.Fatal("a rejected login disturbed an unrelated session")
			}
		})
	}
}

func TestUnreadablePasswordVersionRejectsSessions(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{m: m, jwtKey: key, loginLimit: newLoginLimiter(time.Now), pwdLimit: newLoginLimiter(time.Now)}
	s.authVersionKey = fmt.Sprintf("test.password_version.%d", time.Now().UnixNano())
	tok, err := signJWTVersion(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.applyPasswordVersion(1)
	if !s.sessionOK(tok) {
		t.Fatal("token was rejected before the read failed")
	}
	if err := m.pg.Close(); err != nil {
		t.Fatal(err)
	}
	s.loadPasswordVersion()
	if s.pwdState.Load() != pwdUnreadable {
		t.Fatalf("state=%d want unreadable", s.pwdState.Load())
	}
	if s.sessionOK(tok) {
		t.Fatal("accepted a token while the password version was unreadable")
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/change-password", strings.NewReader(`{"old_password":"correct-horse-1","new_password":"correct-horse-2"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	s.authChangePassword(w, req)
	if w.Code != 401 {
		t.Fatalf("change while unreadable: status=%d want 401 body=%s", w.Code, w.Body.String())
	}
}

func TestLoginRereadsPasswordVersionWhenUnreadable(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()

	stamp := time.Now().UnixNano()
	s := &Server{
		m:              m,
		jwtKey:         []byte("0123456789abcdef0123456789abcdef"),
		loginLimit:     newLoginLimiter(time.Now),
		pwdLimit:       newLoginLimiter(time.Now),
		authHashKey:    fmt.Sprintf("test.password_hash.%d", stamp),
		authVersionKey: fmt.Sprintf("test.password_version.%d", stamp),
	}
	t.Cleanup(func() {
		_, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1 OR key=$2`, s.authHashKey, s.authVersionKey)
	})
	s.setupToken = "setup-ok"
	w := httptest.NewRecorder()
	s.authInit(w, httptest.NewRequest("POST", "/api/auth/init", strings.NewReader(`{"password":"correct-horse-1","setup_token":"setup-ok"}`)))
	if w.Code != 200 {
		t.Fatalf("init status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := m.pg.Exec(`UPDATE settings SET value='not-a-number' WHERE key=$1`, s.authVersionKey); err != nil {
		t.Fatal(err)
	}
	s.pwdVersion.Store(99)
	s.loadPasswordVersion()
	if s.pwdState.Load() != pwdUnreadable {
		t.Fatalf("state=%d want unreadable", s.pwdState.Load())
	}
	w = httptest.NewRecorder()
	s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"correct-horse-1"}`)))
	if w.Code != 503 {
		t.Fatalf("login while unreadable: status=%d want 503 body=%s", w.Code, w.Body.String())
	}
	if s.pwdState.Load() != pwdUnreadable {
		t.Fatal("a failed reread opened sessions")
	}

	if _, err := m.pg.Exec(`UPDATE settings SET value='1' WHERE key=$1`, s.authVersionKey); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	s.authLogin(w, httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"ARTEX","password":"correct-horse-1"}`)))
	if w.Code != 200 {
		t.Fatalf("login after the version can be read: status=%d body=%s", w.Code, w.Body.String())
	}
	if s.pwdState.Load() != pwdReady || s.pwdVersion.Load() != 1 {
		t.Fatalf("state=%d version=%d, want ready at 1", s.pwdState.Load(), s.pwdVersion.Load())
	}
	var logged struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &logged); err != nil || logged.Token == "" {
		t.Fatalf("login token: %v body=%s", err, w.Body.String())
	}
	if !s.sessionOK(logged.Token) {
		t.Fatal("token from the healed login was rejected")
	}
}

func TestAbsentPasswordVersionKeepsSessions(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	defer m.Close()
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{
		m:              m,
		jwtKey:         key,
		authVersionKey: fmt.Sprintf("test.missing.version.%d", time.Now().UnixNano()),
	}
	s.loadPasswordVersion()
	if s.pwdState.Load() != pwdReady || s.pwdVersion.Load() != 0 {
		t.Fatalf("state=%d version=%d, want ready at 0", s.pwdState.Load(), s.pwdVersion.Load())
	}
	tok, err := signJWT(key)
	if err != nil {
		t.Fatal(err)
	}
	if !s.sessionOK(tok) {
		t.Fatal("a token was rejected when no password version is stored")
	}
}

func TestStreamLogsStopsWhenPasswordVersionChanges(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	s := &Server{jwtKey: key}
	s.applyPasswordVersion(1)
	tok, err := signJWTVersion(key, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, cursor := logSink.recent(0, 1)
	ready := make(chan struct{})
	var once sync.Once
	w := &flushNotify{ResponseWriter: httptest.NewRecorder(), notify: func() {
		once.Do(func() { close(ready) })
	}}
	req := requestWithToken("GET", fmt.Sprintf("/api/logs/stream?since=%d", cursor), tok)
	done := make(chan struct{})
	go func() {
		s.streamLogs(w, req)
		close(done)
	}()
	select {
	case <-ready:
	case <-time.After(2 * time.Second):
		t.Fatal("log stream did not start")
	}
	s.applyPasswordVersion(2)
	logSink.add(LogLine{Text: "after password change"})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("log stream stayed open after the password version changed")
	}
}

func requestWithToken(method, target, token string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

type flushNotify struct {
	http.ResponseWriter
	notify func()
}

func (f *flushNotify) Flush() {
	f.notify()
	if fl, ok := f.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}
