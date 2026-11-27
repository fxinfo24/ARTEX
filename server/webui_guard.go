package server

// Authorization for the embedded console.
//
// The console ships as a Next.js static export, and a static export has no
// middleware: src/proxy.ts is dropped from the bundle, so the redirect it
// performs in `next dev` does not exist in the binary. Without a guard here the
// server hands /function/* and /system/* to any caller, and the console only
// looks protected because the client-side shell redirects after it has already
// been downloaded.
//
// The rules mirror src/proxy.ts, with the difference that the token is verified
// rather than merely present: a forged or expired cookie is not a session.

import (
	"net/http"
	"path"
	"strings"
)

// webuiAuthGuard wraps the embedded SPA handler.
func (s *Server) webuiAuthGuard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !webuiPageRequest(r) {
			next.ServeHTTP(w, r)
			return
		}
		authed := s.sessionCookieOK(r)
		switch {
		case webuiPublicPage(r.URL.Path):
			if authed {
				// Already signed in: send them to the console rather than a
				// login form they would only have to navigate away from.
				http.Redirect(w, r, "/function/tasks", http.StatusTemporaryRedirect)
				return
			}
		case !authed:
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionCookieOK reports whether the request carries a verifiable session.
func (s *Server) sessionCookieOK(r *http.Request) bool {
	c, err := r.Cookie(sessionCookie)
	if err != nil || c.Value == "" {
		return false
	}
	return s.sessionOK(c.Value)
}

// webuiPageRequest reports whether the request is for a page rather than a file
// or an API call. Assets keep their plain serving path — a redirect there would
// break the login page itself — and the API is routed on its own before this
// handler.
func webuiPageRequest(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/_next/"), strings.HasPrefix(p, "/api/"):
		return false
	case path.Ext(p) != "":
		// A file (favicon.ico, icon.png, robots.txt, a source map): exported
		// routes carry no extension.
		return false
	}
	return true
}

// webuiPublicPage reports whether a page is reachable without a session: the
// login form and first-run setup.
func webuiPublicPage(p string) bool {
	return p == "/login" || p == "/login/" || p == "/setup" || p == "/setup/"
}
