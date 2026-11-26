package egress

import (
	"context"
	"encoding/base64"
	"net/url"
	"strings"
)

// The proxy URL a Bash subcommand is given carries a per-session token in its
// userinfo (MarkProxyURLToken). The recording proxy hands that token on to the
// gate relay it dials through, which is how a connection the proxy does not
// itself run — a curl in a Bash subcommand — is bound to the session whose
// target scope governs it. The token is a hint the command can drop: the gate
// relay then admits the connection under the install-wide rules only. It is
// never a credential the target sees (the proxy removes Proxy-Authorization).

// HasProxyToken reports whether raw is a proxy URL that already carries
// userinfo.
func HasProxyToken(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User != nil
}

// MarkProxyURLToken returns raw with the marker userinfo whose password is
// token. With an empty token it returns MarkProxyURL(raw): a marked connection
// that names no session. raw is returned unchanged when it does not parse or
// already carries a userinfo (a configured proxy's own credentials win).
func MarkProxyURLToken(raw, token string) string {
	if token == "" {
		return MarkProxyURL(raw)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return raw
	}
	u.User = url.UserPassword(PaceUser, token)
	return u.String()
}

// MarkerToken reads the session token of a Proxy-Authorization value. ok is
// true for the marker userinfo (token may be empty: a marked connection that
// names no session); false for any other credentials, which the recording
// proxy drops without using.
func MarkerToken(proxyAuthorization string) (token string, ok bool) {
	scheme, enc, found := strings.Cut(strings.TrimSpace(proxyAuthorization), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	dec, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", false
	}
	user, pass, _ := strings.Cut(string(dec), ":")
	if user != PaceUser {
		return "", false
	}
	return pass, true
}

// proxyTokenKey carries the session token from the request headers, where the
// recording proxy reads it, to its upstream selection, where the proxy URL of
// the gate relay is built.
type proxyTokenKey struct{}

// WithProxyToken returns ctx carrying the session token of the connection.
func WithProxyToken(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, proxyTokenKey{}, token)
}

// ProxyToken returns the session token carried by ctx ("" when none).
func ProxyToken(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	t, _ := ctx.Value(proxyTokenKey{}).(string)
	return t
}
