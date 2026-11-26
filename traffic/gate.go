package traffic

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/intercept"
)

// The recording proxy records what the tool clients of a session send it, but it
// dials targets itself: go-mitmproxy connects with a plain net.Dialer it does
// not expose, so a request a Bash subcommand sent through the proxy reached the
// target without the target gate ever seeing the address. WebFetch and the http
// custom tools are gated by the dialer of their own client; a curl in a shell is
// not.
//
// The gate relay closes that. It is a forward proxy on loopback that the
// recording proxy dials as its upstream instead of the target: one CONNECT per
// tunnelled upstream connection, one request per plain-HTTP upstream connection.
// The proxy URL a Bash subcommand receives carries its session token in the
// userinfo (egress.MarkProxyURLToken); the proxy copies the token onto the
// request and hands it to the relay as Proxy-Authorization. The relay resolves
// the token to the target scope of that session and dials with the platform's
// gate: the same block rules, resolution, pins and approval request WebFetch's
// dialer applies, decided on the address at connect time and connected only to
// the addresses it compared.
//
// A connection without a token (WebFetch, the http custom tools, the enrich
// probe: clients that gate themselves) is admitted under the install-wide asset
// block rules only. A token that does not resolve is refused: it names a session
// this process no longer honours.
//
// This is a gate, not a sandbox. A command that drops the marker, ignores the
// proxy, or connects straight to the target never reaches the relay; the gate
// can only decide on the connections the proxy is asked to make.

// GateConfig configures the loopback gate relay of the recording proxy.
type GateConfig struct {
	// Resolve maps a session token to the target scope of that session. ok is
	// false for a token this process does not honour: the connection is refused.
	Resolve func(token string) (intercept.TargetScope, bool)
	// Dial opens the connection after the gate decision. In the platform it is
	// intercept.DialSOCKS5, which reads the scope the relay puts on the context.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// MaxConcurrent bounds simultaneous relayed connections (default 256).
	MaxConcurrent int
	// IdleTimeout closes a relayed connection after no bytes move in either
	// direction (default 2 minutes).
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the proxy request and the gated dial together
	// (default 30 seconds).
	HandshakeTimeout time.Duration
}

func (c GateConfig) withDefaults() GateConfig {
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 256
	}
	if c.IdleTimeout <= 0 {
		c.IdleTimeout = 2 * time.Minute
	}
	if c.HandshakeTimeout <= 0 {
		c.HandshakeTimeout = 30 * time.Second
	}
	return c
}

// gateRelay is the upstream the recording proxy dials through.
type gateRelay struct {
	cfg  GateConfig
	ln   net.Listener
	sem  chan struct{}
	stop chan struct{}
	done chan struct{}
}

// startGateRelay binds the relay on loopback and serves it until close.
func startGateRelay(cfg GateConfig) (*gateRelay, error) {
	if cfg.Resolve == nil || cfg.Dial == nil {
		return nil, errors.New("gate relay: a resolver and a dialer are required")
	}
	cfg = cfg.withDefaults()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("gate relay listen: %w", err)
	}
	g := &gateRelay{cfg: cfg, ln: ln, sem: make(chan struct{}, cfg.MaxConcurrent), stop: make(chan struct{}), done: make(chan struct{})}
	go g.serve()
	return g, nil
}

func (g *gateRelay) Addr() string { return g.ln.Addr().String() }

func (g *gateRelay) Close() error {
	select {
	case <-g.stop:
		return nil
	default:
	}
	close(g.stop)
	err := g.ln.Close()
	<-g.done
	return err
}

func (g *gateRelay) serve() {
	defer close(g.done)
	for {
		c, err := g.ln.Accept()
		if err != nil {
			select {
			case <-g.stop:
			default:
				slog.Error("[traffic/gate] relay accept error", "err", err)
			}
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			g.handle(c)
		}(c)
	}
}

// handle serves one upstream connection of the recording proxy: a CONNECT tunnel
// (TLS, WebSocket) or a single plain-HTTP request.
func (g *gateRelay) handle(client net.Conn) {
	_ = client.SetDeadline(time.Now().Add(g.cfg.HandshakeTimeout))
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	// The proxy credentials name the session, and never travel further.
	token, _ := gateToken(req.Header.Get("Proxy-Authorization"))
	req.Header.Del("Proxy-Authorization")

	ctx, ok := g.decide(token)
	if !ok {
		_ = writeGateRefusal(client, http.StatusForbidden,
			"this session token is not valid: the connection was not opened")
		return
	}

	addr, err := gateTarget(req)
	if err != nil {
		_ = writeGateRefusal(client, http.StatusBadRequest, err.Error())
		return
	}
	select {
	case g.sem <- struct{}{}:
		defer func() { <-g.sem }()
	default:
		_ = writeGateRefusal(client, http.StatusServiceUnavailable, "the gate relay is at its connection limit")
		return
	}

	upstream, err := g.dial(ctx, addr)
	if err != nil {
		code, reason := http.StatusBadGateway, err.Error()
		if c, blocked := intercept.IsTargetBlocked(err); blocked {
			slog.Warn("[traffic/gate] refused a proxied connection", "target", addr, "code", c, "err", err)
			code, reason = http.StatusForbidden, err.Error()
		}
		_ = writeGateRefusal(client, code, reason)
		return
	}
	defer upstream.Close()
	_ = client.SetDeadline(time.Time{})

	if req.Method == http.MethodConnect {
		if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		// Anything the client pipelined behind the CONNECT (a TLS ClientHello,
		// usually) is already in the bufio reader.
		src := net.Conn(client)
		if br.Buffered() > 0 {
			src = &bufferedConn{Conn: client, r: br}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			pipeHalf(upstream, src, g.cfg.IdleTimeout)
			closeWrite(upstream)
		}()
		go func() {
			defer wg.Done()
			pipeHalf(client, upstream, g.cfg.IdleTimeout)
			closeWrite(client)
		}()
		wg.Wait()
		return
	}

	// A plain-HTTP request: forward it in origin form, relay one response, and
	// let the proxy open another connection for the next one.
	if req.URL == nil || req.URL.Path == "" {
		req.URL.Path = "/"
	}
	req.Close = true
	req.Header.Del("Proxy-Connection")
	if err := req.Write(upstream); err != nil {
		return
	}
	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	resp.Close = true
	resp.Header.Del("Keep-Alive")
	_ = resp.Write(client)
}

// decide resolves a session token to the gate context of the connection. ok is
// false for a token this process does not honour.
func (g *gateRelay) decide(token string) (context.Context, bool) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-g.stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	if token == "" {
		return ctx, true
	}
	scope, known := g.cfg.Resolve(token)
	if !known {
		return nil, false
	}
	return intercept.WithTargetScope(ctx, scope), true
}

func (g *gateRelay) dial(ctx context.Context, addr string) (net.Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, g.cfg.HandshakeTimeout)
	defer cancel()
	return g.cfg.Dial(dialCtx, "tcp", addr)
}

// gateToken reads the session token of a Proxy-Authorization value: the password
// of the marker user. An absent header, or credentials the proxy did not write,
// name no session.
func gateToken(proxyAuthorization string) (string, bool) {
	scheme, enc, found := strings.Cut(strings.TrimSpace(proxyAuthorization), " ")
	if !found || !strings.EqualFold(scheme, "Basic") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(enc))
	if err != nil {
		return "", false
	}
	user, pass, _ := strings.Cut(string(raw), ":")
	if user != egress.PaceUser {
		return "", false
	}
	// go-mitmproxy builds the header from the URL's userinfo, whose password is
	// percent-encoded; the tokens themselves need no escaping.
	if dec, err := url.PathUnescape(pass); err == nil {
		pass = dec
	}
	return pass, true
}

// gateTarget is the host:port a relayed request names, with the port the scheme
// implies.
func gateTarget(req *http.Request) (string, error) {
	host := req.Host
	if req.Method == http.MethodConnect {
		if req.URL != nil && req.URL.Opaque != "" {
			host = req.URL.Opaque
		}
	} else if req.URL != nil && req.URL.Host != "" {
		host = req.URL.Host
	}
	if host == "" {
		return "", errors.New("the request names no target")
	}
	if h, port, err := net.SplitHostPort(host); err == nil {
		if h == "" || port == "" {
			return "", fmt.Errorf("the request names no target: %q", host)
		}
		return host, nil
	}
	port := 80
	if req.Method == http.MethodConnect || (req.URL != nil && strings.EqualFold(req.URL.Scheme, "https")) {
		port = 443
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// writeGateRefusal answers a request the relay does not forward. It is a full
// HTTP response, which is also what a CONNECT client reports as the reason its
// tunnel did not open.
func writeGateRefusal(w io.Writer, code int, reason string) error {
	body := reason + "\n"
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(body), body)
	return err
}

// bufferedConn reads what a bufio.Reader already holds before the socket.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// pipeHalf copies src to dst until either side ends or idle passes with no bytes.
// Nothing is captured: the recording proxy records the request it relays.
func pipeHalf(dst, src net.Conn, idle time.Duration) {
	buf := make([]byte, 32*1024)
	for {
		if idle > 0 {
			_ = src.SetReadDeadline(time.Now().Add(idle))
		}
		n, rerr := src.Read(buf)
		if n > 0 {
			if idle > 0 {
				_ = dst.SetWriteDeadline(time.Now().Add(idle))
			}
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if rerr != nil {
			return
		}
	}
}
