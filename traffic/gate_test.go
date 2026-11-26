package traffic

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/egress"
	"github.com/Autumn-27/artex/intercept"
)

// gateCall is one connection the gate was asked to admit.
type gateCall struct {
	taskID string // scope the relay resolved for the connection ("" = none)
	addr   string
}

// gateFixture is a gate relay with a recording dialer: it decides like
// intercept.DialSOCKS5 (allow, or refuse the targets in refuse) and remembers
// what it was asked.
type gateFixture struct {
	mu    sync.Mutex
	calls []gateCall
}

func (g *gateFixture) seen() []gateCall {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]gateCall(nil), g.calls...)
}

// config wires the relay to this fixture. tokens resolves like the platform's
// per-session tokens; refuse is the set of "host:port" addresses the gate does
// not admit.
func (g *gateFixture) config(tokens map[string]string, refuse map[string]bool) GateConfig {
	return GateConfig{
		Resolve: func(token string) (intercept.TargetScope, bool) {
			taskID, ok := tokens[token]
			if !ok {
				return intercept.TargetScope{}, false
			}
			return intercept.TargetScope{TaskID: taskID, Enabled: func() bool { return true }, Interceptor: intercept.New(nil)}, true
		},
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			taskID := ""
			if scope, ok := intercept.TargetScopeFromContext(ctx); ok {
				taskID = scope.TaskID
			}
			g.mu.Lock()
			g.calls = append(g.calls, gateCall{taskID: taskID, addr: addr})
			g.mu.Unlock()
			if refuse[addr] {
				return nil, intercept.BlockedError(intercept.TargetApprovalPending, addr,
					"the target is not approved for this task")
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, addr)
		},
	}
}

// startGatedProxy runs a real recording proxy on a loopback port with the gate
// relay installed before it starts, as NewManager does: build receives the
// traffic store so a config can dial through it.
func startGatedProxy(t *testing.T, build func(*Traffic) GateConfig) (*Traffic, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	tr, err := Open(t.TempDir(), addr)
	if err != nil {
		t.Fatal(err)
	}
	if err := tr.SetEgressGate(build(tr)); err != nil {
		t.Fatal(err)
	}
	go func() { _ = tr.Start() }()
	t.Cleanup(func() {
		_ = tr.proxy.Close()
		_ = tr.Close()
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.Dial("tcp", addr)
		if err == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("proxy did not listen on %s: %v", addr, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	return tr, "http://" + addr
}

// refused reports whether the proxy refused the request: a failed CONNECT comes
// back as an error, a plain-HTTP request as a 502.
func refused(t *testing.T, resp *http.Response, err error) bool {
	t.Helper()
	if err != nil {
		return true
	}
	defer resp.Body.Close()
	return resp.StatusCode >= 400
}

// A Bash subcommand's connection is decided by the gate at connect time, under
// the task its session token names: a declared target is dialed and served, an
// undeclared one is refused before any connection is made, and the gate is the
// one that sees the address.
func TestRecordingProxyGatesBashTrafficAtConnect(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	target := strings.TrimPrefix(srv.URL, "http://")

	g := &gateFixture{}
	tr, proxyURL := startGatedProxy(t, func(*Traffic) GateConfig {
		return g.config(map[string]string{"tok-task-7": "7"}, map[string]bool{"undeclared.test:80": true})
	})
	bash := proxyClient(t, tr, egress.MarkProxyURLToken(proxyURL, "tok-task-7"))

	resp, err := bash.Get(srv.URL + "/declared")
	if err != nil {
		t.Fatalf("declared target through the gated proxy: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 || hits.Load() != 1 {
		t.Fatalf("declared target: status %d, target hits %d", resp.StatusCode, hits.Load())
	}
	calls := g.seen()
	if len(calls) != 1 || calls[0].taskID != "7" || calls[0].addr != target {
		t.Fatalf("gate saw %+v, want one call for task 7 at %s", calls, target)
	}

	resp, err = bash.Get("http://undeclared.test/probe")
	if !refused(t, resp, err) {
		t.Fatalf("undeclared target: status %d, want the connection refused", resp.StatusCode)
	}
	if hits.Load() != 1 {
		t.Fatalf("undeclared target reached the server: hits %d", hits.Load())
	}
	calls = g.seen()
	if len(calls) != 2 || calls[1].taskID != "7" || calls[1].addr != "undeclared.test:80" {
		t.Fatalf("gate saw %+v, want the undeclared target under task 7", calls)
	}
}

// The same gate governs the tunnel of an intercepted HTTPS request.
func TestRecordingProxyGatesTunnelledTraffic(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	// The MITM leaf for a bare IP has no IP SAN: address the TLS target by name.
	tlsURL := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	host := strings.TrimPrefix(tlsURL, "https://")

	g := &gateFixture{}
	tr, proxyURL := startGatedProxy(t, func(*Traffic) GateConfig {
		return g.config(map[string]string{"tok-task-9": "9"}, map[string]bool{host: true})
	})
	bash := proxyClient(t, tr, egress.MarkProxyURLToken(proxyURL, "tok-task-9"))

	if resp, err := bash.Get(tlsURL + "/tunnel"); !refused(t, resp, err) {
		t.Fatalf("undeclared HTTPS target: status %d, want the connection refused", resp.StatusCode)
	}
	calls := g.seen()
	if len(calls) == 0 || calls[0].taskID != "9" || calls[0].addr != host {
		t.Fatalf("gate saw %+v, want the tunnelled target under task 9 at %s", calls, host)
	}
}

// A client that gates itself (WebFetch, the http custom tools, the enrich
// probe) sends no token: the relay admits it under the install-wide rules only,
// with no task scope, as before.
func TestRecordingProxyUnmarkedConnectionHasNoScope(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("Proxy-Authorization"); v != "" {
			t.Errorf("Proxy-Authorization reached the target: %q", v)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	g := &gateFixture{}
	tr, proxyURL := startGatedProxy(t, func(*Traffic) GateConfig {
		return g.config(map[string]string{"tok-task-7": "7"}, nil)
	})
	plain := proxyClient(t, tr, proxyURL)

	resp, err := plain.Get(srv.URL + "/unmarked")
	if err != nil {
		t.Fatalf("unmarked request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unmarked request: status %d", resp.StatusCode)
	}
	calls := g.seen()
	if len(calls) != 1 || calls[0].taskID != "" {
		t.Fatalf("gate saw %+v, want one call with no task scope", calls)
	}
}

// A token this process does not honour is refused at the relay's
// authentication: the request never reaches the gate, and no connection is
// opened at all.
func TestRecordingProxyRefusesUnknownToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	g := &gateFixture{}
	tr, proxyURL := startGatedProxy(t, func(*Traffic) GateConfig {
		return g.config(map[string]string{"tok-task-7": "7"}, nil)
	})
	stale := proxyClient(t, tr, egress.MarkProxyURLToken(proxyURL, "tok-task-deleted"))

	if resp, err := stale.Get(srv.URL + "/stale"); !refused(t, resp, err) {
		t.Fatalf("a stale session token was accepted: status %d", resp.StatusCode)
	}
	if calls := g.seen(); len(calls) != 0 {
		t.Fatalf("gate was consulted for an unresolvable token: %+v", calls)
	}
}

// An approved target still leaves through the configured global egress proxy:
// the relay carries that hop once the proxy's upstream is the relay.
func TestRecordingProxyGateKeepsGlobalProxy(t *testing.T) {
	var proxied atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("global proxy saw %s, want CONNECT", r.Method)
		}
		proxied.Add(1)
		// The hop is what this test asserts; it does not need to succeed.
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer upstream.Close()

	g := &gateFixture{}
	var tr *Traffic
	tr, proxyURL := startGatedProxy(t, func(o *Traffic) GateConfig {
		tr = o
		cfg := g.config(map[string]string{"tok-task-7": "7"}, nil)
		// The production dial of the relay: the gate decides, then the
		// connection leaves through the global proxy.
		cfg.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tr.DialUpstream(ctx, network, addr)
		}
		return cfg
	})
	if err := tr.SetUpstreamProxy(upstream.URL); err != nil {
		t.Fatal(err)
	}

	bash := proxyClient(t, tr, egress.MarkProxyURLToken(proxyURL, "tok-task-7"))
	if resp, err := bash.Get("http://example.test/through"); !refused(t, resp, err) {
		t.Fatalf("request through a proxy that answers 502: status %d", resp.StatusCode)
	}
	if proxied.Load() == 0 {
		t.Fatal("the gate bypassed the global egress proxy")
	}
}
