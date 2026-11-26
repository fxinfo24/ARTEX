package traffic

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// echoSocks5 is a minimal SOCKS5 CONNECT server: it authenticates when auth is
// non-nil, reports rep, then echoes whatever it receives.
func echoSocks5(t *testing.T, auth func(user, pass string) bool, rep byte) (addr string, seen chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	seen = make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var hdr [2]byte
				if _, err := io.ReadFull(br, hdr[:]); err != nil {
					return
				}
				methods := make([]byte, int(hdr[1]))
				if _, err := io.ReadFull(br, methods); err != nil {
					return
				}
				method := byte(socks5AuthUserPass)
				if _, err := c.Write([]byte{socks5Version, method}); err != nil {
					return
				}
				if method == socks5AuthUserPass {
					var head [2]byte
					if _, err := io.ReadFull(br, head[:]); err != nil {
						return
					}
					user := make([]byte, int(head[1]))
					if _, err := io.ReadFull(br, user); err != nil {
						return
					}
					var plen [1]byte
					if _, err := io.ReadFull(br, plen[:]); err != nil {
						return
					}
					pass := make([]byte, int(plen[0]))
					if _, err := io.ReadFull(br, pass); err != nil {
						return
					}
					ok := auth == nil || auth(string(user), string(pass))
					status := byte(0x00)
					if !ok {
						status = 0x01
					}
					if _, err := c.Write([]byte{socks5UserPassVer, status}); err != nil || !ok {
						return
					}
				}
				var req [4]byte
				if _, err := io.ReadFull(br, req[:]); err != nil {
					return
				}
				var host string
				switch req[3] {
				case socks5AtypIPv4:
					ip := make([]byte, 4)
					_, _ = io.ReadFull(br, ip)
					host = net.IP(ip).String()
				case socks5AtypDomain:
					var l [1]byte
					_, _ = io.ReadFull(br, l[:])
					dom := make([]byte, int(l[0]))
					_, _ = io.ReadFull(br, dom)
					host = string(dom)
				}
				var port [2]byte
				_, _ = io.ReadFull(br, port[:])
				seen <- net.JoinHostPort(host, itoaPort(port))
				_, _ = c.Write([]byte{socks5Version, rep, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
				if rep != socks5RepSuccess {
					return
				}
				_, _ = io.Copy(c, br)
			}(c)
		}
	}()
	return ln.Addr().String(), seen
}

func itoaPort(p [2]byte) string { return strconv.Itoa(int(binary.BigEndian.Uint16(p[:]))) }

// The platform dials its global SOCKS5 egress proxy itself once the recording
// proxy's upstream is the gate relay: the approved target leaves through the
// configured proxy, with its credentials, and nowhere else.
func TestDialThroughSOCKS5Proxy(t *testing.T) {
	addr, seen := echoSocks5(t, func(user, pass string) bool {
		return user == "u" && pass == "p"
	}, socks5RepSuccess)
	u, _ := url.Parse("socks5://u:p@" + addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialThroughProxy(ctx, u, "example.test:8080")
	if err != nil {
		t.Fatalf("dial through the socks5 proxy: %v", err)
	}
	defer conn.Close()
	select {
	case got := <-seen:
		if got != "example.test:8080" {
			t.Fatalf("proxy was asked for %q, want example.test:8080", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the socks5 proxy saw no CONNECT")
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo through the tunnel: %q, %v", buf, err)
	}
}

// A refusal from the proxy is an error, never a connection.
func TestDialThroughSOCKS5ProxyRefused(t *testing.T) {
	addr, _ := echoSocks5(t, func(string, string) bool { return true }, socks5RepNotAllowed)
	u, _ := url.Parse("socks5://" + addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if conn, err := dialThroughProxy(ctx, u, "example.test:80"); err == nil {
		conn.Close()
		t.Fatal("a refused CONNECT returned a connection")
	}
}

// An HTTP proxy that answers a CONNECT with a non-200 closes the hop with an
// error (the library's SOCKS5 path panics on that, which is why the relay is an
// HTTP proxy).
func TestDialThroughHTTPProxyRefused(t *testing.T) {
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			t.Errorf("method = %s, want CONNECT", r.Method)
		}
		if got := r.Header.Get("Proxy-Authorization"); got != "Basic "+base64.StdEncoding.EncodeToString([]byte("u:p")) {
			t.Errorf("Proxy-Authorization = %q", got)
		}
		w.WriteHeader(http.StatusForbidden)
	})}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	u, _ := url.Parse("http://u:p@" + ln.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialThroughProxy(ctx, u, "example.test:443")
	if err == nil {
		conn.Close()
		t.Fatal("a 403 CONNECT returned a connection")
	}
	if !strings.Contains(err.Error(), "Forbidden") {
		t.Fatalf("err = %v, want the proxy's status", err)
	}
}
