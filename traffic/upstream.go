package traffic

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// upstreamDialer is the net.Dialer settings of every connection the platform
// opens itself (the recording proxy's gate relay, and the hop from it to a
// configured global egress proxy).
var upstreamDialer = &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}

// dialThroughProxy opens addr through the egress proxy proxyURL (http, https or
// socks5, with optional user:pass), for the connections the platform already
// decided to make. It is the dial the gate relay uses to keep the global egress
// proxy in front of everything captured: go-mitmproxy dials its upstream itself,
// so once the proxy's upstream is the relay, the relay has to carry the hop.
func dialThroughProxy(ctx context.Context, proxyURL *url.URL, addr string) (net.Conn, error) {
	switch strings.ToLower(proxyURL.Scheme) {
	case "socks5", "socks5h":
		return dialSOCKS5Proxy(ctx, proxyURL, addr)
	case "http", "https", "":
		return dialHTTPProxy(ctx, proxyURL, addr)
	default:
		return nil, fmt.Errorf("egress proxy: unsupported scheme %q", proxyURL.Scheme)
	}
}

// dialSOCKS5Proxy performs an RFC 1928 CONNECT to addr through a SOCKS5 proxy,
// with RFC 1929 username/password authentication when the URL carries it.
func dialSOCKS5Proxy(ctx context.Context, u *url.URL, addr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("socks5 proxy: bad port %q", portStr)
	}
	conn, err := upstreamDialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}

	methods := []byte{socks5AuthNone}
	var auth []byte
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		methods = append(methods, socks5AuthUserPass)
		auth = append([]byte{socks5UserPassVer, byte(len(user))}, user...)
		auth = append(auth, byte(len(pass)))
		auth = append(auth, pass...)
	}
	if _, err := conn.Write(append([]byte{socks5Version, byte(len(methods))}, methods...)); err != nil {
		return fail(err)
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return fail(err)
	}
	if choice[0] != socks5Version {
		return fail(errors.New("socks5 proxy: bad version in method selection"))
	}
	switch choice[1] {
	case socks5AuthNone:
	case socks5AuthUserPass:
		if auth == nil {
			return fail(errors.New("socks5 proxy: it asked for credentials the URL does not carry"))
		}
		if _, err := conn.Write(auth); err != nil {
			return fail(err)
		}
		var reply [2]byte
		if _, err := io.ReadFull(conn, reply[:]); err != nil {
			return fail(err)
		}
		if reply[1] != 0x00 {
			return fail(errors.New("socks5 proxy: authentication refused"))
		}
	default:
		return fail(errors.New("socks5 proxy: no acceptable authentication method"))
	}

	req := []byte{socks5Version, socks5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, socks5AtypIPv4)
			req = append(req, ip4...)
		} else {
			req = append(req, socks5AtypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return fail(errors.New("socks5 proxy: host name too long"))
		}
		req = append(req, socks5AtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, uint16(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	var head [4]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return fail(err)
	}
	if head[0] != socks5Version {
		return fail(errors.New("socks5 proxy: bad version in reply"))
	}
	if head[1] != socks5RepSuccess {
		return fail(fmt.Errorf("socks5 proxy: %s", socks5ReplyText(head[1])))
	}
	switch head[3] {
	case socks5AtypIPv4:
		_, err = io.ReadFull(conn, make([]byte, 4+2))
	case socks5AtypIPv6:
		_, err = io.ReadFull(conn, make([]byte, 16+2))
	case socks5AtypDomain:
		var l [1]byte
		if _, err = io.ReadFull(conn, l[:]); err == nil {
			_, err = io.ReadFull(conn, make([]byte, int(l[0])+2))
		}
	default:
		err = errors.New("socks5 proxy: bad address type in reply")
	}
	if err != nil {
		return fail(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5ReplyText(rep byte) string {
	switch rep {
	case socks5RepGeneralFailure:
		return "general SOCKS server failure"
	case socks5RepNotAllowed:
		return "connection not allowed by ruleset"
	case socks5RepNetworkUnreachable:
		return "network unreachable"
	case socks5RepHostUnreachable:
		return "host unreachable"
	case socks5RepConnectionRefused:
		return "connection refused"
	case socks5RepTTLExpired:
		return "TTL expired"
	case socks5RepCmdNotSupported:
		return "command not supported"
	case socks5RepAtypNotSupported:
		return "address type not supported"
	default:
		return "reply " + strconv.Itoa(int(rep))
	}
}

// dialHTTPProxy performs an HTTP CONNECT to addr through an http (or https)
// proxy, with Proxy-Authorization when the URL carries credentials.
func dialHTTPProxy(ctx context.Context, u *url.URL, addr string) (net.Conn, error) {
	conn, err := upstreamDialer.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(u.Scheme, "https") {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, err
		}
		conn = tlsConn
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if u.User != nil {
		user := u.User.Username()
		pass, _ := u.User.Password()
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(user+":"+pass)))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("egress proxy: CONNECT %s: %s", addr, resp.Status)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
