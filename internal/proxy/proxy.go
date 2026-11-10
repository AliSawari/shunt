// Package proxy implements client side handshakes for SOCKS5, SOCKS4/4A,
// HTTPS (CONNECT) and plain HTTP proxies, and chaining of several proxies.
package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"shunt/internal/profile"
)

// DialFunc opens an outbound connection (normally bound to the physical
// network interface so that it bypasses the tunnel).
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Error is a proxy level failure, as opposed to a network failure reaching
// the first proxy.
type Error struct {
	Proxy string
	Msg   string
}

func (e *Error) Error() string { return "proxy " + e.Proxy + ": " + e.Msg }

func perr(px *profile.Proxy, format string, a ...any) error {
	return &Error{Proxy: px.HostPort(), Msg: fmt.Sprintf(format, a...)}
}

var socks5Errors = map[byte]string{
	1: "general SOCKS server failure",
	2: "connection not allowed by ruleset",
	3: "network unreachable",
	4: "host unreachable",
	5: "connection refused",
	6: "TTL expired",
	7: "command not supported",
	8: "address type not supported",
}

// Handshake negotiates, over conn (already connected to px), a tunnel to
// host:port. The returned connection carries the tunnelled stream.
func Handshake(ctx context.Context, conn net.Conn, px *profile.Proxy, host string, port uint16) (net.Conn, error) {
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	} else {
		conn.SetDeadline(time.Now().Add(30 * time.Second))
	}
	defer conn.SetDeadline(time.Time{})
	var err error
	switch px.Type {
	case profile.SOCKS5:
		err = socks5(conn, px, host, port)
	case profile.SOCKS4:
		err = socks4(ctx, conn, px, host, port)
	case profile.HTTPS:
		err = httpConnect(conn, px, host, port)
	case profile.HTTP:
		return newHTTPRewriter(conn, px, host, port), nil
	default:
		err = perr(px, "unsupported protocol %s", px.Type)
	}
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func socks5(c net.Conn, px *profile.Proxy, host string, port uint16) error {
	auth := px.AuthEnabled && px.Username != ""
	hello := []byte{5, 1, 0}
	if auth {
		hello = []byte{5, 2, 0, 2}
	}
	if _, err := c.Write(hello); err != nil {
		return err
	}
	var rep [2]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return perr(px, "no SOCKS5 greeting reply (%v)", err)
	}
	if rep[0] != 5 {
		return perr(px, "not a SOCKS5 server (version byte %d)", rep[0])
	}
	switch rep[1] {
	case 0:
	case 2:
		if !auth {
			return perr(px, "server requires username/password authentication")
		}
		if len(px.Username) > 255 || len(px.Password) > 255 {
			return perr(px, "username or password too long")
		}
		b := []byte{1, byte(len(px.Username))}
		b = append(b, px.Username...)
		b = append(b, byte(len(px.Password)))
		b = append(b, px.Password...)
		if _, err := c.Write(b); err != nil {
			return err
		}
		if _, err := io.ReadFull(c, rep[:]); err != nil {
			return perr(px, "authentication reply not received (%v)", err)
		}
		if rep[1] != 0 {
			return perr(px, "authentication failed (wrong username or password)")
		}
	case 0xFF:
		return perr(px, "no acceptable authentication method")
	default:
		return perr(px, "unsupported authentication method %d", rep[1])
	}

	req := []byte{5, 1, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.Is4() {
			req = append(req, 1)
		} else {
			req = append(req, 4)
		}
		req = append(req, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return perr(px, "hostname too long")
		}
		req = append(req, 3, byte(len(host)))
		req = append(req, host...)
	}
	req = binary.BigEndian.AppendUint16(req, port)
	if _, err := c.Write(req); err != nil {
		return err
	}
	var hdr [4]byte
	if _, err := io.ReadFull(c, hdr[:]); err != nil {
		return perr(px, "no reply to CONNECT (%v)", err)
	}
	if hdr[1] != 0 {
		msg, ok := socks5Errors[hdr[1]]
		if !ok {
			msg = "error code " + strconv.Itoa(int(hdr[1]))
		}
		return perr(px, "%s", msg)
	}
	n := 0
	switch hdr[3] {
	case 1:
		n = 4
	case 4:
		n = 16
	case 3:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return perr(px, "malformed reply")
	}
	_, err := io.CopyN(io.Discard, c, int64(n+2))
	return err
}

func socks4(ctx context.Context, c net.Conn, px *profile.Proxy, host string, port uint16) error {
	req := []byte{4, 1}
	req = binary.BigEndian.AppendUint16(req, port)
	ip, err := netip.ParseAddr(host)
	name := ""
	if err != nil {
		if px.Socks4A {
			ip, name = netip.AddrFrom4([4]byte{0, 0, 0, 1}), host
		} else {
			ips, lerr := net.DefaultResolver.LookupNetIP(ctx, "ip4", host)
			if lerr != nil || len(ips) == 0 {
				return perr(px, "cannot resolve %s for SOCKS4 (enable the 4A extension)", host)
			}
			ip = ips[0]
		}
	}
	ip = ip.Unmap()
	if !ip.Is4() {
		return perr(px, "SOCKS4 does not support IPv6 targets")
	}
	req = append(req, ip.AsSlice()...)
	req = append(req, px.Username...)
	req = append(req, 0)
	if name != "" {
		req = append(req, name...)
		req = append(req, 0)
	}
	if _, err := c.Write(req); err != nil {
		return err
	}
	var rep [8]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return perr(px, "no SOCKS4 reply (%v)", err)
	}
	switch rep[1] {
	case 0x5A:
		return nil
	case 0x5B:
		return perr(px, "request rejected or failed")
	case 0x5C, 0x5D:
		return perr(px, "request rejected (identd)")
	}
	return perr(px, "not a SOCKS4 server (reply code %d)", rep[1])
}

func basicAuth(px *profile.Proxy) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(px.Username+":"+px.Password))
}

func httpConnect(c net.Conn, px *profile.Proxy, host string, port uint16) error {
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if px.AuthEnabled && px.Username != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", basicAuth(px))
	}
	if px.UserAgent != "" {
		fmt.Fprintf(&b, "User-Agent: %s\r\n", px.UserAgent)
	}
	b.WriteString("Proxy-Connection: Keep-Alive\r\n\r\n")
	if _, err := io.WriteString(c, b.String()); err != nil {
		return err
	}
	// Read the response header one byte at a time so that no tunnelled
	// payload is consumed.
	var hdr []byte
	var one [1]byte
	for !strings.HasSuffix(string(hdr), "\r\n\r\n") {
		if len(hdr) > 16<<10 {
			return perr(px, "response header too large")
		}
		if _, err := io.ReadFull(c, one[:]); err != nil {
			return perr(px, "no reply to CONNECT (%v)", err)
		}
		hdr = append(hdr, one[0])
	}
	line, _, _ := strings.Cut(string(hdr), "\r\n")
	f := strings.Fields(line)
	if len(f) < 2 || !strings.HasPrefix(f[0], "HTTP/") {
		return perr(px, "not an HTTP proxy server")
	}
	switch f[1] {
	case "200":
		return nil
	case "407":
		return perr(px, "proxy authentication required (407)")
	}
	return perr(px, "CONNECT failed: %s", strings.TrimSpace(strings.TrimPrefix(line, f[0])))
}

// httpRewriter adapts origin-form HTTP requests written by the application
// into absolute-form requests understood by a plain HTTP proxy.
type httpRewriter struct {
	net.Conn
	pw *io.PipeWriter
}

func newHTTPRewriter(c net.Conn, px *profile.Proxy, host string, port uint16) net.Conn {
	pr, pw := io.Pipe()
	go func() {
		br := bufio.NewReader(pr)
		for {
			req, err := http.ReadRequest(br)
			if err != nil {
				pr.CloseWithError(errors.New("shunt: stream is not HTTP; a plain HTTP proxy can only carry HTTP requests"))
				c.Close()
				return
			}
			req.URL.Scheme = "http"
			if req.URL.Host == "" {
				req.URL.Host = req.Host
			}
			if req.URL.Host == "" {
				req.URL.Host = net.JoinHostPort(host, strconv.Itoa(int(port)))
			}
			if px.AuthEnabled && px.Username != "" {
				req.Header.Set("Proxy-Authorization", basicAuth(px))
			}
			if px.UserAgent != "" {
				req.Header.Set("User-Agent", px.UserAgent)
			}
			if err := req.WriteProxy(c); err != nil {
				pr.CloseWithError(err)
				return
			}
		}
	}()
	return &httpRewriter{Conn: c, pw: pw}
}

func (h *httpRewriter) Write(b []byte) (int, error) { return h.pw.Write(b) }
func (h *httpRewriter) Close() error {
	h.pw.Close()
	return h.Conn.Close()
}
func (h *httpRewriter) CloseWrite() error { return h.pw.Close() }

// DialChain connects through the given proxies in order and tunnels to
// host:port through the last one.
func DialChain(ctx context.Context, dial DialFunc, chain []*profile.Proxy, host string, port uint16) (net.Conn, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty proxy chain")
	}
	for i, px := range chain {
		if px.Type == profile.HTTP && i != len(chain)-1 {
			return nil, perr(px, "a plain HTTP proxy can only be the last proxy in a chain")
		}
	}
	conn, err := dial(ctx, "tcp", chain[0].HostPort())
	if err != nil {
		return nil, fmt.Errorf("could not connect to proxy %s: %w", chain[0].HostPort(), err)
	}
	for i, px := range chain {
		th, tp := host, port
		if i < len(chain)-1 {
			th, tp = chain[i+1].Address, uint16(chain[i+1].Port)
		}
		c2, err := Handshake(ctx, conn, px, th, tp)
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = c2
	}
	return conn, nil
}
