package core

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"shunt/internal/dns"
	"shunt/internal/netif"
	"shunt/internal/profile"
	"shunt/internal/tun"
)

// These tests drive the real engine through a userspace "OS" stack piped into
// the engine stack, so the whole data path (netstack, rules, DNS, proxy
// handshakes, relay) runs without administrator rights and without touching
// the system's routes. Set SHUNT_TEST_PROXY=127.0.0.1:10808 to run them.

func testProxy(t *testing.T) (string, int) {
	s := os.Getenv("SHUNT_TEST_PROXY")
	if s == "" {
		t.Skip("SHUNT_TEST_PROXY not set")
	}
	ap := netip.MustParseAddrPort(s)
	return ap.Addr().String(), int(ap.Port())
}

type harness struct {
	e      *Engine
	client *tun.Stack
	src    netip.Addr
}

func newHarness(t *testing.T, p *profile.Profile, bindPhysical, viaProxy bool) *harness {
	e, err := New(p)
	if err != nil {
		t.Fatal(err)
	}
	if bindPhysical {
		b, err := netif.Default(0)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("binding outbound sockets to %s (#%d)", b.Name, b.Index)
		e.bind.Store(&b)
	}
	ups := netif.SystemDNS(e.bind.Load().Index)
	if len(ups) == 0 {
		ups = []string{"1.1.1.1:53"}
	}
	t.Logf("upstream DNS: %v", ups)
	e.res = dns.NewResolver(dns.NewFakeIP(tun.FakeIPPrefix), dns.Dialer(e.dial), e.resolverConfig(viaProxy, ups))
	if e.stack, err = tun.NewStack(1500, e); err != nil {
		t.Fatal(err)
	}
	c, err := tun.NewClientStack(1500)
	if err != nil {
		t.Fatal(err)
	}
	src := netip.MustParseAddr("198.18.0.1")
	c.AddAddress(src)
	tun.Pipe(c, e.stack)
	t.Cleanup(func() { c.Close(); e.stack.Close() })
	return &harness{e: e, client: c, src: src}
}

func (h *harness) query(t *testing.T, name string) netip.Addr {
	c, err := h.client.DialUDP(h.src, netip.MustParseAddrPort("198.18.0.2:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	n := dnsmessage.MustNewName(name + ".")
	m := dnsmessage.Message{Header: dnsmessage.Header{ID: 77, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	q, _ := m.Pack()
	c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := c.Write(q); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1500)
	k, err := c.Read(buf)
	if err != nil {
		t.Fatalf("DNS through tunnel: %v", err)
	}
	var r dnsmessage.Message
	if err := r.Unpack(buf[:k]); err != nil {
		t.Fatal(err)
	}
	for _, a := range r.Answers {
		if x, ok := a.Body.(*dnsmessage.AResource); ok {
			return netip.AddrFrom4(x.A)
		}
	}
	t.Fatalf("no A answer for %s (rcode %v)", name, r.RCode)
	return netip.Addr{}
}

func (h *harness) get(t *testing.T, ip netip.Addr, host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c, err := h.client.DialTCP(ctx, h.src, netip.AddrPortFrom(ip, 80))
	if err != nil {
		t.Fatalf("TCP through tunnel to %s: %v", ip, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(30 * time.Second))
	fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	return strings.TrimSpace(line)
}

func proxyProfile(addr string, port int) *profile.Profile {
	p := profile.Default()
	p.Proxies = []profile.Proxy{{ID: 100, Type: profile.SOCKS5, Address: addr, Port: port, UseHostname: true}}
	p.Rules[len(p.Rules)-1].Action = profile.Action{Type: profile.ActProxy, ID: 100}
	return p
}

func TestTunnelThroughProxyRealDNS(t *testing.T) {
	a, port := testProxy(t)
	h := newHarness(t, proxyProfile(a, port), true, false)
	ip := h.query(t, "example.com")
	t.Logf("example.com -> %s (real DNS)", ip)
	if line := h.get(t, ip, "example.com"); !strings.HasPrefix(line, "HTTP/") {
		t.Fatalf("unexpected response %q", line)
	} else {
		t.Logf("response: %s", line)
	}
}

func TestTunnelThroughProxyFakeDNS(t *testing.T) {
	a, port := testProxy(t)
	h := newHarness(t, proxyProfile(a, port), true, true)
	ip := h.query(t, "example.com")
	if !tun.FakeIPPrefix.Contains(ip) {
		t.Fatalf("expected a fake IP, got %s", ip)
	}
	t.Logf("example.com -> %s (fake)", ip)
	if line := h.get(t, ip, "example.com"); !strings.HasPrefix(line, "HTTP/") {
		t.Fatalf("unexpected response %q", line)
	} else {
		t.Logf("response: %s", line)
	}
}

func TestBoundDirectDial(t *testing.T) {
	testProxy(t)
	b, err := netif.Default(0)
	if err != nil {
		t.Fatal(err)
	}
	d := netif.Dialer(func() netif.Binding { return b })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := d(ctx, "udp", "1.1.1.1:53")
	if err != nil {
		t.Fatalf("bound UDP socket: %v", err)
	}
	c.Close()
	_ = net.IPv4zero
}
