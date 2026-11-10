// Package dns implements Shunt's name resolution: a fake-IP pool used when
// hostnames are resolved through the proxy, a DNS query handler for hijacked
// queries, and IP-to-hostname tracking so rules can match on host names.
package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"shunt/internal/rules"
)

// FakeIP maps hostnames to synthetic addresses from a reserved range
// (198.18.0.0/15 by default, the benchmarking range that is never routed on
// the Internet). Proxifier does the same with 127.8.*.*.
type FakeIP struct {
	mu     sync.Mutex
	prefix netip.Prefix
	base   uint32
	size   uint32
	next   uint32
	byHost map[string]uint32
	byOff  map[uint32]string
}

const fakeReserved = 16 // first addresses are kept for the tunnel itself

func NewFakeIP(prefix netip.Prefix) *FakeIP {
	p := prefix.Masked()
	b := p.Addr().As4()
	return &FakeIP{
		prefix: p,
		base:   binary.BigEndian.Uint32(b[:]),
		size:   uint32(1) << (32 - p.Bits()),
		next:   fakeReserved,
		byHost: map[string]uint32{},
		byOff:  map[uint32]string{},
	}
}

func (f *FakeIP) addr(off uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], f.base+off)
	return netip.AddrFrom4(b)
}

// Alloc returns the fake address for host, allocating one if needed.
func (f *FakeIP) Alloc(host string) netip.Addr {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	f.mu.Lock()
	defer f.mu.Unlock()
	if off, ok := f.byHost[host]; ok {
		return f.addr(off)
	}
	off := f.next
	f.next++
	if f.next >= f.size-1 {
		f.next = fakeReserved
	}
	if old, ok := f.byOff[off]; ok {
		delete(f.byHost, old)
	}
	f.byHost[host] = off
	f.byOff[off] = host
	return f.addr(off)
}

func (f *FakeIP) Contains(ip netip.Addr) bool { return f.prefix.Contains(ip.Unmap()) }

// Lookup returns the hostname a fake address was issued for.
func (f *FakeIP) Lookup(ip netip.Addr) (string, bool) {
	ip = ip.Unmap()
	if !ip.Is4() || !f.prefix.Contains(ip) {
		return "", false
	}
	b := ip.As4()
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.byOff[binary.BigEndian.Uint32(b[:])-f.base]
	return h, ok
}

// Config controls how queries are answered.
type Config struct {
	// ViaProxy: answer A queries with fake IPs so that the hostname is
	// later resolved by the proxy server.
	ViaProxy bool
	// BlockNonA: when resolving via proxy, refuse everything but A/AAAA.
	BlockNonA bool
	// List and OnlyFromList implement the DNS name list: either names that
	// must NOT go through the proxy, or the ONLY names that go through it.
	List         *rules.HostList
	OnlyFromList bool
	// Upstreams are real DNS servers ("ip:53") used for local resolution.
	Upstreams []string
}

// Dialer opens sockets that bypass the tunnel.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Resolver answers DNS queries captured by the engine.
type Resolver struct {
	Fake *FakeIP
	dial Dialer
	cfg  atomic.Pointer[Config]

	mu    sync.Mutex
	names map[netip.Addr]string // real IP -> hostname, learned from answers

	Queries, FakeAnswers, Forwarded, Failed atomic.Uint64
}

func NewResolver(fake *FakeIP, dial Dialer, cfg Config) *Resolver {
	r := &Resolver{Fake: fake, dial: dial, names: map[netip.Addr]string{}}
	r.SetConfig(cfg)
	return r
}

func (r *Resolver) SetConfig(c Config) {
	if c.List == nil {
		c.List = rules.CompileHostList("")
	}
	r.cfg.Store(&c)
}

func (r *Resolver) Config() Config { return *r.cfg.Load() }

// useProxyFor decides whether a name is resolved through the proxy.
func (c *Config) useProxyFor(name string) bool {
	if !c.ViaProxy {
		return false
	}
	listed := c.List.Match(name)
	if c.OnlyFromList {
		return listed
	}
	return !listed
}

// HostFor returns the hostname known for ip: either the name a fake IP was
// issued for or a name learned from a forwarded DNS answer.
func (r *Resolver) HostFor(ip netip.Addr) (host string, fake bool) {
	ip = ip.Unmap()
	if h, ok := r.Fake.Lookup(ip); ok {
		return h, true
	}
	r.mu.Lock()
	h := r.names[ip]
	r.mu.Unlock()
	return h, false
}

func (r *Resolver) learn(name string, ip netip.Addr) {
	r.mu.Lock()
	if len(r.names) > 50000 {
		r.names = map[netip.Addr]string{}
	}
	r.names[ip.Unmap()] = name
	r.mu.Unlock()
}

func reply(q *dnsmessage.Message, rcode dnsmessage.RCode, answers ...dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID: q.ID, Response: true, OpCode: q.OpCode, RecursionDesired: q.RecursionDesired,
			RecursionAvailable: true, RCode: rcode,
		},
		Questions: q.Questions,
		Answers:   answers,
	}
	b, err := m.Pack()
	if err != nil {
		return nil
	}
	return b
}

// Handle answers one raw DNS query and returns the raw response (nil when
// the query is unparseable and should be dropped).
func (r *Resolver) Handle(ctx context.Context, query []byte) []byte {
	var q dnsmessage.Message
	if err := q.Unpack(query); err != nil || len(q.Questions) == 0 || q.Response {
		return nil
	}
	r.Queries.Add(1)
	cfg := r.cfg.Load()
	qu := q.Questions[0]
	name := strings.ToLower(strings.TrimSuffix(qu.Name.String(), "."))

	if qu.Class == dnsmessage.ClassINET && cfg.useProxyFor(name) {
		switch qu.Type {
		case dnsmessage.TypeA:
			ip := r.Fake.Alloc(name)
			r.FakeAnswers.Add(1)
			return reply(&q, dnsmessage.RCodeSuccess, dnsmessage.Resource{
				Header: dnsmessage.ResourceHeader{Name: qu.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
				Body:   &dnsmessage.AResource{A: ip.As4()},
			})
		case dnsmessage.TypeAAAA:
			// No fake IPv6: an empty answer makes applications use A.
			return reply(&q, dnsmessage.RCodeSuccess)
		default:
			if cfg.BlockNonA {
				return reply(&q, dnsmessage.RCodeRefused)
			}
		}
	}
	resp, err := r.forward(ctx, cfg, query)
	if err != nil {
		r.Failed.Add(1)
		return reply(&q, dnsmessage.RCodeServerFailure)
	}
	r.Forwarded.Add(1)
	r.snoop(name, resp)
	return resp
}

func (r *Resolver) snoop(name string, resp []byte) {
	var m dnsmessage.Message
	if m.Unpack(resp) != nil {
		return
	}
	for _, a := range m.Answers {
		switch b := a.Body.(type) {
		case *dnsmessage.AResource:
			r.learn(name, netip.AddrFrom4(b.A))
		case *dnsmessage.AAAAResource:
			r.learn(name, netip.AddrFrom16(b.AAAA))
		}
	}
}

var errNoUpstream = errors.New("no upstream DNS server available")

func (r *Resolver) forward(ctx context.Context, cfg *Config, query []byte) ([]byte, error) {
	err := errNoUpstream
	for _, up := range cfg.Upstreams {
		var resp []byte
		if resp, err = r.exchange(ctx, up, query); err == nil {
			return resp, nil
		}
	}
	return nil, err
}

func (r *Resolver) exchange(ctx context.Context, upstream string, query []byte) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	c, err := r.dial(cctx, "udp", upstream)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write(query); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 2 && len(query) >= 2 && buf[0] == query[0] && buf[1] == query[1] {
			return buf[:n], nil
		}
	}
}

// Probe reports whether any upstream DNS server answers at all.
func (r *Resolver) Probe(ctx context.Context) bool {
	q, err := buildQuery("example.com.", dnsmessage.TypeA)
	if err != nil {
		return false
	}
	_, err = r.forward(ctx, r.cfg.Load(), q)
	return err == nil
}

func buildQuery(name string, t dnsmessage.Type) ([]byte, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	n, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: uint16(time.Now().UnixNano()), RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: t, Class: dnsmessage.ClassINET}},
	}
	return m.Pack()
}

// LookupIP resolves host using the real upstream servers (bypassing the
// tunnel). It is used for direct connections to names that were handed a
// fake IP.
func (r *Resolver) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}
	cfg := r.cfg.Load()
	var out []netip.Addr
	var lastErr error
	for _, t := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		q, err := buildQuery(host, t)
		if err != nil {
			return nil, err
		}
		resp, err := r.forward(ctx, cfg, q)
		if err != nil {
			lastErr = err
			continue
		}
		var m dnsmessage.Message
		if err := m.Unpack(resp); err != nil {
			lastErr = err
			continue
		}
		for _, a := range m.Answers {
			switch b := a.Body.(type) {
			case *dnsmessage.AResource:
				out = append(out, netip.AddrFrom4(b.A))
			case *dnsmessage.AAAAResource:
				out = append(out, netip.AddrFrom16(b.AAAA))
			}
		}
		if len(out) > 0 {
			return out, nil
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no such host: " + host)
	}
	return nil, lastErr
}
