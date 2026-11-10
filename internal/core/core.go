// Package core is the Shunt engine: it receives captured connections, picks
// a proxification rule and relays the traffic directly or through proxies.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"shunt/internal/dns"
	"shunt/internal/netif"
	"shunt/internal/procinfo"
	"shunt/internal/profile"
	"shunt/internal/proxy"
	"shunt/internal/rules"
	"shunt/internal/tun"
)

// Engine holds the running state.
type Engine struct {
	prof    *profile.Profile
	match   *rules.Matcher
	res     *dns.Resolver
	bind    atomic.Pointer[netif.Binding]
	dial    proxy.DialFunc
	dev     *tun.Device
	stack   *tun.Stack
	gateway net.Listener
	selfPID map[uint32]bool // local proxy processes: always direct (loop prevention)

	mu     sync.Mutex
	failed map[int]time.Time // redundancy: proxy id -> time it failed
	sticky map[uint32]int    // load balancing: pid -> proxy id

	conns  sync.Map
	nextID atomic.Int64

	Active, Total, Failed, Sent, Recv atomic.Int64
	Verbose                           bool
}

// New prepares an engine for the given profile.
func New(p *profile.Profile) (*Engine, error) {
	p.Normalize()
	if err := p.Validate(); err != nil {
		return nil, err
	}
	e := &Engine{prof: p, match: rules.Compile(p), failed: map[int]time.Time{}, sticky: map[uint32]int{}, selfPID: map[uint32]bool{}}
	e.bind.Store(&netif.Binding{})
	e.dial = netif.Dialer(func() netif.Binding { return *e.bind.Load() })
	// Infinite connection loop detection: a proxy running on this machine
	// must never have its own connections proxified.
	if p.Options.ConnectionLoopDetection {
		for _, x := range p.Proxies {
			if ip, err := netip.ParseAddr(x.Address); (err == nil && ip.IsLoopback()) || x.Address == "localhost" {
				if pid, ok := procinfo.ListenerPID(uint16(x.Port)); ok {
					e.selfPID[pid] = true
					log.Printf("loop detection: %s (pid %d) serves proxy %s and will connect directly", procinfo.ByPID(pid).Name, pid, x.HostPort())
				}
			}
		}
	}
	return e, nil
}

func (e *Engine) resolverConfig(viaProxy bool, upstreams []string) dns.Config {
	r := e.prof.Options.Resolve
	return dns.Config{ViaProxy: viaProxy, BlockNonA: r.BlockNonA, List: rules.CompileHostList(r.ExclusionList), OnlyFromList: r.OnlyFromList, Upstreams: upstreams}
}

// StartTUN captures the whole system through a virtual network interface.
func (e *Engine) StartTUN() error {
	phys, err := netif.Default(0)
	if err != nil {
		return err
	}
	e.bind.Store(&phys)
	upstreams := netif.SystemDNS(phys.Index)
	if len(upstreams) == 0 {
		upstreams = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	e.res = dns.NewResolver(dns.NewFakeIP(tun.FakeIPPrefix), dns.Dialer(e.dial), e.resolverConfig(false, upstreams))
	via := e.prof.Options.Resolve.ViaProxy
	if e.prof.Options.Resolve.AutoDetect {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		via = !e.res.Probe(ctx)
		cancel()
	}
	if e.prof.Options.LeakPrevention {
		via = true
	}
	e.res.SetConfig(e.resolverConfig(via, upstreams))
	log.Printf("physical interface: %s (#%d), DNS %v, resolve through proxy: %v", phys.Name, phys.Index, upstreams, via)

	cfg := tun.DefaultNetConfig()
	for _, u := range upstreams {
		if ap, err := netip.ParseAddrPort(u); err == nil {
			cfg.HostRoutes = append(cfg.HostRoutes, ap.Addr())
		}
	}
	if e.stack, err = tun.NewStack(cfg.MTU, e); err != nil {
		return err
	}
	if e.dev, err = tun.OpenDevice(cfg); err != nil {
		e.stack.Close()
		return err
	}
	e.dev.Run(e.stack)
	go func() { // follow default-route changes (Wi-Fi <-> Ethernet)
		for e.dev != nil {
			time.Sleep(5 * time.Second)
			if b, err := netif.Default(e.dev.Index()); err == nil && b.Index != e.bind.Load().Index {
				e.bind.Store(&b)
				log.Printf("physical interface changed to %s", b.Name)
			}
		}
	}()
	log.Printf("tunnel is up: all TCP traffic is now processed by the rules")
	return nil
}

// Stop tears everything down and restores normal routing.
func (e *Engine) Stop() {
	if e.gateway != nil {
		e.gateway.Close()
	}
	if d := e.dev; d != nil {
		e.dev = nil
		d.Close()
	}
	if e.stack != nil {
		e.stack.Close()
	}
}

// ---- flow handling -------------------------------------------------------

type flow struct {
	proc     procinfo.Info
	host     string // hostname if known
	ip       netip.Addr
	port     uint16
	fakeOnly bool // ip is a fake address: only the hostname is meaningful
}

func (f *flow) target() string {
	h := f.host
	if h == "" {
		h = f.ip.String()
	}
	return net.JoinHostPort(h, strconv.Itoa(int(f.port)))
}

// HandleTCP implements tun.Handler.
func (e *Engine) HandleTCP(r tun.TCPRequest) {
	f := flow{ip: r.Dst.Addr(), port: r.Dst.Port()}
	f.proc, _ = procinfo.Lookup("tcp", r.Src, r.Dst)
	if h, fake := e.res.HostFor(f.ip); h != "" {
		f.host, f.fakeOnly = h, fake
	}
	up, label, rule, err := e.connect(context.Background(), &f)
	if err != nil {
		r.Reject()
		return
	}
	c, err := r.Accept()
	if err != nil {
		up.Close()
		return
	}
	e.relay(c, up, &f, label, rule)
}

// HandleUDP implements tun.Handler: DNS is answered by the resolver, other
// UDP is bypassed or blocked according to the profile.
func (e *Engine) HandleUDP(r tun.UDPRequest) {
	c, err := r.Accept()
	if err != nil {
		return
	}
	defer c.Close()
	buf := make([]byte, 65535)
	if r.Dst.Port() == 53 {
		for {
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			if resp := e.res.Handle(context.Background(), buf[:n]); resp != nil {
				c.Write(resp)
			}
		}
	}
	f := flow{ip: r.Dst.Addr(), port: r.Dst.Port()}
	f.proc, _ = procinfo.Lookup("udp", r.Src, r.Dst)
	if h, fake := e.res.HostFor(f.ip); h != "" {
		f.host, f.fakeOnly = h, fake
	}
	_, rule := e.matchRule(&f)
	proxied := rule.Action.Type == profile.ActProxy || rule.Action.Type == profile.ActChain
	mode := e.prof.Options.UDPMode
	if rule.Action.Type == profile.ActBlock || e.prof.Options.LeakPrevention && proxied ||
		proxied && (mode == profile.UDPBlockAll || mode == profile.UDPBlock443 && f.port == 443) {
		return // dropped: QUIC clients fall back to TCP
	}
	dst := r.Dst.Addr()
	if f.fakeOnly {
		ips, err := e.res.LookupIP(context.Background(), f.host)
		if err != nil {
			return
		}
		dst = ips[0]
	}
	up, err := e.dial(context.Background(), "udp", netip.AddrPortFrom(dst, f.port).String())
	if err != nil {
		return
	}
	defer up.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			up.SetReadDeadline(time.Now().Add(90 * time.Second))
			n, err := up.Read(b)
			if err != nil {
				c.Close()
				return
			}
			c.Write(b[:n])
		}
	}()
	for {
		c.SetReadDeadline(time.Now().Add(90 * time.Second))
		n, err := c.Read(buf)
		if err != nil {
			return
		}
		up.Write(buf[:n])
	}
}

func (e *Engine) matchRule(f *flow) (int, *profile.Rule) {
	o := &e.prof.Options
	last := len(e.prof.Rules) - 1
	direct := &profile.Rule{Name: "(bypass)", Action: profile.Action{Type: profile.ActDirect}}
	if e.selfPID[f.proc.PID] || (f.proc.OtherUser && !o.ProcessOtherUsers) || (f.proc.Service && !o.ProcessServices) {
		return -1, direct
	}
	q := rules.Query{AppName: f.proc.Name, AppPath: f.proc.Path, Host: f.host, Port: f.port}
	if !f.fakeOnly {
		q.IP = f.ip
	}
	i, r := e.match.Match(q, func(r *profile.Rule) bool {
		if r.Interface == "" || !r.IfDownIgnore {
			return false
		}
		ifc, ok := netif.ByName(r.Interface)
		return !ok || !ifc.Up
	})
	if r == nil {
		return last, &e.prof.Rules[last]
	}
	return i, r
}

// connect applies the rules to a flow and opens the upstream connection.
func (e *Engine) connect(ctx context.Context, f *flow) (net.Conn, string, *profile.Rule, error) {
	_, rule := e.matchRule(f)
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	var c net.Conn
	var err error
	label := "directly"
	switch rule.Action.Type {
	case profile.ActBlock:
		log.Printf("%s - %s blocked by rule %q", f.proc.Name, f.target(), rule.Name)
		return nil, "", rule, errors.New("blocked")
	case profile.ActProxy:
		px := e.prof.ProxyByID(rule.Action.ID)
		label = "through proxy " + px.HostPort() + " " + px.Type
		c, err = e.viaChain(ctx, []*profile.Proxy{px}, f)
	case profile.ActChain:
		ch := e.prof.ChainByID(rule.Action.ID)
		label = "through chain " + ch.Name
		c, err = e.viaChainDef(ctx, ch, f)
	default:
		c, err = e.direct(ctx, rule, f)
	}
	if err != nil {
		e.Failed.Add(1)
		log.Printf("%s - %s error: %v (rule %q)", f.proc.Name, f.target(), err, rule.Name)
		return nil, "", rule, err
	}
	if rule.Action.Type != profile.ActDirect || e.prof.Options.HandleDirectConnections || e.Verbose {
		log.Printf("%s - %s open %s (rule %q)", f.proc.Name, f.target(), label, rule.Name)
	}
	return c, label, rule, nil
}

func (e *Engine) direct(ctx context.Context, rule *profile.Rule, f *flow) (net.Conn, error) {
	dial := e.dial
	if rule.Interface != "" {
		if ifc, ok := netif.ByName(rule.Interface); ok && ifc.Up {
			dial = netif.Dialer(func() netif.Binding { return netif.Binding{Index: ifc.Index, Name: ifc.Name} })
		}
	}
	if f.fakeOnly || !f.ip.IsValid() {
		if e.res == nil { // gateway mode: let the OS resolve
			return dial(ctx, "tcp", f.target())
		}
		ips, err := e.res.LookupIP(ctx, f.host)
		if err != nil {
			return nil, err
		}
		f.ip = ips[0]
	}
	return dial(ctx, "tcp", netip.AddrPortFrom(f.ip, f.port).String())
}

func (e *Engine) viaChain(ctx context.Context, chain []*profile.Proxy, f *flow) (net.Conn, error) {
	last := chain[len(chain)-1]
	host := f.ip.String()
	if f.host != "" && (f.fakeOnly || last.UseHostname || !f.ip.IsValid()) {
		host = f.host
	}
	return proxy.DialChain(ctx, e.dial, chain, host, f.port)
}

func (e *Engine) viaChainDef(ctx context.Context, ch *profile.Chain, f *flow) (net.Conn, error) {
	var list []*profile.Proxy
	for _, it := range ch.Proxies {
		if px := e.prof.ProxyByID(it.ID); px != nil && it.Enabled {
			list = append(list, px)
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("chain %q has no enabled proxies", ch.Name)
	}
	switch ch.Type {
	case profile.ChainLoadBalance:
		px := list[rand.IntN(len(list))]
		if ch.StickyPID && f.proc.PID != 0 {
			e.mu.Lock()
			if id, ok := e.sticky[f.proc.PID]; ok && e.prof.ProxyByID(id) != nil {
				px = e.prof.ProxyByID(id)
			} else {
				e.sticky[f.proc.PID] = px.ID
			}
			e.mu.Unlock()
		}
		return e.viaChain(ctx, []*profile.Proxy{px}, f)
	case profile.ChainRedundancy:
		var lastErr error
		for _, px := range list {
			e.mu.Lock()
			t, bad := e.failed[px.ID]
			e.mu.Unlock()
			if bad && (ch.RecheckSec == 0 || time.Since(t) < time.Duration(ch.RecheckSec)*time.Second) {
				continue
			}
			cctx, cancel := context.WithTimeout(ctx, time.Duration(ch.TimeoutSec)*time.Second)
			c, err := e.viaChain(cctx, []*profile.Proxy{px}, f)
			cancel()
			e.mu.Lock()
			if err == nil {
				delete(e.failed, px.ID)
				e.mu.Unlock()
				return c, nil
			}
			e.failed[px.ID] = time.Now()
			e.mu.Unlock()
			lastErr = err
		}
		if ch.TryDirect {
			return e.direct(ctx, &profile.Rule{}, f)
		}
		if lastErr == nil {
			lastErr = errors.New("all proxies in the chain are marked as failed")
		}
		return nil, lastErr
	}
	return e.viaChain(ctx, list, f)
}

// ConnInfo is a live connection as shown in the connections list.
type ConnInfo struct {
	ID         int64
	App        string
	PID        uint32
	Target     string
	Rule, Via  string
	Start      time.Time
	Sent, Recv atomic.Int64
	Closed     atomic.Bool
	app, up    net.Conn
}

// Disconnect closes the connection.
func (c *ConnInfo) Disconnect() {
	c.app.Close()
	c.up.Close()
}

// Conns returns a snapshot of the displayed connections.
func (e *Engine) Conns() []*ConnInfo {
	var out []*ConnInfo
	e.conns.Range(func(_, v any) bool {
		out = append(out, v.(*ConnInfo))
		return true
	})
	return out
}

type counter struct {
	io.Writer
	n, total *atomic.Int64
}

func (c counter) Write(p []byte) (int, error) {
	n, err := c.Writer.Write(p)
	c.n.Add(int64(n))
	c.total.Add(int64(n))
	return n, err
}

func (e *Engine) relay(app, up net.Conn, f *flow, label string, rule *profile.Rule) {
	e.Active.Add(1)
	e.Total.Add(1)
	ci := &ConnInfo{ID: e.nextID.Add(1), App: f.proc.Name, PID: f.proc.PID, Target: f.target(), Rule: rule.Name, Via: label, Start: time.Now(), app: app, up: up}
	shown := rule.Action.Type != profile.ActDirect || e.prof.Options.HandleDirectConnections
	if shown {
		e.conns.Store(ci.ID, ci)
	}
	done := make(chan struct{})
	go func() {
		io.Copy(counter{app, &ci.Recv, &e.Recv}, up)
		if cw, ok := app.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(done)
	}()
	io.Copy(counter{up, &ci.Sent, &e.Sent}, app)
	if cw, ok := up.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	} else {
		up.Close()
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
	}
	app.Close()
	up.Close()
	<-done
	e.Active.Add(-1)
	ci.Closed.Store(true)
	time.AfterFunc(3*time.Second, func() { e.conns.Delete(ci.ID) })
	if e.Verbose {
		log.Printf("%s - %s close, %d bytes sent, %d bytes received, lifetime %s", ci.App, ci.Target, ci.Sent.Load(), ci.Recv.Load(), time.Since(ci.Start).Round(time.Second))
	}
}
