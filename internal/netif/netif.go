// Package netif deals with physical network interfaces: listing them,
// finding the default one, and binding outbound sockets to it so that
// Shunt's own traffic never loops back into the tunnel.
package netif

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// Iface is a network interface as shown in the rule editor.
type Iface struct {
	Name  string   `json:"name"`
	Index int      `json:"index"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"`
}

// List returns the usable (non loopback) interfaces.
func List() []Iface {
	ifs, _ := net.Interfaces()
	var out []Iface
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		it := Iface{Name: i.Name, Index: i.Index, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			it.Addrs = append(it.Addrs, strings.SplitN(a.String(), "/", 2)[0])
		}
		out = append(out, it)
	}
	return out
}

// ByName finds an interface by name.
func ByName(name string) (Iface, bool) {
	for _, i := range List() {
		if strings.EqualFold(i.Name, name) {
			return i, true
		}
	}
	return Iface{}, false
}

// Binding identifies the interface outbound sockets are pinned to. The zero
// value means "no pinning" (plain OS routing).
type Binding struct {
	Index int
	Name  string
}

// Dialer returns a dial function whose sockets are bound to b. Connections
// to loopback addresses are never bound.
func Dialer(get func() Binding) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		d := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
		b := get()
		if b.Index != 0 && !isLoopbackAddr(addr) {
			d.Control = func(network, address string, c syscall.RawConn) error {
				return bindControl(b, network, c)
			}
		}
		return d.DialContext(ctx, network, addr)
	}
}

func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}
