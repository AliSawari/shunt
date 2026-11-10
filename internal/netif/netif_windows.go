package netif

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const (
	ipUnicastIF   = 31 // IP_UNICAST_IF
	ipv6UnicastIF = 31 // IPV6_UNICAST_IF
)

func bindControl(b Binding, network string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if strings.HasSuffix(network, "6") {
			serr = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIF, b.Index)
			return
		}
		// IP_UNICAST_IF takes the interface index in network byte order.
		var be [4]byte
		binary.BigEndian.PutUint32(be[:], uint32(b.Index))
		serr = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIF, int(*(*uint32)(unsafe.Pointer(&be[0]))))
	})
	if err != nil {
		return err
	}
	return serr
}

// Default returns the interface that carries the IPv4 default route,
// ignoring the interface with index exclude (the tunnel itself).
func Default(exclude int) (Binding, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return Binding{}, err
	}
	best, bestMetric := -1, uint32(0)
	for i := range routes {
		r := &routes[i]
		if r.DestinationPrefix.PrefixLength != 0 || int(r.InterfaceIndex) == exclude {
			continue
		}
		ifrow, err := r.InterfaceLUID.Interface()
		if err != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		metric := r.Metric
		if ipif, err := r.InterfaceLUID.IPInterface(windows.AF_INET); err == nil {
			metric += ipif.Metric
		}
		if best < 0 || metric < bestMetric {
			best, bestMetric = i, metric
		}
	}
	if best < 0 {
		return Binding{}, errors.New("no default route found (is the network connected?)")
	}
	idx := int(routes[best].InterfaceIndex)
	b := Binding{Index: idx}
	if ifi, err := net.InterfaceByIndex(idx); err == nil {
		b.Name = ifi.Name
	}
	return b, nil
}

// SystemDNS returns the DNS servers configured on the given interface (or on
// all interfaces when index is 0), as "ip:53" strings.
func SystemDNS(index int) []string {
	addrs, err := winipcfg.GetAdaptersAddresses(windows.AF_UNSPEC, winipcfg.GAAFlagDefault)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		if a.OperStatus != winipcfg.IfOperStatusUp || (index != 0 && int(a.IfIndex) != index) {
			continue
		}
		for d := a.FirstDNSServerAddress; d != nil; d = d.Next {
			ip := d.Address.IP()
			if ip == nil || ip.IsLoopback() || strings.HasPrefix(ip.String(), "fec0:") {
				continue
			}
			s := net.JoinHostPort(ip.String(), "53")
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	return out
}
