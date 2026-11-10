package tun

import (
	"net/netip"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// NetConfig describes how the TUN interface is configured.
type NetConfig struct {
	Name  string
	MTU   int
	Addr4 netip.Prefix // interface address, e.g. 198.18.0.1/15
	Addr6 netip.Prefix // optional
	DNS4  netip.Addr   // DNS server advertised on the interface
	// HostRoutes are extra destinations forced through the tunnel (the
	// system's own DNS servers, so that their queries are captured too).
	HostRoutes []netip.Addr
}

// DefaultNetConfig returns the standard Shunt tunnel configuration.
func DefaultNetConfig() NetConfig {
	return NetConfig{
		Name:  "Shunt",
		MTU:   1500,
		Addr4: netip.MustParsePrefix("198.18.0.1/15"),
		Addr6: netip.MustParsePrefix("fdfe:dcba:9876::1/126"),
		DNS4:  netip.MustParseAddr("198.18.0.2"),
	}
}

// FakeIPPrefix is the range fake DNS answers are taken from. It lies inside
// the tunnel's on-link subnet so those addresses always route to the tunnel.
var FakeIPPrefix = netip.MustParsePrefix("198.18.0.0/15")

// Device is an open, configured TUN interface.
type Device struct {
	dev     wgtun.Device
	cfg     NetConfig
	index   int
	cleanup []func()
	once    sync.Once
}

// Index returns the OS interface index of the tunnel.
func (d *Device) Index() int { return d.index }

const pktOffset = 16

// Run pumps packets between the device and the stack until either closes.
func (d *Device) Run(st *Stack) {
	go func() { // OS -> stack
		batch := d.dev.BatchSize()
		bufs := make([][]byte, batch)
		sizes := make([]int, batch)
		for i := range bufs {
			bufs[i] = make([]byte, 65535+pktOffset)
		}
		for {
			n, err := d.dev.Read(bufs, sizes, pktOffset)
			for i := 0; i < n; i++ {
				st.InjectInbound(bufs[i][pktOffset : pktOffset+sizes[i]])
			}
			if err != nil {
				return
			}
		}
	}()
	go func() { // stack -> OS
		buf := make([]byte, pktOffset, 65535+pktOffset)
		one := make([][]byte, 1)
		for {
			pkt, ok := st.ReadOutbound(buf[pktOffset:])
			if !ok {
				return
			}
			one[0] = buf[:pktOffset+len(pkt)]
			if _, err := d.dev.Write(one, pktOffset); err != nil {
				return
			}
		}
	}()
}

// Close removes routes and destroys the interface.
func (d *Device) Close() {
	d.once.Do(func() {
		for i := len(d.cleanup) - 1; i >= 0; i-- {
			d.cleanup[i]()
		}
		d.dev.Close()
	})
}
