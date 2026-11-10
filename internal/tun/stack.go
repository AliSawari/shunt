// Package tun turns raw IP packets captured from a TUN device into ordinary
// Go connections using a userspace TCP/IP stack (gVisor netstack).
package tun

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// TCPRequest is an incoming TCP connection attempt (a SYN). The handler must
// call exactly one of Accept or Reject.
type TCPRequest struct {
	Src, Dst netip.AddrPort
	// Accept completes the handshake and returns the application side stream.
	Accept func() (net.Conn, error)
	// Reject answers with a TCP reset, i.e. "connection refused".
	Reject func()
}

// UDPRequest is the first datagram of a new UDP flow.
type UDPRequest struct {
	Src, Dst netip.AddrPort
	// Accept returns a connected datagram socket for the flow.
	Accept func() (net.Conn, error)
}

// Handler receives captured flows. Calls are made on fresh goroutines.
type Handler interface {
	HandleTCP(TCPRequest)
	HandleUDP(UDPRequest)
}

const nicID = 1

// Stack is a userspace network stack that accepts every flow sent to it.
type Stack struct {
	s      *stack.Stack
	ep     *channel.Endpoint
	mtu    int
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
}

func addrPort(a tcpip.Address, port uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), port)
}

// NewStack creates the stack. Packets are exchanged with InjectInbound and
// ReadOutbound.
func NewStack(mtu int, h Handler) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        false,
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errors.New("create NIC: " + err.String())
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, errors.New("promiscuous mode: " + err.String())
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, errors.New("spoofing: " + err.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4 << 10, Default: 1 << 20, Max: 8 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	ctx, cancel := context.WithCancel(context.Background())
	st := &Stack{s: s, ep: ep, mtu: mtu, ctx: ctx, cancel: cancel}

	tf := tcp.NewForwarder(s, 0, 4096, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var done sync.Once
		req := TCPRequest{
			Src: addrPort(id.RemoteAddress, id.RemotePort),
			Dst: addrPort(id.LocalAddress, id.LocalPort),
		}
		req.Accept = func() (c net.Conn, err error) {
			err = errors.New("request already completed")
			done.Do(func() {
				var wq waiter.Queue
				ep, terr := r.CreateEndpoint(&wq)
				if terr != nil {
					r.Complete(true)
					err = errors.New(terr.String())
					return
				}
				r.Complete(false)
				ep.SocketOptions().SetKeepAlive(true)
				c, err = gonet.NewTCPConn(&wq, ep), nil
			})
			return
		}
		req.Reject = func() { done.Do(func() { r.Complete(true) }) }
		go h.HandleTCP(req)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tf.HandlePacket)

	uf := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
		id := r.ID()
		req := UDPRequest{
			Src: addrPort(id.RemoteAddress, id.RemotePort),
			Dst: addrPort(id.LocalAddress, id.LocalPort),
		}
		// The endpoint must be created synchronously so that the first
		// datagram is delivered to it.
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			return
		}
		conn := gonet.NewUDPConn(&wq, ep)
		req.Accept = func() (net.Conn, error) { return conn, nil }
		go h.HandleUDP(req)
	})
	s.SetTransportProtocolHandler(udp.ProtocolNumber, uf.HandlePacket)
	return st, nil
}

// MTU returns the configured MTU.
func (st *Stack) MTU() int { return st.mtu }

// InjectInbound feeds one IP packet received from the operating system. The
// slice is copied.
func (st *Stack) InjectInbound(pkt []byte) {
	if len(pkt) == 0 {
		return
	}
	var proto tcpip.NetworkProtocolNumber
	switch pkt[0] >> 4 {
	case 4:
		proto = header.IPv4ProtocolNumber
	case 6:
		proto = header.IPv6ProtocolNumber
	default:
		return
	}
	pb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(append([]byte(nil), pkt...))})
	st.ep.InjectInbound(proto, pb)
	pb.DecRef()
}

// ReadOutbound blocks for the next IP packet the stack wants to deliver to
// the operating system and appends it to buf[:0]... returning the packet.
// It returns false once the stack is closed.
func (st *Stack) ReadOutbound(buf []byte) ([]byte, bool) {
	pb := st.ep.ReadContext(st.ctx)
	if pb == nil {
		return nil, false
	}
	out := buf[:0]
	for _, s := range pb.AsSlices() {
		out = append(out, s...)
	}
	pb.DecRef()
	return out, true
}

// Close shuts the stack down.
func (st *Stack) Close() {
	st.once.Do(func() {
		st.cancel()
		st.ep.Close()
		st.s.Close()
	})
}

// DialTCP opens a TCP connection originating inside the stack. It exists
// for tests, where a second stack plays the role of the operating system.
func (st *Stack) DialTCP(ctx context.Context, local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if remote.Addr().Is6() {
		proto = header.IPv6ProtocolNumber
	}
	return gonet.DialTCPWithBind(ctx, st.s,
		tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(local.AsSlice())},
		tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(remote.Addr().AsSlice()), Port: remote.Port()}, proto)
}

// DialUDP opens a UDP socket originating inside the stack (tests only).
func (st *Stack) DialUDP(local netip.Addr, remote netip.AddrPort) (net.Conn, error) {
	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if remote.Addr().Is6() {
		proto = header.IPv6ProtocolNumber
	}
	return gonet.DialUDP(st.s,
		&tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(local.AsSlice())},
		&tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(remote.Addr().AsSlice()), Port: remote.Port()}, proto)
}

// AddAddress assigns a local address to the stack (tests only; the engine
// stack runs in promiscuous mode and needs none).
func (st *Stack) AddAddress(a netip.Addr) error {
	proto := tcpip.NetworkProtocolNumber(header.IPv4ProtocolNumber)
	if a.Is6() {
		proto = header.IPv6ProtocolNumber
	}
	err := st.s.AddProtocolAddress(nicID, tcpip.ProtocolAddress{Protocol: proto, AddressWithPrefix: tcpip.AddrFromSlice(a.AsSlice()).WithPrefix()}, stack.AddressProperties{})
	if err != nil {
		return errors.New(err.String())
	}
	return nil
}

// NewClientStack creates a plain (non-intercepting) stack, used by tests to
// emulate the operating system side of the tunnel.
func NewClientStack(mtu int) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	ep := channel.New(1024, uint32(mtu), "")
	if err := s.CreateNIC(nicID, ep); err != nil {
		return nil, errors.New(err.String())
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})
	ctx, cancel := context.WithCancel(context.Background())
	return &Stack{s: s, ep: ep, mtu: mtu, ctx: ctx, cancel: cancel}, nil
}

// Pipe connects two stacks back to back until either is closed.
func Pipe(a, b *Stack) {
	pump := func(from, to *Stack) {
		buf := make([]byte, 0, 65536)
		for {
			pkt, ok := from.ReadOutbound(buf)
			if !ok {
				return
			}
			to.InjectInbound(pkt)
		}
	}
	go pump(a, b)
	go pump(b, a)
}
