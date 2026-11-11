package tun

import (
	"embed"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
	wgtun "golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// The Wintun driver DLL (https://www.wintun.net, signed by WireGuard LLC) may
// be embedded at build time by placing it in internal/tun/embedded/ as
// wintun_<GOARCH>.dll. Otherwise it must sit next to the executable.
//
//go:embed all:embedded
var embedded embed.FS

func exeDir() string {
	p, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(p)
}

// Elevated reports whether the process has administrator rights.
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// EnsureDriver makes sure wintun.dll can be loaded, extracting the embedded
// copy next to the executable when necessary.
func EnsureDriver() error {
	dst := filepath.Join(exeDir(), "wintun.dll")
	if _, err := os.Stat(dst); err == nil {
		return nil
	}
	if sys, err := windows.GetSystemDirectory(); err == nil {
		if _, err := os.Stat(filepath.Join(sys, "wintun.dll")); err == nil {
			return nil
		}
	}
	b, err := embedded.ReadFile("embedded/wintun_" + runtime.GOARCH + ".dll")
	if err != nil {
		return errors.New("wintun.dll was not found next to the executable. Download Wintun from https://www.wintun.net and place wintun.dll (" + runtime.GOARCH + ") beside shunt.exe")
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		return fmt.Errorf("cannot extract wintun.dll to %s: %w", dst, err)
	}
	return nil
}

// Available reports whether TUN capture can be started right now.
func Available() (bool, string) {
	if !Elevated() {
		return false, "Administrator rights are required to create the tunnel interface."
	}
	if err := EnsureDriver(); err != nil {
		return false, err.Error()
	}
	return true, ""
}

// OpenDevice creates the Wintun adapter and routes all traffic into it.
func OpenDevice(cfg NetConfig) (*Device, error) {
	if ok, why := Available(); !ok {
		return nil, errors.New(why)
	}
	guid, _ := windows.GUIDFromString("{5348554E-5400-4C4F-8A01-53484E540001}")
	wgtun.WintunTunnelType = "Shunt"
	dev, err := wgtun.CreateTUNWithRequestedGUID(cfg.Name, &guid, cfg.MTU)
	if err != nil {
		return nil, fmt.Errorf("create Wintun adapter: %w", err)
	}
	d := &Device{dev: dev, cfg: cfg}
	luid := winipcfg.LUID(dev.(*wgtun.NativeTun).LUID())
	fail := func(what string, err error) (*Device, error) {
		d.Close()
		return nil, fmt.Errorf("%s: %w", what, err)
	}

	// Interface parameters first, so the address is usable immediately (no
	// duplicate address detection delay) and the tunnel wins DNS ordering.
	setIf := func(family winipcfg.AddressFamily) {
		ipif, err := luid.IPInterface(family)
		if err != nil {
			return
		}
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		ipif.NLMTU = uint32(cfg.MTU)
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		if err := ipif.Set(); err != nil {
			log.Printf("tun: set interface parameters (family %d): %v", family, err)
		}
		if family == windows.AF_INET {
			d.index = int(ipif.InterfaceIndex)
		}
	}
	setIf(windows.AF_INET)

	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{cfg.Addr4}); err != nil {
		return fail("set IPv4 address", err)
	}
	capture := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}
	if cfg.Routes != nil {
		capture = cfg.Routes
	}
	for _, h := range cfg.HostRoutes {
		if h.Is4() && !cfg.Addr4.Contains(h) {
			capture = append(capture, netip.PrefixFrom(h, 32))
		}
	}
	// Routes are added one by one. luid.SetRoutesForFamily is NOT used: it
	// first flushes every route on the interface, including the local and
	// broadcast routes Windows creates for the address, and deleting those
	// fails with ERROR_NOT_FOUND ("Element not found").
	if err := addRoutes(luid, capture, netip.IPv4Unspecified()); err != nil {
		return fail("add IPv4 routes", err)
	}
	if cfg.DNS4.IsValid() {
		if err := luid.SetDNS(windows.AF_INET, []netip.Addr{cfg.DNS4}, nil); err != nil {
			return fail("set DNS", err)
		}
	}
	if d.index == 0 {
		setIf(windows.AF_INET)
	}

	// IPv6 is captured as well so that it cannot leak around the tunnel.
	// Failures here are not fatal (IPv6 may be disabled on the machine).
	if cfg.Addr6.IsValid() {
		setIf(windows.AF_INET6)
		if err := luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{cfg.Addr6}); err != nil {
			log.Printf("tun: IPv6 address not set (%v); IPv6 is not captured", err)
		} else {
			routes6 := []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")}
			for _, h := range cfg.HostRoutes {
				if h.Is6() {
					routes6 = append(routes6, netip.PrefixFrom(h, 128))
				}
			}
			if err := addRoutes(luid, routes6, netip.IPv6Unspecified()); err != nil {
				log.Printf("tun: IPv6 routes not added (%v); IPv6 is not captured", err)
			}
		}
	}
	log.Printf("tun: adapter %q up, interface index %d, routes %v", cfg.Name, d.index, capture)
	// Routes and addresses vanish together with the adapter on Close.
	return d, nil
}

// addRoutes adds on-link routes through the tunnel. A freshly created
// interface can briefly report ERROR_NOT_FOUND, so that error is retried.
func addRoutes(luid winipcfg.LUID, dsts []netip.Prefix, nextHop netip.Addr) error {
	for _, dst := range dsts {
		var err error
		for try := 0; try < 30; try++ {
			err = luid.AddRoute(dst.Masked(), nextHop, 0)
			if err == nil || errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
				err = nil
				break
			}
			if !errors.Is(err, windows.ERROR_NOT_FOUND) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			return fmt.Errorf("route %s: %w", dst, err)
		}
	}
	return nil
}
