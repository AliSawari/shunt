package tun

import (
	"embed"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"

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

	if err := luid.SetIPAddressesForFamily(windows.AF_INET, []netip.Prefix{cfg.Addr4}); err != nil {
		return fail("set IPv4 address", err)
	}
	routes4 := []*winipcfg.RouteData{
		{Destination: netip.MustParsePrefix("0.0.0.0/1"), NextHop: netip.IPv4Unspecified(), Metric: 0},
		{Destination: netip.MustParsePrefix("128.0.0.0/1"), NextHop: netip.IPv4Unspecified(), Metric: 0},
	}
	for _, h := range cfg.HostRoutes {
		if h.Is4() && !cfg.Addr4.Contains(h) {
			routes4 = append(routes4, &winipcfg.RouteData{Destination: netip.PrefixFrom(h, 32), NextHop: netip.IPv4Unspecified(), Metric: 0})
		}
	}
	if err := luid.SetRoutesForFamily(windows.AF_INET, routes4); err != nil {
		return fail("set IPv4 routes", err)
	}
	if cfg.DNS4.IsValid() {
		if err := luid.SetDNS(windows.AF_INET, []netip.Addr{cfg.DNS4}, nil); err != nil {
			return fail("set DNS", err)
		}
	}
	if ipif, err := luid.IPInterface(windows.AF_INET); err == nil {
		ipif.UseAutomaticMetric = false
		ipif.Metric = 1
		ipif.NLMTU = uint32(cfg.MTU)
		ipif.DadTransmits = 0
		ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
		ipif.Set()
		d.index = int(ipif.InterfaceIndex)
	}

	// IPv6 is captured as well so that it cannot leak around the tunnel.
	if cfg.Addr6.IsValid() {
		if err := luid.SetIPAddressesForFamily(windows.AF_INET6, []netip.Prefix{cfg.Addr6}); err == nil {
			routes6 := []*winipcfg.RouteData{
				{Destination: netip.MustParsePrefix("::/1"), NextHop: netip.IPv6Unspecified(), Metric: 0},
				{Destination: netip.MustParsePrefix("8000::/1"), NextHop: netip.IPv6Unspecified(), Metric: 0},
			}
			for _, h := range cfg.HostRoutes {
				if h.Is6() {
					routes6 = append(routes6, &winipcfg.RouteData{Destination: netip.PrefixFrom(h, 128), NextHop: netip.IPv6Unspecified(), Metric: 0})
				}
			}
			luid.SetRoutesForFamily(windows.AF_INET6, routes6)
			if ipif, err := luid.IPInterface(windows.AF_INET6); err == nil {
				ipif.UseAutomaticMetric = false
				ipif.Metric = 1
				ipif.NLMTU = uint32(cfg.MTU)
				ipif.DadTransmits = 0
				ipif.RouterDiscoveryBehavior = winipcfg.RouterDiscoveryDisabled
				ipif.Set()
			}
		}
	}
	// Routes and addresses vanish together with the adapter on Close.
	return d, nil
}
