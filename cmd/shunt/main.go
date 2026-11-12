// Shunt - a free and open source system-wide proxifier.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"

	"shunt/internal/core"
	"shunt/internal/netif"
	"shunt/internal/profile"
	"shunt/internal/proxy"
)

const version = "0.2.0"

func configDir() string {
	d, _ := os.UserConfigDir()
	return filepath.Join(d, "Shunt")
}

func defaultProfile() string { return filepath.Join(configDir(), "Default"+profile.Ext) }

func usage() {
	fmt.Print(`Shunt ` + version + ` - open source system-wide proxifier

Usage:
  shunt run    [-profile FILE] [-v] [-notray]   start the tunnel (run as Administrator)
  shunt init   [-proxy socks5://127.0.0.1:1080] create a profile sending everything to a proxy
  shunt import FILE.ppx [-o FILE]               convert a Proxifier profile to a Shunt profile
  shunt export FILE.ppx [-profile FILE]         export the profile in Proxifier format
  shunt check  URL [-target host:port]          test a proxy (socks5://, socks4://, https://, http://)
  shunt show   [-profile FILE]                  print proxies and rules

The default profile is ` + defaultProfile() + `
A profile may be a Shunt JSON file or a Proxifier .ppx file.
`)
}

func parseProxyURL(s string) (*profile.Proxy, error) {
	if !strings.Contains(s, "://") {
		s = "socks5://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	port, _ := strconv.Atoi(u.Port())
	px := &profile.Proxy{ID: 100, Address: u.Hostname(), Port: port, UseHostname: true}
	switch strings.ToLower(u.Scheme) {
	case "socks5", "socks5h", "socks":
		px.Type = profile.SOCKS5
	case "socks4":
		px.Type = profile.SOCKS4
	case "socks4a":
		px.Type, px.Socks4A = profile.SOCKS4, true
	case "https", "connect":
		px.Type = profile.HTTPS
	case "http":
		px.Type = profile.HTTP
	default:
		return nil, fmt.Errorf("unknown proxy scheme %q", u.Scheme)
	}
	if u.User != nil {
		px.AuthEnabled, px.Username = true, u.User.Username()
		px.Password, _ = u.User.Password()
	}
	if px.Address == "" || port == 0 {
		return nil, fmt.Errorf("proxy URL needs host and port")
	}
	return px, nil
}

func load(path string) *profile.Profile {
	kr := &profile.Keyring{Master: os.Getenv("SHUNT_MASTER_PASSWORD")}
	p, err := profile.Load(path, kr)
	if err != nil {
		log.Fatalf("cannot load profile %s: %v\nCreate one with: shunt init -proxy socks5://127.0.0.1:1080", path, err)
	}
	return p
}

func main() {
	log.SetFlags(log.Ltime)
	if len(os.Args) < 2 || os.Args[1] == "-start" {
		gui()
		return
	}
	attachConsole()
	cmd, args := os.Args[1], os.Args[2:]
	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	prof := fs.String("profile", defaultProfile(), "profile file")
	verbose := fs.Bool("v", false, "verbose log (direct connections and closes)")
	notray := fs.Bool("notray", false, "do not show a system tray icon")
	pxURL := fs.String("proxy", "socks5://127.0.0.1:1080", "proxy URL")
	out := fs.String("o", defaultProfile(), "output file")
	target := fs.String("target", "www.google.com:80", "test target")
	scope := fs.String("route", "1.0.0.1/32,1.1.1.1/32", "diag: destinations routed into the tunnel")
	secs := fs.Int("seconds", 60, "diag: how long to keep the tunnel up")
	logPath := fs.String("log", "", "diag: log file")
	var pos []string
	for len(args) > 0 { // allow flags after positional arguments
		fs.Parse(args)
		args = fs.Args()
		if len(args) > 0 {
			pos, args = append(pos, args[0]), args[1:]
		}
	}
	kr := &profile.Keyring{Master: os.Getenv("SHUNT_MASTER_PASSWORD")}

	switch cmd {
	case "init":
		px, err := parseProxyURL(*pxURL)
		if err != nil {
			log.Fatal(err)
		}
		p := profile.Default()
		p.Options.HTTPProxySupport = px.Type == profile.HTTP
		p.Proxies = []profile.Proxy{*px}
		p.Rules[len(p.Rules)-1].Action = profile.Action{Type: profile.ActProxy, ID: px.ID}
		if err := p.Save(*out, kr); err != nil {
			log.Fatal(err)
		}
		fmt.Println("profile written to", *out)
	case "import":
		if len(pos) != 1 {
			usage()
			os.Exit(2)
		}
		p := load(pos[0])
		if err := p.Save(*out, kr); err != nil {
			log.Fatal(err)
		}
		fmt.Printf("imported %d proxies, %d chains, %d rules into %s (passwords are not imported)\n", len(p.Proxies), len(p.Chains), len(p.Rules), *out)
	case "export":
		if len(pos) != 1 {
			usage()
			os.Exit(2)
		}
		b, err := load(*prof).MarshalPPX()
		if err == nil {
			err = os.WriteFile(pos[0], b, 0o644)
		}
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("exported to", pos[0])
	case "show":
		p := load(*prof)
		for _, x := range p.Proxies {
			fmt.Printf("proxy %d: %s %s\n", x.ID, x.Type, x.HostPort())
		}
		for _, c := range p.Chains {
			fmt.Printf("chain %d: %s (%s, %d proxies)\n", c.ID, c.Name, c.Type, len(c.Proxies))
		}
		for i, r := range p.Rules {
			fmt.Printf("rule %d: [%v] %-28s apps=%q targets=%q ports=%q -> %s\n", i+1, r.Enabled, r.Name, r.Applications, r.Targets, r.Ports, p.ActionLabel(r.Action))
		}
	case "check":
		if len(pos) != 1 {
			usage()
			os.Exit(2)
		}
		px, err := parseProxyURL(pos[0])
		if err != nil {
			log.Fatal(err)
		}
		s := proxy.DefaultCheckSettings()
		if h, p, ok := strings.Cut(*target, ":"); ok {
			s.TargetHost = h
			s.TargetPort, _ = strconv.Atoi(p)
		}
		res := proxy.Check(context.Background(), netif.Dialer(func() netif.Binding { return netif.Binding{} }), px, s)
		fmt.Println(strings.Join(res.Lines, "\n"))
		if !res.OK {
			os.Exit(1)
		}
	case "diag":
		diag(*pxURL, *scope, *secs, *logPath)
	case "mkicon":
		os.WriteFile(pos[0], icon(), 0o644)
	case "run":
		run(load(*prof), *prof, *verbose, !*notray)
	default:
		usage()
	}
}

func run(p *profile.Profile, path string, verbose, tray bool) {
	os.MkdirAll(configDir(), 0o755)
	if lf, err := os.OpenFile(filepath.Join(configDir(), "shunt.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644); err == nil {
		log.SetOutput(io.MultiWriter(os.Stderr, lf))
	}
	log.Printf("Shunt %s, profile %s: %d proxies, %d chains, %d rules", version, path, len(p.Proxies), len(p.Chains), len(p.Rules))
	e, err := core.New(p)
	if err != nil {
		log.Fatal(err)
	}
	e.Verbose = verbose
	if err := e.StartTUN(); err != nil {
		log.Fatalf("cannot start: %v", err)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	quit := func() {
		log.Printf("stopping, restoring routes")
		e.Stop()
	}
	_ = tray
	<-stop
	quit()
}

func size(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.2f GB", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

// icon draws the Shunt mark (one track splitting into two) as an .ico.
func iconImage() *image.RGBA {
	const n = 64
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	seg := func(x, y, ax, ay, bx, by float64) float64 { // distance to segment
		dx, dy := bx-ax, by-ay
		t := ((x-ax)*dx + (y-ay)*dy) / (dx*dx + dy*dy)
		t = max(0, min(1, t))
		ex, ey := x-ax-t*dx, y-ay-t*dy
		return ex*ex + ey*ey
	}
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			fx, fy := float64(x)+.5, float64(y)+.5
			cx, cy := max(12-fx, fx-52, 0), max(12-fy, fy-52, 0)
			if cx*cx+cy*cy > 144 { // rounded square, radius 12
				continue
			}
			t := (fx + fy) / (2 * n)
			c := color.RGBA{uint8(79 - 60*t), uint8(70 + 110*t), uint8(229 - 10*t), 255}
			d := min(seg(fx, fy, 14, 32, 30, 32), seg(fx, fy, 30, 32, 50, 18), seg(fx, fy, 30, 32, 50, 46))
			if d < 20 {
				c = color.RGBA{255, 255, 255, 255}
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img
}

func icon() []byte {
	const n = 64
	var p bytes.Buffer
	png.Encode(&p, iconImage())
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, []uint16{0, 1, 1})
	b.Write([]byte{n, n, 0, 0})
	binary.Write(&b, binary.LittleEndian, []uint16{1, 32})
	binary.Write(&b, binary.LittleEndian, []uint32{uint32(p.Len()), 22})
	b.Write(p.Bytes())
	return b.Bytes()
}
