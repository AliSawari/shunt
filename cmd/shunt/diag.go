package main

import (
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"shunt/internal/core"
	"shunt/internal/profile"
	"shunt/internal/tun"
)

// diag brings the real tunnel up for a few destinations only, logs every
// step, and tears it down again. The rest of the system is not affected:
// no default routes and no DNS changes are made.
//
// Rules used: 1.1.1.1 -> Direct (checks that Shunt's own bound sockets
// escape the tunnel), everything else routed in -> the given proxy.
func diag(pxURL, scope string, secs int, logPath string) {
	if logPath == "" {
		logPath = filepath.Join(configDir(), "diag.log")
	}
	os.MkdirAll(filepath.Dir(logPath), 0o755)
	if f, err := os.Create(logPath); err == nil {
		defer f.Close()
		log.SetOutput(io.MultiWriter(os.Stderr, f))
	}
	log.SetFlags(log.Ltime | log.Lmicroseconds)
	exe, _ := os.Executable()
	_, dllErr := os.Stat(filepath.Join(filepath.Dir(exe), "wintun.dll"))
	log.Printf("diag: exe=%s elevated=%v wintun.dll beside exe: %v", exe, tun.Elevated(), dllErr == nil)

	px, err := parseProxyURL(pxURL)
	if err != nil {
		log.Fatalf("diag: %v", err)
	}
	var routes []netip.Prefix
	for _, s := range strings.Split(scope, ",") {
		if p, err := netip.ParsePrefix(strings.TrimSpace(s)); err == nil {
			routes = append(routes, p)
		}
	}
	p := profile.Default()
	p.Proxies = []profile.Proxy{*px}
	n := len(p.Rules)
	p.Rules = append(p.Rules[:n-1], profile.Rule{Name: "Diag direct", Enabled: true, Targets: "1.1.1.1", Action: profile.Action{Type: profile.ActDirect}}, p.Rules[n-1])
	p.Rules[len(p.Rules)-1].Action = profile.Action{Type: profile.ActProxy, ID: px.ID}

	e, err := core.New(p)
	if err != nil {
		log.Fatalf("diag: engine: %v", err)
	}
	e.Verbose = true
	if err := e.StartScoped(routes); err != nil {
		log.Fatalf("diag: start FAILED: %v", err)
	}
	log.Printf("diag: tunnel up for %v, waiting %ds", routes, secs)
	time.Sleep(time.Duration(secs) * time.Second)
	log.Printf("diag: stats total=%d failed=%d sent=%d recv=%d", e.Total.Load(), e.Failed.Load(), e.Sent.Load(), e.Recv.Load())
	e.Stop()
	log.Printf("diag: stopped, adapter removed")
}
