# Shunt

**A free and open source system-wide proxifier for Windows.** Shunt sends the
connections of every application – including ones with no proxy settings –
through a SOCKS5, SOCKS4/4A or HTTP(S) proxy, with per-application and
per-destination rules. It is a native Win32 desktop application (about 14 MB,
written in Go): no Electron, no runtime, no installer required.

> Status: **early (v0.1.0)**. The rule engine, profile import and proxy
> checker have been exercised; the tunnel itself (`shunt run`) has **not yet
> been tested end to end** – see [Status](#status).

## How it works

```
 application ──► Windows routing ──► "Shunt" virtual adapter (Wintun)
                                             │ raw IP packets
                                             ▼
                              userspace TCP/IP stack (gVisor netstack)
                                             │ connection + owning process
                                             ▼
                          rules: application / target host / port
                         ┌───────────┬───────────────┬──────────┐
                         ▼           ▼               ▼          ▼
                       Direct      Proxy        Proxy chain    Block
```

Shunt's own outbound sockets are pinned to the physical network interface, so
they never loop back into the tunnel. DNS queries are captured as well, which
lets rules match on host names and lets names be resolved by the proxy
(fake-IP answers from `198.18.0.0/15`).

## Features

| Area | What is implemented |
| --- | --- |
| Proxy protocols | SOCKS5 (user/password auth, remote DNS), SOCKS4, SOCKS4A, HTTPS (CONNECT, basic auth), plain HTTP |
| Proxy chains | Simple chain, redundancy (failover, timeout, recheck, optional direct fallback), load balancing (random, optional same-proxy-per-PID) |
| Rules | Processed top to bottom; match by application (`chrome.exe; "C:\some app.exe"; fire*.exe`), target (`*.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255; 10.0.0.0/8; %ComputerName%; %SimpleHostnames%`) and port (`80; 8000-9000`); actions Direct / Block / Proxy / Chain; optional network-interface pinning |
| Name resolution | Automatic mode (names are resolved by the proxy whenever a rule uses one, so local DNS filtering or poisoning does not matter), resolve through proxy, exclusion / only-from list, block non A/AAAA queries |
| UDP | Bypass, block UDP 443 (QUIC) for proxied rules, block all UDP for proxied rules |
| Safety | Live connection-loop detection: a proxy running on this PC is recognised even after it restarts, connects directly, and gets an "[auto-created]" Direct rule like in Proxifier, DNS/IP leak prevention mode, services / other users filtering |
| Profiles | JSON profiles, **import and export of Proxifier `.ppx` files**, passwords stored plain / static key / Windows DPAPI / master password |
| GUI | Proxifier-style window with a large Start/Stop button, status line and icon toolbar: system tray icon (left-click to open, right-click for Start/Stop and Exit; the close button asks whether to exit or minimize to tray, and can remember the choice), live connections list (application, target, time, rule : proxy, sent, received), log pane, status bar; dialogs for proxy servers, proxification rules, name resolution and advanced options; profile import/export |
| Tools | Proxy checker (reachability, connection through the proxy, latency), command line mode, log file |

## Quick start

1. Keep `wintun.dll` next to `shunt.exe`. It is the signed WireGuard TUN driver
   (Wintun 0.14.1, from <https://www.wintun.net>) Shunt uses to capture traffic;
   an unmodified copy is in `third_party/wintun/amd64/` under its own license.
2. Create a profile, or import your Proxifier one:

   ```
   shunt init -proxy socks5://127.0.0.1:1080
   shunt import "%APPDATA%\Proxifier4\Profiles\Default.ppx"
   ```
3. Test the proxy: `shunt check socks5://127.0.0.1:1080`
4. Start `shunt.exe`. Add proxies under
   **Profile > Proxy Servers**, edit **Proxification Rules**, then press
   **Start**; Shunt offers to restart as administrator when needed. The same
   engine is available headless from an Administrator terminal: `shunt run -v`.

Do not run Shunt and Proxifier at the same time – both would try to capture
the same connections.

### Commands

```
shunt run    [-profile FILE] [-v] [-notray]   start the tunnel
shunt init   [-proxy URL] [-o FILE]           create a profile sending everything to a proxy
shunt import FILE.ppx [-o FILE]               convert a Proxifier profile
shunt export FILE.ppx [-profile FILE]         export in Proxifier format
shunt check  URL [-target host:port]          test a proxy
shunt show   [-profile FILE]                  print proxies and rules
```

The default profile is `%APPDATA%\Shunt\Default.shunt.json`; the log is
`%APPDATA%\Shunt\shunt.log`. For master-password profiles set
`SHUNT_MASTER_PASSWORD`. See [docs/profile.md](docs/profile.md) for the
profile format.

## Build

Requires Go 1.26+ (no C compiler):

```
go build -trimpath -ldflags "-s -w -H windowsgui" -o dist/shunt.exe ./cmd/shunt
```

The icon and manifest are embedded from `cmd/shunt/rsrc_windows_amd64.syso`. To regenerate it
after changing the logo (`internal/brand`), run `go run ./tools/mkres` before building:

```
go run ./tools/mkres
```

To embed the driver into the executable, place it at
`internal/tun/embedded/wintun_amd64.dll` before building.

## Status

Logs: `%APPDATA%\Shunt\shunt.log`; fatal errors are written to `%APPDATA%\Shunt\crash.log`
(**File > Open Log Folder**). Only one Shunt window runs at a time.

Verified on Windows 11: build, `go vet`, Proxifier profile import, rule
listing, and the proxy checker against a live SOCKS5 proxy.

Verified on the real Wintun adapter with `shunt diag` (routes only test
addresses into the tunnel): adapter and route setup, process identification,
proxied and direct connections, and DNS through the tunnel resolver. Not yet
verified: a full system-wide session (all routes). Also not done yet:

- the GUI main window opens and was checked; its dialogs (proxy servers, rules, name resolution, advanced) compile but were not clicked through
- proxy chains have no editor yet (edit them in the profile file); no installer, tray icon or automated tests
- UDP through SOCKS5 (UDP is bypassed or blocked), NTLM / Kerberos proxy auth
- traffic on the local subnet bypasses the tunnel (more specific route)
- Linux and macOS are not supported yet

## Layout

```
cmd/shunt          GUI (gui.go) and command line entry point
internal/core      engine: rule decision, direct / proxy / chain dialling, relay
internal/tun       Wintun device, routes, gVisor netstack
internal/dns       fake-IP pool and DNS query handling
internal/rules     application / target / port matching
internal/proxy     SOCKS5, SOCKS4/4A, HTTPS, HTTP handshakes, chains, checker
internal/profile   profile model, encryption, Proxifier .ppx import/export
internal/procinfo  socket -> process lookup
internal/netif     physical interface detection and socket binding
```

## License

MIT – see [LICENSE](LICENSE). Shunt is an independent project and is not
affiliated with Proxifier or VentoByte; "Proxifier" is a trademark of its
owner. Wintun is © WireGuard LLC and distributed under its own license.
