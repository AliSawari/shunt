# Changelog

All notable changes to Shunt are listed here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-14

First release with a full desktop application and a working tunnel.

### Added
- **Desktop application** in the style of Proxifier: live connections list
  (application, target, time, rule : proxy, sent, received), log pane and
  status bar.
- **Large Start/Stop button** with a status line, and an icon toolbar for
  Proxy Servers, Proxification Rules, Name Resolution, Advanced and Proxy
  Checker.
- **Settings dialogs**: proxy servers (add, edit, remove, check), proxification
  rules (enable, reorder, clone, edit), name resolution, advanced options, and
  profile import/export including Proxifier `.ppx` files.
- **System tray icon**: left-click opens Shunt; the menu has Open, Start/Stop,
  Proxy Servers, Rules and Exit; the tooltip shows live traffic.
- **Close button choice**: exit or minimize to tray, with an option to
  remember it (View > Close Button Minimizes to Tray).
- **Sortable connections list**: click a column header to sort ascending or
  descending.
- **Live loop detection**: a proxy running on this PC is recognised even
  after it restarts, connects directly, and gets an `[auto-created]` Direct
  rule, as in Proxifier.
- **Automatic DNS mode** resolves names through the proxy whenever a rule
  uses one, so local DNS filtering or poisoning does not matter.
- **Branding**: Shunt icon embedded in the executable and on every window and
  dialog; About dialog with author and project link.
- **Bundled Wintun driver** (0.14.1, unmodified, signed by WireGuard LLC).
- **Diagnostics**: log file (`%APPDATA%\Shunt\shunt.log`), crash log
  (`crash.log`), File > Open Log Folder, and a scoped `shunt diag` command
  that tests the tunnel on two addresses only.
- Administrator relaunch starts the tunnel automatically; only one Shunt
  window runs at a time.
- Continuous builds on GitHub Actions with a rolling nightly pre-release.

### Fixed
- **The tunnel never started**: route setup failed with "Element not found"
  because the route API used first flushed routes Windows creates itself.
- **Crash after Stop**, which also closed the app after changing settings
  while running.
- **Connections list only updated on mouse hover.**
- Process ownership: unreadable processes are no longer treated as another
  user's (which silently bypassed the proxy).
- Shunt's own connections can never be proxified back into itself.

## [0.1.0] - 2026-11-10

Initial command-line release.

### Added
- Tunnel engine: Wintun virtual adapter and a userspace TCP/IP stack
  (gVisor) capture system traffic.
- Proxy protocols: SOCKS5 (with authentication and remote DNS), SOCKS4,
  SOCKS4A, HTTPS (CONNECT) and HTTP; proxy chains (simple, redundancy, load
  balancing).
- Proxification rules by application, target host and port, with Direct,
  Block, Proxy and Chain actions.
- Name resolution through the proxy with fake IPs, UDP bypass/block modes,
  leak prevention, services and other users filtering.
- Profiles in JSON with password encryption (plain, static key, Windows DPAPI,
  master password) and Proxifier `.ppx` import/export.
- Proxy checker and command-line interface (`run`, `init`, `import`,
  `export`, `check`, `show`).

[0.2.0]: https://github.com/AliSawari/shunt/releases/tag/v0.2.0
[0.1.0]: https://github.com/AliSawari/shunt/commit/4e406ab
