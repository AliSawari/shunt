# Profile format

A profile is a JSON file (`*.shunt.json`). Proxifier `.ppx` files can be used
directly with `-profile` or converted with `shunt import`.

```json
{
  "version": 1,
  "options": {
    "resolve": {
      "autoDetect": true,
      "viaProxy": false,
      "blockNonA": false,
      "exclusionList": "%ComputerName%; localhost; *.local",
      "onlyFromList": false
    },
    "encryption": "basic",
    "connectionLoopDetection": true,
    "udpMode": "bypass",
    "leakPrevention": false,
    "processOtherUsers": false,
    "processServices": false,
    "handleDirectConnections": false,
    "httpProxySupport": false
  },
  "proxies": [
    { "id": 100, "type": "SOCKS5", "address": "127.0.0.1", "port": 1080,
      "authEnabled": false, "useHostname": true }
  ],
  "chains": [
    { "id": 101, "name": "Failover", "type": "redundancy",
      "proxies": [ { "id": 100, "enabled": true } ],
      "timeoutSec": 30, "recheckSec": 60, "tryDirect": false }
  ],
  "rules": [
    { "name": "Localhost", "enabled": true,
      "targets": "localhost; 127.0.0.1; %ComputerName%; ::1",
      "action": { "type": "Direct" } },
    { "name": "Browsers", "enabled": true, "applications": "chrome.exe; firefox.exe",
      "ports": "80; 443", "action": { "type": "Proxy", "id": 100 } },
    { "name": "Default", "enabled": true, "action": { "type": "Direct" } }
  ]
}
```

- **Rules** are evaluated top to bottom; the last rule is the Default rule
  and always matches. Empty `applications` / `targets` / `ports` mean "any".
- **Action types**: `Direct`, `Block`, `Proxy` (with proxy `id`), `Chain`
  (with chain `id`).
- **Proxy types**: `SOCKS5`, `SOCKS4` (`"socks4a": true` for 4A), `HTTPS`,
  `HTTP` (needs `httpProxySupport`; HTTP traffic only, last in a chain).
- **Chain types**: `simple`, `redundancy`, `loadbalance` (`"stickyPid": true`
  keeps one proxy per process).
- **udpMode**: `bypass`, `block443`, `blockall`.
- **encryption** (for `password`, written as `passwordEnc`): `disabled`,
  `basic` (static key), `user` (Windows DPAPI), `master`
  (`SHUNT_MASTER_PASSWORD`).
- A rule may set `"interface": "Wi-Fi"` to pin direct connections to an
  adapter; `"ifDownIgnore": true` skips the rule while that adapter is down.
