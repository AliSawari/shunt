Optional build-time payload.

Place the Wintun driver DLL here as wintun_amd64.dll / wintun_arm64.dll to
have it embedded into shunt.exe (scripts/fetch-wintun.ps1 does this and
verifies the download). Without it, wintun.dll must be shipped next to the
executable. Wintun is (c) WireGuard LLC, https://www.wintun.net
