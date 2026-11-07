# Rocket Client

A cross-platform-friendly **SSL VPN client for Windows** (Rust), compatible with gateways speaking the legacy "SVN" SSL VPN protocol (the one used by SecoClient / UniVPN era clients).

- **GUI**: Tauri 2 + Vue 3 — tray app, single instance, TUN mode with one click
- **CLI**: pure Rust — SOCKS5 proxy / port forwarding / full TUN mode

> ⚠️ **Disclaimer**: This project is an independent, clean-room reimplementation of a legacy VPN protocol for interoperability and educational purposes. Use it only with gateways you are authorized to access. Not affiliated with any vendor. No vendor trademarks are included.

## Highlights

- **UDP data plane (mode 3)** — negotiates an AES-128 encrypted UDP channel and bypasses the gateway's small TCP window, which caps a pure-TLS tunnel at ~500 KB/s
- Automatic fallback: UDP negotiation failure or mid-session drop silently reverts to the TCP data plane
- TUN mode via **Wintun**, split routing — only the subnets you pick go through the tunnel, everything else stays on the physical NIC
- Single-threaded TLS pump architecture (no lock contention on the data path)
- 1 ms timer resolution while connected (avoids the Windows 15.6 ms timer pitfall)
- Remembers multiple gateways, log panel, minimize-to-tray, NSIS installer script included

## Measured performance (23 ms RTT link)

| Direction | TCP-only data plane | UDP data plane | Reference client |
|---|---|---|---|
| Upload | ~0.5 MB/s | **8–9 MB/s** | 2–3 MB/s |
| Download | ~0.5 MB/s | **5.5 MB/s** (stable) | 2–3 MB/s |
| Ping (intranet) | 44 ms | 44 ms | — |

## Repository layout

```
├── gui/        Tauri 2 + Vue 3 desktop app (tray, TUN mode)
│   ├── src/                Vue UI
│   ├── src-tauri/          Rust backend (vpn.rs = protocol + data plane)
│   └── installer/          NSIS script
├── cli/        Headless CLI: SOCKS5 / port-forward / TUN
└── installer/  NSIS 3 script for the Windows installer
```

## Building

Prerequisites: **Rust (MSVC)**, **Node.js 18+**, [Wintun](https://www.wintun.net/) (bundled at runtime next to the exe).

```bash
# GUI (frontend + tauri release build, no bundler)
cd gui
npm install
npx tauri build --no-bundle
# -> gui/src-tauri/target/release/rocket-gui.exe

# CLI
cd cli
cargo build --release
# -> cli/target/release/rocket-cli.exe
```

Notes for GUI builds:

- Always build with `npx tauri build --no-bundle` (a plain `cargo build` produces a white-screen exe that cannot reach the dev URL)
- After changing the icon or Windows manifest, clear the build cache: `rm -rf src-tauri/target/release/build/rocket-gui-* && touch src-tauri/build.rs`
- `ROCKET_NO_ADMIN=1` builds an `asInvoker` exe (no UAC prompt) for UI smoke tests; the default manifest is `requireAdministrator` because TUN mode needs it

## Usage

### GUI

Enter gateway (`host:port`), username and password, pick the intranet subnets to route through the tunnel, click Connect. Closing the window minimizes to the tray.

### CLI (TUN mode)

```bash
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS \
  -route 10.0.0.0/8 -route 172.16.0.0/12
```

### CLI (SOCKS5 mode, no admin required)

```bash
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS -socks 127.0.0.1:1080
```

## Protocol notes (legacy "SVN" generation)

Control channel is TLS (`legacy` frame format `FEFCEFBE C192A4D6` + cmd + len + sid):

| Cmd | Meaning |
|---|---|
| `0x02` | IP data frame |
| `0x03` | REQVIP — obtain virtual IP / mask / DNS / routes |
| `0x06` | ACL |
| `0x07` | Keepalive (every 10 s over TCP) |
| `0x08` | Kickout |
| `0x1A` | UDP port request (reply: u16 BE port, default 443) |
| `0x0D` | UDP key request (reply: u32 mode + 16-byte AES-128 key, mode 3 supported) |

UDP data plane packet (mode 3):

```
[0..8]   magic FE FC EF BE C1 92 A4 D6
[8..10]  0x021C
[10..12] 0x0010
[12..28] IV = uid(u32 BE) || 12 random bytes
[28..48] plaintext IPv4 header (20 B)
[48..]   AES-128-CBC(key, IV, rest of the packet), zero padding
```

Why UDP matters: the gateway's TCP window (~12 KB) limits a single TLS tunnel to roughly `window / RTT` ≈ 500 KB/s at 23 ms RTT. The UDP channel has no such ceiling.

## Troubleshooting / diagnostics

- `%TEMP%\rocket-tps.log` — one line per second: per-direction bytes/s, pps, write latency, idle ratio
- `%TEMP%\rocket-timing.log` — 120 per-packet samples, written on disconnect
- `%TEMP%\rocket-crash.log` — panic hook output

## License

[MIT](LICENSE)
