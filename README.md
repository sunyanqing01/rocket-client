<div align="right">简体中文 | <a href="#english">English</a></div>

# Rocket Client

一个用 **Rust** 编写的 Windows SSL VPN 客户端，兼容使用旧版 "SVN" SSL VPN 协议的网关（即 SecoClient / UniVPN 时代客户端所使用的协议）。

- **GUI 桌面版**：Tauri 2 + Vue 3 —— 托盘应用、单实例、一键 TUN 模式
- **CLI 命令行版**：纯 Rust —— SOCKS5 代理 / 端口转发 / 完整 TUN 模式

> ⚠️ **免责声明**：本项目是对旧版 VPN 协议的独立 reimagination（净室重实现），仅用于互操作与学习目的。请仅在你被授权访问的网关上使用。本项目与任何厂商无关，不包含任何厂商商标。

## 特性

- **UDP 数据面（mode 3）**——协商一条 AES-128 加密的 UDP 通道，绕过网关狭小的 TCP 窗口。纯 TLS 隧道会被这个窗口卡在 ~500 KB/s
- 自动回退：UDP 协商失败或中途断开，静默切换回 TCP 数据面
- 基于 **Wintun** 的 TUN 模式 + 分流路由——只有你选择的子网走隧道，其余流量走物理网卡
- 单线程独占 TLS pump 架构（数据路径无锁竞争）
- 连接期间将系统定时器精度提升到 1 ms（规避 Windows 15.6 ms 定时器陷阱）
- 多网关记忆、日志面板、最小化到托盘、附带 NSIS 安装包脚本

## 实测性能（23 ms RTT 链路）

| 方向 | 纯 TCP 数据面 | UDP 数据面 | 参考客户端 |
|---|---|---|---|
| 上传 | ~0.5 MB/s | **8–9 MB/s** | 2–3 MB/s |
| 下载 | ~0.5 MB/s | **5.5 MB/s**（稳定） | 2–3 MB/s |
| 内网 Ping | 44 ms | 44 ms | — |

## 目录结构

```
├── gui/        Tauri 2 + Vue 3 桌面应用（托盘 + TUN 模式）
│   ├── src/                Vue 界面
│   ├── src-tauri/          Rust 后端（vpn.rs = 协议 + 数据面）
│   └── installer/          NSIS 脚本
├── cli/        无界面 CLI：SOCKS5 / 端口转发 / TUN
└── installer/  Windows 安装包 NSIS 3 脚本
```

## 构建

前置要求：**Rust (MSVC)**、**Node.js 18+**、[Wintun](https://www.wintun.net/)（运行时放在 exe 旁边即可）。

```bash
# GUI（前端 + tauri release 构建，不打安装包）
cd gui
npm install
npx tauri build --no-bundle
# -> gui/src-tauri/target/release/rocket-gui.exe

# CLI
cd cli
cargo build --release
# -> cli/target/release/rocket-cli.exe
```

GUI 构建注意事项：

- 必须用 `npx tauri build --no-bundle` 构建（直接 `cargo build` 会产出连不上 devUrl 的白屏 exe）
- 改过图标或 Windows manifest 后要清构建缓存：`rm -rf src-tauri/target/release/build/rocket-gui-* && touch src-tauri/build.rs`
- `ROCKET_NO_ADMIN=1` 可构建 `asInvoker` 的 exe（无 UAC 弹窗，仅用于界面冒烟测试）；默认 manifest 是 `requireAdministrator`，因为 TUN 模式需要管理员权限

## 使用

### GUI

输入网关（`host:port`）、账号密码，勾选要走隧道的内网网段，点连接。关闭窗口即最小化到托盘。

### CLI（TUN 模式，需管理员）

```bash
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS \
  -route 10.0.0.0/8 -route 172.16.0.0/12
```

### CLI（SOCKS5 模式，无需管理员）

```bash
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS -socks 127.0.0.1:1080
```

## 协议说明（旧版 "SVN" 协议）

控制通道是 TLS（legacy 帧格式 `FEFCEFBE C192A4D6` + cmd + len + sid）：

| Cmd | 含义 |
|---|---|
| `0x02` | IP 数据帧 |
| `0x03` | REQVIP —— 获取虚拟 IP / 掩码 / DNS / 路由 |
| `0x06` | ACL |
| `0x07` | 保活（TCP 上每 10 秒一次） |
| `0x08` | 踢下线 |
| `0x1A` | UDP 端口请求（应答：u16 大端端口，默认 443） |
| `0x0D` | UDP 密钥请求（应答：u32 mode + 16 字节 AES-128 密钥，支持 mode 3） |

UDP 数据面包（mode 3）：

```
[0..8]   magic FE FC EF BE C1 92 A4 D6
[8..10]  0x021C
[10..12] 0x0010
[12..28] IV = uid(u32 大端) || 12 字节随机数
[28..48] 明文 IPv4 头（20 字节）
[48..]   AES-128-CBC(key, IV, 包剩余部分)，零填充
```

为什么 UDP 很关键：网关的 TCP 窗口（~12 KB）把单条 TLS 隧道限制在约 `窗口 / RTT` ≈ 500 KB/s（23 ms RTT 时）。UDP 通道没有这个天花板。

## 排障 / 诊断日志

- `%TEMP%\rocket-tps.log` —— 每秒一行：双向 bytes/s、pps、写延迟、空闲比
- `%TEMP%\rocket-timing.log` —— 120 条逐包采样，断开时写入
- `%TEMP%\rocket-crash.log` —— panic hook 输出

## 许可证

[MIT](LICENSE)

---

<div align="right"><a href="#rocket-client">简体中文</a> | English</div>

<a name="english"></a>

# Rocket Client (English)

A Windows **SSL VPN client written in Rust**, compatible with gateways speaking the legacy "SVN" SSL VPN protocol (the one used by SecoClient / UniVPN era clients).

- **GUI**: Tauri 2 + Vue 3 — tray app, single instance, one-click TUN mode
- **CLI**: pure Rust — SOCKS5 proxy / port forwarding / full TUN mode

> ⚠️ **Disclaimer**: This project is an independent, clean-room reimplementation of a legacy VPN protocol for interoperability and educational purposes. Use it only with gateways you are authorized to access. Not affiliated with any vendor. No vendor trademarks are included.

## Highlights

- **UDP data plane (mode 3)** — negotiates an AES-128 encrypted UDP channel and bypasses the gateway's small TCP window, which caps a pure-TLS tunnel at ~500 KB/s
- Automatic fallback: UDP negotiation failure or mid-session drop silently reverts to the TCP data plane
- TUN mode via **Wintun**, split routing — only the subnets you pick go through the tunnel
- Single-threaded TLS pump architecture (no lock contention on the data path)
- 1 ms timer resolution while connected (avoids the Windows 15.6 ms timer pitfall)

## Measured performance (23 ms RTT link)

| Direction | TCP-only data plane | UDP data plane | Reference client |
|---|---|---|---|
| Upload | ~0.5 MB/s | **8–9 MB/s** | 2–3 MB/s |
| Download | ~0.5 MB/s | **5.5 MB/s** (stable) | 2–3 MB/s |
| Ping (intranet) | 44 ms | 44 ms | — |

## Layout

```
├── gui/        Tauri 2 + Vue 3 desktop app (tray, TUN mode)
├── cli/        Headless CLI: SOCKS5 / port-forward / TUN
└── installer/  NSIS 3 script for the Windows installer
```

## Building

Prerequisites: **Rust (MSVC)**, **Node.js 18+**, [Wintun](https://www.wintun.net/) (place the DLL next to the exe).

```bash
cd gui && npm install && npx tauri build --no-bundle   # -> gui/src-tauri/target/release/rocket-gui.exe
cd cli && cargo build --release                        # -> cli/target/release/rocket-cli.exe
```

GUI build notes: always use `npx tauri build --no-bundle`; after changing the icon/manifest clear the cache (`rm -rf src-tauri/target/release/build/rocket-gui-* && touch src-tauri/build.rs`); `ROCKET_NO_ADMIN=1` builds an `asInvoker` exe for UI smoke tests.

## Usage

```bash
# TUN mode (admin)
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS -route 10.0.0.0/8

# SOCKS5 mode (no admin)
rocket-cli -gateway gateway.example.com:21443 -user NAME -password PASS -socks 127.0.0.1:1080
```

## Protocol notes (legacy "SVN" generation)

Control channel is TLS (`legacy` frame format `FEFCEFBE C192A4D6` + cmd + len + sid): `0x02` IP data, `0x03` REQVIP, `0x06` ACL, `0x07` keepalive, `0x08` kickout, `0x1A` UDP port request, `0x0D` UDP key request (mode 3).

UDP data plane packet (mode 3):

```
[0..8]   magic FE FC EF BE C1 92 A4 D6
[8..12]  0x021C, 0x0010
[12..28] IV = uid(u32 BE) || 12 random bytes
[28..48] plaintext IPv4 header (20 B)
[48..]   AES-128-CBC(key, IV, rest of the packet), zero padding
```

Why UDP matters: the gateway's TCP window (~12 KB) limits a single TLS tunnel to roughly `window / RTT` ≈ 500 KB/s at 23 ms RTT. The UDP channel has no such ceiling.

## Diagnostics

- `%TEMP%\rocket-tps.log` — per-second throughput (bytes/s, pps, write latency, idle ratio)
- `%TEMP%\rocket-timing.log` — 120 per-packet samples on disconnect
- `%TEMP%\rocket-crash.log` — panic hook output

## License

[MIT](LICENSE)
