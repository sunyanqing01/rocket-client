//! SSL-VPN protocol (SecoClient / UniVPN compatible), Legacy generation.
//! TUN mode only: we create a Wintun adapter and route *only* the subnets the
//! user selected into it. Everything else keeps using the physical NIC.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::windows::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use native_tls::{TlsConnector, TlsStream};
use std::sync::atomic::AtomicU64;
use serde::{Deserialize, Serialize};

const MAGIC_LEGACY1: u32 = 0xFEFC_EFBE;
const MAGIC_V1: u32 = 0xC192_A4D6;
const MAGIC_AUTH: u32 = 0xF0F0_F0F0;

const CMD_ACL: u16 = 0x06;
const CMD_REQVIP: u16 = 0x03;
const CMD_KEEPALIVE: u16 = 0x07;
const CMD_KICKOUT: u16 = 0x08;
const CMD_DATA: u16 = 0x02;
// UDP data-plane negotiation (Legacy mode 3), protocol identical to UniSpoke.
const CMD_UDP_KEY: u16 = 0x0D;
const CMD_UDP_PORT: u16 = 0x1A;
const DEFAULT_UDP_PORT: u16 = 443;

const ADAPTER_NAME: &str = "rocket";
const LEN_SANITY: usize = 4096;

// ------------------------------------------------------- AES-128-CBC (UDP plane)

/// Zero-padded AES-128-CBC encrypt (protocol uses zero padding, not PKCS7).
fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let pad = (16 - plain.len() % 16) % 16;
    let mut data = plain.to_vec();
    data.resize(plain.len() + pad, 0);
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        for (b, p) in chunk.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        let ga = GenericArray::from_mut_slice(chunk);
        cipher.encrypt_block(ga);
        prev.copy_from_slice(chunk);
    }
    data
}

/// AES-128-CBC decrypt, returns None on a length violation.
fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockDecrypt, KeyInit};
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let cipher = aes::Aes128::new(GenericArray::from_slice(key));
    let mut data = ct.to_vec();
    let mut prev = *iv;
    for chunk in data.chunks_mut(16) {
        let mut block = [0u8; 16];
        block.copy_from_slice(chunk);
        let mut ga = GenericArray::from_mut_slice(&mut block);
        cipher.decrypt_block(&mut ga);
        for (b, p) in block.iter_mut().zip(prev.iter()) {
            *b ^= *p;
        }
        prev.copy_from_slice(chunk);
        chunk.copy_from_slice(&block);
    }
    Some(data)
}

/// Cheap non-crypto PRNG for the 12 random IV bytes (uid already fills 4).
struct FastRng(u64);
impl FastRng {
    fn next_u32(&mut self) -> u32 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        (x.wrapping_mul(0x2545_F491_4F6C_DD1D) >> 32) as u32
    }
}

// ------------------------------------------------------------- UDP data plane

/// The negotiated UDP data channel (mode 3): AES-128 key + connected socket.
struct UdpPlane {
    sock: std::net::UdpSocket,
    key: [u8; 16],
    uid: u32,
    rng: Mutex<FastRng>,
}

const UDP_MAGIC: [u8; 8] = [0xFE, 0xFC, 0xEF, 0xBE, 0xC1, 0x92, 0xA4, 0xD6];
const UDP_HDR: usize = 28;
const UDP_IPHDR: usize = 20;

impl UdpPlane {
    fn build_packet(&self, pkt: &[u8]) -> Option<Vec<u8>> {
        if pkt.len() < UDP_IPHDR {
            return None;
        }
        let mut rng = self.rng.lock().ok()?;
        let iv0 = self.uid.to_be_bytes();
        let r0 = rng.next_u32();
        let r1 = rng.next_u32();
        let r2 = rng.next_u32();
        drop(rng);
        let mut iv = [0u8; 16];
        iv[0..4].copy_from_slice(&iv0);
        iv[4..8].copy_from_slice(&r0.to_be_bytes());
        iv[8..12].copy_from_slice(&r1.to_be_bytes());
        iv[12..16].copy_from_slice(&r2.to_be_bytes());
        let body = aes_cbc_encrypt(&self.key, &iv, &pkt[UDP_IPHDR..]);
        let mut out = Vec::with_capacity(UDP_HDR + body.len());
        out.extend_from_slice(&UDP_MAGIC);
        out.extend_from_slice(&0x021C_u16.to_be_bytes());
        out.extend_from_slice(&0x0010_u16.to_be_bytes());
        out.extend_from_slice(&iv);
        out.extend_from_slice(&pkt[..UDP_IPHDR]);
        out.extend_from_slice(&body);
        Some(out)
    }

    /// Parse one UDP datagram into an IPv4 packet (plaintext IP head + decrypted body).
    fn parse_packet(&self, buf: &[u8]) -> Option<Vec<u8>> {
        if buf.len() < UDP_HDR + UDP_IPHDR || buf[0..8] != UDP_MAGIC {
            return None;
        }
        let ip_head = &buf[UDP_HDR..UDP_HDR + UDP_IPHDR];
        if ip_head[0] >> 4 != 4 {
            return None; // control frame, not data
        }
        let total = u16::from_be_bytes([ip_head[2], ip_head[3]]) as usize;
        let body_len = total.checked_sub(UDP_IPHDR)?;
        let mut iv = [0u8; 16];
        iv.copy_from_slice(&buf[12..28]);
        let plain = aes_cbc_decrypt(&self.key, &iv, &buf[UDP_HDR + UDP_IPHDR..])?;
        if plain.len() < body_len {
            return None;
        }
        let mut out = vec![0u8; total];
        out[..UDP_IPHDR].copy_from_slice(ip_head);
        out[UDP_IPHDR..].copy_from_slice(&plain[..body_len]);
        Some(out)
    }
}


// ---------------------------------------------------------- timer resolution

#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

/// Raise the system timer resolution to 1 ms while the tunnel is up.
/// Without this, `SO_RCVTIMEO` is rounded up to the default ~15.6 ms tick,
/// which adds roughly one tick of latency to every reply we pick up.
struct HiResTimer;

impl HiResTimer {
    fn new() -> Self {
        unsafe {
            timeBeginPeriod(1);
        }
        Self
    }
}

impl Drop for HiResTimer {
    fn drop(&mut self) {
        unsafe {
            timeEndPeriod(1);
        }
    }
}

// ---------------------------------------------------------------- timing

struct TimingBuf {
    lines: Vec<String>,
    limit: usize,
}

impl TimingBuf {
    fn new(limit: usize) -> Self {
        Self { lines: Vec::new(), limit }
    }
    fn push(&mut self, line: String) {
        if self.lines.len() < self.limit {
            self.lines.push(line);
        }
    }
}

fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Append one line to %TEMP%\rocket-tps.log. Called at most once per second
/// from the pump thread, so the cost (open+write+close) is irrelevant, but it
/// survives a crash or a force-kill — unlike the on-disconnect timing dump.
fn tps_line(line: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("rocket-tps.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

/// Write collected samples to %TEMP%\rocket-timing.log (call on disconnect only,
/// never on the data path).
fn dump_timing(buf: &TimingBuf) {
    use std::io::Write;
    let path = std::env::temp_dir().join("rocket-timing.log");
    if let Ok(mut f) = std::fs::File::create(&path) {
        for l in &buf.lines {
            let _ = writeln!(f, "{l}");
        }
        let _ = writeln!(f, "=== end of session ({} samples) ===", buf.lines.len());
    }
}

// ------------------------------------------------------ UDP plane negotiation

/// Ask the gateway (over the TCP control channel) for the UDP data plane.
/// Legacy mode 3: CMD 0x1A -> UDP port, CMD 0x0D -> mode + 16-byte AES key.
fn negotiate_udp(fr: &mut FrameReader, host: &str, uid: u32) -> Result<UdpPlane, String> {
    // 1. UDP port (some gateways ignore this and use 443)
    let mut port = DEFAULT_UDP_PORT;
    if fr.write_frame(CMD_UDP_PORT, &[0, 0, 0, 0], uid).is_ok() {
        if let Ok(f) = fr.next() {
            if f.cmd == CMD_UDP_PORT && f.payload.len() >= 2 {
                port = u16::from_be_bytes([f.payload[0], f.payload[1]]);
            }
        }
    }
    // 2. AES key
    fr.write_frame(CMD_UDP_KEY, &[0, 0, 0, 4], uid)
        .map_err(|e| format!("UDP key 请求失败: {e}"))?;
    let f = fr.next().map_err(|e| format!("UDP key 应答失败: {e}"))?;
    if f.cmd != CMD_UDP_KEY {
        return Err(format!("UDP key 应答 cmd=0x{:04X}", f.cmd));
    }
    if f.payload.len() < 20 {
        return Err(format!("UDP key 应答过短 ({})", f.payload.len()));
    }
    let mode = u32::from_be_bytes([
        f.payload[0],
        f.payload[1],
        f.payload[2],
        f.payload[3],
    ]);
    if mode != 3 {
        return Err(format!("UDP mode {mode} 不支持"));
    }
    let mut key = [0u8; 16];
    key.copy_from_slice(&f.payload[4..20]);
    // 3. connect the UDP data channel
    let addr = format!("{host}:{port}");
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    sock.connect(&addr).map_err(|e| format!("UDP 连接 {addr} 失败: {e}"))?;
    let _ = sock.set_read_timeout(Some(Duration::from_millis(1000)));
    let seed = now_us() ^ (uid as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    Ok(UdpPlane { sock, key, uid, rng: Mutex::new(FastRng(seed | 1)) })
}

/// Negotiate and install the UDP plane; returns a status line for the log.
fn try_udp_plane(
    fr: &mut FrameReader,
    host: &str,
    uid: u32,
    slot: &Arc<std::sync::RwLock<Option<Arc<UdpPlane>>>>,
) -> String {
    match negotiate_udp(fr, host, uid) {
        Ok(p) => {
            if let Ok(mut w) = slot.write() {
                *w = Some(Arc::new(p));
            }
            "UDP 数据面已启用（mode 3），吞吐不再受 TCP 窗口限制".to_string()
        }
        Err(e) => format!("UDP 数据面协商失败，继续走 TCP: {e}"),
    }
}

/// Per-second throughput line for a dedicated thread (tagged).
fn tps_thread(
    tag: &str,
    stop: Arc<AtomicBool>,
    mut stat: impl FnMut() -> (u64, u64, u64),
) {
    let mut last = Instant::now();
    let mut acc = (0u64, 0u64, 0u64);
    loop {
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
        let s = stat();
        acc.0 += s.0;
        acc.1 += s.1;
        acc.2 += s.2;
        if last.elapsed() >= Duration::from_secs(1) {
            let dt = last.elapsed().as_secs_f64().max(1e-9);
            tps_line(&format!(
                "{tag} bytes/s={:.0} pkts/s={:.0} max_len={}",
                acc.0 as f64 / dt,
                acc.1 as f64 / dt,
                acc.2
            ));
            last = Instant::now();
            acc = (0, 0, 0);
        }
    }
}

// ---------------------------------------------------------------- local mac

/// Best-effort MAC of this machine, formatted as 12 uppercase hex chars.
/// `getmac` is used because it needs no extra crates and prints every adapter
/// in a stable, machine-readable CSV form.
pub fn local_mac() -> String {
    let out = match cmd("getmac").args(["/fo", "csv", "/nh"]).output() {
        Ok(o) => o.stdout,
        Err(_) => return String::new(),
    };
    // Adapter names may be non-UTF8; MACs are ASCII, so lossy is fine.
    let text = String::from_utf8_lossy(&out);
    for line in text.lines() {
        for tok in line.split(',') {
            let t: String = tok
                .trim()
                .trim_matches('"')
                .chars()
                .filter(|c| c.is_ascii_hexdigit())
                .collect();
            if t.len() == 12 && !t.chars().all(|c| c == '0') && !t.starts_with("0000") {
                return t.to_uppercase();
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------- config

#[derive(Deserialize, Clone, Debug)]
pub struct ConnectConfig {
    pub gateway: String,
    pub username: String,
    pub password: String,
    pub mac: String,
    pub insecure: bool,
    pub routes: Vec<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ConnectResult {
    pub vip: String,
    pub routes: Vec<String>,
}

#[derive(Debug)]
struct Frame {
    cmd: u16,
    payload: Vec<u8>,
}

// ---------------------------------------------------------------- protocol

fn build_legacy(cmd: u16, payload: &[u8], sid: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + payload.len());
    b.extend_from_slice(&MAGIC_LEGACY1.to_be_bytes());
    b.extend_from_slice(&MAGIC_V1.to_be_bytes());
    b.extend_from_slice(&sid.to_be_bytes());
    b.extend_from_slice(&cmd.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

fn parse_frame(b: &[u8]) -> Option<(Frame, usize)> {
    if b.len() < 4 {
        return None;
    }
    let m0 = u32::from_be_bytes([b[0], b[1], b[2], b[3]]);
    if m0 == MAGIC_V1 {
        if b.len() < 8 {
            return None;
        }
        let len = u16::from_be_bytes([b[6], b[7]]) as usize;
        if b.len() < 8 + len {
            return None;
        }
        return Some((Frame { cmd: b[5] as u16, payload: b[8..8 + len].to_vec() }, 8 + len));
    }
    if b.len() < 8 {
        return None;
    }
    let m1 = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
    if m0 != MAGIC_LEGACY1 || m1 != MAGIC_V1 {
        return None;
    }
    if b.len() < 16 {
        return None;
    }
    let be = u16::from_be_bytes([b[14], b[15]]) as usize;
    let le = u16::from_le_bytes([b[14], b[15]]) as usize;
    let len = if be > LEN_SANITY && le <= LEN_SANITY { le } else { be };
    if b.len() < 16 + len {
        return None;
    }
    Some((
        Frame { cmd: u16::from_be_bytes([b[12], b[13]]), payload: b[16..16 + len].to_vec() },
        16 + len,
    ))
}

fn strip_vnic_prefix(p: &[u8]) -> &[u8] {
    if p.len() >= 20 && p[0] >> 4 == 4 {
        return p;
    }
    if p.len() >= 22 && p[2] >> 4 == 4 {
        return &p[2..];
    }
    p
}

fn url_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for c in s.chars() {
        match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}

fn tls_connect(host: &str, port: u16, insecure: bool) -> Result<TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("无法连接网关 {host}:{port} — {e}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let mut b = TlsConnector::builder();
    b.danger_accept_invalid_certs(insecure);
    b.danger_accept_invalid_hostnames(insecure);
    let conn = b.build().map_err(|e| format!("TLS 初始化失败: {e}"))?;
    conn.connect(host, tcp).map_err(|e| format!("TLS 握手失败: {e}"))
}

struct FrameReader {
    inner: TlsStream<TcpStream>,
    buf: Vec<u8>,
}

impl FrameReader {
    fn new(inner: TlsStream<TcpStream>) -> Self {
        Self { inner, buf: Vec::new() }
    }

    fn into_inner(self) -> TlsStream<TcpStream> {
        self.inner
    }

    fn write_frame(&mut self, cmd: u16, payload: &[u8], sid: u32) -> Result<(), String> {
        let b = build_legacy(cmd, payload, sid);
        self.inner.write_all(&b).map_err(|e| format!("隧道写入失败: {e}"))?;
        self.inner.flush().ok();
        Ok(())
    }

    fn next(&mut self) -> Result<Frame, String> {
        loop {
            if let Some((f, n)) = parse_frame(&self.buf) {
                self.buf.drain(..n);
                return Ok(f);
            }
            let mut tmp = [0u8; 65536];
            let n = self.inner.read(&mut tmp).map_err(|e| format!("隧道读取失败: {e}"))?;
            if n == 0 {
                return Err("网关关闭了连接".into());
            }
            self.buf.extend_from_slice(&tmp[..n]);
            if self.buf.len() > (1 << 22) {
                return Err("帧缓冲溢出".into());
            }
        }
    }
}

fn login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    mac: &str,
    insecure: bool,
) -> Result<u32, String> {
    let mut s = tls_connect(host, port, insecure)?;
    let mac_clean = mac.replace(['-', ':'], "").to_uppercase();
    let path = format!(
        "/netextension/netextensionlogin.html?SelectLanguage=0&UserName={}&Password={}&MacAddress={}&SVN_Seco_AaA=1",
        url_escape(user),
        url_escape(pass),
        mac_clean
    );
    let req = format!(
        "GET {path} HTTP/1.1\r\n\
         Accept: image/gif, */*\r\n\
         Accept-Language: zh-cn\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)\r\n\
         OS=Windows64\r\n\
         Host: {host}:{port}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| format!("发送登录请求失败: {e}"))?;
    s.flush().ok();

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match s.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() >= 65536 {
                    break;
                }
            }
            Err(_) => break,
        }
    }

    if buf.len() < 8 {
        return Err(format!("登录响应过短（{} 字节）", buf.len()));
    }
    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC_AUTH {
        return Err(format!("登录响应格式异常 magic={magic:08x}"));
    }
    let res = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if res < 0 {
        return Err(format!("认证被拒绝（错误码 {res}），请检查账号密码"));
    }
    if buf.len() < 48 {
        return Err(format!("登录成功但响应过短（{} 字节）", buf.len()));
    }
    Ok(u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]))
}

struct NetCfg {
    vip: [u8; 4],
}

fn parse_netcfg(p: &[u8]) -> Result<NetCfg, String> {
    if p.len() < 8 {
        return Err(format!("REQVIP 响应过短（{} 字节）", p.len()));
    }
    Ok(NetCfg { vip: [p[0], p[1], p[2], p[3]] })
}

// ---------------------------------------------------------------- tunnel

// ---------------------------------------------------------------- helpers

fn ip_str(v: u32) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, bits) = s.trim().split_once('/')?;
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut v: u32 = 0;
    for p in &parts {
        v = (v << 8) | p.parse::<u8>().ok()? as u32;
    }
    let n: u32 = bits.parse().ok()?;
    if n == 0 || n > 32 {
        return None;
    }
    let mask: u32 = if n == 32 { 0xffff_ffff } else { (!0u32) << (32 - n) };
    Some((v & mask, mask))
}

/// CREATE_NO_WINDOW — a GUI process has no console, so every console child
/// (netsh/route) would otherwise flash its own black window.
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn cmd(program: &str) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

fn run_cmd(program: &str, args: &[&str]) -> bool {
    cmd(program)
        .args(args)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a command and surface the real stderr on failure.
fn run_cmd_out(program: &str, args: &[&str]) -> Result<(), String> {
    match cmd(program).args(args).output() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).trim().to_string();
            let out = String::from_utf8_lossy(&o.stdout).trim().to_string();
            let msg = if !err.is_empty() { err } else { out };
            Err(if msg.is_empty() {
                format!("{program} 退出码 {:?}", o.status.code())
            } else {
                msg
            })
        }
        Err(e) => Err(format!("无法执行 {program}: {e}")),
    }
}

/// Add one route to the adapter. netsh is tried first (name-based, no index
/// juggling); route.exe is the fallback with "if" and the index as separate
/// arguments.
fn add_route(net: u32, mask: u32, idx: u32) -> Result<(), String> {
    let ns = ip_str(net);
    let ms = ip_str(mask);
    let cidr = format!("{ns}/{}", mask.count_ones());
    let idxs = idx.to_string();

    match run_cmd_out(
        "netsh",
        &["interface", "ipv4", "add", "route", &cidr, ADAPTER_NAME, "store=active"],
    ) {
        Ok(()) => return Ok(()),
        Err(e1) => {
            match run_cmd_out("route", &["add", &ns, "mask", &ms, "0.0.0.0", "if", &idxs]) {
                Ok(()) => Ok(()),
                Err(e2) => Err(format!("netsh: {e1} | route: {e2}")),
            }
        }
    }
}

fn delete_routes(routes: &[(u32, u32)]) {
    for (net, mask) in routes {
        run_cmd("route", &["delete", &ip_str(*net), "mask", &ip_str(*mask)]);
    }
}

// ---------------------------------------------------------------- session

pub struct Session {
    #[allow(dead_code)]
    timer: HiResTimer,
    raw_sock: TcpStream,
    stop: Arc<AtomicBool>,
    timing: Arc<Mutex<TimingBuf>>,
    #[allow(dead_code)]
    adapter: Arc<wintun::Adapter>,
    #[allow(dead_code)]
    session: Arc<wintun::Session>,
    routes_raw: Vec<(u32, u32)>,
}

impl Session {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        delete_routes(&self.routes_raw);
        // Wakes the pump thread (blocked in TLS read) and the TUN reader
        // thread (blocked in receive_blocking).
        let _ = self.raw_sock.shutdown(std::net::Shutdown::Both);
        let _ = self.session.shutdown();
        if let Ok(tb) = self.timing.lock() {
            dump_timing(&tb);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        delete_routes(&self.routes_raw);
    }
}

pub fn connect<F>(cfg: &ConnectConfig, log: F) -> Result<(Session, ConnectResult), String>
where
    F: Fn(&str) + Send + Sync + Clone + 'static,
{
    let (host, port) = cfg
        .gateway
        .rsplit_once(':')
        .map(|(h, p)| (h.to_string(), p.parse::<u16>().unwrap_or(443)))
        .unwrap_or((cfg.gateway.clone(), 443));

    log(&format!("网关 {host}:{port}"));

    // 1. login
    // An empty MAC means "use this machine's own adapter".
    let mac = if cfg.mac.trim().is_empty() {
        let m = local_mac();
        if m.is_empty() {
            log("未读取到本机 MAC，使用默认值继续");
            "000000000000".to_string()
        } else {
            log(&format!("使用本机 MAC {m}"));
            m
        }
    } else {
        cfg.mac.trim().to_string()
    };

    log("正在认证…");
    let uid = login(&host, port, &cfg.username, &cfg.password, &mac, cfg.insecure)?;
    log(&format!("认证成功，会话 0x{uid:08x}"));

    // 2. control channel + ACL + REQVIP
    log("建立控制通道…");
    let stream = tls_connect(&host, port, cfg.insecure)?;
    let mut fr = FrameReader::new(stream);

    fr.write_frame(CMD_ACL, &[0, 0, 0, 0], uid)?;
    loop {
        let f = fr.next()?;
        if f.cmd == CMD_ACL {
            break;
        }
        if f.cmd == CMD_KICKOUT {
            return Err("被网关踢下线".into());
        }
    }
    log("ACL 通过");

    fr.write_frame(CMD_REQVIP, &[], uid)?;
    let vipf = loop {
        let f = fr.next()?;
        if f.cmd == CMD_REQVIP {
            break f;
        }
    };
    let ncfg = parse_netcfg(&vipf.payload)?;
    let vip_s = ip_str(u32::from_be_bytes(ncfg.vip));
    log(&format!("获得虚拟 IP {vip_s}"));

    // 3. parse routes
    let mut routes_raw: Vec<(u32, u32)> = Vec::new();
    let mut route_strs: Vec<String> = Vec::new();
    for r in &cfg.routes {
        match parse_cidr(r) {
            Some((net, mask)) => {
                routes_raw.push((net, mask));
                route_strs.push(r.trim().to_string());
            }
            None => return Err(format!("路由格式无效: {r}")),
        }
    }
    if routes_raw.is_empty() {
        return Err("至少需要一个网段".into());
    }

    // 4. create adapter
    log("创建虚拟网卡…");
    let wintun = unsafe { wintun::load() }
        .map_err(|e| format!("加载 wintun.dll 失败: {e}（请把 wintun.dll 放在程序目录）"))?;
    let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, ADAPTER_NAME, "Rocket Client", None)
            .map_err(|e| format!("创建网卡失败: {e}（请以管理员身份运行本程序）"))?,
    };
    let idx = adapter.get_adapter_index().map_err(|e| format!("获取网卡索引失败: {e}"))?;
    log(&format!("网卡 {ADAPTER_NAME} (ifIndex {idx})"));

    let _ = run_cmd(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "address",
            &format!("name={ADAPTER_NAME}"),
            "source=static",
            &format!("address={vip_s}"),
            "mask=255.255.255.0",
            "gateway=none",
        ],
    );

    // 4b. clamp MTU: outer frame header is 16B and the TLS record adds
    // ~45-57B (CBC/HMAC), so 1400 keeps the whole frame inside one 1500B
    // outer TCP segment (1400+16+57=1473) with zero fragmentation. The old
    // 1300 setting shrank the inner TCP MSS and directly throttled upload
    // throughput (throughput ≈ cwnd × MSS / RTT).
    let _ = run_cmd_out(
        "netsh",
        &[
            "interface",
            "ipv4",
            "set",
            "subinterface",
            ADAPTER_NAME,
            "mtu=1400",
            "store=active",
        ],
    );
    log("网卡 MTU 设为 1400");

    // 5. add precise routes
    delete_routes(&routes_raw);
    for (net, mask) in &routes_raw {
        let ns = ip_str(*net);
        let ms = ip_str(*mask);
        if let Err(e) = add_route(*net, *mask, idx) {
            delete_routes(&routes_raw);
            return Err(format!("添加路由 {ns}/{ms} 失败: {e}"));
        }
        log(&format!("路由 {ns}/{ms} → {ADAPTER_NAME}"));
    }

    // 5b. negotiate the UDP data plane (huge speed-up: the gateway's TCP
    // window caps a single TLS tunnel at ~500KB/s, UDP has no such limit)
    let udp_slot: Arc<std::sync::RwLock<Option<Arc<UdpPlane>>>> =
        Arc::new(std::sync::RwLock::new(None));
    let udp_msg = try_udp_plane(&mut fr, &host, uid, &udp_slot);
    log(&udp_msg);

    // 6. start session
    let session = Arc::new(
        adapter
            .start_session(0x40_0000)
            .map_err(|e| format!("启动 Wintun 会话失败: {e}"))?,
    );

    let timer = HiResTimer::new();
    tps_line(&format!(
        "=== session start ts={} vip={} mtu=1400 ===",
        now_us() / 1_000_000,
        vip_s
    ));
    let timing = Arc::new(Mutex::new(TimingBuf::new(120)));
    if let Ok(mut t) = timing.lock() {
        t.push("=== session start ===".to_string());
    }
    let stop = Arc::new(AtomicBool::new(false));
    let last_tx = Arc::new(AtomicU64::new(0));

    let mut tls = fr.into_inner();
    tls.get_ref()
        .set_read_timeout(Some(Duration::from_millis(2)))
        .ok();
    // A second handle to the same socket so stop() can shut it down.
    let raw_sock = tls
        .get_ref()
        .try_clone()
        .map_err(|e| format!("socket clone: {e}"))?;

    // TUN -> UDP (preferred) or channel -> TLS pump (fallback)
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    {
        let s = session.clone();
        let routes = routes_raw.clone();
        let udp2 = udp_slot.clone();
        let stop2 = stop.clone();
        // TX throughput sampler for the tps log
        let tx_stat: Arc<Mutex<(u64, u64, u64)>> = Arc::new(Mutex::new((0, 0, 0)));
        let log_tx = log.clone();
        {
            let stat_cell2 = tx_stat.clone();
            let stop3 = stop.clone();
            std::thread::spawn(move || {
                tps_thread("udp-tx", stop3, move || {
                    let mut g = stat_cell2.lock().unwrap();
                    let v = *g;
                    *g = (0, 0, 0);
                    v
                })
            });
        }
        std::thread::spawn(move || loop {
            match s.receive_blocking() {
                Ok(p) => {
                    let bytes = p.bytes().to_vec();
                    drop(p);
                    // Only forward destinations inside the configured intranet
                    // subnets; drop ARP/LLMNR/NetBIOS/mDNS and stray traffic.
                    if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
                        let dst =
                            u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
                        if !routes.iter().any(|(net, mask)| dst & *mask == *net) {
                            continue;
                        }
                        // UDP plane first; on any failure fall back to TCP
                        let plane =
                            udp2.read().ok().and_then(|g| g.as_ref().cloned());
                        if let Some(up) = plane {
                            if let Some(frame) = up.build_packet(&bytes) {
                                if up.sock.send(&frame).is_ok() {
                                    let mut g = tx_stat.lock().unwrap();
                                    g.0 += bytes.len() as u64;
                                    g.1 += 1;
                                    if (bytes.len() as u64) > g.2 {
                                        g.2 = bytes.len() as u64;
                                    }
                                    continue;
                                }
                                // UDP send failed -> permanently downgrade to TCP
                                if let Ok(mut w) = udp2.write() {
                                    *w = None;
                                }
                                log_tx("UDP 发送失败，回退 TCP 数据面");
                            }
                        }
                        if pkt_tx.send(bytes).is_err() {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
            if stop2.load(Ordering::SeqCst) {
                break;
            }
        });
    }

    // UDP RX: dedicated reader; forwards decrypted IPv4 packets into the TUN
    if udp_slot.read().map(|g| g.is_some()).unwrap_or(false) {
        let s = session.clone();
        let udp4 = udp_slot.clone();
        let stop4 = stop.clone();
        let stat_cell = Arc::new(Mutex::new((0u64, 0u64, 0u64)));
        let stat_cell2 = stat_cell.clone();
        let stop5 = stop.clone();
        let log_rx = log.clone();
        std::thread::spawn(move || {
            tps_thread("udp-rx", stop5, move || {
                let mut g = stat_cell2.lock().unwrap();
                let v = *g;
                *g = (0, 0, 0);
                v
            })
        });
        std::thread::spawn(move || {
            let mut rbuf = [0u8; 65535];
            loop {
                if stop4.load(Ordering::SeqCst) {
                    return;
                }
                let plane = match udp4.read() {
                    Ok(g) => match g.as_ref() {
                        Some(p) => p.clone(),
                        None => return, // downgraded to TCP
                    },
                    Err(_) => return,
                };
                match plane.sock.recv(&mut rbuf) {
                    Ok(n) => {
                        if let Some(pkt) = plane.parse_packet(&rbuf[..n]) {
                            if let Ok(mut p) = s.allocate_send_packet(pkt.len() as u16) {
                                p.bytes_mut().copy_from_slice(&pkt);
                                s.send_packet(p);
                            }
                            let mut g = stat_cell.lock().unwrap();
                            g.0 += pkt.len() as u64;
                            g.1 += 1;
                            if (pkt.len() as u64) > g.2 {
                                g.2 = pkt.len() as u64;
                            }
                        }
                    }
                    Err(e) => {
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                        ) {
                            continue;
                        }
                        // UDP channel dead -> downgrade to TCP
                        if let Ok(mut w) = udp4.write() {
                            *w = None;
                        }
                        log_rx("UDP 接收异常，回退 TCP 数据面");
                        return;
                    }
                }
            }
        });
    }

    // Single-owner TLS pump: one thread performs ALL TLS reads and writes,
    // so there is no lock to contend for.
    {
        let s = session.clone();
        let st = stop.clone();
        let last_tx = last_tx.clone();
        let timing2 = timing.clone();
        std::thread::spawn(move || {
            let mut buf: Vec<u8> = Vec::new();
            let mut last_ka = Instant::now();
            // per-second throughput accounting (for upload diagnostics)
            let mut t_start = Instant::now();
            let mut tx_bytes: u64 = 0;
            let mut tx_pkts: u64 = 0;
            let mut rx_bytes: u64 = 0;
            let mut rx_pkts: u64 = 0;
            let mut tx_wait_us: u64 = 0; // time blocked inside write_all
            let mut tx_wait_max: u64 = 0;
            let mut idle_us: u64 = 0; // time blocked in read with nothing to do
            let mut loops: u64 = 0;
            let mut detail_left: u32 = 200; // per-packet samples only at start
            loop {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                loops += 1;
                // 1. drain outgoing packets
                loop {
                    match pkt_rx.try_recv() {
                        Ok(bytes) => {
                            let plen = bytes.len();
                            last_tx.store(now_us(), Ordering::Relaxed);
                            tx_bytes += plen as u64;
                            tx_pkts += 1;
                            let frame = build_legacy(CMD_DATA, &bytes, uid);
                            let t0 = now_us();
                            let r = tls.write_all(&frame);
                            let t1 = now_us();
                            let d = t1 - t0;
                            tx_wait_us += d;
                            if d > tx_wait_max {
                                tx_wait_max = d;
                            }
                            if detail_left > 0 {
                                detail_left -= 1;
                                if let Ok(mut tb) = timing2.lock() {
                                    tb.push(format!("TX write={}us len={}", d, plen));
                                }
                            }
                            if r.is_err() {
                                return;
                            }
                        }
                        Err(std::sync::mpsc::TryRecvError::Empty) => break,
                        Err(std::sync::mpsc::TryRecvError::Disconnected) => return,
                    }
                }
                // keepalive + per-second throughput sample
                if last_ka.elapsed() >= Duration::from_secs(10) {
                    if tls
                        .write_all(&build_legacy(CMD_KEEPALIVE, &[], uid))
                        .is_err()
                    {
                        break;
                    }
                    last_ka = Instant::now();
                }
                if t_start.elapsed() >= Duration::from_secs(1) {
                    let dt = t_start.elapsed().as_secs_f64().max(1e-9);
                    let avg_w = if tx_pkts > 0 { tx_wait_us / tx_pkts } else { 0 };
                    tps_line(&format!(
                        "tx={:.0}KB/s {}pps wavg={}us wmax={}us | rx={:.0}KB/s {}pps | idle={:.0}% loops={}",
                        tx_bytes as f64 / 1024.0,
                        tx_pkts,
                        avg_w,
                        tx_wait_max,
                        rx_bytes as f64 / 1024.0,
                        rx_pkts,
                        idle_us as f64 / (dt * 1e6) * 100.0,
                        loops
                    ));
                    t_start = Instant::now();
                    tx_bytes = 0;
                    tx_pkts = 0;
                    rx_bytes = 0;
                    rx_pkts = 0;
                    tx_wait_us = 0;
                    tx_wait_max = 0;
                    idle_us = 0;
                    loops = 0;
                }
                // 2. read (2ms timeout); forward complete frames to the TUN adapter
                let mut tmp = [0u8; 65536];
                let tr0 = now_us();
                match tls.read(&mut tmp) {
                    Ok(0) => break,
                    Ok(n) => {
                        idle_us += now_us() - tr0;
                        buf.extend_from_slice(&tmp[..n]);
                        while let Some((f, used)) = parse_frame(&buf) {
                            buf.drain(..used);
                            if f.cmd == CMD_DATA {
                                let p = strip_vnic_prefix(&f.payload);
                                let t_rx = now_us();
                                let plen = p.len();
                                rx_bytes += plen as u64;
                                rx_pkts += 1;
                                let mut ok = false;
                                if let Ok(mut pkt) = s.allocate_send_packet(plen as u16) {
                                    pkt.bytes_mut().copy_from_slice(p);
                                    s.send_packet(pkt);
                                    ok = true;
                                }
                                let tx = last_tx.swap(0, Ordering::Relaxed);
                                if tx > 0 && detail_left > 0 {
                                    detail_left -= 1;
                                    if let Ok(mut tb) = timing2.lock() {
                                        tb.push(format!(
                                            "RX rtt={}ms tun_write={}us len={} ok={}",
                                            (t_rx - tx) / 1000,
                                            now_us() - t_rx,
                                            plen,
                                            ok
                                        ));
                                    }
                                }
                            } else if f.cmd == CMD_KICKOUT {
                                return;
                            }
                        }
                        if buf.len() > (1 << 22) {
                            break;
                        }
                    }
                    Err(e) => {
                        // A timeout is normal (we poll the stop flag and the
                        // outbound queue every few ms). Anything else means the
                        // tunnel is gone.
                        let timeout = matches!(
                            e.kind(),
                            std::io::ErrorKind::TimedOut
                                | std::io::ErrorKind::WouldBlock
                                | std::io::ErrorKind::Interrupted
                        );
                        if !timeout {
                            break;
                        }
                        idle_us += now_us() - tr0;
                    }
                }
            }
        });
    }
    log("隧道已建立");

    Ok((
        Session { timer, raw_sock, stop, timing, adapter, session, routes_raw },
        ConnectResult { vip: vip_s, routes: route_strs },
    ))
}
