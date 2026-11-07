//! Platform-neutral protocol core: legacy frame codec, TLS login, the UDP
//! data plane (mode 3) and diagnostics helpers. No Windows dependencies.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Mutex;
use std::time::Duration;

// ---------------------------------------------------------------- constants

pub const MAGIC_LEGACY1: u32 = 0xFEFC_EFBE;
pub const MAGIC_V1: u32 = 0xC192_A4D6;
pub const MAGIC_AUTH: u32 = 0xF0F0_F0F0;

pub const CMD_ACL: u16 = 0x06;
pub const CMD_REQVIP: u16 = 0x03;
pub const CMD_KEEPALIVE: u16 = 0x07;
pub const CMD_KICKOUT: u16 = 0x08;
pub const CMD_DATA: u16 = 0x02;
// UDP data-plane negotiation (Legacy mode 3), protocol identical to UniSpoke.
pub const CMD_UDP_KEY: u16 = 0x0D;
pub const CMD_UDP_PORT: u16 = 0x1A;
pub const DEFAULT_UDP_PORT: u16 = 443;

pub const LEN_SANITY: usize = 4096;

pub fn now_us() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

// --------------------------------------------------------------- diagnostics

/// Append one line to the per-second throughput log. Called at most once per
/// second from the pump thread, so the cost (open+write+close) is irrelevant,
/// but it survives a crash or a force-kill — unlike the on-disconnect dump.
pub fn tps_line(line: &str) {
    use std::io::Write;
    let path = std::env::temp_dir().join("rocket-tps.log");
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{line}");
    }
}

pub struct TimingBuf {
    lines: Vec<String>,
    limit: usize,
}

impl TimingBuf {
    pub fn new(limit: usize) -> Self {
        Self { lines: Vec::new(), limit }
    }
    pub fn push(&mut self, line: String) {
        if self.lines.len() < self.limit {
            self.lines.push(line);
        }
    }
}

/// Write collected samples to the timing log (call on disconnect only, never
/// on the data path).
pub fn dump_timing(buf: &TimingBuf) {
    use std::io::Write;
    let path = std::env::temp_dir().join("rocket-timing.log");
    if let Ok(mut f) = std::fs::File::create(&path) {
        for l in &buf.lines {
            let _ = writeln!(f, "{l}");
        }
        let _ = writeln!(f, "=== end of session ({} samples) ===", buf.lines.len());
    }
}

// ------------------------------------------------------- AES-128-CBC (UDP plane)

/// Zero-padded AES-128-CBC encrypt (protocol uses zero padding, not PKCS7).
pub fn aes_cbc_encrypt(key: &[u8; 16], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
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
pub fn aes_cbc_decrypt(key: &[u8; 16], iv: &[u8; 16], ct: &[u8]) -> Option<Vec<u8>> {
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
pub struct FastRng(u64);
impl FastRng {
    pub fn next_u32(&mut self) -> u32 {
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
pub struct UdpPlane {
    pub sock: std::net::UdpSocket,
    key: [u8; 16],
    uid: u32,
    rng: Mutex<FastRng>,
}

pub const UDP_MAGIC: [u8; 8] = [0xFE, 0xFC, 0xEF, 0xBE, 0xC1, 0x92, 0xA4, 0xD6];
pub const UDP_HDR: usize = 28;
pub const UDP_IPHDR: usize = 20;

impl UdpPlane {
    pub fn build_packet(&self, pkt: &[u8]) -> Option<Vec<u8>> {
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
    pub fn parse_packet(&self, buf: &[u8]) -> Option<Vec<u8>> {
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

/// Ask the gateway (over the TCP control channel) for the UDP data plane.
/// Legacy mode 3: CMD 0x1A -> UDP port, CMD 0x0D -> mode + 16-byte AES key.
pub fn negotiate_udp(
    fr: &mut FrameReader,
    host: &str,
    uid: u32,
) -> Result<UdpPlane, String> {
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

// ------------------------------------------------------------------- frames

#[derive(Debug)]
pub struct Frame {
    pub cmd: u16,
    pub payload: Vec<u8>,
}

pub fn build_legacy(cmd: u16, payload: &[u8], sid: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + payload.len());
    b.extend_from_slice(&MAGIC_LEGACY1.to_be_bytes());
    b.extend_from_slice(&MAGIC_V1.to_be_bytes());
    b.extend_from_slice(&sid.to_be_bytes());
    b.extend_from_slice(&cmd.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

pub fn parse_frame(b: &[u8]) -> Option<(Frame, usize)> {
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

pub fn strip_vnic_prefix(p: &[u8]) -> &[u8] {
    if p.len() >= 20 && p[0] >> 4 == 4 {
        return p;
    }
    if p.len() >= 22 && p[2] >> 4 == 4 {
        return &p[2..];
    }
    p
}

pub fn url_escape(s: &str) -> String {
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

pub fn ip_str(v: u32) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

pub fn parse_cidr(s: &str) -> Option<(u32, u32)> {
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

// ------------------------------------------------------------------ TLS link

/// Object-safe read+write stream so the TLS backend can vary per platform
/// (SChannel via native-tls on Windows, OpenSSL on macOS for the legacy RSA
/// key exchange the gateway still requires).
pub trait TunnelIo: Read + Write + Send {}
impl<T: Read + Write + Send> TunnelIo for T {}

pub struct TlsLink {
    pub io: Box<dyn TunnelIo>,
    /// A second handle to the same socket (for timeouts and shutdown).
    pub raw: TcpStream,
}

#[cfg(windows)]
pub fn tls_connect(host: &str, port: u16, insecure: bool) -> Result<TlsLink, String> {
    let tcp = TcpStream::connect((host, port))
        .map_err(|e| format!("无法连接网关 {host}:{port} — {e}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let mut b = native_tls::TlsConnector::builder();
    b.danger_accept_invalid_certs(insecure);
    b.danger_accept_invalid_hostnames(insecure);
    let conn = b.build().map_err(|e| format!("TLS 初始化失败: {e}"))?;
    let s: native_tls::TlsStream<TcpStream> =
        conn.connect(host, tcp).map_err(|e| format!("TLS 握手失败: {e}"))?;
    let raw = s.get_ref().try_clone().map_err(|e| format!("socket clone: {e}"))?;
    Ok(TlsLink { io: Box::new(s), raw })
}

#[cfg(target_os = "macos")]
pub fn tls_connect(host: &str, port: u16, insecure: bool) -> Result<TlsLink, String> {
    use openssl::ssl::{SslConnector, SslMethod, SslStream, SslVerifyMode};
    let tcp = TcpStream::connect((host, port))
        .map_err(|e| format!("无法连接网关 {host}:{port} — {e}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let mut b = SslConnector::builder(SslMethod::tls())
        .map_err(|e| format!("TLS 初始化失败: {e}"))?;
    // The gateway is ancient: it only offers static-RSA key exchange, which
    // modern defaults exclude. Enable the full legacy suite and allow TLS 1.0.
    b.set_cipher_list("ALL:@SECLEVEL=0").map_err(|e| format!("TLS 套件设置失败: {e}"))?;
    if insecure {
        b.set_verify(SslVerifyMode::NONE);
    }
    let connector = b.build();
    let setup = connector.configure().map_err(|e| format!("TLS 配置失败: {e}"))?;
    let s: SslStream<TcpStream> =
        setup.connect(host, tcp).map_err(|e| format!("TLS 握手失败: {e}"))?;
    let raw = s.get_ref().try_clone().map_err(|e| format!("socket clone: {e}"))?;
    Ok(TlsLink { io: Box::new(s), raw })
}

pub struct FrameReader {
    inner: Box<dyn TunnelIo>,
    buf: Vec<u8>,
}

impl FrameReader {
    pub fn new(inner: Box<dyn TunnelIo>) -> Self {
        Self { inner, buf: Vec::new() }
    }

    pub fn into_inner(self) -> Box<dyn TunnelIo> {
        self.inner
    }

    pub fn write_frame(&mut self, cmd: u16, payload: &[u8], sid: u32) -> Result<(), String> {
        let b = build_legacy(cmd, payload, sid);
        self.inner.write_all(&b).map_err(|e| format!("隧道写入失败: {e}"))?;
        self.inner.flush().ok();
        Ok(())
    }

    pub fn next(&mut self) -> Result<Frame, String> {
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

// --------------------------------------------------------------------- login

pub struct NetCfg {
    pub vip: [u8; 4],
}

pub fn parse_netcfg(p: &[u8]) -> Result<NetCfg, String> {
    if p.len() < 8 {
        return Err(format!("REQVIP 响应过短（{} 字节）", p.len()));
    }
    Ok(NetCfg { vip: [p[0], p[1], p[2], p[3]] })
}

pub fn login(
    host: &str,
    port: u16,
    user: &str,
    pass: &str,
    mac: &str,
    insecure: bool,
) -> Result<u32, String> {
    let mut link = tls_connect(host, port, insecure)?;
    let io = &mut link.io;
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
    io.write_all(req.as_bytes()).map_err(|e| format!("发送登录请求失败: {e}"))?;
    io.flush().ok();

    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    loop {
        match io.read(&mut tmp) {
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

// ----------------------------------------------------------------- local MAC

/// Best-effort MAC of this machine, formatted as 12 uppercase hex chars.
pub fn local_mac() -> String {
    #[cfg(windows)]
    {
        let out = match std::process::Command::new("getmac")
            .args(["/fo", "csv", "/nh"])
            .output()
        {
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
    #[cfg(target_os = "macos")]
    {
        let out = match std::process::Command::new("ifconfig").output() {
            Ok(o) => o.stdout,
            Err(_) => return String::new(),
        };
        let text = String::from_utf8_lossy(&out);
        for line in text.lines() {
            let line = line.trim();
            if let Some(idx) = line.find("ether ") {
                let t: String = line[idx + 6..]
                    .chars()
                    .take(17)
                    .filter(|c| c.is_ascii_hexdigit())
                    .collect();
                if t.len() == 12 && !t.chars().all(|c| c == '0') {
                    return t.to_uppercase();
                }
            }
        }
        String::new()
    }
    #[cfg(not(any(windows, target_os = "macos")))]
    {
        String::new()
    }
}
