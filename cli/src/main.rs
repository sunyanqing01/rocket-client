//! rocket-cli — minimal SSL-VPN client (SecoClient / UniVPN compatible, Legacy protocol).
//!
//! Two modes:
//!   * probe  — login, request a virtual IP, print what the gateway hands out
//!   * proxy  — same handshake, then expose a local SOCKS5 server that pushes
//!              traffic through the tunnel using a user-space TCP stack.
//!
//! Why this exists: the reference Go client is built with Go 1.27, which
//! removed RSA key-exchange cipher suites entirely. Gateways of this
//! generation only offer AES256-SHA256 / AES128-SHA (RSA kx), so the Go
//! client fails with "tls: handshake failure". Windows SChannel (used by
//! native-tls) still supports these suites.

mod netstack;
mod tunmode;

use native_tls::{TlsConnector, TlsStream};
use netstack::{pad_small_packet, NetStack};
use smoltcp::iface::SocketHandle;
use smoltcp::socket::tcp;
use smoltcp::wire::Ipv4Address;
use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAGIC_LEGACY1: u32 = 0xFEFC_EFBE;
const MAGIC_V1: u32 = 0xC192_A4D6;
const MAGIC_AUTH: u32 = 0xF0F0_F0F0;

pub(crate) const CMD_ACL: u16 = 0x06;
pub(crate) const CMD_REQVIP: u16 = 0x03;
pub(crate) const CMD_KEEPALIVE: u16 = 0x07;
pub(crate) const CMD_KICKOUT: u16 = 0x08;
pub(crate) const CMD_DATA: u16 = 0x02;

const LEN_SANITY: usize = 4096;

// ---------------------------------------------------------------- frames

#[derive(Debug)]
pub struct Frame {
    pub cmd: u16,
    pub sid: u32,
    pub payload: Vec<u8>,
}

pub(crate) fn build_legacy(cmd: u16, payload: &[u8], sid: u32) -> Vec<u8> {
    let mut b = Vec::with_capacity(16 + payload.len());
    b.extend_from_slice(&MAGIC_LEGACY1.to_be_bytes());
    b.extend_from_slice(&MAGIC_V1.to_be_bytes());
    b.extend_from_slice(&sid.to_be_bytes());
    b.extend_from_slice(&cmd.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

pub(crate) fn parse_frame(b: &[u8]) -> Option<(Frame, usize)> {
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
        return Some((Frame { cmd: b[5] as u16, sid: 0, payload: b[8..8 + len].to_vec() }, 8 + len));
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
        Frame {
            cmd: u16::from_be_bytes([b[12], b[13]]),
            sid: u32::from_be_bytes([b[8], b[9], b[10], b[11]]),
            payload: b[16..16 + len].to_vec(),
        },
        16 + len,
    ))
}

struct FrameReader {
    inner: TlsStream<TcpStream>,
    buf: Vec<u8>,
}

impl FrameReader {
    fn new(inner: TlsStream<TcpStream>) -> Self {
        Self { inner, buf: Vec::new() }
    }

    fn write_frame(&mut self, cmd: u16, payload: &[u8], sid: u32) -> Result<(), String> {
        let b = build_legacy(cmd, payload, sid);
        self.inner.write_all(&b).map_err(|e| format!("write: {e}"))?;
        self.inner.flush().ok();
        Ok(())
    }

    fn into_inner(self) -> TlsStream<TcpStream> {
        self.inner
    }

    fn set_timeout(&self, d: Duration) {
        let _ = self.inner.get_ref().set_read_timeout(Some(d));
        let _ = self.inner.get_ref().set_write_timeout(Some(d.max(Duration::from_secs(5))));
    }

    /// Blocking read of the next frame.
    fn next(&mut self) -> Result<Frame, String> {
        loop {
            if let Some((f, n)) = parse_frame(&self.buf) {
                self.buf.drain(..n);
                return Ok(f);
            }
            let mut tmp = [0u8; 65536];
            let n = self.inner.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
            if n == 0 {
                return Err("connection closed by peer".into());
            }
            self.buf.extend_from_slice(&tmp[..n]);
            if self.buf.len() > (1 << 22) {
                return Err("frame buffer overflow".into());
            }
        }
    }

    /// Non-blocking-ish read: returns None when nothing is available.
    fn try_next(&mut self) -> Option<Frame> {
        if let Some((f, n)) = parse_frame(&self.buf) {
            self.buf.drain(..n);
            return Some(f);
        }
        let mut tmp = [0u8; 65536];
        match self.inner.read(&mut tmp) {
            Ok(0) => None,
            Ok(n) => {
                self.buf.extend_from_slice(&tmp[..n]);
                if let Some((f, cn)) = parse_frame(&self.buf) {
                    self.buf.drain(..cn);
                    return Some(f);
                }
                None
            }
            Err(_) => None,
        }
    }
}

// ---------------------------------------------------------------- tls

fn tls_connect(host: &str, port: u16, insecure: bool) -> Result<TlsStream<TcpStream>, String> {
    let tcp = TcpStream::connect((host, port)).map_err(|e| format!("tcp connect: {e}"))?;
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(20))).ok();

    let mut b = TlsConnector::builder();
    b.danger_accept_invalid_certs(insecure);
    b.danger_accept_invalid_hostnames(insecure);
    let conn = b.build().map_err(|e| format!("tls init: {e}"))?;
    conn.connect(host, tcp).map_err(|e| format!("tls handshake: {e}"))
}

// ---------------------------------------------------------------- login

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

fn login(host: &str, port: u16, user: &str, pass: &str, mac: &str, insecure: bool) -> Result<u32, String> {
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
         Accept: image/gif, image/x-xbitmap, image/jpeg, image/pjpeg, application/msword, application/vnd.ms-excel, application/vnd.ms-powerpoint, */*\r\n\
         Accept-Language: zh-cn\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; NT 5.1; SV1; .NET CLR 2.0.50727)\r\n\
         OS=Windows64\r\n\
         Host: {host}:{port}\r\n\r\n"
    );
    s.write_all(req.as_bytes()).map_err(|e| format!("send login: {e}"))?;
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
        return Err(format!("short auth reply ({} bytes)", buf.len()));
    }
    let magic = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if magic != MAGIC_AUTH {
        return Err(format!("unexpected auth reply magic={magic:08x}"));
    }
    let res = i32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if res < 0 {
        return Err(format!("auth rejected, code={res}"));
    }
    if buf.len() < 48 {
        return Err(format!("short auth success ({} bytes)", buf.len()));
    }
    Ok(u32::from_be_bytes([buf[44], buf[45], buf[46], buf[47]]))
}

// ---------------------------------------------------------------- netcfg

#[derive(Debug, Default)]
struct NetCfg {
    vip: [u8; 4],
    mask: [u8; 4],
    dns: Vec<[u8; 4]>,
    routes: Vec<([u8; 4], [u8; 4])>,
}

fn ip4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

fn parse_netcfg(p: &[u8]) -> Result<NetCfg, String> {
    if p.len() < 8 {
        return Err(format!("reqvip payload too short ({})", p.len()));
    }
    let mut c = NetCfg { vip: ip4(&p[0..4]), mask: ip4(&p[4..8]), ..Default::default() };
    if p.len() >= 172 {
        for i in 0..3 {
            let a = ip4(&p[160 + 4 * i..164 + 4 * i]);
            if a != [0, 0, 0, 0] {
                c.dns.push(a);
            }
        }
    }
    if p.len() >= 188 {
        let n = u32::from_be_bytes([p[184], p[185], p[186], p[187]]) as usize;
        if n > 0 && n <= 0x400 && p.len() >= 188 + 12 * n {
            for i in 0..n {
                let e = &p[188 + 12 * i..200 + 12 * i];
                c.routes.push((ip4(&e[0..4]), ip4(&e[4..8])));
            }
        }
    }
    Ok(c)
}

// ---------------------------------------------------------------- icmp

fn csum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_icmp_echo(src: [u8; 4], dst: [u8; 4], id: u16, seq: u16) -> Vec<u8> {
    let payload = 32usize;
    let total = 20 + 8 + payload;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[4..6].copy_from_slice(&id.to_be_bytes());
    p[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    p[8] = 64;
    p[9] = 1;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let h = csum(&p[..20]);
    p[10..12].copy_from_slice(&h.to_be_bytes());
    p[20] = 8;
    p[24..26].copy_from_slice(&id.to_be_bytes());
    p[26..28].copy_from_slice(&seq.to_be_bytes());
    for i in 0..payload {
        p[28 + i] = b'a' + (i % 26) as u8;
    }
    let ic = csum(&p[20..]);
    p[22..24].copy_from_slice(&ic.to_be_bytes());
    p
}

pub(crate) fn strip_vnic_prefix(p: &[u8]) -> &[u8] {
    if p.len() >= 20 && p[0] >> 4 == 4 {
        return p;
    }
    if p.len() >= 22 && p[2] >> 4 == 4 {
        return &p[2..];
    }
    p
}

fn parse_ipv4(s: &str) -> Result<[u8; 4], String> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return Err(format!("bad ipv4: {s}"));
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        out[i] = p.parse::<u8>().map_err(|_| format!("bad ipv4: {s}"))?;
    }
    Ok(out)
}

fn resolve_host(host: &str) -> Option<Ipv4Address> {
    use std::net::ToSocketAddrs;
    match (host, 0u16).to_socket_addrs() {
        Ok(iter) => {
            for a in iter {
                if let std::net::IpAddr::V4(v4) = a.ip() {
                    let o = v4.octets();
                    return Some(Ipv4Address::new(o[0], o[1], o[2], o[3]));
                }
            }
            None
        }
        Err(_) => None,
    }
}

// ---------------------------------------------------------------- socks5

enum Stage {
    Greeting,
    Request,
    Connecting,
    Forward,
}

struct Conn {
    stream: TcpStream,
    stage: Stage,
    inbuf: Vec<u8>,
    outbuf: Vec<u8>,
    handle: Option<SocketHandle>,
    started: Instant,
    socks_replied: bool,
    remote_closed: bool,
    direct: bool,
}

struct ForwardSpec {
    listen_port: u16,
    dst: Ipv4Address,
    dst_port: u16,
}

fn socks_reply_ok(stream: &mut TcpStream, vip: [u8; 4]) {
    let mut r = vec![0x05, 0x00, 0x00, 0x01];
    r.extend_from_slice(&vip);
    r.extend_from_slice(&[0, 0]);
    let _ = stream.write_all(&r);
}

fn socks_reply_err(stream: &mut TcpStream, code: u8) {
    let _ = stream.write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
}

// ---------------------------------------------------------------- proxy loop

fn run_proxy(
    ns: &mut NetStack,
    listener: TcpListener,
    fr: &mut FrameReader,
    uid: u32,
    vip: [u8; 4],
    verbose: bool,
    forwards: Vec<ForwardSpec>,
) -> Result<(), String> {
    listener.set_nonblocking(true).ok();
    fr.set_timeout(Duration::from_millis(5));

    let mut fwd_listeners: Vec<(TcpListener, Ipv4Address, u16)> = Vec::new();
    for f in &forwards {
        match TcpListener::bind(("127.0.0.1", f.listen_port)) {
            Ok(l) => {
                l.set_nonblocking(true).ok();
                println!("port forward   127.0.0.1:{} -> {}:{}", f.listen_port, f.dst, f.dst_port);
                fwd_listeners.push((l, f.dst, f.dst_port));
            }
            Err(e) => eprintln!("cannot bind 127.0.0.1:{}: {e}", f.listen_port),
        }
    }

    let mut conns: Vec<Conn> = Vec::new();
    let mut last_keepalive = Instant::now();
    let mut total_rx: u64 = 0;
    let mut total_tx: u64 = 0;

    println!("SOCKS5 listening, press Ctrl+C to stop");
    println!("Press Ctrl+C to stop.\n");

    loop {
        // 1. Pull packets out of the tunnel.
        for _ in 0..32 {
            match fr.try_next() {
                Some(f) if f.cmd == CMD_DATA => {
                    let p = strip_vnic_prefix(&f.payload).to_vec();
                    if !p.is_empty() {
                        total_rx += p.len() as u64;
                        ns.device.rx.push_back(p);
                    }
                }
                Some(f) if f.cmd == CMD_KICKOUT => {
                    return Err("kicked by gateway".into());
                }
                Some(_) => {}
                None => break,
            }
        }
        // keep draining whatever arrived inside the same TLS record
        while let Some((f, _n)) = {
            let peek = parse_frame(&fr.buf);
            peek
        } {
            let _ = f;
            break;
        }

        // 2. Let the stack process.
        ns.poll();

        // 3. Whatever the stack wants to send goes into the tunnel.
        while let Some(pkt) = ns.device.tx.pop_front() {
            let mut p = pkt;
            pad_small_packet(&mut p);
            total_tx += p.len() as u64;
            fr.write_frame(CMD_DATA, &p, uid)?;
        }

        // 4. Accept new SOCKS clients.
        loop {
            match listener.accept() {
                Ok((s, _addr)) => {
                    s.set_nonblocking(true).ok();
                    s.set_nodelay(true).ok();
                    conns.push(Conn {
                        stream: s,
                        stage: Stage::Greeting,
                        inbuf: Vec::new(),
                        outbuf: Vec::new(),
                        handle: None,
                        started: Instant::now(),
                        socks_replied: false,
                        remote_closed: false,
                        direct: false,
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }

        // 4b. Accept on static forward ports (no SOCKS handshake).
        for k in 0..fwd_listeners.len() {
            loop {
                match fwd_listeners[k].0.accept() {
                    Ok((s, _addr)) => {
                        s.set_nonblocking(true).ok();
                        s.set_nodelay(true).ok();
                        let dst = fwd_listeners[k].1;
                        let port = fwd_listeners[k].2;
                        let lp = fwd_listeners[k].0.local_addr().map(|a| a.port()).unwrap_or(0);
                        match ns.connect(dst, port) {
                            Some(h) => {
                                println!("[fwd] local:{lp} -> {dst}:{port}");
                                conns.push(Conn {
                                    stream: s,
                                    stage: Stage::Connecting,
                                    inbuf: Vec::new(),
                                    outbuf: Vec::new(),
                                    handle: Some(h),
                                    started: Instant::now(),
                                    socks_replied: true,
                                    remote_closed: false,
                                    direct: true,
                                });
                            }
                            None => eprintln!("[fwd] cannot connect {dst}:{port}"),
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }

        // 5. Drive every connection.
        let mut dead: Vec<usize> = Vec::new();
        for i in 0..conns.len() {
            // --- local -> rocket ---
            let mut tmp = [0u8; 16384];
            loop {
                match conns[i].stream.read(&mut tmp) {
                    Ok(0) => {
                        conns[i].remote_closed = true;
                        break;
                    }
                    Ok(n) => {
                        conns[i].inbuf.extend_from_slice(&tmp[..n]);
                        if conns[i].inbuf.len() > 512 * 1024 {
                            break;
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(_) => {
                        conns[i].remote_closed = true;
                        break;
                    }
                }
            }

            // --- state machine ---
            match conns[i].stage {
                Stage::Greeting => {
                    if conns[i].inbuf.len() >= 2 {
                        let nm = conns[i].inbuf[1] as usize;
                        if conns[i].inbuf.len() >= 2 + nm {
                            if verbose {
                                println!("[socks] greeting {:02x?}", &conns[i].inbuf[..2 + nm]);
                            }
                            let _ = conns[i].stream.write_all(&[0x05, 0x00]);
                            // Drain only the greeting; a pipelined request may follow.
                            conns[i].inbuf.drain(..2 + nm);
                            conns[i].stage = Stage::Request;
                        }
                    }
                }
                Stage::Request => {
                    if conns[i].inbuf.len() >= 4 {
                        let b = conns[i].inbuf.clone();
                        if b[0] != 0x05 || b[1] != 0x01 {
                            if verbose {
                                println!("[socks] unsupported cmd: {:02x?}", &b[..b.len().min(16)]);
                            }
                            socks_reply_err(&mut conns[i].stream, 0x07);
                            dead.push(i);
                            continue;
                        }
                        let parsed: Option<(Ipv4Address, u16, usize)> = match b[3] {
                            0x01 => {
                                if b.len() < 10 {
                                    None
                                } else {
                                    Some((
                                        Ipv4Address::new(b[4], b[5], b[6], b[7]),
                                        u16::from_be_bytes([b[8], b[9]]),
                                        10,
                                    ))
                                }
                            }
                            0x03 => {
                                let l = b.get(4).copied().unwrap_or(0) as usize;
                                if b.len() < 5 + l + 2 {
                                    None
                                } else {
                                    let host = String::from_utf8_lossy(&b[5..5 + l]).to_string();
                                    let port = u16::from_be_bytes([b[5 + l], b[6 + l]]);
                                    if verbose {
                                        println!("[socks] domain request: {host}:{port}");
                                    }
                                    match resolve_host(&host) {
                                        Some(ip) => Some((ip, port, 5 + l + 2)),
                                        None => {
                                            println!("[socks] cannot resolve {host}");
                                            socks_reply_err(&mut conns[i].stream, 0x04);
                                            dead.push(i);
                                            continue;
                                        }
                                    }
                                }
                            }
                            _ => {
                                if verbose {
                                    println!(
                                        "[socks] unsupported atyp {}: {:02x?}",
                                        b[3],
                                        &b[..b.len().min(16)]
                                    );
                                }
                                socks_reply_err(&mut conns[i].stream, 0x08);
                                dead.push(i);
                                continue;
                            }
                        };

                        if let Some((dst, port, need)) = parsed {
                            if verbose {
                                println!("[socks] CONNECT {dst}:{port}  raw={:02x?}", &b[..need]);
                            }
                            conns[i].inbuf.drain(..need);
                            match ns.connect(dst, port) {
                                Some(h) => {
                                    conns[i].handle = Some(h);
                                    conns[i].stage = Stage::Connecting;
                                    println!("[conn] -> {}:{}", dst, port);
                                }
                                None => {
                                    socks_reply_err(&mut conns[i].stream, 0x05);
                                    dead.push(i);
                                }
                            }
                        }
                    }
                }
                Stage::Connecting => {
                    if let Some(h) = conns[i].handle {
                        let st = ns.sockets.get_mut::<tcp::Socket>(h).state();
                        match st {
                            tcp::State::Established => {
                                if !conns[i].direct && !conns[i].socks_replied {
                                    socks_reply_ok(&mut conns[i].stream, vip);
                                    conns[i].socks_replied = true;
                                }
                                conns[i].stage = Stage::Forward;
                            }
                            tcp::State::Closed | tcp::State::TimeWait | tcp::State::Closing => {
                                if !conns[i].direct && !conns[i].socks_replied {
                                    socks_reply_err(&mut conns[i].stream, 0x05);
                                }
                                dead.push(i);
                            }
                            _ => {
                                if conns[i].started.elapsed() > Duration::from_secs(10) {
                                    if !conns[i].direct {
                                        socks_reply_err(&mut conns[i].stream, 0x06);
                                    }
                                    dead.push(i);
                                }
                            }
                        }
                    }
                }
                Stage::Forward => {
                    let h = match conns[i].handle {
                        Some(h) => h,
                        None => {
                            dead.push(i);
                            continue;
                        }
                    };

                    // smoltcp -> local
                    {
                        let sock = ns.sockets.get_mut::<tcp::Socket>(h);
                        while sock.can_recv() {
                            let mut buf = [0u8; 16384];
                            match sock.recv_slice(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    if conns[i].stream.write_all(&buf[..n]).is_err() {
                                        dead.push(i);
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                    }
                    if dead.contains(&i) {
                        continue;
                    }

                    // local -> smoltcp
                    if !conns[i].inbuf.is_empty() {
                        let data = std::mem::take(&mut conns[i].inbuf);
                        let sock = ns.sockets.get_mut::<tcp::Socket>(h);
                        let mut off = 0;
                        while off < data.len() {
                            if !sock.can_send() {
                                break;
                            }
                            match sock.send_slice(&data[off..]) {
                                Ok(0) => break,
                                Ok(n) => off += n,
                                Err(_) => break,
                            }
                        }
                        if off < data.len() {
                            conns[i].inbuf.extend_from_slice(&data[off..]);
                        }
                    }

                    // teardown
                    let sock = ns.sockets.get_mut::<tcp::Socket>(h);
                    if conns[i].remote_closed && sock.send_queue() == 0 {
                        sock.close();
                    }
                    if !sock.is_open() {
                        dead.push(i);
                    }
                }
            }
        }

        // 6. Reap dead connections.
        dead.sort_unstable();
        dead.dedup();
        for i in dead.into_iter().rev() {
            if let Some(c) = conns.get(i) {
                if let Some(h) = c.handle {
                    ns.remove(h);
                }
            }
            if i < conns.len() {
                conns.remove(i);
            }
        }

        // 7. Control-channel keepalive.
        if last_keepalive.elapsed() >= Duration::from_secs(10) {
            fr.write_frame(CMD_KEEPALIVE, &[], uid)?;
            last_keepalive = Instant::now();
            let _ = (total_rx, total_tx);
        }

        std::thread::sleep(Duration::from_millis(2));
    }
}

// ---------------------------------------------------------------- main

fn usage() {
    eprintln!(
        "rocket-cli 0.2.0 — SSL VPN client (Legacy protocol, SecoClient/UniVPN compatible)\n\
         \n\
         Usage:\n\
         \x20 rocket-cli -gateway HOST:PORT -user NAME -password PASS [options]\n\
         \n\
         Options:\n\
         \x20 -gateway   gateway host:port (required), e.g. gateway.example.com:21443\n\
         \x20 -user      account (required)\n\
         \x20 -password  password (required)\n\
         \x20 -mac       client MAC, 12 hex chars (default: local NIC MAC)\n\
         \x20 -insecure  skip TLS certificate verification (self-signed gateways)\n\
         \x20 -tun       create a virtual adapter and route only -route subnets (admin)\n\
         \x20 -route     intranet CIDR to send through the adapter, e.g. 10.0.0.0/8\n\
         \x20 -socks     run a SOCKS5 proxy on this address, e.g. 127.0.0.1:1080\n\
         \x20 -forward   static forward LOCALPORT:DSTIP:DSTPORT (repeatable)\n\
         \x20 -ping IP   send one ICMP echo through the tunnel and exit\n\
         \x20 -dump FILE write the raw REQVIP reply payload to FILE\n\
         \x20 -verbose   print protocol details\n"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut gateway = String::new();
    let mut user = String::new();
    let mut password = String::new();
    let mut mac = String::from("D853BC3D99AB");
    let mut insecure = false;
    let mut verbose = false;
    let mut ping_ip: Option<String> = None;
    let mut dump_file: Option<String> = None;
    let mut socks_addr: Option<String> = None;
    let mut forwards: Vec<ForwardSpec> = Vec::new();
    let mut tun_mode = false;
    let mut route_args: Vec<(u32, u32)> = Vec::new();

    let mut i = 1;
    while i < args.len() {
        let take = |i: &mut usize| -> String {
            *i += 1;
            args.get(*i).cloned().unwrap_or_default()
        };
        match args[i].as_str() {
            "-gateway" => gateway = take(&mut i),
            "-user" => user = take(&mut i),
            "-password" => password = take(&mut i),
            "-mac" => mac = take(&mut i),
            "-ping" => ping_ip = Some(take(&mut i)),
            "-dump" => dump_file = Some(take(&mut i)),
            "-tun" => tun_mode = true,
            "-route" => {
                let v = take(&mut i);
                match tunmode::parse_cidr(&v) {
                    Some(r) => route_args.push(r),
                    None => {
                        eprintln!("bad -route {v}, expected CIDR like 10.0.0.0/8");
                        exit(2);
                    }
                }
            }
            "-socks" => socks_addr = Some(take(&mut i)),
            "-forward" => {
                let v = take(&mut i);
                let parts: Vec<&str> = v.split(':').collect();
                if parts.len() != 3 {
                    eprintln!("bad -forward {v}, expected LOCALPORT:DSTIP:DSTPORT");
                    exit(2);
                }
                let lp: u16 = match parts[0].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("bad local port in {v}");
                        exit(2);
                    }
                };
                let dst = match parse_ipv4(parts[1]) {
                    Ok(a) => Ipv4Address::new(a[0], a[1], a[2], a[3]),
                    Err(_) => match resolve_host(parts[1]) {
                        Some(a) => a,
                        None => {
                            eprintln!("bad destination in {v}");
                            exit(2);
                        }
                    },
                };
                let dp: u16 = match parts[2].parse() {
                    Ok(p) => p,
                    Err(_) => {
                        eprintln!("bad dest port in {v}");
                        exit(2);
                    }
                };
                forwards.push(ForwardSpec { listen_port: lp, dst, dst_port: dp });
            }
            "-insecure" => insecure = true,
            "-verbose" => verbose = true,
            "-h" | "--help" => {
                usage();
                return;
            }
            other => {
                eprintln!("unknown argument: {other}");
                usage();
                exit(2);
            }
        }
        i += 1;
    }

    if gateway.is_empty() || user.is_empty() {
        usage();
        exit(2);
    }

    let (host, port) = match gateway.rsplit_once(':') {
        Some((h, p)) => match p.parse::<u16>() {
            Ok(p) => (h.to_string(), p),
            Err(_) => {
                eprintln!("bad port in gateway: {gateway}");
                exit(2);
            }
        },
        None => (gateway.clone(), 443),
    };

    println!("gateway : {host}:{port}");
    println!("account : {user}");
    println!("mac     : {mac}\n");

    print!("[1/3] login ... ");
    std::io::stdout().flush().ok();
    let uid = match login(&host, port, &user, &password, &mac, insecure) {
        Ok(u) => {
            println!("ok, session id = 0x{u:08x}");
            u
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("\n  {e}");
            exit(1);
        }
    };

    print!("[2/3] control channel ... ");
    std::io::stdout().flush().ok();
    let stream = match tls_connect(&host, port, insecure) {
        Ok(s) => {
            println!("ok");
            s
        }
        Err(e) => {
            println!("FAILED");
            eprintln!("\n  {e}");
            exit(1);
        }
    };
    let mut fr = FrameReader::new(stream);

    if let Err(e) = fr.write_frame(CMD_ACL, &[0, 0, 0, 0], uid) {
        eprintln!("acl send failed: {e}");
        exit(1);
    }
    loop {
        match fr.next() {
            Ok(f) if f.cmd == CMD_ACL => break,
            Ok(f) if f.cmd == CMD_KICKOUT => {
                eprintln!("kicked by gateway during ACL");
                exit(1);
            }
            Ok(f) => {
                if verbose {
                    println!("  (skip cmd=0x{:02x} len={})", f.cmd, f.payload.len());
                }
            }
            Err(e) => {
                eprintln!("acl read failed: {e}");
                exit(1);
            }
        }
    }

    print!("[3/3] request virtual IP ... ");
    std::io::stdout().flush().ok();
    if let Err(e) = fr.write_frame(CMD_REQVIP, &[], uid) {
        eprintln!("reqvip send failed: {e}");
        exit(1);
    }
    let vipf = loop {
        match fr.next() {
            Ok(f) if f.cmd == CMD_REQVIP => break f,
            Ok(_) => {}
            Err(e) => {
                eprintln!("reqvip read failed: {e}");
                exit(1);
            }
        }
    };
    let cfg = match parse_netcfg(&vipf.payload) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("parse failed: {e}");
            exit(1);
        }
    };
    println!("ok\n");

    println!("assigned address : {}.{}.{}.{}", cfg.vip[0], cfg.vip[1], cfg.vip[2], cfg.vip[3]);
    println!("mask             : {}.{}.{}.{}", cfg.mask[0], cfg.mask[1], cfg.mask[2], cfg.mask[3]);
    println!("routes           : {}", cfg.routes.len());

    if let Some(path) = &dump_file {
        match std::fs::write(path, &vipf.payload) {
            Ok(_) => println!("\nREQVIP payload ({} bytes) written to {path}", vipf.payload.len()),
            Err(e) => eprintln!("\ncannot write {path}: {e}"),
        }
    }

    // ---- optional ICMP probe ----
    if let Some(target) = ping_ip {
        let dst = match parse_ipv4(&target) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("{e}");
                exit(2);
            }
        };
        println!("\n=== data-plane test: ICMP echo -> {target} ===");
        fr.set_timeout(Duration::from_secs(2));
        let id: u16 = 0x4849;
        let mut replied = false;
        for seq in 1..=3u16 {
            let pkt = build_icmp_echo(cfg.vip, dst, id, seq);
            if fr.write_frame(CMD_DATA, &pkt, uid).is_err() {
                break;
            }
            let t0 = Instant::now();
            while t0.elapsed() < Duration::from_secs(3) {
                if let Ok(f) = fr.next() {
                    if f.cmd == CMD_DATA {
                        let p = strip_vnic_prefix(&f.payload);
                        if p.len() >= 28 && p[9] == 1 && p[20] == 0 {
                            let s = &p[12..16];
                            println!(
                                "  seq={seq} reply from {}.{}.{}.{} ttl={} in {} ms",
                                s[0], s[1], s[2], s[3], p[8], t0.elapsed().as_millis()
                            );
                            replied = true;
                            break;
                        }
                    }
                }
            }
            if replied {
                break;
            }
            std::thread::sleep(Duration::from_millis(300));
        }
        println!(
            "{}",
            if replied {
                "Data plane OK — packets flow through the tunnel."
            } else {
                "No ICMP reply (target may block ICMP)."
            }
        );
        if socks_addr.is_none() {
            return;
        }
    }

    // ---- TUN mode: precise routes only ----
    if tun_mode {
        let routes = if route_args.is_empty() {
            vec![
                tunmode::parse_cidr("10.0.0.0/8").unwrap(),
                tunmode::parse_cidr("172.16.0.0/12").unwrap(),
                tunmode::parse_cidr("192.0.2.0/24").unwrap(),
            ]
        } else {
            route_args
        };
        let stream = fr.into_inner();
        let tunnel = Arc::new(tunmode::Tunnel::new(stream, uid));
        if let Err(e) = tunmode::run(tunnel, cfg.vip, routes) {
            eprintln!("\nTUN mode failed: {e}");
            exit(1);
        }
        return;
    }

    // ---- SOCKS5 proxy mode ----
    if let Some(addr) = socks_addr {
        let listener = match TcpListener::bind(&addr) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("bind {addr}: {e}");
                exit(1);
            }
        };
        println!("\nSOCKS5 proxy on {addr}  (tunnel vip {}.{}.{}.{})", cfg.vip[0], cfg.vip[1], cfg.vip[2], cfg.vip[3]);
        let mut ns = NetStack::new(cfg.vip);
        if let Err(e) = run_proxy(&mut ns, listener, &mut fr, uid, cfg.vip, verbose, forwards) {
            eprintln!("\nproxy stopped: {e}");
            exit(1);
        }
    }
}
