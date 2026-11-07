//! SSL-VPN orchestrator: protocol (protocol.rs) + virtual NIC (device.rs).
//! Windows uses Wintun/SChannel; macOS uses utun/OpenSSL. The data path is
//! identical: TUN -> UDP (mode 3) preferred, TLS frames as fallback.

use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

pub mod device;
pub mod protocol;

pub use protocol::local_mac;

use protocol::{
    dump_timing, login, negotiate_udp, now_us, parse_cidr, parse_frame, parse_netcfg,
    strip_vnic_prefix, tps_line, FrameReader, TimingBuf, CMD_ACL, CMD_DATA, CMD_KEEPALIVE,
    CMD_KICKOUT, CMD_REQVIP,
};

// ---------------------------------------------------------- timer resolution

// Raise the system timer resolution to 1 ms while the tunnel is up (Windows
/// only: SO_RCVTIMEO rounds up to ~15.6 ms otherwise).
#[cfg(windows)]
#[link(name = "winmm")]
extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

#[cfg(windows)]
struct HiResTimer;
#[cfg(windows)]
impl HiResTimer {
    fn new() -> Self {
        unsafe {
            timeBeginPeriod(1);
        }
        Self
    }
}
#[cfg(windows)]
impl Drop for HiResTimer {
    fn drop(&mut self) {
        unsafe {
            timeEndPeriod(1);
        }
    }
}

// ----------------------------------------------------------------- helpers

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

// ------------------------------------------------------------------- config

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

// ------------------------------------------------------------------ session

pub struct Session {
    #[cfg(windows)]
    _timer: HiResTimer,
    raw_sock: TcpStream,
    stop: Arc<AtomicBool>,
    timing: Arc<Mutex<TimingBuf>>,
    device: Arc<device::DeviceHandle>,
    routes_raw: Vec<(u32, u32)>,
}

impl Session {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
        device::delete_routes(&self.routes_raw);
        // Wakes the pump thread (blocked in TLS read) and the TUN reader.
        let _ = self.raw_sock.shutdown(std::net::Shutdown::Both);
        self.device.shutdown();
        if let Ok(tb) = self.timing.lock() {
            dump_timing(&tb);
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        device::delete_routes(&self.routes_raw);
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
        let m = protocol::local_mac();
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
    let link = protocol::tls_connect(&host, port, cfg.insecure)?;
    let raw_sock = link.raw.try_clone().map_err(|e| format!("socket clone: {e}"))?;
    link.raw.set_read_timeout(Some(Duration::from_millis(2))).ok();
    let mut fr = FrameReader::new(link.io);

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
    let vip_s = protocol::ip_str(u32::from_be_bytes(ncfg.vip));
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

    // 4. create the virtual NIC (Wintun on Windows / utun on macOS)
    log("创建虚拟网卡…");
    let device = Arc::new(device::DeviceHandle::create(&vip_s, &log)?);

    device::delete_routes(&routes_raw);
    device::setup_routes(&routes_raw, device.name(), &log)?;

    // 5. negotiate the UDP data plane (huge speed-up: the gateway's TCP
    // window caps a single TLS tunnel at ~500KB/s, UDP has no such limit)
    let udp_slot: Arc<std::sync::RwLock<Option<Arc<protocol::UdpPlane>>>> =
        Arc::new(std::sync::RwLock::new(None));
    match negotiate_udp(&mut fr, &host, uid) {
        Ok(p) => {
            if let Ok(mut w) = udp_slot.write() {
                *w = Some(Arc::new(p));
            }
            log("UDP 数据面已启用（mode 3），吞吐不再受 TCP 窗口限制");
        }
        Err(e) => log(&format!("UDP 数据面协商失败，继续走 TCP: {e}")),
    }

    let stop = Arc::new(AtomicBool::new(false));
    let last_tx = Arc::new(AtomicU64::new(0));

    let timing = Arc::new(Mutex::new(TimingBuf::new(120)));
    if let Ok(mut t) = timing.lock() {
        t.push("=== session start ===".to_string());
    }
    tps_line(&format!(
        "=== session start ts={} vip={} mtu={} ===",
        now_us() / 1_000_000,
        vip_s,
        device::TUN_MTU
    ));

    // Pump owns the TLS stream (retrieved from the FrameReader), reading with
    // a 2 ms timeout so it can poll the stop flag and the outbound queue.
    let raw_sock_for_pump = raw_sock.try_clone().map_err(|e| format!("socket clone: {e}"))?;
    let mut tls = fr.into_inner();

    // TUN -> UDP (preferred) or channel -> TLS pump (fallback)
    let (pkt_tx, pkt_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    {
        let device2 = device.clone();
        let routes = routes_raw.clone();
        let udp2 = udp_slot.clone();
        let stop2 = stop.clone();
        let log_tx = log.clone();

        // TX throughput sampler for the tps log
        let tx_stat: Arc<Mutex<(u64, u64, u64)>> = Arc::new(Mutex::new((0, 0, 0)));
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
            match device2.recv(&stop2) {
                Ok(Some(bytes)) => {
                    // Only forward destinations inside the configured intranet
                    // subnets; drop ARP/LLMNR/NetBIOS/mDNS and stray traffic.
                    if bytes.len() >= 20 && bytes[0] >> 4 == 4 {
                        let dst =
                            u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
                        if !routes.iter().any(|(net, mask)| dst & *mask == *net) {
                            continue;
                        }
                        // UDP plane first; on any failure fall back to TCP
                        let plane = udp2.read().ok().and_then(|g| g.as_ref().cloned());
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
                Ok(None) => break, // stopped
                Err(_) => break,
            }
        });
    }

    // UDP RX: dedicated reader; forwards decrypted IPv4 packets into the TUN
    if udp_slot.read().map(|g| g.is_some()).unwrap_or(false) {
        let device3 = device.clone();
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
                            if device3.send(&pkt).is_ok() {
                                let mut g = stat_cell.lock().unwrap();
                                g.0 += pkt.len() as u64;
                                g.1 += 1;
                                if (pkt.len() as u64) > g.2 {
                                    g.2 = pkt.len() as u64;
                                }
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
        let device4 = device.clone();
        let st = stop.clone();
        let last_tx = last_tx.clone();
        let timing2 = timing.clone();
        let raw_for_stop = raw_sock_for_pump;
        std::thread::spawn(move || {
            let mut buf: Vec<u8> = Vec::new();
            let mut last_ka = Instant::now();
            let mut t_start = Instant::now();
            let mut tx_bytes: u64 = 0;
            let mut tx_pkts: u64 = 0;
            let mut rx_bytes: u64 = 0;
            let mut rx_pkts: u64 = 0;
            let mut tx_wait_us: u64 = 0;
            let mut tx_wait_max: u64 = 0;
            let mut idle_us: u64 = 0;
            let mut loops: u64 = 0;
            let mut detail_left: u32 = 200;
            loop {
                if st.load(Ordering::SeqCst) {
                    break;
                }
                loops += 1;
                // 1. drain outgoing packets (TCP fallback path)
                loop {
                    match pkt_rx.try_recv() {
                        Ok(bytes) => {
                            let plen = bytes.len();
                            last_tx.store(now_us(), Ordering::Relaxed);
                            tx_bytes += plen as u64;
                            tx_pkts += 1;
                            let frame = protocol::build_legacy(CMD_DATA, &bytes, uid);
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
                        .write_all(&protocol::build_legacy(CMD_KEEPALIVE, &[], uid))
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
                        "tcp tx={:.0}KB/s {}pps wavg={}us wmax={}us | rx={:.0}KB/s {}pps | idle={:.0}% loops={}",
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
                                let ok = device4.send(p).is_ok();
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
            let _ = raw_for_stop;
        });
    }
    log("隧道已建立");

    Ok((
        Session {
            #[cfg(windows)]
            _timer: HiResTimer::new(),
            raw_sock,
            stop,
            timing,
            device,
            routes_raw,
        },
        ConnectResult { vip: vip_s, routes: route_strs },
    ))
}
