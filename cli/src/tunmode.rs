//! TUN mode: create a Wintun adapter and route ONLY the company intranet
//! subnets into it. Nothing else changes — default route, local LAN and the
//! public internet keep using the physical NIC.
//!
//! This is the clean counterpart to what SecoClient does wrong: it hijacks
//! 0.0.0.0/0 and mirrors every local subnet into the virtual adapter.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use native_tls::TlsStream;

use crate::{parse_frame, Frame, CMD_DATA, CMD_KEEPALIVE, CMD_KICKOUT};

pub const ADAPTER_NAME: &str = "rocket";

// ---------------------------------------------------------------- tunnel

pub struct TlsInner {
    pub stream: TlsStream<TcpStream>,
    pub buf: Vec<u8>,
}

pub struct Tunnel {
    inner: Mutex<TlsInner>,
    sid: u32,
    kick: AtomicBool,
}

impl Tunnel {
    pub fn new(stream: TlsStream<TcpStream>, sid: u32) -> Self {
        Self { inner: Mutex::new(TlsInner { stream, buf: Vec::new() }), sid, kick: AtomicBool::new(false) }
    }

    pub fn send(&self, cmd: u16, payload: &[u8]) -> Result<(), String> {
        let mut g = self.inner.lock().map_err(|_| "mutex poisoned".to_string())?;
        let b = crate::build_legacy(cmd, payload, self.sid);
        g.stream.write_all(&b).map_err(|e| format!("tunnel write: {e}"))?;
        g.stream.flush().ok();
        Ok(())
    }

    /// Blocking read with a short timeout; returns None when nothing arrived.
    pub fn recv(&self, timeout: Duration) -> Option<Frame> {
        let mut g = self.inner.lock().ok()?;
        g.stream.get_ref().set_read_timeout(Some(timeout)).ok();
        loop {
            if let Some((f, n)) = parse_frame(&g.buf) {
                g.buf.drain(..n);
                return Some(f);
            }
            let mut tmp = [0u8; 65536];
            match g.stream.read(&mut tmp) {
                Ok(0) => return None,
                Ok(n) => {
                    g.buf.extend_from_slice(&tmp[..n]);
                    if g.buf.len() > (1 << 22) {
                        return None;
                    }
                }
                Err(_) => return None,
            }
        }
    }
}

// ---------------------------------------------------------------- helpers

fn run_net(args: &[&str]) -> bool {
    match Command::new("netsh").args(args).output() {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

fn run_route(args: &[&str]) -> bool {
    match Command::new("route").args(args).output() {
        Ok(o) => o.status.success(),
        Err(_) => false,
    }
}

fn ip_str(v: u32) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

pub fn parse_cidr(s: &str) -> Option<(u32, u32)> {
    let (ip, bits) = s.split_once('/')?;
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

// ---------------------------------------------------------------- main

pub fn run(
    tunnel: Arc<Tunnel>,
    vip: [u8; 4],
    routes: Vec<(u32, u32)>,
) -> Result<(), String> {
    let wintun = unsafe { wintun::load() }
        .map_err(|e| format!("load wintun.dll: {e}  (put wintun.dll next to the exe)"))?;

    // Reuse an existing adapter if a previous run left one behind.
    let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
        Ok(a) => a,
        Err(_) => wintun::Adapter::create(&wintun, ADAPTER_NAME, "rocket", None)
            .map_err(|e| format!("create adapter: {e}  (run as administrator)"))?,
    };

    let idx = adapter.get_adapter_index().map_err(|e| format!("adapter index: {e}"))?;
    println!("adapter        : {ADAPTER_NAME} (ifIndex {idx})");

    // Assign the tunnel VIP to the adapter, no gateway (keeps default route intact).
    let vip_s = ip_str(u32::from_be_bytes(vip));
    if !run_net(&[
        "interface",
        "ipv4",
        "set",
        "address",
        &format!("name={ADAPTER_NAME}"),
        "source=static",
        &format!("address={vip_s}"),
        "mask=255.255.255.0",
        "gateway=none",
    ]) {
        // It may already have the address; that is fine.
        println!("note: setting adapter address returned an error (may already be set)");
    }

    // Only the intranet subnets go to the adapter.
    for (net, mask) in &routes {
        let ns = ip_str(*net);
        let ms = ip_str(*mask);
        // Remove a stale entry first (ignore failure).
        run_route(&["delete", &ns, "mask", &ms]);
        let ok = run_route(&["add", &ns, "mask", &ms, "0.0.0.0", &format!("if {idx}")]);
        if ok {
            println!("route          : {ns}/{ms} -> {ADAPTER_NAME}");
        } else {
            // Fall back to netsh syntax.
            let failed = !run_net(&[
                "interface",
                "ipv4",
                "add",
                "route",
                &format!("{ns}/{}", mask_bits(*mask)),
                ADAPTER_NAME,
                "store=active",
            ]);
            if failed {
                return Err(format!("cannot add route {ns} mask {ms} to ifIndex {idx}"));
            }
            println!("route          : {ns}/{ms} -> {ADAPTER_NAME}");
        }
    }

    let session = adapter
        .start_session(0x40_0000)
        .map_err(|e| format!("start session: {e}"))?;
    println!("\nTUN mode active. Traffic for the routes above now goes through the VPN.");
    println!("Everything else (local LAN, internet) is untouched. Ctrl+C to stop.\n");

    // Cleanup on Ctrl+C: removing routes is what matters, the adapter is reused.
    let cleanup_routes = routes.clone();
    let sess = Arc::new(session);
    ctrlc::set_handler(move || {
        for (net, mask) in &cleanup_routes {
            let ns = ip_str(*net);
            let ms = ip_str(*mask);
            let _ = Command::new("route")
                .args(["delete", &ns, "mask", &ms])
                .output();
        }
        eprintln!("\n[tun] routes removed, exiting");
        std::process::exit(0);
    })
    .ok();

    // Thread 1: tunnel -> adapter
    {
        let t = tunnel.clone();
        let s = sess.clone();
        std::thread::spawn(move || loop {
            match t.recv(Duration::from_millis(5)) {
                Some(f) if f.cmd == CMD_DATA => {
                    let p = crate::strip_vnic_prefix(&f.payload);
                    if let Some(mut pkt) = s.allocate_send_packet(p.len() as u16).ok() {
                        pkt.bytes_mut().copy_from_slice(p);
                        s.send_packet(pkt);
                    }
                }
                Some(f) if f.cmd == CMD_KICKOUT => {
                    eprintln!("[tun] kicked by gateway");
                    std::process::exit(1);
                }
                Some(_) => {}
                None => {}
            }
        });
    }

    // Thread 2: adapter -> tunnel
    let t2 = tunnel.clone();
    let keep = sess.clone();
    std::thread::spawn(move || {
        let _keep = keep;
        loop {
            let packet = sess.receive_blocking();
            match packet {
                Ok(p) => {
                    let bytes = p.bytes().to_vec();
                    drop(p);
                    let _ = t2.send(CMD_DATA, &bytes);
                }
                Err(_) => break,
            }
        }
    });

    // Keepalive on the main thread.
    loop {
        std::thread::sleep(Duration::from_secs(10));
        if tunnel.send(CMD_KEEPALIVE, &[]).is_err() {
            return Err("keepalive failed, connection lost".into());
        }
    }
}

fn mask_bits(mask: u32) -> u32 {
    mask.count_ones()
}
