//! Cross-platform virtual NIC bring-up and packet I/O.
//!
//! - Windows: Wintun ring sessions, netsh for address/MTU, netsh for routes
//! - macOS: utun device (via the `tun` crate), ifconfig for address/MTU, route for routes

use std::io;
use std::process::Command;
use std::sync::atomic::AtomicBool;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

pub const TUN_MTU: u32 = 1400;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[cfg(windows)]
fn cmd(program: &str) -> Command {
    let mut c = Command::new(program);
    c.creation_flags(CREATE_NO_WINDOW);
    c
}

#[cfg(not(windows))]
fn cmd(program: &str) -> Command {
    Command::new(program)
}

fn run_cmd(program: &str, args: &[&str]) -> bool {
    cmd(program).args(args).output().map(|o| o.status.success()).unwrap_or(false)
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

pub fn ip_str(v: u32) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

// ------------------------------------------------------------------ Windows

#[cfg(windows)]
mod imp {
    use super::*;
    use std::sync::Arc;

    pub struct DeviceImpl {
        pub session: Arc<wintun::Session>,
        #[allow(dead_code)]
        pub adapter: Arc<wintun::Adapter>,
        pub name: String,
    }

    pub fn create(vip: &str, log: &dyn Fn(&str)) -> Result<DeviceImpl, String> {
        const ADAPTER_NAME: &str = "rocket";
        let wintun = unsafe { wintun::load() }
            .map_err(|e| format!("加载 wintun.dll 失败: {e}（请把 wintun.dll 放在程序目录）"))?;
        let adapter = match wintun::Adapter::open(&wintun, ADAPTER_NAME) {
            Ok(a) => a,
            Err(_) => wintun::Adapter::create(&wintun, ADAPTER_NAME, "Rocket Client", None)
                .map_err(|e| format!("创建网卡失败: {e}（请以管理员身份运行本程序）"))?,
        };
        let idx = adapter
            .get_adapter_index()
            .map_err(|e| format!("获取网卡索引失败: {e}"))?;
        log(&format!("网卡 {ADAPTER_NAME} (ifIndex {idx})"));

        let _ = run_cmd(
            "netsh",
            &[
                "interface", "ipv4", "set", "address",
                &format!("name={ADAPTER_NAME}"),
                "source=static", &format!("address={vip}"),
                "mask=255.255.255.0", "gateway=none",
            ],
        );

        // MTU 1400: 16B legacy frame header + ~45-57B TLS record overhead keeps
        // every outer frame inside one 1500B TCP segment.
        let _ = run_cmd_out(
            "netsh",
            &[
                "interface", "ipv4", "set", "subinterface",
                ADAPTER_NAME, &format!("mtu={TUN_MTU}"), "store=active",
            ],
        );
        log(&format!("网卡 MTU 设为 {TUN_MTU}"));

        let session = Arc::new(
            adapter
                .start_session(0x40_0000)
                .map_err(|e| format!("启动 Wintun 会话失败: {e}"))?,
        );
        Ok(DeviceImpl { session, adapter, name: ADAPTER_NAME.to_string() })
    }

    pub fn setup_routes(routes: &[(u32, u32)], _name: &str, log: &dyn Fn(&str)) -> Result<(), String> {
        for (net, mask) in routes {
            let ns = ip_str(*net);
            let ms = ip_str(*mask);
            let cidr = format!("{ns}/{}", mask.count_ones());
            run_cmd_out(
                "netsh",
                &["interface", "ipv4", "add", "route", &cidr, "rocket", "store=active"],
            )
            .map_err(|e| format!("添加路由 {ns}/{ms} 失败: {e}"))?;
            log(&format!("路由 {ns}/{ms} → rocket"));
        }
        Ok(())
    }

    pub fn delete_routes(routes: &[(u32, u32)]) {
        for (net, mask) in routes {
            run_cmd("route", &["delete", &ip_str(*net), "mask", &ip_str(*mask)]);
        }
    }

    pub fn recv(session: &Arc<wintun::Session>, _stop: &AtomicBool) -> io::Result<Option<Vec<u8>>> {
        match session.receive_blocking() {
            Ok(p) => {
                let bytes = p.bytes().to_vec();
                drop(p);
                Ok(Some(bytes))
            }
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "wintun session closed")),
        }
    }

    pub fn send(session: &Arc<wintun::Session>, pkt: &[u8]) -> io::Result<()> {
        let mut p = session
            .allocate_send_packet(pkt.len() as u16)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("wintun alloc: {e}")))?;
        p.bytes_mut().copy_from_slice(pkt);
        session.send_packet(p);
        Ok(())
    }

    pub fn shutdown(session: &wintun::Session) {
        let _ = session.shutdown();
    }
}

// -------------------------------------------------------------------- macOS

#[cfg(target_os = "macos")]
mod imp {
    use super::*;
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;

    /// macOS utun frames carry a 4-byte address-family prefix.
    const AF_INET: u32 = 2;

    pub struct DeviceImpl {
        rd: Mutex<tun::platform::posix::Reader>,
        wr: Mutex<tun::platform::posix::Writer>,
        pub name: String,
    }

    pub fn create(vip: &str, log: &dyn Fn(&str)) -> Result<DeviceImpl, String> {
        let mut cfg = tun::Configuration::default();
        cfg.address(vip)
            .destination(vip)
            .netmask("255.255.255.0")
            .mtu(TUN_MTU as i32)
            .up();
        let mut dev = tun::create(&cfg)
            .map_err(|e| format!("创建 utun 失败: {e}（需要 sudo 运行）"))?;
        let name = tun::Device::name(&mut dev)
            .map_err(|e| format!("获取 utun 名称失败: {e}"))?;
        log(&format!("虚拟网卡 {name}"));

        // Non-blocking fd + split into reader/writer halves.
        dev.set_nonblock()
            .map_err(|e| format!("设置非阻塞失败: {e}"))?;
        let (r, w) = dev.split();
        Ok(DeviceImpl {
            rd: Mutex::new(r),
            wr: Mutex::new(w),
            name,
        })
    }

    pub fn setup_routes(
        routes: &[(u32, u32)],
        name: &str,
        log: &dyn Fn(&str),
    ) -> Result<(), String> {
        for (net, mask) in routes {
            let cidr = format!("{}/{}", ip_str(*net), mask.count_ones());
            run_cmd_out("route", &["-n", "add", "-net", &cidr, "-interface", name])
                .map_err(|e| format!("添加路由 {cidr} 失败: {e}（需要 sudo）"))?;
            log(&format!("路由 {cidr} → {name}"));
        }
        Ok(())
    }

    pub fn delete_routes(routes: &[(u32, u32)]) {
        for (net, mask) in routes {
            let cidr = format!("{}/{}", ip_str(*net), mask.count_ones());
            run_cmd("route", &["-n", "delete", "-net", &cidr]);
        }
    }

    /// Non-blocking read + stop-flag poll, so disconnect actually works.
    /// Strips the 4-byte utun header; only IPv4 packets are returned.
    pub fn recv(rd: &Mutex<tun::platform::posix::Reader>, stop: &AtomicBool)
        -> io::Result<Option<Vec<u8>>>
    {
        loop {
            if stop.load(Ordering::SeqCst) {
                return Ok(None);
            }
            let mut buf = vec![0u8; 65535];
            let res = {
                let mut d = rd
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock"))?;
                d.read(&mut buf)
            };
            match res {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::Other, "utun closed")),
                Ok(n) if n > 4 => {
                    let af = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
                    if af != AF_INET {
                        continue; // IPv6 or other families: drop
                    }
                    buf.truncate(n);
                    return Ok(Some(buf[4..].to_vec()));
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Prepends the 4-byte utun header before writing to the fd.
    pub fn send(wr: &Mutex<tun::platform::posix::Writer>, pkt: &[u8]) -> io::Result<()> {
        let mut d = wr
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "lock"))?;
        let mut framed = Vec::with_capacity(4 + pkt.len());
        framed.extend_from_slice(&AF_INET.to_be_bytes());
        framed.extend_from_slice(pkt);
        d.write_all(&framed)
    }
}

// ------------------------------------------------------------- unified view

pub struct DeviceHandle {
    inner: imp::DeviceImpl,
}

impl DeviceHandle {
    /// Bring the virtual NIC up (address + MTU). Routes are added separately.
    pub fn create(vip: &str, log: &dyn Fn(&str)) -> Result<DeviceHandle, String> {
        let inner = imp::create(vip, log)?;
        Ok(DeviceHandle { inner })
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    /// Read one packet from the NIC. Returns Ok(None) after shutdown.
    pub fn recv(&self, stop: &AtomicBool) -> io::Result<Option<Vec<u8>>> {
        #[cfg(windows)]
        return imp::recv(&self.inner.session, stop);
        #[cfg(target_os = "macos")]
        return imp::recv(&self.inner.rd, stop);
    }

    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        #[cfg(windows)]
        return imp::send(&self.inner.session, pkt);
        #[cfg(target_os = "macos")]
        return imp::send(&self.inner.wr, pkt);
    }

    pub fn shutdown(&self) {
        #[cfg(windows)]
        imp::shutdown(&self.inner.session);
        // On macOS the reader loop polls the stop flag; nothing to close.
    }
}

pub fn setup_routes(routes: &[(u32, u32)], name: &str, log: &dyn Fn(&str)) -> Result<(), String> {
    imp::setup_routes(routes, name, log)
}

pub fn delete_routes(routes: &[(u32, u32)]) {
    imp::delete_routes(routes)
}
