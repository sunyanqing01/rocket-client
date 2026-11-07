//! User-space TCP/IP stack bridging the VPN tunnel and local TCP sockets.
//!
//! The tunnel carries raw IPv4 packets, so we need a TCP state machine to
//! turn a local TCP stream into something the gateway will route. smoltcp
//! provides the state machine; this module wires it to the tunnel.

use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv4Address};
use std::collections::VecDeque;

pub const TUNNEL_MTU: usize = 1300;
pub const TCP_MSS: usize = 1200;

/// Rc<RefCell> style single-threaded device: the main loop owns it, so plain
/// queues are enough.
pub struct TunnelDevice {
    pub rx: VecDeque<Vec<u8>>,
    pub tx: VecDeque<Vec<u8>>,
}

impl TunnelDevice {
    pub fn new() -> Self {
        Self { rx: VecDeque::new(), tx: VecDeque::new() }
    }
}

pub struct RxT(pub Vec<u8>);

impl RxToken for RxT {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(mut self, f: F) -> R {
        f(&mut self.0)
    }
}

pub struct TxT<'a>(pub &'a mut VecDeque<Vec<u8>>);

impl<'a> TxToken for TxT<'a> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        self.0.push_back(buf);
        r
    }
}

impl Device for TunnelDevice {
    type RxToken<'a> = RxT;
    type TxToken<'a> = TxT<'a>;

    fn receive(&mut self, _t: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let pkt = self.rx.pop_front()?;
        Some((RxT(pkt), TxT(&mut self.tx)))
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TxT(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        c.medium = Medium::Ip;
        c.max_transmission_unit = TUNNEL_MTU;
        c.max_burst_size = Some(16);
        c
    }
}

pub struct NetStack {
    pub iface: Interface,
    pub sockets: SocketSet<'static>,
    pub device: TunnelDevice,
    next_port: u16,
}

impl NetStack {
    pub fn new(vip: [u8; 4]) -> Self {
        let mut device = TunnelDevice::new();
        let config = Config::new(HardwareAddress::Ip);
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());

        let addr = Ipv4Address::new(vip[0], vip[1], vip[2], vip[3]);
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), 24));
        });
        // Any next hop works: every packet leaves through the tunnel anyway.
        let _ = iface.routes_mut().add_default_ipv4_route(Ipv4Address::new(vip[0], vip[1], vip[2], 1));

        Self { iface, sockets: SocketSet::new(Vec::new()), device, next_port: 40000 }
    }

    /// Allocate a TCP socket and start connecting to `dst`:`port`.
    pub fn connect(
        &mut self,
        dst: Ipv4Address,
        port: u16,
    ) -> Option<SocketHandle> {
        let rx = tcp::SocketBuffer::new(vec![0u8; 128 * 1024]);
        let tx = tcp::SocketBuffer::new(vec![0u8; 128 * 1024]);
        let mut sock = tcp::Socket::new(rx, tx);
        // MSS follows the device MTU (1300 - 40 = 1260), which matches the
        // gateway's own limit. No explicit set_mss needed.
        sock.set_nagle_enabled(false);

        let local_port = self.next_port;
        self.next_port = if self.next_port >= 60000 { 40000 } else { self.next_port + 1 };

        let handle = self.sockets.add(sock);
        let s = self.sockets.get_mut::<tcp::Socket>(handle);
        match s.connect(self.iface.context(), (IpAddress::Ipv4(dst), port), local_port) {
            Ok(()) => Some(handle),
            Err(e) => {
                if !matches!(e, tcp::ConnectError::Unaddressable) {
                    eprintln!("[net] connect error: {e:?}");
                }
                self.sockets.remove(handle);
                None
            }
        }
    }

    pub fn poll(&mut self) {
        self.iface.poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    pub fn socket(&mut self, h: SocketHandle) -> &mut tcp::Socket<'static> {
        self.sockets.get_mut::<tcp::Socket>(h)
    }

    pub fn remove(&mut self, h: SocketHandle) {
        self.sockets.remove(h);
    }
}

/// The gateway drops frames of 40 bytes or less (a bare TCP ACK is exactly
/// 40 bytes), so pad them with no-op options.
pub fn pad_small_packet(pkt: &mut Vec<u8>) {
    if pkt.len() > 40 || pkt.len() < 20 {
        return;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if ihl < 20 || pkt.len() < ihl {
        return;
    }
    let proto = pkt[9];

    if proto == 6 && pkt.len() >= ihl + 20 {
        // TCP: grow the TCP header by 4 bytes of NOP options.
        let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
        if data_off != 20 {
            return; // header already has options; leave it alone
        }
        let payload_start = ihl + data_off;
        let mut newpkt = Vec::with_capacity(pkt.len() + 4);
        newpkt.extend_from_slice(&pkt[..payload_start]);
        newpkt.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]); // NOP x4
        newpkt.extend_from_slice(&pkt[payload_start..]);

        // IP total length
        let total = newpkt.len() as u16;
        newpkt[2..4].copy_from_slice(&total.to_be_bytes());
        // TCP data offset 5 -> 6
        newpkt[ihl + 12] = (newpkt[ihl + 12] & 0x0f) | (6 << 4);
        // clear TCP checksum, recompute
        newpkt[ihl + 16..ihl + 18].copy_from_slice(&[0, 0]);
        let c = tcp_checksum(&newpkt[12..16], &newpkt[16..20], &newpkt[ihl..]);
        newpkt[ihl + 16..ihl + 18].copy_from_slice(&c.to_be_bytes());
        // clear and recompute IP checksum
        newpkt[10..12].copy_from_slice(&[0, 0]);
        let ih = checksum(&newpkt[..ihl]);
        newpkt[10..12].copy_from_slice(&ih.to_be_bytes());

        *pkt = newpkt;
    } else if proto != 6 {
        // UDP / ICMP: grow the IP header by 4 bytes of NOP options.
        let mut newpkt = Vec::with_capacity(pkt.len() + 4);
        newpkt.extend_from_slice(&pkt[..ihl]);
        newpkt.extend_from_slice(&[0x01, 0x01, 0x01, 0x01]);
        newpkt.extend_from_slice(&pkt[ihl..]);
        let total = newpkt.len() as u16;
        newpkt[2..4].copy_from_slice(&total.to_be_bytes());
        newpkt[0] = (newpkt[0] & 0xf0) | 6; // IHL 5 -> 6
        newpkt[10..12].copy_from_slice(&[0, 0]);
        let ih = checksum(&newpkt[..(6 * 4)]);
        newpkt[10..12].copy_from_slice(&ih.to_be_bytes());
        *pkt = newpkt;
    }
}

pub fn checksum(data: &[u8]) -> u16 {
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

fn tcp_checksum(src: &[u8], dst: &[u8], tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    checksum(&pseudo)
}
