//! sing-box UDP-over-TCP, server side (what sing-box, mihomo and prism
//! AnyTLS clients use for UDP).
//!
//! v2 (`sp.v2.udp-over-tcp.arpa`) starts with `is_connect u8 | socks addr`.
//! In connect mode every packet is `u16 len | data`, to and from that
//! destination. Otherwise (and always in v1, which has no request) packets
//! are `addr | u16 len | data`, where addr is `family u8 (0 = IPv4,
//! 1 = IPv6, 2 = domain) | address | port u16`: the destination going up,
//! the source coming back.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::address::Address;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::net::UdpSocket;

use crate::dial;
use crate::session::{Inflow, Session};

/// Ends the association when no datagram went either way for this long.
const IDLE: Duration = Duration::from_secs(180);

pub async fn read_addr<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Address> {
    let addr = match r.read_u8().await? {
        0 => {
            let mut b = [0u8; 4];
            r.read_exact(&mut b).await?;
            Address::Ip(SocketAddr::new(Ipv4Addr::from(b).into(), r.read_u16().await?))
        }
        1 => {
            let mut b = [0u8; 16];
            r.read_exact(&mut b).await?;
            Address::Ip(SocketAddr::new(Ipv6Addr::from(b).into(), r.read_u16().await?))
        }
        2 => {
            let len = r.read_u8().await? as usize;
            let mut b = vec![0u8; len];
            r.read_exact(&mut b).await?;
            let host = String::from_utf8(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain"))?;
            Address::new(&host, r.read_u16().await?)
        }
        f => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad UoT address family {f}"))),
    };
    Ok(addr)
}

pub fn write_addr(buf: &mut Vec<u8>, sa: SocketAddr) {
    match unmap(sa.ip()) {
        IpAddr::V4(v4) => {
            buf.push(0);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(1);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&sa.port().to_be_bytes());
}

fn unmap(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

struct Activity(Mutex<Instant>);

impl Activity {
    fn touch(&self) {
        *self.0.lock().unwrap() = Instant::now();
    }
    async fn idle(&self) {
        loop {
            let left = IDLE.saturating_sub(self.0.lock().unwrap().elapsed());
            if left.is_zero() {
                return;
            }
            tokio::time::sleep(left).await;
        }
    }
}

pub async fn serve(sess: &Session, sid: u32, inflow: &mut Inflow, legacy: bool) -> io::Result<()> {
    let connect_to = if legacy {
        None
    } else {
        let is_connect = inflow.read_u8().await? != 0;
        let dest = Address::read_socks(inflow).await?;
        is_connect.then_some(dest)
    };
    let activity = Activity(Mutex::new(Instant::now()));
    let res = match connect_to {
        Some(dest) => {
            tracing::debug!("{sid}: UDP connect {dest}");
            tokio::select! {
                r = connected(sess, sid, inflow, &dest, &activity) => r,
                _ = activity.idle() => Ok(()),
            }
        }
        None => tokio::select! {
            r = addressed(sess, sid, inflow, &activity) => r,
            _ = activity.idle() => Ok(()),
        },
    };
    match res {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        r => r,
    }
}

async fn bind_for(ip: IpAddr) -> io::Result<UdpSocket> {
    match ip {
        IpAddr::V4(_) => UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await,
        IpAddr::V6(_) => UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0)).await,
    }
}

async fn read_packet(inflow: &mut Inflow, buf: &mut Vec<u8>) -> io::Result<()> {
    let len = inflow.read_u16().await? as usize;
    buf.resize(len, 0);
    inflow.read_exact(buf).await?;
    Ok(())
}

async fn connected(sess: &Session, sid: u32, inflow: &mut Inflow, dest: &Address, act: &Activity) -> io::Result<()> {
    let target = dial::resolve(dest, sess.allow_local).await?[0];
    let sock = bind_for(target.ip()).await?;
    sock.connect(target).await?;
    let up = async {
        let mut buf = Vec::new();
        loop {
            read_packet(inflow, &mut buf).await?;
            act.touch();
            // A send error (e.g. ICMP unreachable) only loses this packet.
            if sock.send(&buf).await.is_ok() {
                sess.counter.add_up(buf.len());
            }
        }
    };
    let down = async {
        let mut buf = vec![0u8; 65535];
        loop {
            let n = match sock.recv(&mut buf).await {
                Ok(n) => n,
                Err(_) => continue,
            };
            act.touch();
            let mut f = Vec::with_capacity(n + 2);
            f.extend_from_slice(&(n as u16).to_be_bytes());
            f.extend_from_slice(&buf[..n]);
            sess.send_data(sid, &f).await?;
            sess.counter.add_down(n);
        }
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

/// One socket per address family, created on first use.
#[derive(Default)]
struct Sockets {
    v4: Option<Arc<UdpSocket>>,
    v6: Option<Arc<UdpSocket>>,
}

async fn addressed(sess: &Session, sid: u32, inflow: &mut Inflow, act: &Activity) -> io::Result<()> {
    let (new_tx, mut new_rx) = tokio::sync::mpsc::unbounded_channel::<Arc<UdpSocket>>();
    let up = async {
        let mut socks = Sockets::default();
        let mut dns: HashMap<String, SocketAddr> = HashMap::new();
        let mut buf = Vec::new();
        loop {
            let dest = read_addr(inflow).await?;
            read_packet(inflow, &mut buf).await?;
            act.touch();
            let target = match &dest {
                Address::Ip(sa) if sess.allow_local || !dial::is_local(sa.ip()) => *sa,
                Address::Ip(_) => continue,
                Address::Domain(host, port) => match dns.get(host) {
                    Some(sa) => SocketAddr::new(sa.ip(), *port),
                    None => match dial::resolve(&dest, sess.allow_local).await {
                        Ok(v) => {
                            dns.insert(host.clone(), v[0]);
                            v[0]
                        }
                        Err(e) => {
                            tracing::debug!("{sid}: UDP {dest}: {e}");
                            continue;
                        }
                    },
                },
            };
            let slot = if target.is_ipv4() { &mut socks.v4 } else { &mut socks.v6 };
            if slot.is_none() {
                let s = Arc::new(bind_for(target.ip()).await?);
                let _ = new_tx.send(s.clone());
                *slot = Some(s);
            }
            if slot.as_ref().unwrap().send_to(&buf, target).await.is_ok() {
                sess.counter.add_up(buf.len());
            }
        }
    };
    let down = async {
        let mut readers = tokio::task::JoinSet::new();
        let (pkt_tx, mut pkt_rx) = tokio::sync::mpsc::channel::<(SocketAddr, Vec<u8>)>(64);
        loop {
            tokio::select! {
                Some(s) = new_rx.recv() => {
                    let tx = pkt_tx.clone();
                    readers.spawn(async move {
                        let mut buf = vec![0u8; 65535];
                        loop {
                            if let Ok((n, from)) = s.recv_from(&mut buf).await {
                                if tx.send((from, buf[..n].to_vec())).await.is_err() {
                                    return;
                                }
                            }
                        }
                    });
                }
                Some((from, data)) = pkt_rx.recv() => {
                    act.touch();
                    let mut f = Vec::with_capacity(data.len() + 21);
                    write_addr(&mut f, from);
                    f.extend_from_slice(&(data.len() as u16).to_be_bytes());
                    f.extend_from_slice(&data);
                    sess.send_data(sid, &f).await?;
                    sess.counter.add_down(data.len());
                }
                else => return Ok::<(), io::Error>(()),
            }
        }
    };
    tokio::select! {
        r = up => r,
        r = down => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn addr_round_trip() {
        for sa in ["1.2.3.4:53", "[2001:db8::1]:443", "[::ffff:1.2.3.4]:53"] {
            let sa: SocketAddr = sa.parse().unwrap();
            let mut b = Vec::new();
            write_addr(&mut b, sa);
            let got = read_addr(&mut &b[..]).await.unwrap();
            assert_eq!(got, Address::Ip(SocketAddr::new(unmap(sa.ip()), sa.port())));
        }
        let b = [2u8, 3, b'a', b'.', b'b', 0, 53];
        assert_eq!(read_addr(&mut &b[..]).await.unwrap(), Address::new("a.b", 53));
    }
}
