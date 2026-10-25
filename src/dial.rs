//! Outbound connections to the destinations clients ask for.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::address::Address;
use tokio::net::TcpStream;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Loopback, unspecified and link-local (169.254.169.254 cloud metadata)
/// addresses reach the node itself, not the internet.
pub fn is_local(ip: IpAddr) -> bool {
    let ip = match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    };
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_unspecified() || v4.is_link_local() || v4.octets()[0] == 0,
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Resolves `addr`, dropping addresses clients may not reach.
pub async fn resolve(addr: &Address, allow_local: bool) -> io::Result<Vec<SocketAddr>> {
    let all: Vec<SocketAddr> = match addr {
        Address::Ip(sa) => vec![*sa],
        Address::Domain(host, port) => tokio::net::lookup_host((host.as_str(), *port)).await?.collect(),
    };
    let ok: Vec<SocketAddr> = all.iter().copied().filter(|sa| allow_local || !is_local(sa.ip())).collect();
    if ok.is_empty() {
        let msg = if all.is_empty() { "no address" } else { "destination not allowed" };
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("{addr}: {msg}")));
    }
    Ok(ok)
}

pub async fn tcp(addr: &Address, allow_local: bool) -> io::Result<TcpStream> {
    let addrs = resolve(addr, allow_local).await?;
    let attempt = async {
        let mut last = None;
        for sa in addrs {
            match TcpStream::connect(sa).await {
                Ok(s) => {
                    s.set_nodelay(true)?;
                    return Ok(s);
                }
                Err(e) => last = Some(e),
            }
        }
        Err(last.unwrap())
    };
    tokio::time::timeout(CONNECT_TIMEOUT, attempt)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, format!("connect {addr}: timed out")))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_addresses() {
        for s in ["127.0.0.1", "0.0.0.0", "169.254.169.254", "::1", "::", "fe80::1", "::ffff:127.0.0.1"] {
            assert!(is_local(s.parse().unwrap()), "{s}");
        }
        for s in ["1.1.1.1", "10.0.0.1", "2001:db8::1", "::ffff:8.8.8.8"] {
            assert!(!is_local(s.parse().unwrap()), "{s}");
        }
    }

    #[tokio::test]
    async fn refuses_local_unless_allowed() {
        let a = Address::new("127.0.0.1", 9550);
        assert_eq!(resolve(&a, false).await.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert!(resolve(&a, true).await.is_ok());
    }
}
