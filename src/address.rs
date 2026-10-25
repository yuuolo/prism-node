//! Destination addresses as clients send them (SOCKS5 encoding).

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};

/// A domain (resolved here) or a literal socket address.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Address {
    Domain(String, u16),
    Ip(SocketAddr),
}

impl Address {
    pub fn new(host: &str, port: u16) -> Self {
        let h = host.trim_start_matches('[').trim_end_matches(']');
        match h.parse::<IpAddr>() {
            Ok(ip) => Address::Ip(SocketAddr::new(ip, port)),
            Err(_) => Address::Domain(h.to_ascii_lowercase(), port),
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            Address::Domain(_, p) => *p,
            Address::Ip(sa) => sa.port(),
        }
    }

    pub fn host(&self) -> String {
        match self {
            Address::Domain(d, _) => d.clone(),
            Address::Ip(sa) => sa.ip().to_string(),
        }
    }

    pub fn domain(&self) -> Option<&str> {
        match self {
            Address::Domain(d, _) => Some(d),
            Address::Ip(_) => None,
        }
    }

    /// ATYP (1 = IPv4, 3 = domain, 4 = IPv6) | address | port u16 BE.
    pub fn write_socks(&self, buf: &mut Vec<u8>) {
        match self {
            Address::Ip(SocketAddr::V4(sa)) => {
                buf.push(1);
                buf.extend_from_slice(&sa.ip().octets());
            }
            Address::Ip(SocketAddr::V6(sa)) => {
                buf.push(4);
                buf.extend_from_slice(&sa.ip().octets());
            }
            Address::Domain(d, _) => {
                let d = &d.as_bytes()[..d.len().min(255)];
                buf.push(3);
                buf.push(d.len() as u8);
                buf.extend_from_slice(d);
            }
        }
        buf.extend_from_slice(&self.port().to_be_bytes());
    }

    pub async fn read_socks<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Self> {
        let addr = match r.read_u8().await? {
            1 => {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).await?;
                Address::Ip(SocketAddr::new(Ipv4Addr::from(b).into(), r.read_u16().await?))
            }
            4 => {
                let mut b = [0u8; 16];
                r.read_exact(&mut b).await?;
                Address::Ip(SocketAddr::new(Ipv6Addr::from(b).into(), r.read_u16().await?))
            }
            3 => {
                let len = r.read_u8().await? as usize;
                let mut b = vec![0u8; len];
                r.read_exact(&mut b).await?;
                let host = String::from_utf8(b).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad domain"))?;
                Address::new(&host, r.read_u16().await?)
            }
            t => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("bad address type {t}"))),
        };
        Ok(addr)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Address::Domain(d, p) => write!(f, "{d}:{p}"),
            Address::Ip(sa) => write!(f, "{sa}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks_round_trip() {
        for a in [Address::new("1.2.3.4", 80), Address::new("[2001:db8::1]", 443), Address::new("Example.COM", 53)] {
            let mut b = Vec::new();
            a.write_socks(&mut b);
            assert_eq!(Address::read_socks(&mut &b[..]).await.unwrap(), a);
        }
        assert_eq!(Address::new("Example.COM", 53).to_string(), "example.com:53");
    }
}
