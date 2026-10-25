//! End to end against real third-party clients: each one runs a local SOCKS
//! inbound with an AnyTLS outbound to prism-node; TCP and UDP go through.
//!
//! Skipped unless the client binaries are given:
//!   PRISM_E2E_SINGBOX=/path/to/sing-box  PRISM_E2E_MIHOMO=/path/to/mihomo
//!   cargo test -p prism-node --test clients -- --nocapture

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use prism_node::server::Node;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

const PASSWORD: &str = "e2e-password";

struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

async fn start_node(dir: &Path) -> (Arc<Node>, SocketAddr, CancellationToken) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), c.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), c.key_pair.serialize_pem()).unwrap();
    let cfg = json!({
        "api": {"listen": ""},
        "allow_local": true,
        "inbounds": [{
            "type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": free_port(),
            "users": [{"name": "e2e", "password": PASSWORD}],
            "tls": {"enabled": true, "certificate_path": "cert.pem", "key_path": "key.pem"}
        }]
    });
    let path = dir.join("node.json");
    std::fs::write(&path, cfg.to_string()).unwrap();
    let node = Node::new(&prism_node::config::load(&path).unwrap(), Some(path));
    let shutdown = CancellationToken::new();
    let addr = node.start(shutdown.clone()).await.unwrap()[0];
    (node, addr, shutdown)
}

async fn tcp_echo() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = l.accept().await.unwrap();
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    addr
}

async fn udp_echo() -> SocketAddr {
    let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = s.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            let (n, from) = s.recv_from(&mut buf).await.unwrap();
            s.send_to(&buf[..n], from).await.unwrap();
        }
    });
    addr
}

fn socks_addr(buf: &mut Vec<u8>, a: SocketAddr) {
    let SocketAddr::V4(v4) = a else { panic!("IPv4 only") };
    buf.push(1);
    buf.extend_from_slice(&v4.ip().octets());
    buf.extend_from_slice(&v4.port().to_be_bytes());
}

/// SOCKS5 request (no auth); returns the control connection and BND.ADDR.
async fn socks(proxy: u16, cmd: u8, target: SocketAddr) -> std::io::Result<(TcpStream, SocketAddr)> {
    let mut s = TcpStream::connect(("127.0.0.1", proxy)).await?;
    s.write_all(&[5, 1, 0]).await?;
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    let mut req = vec![5, cmd, 0];
    socks_addr(&mut req, target);
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        return Err(std::io::Error::other(format!("SOCKS reply {}", head[1])));
    }
    let bnd = match head[3] {
        1 => {
            let mut b = [0u8; 6];
            s.read_exact(&mut b).await?;
            SocketAddr::from(([b[0], b[1], b[2], b[3]], u16::from_be_bytes([b[4], b[5]])))
        }
        4 => {
            let mut b = [0u8; 18];
            s.read_exact(&mut b).await?;
            let ip: [u8; 16] = b[..16].try_into().unwrap();
            SocketAddr::from((ip, u16::from_be_bytes([b[16], b[17]])))
        }
        t => return Err(std::io::Error::other(format!("SOCKS address type {t}"))),
    };
    Ok((s, bnd))
}

async fn wait_port(port: u16) {
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("client did not open port {port}");
}

async fn check_tcp(proxy: u16, echo: SocketAddr) {
    // Several streams: later ones reuse the session and must get SYNACKs
    // within the client's deadline.
    for i in 0..5usize {
        let (mut s, _) = socks(proxy, 1, echo).await.unwrap();
        let msg = vec![i as u8; 1000 + i * 50_000];
        s.write_all(&msg).await.unwrap();
        let mut got = vec![0u8; msg.len()];
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got)).await.unwrap().unwrap();
        assert_eq!(got, msg, "stream {i}");
    }
}

async fn check_udp(proxy: u16, echo: SocketAddr) {
    let (_ctl, mut relay) = socks(proxy, 3, "0.0.0.0:0".parse().unwrap()).await.unwrap();
    if relay.ip().is_unspecified() {
        relay.set_ip([127, 0, 0, 1].into());
    }
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for msg in [&b"ping"[..], &[9u8; 1200][..]] {
        let mut pkt = vec![0, 0, 0];
        socks_addr(&mut pkt, echo);
        pkt.extend_from_slice(msg);
        let mut buf = vec![0u8; 2048];
        // UDP may be dropped while the client sets up; retry a few times.
        let mut got = None;
        for _ in 0..5 {
            sock.send_to(&pkt, relay).await.unwrap();
            if let Ok(Ok((n, _))) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
                got = Some(buf[10..n].to_vec());
                break;
            }
        }
        assert_eq!(got.as_deref(), Some(msg), "UDP echo");
    }
}

fn workdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("prism-node-e2e-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn spawn(bin: &str, args: &[&str], dir: &Path) -> Kill {
    let log = std::fs::File::create(dir.join("client.log")).unwrap();
    let child = Command::new(bin)
        .args(args)
        .current_dir(dir)
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .stdin(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("start {bin}: {e}"));
    Kill(child)
}

async fn run_client(name: &str, dir: &Path, node: &Node, proxy: u16, child: Kill) {
    wait_port(proxy).await;
    let echo_t = tcp_echo().await;
    let echo_u = udp_echo().await;
    check_tcp(proxy, echo_t).await;
    check_udp(proxy, echo_u).await;
    let r = node.stats.report();
    let e2e = &r.users["e2e"];
    assert!(e2e.up > 100_000 && e2e.down > 100_000, "{name}: counters {} / {}", e2e.up, e2e.down);
    eprintln!("{name}: ok (up {} B, down {} B); log: {}", e2e.up, e2e.down, dir.join("client.log").display());
    drop(child);
}

#[tokio::test]
async fn sing_box_client() {
    let Ok(bin) = std::env::var("PRISM_E2E_SINGBOX") else {
        eprintln!("skipped: set PRISM_E2E_SINGBOX");
        return;
    };
    let dir = workdir("singbox");
    let (node, addr, _stop) = start_node(&dir).await;
    let proxy = free_port();
    let cfg = json!({
        "log": {"level": "debug"},
        "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": proxy}],
        "outbounds": [{
            "type": "anytls", "tag": "node", "server": "127.0.0.1", "server_port": addr.port(),
            "password": PASSWORD,
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
        }],
        "route": {"final": "node"}
    });
    std::fs::write(dir.join("client.json"), cfg.to_string()).unwrap();
    let child = spawn(&bin, &["run", "-c", "client.json"], &dir);
    run_client("sing-box", &dir, &node, proxy, child).await;
}

#[tokio::test]
async fn mihomo_client() {
    let Ok(bin) = std::env::var("PRISM_E2E_MIHOMO") else {
        eprintln!("skipped: set PRISM_E2E_MIHOMO");
        return;
    };
    let dir = workdir("mihomo");
    let (node, addr, _stop) = start_node(&dir).await;
    let proxy = free_port();
    let cfg = format!(
        "socks-port: {proxy}\nbind-address: 127.0.0.1\nallow-lan: false\nmode: rule\nlog-level: debug\n\
         geo-auto-update: false\nipv6: false\n\
         proxies:\n  - {{name: node, type: anytls, server: 127.0.0.1, port: {}, password: {PASSWORD}, \
         sni: localhost, skip-cert-verify: true, udp: true}}\n\
         rules:\n  - MATCH,node\n",
        addr.port()
    );
    std::fs::write(dir.join("config.yaml"), cfg).unwrap();
    let d = dir.to_string_lossy().to_string();
    let child = spawn(&bin, &["-d", &d, "-f", "config.yaml"], &dir);
    run_client("mihomo", &dir, &node, proxy, child).await;
}
