//! prism-node against prism-core's AnyTLS client, plus raw protocol checks
//! for what that client does not exercise (SYNACK, padding update, alerts,
//! fallback, reload).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use prism_core::common::Address;
use prism_core::config::ProxyConfig;
use prism_core::outbound::anytls::AnyTls;
use prism_core::outbound::tls::Tls;
use prism_core::outbound::{Dialer, Outbound};
use prism_node::proto::*;
use prism_node::server::Node;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

struct TestNode {
    node: Arc<Node>,
    addr: SocketAddr,
    dir: PathBuf,
    _shutdown: tokio_util::sync::DropGuard,
}

fn write_config(dir: &std::path::Path, users: &[(&str, &str)], fallback: Option<SocketAddr>) {
    let users: Vec<_> = users.iter().map(|(n, p)| json!({"name": n, "password": p})).collect();
    let mut inbound = json!({
        "type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": 1,
        "users": users,
        "tls": {"enabled": true, "certificate_path": "cert.pem", "key_path": "key.pem"}
    });
    if let Some(fb) = fallback {
        inbound["fallback"] = json!({"server": fb.ip().to_string(), "server_port": fb.port()});
    }
    let cfg = json!({"api": {"listen": ""}, "allow_local": true, "inbounds": [inbound]});
    std::fs::write(dir.join("config.json"), serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
}

async fn start(name: &str, users: &[(&str, &str)], fallback: Option<SocketAddr>) -> TestNode {
    let dir = std::env::temp_dir().join(format!("prism-node-it-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), c.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), c.key_pair.serialize_pem()).unwrap();
    write_config(&dir, users, fallback);
    let path = dir.join("config.json");
    let mut cfg = prism_node::config::load(&path).unwrap();
    // Any free port; reload keeps comparing against port 1 only for a warning.
    cfg.inbounds[0].listen.set_port(0);
    let node = Node::new(&cfg, Some(path));
    let shutdown = CancellationToken::new();
    let addr = node.start(shutdown.clone()).await.unwrap()[0];
    TestNode { node, addr, dir, _shutdown: shutdown.drop_guard() }
}

fn client(addr: SocketAddr, password: &str) -> AnyTls {
    let p = ProxyConfig {
        name: "t".into(),
        server: addr.ip().to_string(),
        port: addr.port(),
        password: Some(password.into()),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        ..Default::default()
    };
    AnyTls::new(&p, Dialer::Direct).unwrap()
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
    let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
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

async fn echo_once(c: &AnyTls, target: SocketAddr, msg: &[u8]) -> std::io::Result<()> {
    let mut s = c.connect(&Address::Ip(target)).await?;
    s.write_all(msg).await?;
    let mut got = vec![0u8; msg.len()];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got)).await??;
    assert_eq!(got, msg);
    Ok(())
}

async fn eventually(mut f: impl FnMut() -> bool) {
    for _ in 0..100 {
        if f() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("condition not reached");
}

#[tokio::test]
async fn tcp_relay_session_reuse_and_stats() {
    let n = start("tcp", &[("alice", "pw-a")], None).await;
    let echo = tcp_echo().await;
    let c = client(n.addr, "pw-a");
    let big = vec![7u8; 200_000];
    echo_once(&c, echo, b"hello").await.unwrap();
    // The client pools the session once both FINs went through; then the
    // second stream reuses it (stream id 2).
    tokio::time::sleep(Duration::from_millis(300)).await;
    echo_once(&c, echo, &big).await.unwrap();
    let total = 5 + big.len() as u64;
    let ok = || {
        let r = n.node.stats.report();
        r.users.get("alice").is_some_and(|u| u.up == total && u.down == total)
    };
    for _ in 0..100 {
        if ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ok(), "{}", serde_json::to_string(&n.node.stats.report()).unwrap());
    assert_eq!(n.node.stats.report().sessions, 1, "one TLS session for both streams");
}

#[tokio::test]
async fn udp_over_tcp() {
    let n = start("udp", &[("alice", "pw-a")], None).await;
    let echo = udp_echo().await;
    let c = client(n.addr, "pw-a");
    let mut pipe = c.connect_udp(&Address::Ip(echo)).await.unwrap();
    for msg in [&b"ping"[..], &[1u8; 1400][..]] {
        pipe.tx.send(msg.to_vec()).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(5), pipe.rx.recv()).await.unwrap().unwrap();
        assert_eq!(got, msg);
    }
    eventually(|| n.node.stats.report().users["alice"].down == 1404).await;
}

/// A bare AnyTLS connection for driving the protocol by hand.
async fn raw(addr: SocketAddr, password: &str) -> prism_core::common::BoxedStream {
    let tls = Tls::new("localhost", true, &[], None).unwrap();
    let mut s = tls.connect(&Dialer::Direct, &addr.ip().to_string(), addr.port()).await.unwrap();
    let mut hello = Sha256::digest(password.as_bytes()).to_vec();
    hello.extend_from_slice(&3u16.to_be_bytes());
    hello.extend_from_slice(b"pad");
    s.write_all(&hello).await.unwrap();
    s
}

async fn next_frame<R: AsyncRead + Unpin>(r: &mut R) -> (u8, u32, Vec<u8>) {
    let fut = async {
        let mut h = [0u8; HEADER_LEN];
        r.read_exact(&mut h).await.unwrap();
        let mut d = vec![0u8; u16::from_be_bytes([h[5], h[6]]) as usize];
        r.read_exact(&mut d).await.unwrap();
        (h[0], u32::from_be_bytes([h[1], h[2], h[3], h[4]]), d)
    };
    tokio::time::timeout(Duration::from_secs(5), fut).await.expect("frame")
}

#[tokio::test]
async fn raw_protocol_v2() {
    let n = start("raw", &[("alice", "pw-a")], None).await;
    let echo = tcp_echo().await;
    let mut s = raw(n.addr, "pw-a").await;

    let mut f = Vec::new();
    frame(&mut f, CMD_SETTINGS, 0, b"v=2\nclient=test\npadding-md5=00");
    s.write_all(&f).await.unwrap();
    let (cmd, _, data) = next_frame(&mut s).await;
    assert_eq!((cmd, data.as_slice()), (CMD_UPDATE_PADDING, DEFAULT_PADDING_SCHEME.as_bytes()));
    let (cmd, _, data) = next_frame(&mut s).await;
    assert_eq!((cmd, data.as_slice()), (CMD_SERVER_SETTINGS, &b"v=2"[..]));

    // Stream 1 to the echo server: SYNACK without error, then data.
    let mut f = Vec::new();
    let mut dest = Vec::new();
    Address::Ip(echo).write_socks(&mut dest);
    frame(&mut f, CMD_SYN, 1, &[]);
    frame(&mut f, CMD_PSH, 1, &dest);
    frame(&mut f, CMD_PSH, 1, b"abc");
    s.write_all(&f).await.unwrap();
    assert_eq!(next_frame(&mut s).await, (CMD_SYNACK, 1, vec![]));
    assert_eq!(next_frame(&mut s).await, (CMD_PSH, 1, b"abc".to_vec()));

    // Heartbeat.
    let mut f = Vec::new();
    frame(&mut f, CMD_HEART_REQUEST, 0, &[]);
    s.write_all(&f).await.unwrap();
    assert_eq!(next_frame(&mut s).await.0, CMD_HEART_RESPONSE);

    // Stream 2 to a closed port: SYNACK carries the error, then FIN.
    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
    let mut f = Vec::new();
    let mut dest = Vec::new();
    Address::Ip(closed).write_socks(&mut dest);
    frame(&mut f, CMD_SYN, 2, &[]);
    frame(&mut f, CMD_PSH, 2, &dest);
    s.write_all(&f).await.unwrap();
    let (cmd, sid, err) = next_frame(&mut s).await;
    assert_eq!((cmd, sid), (CMD_SYNACK, 2));
    assert!(!err.is_empty());
    assert_eq!(next_frame(&mut s).await, (CMD_FIN, 2, vec![]));

    // Client FIN on stream 1: the server answers with its FIN.
    let mut f = Vec::new();
    frame(&mut f, CMD_FIN, 1, &[]);
    s.write_all(&f).await.unwrap();
    assert_eq!(next_frame(&mut s).await, (CMD_FIN, 1, vec![]));
}

#[tokio::test]
async fn syn_before_settings_is_an_alert() {
    let n = start("alert", &[("alice", "pw-a")], None).await;
    let mut s = raw(n.addr, "pw-a").await;
    let mut f = Vec::new();
    frame(&mut f, CMD_SYN, 1, &[]);
    s.write_all(&f).await.unwrap();
    assert_eq!(next_frame(&mut s).await.0, CMD_ALERT);
}

#[tokio::test]
async fn bad_password_goes_to_fallback() {
    let decoy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let decoy_addr = decoy.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut s, _) = decoy.accept().await.unwrap();
        let mut req = vec![0u8; 18];
        s.read_exact(&mut req).await.unwrap();
        assert_eq!(&req, b"GET / HTTP/1.1\r\n\r\n");
        s.write_all(b"HTTP/1.1 200 OK\r\n\r\ndecoy").await.unwrap();
    });
    let n = start("fallback", &[("alice", "pw-a")], Some(decoy_addr)).await;
    let tls = Tls::new("localhost", true, &[], None).unwrap();
    let mut s = tls.connect(&Dialer::Direct, "127.0.0.1", n.addr.port()).await.unwrap();
    s.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut resp = String::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_string(&mut resp)).await.unwrap().ok();
    assert!(resp.ends_with("decoy"), "{resp:?}");

    // With the decoy gone, a wrong password just gets disconnected.
    let c = client(n.addr, "wrong");
    assert!(echo_once(&c, decoy_addr, b"x").await.is_err());
}

#[tokio::test]
async fn reload_adds_users_and_kicks_removed_ones() {
    let n = start("reload", &[("alice", "pw-a"), ("bob", "pw-b")], None).await;
    let echo = tcp_echo().await;
    let bob = client(n.addr, "pw-b");
    let mut bob_stream = bob.connect(&Address::Ip(echo)).await.unwrap();
    bob_stream.write_all(b"hi").await.unwrap();
    let mut b2 = [0u8; 2];
    bob_stream.read_exact(&mut b2).await.unwrap();

    write_config(&n.dir, &[("alice", "pw-a"), ("carol", "pw-c")], None);
    let r = n.node.reload().unwrap();
    assert_eq!((r.users, r.kicked), (2, 1));

    // Bob's open stream ends; new connections fail; carol works right away.
    let mut rest = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), bob_stream.read_to_end(&mut rest)).await;
    assert!(read.is_ok(), "bob's stream should end");
    assert!(echo_once(&client(n.addr, "pw-b"), echo, b"x").await.is_err());
    echo_once(&client(n.addr, "pw-c"), echo, b"carol").await.unwrap();
    echo_once(&client(n.addr, "pw-a"), echo, b"alice").await.unwrap();
}
