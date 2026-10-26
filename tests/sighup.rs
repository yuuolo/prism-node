//! The real binary under Unix signals: SIGHUP reloads users and
//! certificates (keeping the old config when the new one is broken),
//! SIGTERM exits cleanly.
#![cfg(unix)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use prism_core::common::Address;
use prism_core::config::ProxyConfig;
use prism_core::outbound::anytls::AnyTls;
use prism_core::outbound::{Dialer, Outbound};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Proc(Child);

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn new_cert(dir: &Path) {
    let c = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(dir.join("cert.pem"), c.cert.pem()).unwrap();
    std::fs::write(dir.join("key.pem"), c.key_pair.serialize_pem()).unwrap();
}

fn write_config(dir: &Path, port: u16, users: &[(&str, &str)]) {
    let users: Vec<_> = users.iter().map(|(n, p)| json!({"name": n, "password": p})).collect();
    let cfg = json!({
        "log": {"level": "debug"},
        "api": {"listen": ""},
        "allow_local": true,
        "inbounds": [{
            "type": "anytls", "tag": "anytls-in", "listen": "127.0.0.1", "listen_port": port,
            "users": users,
            "tls": {"enabled": true, "certificate_path": "cert.pem", "key_path": "key.pem"}
        }]
    });
    // Write then rename, like sbm's push script: a reload never sees half a file.
    std::fs::write(dir.join("config.tmp"), cfg.to_string()).unwrap();
    std::fs::rename(dir.join("config.tmp"), dir.join("config.json")).unwrap();
}

fn signal(p: &Proc, sig: &str) {
    let ok = Command::new("kill").args([sig, &p.0.id().to_string()]).status().unwrap().success();
    assert!(ok, "kill {sig}");
}

/// Waits until the log has `n` lines containing `needle`; returns the last.
async fn log_line(log: &Path, needle: &str, n: usize) -> String {
    for _ in 0..100 {
        let text = std::fs::read_to_string(log).unwrap_or_default();
        let hits: Vec<&str> = text.lines().filter(|l| l.contains(needle)).collect();
        if hits.len() >= n {
            return hits[n - 1].to_string();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("log has no {n}x {needle:?}:\n{}", std::fs::read_to_string(log).unwrap_or_default());
}

fn client(port: u16, password: &str) -> AnyTls {
    let p = ProxyConfig {
        name: "t".into(),
        server: "127.0.0.1".into(),
        port,
        password: Some(password.into()),
        sni: Some("localhost".into()),
        skip_cert_verify: true,
        ..Default::default()
    };
    AnyTls::new(&p, Dialer::Direct).unwrap()
}

async fn echo_server() -> SocketAddr {
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

async fn works(c: &AnyTls, echo: SocketAddr) -> bool {
    let attempt = async {
        let mut s = c.connect(&Address::Ip(echo)).await?;
        s.write_all(b"ping").await?;
        let mut b = [0u8; 4];
        s.read_exact(&mut b).await?;
        Ok::<_, std::io::Error>(&b == b"ping")
    };
    matches!(tokio::time::timeout(Duration::from_secs(5), attempt).await, Ok(Ok(true)))
}

/// Accepts any certificate and remembers the one it saw.
#[derive(Debug)]
struct Capture(Mutex<Option<Vec<u8>>>, Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for Capture {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.0.lock().unwrap() = Some(end_entity.to_vec());
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.1.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.1.signature_verification_algorithms.supported_schemes()
    }
}

async fn served_cert(port: u16) -> Vec<u8> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let capture = Arc::new(Capture(Mutex::new(None), provider.clone()));
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(capture.clone())
        .with_no_client_auth();
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let name = ServerName::try_from("localhost").unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await.unwrap();
    let der = capture.0.lock().unwrap().clone().unwrap();
    der
}

fn workdir() -> PathBuf {
    let d = std::env::temp_dir().join(format!("prism-node-sighup-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[tokio::test]
async fn sighup_reload_and_sigterm() {
    let dir = workdir();
    let port = free_port();
    new_cert(&dir);
    write_config(&dir, port, &[("alice", "pw-a")]);
    let log = dir.join("node.log");
    let out = std::fs::File::create(&log).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_prism-node"))
        .args(["run", "-c"])
        .arg(dir.join("config.json"))
        .stdin(Stdio::null())
        .stdout(out.try_clone().unwrap())
        .stderr(out)
        .spawn()
        .unwrap();
    let mut node = Proc(child);
    log_line(&log, "listening on", 1).await;
    let echo = echo_server().await;
    let (alice, bob) = (client(port, "pw-a"), client(port, "pw-b"));

    assert!(works(&alice, echo).await, "alice before reload");
    assert!(!works(&bob, echo).await, "bob is not a user yet");

    // 1. New user: usable right after SIGHUP, nobody disconnected.
    write_config(&dir, port, &[("alice", "pw-a"), ("bob", "pw-b")]);
    signal(&node, "-HUP");
    let l = log_line(&log, "reloaded:", 1).await;
    assert!(l.contains("2 users, 0 sessions disconnected"), "{l}");
    assert!(works(&bob, echo).await, "bob after reload");

    // 2. Removed user: alice's pooled session is disconnected and she can
    //    no longer connect; bob is untouched.
    tokio::time::sleep(Duration::from_millis(300)).await;
    write_config(&dir, port, &[("bob", "pw-b")]);
    signal(&node, "-HUP");
    let l = log_line(&log, "reloaded:", 2).await;
    assert!(l.contains("1 users, 1 sessions disconnected"), "{l}");
    assert!(!works(&alice, echo).await, "alice was removed");
    assert!(works(&bob, echo).await, "bob after alice's removal");

    // 3. Broken config: the node keeps running on the old one.
    std::fs::write(dir.join("config.json"), "{ not json").unwrap();
    signal(&node, "-HUP");
    log_line(&log, "reload failed, keeping the old config", 1).await;
    assert!(node.0.try_wait().unwrap().is_none(), "node must survive a bad config");
    assert!(works(&bob, echo).await, "bob with the old config");

    // 4. Renewed certificate: served from the next handshake on.
    let before = served_cert(port).await;
    new_cert(&dir);
    write_config(&dir, port, &[("bob", "pw-b")]);
    signal(&node, "-HUP");
    log_line(&log, "reloaded:", 3).await;
    let after = served_cert(port).await;
    assert_ne!(before, after, "new certificate after reload");
    assert!(works(&client(port, "pw-b"), echo).await, "bob with the new certificate");

    // 5. SIGTERM: clean exit.
    signal(&node, "-TERM");
    let mut status = None;
    for _ in 0..100 {
        if let Some(s) = node.0.try_wait().unwrap() {
            status = Some(s);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let status = status.expect("node exits on SIGTERM");
    assert!(status.success(), "exit status {status}");
    log_line(&log, "shutting down", 1).await;
    std::fs::remove_dir_all(&dir).ok();
}
