//! Listeners, TLS, AnyTLS authentication (with fallback) and hot reload.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::{Context, Result};
use crate::address::Address;
use crate::proto::padding_md5;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;

use crate::config::{Config, Inbound};
use crate::session::{self, Padding, SessionCtx};
use crate::stats::Stats;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Live state of one inbound; everything but the listen address can change
/// on reload.
pub struct InboundState {
    pub tag: String,
    pub listen: SocketAddr,
    users: RwLock<Arc<HashMap<[u8; 32], String>>>,
    tls: RwLock<TlsAcceptor>,
    padding: RwLock<Arc<Padding>>,
    fallback: RwLock<Option<Address>>,
}

impl InboundState {
    fn new(ib: &Inbound) -> Self {
        InboundState {
            tag: ib.tag.clone(),
            listen: ib.listen,
            users: RwLock::new(Arc::new(user_map(ib))),
            tls: RwLock::new(TlsAcceptor::from(ib.tls.clone())),
            padding: RwLock::new(Arc::new(padding(ib))),
            fallback: RwLock::new(ib.fallback.clone()),
        }
    }

    fn update(&self, ib: &Inbound) {
        *self.users.write().unwrap() = Arc::new(user_map(ib));
        *self.tls.write().unwrap() = TlsAcceptor::from(ib.tls.clone());
        *self.padding.write().unwrap() = Arc::new(padding(ib));
        *self.fallback.write().unwrap() = ib.fallback.clone();
    }

    fn user(&self, hash: &[u8; 32]) -> Option<String> {
        self.users.read().unwrap().get(hash).cloned()
    }
}

fn user_map(ib: &Inbound) -> HashMap<[u8; 32], String> {
    ib.users.iter().map(|u| (Sha256::digest(u.password.as_bytes()).into(), u.name.clone())).collect()
}

fn padding(ib: &Inbound) -> Padding {
    Padding { md5: padding_md5(&ib.padding_scheme), raw: ib.padding_scheme.clone() }
}

#[derive(Serialize)]
pub struct ReloadReport {
    pub users: usize,
    pub kicked: usize,
    pub warnings: Vec<String>,
}

pub struct Node {
    pub path: Option<PathBuf>,
    pub stats: Arc<Stats>,
    pub inbounds: Vec<Arc<InboundState>>,
    pub api: Option<SocketAddr>,
    allow_local: AtomicBool,
}

impl Node {
    pub fn new(cfg: &Config, path: Option<PathBuf>) -> Arc<Node> {
        Arc::new(Node {
            path,
            stats: Arc::new(Stats::default()),
            inbounds: cfg.inbounds.iter().map(|ib| Arc::new(InboundState::new(ib))).collect(),
            api: cfg.api,
            allow_local: AtomicBool::new(cfg.allow_local),
        })
    }

    /// Binds every inbound and starts accepting; returns the bound
    /// addresses in inbound order.
    pub async fn start(self: &Arc<Self>, shutdown: CancellationToken) -> Result<Vec<SocketAddr>> {
        let mut addrs = Vec::new();
        for ib in &self.inbounds {
            let listener = bind(ib.listen).with_context(|| format!("inbound {}: listen on {}", ib.tag, ib.listen))?;
            addrs.push(listener.local_addr()?);
            tracing::info!("inbound {} listening on {}", ib.tag, listener.local_addr()?);
            tokio::spawn(self.clone().accept_loop(ib.clone(), listener, shutdown.clone()));
        }
        Ok(addrs)
    }

    async fn accept_loop(self: Arc<Self>, ib: Arc<InboundState>, listener: TcpListener, shutdown: CancellationToken) {
        loop {
            let (tcp, peer) = tokio::select! {
                _ = shutdown.cancelled() => return,
                r = listener.accept() => match r {
                    Ok(c) => c,
                    Err(e) => {
                        // EMFILE and friends: back off instead of spinning.
                        tracing::warn!("inbound {}: accept: {e}", ib.tag);
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                },
            };
            let node = self.clone();
            let ib = ib.clone();
            let shutdown = shutdown.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle(&ib, tcp, peer, shutdown).await {
                    tracing::debug!("{peer} [{}]: {e}", ib.tag);
                }
            });
        }
    }

    async fn handle(&self, ib: &InboundState, tcp: TcpStream, peer: SocketAddr, shutdown: CancellationToken) -> io::Result<()> {
        tcp.set_nodelay(true)?;
        set_keepalive(&tcp);
        let acceptor = ib.tls.read().unwrap().clone();
        let mut tls = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out"))??;

        // Like sing-anytls: the client sends its auth in one write, so the
        // first read decides; anything else goes to the fallback.
        let mut first = vec![0u8; 8192];
        let n = tokio::time::timeout(HANDSHAKE_TIMEOUT, tls.read(&mut first))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no data after TLS handshake"))??;
        first.truncate(n);
        let hash: Option<[u8; 32]> = first.get(..32).map(|h| h.try_into().unwrap());
        let user = hash.and_then(|h| ib.user(&h).map(|u| (h, u)));
        let Some((hash, user)) = user.filter(|_| first.len() >= 34) else {
            let fallback = ib.fallback.read().unwrap().clone();
            return match fallback {
                Some(fb) => relay_fallback(tls, &first, &fb).await,
                None => Err(io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed")),
            };
        };
        let pad = u16::from_be_bytes([first[32], first[33]]) as usize;
        let mut rest = first.split_off(34);
        if rest.len() < pad {
            let mut more = vec![0u8; pad - rest.len()];
            tls.read_exact(&mut more).await?;
            rest.clear();
        } else {
            rest.drain(..pad);
        }

        let cancel = shutdown.child_token();
        let _guard = self.stats.register(&ib.tag, &user, hash, cancel.clone());
        tracing::debug!("{peer} [{}] session for {user}", ib.tag);
        let ctx = SessionCtx {
            counter: self.stats.counter(&user),
            user,
            padding: ib.padding.read().unwrap().clone(),
            cancel,
            allow_local: self.allow_local.load(Ordering::Relaxed),
        };
        let (rd, wr) = tokio::io::split(tls);
        session::run(std::io::Cursor::new(rest).chain(rd), wr, ctx).await
    }

    /// Re-reads the config file and applies what can change without a
    /// restart: users, certificates, padding scheme, fallback. Sessions of
    /// removed users (or changed passwords) are disconnected.
    pub fn reload(&self) -> Result<ReloadReport> {
        let path = self.path.as_ref().context("node was not started from a config file")?;
        let cfg = crate::config::load(path)?;
        Ok(self.apply(&cfg))
    }

    pub fn apply(&self, cfg: &Config) -> ReloadReport {
        let mut warnings = cfg.warnings.clone();
        for state in &self.inbounds {
            match cfg.inbounds.iter().find(|ib| ib.tag == state.tag) {
                Some(ib) => {
                    if ib.listen != state.listen {
                        warnings.push(format!("inbound {}: listen address change needs a restart", ib.tag));
                    }
                    state.update(ib);
                }
                None => {
                    warnings.push(format!("inbound {} was removed; it rejects everyone until a restart", state.tag));
                    *state.users.write().unwrap() = Default::default();
                }
            }
        }
        for ib in &cfg.inbounds {
            if !self.inbounds.iter().any(|s| s.tag == ib.tag) {
                warnings.push(format!("new inbound {} needs a restart", ib.tag));
            }
        }
        if cfg.api != self.api {
            warnings.push("api.listen change needs a restart".into());
        }
        self.allow_local.store(cfg.allow_local, Ordering::Relaxed);
        let kicked = self.stats.kick(|tag, hash, user| {
            self.inbounds.iter().find(|s| s.tag == tag).and_then(|s| s.user(hash)).is_some_and(|u| u == user)
        });
        let users = self.inbounds.iter().map(|s| s.users.read().unwrap().len()).sum();
        for w in &warnings {
            tracing::warn!("{w}");
        }
        tracing::info!("reloaded: {users} users, {kicked} sessions disconnected");
        ReloadReport { users, kicked, warnings }
    }
}

/// `::` listens on IPv4 too, like sing-box (Windows defaults to v6-only).
fn bind(addr: SocketAddr) -> io::Result<TcpListener> {
    use socket2::{Domain, Socket, Type};
    let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    if addr.is_ipv6() && addr.ip().is_unspecified() {
        sock.set_only_v6(false)?;
    }
    #[cfg(unix)]
    sock.set_reuse_address(true)?;
    sock.bind(&addr.into())?;
    sock.listen(1024)?;
    sock.set_nonblocking(true)?;
    TcpListener::from_std(sock.into())
}

/// Detects dead clients (pooled sessions can sit idle for a long time).
fn set_keepalive(tcp: &TcpStream) {
    let ka = socket2::TcpKeepalive::new().with_time(Duration::from_secs(60)).with_interval(Duration::from_secs(15));
    let _ = socket2::SockRef::from(tcp).set_tcp_keepalive(&ka);
}

async fn relay_fallback<S>(mut client: S, consumed: &[u8], fb: &Address) -> io::Result<()>
where
    S: AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut upstream = TcpStream::connect((fb.host().as_str(), fb.port())).await?;
    upstream.write_all(consumed).await?;
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}
