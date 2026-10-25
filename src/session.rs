//! One AnyTLS session (TLS connection) on the server side, following
//! sing-anytls: the client must send its settings before the first SYN; v2
//! clients get server settings and a SYNACK per stream (empty on success,
//! the error text when the destination could not be reached). Clients with
//! an outdated padding scheme are sent ours. The server does not pad.
//!
//! AnyTLS has no half-close: FIN ends a stream. After the client's FIN we
//! close the write side to the destination and keep relaying its replies
//! until it goes quiet for [`LINGER`], then send our FIN.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use crate::address::Address;
use crate::proto::*;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::stats::Counter;
use crate::{dial, uot};

const ADDRESS_TIMEOUT: Duration = Duration::from_secs(10);
const LINGER: Duration = Duration::from_secs(10);
const BUF: usize = 16 * 1024;

pub struct Padding {
    pub raw: Vec<u8>,
    pub md5: String,
}

pub struct SessionCtx {
    pub user: String,
    pub counter: Arc<Counter>,
    pub padding: Arc<Padding>,
    /// Cancelled to end the session (shutdown, or the user was removed).
    pub cancel: CancellationToken,
    pub allow_local: bool,
}

pub struct Session {
    out: mpsc::Sender<Vec<u8>>,
    streams: Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    peer_version: AtomicU8,
    pub counter: Arc<Counter>,
    pub cancel: CancellationToken,
    pub allow_local: bool,
    user: String,
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "session closed")
}

impl Session {
    async fn send_frame(&self, cmd: u8, sid: u32, data: &[u8]) -> io::Result<()> {
        let mut f = Vec::with_capacity(HEADER_LEN + data.len());
        frame(&mut f, cmd, sid, data);
        self.out.send(f).await.map_err(|_| closed())
    }

    /// Sends stream data, split into frames as needed.
    pub async fn send_data(&self, sid: u32, data: &[u8]) -> io::Result<()> {
        for chunk in data.chunks(MAX_FRAME_DATA) {
            self.send_frame(CMD_PSH, sid, chunk).await?;
        }
        Ok(())
    }

    /// Reports the outcome of opening a stream (v2 clients only).
    pub async fn synack(&self, sid: u32, err: Option<&str>) -> io::Result<()> {
        if self.peer_version.load(Ordering::Acquire) < 2 {
            return Ok(());
        }
        let msg = err.unwrap_or("").as_bytes();
        self.send_frame(CMD_SYNACK, sid, &msg[..msg.len().min(MAX_FRAME_DATA)]).await
    }
}

/// Client data of one stream as a byte stream; EOF once the client sent FIN
/// (its sender is removed from the session) or the session ended.
pub struct Inflow {
    rx: mpsc::Receiver<Vec<u8>>,
    buf: Vec<u8>,
    pos: usize,
}

impl AsyncRead for Inflow {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, out: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.pos >= this.buf.len() {
            match this.rx.poll_recv(cx) {
                Poll::Ready(Some(v)) => {
                    this.buf = v;
                    this.pos = 0;
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
        let n = out.remaining().min(this.buf.len() - this.pos);
        out.put_slice(&this.buf[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

async fn read_frame<R: AsyncRead + Unpin>(rd: &mut R, data: &mut Vec<u8>) -> io::Result<(u8, u32)> {
    let mut head = [0u8; HEADER_LEN];
    rd.read_exact(&mut head).await?;
    let sid = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    let len = u16::from_be_bytes([head[5], head[6]]) as usize;
    data.resize(len, 0);
    rd.read_exact(data).await?;
    Ok((head[0], sid))
}

/// Runs the session until the client disconnects or `ctx.cancel` fires.
pub async fn run<R, W>(mut rd: R, wr: W, ctx: SessionCtx) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
    // A kick stops the writer at once; otherwise it sends what is queued
    // (e.g. an alert) and stops when the last stream task is gone.
    let writer = tokio::spawn(write_loop(wr, rx, ctx.cancel.clone()));
    let sess = Arc::new(Session {
        out: tx,
        streams: Mutex::new(HashMap::new()),
        peer_version: AtomicU8::new(0),
        counter: ctx.counter,
        cancel: ctx.cancel.child_token(),
        allow_local: ctx.allow_local,
        user: ctx.user,
    });
    let res = read_loop(&sess, &mut rd, &ctx.padding).await;
    sess.cancel.cancel();
    sess.streams.lock().unwrap().clear();
    drop(sess);
    let _ = writer.await;
    match res {
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        r => r,
    }
}

async fn read_loop<R: AsyncRead + Unpin>(sess: &Arc<Session>, rd: &mut R, padding: &Padding) -> io::Result<()> {
    let mut settings_received = false;
    let mut data = Vec::with_capacity(MAX_FRAME_DATA);
    loop {
        let (cmd, sid) = tokio::select! {
            _ = sess.cancel.cancelled() => return Ok(()),
            r = read_frame(rd, &mut data) => r?,
        };
        match cmd {
            CMD_PSH => {
                if data.is_empty() {
                    continue;
                }
                let tx = sess.streams.lock().unwrap().get(&sid).cloned();
                // A slow destination holds up the whole session, as in
                // anytls-go; the stream's buffer absorbs short bursts.
                if let Some(tx) = tx {
                    if tx.send(data.clone()).await.is_err() {
                        sess.streams.lock().unwrap().remove(&sid);
                    }
                }
            }
            CMD_SYN => {
                if !settings_received {
                    sess.send_frame(CMD_ALERT, 0, b"client did not send its settings").await?;
                    return Ok(());
                }
                if let std::collections::hash_map::Entry::Vacant(e) = sess.streams.lock().unwrap().entry(sid) {
                    let (tx, rx) = mpsc::channel(64);
                    e.insert(tx);
                    tokio::spawn(stream_task(sess.clone(), sid, Inflow { rx, buf: Vec::new(), pos: 0 }));
                }
            }
            CMD_FIN => {
                sess.streams.lock().unwrap().remove(&sid);
            }
            CMD_SETTINGS => {
                settings_received = true;
                let m = parse_kv(&data);
                if m.get("padding-md5") != Some(&padding.md5) {
                    sess.send_frame(CMD_UPDATE_PADDING, 0, &padding.raw).await?;
                }
                if let Some(v) = m.get("v").and_then(|v| v.parse::<u8>().ok()).filter(|v| *v >= 2) {
                    sess.peer_version.store(v, Ordering::Release);
                    sess.send_frame(CMD_SERVER_SETTINGS, 0, b"v=2").await?;
                }
            }
            CMD_HEART_REQUEST => sess.send_frame(CMD_HEART_RESPONSE, sid, &[]).await?,
            CMD_ALERT => return Ok(()),
            // Waste, heartbeat responses and anything unknown.
            _ => {}
        }
    }
}

async fn write_loop<W: AsyncWrite + Unpin>(mut wr: W, mut rx: mpsc::Receiver<Vec<u8>>, cancel: CancellationToken) {
    let res: io::Result<()> = async {
        loop {
            let buf = tokio::select! {
                _ = cancel.cancelled() => break,
                b = rx.recv() => match b { Some(b) => b, None => break },
            };
            wr.write_all(&buf).await?;
            while let Ok(more) = rx.try_recv() {
                wr.write_all(&more).await?;
            }
            wr.flush().await?;
        }
        Ok(())
    }
    .await;
    if res.is_ok() {
        let _ = tokio::time::timeout(Duration::from_secs(2), wr.shutdown()).await;
    }
}

async fn stream_task(sess: Arc<Session>, sid: u32, mut inflow: Inflow) {
    let res = tokio::select! {
        _ = sess.cancel.cancelled() => return,
        r = serve_stream(&sess, sid, &mut inflow) => r,
    };
    if let Err(e) = res {
        tracing::debug!("{} stream {sid}: {e}", sess.user);
    }
    sess.streams.lock().unwrap().remove(&sid);
    let _ = sess.send_frame(CMD_FIN, sid, &[]).await;
}

async fn serve_stream(sess: &Arc<Session>, sid: u32, inflow: &mut Inflow) -> io::Result<()> {
    let dest = tokio::time::timeout(ADDRESS_TIMEOUT, Address::read_socks(inflow))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no destination"))??;
    match dest.domain() {
        // SYNACK first: v1 sends no request, v2 clients send theirs with
        // the first datagram, which may come later than the SYNACK deadline.
        Some(UOT_MAGIC) => {
            sess.synack(sid, None).await?;
            uot::serve(sess, sid, inflow, false).await
        }
        Some(UOT_LEGACY_MAGIC) => {
            sess.synack(sid, None).await?;
            uot::serve(sess, sid, inflow, true).await
        }
        _ => {
            tracing::debug!("{} -> {dest}", sess.user);
            let target = match dial::tcp(&dest, sess.allow_local).await {
                Ok(t) => t,
                Err(e) => {
                    let _ = sess.synack(sid, Some(&e.to_string())).await;
                    return Err(e);
                }
            };
            sess.synack(sid, None).await?;
            relay(sess, sid, inflow, target).await
        }
    }
}

async fn relay(sess: &Session, sid: u32, inflow: &mut Inflow, target: tokio::net::TcpStream) -> io::Result<()> {
    let (mut trd, mut twr) = target.into_split();
    let client_done = CancellationToken::new();
    let upload = async {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = inflow.read(&mut buf).await?;
            if n == 0 {
                client_done.cancel();
                let _ = twr.shutdown().await;
                // Leave the rest to the download side.
                std::future::pending::<()>().await;
            }
            twr.write_all(&buf[..n]).await?;
            sess.counter.add_up(n);
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    let download = async {
        let mut buf = vec![0u8; BUF];
        loop {
            let n = tokio::select! {
                r = trd.read(&mut buf) => r?,
                // Idle timer, restarted for every read once the client is done.
                _ = async { client_done.cancelled().await; tokio::time::sleep(LINGER).await } => return Ok(()),
            };
            if n == 0 {
                return Ok(());
            }
            sess.send_data(sid, &buf[..n]).await?;
            sess.counter.add_down(n);
        }
    };
    tokio::select! {
        r = upload => r,
        r = download => r,
    }
}
