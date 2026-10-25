//! Per-user traffic counters and the registry of live sessions (so a reload
//! can disconnect users that were removed or whose password changed).
//!
//! Counters are cumulative since the process started and survive reloads;
//! readers compute deltas and treat a smaller value as a restart, like sbm
//! already does for its iptables counters.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use serde::Serialize;
use tokio_util::sync::CancellationToken;

#[derive(Default)]
pub struct Counter {
    pub up: AtomicU64,
    pub down: AtomicU64,
}

impl Counter {
    pub fn add_up(&self, n: usize) {
        self.up.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub fn add_down(&self, n: usize) {
        self.down.fetch_add(n as u64, Ordering::Relaxed);
    }
}

struct Live {
    inbound: String,
    user: String,
    password_hash: [u8; 32],
    cancel: CancellationToken,
}

pub struct Stats {
    started: Instant,
    users: RwLock<HashMap<String, Arc<Counter>>>,
    sessions: Mutex<HashMap<u64, Live>>,
    next_id: AtomicU64,
}

/// Removes its session from the registry when dropped.
pub struct SessionGuard {
    stats: Arc<Stats>,
    id: u64,
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.stats.sessions.lock().unwrap().remove(&self.id);
    }
}

#[derive(Serialize)]
pub struct UserReport {
    pub up: u64,
    pub down: u64,
    pub sessions: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub version: &'static str,
    pub uptime: u64,
    pub sessions: usize,
    pub users: BTreeMap<String, UserReport>,
}

impl Default for Stats {
    fn default() -> Self {
        Stats { started: Instant::now(), users: Default::default(), sessions: Default::default(), next_id: AtomicU64::new(1) }
    }
}

impl Stats {
    pub fn counter(&self, user: &str) -> Arc<Counter> {
        if let Some(c) = self.users.read().unwrap().get(user) {
            return c.clone();
        }
        self.users.write().unwrap().entry(user.to_string()).or_default().clone()
    }

    pub fn register(
        self: &Arc<Self>,
        inbound: &str,
        user: &str,
        password_hash: [u8; 32],
        cancel: CancellationToken,
    ) -> SessionGuard {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let live = Live { inbound: inbound.to_string(), user: user.to_string(), password_hash, cancel };
        self.sessions.lock().unwrap().insert(id, live);
        SessionGuard { stats: self.clone(), id }
    }

    /// Cancels sessions for which `still_valid(inbound, password_hash, user)`
    /// is false; returns how many.
    pub fn kick(&self, still_valid: impl Fn(&str, &[u8; 32], &str) -> bool) -> usize {
        let sessions = self.sessions.lock().unwrap();
        let mut n = 0;
        for s in sessions.values() {
            if !still_valid(&s.inbound, &s.password_hash, &s.user) && !s.cancel.is_cancelled() {
                s.cancel.cancel();
                n += 1;
            }
        }
        n
    }

    pub fn report(&self) -> Report {
        let mut live: HashMap<&str, usize> = HashMap::new();
        let sessions = self.sessions.lock().unwrap();
        for s in sessions.values() {
            *live.entry(s.user.as_str()).or_default() += 1;
        }
        let users = self
            .users
            .read()
            .unwrap()
            .iter()
            .map(|(name, c)| {
                let r = UserReport {
                    up: c.up.load(Ordering::Relaxed),
                    down: c.down.load(Ordering::Relaxed),
                    sessions: live.get(name.as_str()).copied().unwrap_or(0),
                };
                (name.clone(), r)
            })
            .collect();
        Report {
            version: env!("CARGO_PKG_VERSION"),
            uptime: self.started.elapsed().as_secs(),
            sessions: sessions.len(),
            users,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_and_kicks() {
        let stats = Arc::new(Stats::default());
        stats.counter("a").add_up(10);
        stats.counter("a").add_down(5);
        let t1 = CancellationToken::new();
        let t2 = CancellationToken::new();
        let g1 = stats.register("in", "a", [1; 32], t1.clone());
        let _g2 = stats.register("in", "b", [2; 32], t2.clone());
        let r = stats.report();
        assert_eq!(r.sessions, 2);
        assert_eq!((r.users["a"].up, r.users["a"].down, r.users["a"].sessions), (10, 5, 1));

        assert_eq!(stats.kick(|_, h, _| h == &[2; 32]), 1);
        assert!(t1.is_cancelled() && !t2.is_cancelled());
        drop(g1);
        assert_eq!(stats.report().sessions, 1);
    }
}
