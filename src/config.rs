//! Node config: the sing-box config format, of which only `anytls` inbounds
//! are used. sbm's per-user `direct` outbounds and `auth_user` route rules
//! (its iptables traffic accounting) are ignored: counting is built in.
//!
//! Extensions sing-box does not have:
//! - `inbounds[].fallback: {server, server_port}`: where connections that
//!   fail authentication are relayed (plaintext, after TLS), so probes see
//!   an ordinary site instead of a closed connection.
//! - top-level `api: {listen}`: the local control API (default
//!   `127.0.0.1:9550`; an empty string disables it).
//! - top-level `allow_local: true`: let clients reach loopback, link-local
//!   (cloud metadata) and unspecified addresses, which are refused by
//!   default so users cannot reach the node's own services such as the API.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use crate::address::Address;
use crate::proto::{valid_padding_scheme, DEFAULT_PADDING_SCHEME};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use serde_json::Value;

pub const DEFAULT_API: &str = "127.0.0.1:9550";

pub struct Config {
    pub log_level: String,
    pub api: Option<SocketAddr>,
    pub allow_local: bool,
    pub inbounds: Vec<Inbound>,
    pub warnings: Vec<String>,
}

pub struct Inbound {
    pub tag: String,
    pub listen: SocketAddr,
    pub users: Vec<User>,
    pub padding_scheme: Vec<u8>,
    pub tls: Arc<rustls::ServerConfig>,
    pub fallback: Option<Address>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct User {
    #[serde(default)]
    pub name: String,
    pub password: String,
}

#[derive(Deserialize)]
struct RawInbound {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    listen_port: u16,
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    padding_scheme: Vec<String>,
    #[serde(default)]
    tls: Option<RawTls>,
    #[serde(default)]
    fallback: Option<RawServer>,
}

#[derive(Deserialize)]
struct RawTls {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    alpn: Vec<String>,
    #[serde(default)]
    certificate_path: Option<PathBuf>,
    #[serde(default)]
    key_path: Option<PathBuf>,
    /// Inline PEM: one string or a list of lines.
    #[serde(default)]
    certificate: Option<Lines>,
    #[serde(default)]
    key: Option<Lines>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Lines {
    One(String),
    Many(Vec<String>),
}

impl Lines {
    fn join(&self) -> String {
        match self {
            Lines::One(s) => s.clone(),
            Lines::Many(v) => v.join("\n"),
        }
    }
}

#[derive(Deserialize)]
struct RawServer {
    server: String,
    server_port: u16,
}

pub fn load(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let base = path.parent().unwrap_or(Path::new("."));
    parse(&raw, base)
}

/// Parses a config; relative certificate paths are resolved against `base`.
pub fn parse(raw: &str, base: &Path) -> Result<Config> {
    let doc: Value = serde_json::from_str(raw).context("config is not valid JSON")?;
    let mut warnings = Vec::new();
    let log_level = doc.pointer("/log/level").and_then(Value::as_str).unwrap_or("info").to_string();
    let api = match doc.pointer("/api/listen").and_then(Value::as_str).unwrap_or(DEFAULT_API) {
        "" => None,
        s => Some(s.parse().with_context(|| format!("api.listen: bad address {s}"))?),
    };
    let allow_local = doc.get("allow_local").and_then(Value::as_bool).unwrap_or(false);

    let mut inbounds = Vec::new();
    for (i, v) in doc.get("inbounds").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let raw: RawInbound = serde_json::from_value(v.clone()).with_context(|| format!("inbounds[{i}]"))?;
        if raw.kind != "anytls" {
            warnings.push(format!("inbounds[{i}]: type {} is not supported, skipped", raw.kind));
            continue;
        }
        let tag = if raw.tag.is_empty() { format!("anytls-{i}") } else { raw.tag.clone() };
        inbounds.push(inbound(raw, tag.clone(), base, &mut warnings).with_context(|| format!("inbound {tag}"))?);
    }
    if inbounds.is_empty() {
        bail!("no anytls inbound in config");
    }
    let mut seen = std::collections::HashSet::new();
    for ib in &inbounds {
        if !seen.insert(&ib.tag) {
            bail!("duplicate inbound tag {}", ib.tag);
        }
    }
    Ok(Config { log_level, api, allow_local, inbounds, warnings })
}

/// Just `api.listen`, for the `stats` / `reload` commands (no certificate
/// loading, so they work without access to the key).
pub fn api_addr(path: &Path) -> Result<Option<SocketAddr>> {
    let raw = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let doc: Value = serde_json::from_str(&raw).context("config is not valid JSON")?;
    match doc.pointer("/api/listen").and_then(Value::as_str).unwrap_or(DEFAULT_API) {
        "" => Ok(None),
        s => Ok(Some(s.parse().with_context(|| format!("api.listen: bad address {s}"))?)),
    }
}

fn inbound(raw: RawInbound, tag: String, base: &Path, warnings: &mut Vec<String>) -> Result<Inbound> {
    if raw.listen_port == 0 {
        bail!("listen_port is required");
    }
    let ip: IpAddr = match raw.listen.as_deref() {
        None | Some("") => Ipv6Addr::UNSPECIFIED.into(),
        Some(s) => s.trim_start_matches('[').trim_end_matches(']').parse().with_context(|| format!("bad listen address {s}"))?,
    };
    if raw.users.is_empty() {
        warnings.push(format!("inbound {tag}: no users, every connection will be rejected"));
    }
    let mut passwords = std::collections::HashSet::new();
    for u in &raw.users {
        if u.password.is_empty() {
            bail!("user {:?} has an empty password", u.name);
        }
        if !passwords.insert(&u.password) {
            warnings.push(format!("inbound {tag}: users share a password; only the last one ({}) is used", u.name));
        }
    }
    let padding_scheme = if raw.padding_scheme.is_empty() {
        DEFAULT_PADDING_SCHEME.as_bytes().to_vec()
    } else {
        raw.padding_scheme.join("\n").into_bytes()
    };
    if !valid_padding_scheme(&padding_scheme) {
        bail!("padding_scheme has no valid stop=N line");
    }
    if padding_scheme.len() > u16::MAX as usize {
        bail!("padding_scheme is too long");
    }
    let tls = match raw.tls {
        Some(t) if t.enabled => server_tls(&t, base)?,
        _ => bail!("tls must be enabled for anytls"),
    };
    let fallback = raw.fallback.map(|f| Address::new(&f.server, f.server_port));
    Ok(Inbound { tag, listen: SocketAddr::new(ip, raw.listen_port), users: raw.users, padding_scheme, tls, fallback })
}

fn read_pem(inline: &Option<Lines>, path: &Option<PathBuf>, base: &Path, what: &str) -> Result<Vec<u8>> {
    if let Some(l) = inline {
        return Ok(l.join().into_bytes());
    }
    let Some(p) = path else { bail!("tls.{what}_path or tls.{what} is required") };
    let p = base.join(p);
    std::fs::read(&p).with_context(|| format!("read {}", p.display()))
}

fn server_tls(t: &RawTls, base: &Path) -> Result<Arc<rustls::ServerConfig>> {
    let cert_pem = read_pem(&t.certificate, &t.certificate_path, base, "certificate")?;
    let key_pem = read_pem(&t.key, &t.key_path, base, "key")?;
    let certs = CertificateDer::pem_slice_iter(&cert_pem).collect::<Result<Vec<_>, _>>().context("bad certificate PEM")?;
    if certs.is_empty() {
        bail!("no certificate in PEM");
    }
    let key = PrivateKeyDer::from_pem_slice(&key_pem).context("bad private key PEM")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut cfg = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and key do not match")?;
    cfg.alpn_protocols = t.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Ok(Arc::new(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_files(dir: &Path) {
        let c = rcgen::generate_simple_self_signed(vec!["n1.example.com".into()]).unwrap();
        std::fs::write(dir.join("fullchain.pem"), c.cert.pem()).unwrap();
        std::fs::write(dir.join("privkey.pem"), c.key_pair.serialize_pem()).unwrap();
    }

    /// What sbm's `node_config` + `apply_stats_routing` generate.
    #[test]
    fn sbm_generated_config() {
        let dir = std::env::temp_dir().join(format!("prism-node-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        cert_files(&dir);
        let raw = r#"{
          "log": {"level": "info"},
          "inbounds": [{
            "type": "anytls", "tag": "anytls-in", "listen": "::", "listen_port": 443,
            "users": [{"name": "u001", "password": "p1"}, {"name": "u002", "password": "p2"}],
            "tls": {"enabled": true, "server_name": "n1.example.com",
                    "certificate_path": "fullchain.pem", "key_path": "privkey.pem"}
          }],
          "outbounds": [{"type": "direct", "tag": "direct"},
                        {"type": "direct", "tag": "u-u001", "routing_mark": 4097}],
          "route": {"rules": [{"inbound": ["anytls-in"], "action": "sniff"},
                              {"auth_user": ["u001"], "outbound": "u-u001"}]}
        }"#;
        let c = parse(raw, &dir).unwrap();
        assert_eq!(c.inbounds.len(), 1);
        let ib = &c.inbounds[0];
        assert_eq!(ib.tag, "anytls-in");
        assert_eq!(ib.listen, "[::]:443".parse().unwrap());
        assert_eq!(ib.users.len(), 2);
        assert_eq!(ib.padding_scheme, DEFAULT_PADDING_SCHEME.as_bytes());
        assert_eq!(c.api, Some(DEFAULT_API.parse().unwrap()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn extensions_and_errors() {
        let dir = std::env::temp_dir().join(format!("prism-node-cfg2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        cert_files(&dir);
        let raw = r#"{
          "api": {"listen": ""},
          "inbounds": [
            {"type": "mixed", "listen_port": 1080},
            {"type": "anytls", "listen": "127.0.0.1", "listen_port": 8443,
             "users": [{"name": "a", "password": "x"}],
             "padding_scheme": ["stop=2", "0=10-20", "1=100-200"],
             "fallback": {"server": "127.0.0.1", "server_port": 80},
             "tls": {"enabled": true, "certificate_path": "fullchain.pem", "key_path": "privkey.pem"}}
          ]
        }"#;
        let c = parse(raw, &dir).unwrap();
        assert!(c.api.is_none());
        assert_eq!(c.warnings.len(), 1);
        let ib = &c.inbounds[0];
        assert_eq!(ib.tag, "anytls-1");
        assert_eq!(ib.padding_scheme, b"stop=2\n0=10-20\n1=100-200");
        assert_eq!(ib.fallback, Some(Address::new("127.0.0.1", 80)));

        assert!(parse(r#"{"inbounds": []}"#, &dir).is_err());
        let no_tls = r#"{"inbounds": [{"type": "anytls", "listen_port": 1, "users": [{"password": "x"}]}]}"#;
        assert!(parse(no_tls, &dir).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }
}
