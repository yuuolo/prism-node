//! AnyTLS protocol v2 definitions (compatible with anytls-go, sing-anytls
//! and the Prism client).
//!
//! Wire format after the TLS handshake:
//!   auth:  sha256(password)[32] | padding_len u16 BE | padding
//!   frame: cmd u8 | stream_id u32 BE | data_len u16 BE | data
//!
//! Settings frames carry `key=value` lines. A stream's first PSH data is
//! the destination as a SOCKS address.

use std::collections::HashMap;

use md5::{Digest as _, Md5};

pub const CMD_WASTE: u8 = 0;
pub const CMD_SYN: u8 = 1;
pub const CMD_PSH: u8 = 2;
pub const CMD_FIN: u8 = 3;
pub const CMD_SETTINGS: u8 = 4;
pub const CMD_ALERT: u8 = 5;
pub const CMD_UPDATE_PADDING: u8 = 6;
pub const CMD_SYNACK: u8 = 7;
pub const CMD_HEART_REQUEST: u8 = 8;
pub const CMD_HEART_RESPONSE: u8 = 9;
pub const CMD_SERVER_SETTINGS: u8 = 10;

pub const HEADER_LEN: usize = 7;
/// Largest data field a frame can carry.
pub const MAX_FRAME_DATA: usize = u16::MAX as usize;

/// sing-box UDP-over-TCP v2: a stream to this address carries datagrams.
pub const UOT_MAGIC: &str = "sp.v2.udp-over-tcp.arpa";
/// UDP-over-TCP v1 (no request header, every packet addressed).
pub const UOT_LEGACY_MAGIC: &str = "sp.udp-over-tcp.arpa";

/// anytls-go / sing-anytls default padding scheme.
pub const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

/// Appends one frame to `buf`. `data` must fit in [`MAX_FRAME_DATA`].
pub fn frame(buf: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    debug_assert!(data.len() <= MAX_FRAME_DATA);
    buf.push(cmd);
    buf.extend_from_slice(&sid.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Hex md5 of a padding scheme, as exchanged in settings (`padding-md5`).
pub fn padding_md5(scheme: &[u8]) -> String {
    hex::encode(Md5::digest(scheme))
}

/// Parses `key=value` lines (settings frames, padding schemes).
pub fn parse_kv(b: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(b)
        .split('\n')
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// A padding scheme is usable when it has a numeric `stop` (what
/// sing-anytls checks before accepting one).
pub fn valid_padding_scheme(scheme: &[u8]) -> bool {
    parse_kv(scheme).get("stop").is_some_and(|s| s.parse::<u32>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_layout() {
        let mut b = Vec::new();
        frame(&mut b, CMD_PSH, 1, b"hi");
        assert_eq!(b, [2, 0, 0, 0, 1, 0, 2, b'h', b'i']);
    }

    #[test]
    fn settings_and_padding() {
        let m = parse_kv(b"v=2\nclient=x\npadding-md5=abc");
        assert_eq!(m["v"], "2");
        assert_eq!(m["padding-md5"], "abc");
        assert!(valid_padding_scheme(DEFAULT_PADDING_SCHEME.as_bytes()));
        assert!(!valid_padding_scheme(b"0=30-30"));
        assert_eq!(padding_md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
