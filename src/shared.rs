//! Shared data structures, utilities, and protocol definitions.

use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_util::codec::{AnyDelimiterCodec, Framed, FramedParts};
use tracing::trace;
use uuid::Uuid;

/// TCP port used for control connections with the relay.
pub const CONTROL_PORT: u16 = 7835;

/// Default public Minecraft port. A player who types just `name.tunnel.birdflop.com`
/// (no port) connects here, so we always keep a host-mux listener open on it.
pub const DEFAULT_MC_PORT: u16 = 25565;

/// Lowest public port a client is allowed to claim. Ports must be strictly above this.
pub const MIN_USER_PORT: u16 = 1000;

/// Maximum byte length for a JSON frame in the stream. Large enough to carry a
/// `Listen`/`Bound` for a client that registers many routes at once.
pub const MAX_FRAME_LENGTH: usize = 8 * 1024;

/// Timeout for network connections and initial protocol messages.
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(3);

/// Total wall-clock budget for reading a player's Minecraft handshake. This is a
/// hard ceiling on the whole read loop (not per-read like [`NETWORK_TIMEOUT`]),
/// so a slowloris that dribbles bytes can't pin a public connection open.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// One route a client wants to expose: a public port and an optional sub-label.
/// The relay registers `[label.]subdomain.<base>` on `port` and proxies it to the
/// backend the client paired with this route.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteSpec {
    /// Public port to expose (must be above [`MIN_USER_PORT`]).
    pub port: u16,
    /// Optional sub-label, e.g. `survival` in `survival.name.tunnel.birdflop.com`.
    pub label: Option<String>,
}

/// A message from the client on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Request a brand-new identity. The relay issues a subdomain + token and
    /// treats this connection as authenticated for that subdomain.
    Register,

    /// Authenticate as an existing identity, named by its (public) subdomain.
    /// The relay replies with a [`ServerMessage::Challenge`].
    Authenticate(String),

    /// Answer to an authentication challenge (HMAC of the challenge under the token).
    Answer(String),

    /// After authenticating, claim one or more routes to forward. Each route is an
    /// independent `[label.]subdomain.<base>` on its own port, all multiplexed over
    /// this single control connection.
    Listen {
        /// The routes to register. Must be non-empty.
        routes: Vec<RouteSpec>,
    },

    /// Accepts an incoming TCP connection, using this stream as a proxy.
    Accept(Uuid),
}

/// A message from the relay on the control connection.
#[derive(Debug, Serialize, Deserialize)]
pub enum ServerMessage {
    /// A newly issued identity, in response to [`ClientMessage::Register`]. The
    /// token is plaintext and shown to the user only this once.
    Issued {
        /// The assigned public subdomain (e.g. `a3k9zq`).
        subdomain: String,
        /// The secret token used to re-authenticate later. Store it; never share it.
        token: String,
    },

    /// Authentication challenge, in response to [`ClientMessage::Authenticate`].
    Challenge(Uuid),

    /// Confirms a successful existing-identity authentication.
    Authenticated,

    /// Confirms a [`ClientMessage::Listen`], carrying the public address for each
    /// requested route, in the same order (e.g. `a3k9zq.tunnel.birdflop.com` or
    /// `survival.a3k9zq.tunnel.birdflop.com:25566`).
    Bound {
        /// One public address per registered route, in request order.
        addresses: Vec<String>,
    },

    /// No-op used to test if the client is still reachable.
    Heartbeat,

    /// Asks the client to accept a forwarded TCP connection. `hostname` and
    /// `port` together identify the route the player connected to, so a
    /// multi-route client knows which local backend to dial. Both are needed:
    /// two routes can share a hostname but differ by port (and vice versa).
    Connection {
        /// Identifier the client echoes back in [`ClientMessage::Accept`].
        id: Uuid,
        /// The matched route's hostname (e.g. `survival.a3k9zq.tunnel.birdflop.com`).
        hostname: String,
        /// The public port the player connected on.
        port: u16,
    },

    /// Indicates a server error that terminates the connection.
    Error(String),
}

/// Whether a string is a valid single DNS label (sub-name) we'll accept.
pub fn is_valid_label(label: &str) -> bool {
    let len = label.len();
    if len == 0 || len > 63 {
        return false;
    }
    if label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    label
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Outcome of trying to parse a Minecraft handshake from a partial buffer.
pub enum HandshakeParse {
    /// Parsed successfully; carries the (normalized) server address the player typed.
    Ok(String),
    /// Not enough bytes yet — read more and try again.
    NeedMore,
    /// Not a valid modern Minecraft handshake.
    Invalid,
}

/// Read a Minecraft-style VarInt from `buf` at `*pos`, advancing `*pos` on success.
/// Returns `None` if the buffer ends mid-VarInt (caller should read more) or if
/// it is malformed (more than 5 bytes).
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<i32> {
    let mut result: i32 = 0;
    let mut shift = 0u32;
    let mut cur = *pos;
    loop {
        let byte = *buf.get(cur)?;
        cur += 1;
        result |= ((byte & 0x7f) as i32) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= 35 {
            return None; // malformed VarInt
        }
    }
    *pos = cur;
    Some(result)
}

/// Try to extract the server address from the first packet of a Minecraft
/// connection (the C→S Handshake, packet id 0x00).
///
/// The handshake layout is: VarInt packet length, then a body of
/// `[VarInt id=0][VarInt protocol][String address][u16 port][VarInt next-state]`.
/// We only need `address`. FML/Forge and proxy-forwarding clients append extra
/// data after a NUL byte, so we keep only the part before the first NUL, strip a
/// trailing dot, and lowercase it.
pub fn parse_handshake_hostname(buf: &[u8]) -> HandshakeParse {
    // Legacy (pre-1.7) ping starts with 0xFE — not supported.
    if buf.first() == Some(&0xFE) {
        return HandshakeParse::Invalid;
    }

    let mut pos = 0;
    let packet_len = match read_varint(buf, &mut pos) {
        Some(v) if v > 0 => v as usize,
        Some(_) => return HandshakeParse::Invalid,
        None => return HandshakeParse::NeedMore,
    };
    if packet_len > 1024 {
        return HandshakeParse::Invalid; // a handshake is tiny; this isn't one
    }
    if buf.len() - pos < packet_len {
        return HandshakeParse::NeedMore;
    }

    let packet = &buf[pos..pos + packet_len];
    let mut p = 0;
    match read_varint(packet, &mut p) {
        Some(0) => {} // handshake packet id
        _ => return HandshakeParse::Invalid,
    }
    if read_varint(packet, &mut p).is_none() {
        return HandshakeParse::Invalid; // protocol version
    }
    let addr_len = match read_varint(packet, &mut p) {
        Some(v) if v >= 0 => v as usize,
        _ => return HandshakeParse::Invalid,
    };
    if addr_len > 255 || p + addr_len > packet.len() {
        return HandshakeParse::Invalid;
    }
    let addr = match std::str::from_utf8(&packet[p..p + addr_len]) {
        Ok(s) => s,
        Err(_) => return HandshakeParse::Invalid,
    };

    let hostname = addr
        .split('\0')
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if hostname.is_empty() {
        return HandshakeParse::Invalid;
    }
    HandshakeParse::Ok(hostname)
}

/// Transport stream with JSON frames delimited by null characters.
pub struct Delimited<U>(Framed<U, AnyDelimiterCodec>);

impl<U: AsyncRead + AsyncWrite + Unpin> Delimited<U> {
    /// Construct a new delimited stream.
    pub fn new(stream: U) -> Self {
        let codec = AnyDelimiterCodec::new_with_max_length(vec![0], vec![0], MAX_FRAME_LENGTH);
        Self(Framed::new(stream, codec))
    }

    /// Read the next null-delimited JSON instruction from a stream.
    pub async fn recv<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        trace!("waiting to receive json message");
        if let Some(next_message) = self.0.next().await {
            let byte_message = next_message.context("frame error, invalid byte length")?;
            let serialized_obj =
                serde_json::from_slice(&byte_message).context("unable to parse message")?;
            Ok(serialized_obj)
        } else {
            Ok(None)
        }
    }

    /// Read the next null-delimited JSON instruction, with a default timeout.
    ///
    /// This is useful for parsing the initial message of a stream for handshake or
    /// other protocol purposes, where we do not want to wait indefinitely.
    pub async fn recv_timeout<T: DeserializeOwned>(&mut self) -> Result<Option<T>> {
        timeout(NETWORK_TIMEOUT, self.recv())
            .await
            .context("timed out waiting for initial message")?
    }

    /// Send a null-terminated JSON instruction on a stream.
    pub async fn send<T: Serialize>(&mut self, msg: T) -> Result<()> {
        trace!("sending json message");
        self.0.send(serde_json::to_string(&msg)?).await?;
        Ok(())
    }

    /// Consume this object, returning current buffers and the inner transport.
    pub fn into_parts(self) -> FramedParts<U, AnyDelimiterCodec> {
        self.0.into_parts()
    }
}

#[cfg(test)]
mod tests {
    use super::{is_valid_label, parse_handshake_hostname, HandshakeParse};

    fn write_varint(buf: &mut Vec<u8>, mut value: u32) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            buf.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    /// Build a Minecraft C→S handshake packet for the given address/port.
    pub fn handshake(address: &str, port: u16) -> Vec<u8> {
        let mut body = Vec::new();
        write_varint(&mut body, 0); // packet id (handshake)
        write_varint(&mut body, 765); // protocol version
        write_varint(&mut body, address.len() as u32);
        body.extend_from_slice(address.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        write_varint(&mut body, 2); // next state: login

        let mut packet = Vec::new();
        write_varint(&mut packet, body.len() as u32);
        packet.extend_from_slice(&body);
        packet
    }

    #[test]
    fn parses_hostname() {
        let pkt = handshake("a3k9zq.tunnel.birdflop.com", 25565);
        match parse_handshake_hostname(&pkt) {
            HandshakeParse::Ok(host) => assert_eq!(host, "a3k9zq.tunnel.birdflop.com"),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn strips_forge_suffix_and_lowercases() {
        let pkt = handshake("Survival.A3K9ZQ.tunnel.birdflop.com\0FML2\0", 25566);
        match parse_handshake_hostname(&pkt) {
            HandshakeParse::Ok(host) => assert_eq!(host, "survival.a3k9zq.tunnel.birdflop.com"),
            _ => panic!("expected Ok"),
        }
    }

    #[test]
    fn needs_more_when_truncated() {
        let pkt = handshake("a3k9zq.tunnel.birdflop.com", 25565);
        assert!(matches!(
            parse_handshake_hostname(&pkt[..3]),
            HandshakeParse::NeedMore
        ));
    }

    #[test]
    fn rejects_legacy_ping() {
        assert!(matches!(
            parse_handshake_hostname(&[0xFE, 0x01]),
            HandshakeParse::Invalid
        ));
    }

    #[test]
    fn labels() {
        assert!(is_valid_label("survival"));
        assert!(is_valid_label("lobby-1"));
        assert!(!is_valid_label("-bad"));
        assert!(!is_valid_label("bad-"));
        assert!(!is_valid_label("Has.Dot"));
        assert!(!is_valid_label(""));
    }
}
