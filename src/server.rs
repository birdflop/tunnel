//! Relay implementation for the Birdflop tunnel.
//!
//! The relay accepts control connections from clients (each running next to a
//! Minecraft server) on [`CONTROL_PORT`], and it opens public, host-multiplexed
//! TCP listeners on demand. When a player connects to a public port, the relay
//! reads the Minecraft handshake to learn which hostname they typed, looks up the
//! client that registered that hostname on that port, and proxies the two
//! together. Because routing is by hostname, one public port serves every user.

use std::net::{IpAddr, Ipv4Addr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Result};
use dashmap::DashMap;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep, timeout};
use tracing::{info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::identity::IdentityStore;
use crate::shared::{
    is_valid_label, parse_handshake_hostname, ClientMessage, Delimited, HandshakeParse,
    ServerMessage, CONTROL_PORT, DEFAULT_MC_PORT, MIN_USER_PORT, NETWORK_TIMEOUT,
};

/// Routing table for a single public port: full hostname → control channel.
type PortRouter = DashMap<String, mpsc::Sender<Uuid>>;

/// A player connection awaiting acceptance, plus the bytes already read from it
/// (the handshake) which must be replayed to the backend.
type Pending = (TcpStream, Vec<u8>);

/// State structure for the relay.
pub struct Server {
    /// Range of public ports clients may claim.
    port_range: RangeInclusive<u16>,

    /// Persistent identity store.
    store: Arc<IdentityStore>,

    /// Open host-mux listeners, keyed by public port.
    routers: DashMap<u16, Arc<PortRouter>>,

    /// Serializes opening of new port listeners (binding is async).
    open_lock: Mutex<()>,

    /// Pending player connections awaiting an `Accept`.
    conns: DashMap<Uuid, Pending>,

    /// Base domain that subdomains live under, e.g. `tunnel.birdflop.com`.
    base_domain: String,

    /// Address the control server binds to.
    bind_addr: IpAddr,

    /// Address the public tunnel listeners bind to.
    bind_tunnels: IpAddr,

    /// Control port to listen on.
    control_port: u16,
}

impl Server {
    /// Create a new relay.
    pub fn new(port_range: RangeInclusive<u16>, base_domain: String, store: IdentityStore) -> Self {
        assert!(!port_range.is_empty(), "must provide at least one port");
        Server {
            port_range,
            store: Arc::new(store),
            routers: DashMap::new(),
            open_lock: Mutex::new(()),
            conns: DashMap::new(),
            base_domain,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            control_port: CONTROL_PORT,
        }
    }

    /// Set the address the control server binds to.
    pub fn set_bind_addr(&mut self, bind_addr: IpAddr) {
        self.bind_addr = bind_addr;
    }

    /// Set the address the public tunnel listeners bind to.
    pub fn set_bind_tunnels(&mut self, bind_tunnels: IpAddr) {
        self.bind_tunnels = bind_tunnels;
    }

    /// Set the control port.
    pub fn set_control_port(&mut self, port: u16) {
        self.control_port = port;
    }

    /// Start the relay, listening for control connections forever.
    pub async fn listen(self) -> Result<()> {
        let this = Arc::new(self);

        // Always keep the default Minecraft port open so port-less addresses work.
        if this.port_range.contains(&DEFAULT_MC_PORT) {
            if let Err(err) = this.ensure_port_listener(DEFAULT_MC_PORT).await {
                warn!(%err, port = DEFAULT_MC_PORT, "could not open default port");
            }
        }

        let listener = TcpListener::bind((this.bind_addr, this.control_port)).await?;
        info!(addr = ?this.bind_addr, port = this.control_port, "control server listening");

        loop {
            let (stream, addr) = listener.accept().await?;
            let this = Arc::clone(&this);
            tokio::spawn(
                async move {
                    if let Err(err) = this.handle_control(stream).await {
                        warn!(%err, "control connection exited with error");
                    }
                }
                .instrument(info_span!("control", ?addr)),
            );
        }
    }

    /// Ensure a host-mux listener exists for `port`, returning its router.
    async fn ensure_port_listener(self: &Arc<Self>, port: u16) -> Result<Arc<PortRouter>, String> {
        if let Some(router) = self.routers.get(&port) {
            return Ok(router.value().clone());
        }
        let _guard = self.open_lock.lock().await;
        // Re-check after taking the lock — another task may have opened it.
        if let Some(router) = self.routers.get(&port) {
            return Ok(router.value().clone());
        }
        let listener = TcpListener::bind((self.bind_tunnels, port))
            .await
            .map_err(|err| format!("failed to bind port {port}: {err}"))?;
        let router: Arc<PortRouter> = Arc::new(DashMap::new());
        self.routers.insert(port, router.clone());
        info!(port, "opened public listener");
        Arc::clone(self).spawn_port_accept(port, listener, router.clone());
        Ok(router)
    }

    /// Run the accept loop for one public port.
    fn spawn_port_accept(
        self: Arc<Self>,
        port: u16,
        listener: TcpListener,
        router: Arc<PortRouter>,
    ) {
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((socket, addr)) => {
                        let this = Arc::clone(&self);
                        let router = Arc::clone(&router);
                        tokio::spawn(
                            async move {
                                if let Err(err) = this.handle_player(socket, &router).await {
                                    warn!(%err, "player connection dropped");
                                }
                            }
                            .instrument(info_span!(
                                "player",
                                ?addr,
                                port
                            )),
                        );
                    }
                    Err(err) => warn!(%err, port, "accept error on public listener"),
                }
            }
        });
    }

    /// Read a player's handshake, then hand the connection to the right client.
    async fn handle_player(
        self: Arc<Self>,
        mut socket: TcpStream,
        router: &PortRouter,
    ) -> Result<()> {
        let (hostname, prefix) = read_handshake(&mut socket).await?;
        let tx = match router.get(&hostname) {
            Some(tx) => tx.value().clone(),
            None => {
                // No tunnel registered for this hostname on this port — drop it.
                return Ok(());
            }
        };

        let id = Uuid::new_v4();
        self.conns.insert(id, (socket, prefix));

        // Drop the pending connection if the client never accepts it in time.
        let this = Arc::clone(&self);
        tokio::spawn(async move {
            sleep(Duration::from_secs(10)).await;
            if this.conns.remove(&id).is_some() {
                warn!(%id, "removed stale connection");
            }
        });

        // Send the connection id to the owning client; clean up if it's gone.
        if tx.send(id).await.is_err() {
            self.conns.remove(&id);
        }
        Ok(())
    }

    async fn handle_control(self: Arc<Self>, stream: TcpStream) -> Result<()> {
        let mut stream = Delimited::new(stream);
        match stream.recv_timeout().await? {
            Some(ClientMessage::Register) => {
                let (subdomain, token) = match self.store.issue() {
                    Ok(pair) => pair,
                    Err(err) => {
                        warn!(%err, "failed to issue identity");
                        stream
                            .send(ServerMessage::Error("could not issue identity".into()))
                            .await?;
                        return Ok(());
                    }
                };
                stream
                    .send(ServerMessage::Issued {
                        subdomain: subdomain.clone(),
                        token,
                    })
                    .await?;
                self.serve_registered(stream, subdomain).await
            }
            Some(ClientMessage::Authenticate(subdomain)) => {
                let key = match self.store.token_key(&subdomain) {
                    Some(key) => key,
                    None => {
                        stream
                            .send(ServerMessage::Error("unknown subdomain".into()))
                            .await?;
                        return Ok(());
                    }
                };
                let auth = Authenticator::from_key(&key);
                let challenge = Uuid::new_v4();
                stream.send(ServerMessage::Challenge(challenge)).await?;
                match stream.recv_timeout().await? {
                    Some(ClientMessage::Answer(tag)) if auth.validate(&challenge, &tag) => {
                        stream.send(ServerMessage::Authenticated).await?;
                        self.serve_registered(stream, subdomain).await
                    }
                    _ => {
                        stream
                            .send(ServerMessage::Error("invalid token".into()))
                            .await?;
                        Ok(())
                    }
                }
            }
            Some(ClientMessage::Accept(id)) => self.handle_accept(stream, id).await,
            _ => Ok(()),
        }
    }

    /// After a client authenticates, handle its `Listen` and run the notify loop.
    async fn serve_registered(
        self: Arc<Self>,
        mut stream: Delimited<TcpStream>,
        subdomain: String,
    ) -> Result<()> {
        let (port, label) = match stream.recv_timeout().await? {
            Some(ClientMessage::Listen { port, label }) => (port, label),
            _ => {
                stream
                    .send(ServerMessage::Error("expected a listen request".into()))
                    .await?;
                return Ok(());
            }
        };

        if port <= MIN_USER_PORT {
            stream
                .send(ServerMessage::Error(format!(
                    "port must be above {MIN_USER_PORT}"
                )))
                .await?;
            return Ok(());
        }
        if !self.port_range.contains(&port) {
            stream
                .send(ServerMessage::Error("port not in allowed range".into()))
                .await?;
            return Ok(());
        }
        if let Some(label) = &label {
            if !is_valid_label(label) {
                stream
                    .send(ServerMessage::Error("invalid label".into()))
                    .await?;
                return Ok(());
            }
        }

        let hostname = match &label {
            Some(label) => format!("{label}.{subdomain}.{}", self.base_domain),
            None => format!("{subdomain}.{}", self.base_domain),
        };

        let router = match self.ensure_port_listener(port).await {
            Ok(router) => router,
            Err(err) => {
                stream.send(ServerMessage::Error(err)).await?;
                return Ok(());
            }
        };
        if router.contains_key(&hostname) {
            stream
                .send(ServerMessage::Error("address already in use".into()))
                .await?;
            return Ok(());
        }

        let (tx, mut rx) = mpsc::channel::<Uuid>(32);
        router.insert(hostname.clone(), tx);

        let address = if port == DEFAULT_MC_PORT {
            hostname.clone()
        } else {
            format!("{hostname}:{port}")
        };
        info!(%address, "tunnel registered");
        stream.send(ServerMessage::Bound(address)).await?;

        // Forward connection notifications and heartbeat. A failed send means the
        // client is gone, which ends the loop and unregisters the hostname.
        let mut heartbeat = interval(Duration::from_millis(900));
        let result = loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(id) => {
                        if stream.send(ServerMessage::Connection(id)).await.is_err() {
                            break Ok(());
                        }
                    }
                    None => break Ok(()),
                },
                _ = heartbeat.tick() => {
                    if stream.send(ServerMessage::Heartbeat).await.is_err() {
                        break Ok(());
                    }
                }
            }
        };

        router.remove(&hostname);
        info!(%hostname, "tunnel unregistered");
        result
    }

    /// Splice a client's accept stream onto the pending player connection.
    async fn handle_accept(&self, stream: Delimited<TcpStream>, id: Uuid) -> Result<()> {
        match self.conns.remove(&id) {
            Some((_, (mut player, prefix))) => {
                let mut parts = stream.into_parts();
                debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                // Any bytes the client pre-sent on the accept stream go to the player.
                player.write_all(&parts.read_buf).await?;
                // The peeked handshake bytes go to the backend (via the client).
                parts.io.write_all(&prefix).await?;
                copy_bidirectional(&mut parts.io, &mut player).await?;
            }
            None => warn!(%id, "missing connection for accept"),
        }
        Ok(())
    }
}

/// Read until we can parse the Minecraft handshake, returning the typed hostname
/// and every byte consumed so far (to be replayed to the backend).
async fn read_handshake(socket: &mut TcpStream) -> Result<(String, Vec<u8>)> {
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let n = timeout(NETWORK_TIMEOUT, socket.read(&mut chunk)).await??;
        if n == 0 {
            bail!("connection closed before handshake");
        }
        buf.extend_from_slice(&chunk[..n]);
        match parse_handshake_hostname(&buf) {
            HandshakeParse::Ok(hostname) => return Ok((hostname, buf)),
            HandshakeParse::Invalid => bail!("not a valid Minecraft handshake"),
            HandshakeParse::NeedMore => {
                if buf.len() > 2048 {
                    bail!("handshake too large");
                }
            }
        }
    }
}
