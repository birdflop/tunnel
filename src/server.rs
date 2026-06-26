//! Relay implementation for the Birdflop tunnel.
//!
//! The relay accepts control connections from clients (each running next to a
//! Minecraft server) on [`CONTROL_PORT`], and it opens public, host-multiplexed
//! TCP listeners on demand. When a player connects to a public port, the relay
//! reads the Minecraft handshake to learn which hostname they typed, looks up the
//! client that registered that hostname on that port, and proxies the two
//! together. Because routing is by hostname, one public port serves every user.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Result};
use dashmap::{mapref::entry::Entry, DashMap};
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};
use tokio::time::{interval, sleep, timeout};
use tracing::{info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::identity::IdentityStore;
use crate::metrics::Metrics;
use crate::shared::{
    is_valid_label, parse_handshake_hostname, ClientMessage, Delimited, HandshakeParse, RouteSpec,
    ServerMessage, CONTROL_PORT, DEFAULT_MC_PORT, HANDSHAKE_TIMEOUT, MIN_USER_PORT, NETWORK_TIMEOUT,
};

/// How often the relay sends a heartbeat on each idle control connection. This
/// both keeps NAT/firewall state warm and lets the relay notice a dead client
/// (the send fails). Kept coarse so thousands of tunnels don't generate a storm
/// of tiny writes.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long a pending player connection waits for its client to `Accept` before
/// the relay drops it.
const PENDING_TTL: Duration = Duration::from_secs(10);

/// Default ceiling on simultaneously pending (un-accepted) player connections.
const DEFAULT_MAX_PENDING: usize = 1024;

/// Default ceiling on routes (ports/labels) one identity may hold at once.
const DEFAULT_MAX_PER_IDENTITY: usize = 10;

/// Routing table for a single public port: full hostname → a sender that carries
/// `(hostname, port, connection id)` to the owning client's control connection.
/// The port travels with the notification because one client multiplexes many
/// routes over a single channel, and the same hostname can appear on several ports.
type PortRouter = DashMap<String, mpsc::Sender<(String, u16, Uuid)>>;

/// A player connection awaiting acceptance, plus the bytes already read from it
/// (the handshake) which must be replayed to the backend.
type Pending = (TcpStream, Vec<u8>);

/// Per-source-IP fixed-window rate limiter for identity issuance, so a single
/// host can't mint unbounded identities (which would bloat the store and its
/// O(n) writes). Entries reset once their window elapses and are pruned lazily.
struct RegistrationLimiter {
    /// source IP → (window start, requests counted in this window).
    seen: DashMap<IpAddr, (Instant, u32)>,
    /// Max issuances allowed per source IP per `window`.
    max_per_window: u32,
    /// Length of the fixed window.
    window: Duration,
}

impl RegistrationLimiter {
    fn new(max_per_window: u32, window: Duration) -> Self {
        Self {
            seen: DashMap::new(),
            max_per_window,
            window,
        }
    }

    /// Record an attempt from `ip`, returning `true` if it is within the limit.
    fn allow(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        // Opportunistically prune so the map can't grow without bound.
        if self.seen.len() > 8192 {
            self.seen
                .retain(|_, (start, _)| now.duration_since(*start) < self.window);
        }
        let mut entry = self.seen.entry(ip).or_insert((now, 0));
        let (start, count) = &mut *entry;
        if now.duration_since(*start) >= self.window {
            *start = now;
            *count = 0;
        }
        if *count >= self.max_per_window {
            false
        } else {
            *count += 1;
            true
        }
    }
}

/// State structure for the relay.
pub struct Server {
    /// Range of public ports clients may claim.
    port_range: RangeInclusive<u16>,

    /// Persistent identity store.
    store: Arc<IdentityStore>,

    /// Open host-mux listeners, keyed by public port.
    routers: DashMap<u16, Arc<PortRouter>>,

    /// Active route count per subdomain, used to enforce a per-identity cap.
    active: DashMap<String, usize>,

    /// Serializes opening of new port listeners (binding is async).
    open_lock: Mutex<()>,

    /// Pending player connections awaiting an `Accept`.
    conns: DashMap<Uuid, Pending>,

    /// Rate limiter for new-identity issuance.
    reg_limiter: RegistrationLimiter,

    /// Base domain that subdomains live under, e.g. `tunnel.birdflop.com`.
    base_domain: String,

    /// Address the control server binds to.
    bind_addr: IpAddr,

    /// Address the public tunnel listeners bind to.
    bind_tunnels: IpAddr,

    /// Control port to listen on.
    control_port: u16,

    /// Ceiling on simultaneously pending (un-accepted) player connections.
    max_pending: usize,

    /// Ceiling on routes one identity may hold at once.
    max_per_identity: usize,

    /// Ceiling on total issued identities (0 = unlimited).
    max_identities: usize,

    /// Address the Prometheus `/metrics` endpoint binds to, if enabled.
    metrics_addr: Option<SocketAddr>,

    /// Collected counters and gauges.
    metrics: Metrics,
}

impl Server {
    /// Create a new relay.
    pub fn new(port_range: RangeInclusive<u16>, base_domain: String, store: IdentityStore) -> Self {
        assert!(!port_range.is_empty(), "must provide at least one port");
        Server {
            port_range,
            store: Arc::new(store),
            routers: DashMap::new(),
            active: DashMap::new(),
            open_lock: Mutex::new(()),
            conns: DashMap::new(),
            reg_limiter: RegistrationLimiter::new(5, Duration::from_secs(60)),
            base_domain,
            bind_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            bind_tunnels: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            control_port: CONTROL_PORT,
            max_pending: DEFAULT_MAX_PENDING,
            max_per_identity: DEFAULT_MAX_PER_IDENTITY,
            max_identities: 0,
            metrics_addr: None,
            metrics: Metrics::default(),
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

    /// Set the ceiling on simultaneously pending player connections.
    pub fn set_max_pending(&mut self, max_pending: usize) {
        self.max_pending = max_pending;
    }

    /// Set the ceiling on routes one identity may hold at once.
    pub fn set_max_per_identity(&mut self, max_per_identity: usize) {
        self.max_per_identity = max_per_identity;
    }

    /// Set the ceiling on total issued identities (0 = unlimited).
    pub fn set_max_identities(&mut self, max_identities: usize) {
        self.max_identities = max_identities;
    }

    /// Configure the new-identity issuance rate limit (per source IP).
    pub fn set_register_rate(&mut self, max_per_window: u32, window: Duration) {
        self.reg_limiter = RegistrationLimiter::new(max_per_window, window);
    }

    /// Enable the Prometheus `/metrics` endpoint on `addr`.
    pub fn set_metrics_addr(&mut self, addr: SocketAddr) {
        self.metrics_addr = Some(addr);
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

        // Spin up the metrics endpoint if configured. A bind failure there must
        // not take down the relay, so it logs and exits on its own.
        if let Some(addr) = this.metrics_addr {
            let m = Arc::clone(&this);
            tokio::spawn(async move {
                if let Err(err) = m.serve_metrics(addr).await {
                    warn!(%err, "metrics endpoint exited");
                }
            });
        }

        let listener = TcpListener::bind((this.bind_addr, this.control_port)).await?;
        info!(addr = ?this.bind_addr, port = this.control_port, "control server listening");

        loop {
            let (stream, addr) = listener.accept().await?;
            // Minecraft is latency-sensitive and chatty with tiny packets; disable
            // Nagle so control and proxied bytes are not coalesced/delayed.
            let _ = stream.set_nodelay(true);
            let this = Arc::clone(&this);
            tokio::spawn(
                async move {
                    if let Err(err) = this.handle_control(stream, addr).await {
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
                        let _ = socket.set_nodelay(true);
                        let this = Arc::clone(&self);
                        let router = Arc::clone(&router);
                        tokio::spawn(
                            async move {
                                if let Err(err) = this.handle_player(socket, port, &router).await {
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
        port: u16,
        router: &PortRouter,
    ) -> Result<()> {
        // Bound the whole handshake read so a slow/bad client can't pin the
        // connection; on timeout or a malformed handshake we drop it quietly.
        let (hostname, prefix) = match timeout(HANDSHAKE_TIMEOUT, read_handshake(&mut socket)).await
        {
            Ok(Ok(parsed)) => parsed,
            Ok(Err(_)) | Err(_) => {
                self.metrics.handshake_failed();
                return Ok(());
            }
        };
        let tx = match router.get(&hostname) {
            Some(tx) => tx.value().clone(),
            None => {
                // No tunnel registered for this hostname on this port — drop it.
                self.metrics.unknown_host();
                return Ok(());
            }
        };

        // Cap how many un-accepted connections we hold, so a join-flood against a
        // known hostname can't exhaust memory.
        if self.conns.len() >= self.max_pending {
            warn!(%hostname, "pending connection limit reached; dropping");
            self.metrics.pending_full();
            return Ok(());
        }

        let id = Uuid::new_v4();
        self.conns.insert(id, (socket, prefix));
        self.metrics.player_connected();

        // Drop the pending connection if the client never accepts it in time.
        let this = Arc::clone(&self);
        tokio::spawn(async move {
            sleep(PENDING_TTL).await;
            if this.conns.remove(&id).is_some() {
                warn!(%id, "removed stale connection");
                this.metrics.stale_connection();
            }
        });

        // Send the connection id to the owning client; clean up if it's gone.
        if tx.send((hostname, port, id)).await.is_err() {
            self.conns.remove(&id);
        }
        Ok(())
    }

    async fn handle_control(self: Arc<Self>, stream: TcpStream, addr: SocketAddr) -> Result<()> {
        let mut stream = Delimited::new(stream);
        match stream.recv_timeout().await? {
            Some(ClientMessage::Register) => {
                if !self.reg_limiter.allow(addr.ip()) {
                    warn!(ip = %addr.ip(), "registration rate limit hit");
                    self.metrics.registration_rate_limited();
                    stream
                        .send(ServerMessage::Error("registration rate limit exceeded".into()))
                        .await?;
                    return Ok(());
                }
                if self.max_identities != 0 && self.store.count() >= self.max_identities {
                    warn!("identity capacity reached; refusing registration");
                    self.metrics.registration_at_capacity();
                    stream
                        .send(ServerMessage::Error("identity capacity reached".into()))
                        .await?;
                    return Ok(());
                }
                // Issuance writes the store to disk; run it off the async workers.
                let store = Arc::clone(&self.store);
                let issued = tokio::task::spawn_blocking(move || store.issue()).await;
                let (subdomain, token) = match issued {
                    Ok(Ok(pair)) => pair,
                    Ok(Err(err)) => {
                        warn!(%err, "failed to issue identity");
                        stream
                            .send(ServerMessage::Error("could not issue identity".into()))
                            .await?;
                        return Ok(());
                    }
                    Err(err) => {
                        warn!(%err, "issue task panicked");
                        stream
                            .send(ServerMessage::Error("could not issue identity".into()))
                            .await?;
                        return Ok(());
                    }
                };
                self.metrics.registration_issued();
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
                        self.metrics.auth_failed();
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
                        self.metrics.auth_failed();
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

    /// After a client authenticates, register its routes and run the notify loop.
    ///
    /// One control connection may carry many routes; they all share a single
    /// notify channel, and each `Connection` notification names the matched
    /// hostname so the client knows which local backend to dial.
    async fn serve_registered(
        self: Arc<Self>,
        mut stream: Delimited<TcpStream>,
        subdomain: String,
    ) -> Result<()> {
        let routes = match stream.recv_timeout().await? {
            Some(ClientMessage::Listen { routes }) => routes,
            _ => {
                stream
                    .send(ServerMessage::Error("expected a listen request".into()))
                    .await?;
                return Ok(());
            }
        };
        if routes.is_empty() {
            stream
                .send(ServerMessage::Error("listen request had no routes".into()))
                .await?;
            return Ok(());
        }

        // Atomically reserve per-identity slots for the whole request.
        let count = routes.len();
        let over_cap = {
            let mut slot = self.active.entry(subdomain.clone()).or_insert(0);
            if *slot + count > self.max_per_identity {
                true
            } else {
                *slot += count;
                false
            }
        };
        if over_cap {
            stream
                .send(ServerMessage::Error(format!(
                    "too many tunnels for this identity (max {})",
                    self.max_per_identity
                )))
                .await?;
            return Ok(());
        }

        // Register each route, rolling everything back on the first failure.
        let (tx, mut rx) = mpsc::channel::<(String, u16, Uuid)>(32);
        let mut registered: Vec<(u16, String)> = Vec::with_capacity(count);
        let mut addresses: Vec<String> = Vec::with_capacity(count);
        let mut error: Option<String> = None;
        for spec in &routes {
            match self.register_route(spec, &subdomain, &tx).await {
                Ok((port, hostname, address)) => {
                    registered.push((port, hostname));
                    addresses.push(address);
                }
                Err(err) => {
                    error = Some(err);
                    break;
                }
            }
        }
        if let Some(err) = error {
            self.unregister_routes(&registered);
            self.release_slots(&subdomain, count);
            stream.send(ServerMessage::Error(err)).await?;
            return Ok(());
        }

        for address in &addresses {
            info!(%address, "tunnel registered");
        }
        stream.send(ServerMessage::Bound { addresses }).await?;

        // Forward connection notifications and heartbeat. A failed send means the
        // client is gone, which ends the loop and unregisters every route.
        let mut heartbeat = interval(HEARTBEAT_INTERVAL);
        let result = loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some((hostname, port, id)) => {
                        if stream
                            .send(ServerMessage::Connection { id, hostname, port })
                            .await
                            .is_err()
                        {
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

        self.unregister_routes(&registered);
        for (_, hostname) in &registered {
            info!(%hostname, "tunnel unregistered");
        }
        self.release_slots(&subdomain, count);
        result
    }

    /// Validate and register a single route, returning `(port, hostname, address)`.
    /// The shared `tx` is cloned into the port router so player connections for the
    /// route flow back to the owning control connection.
    async fn register_route(
        self: &Arc<Self>,
        spec: &RouteSpec,
        subdomain: &str,
        tx: &mpsc::Sender<(String, u16, Uuid)>,
    ) -> Result<(u16, String, String), String> {
        if spec.port <= MIN_USER_PORT {
            return Err(format!("port must be above {MIN_USER_PORT}"));
        }
        if !self.port_range.contains(&spec.port) {
            return Err("port not in allowed range".into());
        }
        if let Some(label) = &spec.label {
            if !is_valid_label(label) {
                return Err("invalid label".into());
            }
        }
        let hostname = match &spec.label {
            Some(label) => format!("{label}.{subdomain}.{}", self.base_domain),
            None => format!("{subdomain}.{}", self.base_domain),
        };
        let router = self.ensure_port_listener(spec.port).await?;
        // Atomic vacancy check so two sessions can't claim the same hostname.
        match router.entry(hostname.clone()) {
            Entry::Occupied(_) => return Err(format!("address already in use: {hostname}")),
            Entry::Vacant(slot) => {
                slot.insert(tx.clone());
            }
        }
        let address = if spec.port == DEFAULT_MC_PORT {
            hostname.clone()
        } else {
            format!("{hostname}:{}", spec.port)
        };
        Ok((spec.port, hostname, address))
    }

    /// Remove the given `(port, hostname)` registrations from their port routers.
    fn unregister_routes(&self, registered: &[(u16, String)]) {
        for (port, hostname) in registered {
            if let Some(router) = self.routers.get(port) {
                router.remove(hostname);
            }
        }
    }

    /// Release `count` previously reserved per-identity slots, dropping the entry
    /// once it reaches zero.
    fn release_slots(&self, subdomain: &str, count: usize) {
        let now_zero = match self.active.get_mut(subdomain) {
            Some(mut slot) => {
                *slot = slot.saturating_sub(count);
                *slot == 0
            }
            None => false,
        };
        if now_zero {
            // Only remove if still zero, so we don't race a concurrent reservation.
            self.active.remove_if(subdomain, |_, v| *v == 0);
        }
    }

    /// Splice a client's accept stream onto the pending player connection.
    async fn handle_accept(&self, stream: Delimited<TcpStream>, id: Uuid) -> Result<()> {
        match self.conns.remove(&id) {
            Some((_, (mut player, prefix))) => {
                let mut parts = stream.into_parts();
                debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
                // Count this as live until the splice ends (even on an early error).
                let _guard = self.metrics.connection_guard();
                // Any bytes the client pre-sent on the accept stream go to the player.
                player.write_all(&parts.read_buf).await?;
                // The peeked handshake bytes go to the backend (via the client).
                parts.io.write_all(&prefix).await?;
                let (to_backend, to_player) =
                    copy_bidirectional(&mut parts.io, &mut player).await?;
                self.metrics.add_bytes(to_backend + to_player);
            }
            None => warn!(%id, "missing connection for accept"),
        }
        Ok(())
    }

    /// Serve the Prometheus `/metrics` endpoint. Each scrape gets a fresh snapshot;
    /// the request line is read and ignored (any path returns the metrics).
    async fn serve_metrics(self: Arc<Self>, addr: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;
        info!(?addr, "metrics endpoint listening");
        loop {
            let (mut socket, _) = listener.accept().await?;
            let this = Arc::clone(&self);
            tokio::spawn(async move {
                // Drain the request headers (bounded) before replying.
                let mut buf = [0u8; 1024];
                let _ = timeout(NETWORK_TIMEOUT, socket.read(&mut buf)).await;
                let body = this.metrics_text();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    }

    /// Render the current metrics, reading live gauges from relay state.
    fn metrics_text(&self) -> String {
        let active_identities = self.store.count() as u64;
        let pending = self.conns.len() as u64;
        let open_ports = self.routers.len() as u64;
        let active_tunnels: u64 = self.routers.iter().map(|r| r.value().len() as u64).sum();
        self.metrics
            .render(active_identities, pending, open_ports, active_tunnels)
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
