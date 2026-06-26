//! Client implementation for the Birdflop tunnel.
//!
//! The client runs next to one or more Minecraft servers. It authenticates to the
//! relay (or requests a new identity on first run), claims one or more public
//! routes under its subdomain, and then forwards each incoming connection to the
//! matching local server. All routes are multiplexed over a single control
//! connection; each `Connection` notification names the hostname the player used,
//! so the client knows which local backend to dial.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tracing::{error, info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{ClientMessage, Delimited, RouteSpec, ServerMessage, NETWORK_TIMEOUT};

/// An existing identity to authenticate with: `(subdomain, secret token)`.
pub type Identity = (String, String);

/// One route to expose: a public port (and optional sub-label) under the user's
/// subdomain, forwarded to a local backend.
#[derive(Clone, Debug)]
pub struct Route {
    /// Optional sub-label, e.g. `survival` in `survival.<you>.tunnel.birdflop.com`.
    pub label: Option<String>,
    /// Public port to expose under the subdomain.
    pub public_port: u16,
    /// Local host to forward this route to.
    pub local_host: String,
    /// Local port to forward this route to.
    pub local_port: u16,
}

/// State structure for the client.
pub struct Client {
    /// Control connection to the relay.
    conn: Option<Delimited<TcpStream>>,

    /// Relay host.
    to: String,

    /// Relay control port.
    control_port: u16,

    /// Map of `(public hostname, public port)` → local backend `(host, port)`.
    /// Keyed by both because the same hostname can be served on several ports.
    targets: HashMap<(String, u16), (String, u16)>,

    /// Public addresses players connect to, one per registered route.
    addresses: Vec<String>,

    /// A newly issued identity, if one was created during [`Client::new`].
    issued: Option<Identity>,
}

impl Client {
    /// Create a new client and register one or more routes.
    ///
    /// If `identity` is `Some`, the client authenticates as that subdomain;
    /// otherwise it requests a brand-new identity from the relay.
    pub async fn new(
        to: &str,
        control_port: u16,
        routes: Vec<Route>,
        identity: Option<Identity>,
    ) -> Result<Self> {
        if routes.is_empty() {
            bail!("at least one route is required");
        }

        let mut stream = Delimited::new(connect_with_timeout(to, control_port).await?);
        let mut issued = None;

        match identity {
            Some((subdomain, token)) => {
                stream.send(ClientMessage::Authenticate(subdomain)).await?;
                match stream.recv_timeout().await? {
                    Some(ServerMessage::Challenge(challenge)) => {
                        let auth = Authenticator::new(&token);
                        stream
                            .send(ClientMessage::Answer(auth.answer(&challenge)))
                            .await?;
                    }
                    Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
                    Some(_) => bail!("unexpected response to authenticate"),
                    None => bail!("unexpected EOF during authentication"),
                }
                match stream.recv_timeout().await? {
                    Some(ServerMessage::Authenticated) => {}
                    Some(ServerMessage::Error(message)) => {
                        bail!("authentication failed: {message}")
                    }
                    Some(_) => bail!("unexpected authentication result"),
                    None => bail!("unexpected EOF during authentication"),
                }
            }
            None => {
                stream.send(ClientMessage::Register).await?;
                match stream.recv_timeout().await? {
                    Some(ServerMessage::Issued { subdomain, token }) => {
                        issued = Some((subdomain, token));
                    }
                    Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
                    Some(_) => bail!("unexpected response to register"),
                    None => bail!("unexpected EOF during registration"),
                }
            }
        }

        let specs: Vec<RouteSpec> = routes
            .iter()
            .map(|r| RouteSpec {
                port: r.public_port,
                label: r.label.clone(),
            })
            .collect();
        stream.send(ClientMessage::Listen { routes: specs }).await?;
        let addresses = match stream.recv_timeout().await? {
            Some(ServerMessage::Bound { addresses }) => addresses,
            Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
            Some(_) => bail!("unexpected response to listen"),
            None => bail!("unexpected EOF after listen"),
        };
        if addresses.len() != routes.len() {
            bail!(
                "relay returned {} addresses for {} routes",
                addresses.len(),
                routes.len()
            );
        }

        // Key each backend by the (hostname, port) the relay routes on, so an
        // incoming `Connection` maps to exactly the right one even when several
        // routes share a hostname (different ports) or a port (different labels).
        let mut targets = HashMap::with_capacity(routes.len());
        for (route, address) in routes.iter().zip(addresses.iter()) {
            let hostname = address.split(':').next().unwrap_or(address).to_string();
            targets.insert(
                (hostname, route.public_port),
                (route.local_host.clone(), route.local_port),
            );
            info!("listening at {address}");
        }

        Ok(Client {
            conn: Some(stream),
            to: to.to_string(),
            control_port,
            targets,
            addresses,
            issued,
        })
    }

    /// The public addresses players connect to, one per registered route.
    pub fn addresses(&self) -> &[String] {
        &self.addresses
    }

    /// An identity newly issued during construction, if any (subdomain, token).
    pub fn issued(&self) -> Option<&Identity> {
        self.issued.as_ref()
    }

    /// Start the client, forwarding connections until the relay disconnects.
    pub async fn listen(mut self) -> Result<()> {
        let mut conn = self.conn.take().unwrap();
        let this = Arc::new(self);
        loop {
            match conn.recv().await? {
                Some(ServerMessage::Heartbeat) => (),
                Some(ServerMessage::Connection { id, hostname, port }) => {
                    let this = Arc::clone(&this);
                    tokio::spawn(
                        async move {
                            info!(%hostname, port, "new connection");
                            match this.handle_connection(id, &hostname, port).await {
                                Ok(_) => info!("connection exited"),
                                Err(err) => warn!(%err, "connection exited with error"),
                            }
                        }
                        .instrument(info_span!("proxy", %id)),
                    );
                }
                Some(ServerMessage::Error(err)) => error!(%err, "server error"),
                Some(_) => warn!("unexpected message from relay"),
                None => return Ok(()),
            }
        }
    }

    async fn handle_connection(&self, id: Uuid, hostname: &str, port: u16) -> Result<()> {
        let (local_host, local_port) = match self.targets.get(&(hostname.to_string(), port)) {
            Some(target) => target,
            None => {
                warn!(%hostname, port, "no local backend registered for route");
                return Ok(());
            }
        };
        let mut remote_conn =
            Delimited::new(connect_with_timeout(&self.to, self.control_port).await?);
        remote_conn.send(ClientMessage::Accept(id)).await?;
        let mut local_conn = connect_with_timeout(local_host, *local_port).await?;
        let mut parts = remote_conn.into_parts();
        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
        local_conn.write_all(&parts.read_buf).await?;
        tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
        Ok(())
    }
}

async fn connect_with_timeout(to: &str, port: u16) -> Result<TcpStream> {
    let stream = match timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port))).await {
        Ok(res) => res,
        Err(err) => Err(err.into()),
    }
    .with_context(|| format!("could not connect to {to}:{port}"))?;
    // Minecraft sends many tiny packets; disable Nagle to avoid added latency.
    let _ = stream.set_nodelay(true);
    Ok(stream)
}
