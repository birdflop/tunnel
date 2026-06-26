//! Client implementation for the Birdflop tunnel.
//!
//! The client runs next to a Minecraft server. It authenticates to the relay
//! (or requests a new identity on first run), claims a public port under its
//! subdomain, and then forwards each incoming connection to the local server.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::{io::AsyncWriteExt, net::TcpStream, time::timeout};
use tracing::{error, info, info_span, warn, Instrument};
use uuid::Uuid;

use crate::auth::Authenticator;
use crate::shared::{ClientMessage, Delimited, ServerMessage, NETWORK_TIMEOUT};

/// An existing identity to authenticate with: `(subdomain, secret token)`.
pub type Identity = (String, String);

/// State structure for the client.
pub struct Client {
    /// Control connection to the relay.
    conn: Option<Delimited<TcpStream>>,

    /// Relay host.
    to: String,

    /// Relay control port.
    control_port: u16,

    /// Local host that is forwarded.
    local_host: String,

    /// Local port that is forwarded.
    local_port: u16,

    /// Public address players connect to.
    address: String,

    /// A newly issued identity, if one was created during [`Client::new`].
    issued: Option<Identity>,
}

impl Client {
    /// Create a new client and register a public port.
    ///
    /// If `identity` is `Some`, the client authenticates as that subdomain;
    /// otherwise it requests a brand-new identity from the relay.
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        local_host: &str,
        local_port: u16,
        to: &str,
        control_port: u16,
        public_port: u16,
        label: Option<&str>,
        identity: Option<Identity>,
    ) -> Result<Self> {
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

        stream
            .send(ClientMessage::Listen {
                port: public_port,
                label: label.map(str::to_string),
            })
            .await?;
        let address = match stream.recv_timeout().await? {
            Some(ServerMessage::Bound(address)) => address,
            Some(ServerMessage::Error(message)) => bail!("server error: {message}"),
            Some(_) => bail!("unexpected response to listen"),
            None => bail!("unexpected EOF after listen"),
        };
        info!("listening at {address}");

        Ok(Client {
            conn: Some(stream),
            to: to.to_string(),
            control_port,
            local_host: local_host.to_string(),
            local_port,
            address,
            issued,
        })
    }

    /// The public address players connect to.
    pub fn address(&self) -> &str {
        &self.address
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
                Some(ServerMessage::Connection(id)) => {
                    let this = Arc::clone(&this);
                    tokio::spawn(
                        async move {
                            info!("new connection");
                            match this.handle_connection(id).await {
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

    async fn handle_connection(&self, id: Uuid) -> Result<()> {
        let mut remote_conn =
            Delimited::new(connect_with_timeout(&self.to, self.control_port).await?);
        remote_conn.send(ClientMessage::Accept(id)).await?;
        let mut local_conn = connect_with_timeout(&self.local_host, self.local_port).await?;
        let mut parts = remote_conn.into_parts();
        debug_assert!(parts.write_buf.is_empty(), "framed write buffer not empty");
        local_conn.write_all(&parts.read_buf).await?;
        tokio::io::copy_bidirectional(&mut local_conn, &mut parts.io).await?;
        Ok(())
    }
}

async fn connect_with_timeout(to: &str, port: u16) -> Result<TcpStream> {
    match timeout(NETWORK_TIMEOUT, TcpStream::connect((to, port))).await {
        Ok(res) => res,
        Err(err) => Err(err.into()),
    }
    .with_context(|| format!("could not connect to {to}:{port}"))
}
