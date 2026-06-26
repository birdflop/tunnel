use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use birdflop_tunnel::client::{Client, Route};
use birdflop_tunnel::identity::IdentityStore;
use birdflop_tunnel::server::Server;
use birdflop_tunnel::shared::{CONTROL_PORT, DEFAULT_MC_PORT};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};
use serde::Deserialize;

#[derive(Parser, Debug)]
#[clap(name = "bftunnel", author, version, about)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Forward one or more local Minecraft servers through the relay.
    Local {
        /// The local port to expose. Omit when using --config.
        #[clap(env = "BFTUNNEL_LOCAL_PORT")]
        local_port: Option<u16>,

        /// The local host to expose.
        #[clap(short, long, value_name = "HOST", default_value = "localhost")]
        local_host: String,

        /// Address of the relay to connect to.
        #[clap(short, long, env = "BFTUNNEL_SERVER")]
        to: String,

        /// Relay control port.
        #[clap(long, default_value_t = CONTROL_PORT)]
        control_port: u16,

        /// Public port to expose under your subdomain (must be above 1000).
        #[clap(short, long, default_value_t = DEFAULT_MC_PORT)]
        port: u16,

        /// Optional sub-label, e.g. `survival` in `survival.<you>.tunnel.birdflop.com`.
        #[clap(long)]
        label: Option<String>,

        /// JSON file listing multiple routes; supersedes the single-route flags.
        #[clap(long, value_name = "PATH")]
        config: Option<PathBuf>,

        /// Your subdomain (paired with --token). Omit both to request a new identity.
        #[clap(long, env = "BFTUNNEL_SUBDOMAIN")]
        subdomain: Option<String>,

        /// Your secret token (paired with --subdomain).
        #[clap(long, env = "BFTUNNEL_TOKEN", hide_env_values = true)]
        token: Option<String>,
    },

    /// Run the public relay.
    Server {
        /// Base domain that subdomains live under.
        #[clap(long, default_value = "tunnel.birdflop.com")]
        base_domain: String,

        /// Minimum public port clients may claim.
        #[clap(long, default_value_t = 1024, env = "BFTUNNEL_MIN_PORT")]
        min_port: u16,

        /// Maximum public port clients may claim.
        #[clap(long, default_value_t = 65535, env = "BFTUNNEL_MAX_PORT")]
        max_port: u16,

        /// Path to the persistent identity store.
        #[clap(long, default_value = "tunnel-identities.json")]
        store: PathBuf,

        /// Control port to listen on.
        #[clap(long, default_value_t = CONTROL_PORT)]
        control_port: u16,

        /// IP address the control server binds to.
        #[clap(long, default_value = "0.0.0.0")]
        bind_addr: IpAddr,

        /// IP address public tunnel listeners bind to, defaults to --bind-addr.
        #[clap(long)]
        bind_tunnels: Option<IpAddr>,

        /// Serve Prometheus metrics on this address, e.g. `127.0.0.1:9090` (off by default).
        #[clap(long, value_name = "ADDR", env = "BFTUNNEL_METRICS_ADDR")]
        metrics_addr: Option<SocketAddr>,

        /// Max total identities to issue (0 = unlimited).
        #[clap(long, default_value_t = 0, env = "BFTUNNEL_MAX_IDENTITIES")]
        max_identities: usize,

        /// Max simultaneously pending (un-accepted) player connections.
        #[clap(long, default_value_t = 1024, env = "BFTUNNEL_MAX_PENDING")]
        max_pending: usize,

        /// Max routes (ports/labels) one identity may hold at once.
        #[clap(long, default_value_t = 10, env = "BFTUNNEL_MAX_TUNNELS_PER_IDENTITY")]
        max_tunnels_per_identity: usize,

        /// Max new-identity registrations allowed per source IP per minute.
        #[clap(long, default_value_t = 5, env = "BFTUNNEL_REGISTER_RATE")]
        register_rate: u32,
    },
}

/// One route entry in a client `--config` file.
#[derive(Debug, Deserialize)]
struct RouteConfig {
    label: Option<String>,
    local_host: Option<String>,
    local_port: u16,
    public_port: Option<u16>,
}

/// Top-level client `--config` file shape.
#[derive(Debug, Deserialize)]
struct ClientConfig {
    routes: Vec<RouteConfig>,
}

fn load_routes(
    config: Option<PathBuf>,
    local_port: Option<u16>,
    local_host: String,
    port: u16,
    label: Option<String>,
) -> Result<Vec<Route>> {
    if let Some(path) = config {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("reading route config {}", path.display()))?;
        let cfg: ClientConfig = serde_json::from_slice(&bytes)
            .with_context(|| format!("parsing route config {}", path.display()))?;
        if cfg.routes.is_empty() {
            Args::command()
                .error(ErrorKind::InvalidValue, "config has no routes")
                .exit();
        }
        Ok(cfg
            .routes
            .into_iter()
            .map(|r| Route {
                label: r.label,
                public_port: r.public_port.unwrap_or(DEFAULT_MC_PORT),
                local_host: r.local_host.unwrap_or_else(|| "localhost".to_string()),
                local_port: r.local_port,
            })
            .collect())
    } else {
        let local_port = match local_port {
            Some(p) => p,
            None => {
                Args::command()
                    .error(
                        ErrorKind::MissingRequiredArgument,
                        "a local_port is required unless --config is given",
                    )
                    .exit();
            }
        };
        Ok(vec![Route {
            label,
            public_port: port,
            local_host,
            local_port,
        }])
    }
}

#[tokio::main]
async fn run(command: Command) -> Result<()> {
    match command {
        Command::Local {
            local_host,
            local_port,
            to,
            control_port,
            port,
            label,
            config,
            subdomain,
            token,
        } => {
            let identity = match (subdomain, token) {
                (Some(subdomain), Some(token)) => Some((subdomain, token)),
                (None, None) => None,
                _ => {
                    Args::command()
                        .error(
                            ErrorKind::MissingRequiredArgument,
                            "--subdomain and --token must be provided together",
                        )
                        .exit();
                }
            };

            let routes = load_routes(config, local_port, local_host, port, label)?;

            let client = Client::new(&to, control_port, routes, identity).await?;

            // On first run, print the issued identity so the caller can persist it.
            if let Some((subdomain, token)) = client.issued() {
                println!("BFTUNNEL_IDENTITY subdomain={subdomain} token={token}");
            }
            for address in client.addresses() {
                println!("BFTUNNEL_ADDRESS {address}");
            }

            client.listen().await?;
        }
        Command::Server {
            base_domain,
            min_port,
            max_port,
            store,
            control_port,
            bind_addr,
            bind_tunnels,
            metrics_addr,
            max_identities,
            max_pending,
            max_tunnels_per_identity,
            register_rate,
        } => {
            let port_range = min_port..=max_port;
            if port_range.is_empty() {
                Args::command()
                    .error(ErrorKind::InvalidValue, "port range is empty")
                    .exit();
            }
            let store = IdentityStore::load(&store)?;
            let mut server = Server::new(port_range, base_domain, store);
            server.set_bind_addr(bind_addr);
            server.set_bind_tunnels(bind_tunnels.unwrap_or(bind_addr));
            server.set_control_port(control_port);
            server.set_max_identities(max_identities);
            server.set_max_pending(max_pending);
            server.set_max_per_identity(max_tunnels_per_identity);
            server.set_register_rate(register_rate, Duration::from_secs(60));
            if let Some(addr) = metrics_addr {
                server.set_metrics_addr(addr);
            }
            server.listen().await?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run(Args::parse().command)
}
