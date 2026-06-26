use std::net::IpAddr;
use std::path::PathBuf;

use anyhow::Result;
use birdflop_tunnel::client::Client;
use birdflop_tunnel::identity::IdentityStore;
use birdflop_tunnel::server::Server;
use birdflop_tunnel::shared::{CONTROL_PORT, DEFAULT_MC_PORT};
use clap::{error::ErrorKind, CommandFactory, Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(name = "bftunnel", author, version, about)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Forward a local Minecraft server through the relay.
    Local {
        /// The local port to expose.
        #[clap(env = "BFTUNNEL_LOCAL_PORT")]
        local_port: u16,

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
    },
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

            let client = Client::new(
                &local_host,
                local_port,
                &to,
                control_port,
                port,
                label.as_deref(),
                identity,
            )
            .await?;

            // On first run, print the issued identity so the caller can persist it.
            if let Some((subdomain, token)) = client.issued() {
                println!("BFTUNNEL_IDENTITY subdomain={subdomain} token={token}");
            }
            println!("BFTUNNEL_ADDRESS {}", client.address());

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
            server.listen().await?;
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    run(Args::parse().command)
}
