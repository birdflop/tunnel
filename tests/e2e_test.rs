//! End-to-end tests for the Birdflop tunnel.
//!
//! Each test runs its relay on its own control/public ports so they don't
//! collide, and uses a temp identity store for isolation.

use std::time::Duration;

use anyhow::Result;
use birdflop_tunnel::client::{Client, Route};
use birdflop_tunnel::identity::IdentityStore;
use birdflop_tunnel::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

const BASE: &str = "tunnel.test";

/// Build a single route for the common one-backend case.
fn route(local_port: u16, public_port: u16, label: Option<&str>) -> Route {
    Route {
        label: label.map(str::to_string),
        public_port,
        local_host: "localhost".to_string(),
        local_port,
    }
}

fn temp_store(name: &str) -> IdentityStore {
    let path = std::env::temp_dir().join(format!("bftunnel-e2e-{name}.json"));
    let _ = std::fs::remove_file(&path);
    IdentityStore::load(path).unwrap()
}

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
fn handshake(address: &str, port: u16) -> Vec<u8> {
    let mut body = Vec::new();
    write_varint(&mut body, 0);
    write_varint(&mut body, 765);
    write_varint(&mut body, address.len() as u32);
    body.extend_from_slice(address.as_bytes());
    body.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut body, 2);

    let mut packet = Vec::new();
    write_varint(&mut packet, body.len() as u32);
    packet.extend_from_slice(&body);
    packet
}

async fn spawn_relay(control_port: u16, store: IdentityStore) {
    let mut server = Server::new(1024..=65535, BASE.to_string(), store);
    server.set_control_port(control_port);
    tokio::spawn(server.listen());
    time::sleep(Duration::from_millis(80)).await;
}

#[tokio::test]
async fn proxies_by_handshake_hostname() -> Result<()> {
    let control_port = 17801;
    let public_port = 30001;
    spawn_relay(control_port, temp_store("proxy")).await;

    // A fake "Minecraft server" the client forwards to.
    let backend = tokio::net::TcpListener::bind("localhost:0").await?;
    let local_port = backend.local_addr()?.port();

    // Client requests a fresh identity and registers the public port.
    let client = Client::new(
        "localhost",
        control_port,
        vec![route(local_port, public_port, None)],
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    let hostname = format!("{subdomain}.{BASE}");
    assert_eq!(client.addresses(), &[format!("{hostname}:{public_port}")]);
    tokio::spawn(client.listen());

    let hs = handshake(&hostname, public_port);
    let hs_len = hs.len();

    // Backend side: read the replayed handshake, then the app data, then reply.
    let backend_task = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await?;
        let mut prefix = vec![0u8; hs_len];
        stream.read_exact(&mut prefix).await?;
        let mut buf = [0u8; 11];
        stream.read_exact(&mut buf).await?;
        assert_eq!(&buf, b"hello world");
        stream.write_all(b"hi from backend").await?;
        anyhow::Ok(())
    });

    // Player side: connect to the public port, send the handshake, then data.
    let mut player = TcpStream::connect(("localhost", public_port)).await?;
    player.write_all(&hs).await?;
    player.write_all(b"hello world").await?;

    let mut reply = [0u8; 15];
    player.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"hi from backend");

    backend_task.await??;
    Ok(())
}

#[tokio::test]
async fn unknown_hostname_is_dropped() -> Result<()> {
    let control_port = 17803;
    let public_port = 30003;
    spawn_relay(control_port, temp_store("unknown")).await;

    let backend = tokio::net::TcpListener::bind("localhost:0").await?;
    let local_port = backend.local_addr()?.port();
    let client = Client::new(
        "localhost",
        control_port,
        vec![route(local_port, public_port, None)],
        None,
    )
    .await?;
    tokio::spawn(client.listen());

    // Connect with a handshake for a hostname nobody registered → relay closes it.
    let mut player = TcpStream::connect(("localhost", public_port)).await?;
    player
        .write_all(&handshake("does-not-exist.tunnel.test", public_port))
        .await?;
    let mut buf = [0u8; 1];
    // The relay drops the connection without sending anything.
    assert_eq!(player.read(&mut buf).await?, 0);
    Ok(())
}

#[tokio::test]
async fn wrong_token_is_rejected() -> Result<()> {
    let control_port = 17802;
    spawn_relay(control_port, temp_store("auth")).await;

    // Create an identity.
    let backend = tokio::net::TcpListener::bind("localhost:0").await?;
    let local_port = backend.local_addr()?.port();
    let client = Client::new(
        "localhost",
        control_port,
        vec![route(local_port, 30002, None)],
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    drop(client);

    // Re-authenticate with the right subdomain but the wrong token.
    let result = Client::new(
        "localhost",
        control_port,
        vec![route(local_port, 30002, None)],
        Some((subdomain, "totally-wrong-token".to_string())),
    )
    .await;
    assert!(result.is_err(), "expected auth failure with wrong token");
    Ok(())
}

#[tokio::test]
async fn multi_route_routes_by_label() -> Result<()> {
    let control_port = 17804;
    let survival_port = 30004;
    let creative_port = 30005;
    spawn_relay(control_port, temp_store("multi")).await;

    // Two distinct backends, each tagging its reply so we can tell them apart.
    async fn spawn_backend(tag: &'static [u8]) -> Result<u16> {
        let listener = tokio::net::TcpListener::bind("localhost:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await?;
                let tag = tag.to_vec();
                tokio::spawn(async move {
                    // Drain whatever the player sends (handshake + data), then reply.
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf).await;
                    stream.write_all(&tag).await?;
                    anyhow::Ok(())
                });
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        });
        Ok(port)
    }

    let survival_local = spawn_backend(b"survival!").await?;
    let creative_local = spawn_backend(b"creative!").await?;

    // One client, one identity, two labelled routes to two different backends.
    let client = Client::new(
        "localhost",
        control_port,
        vec![
            route(survival_local, survival_port, Some("survival")),
            route(creative_local, creative_port, Some("creative")),
        ],
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    tokio::spawn(client.listen());

    // A player connecting to survival.<sub> on its port reaches the survival backend.
    let survival_host = format!("survival.{subdomain}.{BASE}");
    let mut player = TcpStream::connect(("localhost", survival_port)).await?;
    player
        .write_all(&handshake(&survival_host, survival_port))
        .await?;
    let mut reply = [0u8; 9];
    player.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"survival!");

    // And creative.<sub> reaches the creative backend.
    let creative_host = format!("creative.{subdomain}.{BASE}");
    let mut player = TcpStream::connect(("localhost", creative_port)).await?;
    player
        .write_all(&handshake(&creative_host, creative_port))
        .await?;
    let mut reply = [0u8; 9];
    player.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"creative!");

    Ok(())
}

/// Two servers under one flat subdomain (no labels), told apart only by port —
/// the `xxxxx.tunnel.birdflop.com` + `xxxxx.tunnel.birdflop.com:NNNN` case.
#[tokio::test]
async fn multi_route_by_port_no_label() -> Result<()> {
    let control_port = 17805;
    let port_a = 30006;
    let port_b = 30007;
    spawn_relay(control_port, temp_store("byport")).await;

    async fn spawn_backend(tag: &'static [u8]) -> Result<u16> {
        let listener = tokio::net::TcpListener::bind("localhost:0").await?;
        let port = listener.local_addr()?.port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await?;
                let tag = tag.to_vec();
                tokio::spawn(async move {
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf).await;
                    stream.write_all(&tag).await?;
                    anyhow::Ok(())
                });
            }
            #[allow(unreachable_code)]
            anyhow::Ok(())
        });
        Ok(port)
    }

    let local_a = spawn_backend(b"aaaaaaaaa").await?;
    let local_b = spawn_backend(b"bbbbbbbbb").await?;

    // One client, one identity, two unlabelled routes differing only by port.
    let client = Client::new(
        "localhost",
        control_port,
        vec![route(local_a, port_a, None), route(local_b, port_b, None)],
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    tokio::spawn(client.listen());

    // Same hostname on both ports must reach distinct backends.
    let host = format!("{subdomain}.{BASE}");

    let mut player = TcpStream::connect(("localhost", port_a)).await?;
    player.write_all(&handshake(&host, port_a)).await?;
    let mut reply = [0u8; 9];
    player.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"aaaaaaaaa");

    let mut player = TcpStream::connect(("localhost", port_b)).await?;
    player.write_all(&handshake(&host, port_b)).await?;
    let mut reply = [0u8; 9];
    player.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"bbbbbbbbb");

    Ok(())
}

/// Scrape the relay's `/metrics` endpoint over a one-shot HTTP request.
async fn scrape(port: u16) -> Result<String> {
    let mut conn = TcpStream::connect(("127.0.0.1", port)).await?;
    conn.write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut buf = Vec::new();
    conn.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    Ok(text.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

#[tokio::test]
async fn metrics_endpoint_reports() -> Result<()> {
    let control_port = 17806;
    let public_port = 30009;
    let metrics_port = 19090;

    let mut server = Server::new(1024..=65535, BASE.to_string(), temp_store("metrics"));
    server.set_control_port(control_port);
    server.set_metrics_addr(format!("127.0.0.1:{metrics_port}").parse().unwrap());
    tokio::spawn(server.listen());
    time::sleep(Duration::from_millis(80)).await;

    let backend = tokio::net::TcpListener::bind("localhost:0").await?;
    let local_port = backend.local_addr()?.port();
    let client = Client::new(
        "localhost",
        control_port,
        vec![route(local_port, public_port, None)],
        None,
    )
    .await?;
    // Registration + the route are live by the time `new` returns.
    tokio::spawn(client.listen());

    let body = scrape(metrics_port).await?;
    assert!(
        body.contains("bftunnel_registrations_total 1"),
        "missing registrations counter:\n{body}"
    );
    assert!(
        body.contains("bftunnel_active_tunnels 1"),
        "missing active tunnels gauge:\n{body}"
    );
    Ok(())
}

#[tokio::test]
#[should_panic]
#[allow(clippy::reversed_empty_ranges)] // deliberately empty to assert the guard panics
async fn empty_port_range_panics() {
    let store = temp_store("empty-range");
    let _ = Server::new(5000..=3000, BASE.to_string(), store);
}
