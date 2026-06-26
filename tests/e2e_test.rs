//! End-to-end tests for the Birdflop tunnel.
//!
//! Each test runs its relay on its own control/public ports so they don't
//! collide, and uses a temp identity store for isolation.

use std::time::Duration;

use anyhow::Result;
use birdflop_tunnel::client::Client;
use birdflop_tunnel::identity::IdentityStore;
use birdflop_tunnel::server::Server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time;

const BASE: &str = "tunnel.test";

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
        local_port,
        "localhost",
        control_port,
        public_port,
        None,
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    let hostname = format!("{subdomain}.{BASE}");
    assert_eq!(client.address(), format!("{hostname}:{public_port}"));
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
        local_port,
        "localhost",
        control_port,
        public_port,
        None,
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
        local_port,
        "localhost",
        control_port,
        30002,
        None,
        None,
    )
    .await?;
    let (subdomain, _token) = client.issued().cloned().expect("issued an identity");
    drop(client);

    // Re-authenticate with the right subdomain but the wrong token.
    let result = Client::new(
        "localhost",
        local_port,
        "localhost",
        control_port,
        30002,
        None,
        Some((subdomain, "totally-wrong-token".to_string())),
    )
    .await;
    assert!(result.is_err(), "expected auth failure with wrong token");
    Ok(())
}

#[tokio::test]
#[should_panic]
#[allow(clippy::reversed_empty_ranges)] // deliberately empty to assert the guard panics
async fn empty_port_range_panics() {
    let store = temp_store("empty-range");
    let _ = Server::new(5000..=3000, BASE.to_string(), store);
}
