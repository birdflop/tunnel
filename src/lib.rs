//! A self-hosted Minecraft tunnel that exposes local servers to the public
//! internet under a stable, per-user subdomain (`*.tunnel.birdflop.com`).
//!
//! It is a heavily modified fork of [bore](https://github.com/ekzhang/bore).
//! The original assigns each tunnel a random public port; this version instead
//! gives every user one persistent subdomain and routes incoming Minecraft
//! connections to the right backend by reading the hostname out of the
//! Minecraft handshake. Because routing is by hostname, every user shares the
//! same set of public ports, so the port space is never exhausted.
//!
//! There are two components: the [`server`] (the public relay) and the
//! [`client`] (runs next to a Minecraft server and forwards it).

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth;
pub mod client;
pub mod identity;
pub mod server;
pub mod shared;
