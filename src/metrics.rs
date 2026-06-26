//! Lightweight, dependency-free relay metrics in Prometheus text format.
//!
//! Counters and gauges are plain atomics bumped from the hot paths; a few gauges
//! (active identities, pending connections, open ports, active tunnels) are read
//! straight from the relay's live state at scrape time instead of being tracked
//! incrementally. [`Metrics::render`] formats everything as the Prometheus text
//! exposition format, served by the relay's `/metrics` endpoint.

use std::fmt::Write;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

/// Counters and gauges collected by the relay.
#[derive(Default)]
pub struct Metrics {
    /// Identities successfully issued.
    registrations_total: AtomicU64,
    /// Registrations refused by the per-IP rate limiter.
    registrations_rate_limited_total: AtomicU64,
    /// Registrations refused because the identity cap was reached.
    registrations_capacity_total: AtomicU64,
    /// Failed authentication attempts (unknown subdomain or bad token).
    auth_failures_total: AtomicU64,
    /// Player connections successfully routed to a client.
    player_connections_total: AtomicU64,
    /// Player connections dropped before routing due to a bad/slow handshake.
    handshake_failures_total: AtomicU64,
    /// Player connections for a hostname nobody registered on that port.
    unknown_host_total: AtomicU64,
    /// Player connections shed because the pending-connection cap was reached.
    pending_full_total: AtomicU64,
    /// Pending connections dropped because the client never accepted in time.
    stale_connections_total: AtomicU64,
    /// Bytes proxied across all (cleanly closed) player connections.
    bytes_proxied_total: AtomicU64,
    /// Currently live, spliced player connections (gauge).
    active_connections: AtomicU64,
}

impl Metrics {
    /// Record a successfully issued identity.
    pub fn registration_issued(&self) {
        self.registrations_total.fetch_add(1, Relaxed);
    }

    /// Record a registration refused by the rate limiter.
    pub fn registration_rate_limited(&self) {
        self.registrations_rate_limited_total.fetch_add(1, Relaxed);
    }

    /// Record a registration refused because the identity cap was reached.
    pub fn registration_at_capacity(&self) {
        self.registrations_capacity_total.fetch_add(1, Relaxed);
    }

    /// Record a failed authentication.
    pub fn auth_failed(&self) {
        self.auth_failures_total.fetch_add(1, Relaxed);
    }

    /// Record a player connection that was routed to a client.
    pub fn player_connected(&self) {
        self.player_connections_total.fetch_add(1, Relaxed);
    }

    /// Record a player connection dropped on a bad/slow handshake.
    pub fn handshake_failed(&self) {
        self.handshake_failures_total.fetch_add(1, Relaxed);
    }

    /// Record a player connection for an unregistered hostname.
    pub fn unknown_host(&self) {
        self.unknown_host_total.fetch_add(1, Relaxed);
    }

    /// Record a player connection shed because the pending cap was reached.
    pub fn pending_full(&self) {
        self.pending_full_total.fetch_add(1, Relaxed);
    }

    /// Record a pending connection dropped because it was never accepted in time.
    pub fn stale_connection(&self) {
        self.stale_connections_total.fetch_add(1, Relaxed);
    }

    /// Add proxied bytes to the running total.
    pub fn add_bytes(&self, bytes: u64) {
        self.bytes_proxied_total.fetch_add(bytes, Relaxed);
    }

    /// Mark a spliced connection as live, returning a guard that decrements the
    /// gauge when dropped (so the count is correct even on an early error).
    pub fn connection_guard(&self) -> ConnectionGuard<'_> {
        self.active_connections.fetch_add(1, Relaxed);
        ConnectionGuard(&self.active_connections)
    }

    /// Render all metrics as Prometheus text. The arguments are gauges read from
    /// the relay's live state at scrape time.
    pub fn render(
        &self,
        active_identities: u64,
        pending_connections: u64,
        open_ports: u64,
        active_tunnels: u64,
    ) -> String {
        fn counter(out: &mut String, name: &str, help: &str, value: u64) {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} counter");
            let _ = writeln!(out, "{name} {value}");
        }
        fn gauge(out: &mut String, name: &str, help: &str, value: u64) {
            let _ = writeln!(out, "# HELP {name} {help}");
            let _ = writeln!(out, "# TYPE {name} gauge");
            let _ = writeln!(out, "{name} {value}");
        }

        let mut out = String::with_capacity(2048);
        counter(
            &mut out,
            "bftunnel_registrations_total",
            "Identities successfully issued.",
            self.registrations_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_registrations_rate_limited_total",
            "Registrations refused by the per-IP rate limiter.",
            self.registrations_rate_limited_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_registrations_capacity_total",
            "Registrations refused because the identity cap was reached.",
            self.registrations_capacity_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_auth_failures_total",
            "Failed authentication attempts.",
            self.auth_failures_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_player_connections_total",
            "Player connections routed to a client.",
            self.player_connections_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_handshake_failures_total",
            "Player connections dropped on a bad or slow handshake.",
            self.handshake_failures_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_unknown_host_total",
            "Player connections for an unregistered hostname.",
            self.unknown_host_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_pending_full_total",
            "Player connections shed because the pending cap was reached.",
            self.pending_full_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_stale_connections_total",
            "Pending connections dropped before being accepted.",
            self.stale_connections_total.load(Relaxed),
        );
        counter(
            &mut out,
            "bftunnel_bytes_proxied_total",
            "Bytes proxied across cleanly closed player connections.",
            self.bytes_proxied_total.load(Relaxed),
        );
        gauge(
            &mut out,
            "bftunnel_active_connections",
            "Currently live, spliced player connections.",
            self.active_connections.load(Relaxed),
        );
        gauge(
            &mut out,
            "bftunnel_active_identities",
            "Identities currently in the store.",
            active_identities,
        );
        gauge(
            &mut out,
            "bftunnel_pending_connections",
            "Player connections awaiting acceptance.",
            pending_connections,
        );
        gauge(
            &mut out,
            "bftunnel_open_ports",
            "Public ports with an open listener.",
            open_ports,
        );
        gauge(
            &mut out,
            "bftunnel_active_tunnels",
            "Routes currently registered across all ports.",
            active_tunnels,
        );
        out
    }
}

/// Decrements the live-connection gauge when dropped.
pub struct ConnectionGuard<'a>(&'a AtomicU64);

impl Drop for ConnectionGuard<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Relaxed);
    }
}
