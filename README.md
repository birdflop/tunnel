# Birdflop Tunnel

A self-hosted Minecraft tunnel that gives every user one **stable subdomain** under
`*.tunnel.birdflop.com` and routes incoming traffic by reading the hostname out of
the **Minecraft handshake**. Because routing is by hostname, a single public IP and
a single port serve unlimited users — the port space is never exhausted.

This is a heavily modified fork of [`bore`](https://github.com/ekzhang/bore) by
Eric Zhang. The original assigns each tunnel a random public port; this version
instead assigns persistent per-user subdomains and multiplexes everyone onto shared
ports by Minecraft hostname.

## How it works

```
Player connects to:   a3k9zq.tunnel.birdflop.com         (or  a3k9zq.tunnel.birdflop.com:25566
                                                              for a second server)
        │
        │   DNS:  *.tunnel.birdflop.com  →  ONE relay IP   (single-label wildcard)
        ▼
   relay :25565   ← ONE shared port for ALL users   (a second server uses :25566, etc.)
        │   reads the Minecraft handshake → hostname = "a3k9zq.tunnel.birdflop.com"
        │   routes by (hostname, port) → the client that registered it
        ▼
   forwards the (replayed) stream to that client → its local Minecraft server
```

- **One domain per user.** The relay issues a random 6-char subdomain (e.g. `a3k9zq`)
  plus a long secret token. The subdomain is the public address; the token proves
  ownership and never crosses the wire after issuance (HMAC challenge/response).
- **Many servers per user, by port.** A user exposes each server on its own port under
  their subdomain — `a3k9zq.tunnel.birdflop.com` (default port 25565),
  `a3k9zq.tunnel.birdflop.com:25566`, and so on. Every port is host-muxed, so two users
  can both use `:25565` and the port space is never exhausted.
- **Optional sub-labels.** A server can instead be exposed at `survival.a3k9zq…`, but this
  relies on multi-label wildcard DNS (see the DNS note below) and may not resolve on every
  provider, so **port addressing is the default and the robust choice**.
- **Stable URLs.** Identities are persisted, so a user's address never changes.

The only traffic that cannot be host-muxed is genuinely non-Minecraft raw TCP (no
handshake to read); that would need a dedicated global port. This relay is optimized
for Java Minecraft.

## Usage

### Relay (server)

```shell
bftunnel server \
  --base-domain tunnel.birdflop.com \
  --store /var/lib/bftunnel/identities.json
```

| Option | Default | Meaning |
|---|---|---|
| `--base-domain` | `tunnel.birdflop.com` | Domain subdomains live under |
| `--min-port` / `--max-port` | `1024` / `65535` | Public ports clients may claim |
| `--store` | `tunnel-identities.json` | Persistent identity file |
| `--control-port` | `7835` | Control connection port |
| `--bind-addr` | `0.0.0.0` | Where the control server binds |
| `--bind-tunnels` | = `--bind-addr` | Where public listeners bind |

**DNS:** point a single wildcard record `*.tunnel.birdflop.com` at the relay's public IP.
This single-label wildcard covers every user's subdomain (`a3k9zq.tunnel.birdflop.com`),
which is all the default port-based addressing needs, and works on every DNS provider.
Optional sub-labels (`survival.a3k9zq.tunnel.birdflop.com`) require the wildcard to also
synthesize *multi-label* names (RFC 4592). Standards-compliant authoritative servers do
this — provided you never create an explicit record for a base subdomain — but some managed
DNS providers don't, so sub-labels may not resolve everywhere. Port addressing always does.

**Firewall:** allow the control port (`7835`, ideally restricted to clients) and the
public Minecraft ports you let clients claim (`25565` and anything else in range).

### Client (next to a Minecraft server)

First run — request a new identity (printed once, save it):

```shell
bftunnel local 25565 --to tunnel.birdflop.com
# → BFTUNNEL_IDENTITY subdomain=a3k9zq token=<secret>
# → BFTUNNEL_ADDRESS a3k9zq.tunnel.birdflop.com
```

Later runs — reuse the saved identity:

```shell
bftunnel local 25565 --to tunnel.birdflop.com \
  --subdomain a3k9zq --token <secret>
```

Expose a second server under the same domain on its own port:

```shell
bftunnel local 25566 --to tunnel.birdflop.com \
  --subdomain a3k9zq --token <secret> --port 25566
# → BFTUNNEL_ADDRESS a3k9zq.tunnel.birdflop.com:25566
```

Adding `--label creative` would instead expose it at `creative.a3k9zq.tunnel.birdflop.com:25566`,
but that depends on multi-label wildcard DNS (see the DNS note above).

| Option | Default | Meaning |
|---|---|---|
| `<local_port>` | — | Local port to forward |
| `--local-host` | `localhost` | Local host to forward |
| `--to` | — | Relay address |
| `--port` | `25565` | Public port under your subdomain (must be > 1000) |
| `--label` | — | Optional sub-name (`survival.<you>…`) |
| `--subdomain` / `--token` | — | Existing identity (provide both, or neither to enroll) |

Machine-readable lines are printed to stdout on startup:
`BFTUNNEL_IDENTITY subdomain=… token=…` (only when a new identity is issued) and
`BFTUNNEL_ADDRESS <public address>`.

## Protocol

The client opens a control connection to the relay and either `Register`s (the relay
issues `{subdomain, token}` and treats the connection as authenticated) or
`Authenticate`s by subdomain (the relay replies with a `Challenge`; the client
returns an HMAC `Answer` keyed by the token). It then `Listen`s on a public port with
an optional label; the relay registers `[label.]subdomain.<base>` on that port and
replies `Bound(address)`.

When a player connects, the relay reads the handshake, finds the registered client,
stores the pending connection under a UUID, and sends `Connection(uuid)`. The client
opens a fresh stream, sends `Accept(uuid)`, and the relay splices the two — replaying
the buffered handshake bytes so the backend sees a normal connection.

## License

MIT, as with upstream bore.
