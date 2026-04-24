# Running `dnsmesh-node` as a Docker image

Published image: **`oscarvalenzuelab/dnsmesh-node`** on Docker Hub (tags:
`latest`, `main`, and `<semver>` for tagged releases).

This bundle is the reference recipe for a production-style *single-node*
deploy of `dnsmesh-node`. It is intentionally platform-agnostic: the image
runs anywhere docker does — DigitalOcean Droplets, AWS EC2 / Lightsail,
Hetzner, bare-metal, your laptop — as long as the host can expose UDP
on the DNS port. (Most serverless / PaaS tiers, including DigitalOcean
App Platform, do *not* support UDP, so they will not work here.)

For a federated 3-node cluster, use `docker-compose.cluster.yml` in the
repo root instead; the single-node flow below is the minimum a client
application needs to send and receive over DMP.

## Quick start (anywhere with docker)

```bash
# One-off: set the DNS name you'll point at this host, and generate a
# bearer token that gates the HTTP publish API.
export DMP_NODE_HOSTNAME=dmp.example.com
export DMP_HTTP_TOKEN=$(openssl rand -hex 32)

# Pull + start (the compose file pulls dnsmesh-node:latest + caddy:2).
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/docker/compose.yml \
    -o compose.yml
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/Caddyfile \
    -o Caddyfile
docker compose up -d
```

The stack:

- **`dnsmesh-node`**: UDP 53 (DMP authoritative DNS), internal 8053 for
  the publish API (Caddy-proxied, not exposed to the host).
- **`caddy`**: 80 (ACME HTTP-01) + 443/tcp + 443/udp (HTTPS + HTTP/3),
  auto-ACME with Let's Encrypt.

Publish and read a record:

```bash
# Publish (auth-gated):
curl -X POST "https://$DMP_NODE_HOSTNAME/v1/records/hello.example" \
     -H "Authorization: Bearer $DMP_HTTP_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"value":"world","ttl":60}'

# Read via DNS (from anywhere on the internet):
dig @$DMP_NODE_HOSTNAME hello.example TXT +short
```

## Plain `docker run` (no compose)

If you don't want Caddy or compose, the image runs standalone:

```bash
docker run -d --name dnsmesh-node \
  -p 53:5353/udp \
  -p 8053:8053/tcp \
  -e DMP_HTTP_TOKEN=$(openssl rand -hex 32) \
  -v dnsmesh-data:/var/lib/dmp \
  oscarvalenzuelab/dnsmesh-node:latest
```

With this shape, the HTTP publish API is exposed directly on TCP 8053
(no TLS). Do not do this in production — put a reverse proxy in
front, or use the compose recipe above.

## Configuration

All config is env vars. The most common:

| Var                     | Default              | Purpose                                |
|-------------------------|----------------------|----------------------------------------|
| `DMP_HTTP_TOKEN`        | (unset — open)       | Bearer token required on `/v1/records/*` POST/DELETE. Leaving it unset makes the publish API open, which is only safe on a trusted network. |
| `DMP_DNS_TTL`           | `60`                 | Default TTL for published records.     |
| `DMP_DNS_RATE`          | (unset)              | Per-source-IP rate limit (queries/sec) on the DNS plane. |
| `DMP_DNS_BURST`         | (unset)              | Burst budget for `DMP_DNS_RATE`.       |
| `DMP_HTTP_RATE`         | (unset)              | Per-source-IP rate limit on the HTTP plane. |
| `DMP_CLEANUP_INTERVAL`  | `60`                 | Expired-record sweep interval (seconds). |
| `DMP_LOG_FORMAT`        | `text`               | `json` for structured logs.            |
| `DMP_LOG_LEVEL`         | `INFO`               |                                         |

See the `docs/` directory for the full operator guide, metrics, and
hardening checklist.

## Persistence

State lives at `/var/lib/dmp` in the container. Mount a named volume
(or a host path) there so state survives container restarts; the
compose file in this directory already does.

## Ports you must open

- **UDP 53** — DMP authoritative DNS. Must be internet-reachable for
  other clients to resolve names this node serves.
- **TCP 443** (and optionally **UDP 443** for HTTP/3) — HTTPS publish
  API and ACME HTTP-01 challenge.
- **TCP 80** — only for Let's Encrypt HTTP-01 challenges (Caddy
  redirects to HTTPS otherwise).

DMP's anti-entropy sync uses the same `DMP_HTTP_PORT` (default
`8053`). When you scale to a multi-node cluster, peers must reach
each other on that port — typically on a private network, gated by
`DMP_SYNC_PEER_TOKEN`. See `docs/deployment/cluster.md`.

## Publishing the image (maintainer notes)

Pushes to `main` and pushes of `v*` tags trigger
`.github/workflows/publish-image.yml`, which builds multi-arch
(`linux/amd64`, `linux/arm64`) and pushes to Docker Hub. Repo
secrets required: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`.
