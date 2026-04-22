---
title: Production
layout: default
parent: Deployment
nav_order: 2
---

# Production deployment
{: .no_toc }

1. TOC
{:toc}

{: .warning }
This is alpha software. Run it on a machine you can afford to lose.
External review happens as part of the beta tag — don't put real
secrets through it before then.

## TLS via Caddy

The repo ships a production overlay for docker-compose that puts
Caddy in front of the HTTP API. Caddy obtains a Let's Encrypt cert
automatically and reverse-proxies `:443 → dmp-node:8053` over
HTTPS + HTTP/3.

### Prerequisites

- DNS `A`/`AAAA` record pointing at the host for `$DMP_NODE_HOSTNAME`.
  The ACME challenge needs this before first boot.
- Port 80 and 443 open on the host.

### Bring it up

```bash
export DMP_NODE_HOSTNAME=dmp.example.com
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  up -d
```

The overlay:

- Removes the raw `8053` host port so HTTP isn't reachable except
  through Caddy.
- Publishes `80` and `443/tcp+udp` on the host.
- Mounts `Caddyfile` and two named volumes (`caddy-data`,
  `caddy-config`) for certificate storage.

### Caddyfile

The shipped `Caddyfile` is minimal:

```
{$DMP_NODE_HOSTNAME} {
    encode gzip zstd
    reverse_proxy dmp-node:8053 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Real-IP {remote_host}
    }
    log {
        output stdout
        format json
    }
}
```

Client IPs are preserved via `X-Real-IP` so the node's rate limiter
sees the real source, not the Caddy container's internal address.

## Environment variables

### Storage and logging

| Var | Default | Notes |
|---|---|---|
| `DMP_DB_PATH` | `/var/lib/dmp/dmp.db` | Mount the parent dir as a persistent volume |
| `DMP_CLEANUP_INTERVAL` | `60` | Seconds between expired-record sweeps |
| `DMP_LOG_LEVEL` | `INFO` | Standard Python levels |
| `DMP_LOG_FORMAT` | `text` | Set to `json` for structured logs |

### DNS server

| Var | Default |
|---|---|
| `DMP_DNS_HOST` | `0.0.0.0` |
| `DMP_DNS_PORT` | `5353` |
| `DMP_DNS_TTL` | `60` (seconds advertised in responses) |
| `DMP_DNS_RATE` | `50` (queries/sec per source IP) |
| `DMP_DNS_BURST` | `200` |
| `DMP_DNS_MAX_CONCURRENCY` | `128` (handler threads) |

### HTTP API

| Var | Default |
|---|---|
| `DMP_HTTP_HOST` | `0.0.0.0` |
| `DMP_HTTP_PORT` | `8053` |
| `DMP_HTTP_TOKEN` | *(none)* — set to require bearer auth on publish AND metrics |
| `DMP_HTTP_RATE` | `10` (requests/sec per source IP) |
| `DMP_HTTP_BURST` | `100` |
| `DMP_HTTP_MAX_CONCURRENCY` | `64` (handler threads) |

**`DMP_HTTP_TOKEN` gates both `/v1/records/*` and `/metrics`.** Metrics
leak operational metadata — publish rate, rate-limit hits, per-operation
error counters — which is an activity indicator for a privacy-oriented
protocol. When the token is unset (dev / local mode), the server logs
a startup WARNING saying `metrics endpoint unauthenticated` and
`/metrics` remains open. Do NOT ship a node to the public internet with
the token unset. Generate one with:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

### Publish-side resource caps

| Var | Default | Purpose |
|---|---|---|
| `DMP_MAX_TTL` | `86400` | Longest TTL a client can set (1 day) |
| `DMP_MAX_VALUE_BYTES` | `2048` | Per-record payload cap |
| `DMP_MAX_VALUES_PER_NAME` | `64` | Max RRset cardinality |

## Metrics scraping

Point Prometheus at `GET /metrics`. If `DMP_HTTP_TOKEN` is set, the
scrape must carry the same bearer token as the publish side:

```yaml
scrape_configs:
  - job_name: dmp-node
    metrics_path: /metrics
    static_configs:
      - targets: ["dmp.example.com"]
    scheme: https
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/dmp-token
```

Useful alerts:

- `rate(dmp_dns_queries_total{outcome="rate_limited"}[5m]) > 0` —
  someone is hammering the DNS server.
- `dmp_records > 100000` — the store is filling up faster than
  cleanup; raise `DMP_CLEANUP_INTERVAL` or lower `DMP_MAX_TTL`.
- `rate(dmp_http_requests_total{status="429"}[5m]) > 0` — publish
  side is hitting the rate limit.

## Hardening checklist

- [ ] TLS termination in front of the HTTP API (Caddy overlay or
      your own).
- [ ] `DMP_HTTP_TOKEN` set if you don't want open publish.
- [ ] Persistent volume for `/var/lib/dmp`.
- [ ] `/health` wired to your orchestrator's liveness probe.
- [ ] `/metrics` scraped and alerted on.
- [ ] Host firewall allowing only `53/udp`, `80/tcp`, `443/tcp+udp`.
- [ ] Off-host backups of the sqlite store.
- [ ] Container log aggregation (JSON mode).

## Updating a running node

`docker compose pull && docker compose up -d` if you publish images,
or `git pull && docker compose up -d --build` for source-built images.

The sqlite schema auto-migrates on open (the prekey `wire_record`
column was added this way). Clients don't need to be restarted.
