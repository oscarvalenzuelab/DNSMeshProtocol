---
title: Docker
layout: default
parent: Deployment
nav_order: 1
---

# Docker
{: .no_toc }

1. TOC
{:toc}

## Build the image

```bash
docker build -t dmp-node:latest .
```

Multi-stage build on `python:3.11-slim`. Final image runs as a
non-root `dmp` user, exposes `5353/udp` and `8053/tcp`, and has a
`HEALTHCHECK` that hits `/health` through curl.

## Run a single node

```bash
docker run -d --name dmp-node \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dmp-data:/var/lib/dmp \
  dmp-node:latest
```

| Mount | Purpose |
|---|---|
| `-v dmp-data:/var/lib/dmp` | Persistent sqlite store (message RRsets, replay state) |

Check it's up:

```bash
curl http://127.0.0.1:8053/health    # {"status":"ok"}
curl http://127.0.0.1:8053/metrics   # Prometheus text
```

## docker-compose

`docker-compose.yml` at the repo root is the local-dev config:

```yaml
services:
  dmp-node:
    build: .
    ports:
      - "5353:5353/udp"
      - "8053:8053/tcp"
    volumes:
      - dmp-data:/var/lib/dmp
    environment:
      DMP_LOG_LEVEL: INFO
      # (commented-out knobs for rate limits, bearer token, log format)
    healthcheck:
      test: ["CMD", "curl", "-fsS", "http://127.0.0.1:8053/health"]
      interval: 30s

volumes:
  dmp-data:
```

Bring it up:

```bash
docker compose up -d
docker compose logs -f dmp-node
docker compose down     # stop; volume persists
```

## Port 53 on the host

Port 53 is privileged on Linux. Three options:

1. **Map the host's 53 to the container's 5353** (recommended):
   ```
   -p 53:5353/udp
   ```
   Your DMP node now answers real DNS queries for configured names.
   The container itself still binds 5353 internally.
2. **Run the container with `CAP_NET_BIND_SERVICE`** and set
   `DMP_DNS_PORT=53`. Requires `--cap-add=NET_BIND_SERVICE`.
3. **Stay on 5353** for dev. Easier, but external resolvers won't
   query you automatically.

Most Linux distros' `systemd-resolved` holds port 53 out of the box.
Free it with:

```bash
sudo systemctl disable --now systemd-resolved
sudo rm /etc/resolv.conf
echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf
```

## Health and metrics

- `GET /health` — 200 with `{"status":"ok"}` when sqlite is reachable;
  503 with `{"status":"degraded"}` otherwise. Use this for your
  orchestrator's liveness probe.
- `GET /metrics` — Prometheus text format. Exposes:
  - `dmp_http_requests_total{method,status}`
  - `dmp_dns_queries_total{outcome}` (outcome ∈ noerror/nxdomain/…/rate_limited)
  - `dmp_records` (gauge — live records in the sqlite store)
- `GET /stats` — JSON `{"records": <count>}`. Same info as the gauge,
  for humans.

## Upgrading

```bash
git pull
docker build -t dmp-node:latest .
docker compose up -d dmp-node
```

The sqlite schema migrates itself on open — no manual step. Existing
records keep their TTLs; clients keep their replay caches.

## Next

- [Production deployment]({{ site.baseurl }}/deployment/production) for
  TLS, rate limits, and public exposure.
