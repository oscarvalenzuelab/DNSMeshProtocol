---
title: Hardening
layout: default
parent: Deployment
nav_order: 4
---

# Operator hardening guide
{: .no_toc }

Mandatory-reading checklist before shipping a DMP node to production.
The items below close the attack surface an external observer — or a
compromised peer — can actually reach. A missing item from this list
is the most common way a DMP node gets owned; treat them as defaults,
not "nice to haves."

1. TOC
{:toc}

{: .warning }
External cryptographic audit is tracked separately (see `ROADMAP.md`
M4.2-M4.4). The hardening below is orthogonal: these are the
operator-facing knobs whose defaults still need to be right regardless
of how the audit concludes.

## 1. TLS is not optional in production

The HTTP API publishes records (signed, but not confidential) and
serves `/metrics` (operational metadata) and `/v1/sync/*` (cluster-
internal state dumps). Plain-HTTP deployments leak:

- The bearer token (`DMP_OPERATOR_TOKEN` or a per-user token under
  `DMP_AUTH_MODE=multi-tenant`) on every publish.
- Every publish payload — an attacker on path sees who is publishing
  what to which slot.
- The entire `/metrics` body on every scrape.

Ship the [`docker-compose.prod.yml`]({{ site.baseurl }}/deployment/production#tls-via-caddy)
overlay. It puts Caddy in front of the HTTP API with automatic
Let's Encrypt certificates — you get HTTPS (and HTTP/3) for free, and
the raw `:8053` port is removed from the host so there is no
plain-HTTP fallback.

```bash
export DMP_NODE_HOSTNAME=dmp.example.com
docker compose \
  -f docker-compose.yml \
  -f docker-compose.prod.yml \
  up -d
```

If you terminate TLS elsewhere (your own proxy, a cloud load
balancer), make sure the upstream path from proxy → node stays on the
Docker bridge network or a private interface, never a public one.

## 2. Token hygiene

Three token classes as of M5.5:

- `DMP_OPERATOR_TOKEN` (alias: `DMP_HTTP_TOKEN`) — operator-scoped
  bearer. In `DMP_AUTH_MODE=legacy` (the default when a token is
  set but no mode is configured), it gates every write to
  `/v1/records/*` plus `GET /metrics`. In `DMP_AUTH_MODE=multi-tenant`,
  it still gates `/metrics` and operator-reserved namespaces (cluster
  manifests, bootstrap records) but end-user writes are handled by
  per-user tokens instead.
- **Per-user tokens (M5.5, multi-tenant mode only).** Minted via
  `dmp-node-admin token issue` or self-service
  `POST /v1/registration/confirm`. Each is scope-bound to a subject
  (`alice@example.com` can only write under her namespace). Never
  persisted to disk on the node — only `sha256(token)` in
  `tokens.db`. Leaking one user's token does not expose other
  users' records.
- `DMP_SYNC_PEER_TOKEN` — gates `/v1/sync/digest`, `/v1/sync/pull`,
  `/v1/sync/cluster-manifest`. Only sibling cluster nodes need this.

Rules:

- **Rotate on a cadence.** Quarterly is a reasonable default. Rotate
  immediately on operator departure, node compromise, or any leak
  suspicion.
- **Never reuse a token across environments.** A prod-grade token in
  a staging node means staging can impersonate prod clients to prod.
- **Generate with `secrets.token_urlsafe`**, never by hand or with a
  human-memorable string:

  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(32))"
  ```

- **Keep both tokens equally long.** They share the same entropy
  requirement even though only one is publicly-reachable — a compromised
  sync token exposes every record on the node via `/v1/sync/pull`.

## 3. Operator signing-key handling

The Ed25519 key that signs `ClusterManifest` (and `BootstrapRecord`,
if you publish one) is **the** trust anchor for every client pinned
to your cluster. A client with this key can decide which nodes belong
to the cluster. Losing control of it is equivalent to losing the
domain.

- **Keep it offline after signing.** The signing operation happens
  once per rollout (seq++). Run it on a machine that does not run the
  node. The `scripts/generate-cluster-manifest.py` helper is
  deliberately a separate tool so the key never needs to live on a
  public-facing host.
- **Air-gap the signing machine for high-value deployments.** Copy
  the unsigned manifest in, copy the wire file out, never plug the
  signing machine into the public network. This is the same threat
  model as a DNSSEC KSK.
- **Never check `operator-ed25519.hex` into version control.**
  [`.gitignore`]({{ site.baseurl }}/../.gitignore) already covers
  this, but audit your `git status` before every commit.
- **HSM / YubiKey for high-value deployments.** Post-audit we expect
  to formalize the HSM path; until then, the recommendation is an
  offline machine with full-disk encryption and a strong passphrase.

## 4. DNS zone hygiene

The zone serving `_dmp.<user_domain>` (bootstrap), `cluster.<base>`
(cluster manifest), and per-user identity records is a trust surface.
An attacker who controls your zone can publish a forged bootstrap /
cluster / identity record — signatures protect against tampering, but
the attacker also controls which records reach clients.

- **Enable DNSSEC** if your registrar and resolver path support it.
  DNSSEC gives cryptographic provenance for the zone contents; signed
  DMP records give cryptographic provenance for the data. Defense in
  depth.
- **Lock the registrar account with 2FA** — preferably hardware
  (WebAuthn / YubiKey), failing that TOTP. SMS-based 2FA is
  SIM-swappable and does not count.
- **Monitor for unauthorized zone changes.** Registrar change logs,
  `dig` against your public zone from an external vantage point,
  third-party DNS monitoring — whichever fits your stack. Noticing a
  zone change within an hour is worth much more than noticing it
  within a week.

## 5. File permissions

The process runs as the `dmp` user created in the Dockerfile; these
are the expected modes on the volumes and mounted files:

| Path | Mode | Owner | Notes |
|---|---|---|---|
| `/var/lib/dmp/dmp.db` | `0600` | `dmp:dmp` | SQLite store |
| `/var/lib/dmp/*` | `0600` | `dmp:dmp` | rollback / tmp / wire files |
| `cluster.json` (mounted) | `0600` | `dmp:dmp` | cluster manifest wire |
| `operator-ed25519.hex` | `0400` | operator user | On the SIGNING machine only, NEVER in the container |
| `/var/lib/dmp/` (dir) | `0700` | `dmp:dmp` | parent dir |

Docker volumes are already owned by the `dmp` user (see `Dockerfile`).
If you bind-mount host paths, make sure the host UID/GID matches, or
the node's writes will fail silently (or worse, succeed as root).

## 6. Metrics and logs

- **`/metrics` behind `DMP_OPERATOR_TOKEN`.** The server refuses
  unauthenticated metrics scrapes when a token is configured (see
  the sec-hardening bundle). If you deploy without a token, the
  server logs `metrics endpoint unauthenticated` at startup — that
  warning is not cosmetic, it's telling you an activity indicator is
  open to the world.
- **Logs to stdout in JSON.** `DMP_LOG_FORMAT=json` gives you
  structured events suitable for Loki, CloudWatch, Datadog, etc. Do
  NOT redirect logs into a public file share or a world-readable S3
  bucket — they carry request IPs, publish counts, token-auth
  failures (useful to an attacker probing token validity).
- **Log consumer access control matches node trust level.** If only
  your on-call can SSH the node, only your on-call should have
  read-access to the log destination.

## 7. Network exposure

Only these ports should be reachable from the public internet:

- `443/tcp` (+ `443/udp` for HTTP/3) — HTTPS API via Caddy.
- `5353/udp` — DMP DNS server, for record lookups.

These ports must NEVER be public:

- `8053/tcp` — raw HTTP API. Caddy terminates TLS in front; the
  container's `8053` should be bound to `127.0.0.1` or the Docker
  bridge network. The `docker-compose.prod.yml` overlay removes the
  public host port for this reason.
- `/v1/sync/*` endpoints (served by the HTTP API on the same port).
  These are cluster-internal. They return hashes + values + cluster
  manifests in bulk. Even with `DMP_SYNC_PEER_TOKEN` set, exposing
  them publicly broadens the attack surface pointlessly.

Configure your host firewall (`ufw`, cloud security group, etc.) to
drop any inbound traffic on `:8053` from outside the cluster VPC.
The compose sample in [`docker-compose.cluster.yml`]({{ site.baseurl }}/deployment/cluster)
binds node-to-node channels to `127.0.0.1` or the Docker bridge for
exactly this reason.

## 8. Upgrade cadence

The supply-chain / CVE story is only useful if someone acts on it.

- **Subscribe to the repo's Watch → Releases.** GitHub will email you
  when a new tag lands.
- **Apply security updates within a sensible window.** 7 days for
  HIGH / CRITICAL findings from `pip-audit`; 30 days for MEDIUM. The
  security CI workflow (`pip-audit` against the hashed lockfiles)
  runs weekly so you don't have to remember to check.
- **Test the upgrade on a staging cluster first** if you have one.
  The sqlite schema auto-migrates on open, so you mostly need to
  confirm the new wire format (if any) is still accepted by your
  existing peers. Check `CHANGELOG.md` for any breaking change notes.
- **Pin by digest in production.** The Dockerfile already pins the
  base image by sha256; your deployment YAML / Compose file should
  pin the `dmp-node` image by digest too (not by `:latest`).

## Cross-references

- [Production]({{ site.baseurl }}/deployment/production) — env-var
  reference, Caddy config.
- [Docker]({{ site.baseurl }}/deployment/docker) — container build
  story.
- [Clustered]({{ site.baseurl }}/deployment/cluster) — 3-node
  compose sample.
- `SECURITY.md` in the repo root — how to report vulnerabilities
  responsibly.
