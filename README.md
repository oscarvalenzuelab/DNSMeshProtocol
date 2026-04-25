# DNS Mesh Protocol

**End-to-end encrypted messaging with no central server, no app store, no
gatekeeper — delivered over DNS, on the relays and infrastructure the
internet already runs on.**

---

## What this is

DMP is an **open, free messaging protocol** built around one job:
deliver a private message from one person to another, even when the
network actively tries to stop you. Not a company, not a product —
a specification anyone can implement, plus a permissively-licensed
reference implementation.

Think of it as **the email of private messaging**: nobody owns email,
nobody can shut it off. DMP aims for the same durability, with
end-to-end encryption baked in from the start.

## Why it exists

Today's "private" messaging looks like this:

```
You ↔ One company ↔ The other person
```

That company is a single point of failure. They can be subpoenaed,
blocked at a national border, acquired, hacked, or simply shut down.
End-to-end encryption protects message *content* — none of it
protects you from the company in the middle disappearing or being
made to.

DMP removes the company from the middle.

## Who this is for

- **Journalists and sources** in countries where the usual apps are
  blocked, monitored, or unsafe to have on a phone.
- **Organizations** that want a backup channel that keeps working
  when their primary vendor is down, regulated, or subpoenaed.
- **Privacy advocates** who don't want a phone number, an account,
  or any company in between two people who agreed to talk.
- **Builders** who need a small, auditable messaging primitive they
  can embed into their own products with no licensing or vendor
  lock-in.

If DNS works on your network, DMP works on your network. That's the
whole pitch.

[**→ 5-minute training deck**](https://oscarvalenzuelab.github.io/DNSMeshProtocol/how-resolution-works.html) ·
[**→ Try the public node**](#try-it-on-dnsmeshio) ·
[**→ Self-host**](#self-host)

---

> **Status: alpha, pre-external-audit.** Full federation (client
> fan-out + union reader + node-side anti-entropy + manifest gossip),
> bootstrap discovery, key rotation + revocation (M5.4), multi-tenant
> node auth with per-user publish tokens (M5.5), cross-zone receive
> + first-message claim layer (M8 / 0.4.x), and the formal protocol
> spec are shipped. The remaining path to `v1.0` is a certification
> backlog: external cryptographic audit, mobile/web clients,
> standalone CLI binaries, traffic-analysis hardening.
>
> **Don't route secrets through DMP until the external cryptographic
> audit is done.** The codebase has had ~40+ rounds of automated
> review across all milestones, but automated review is not a
> substitute for professional cryptanalysis. A human auditor catches
> a different class of bugs (crypto composition errors, side-channel
> weaknesses, protocol-level attacks, implementation-vs-spec drift)
> that no amount of LLM-driven pattern matching will find. The audit
> is a post-beta deliverable; until then treat DMP as experimental
> for confidentiality-critical traffic.

## How it works (30-second version)

Instead of sending messages through a central server you have to trust,
DNS Mesh Protocol encrypts each message end-to-end and writes it as
DNS records on a node *you* choose. The recipient looks those records
up the same way any computer looks up `google.com`. If DNS works on
your network, DMP works on your network.

- **One docker container** is a complete, deployable node.
- **One command-line tool** covers identity, key management, send, and
  receive.
- **One protocol** composes Ed25519 signatures, X25519 ECDH,
  ChaCha20-Poly1305, Argon2id passphrase derivation, one-time prekeys
  for forward secrecy, and Reed-Solomon erasure coding for chunk loss.

## Try it on dnsmesh.io

The public reference node at `dnsmesh.io` is open: no operator approval,
no email, just a CLI command. It advertises open registration, the
M8 claim-provider role, and acts as the canonical bootstrap seed for
the federated network.

```bash
pip install dnsmesh
dnsmesh init alice --domain <your-zone> --endpoint dnsmesh.io
dnsmesh register --node dnsmesh.io
dnsmesh identity publish
```

Curious what's actually advertised: `curl https://dnsmesh.io/v1/info`.

## Self-host

```bash
git clone https://github.com/oscarvalenzuelab/DNSMeshProtocol.git
cd DNSMeshProtocol

# Install the CLI
pip install -e .

# Build and run the node
docker build -t dnsmesh-node:latest .
docker run -d -p 5353:5353/udp -p 8053:8053/tcp \
  -v dnsmesh-data:/var/lib/dmp dnsmesh-node:latest

# Set up an identity and send your first message
export DMP_PASSPHRASE=a-strong-passphrase
dnsmesh init alice --domain mesh.local \
               --endpoint http://127.0.0.1:8053 \
               --dns-host 127.0.0.1 --dns-port 5353
dnsmesh identity publish
```

For a production Ubuntu deployment with auto-TLS and systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/oscarvalenzuelab/DNSMeshProtocol/main/deploy/native-ubuntu/install.sh \
    | sudo DMP_NODE_HOSTNAME=dmp.example.com bash
```

**Then delegate a DNS subdomain to the node** so clients on the public
internet can resolve records served by the node. Without this step,
`dig @1.1.1.1 id-XXX.example.com TXT` returns nothing even though the
node has the record — the registrar's nameservers don't know about
DMP records. The fix is one `NS` record at the registrar plus one env
var on the node:

```
At the registrar (DigitalOcean / Cloudflare / etc.):
  mesh.example.com.   IN NS   example.com.

On the node:
  DMP_DOMAIN=mesh.example.com
  sudo systemctl restart dnsmesh-node
```

Full walk-through with screenshots and verification steps:
[Deployment → DNS subdomain delegation](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/dns-delegation).

Once your node is up, point the CLI at it via the **public hostname**,
not loopback — the saved registration token is keyed by hostname, so
`--endpoint http://127.0.0.1:8053` won't auto-attach a token registered
against `dmp.example.com`.

```bash
dnsmesh init alice@dmp.example.com               # auto-splits user + zone
dnsmesh register --node dmp.example.com           # mints + saves a token
dnsmesh identity publish                          # token attaches automatically
```

Full walk-through with two users:
[Getting Started](https://oscarvalenzuelab.github.io/DNSMeshProtocol/getting-started).

## What you get

- **End-to-end encryption with forward secrecy** for prekey-consumed
  messages. Past messages stay safe if long-term keys leak later; see
  [Forward secrecy and prekeys](https://oscarvalenzuelab.github.io/DNSMeshProtocol/guide/forward-secrecy).
- **Signed sender authentication.** With pinned contacts, unknown
  signers are dropped. Without, receive runs in trust-on-first-use.
- **Zone-anchored identity addresses.** `alice@alice.example.com`.
  Squatting requires compromising DNS for the zone.
- **Cross-chunk erasure coding.** Loss of up to `n-k` chunks still
  reconstructs the message.
- **Resolver resilience.** `ResolverPool` fans queries across multiple
  upstream resolvers with oracle-based demotion on lying resolvers.
  `dnsmesh resolvers discover` auto-builds the pool from public resolvers.
- **Multi-node federation** (client AND node side). `FanoutWriter`
  publishes to every cluster node (quorum = `ceil(N/2)`); `UnionReader`
  reads the union with dedup. Nodes run pull-based anti-entropy
  against their peers so a node that was offline catches up when it
  rejoins. A 3-node `docker-compose.cluster.yml` is a checked-in
  operator starting point; see
  [Clustered deployment](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/cluster).
- **Key rotation + revocation.** `dnsmesh identity rotate --experimental`
  publishes a co-signed `RotationRecord` (new key ← old key) plus an
  optional self-signed `RevocationRecord` when `--reason compromise`
  or `--reason lost_key` is set. Rotation-aware contacts chain-walk
  from their pinned key to the current head automatically; a
  revocation aborts trust on any path that touches the revoked
  key. See
  [`docs/protocol/rotation.md`](https://ovalenzuela.com/DNSMeshProtocol/protocol/rotation).
- **Multi-tenant node auth (M5.5).** `DMP_AUTH_MODE=multi-tenant`
  enables per-user publish tokens: every write to `/v1/records/*`
  is scope-checked against the token's subject, and `dnsmesh register`
  + `/v1/registration/{challenge,confirm}` give users a self-service
  path to mint their own tokens via an Ed25519-signed challenge.
  Shared-pool writes (mailbox + chunks) don't log subject or
  token hash, so an operator handed the DB cannot reconstruct
  who-delivered-to-whom. See
  [Multi-tenant deployment](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/multi-tenant).
- **Zero-config onboarding via bootstrap discovery.** Given just
  `alice@example.com`, `dnsmesh bootstrap discover me@my-domain --auto-pin`
  resolves the cluster, verifies the two-hop trust chain (bootstrap
  signer → cluster operator), and cuts over atomically.
- **Persistent, size-bounded node.** sqlite storage, TTL cleanup,
  token-bucket rate limits, bounded concurrency, Prometheus metrics.
- **Docker-first deploy.** `docker compose` for dev, Caddy + Let's
  Encrypt overlay for production.
- **Formal protocol spec.** Wire format, routing, flows, and threat
  model at
  [docs/protocol/](https://ovalenzuela.com/DNSMeshProtocol/protocol).
  Every constant cross-verified against the source; designed so a
  third party can build an interoperable client.

## Running a node

```bash
# Dev
docker compose up -d

# Production (real hostname, auto TLS)
export DMP_NODE_HOSTNAME=dmp.example.com
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

See [Deployment](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment).
**Before shipping to production, read the
[operator hardening guide](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/hardening)**,
a mandatory checklist covering TLS, token hygiene, operator signing-key
handling, DNS zone hygiene, file permissions, and network exposure.

## Project layout

```
dmp/
├── core/       Protocol primitives: crypto, chunking, erasure,
│               manifests, identity, prekeys, DNS encoding
├── network/    DNSRecordWriter / DNSRecordReader abstraction +
│               Cloudflare, Route53, BIND, in-memory backends
├── storage/    SqliteMailboxStore: persistent TTL-aware record store
├── server/     DMPNode: UDP DNS server, HTTP API, cleanup worker,
│               metrics, rate limiting, structured logging
├── client/     DMPClient: send / receive / identity / prekeys
└── cli.py      `dnsmesh` command-line interface

docs/          Jekyll docs site (Just the Docs theme, GitHub Pages)
               Includes docs/protocol/ for the formal wire spec
tests/         1050+ unit, integration, fuzz, and docker-in-the-loop tests
               Includes tests/fuzz/ (hypothesis property tests) and
               tests/test_vectors.py (golden interop test vectors).
Dockerfile, docker-compose.yml, docker-compose.prod.yml, Caddyfile
```

## Tests

```bash
pip install -e ".[dev]"
pytest                                         # ~1050 tests (incl. fuzz)
docker build -t dnsmesh-node:latest .
pytest tests/test_docker_integration.py        # 6 docker tests (incl. M5.4 rotation)
pytest tests/test_compose_cluster.py           # 3 compose-cluster tests
python examples/docker_e2e_demo.py             # single-node send/receive + rotation demo
python examples/cluster_e2e_demo.py            # 3-node federated e2e demo
```

Production installs use the hashed lockfile:

```bash
pip install --require-hashes -r requirements.lock
pip install . --no-deps
```

## Not a good fit for

- Real-time chat (seconds-to-minutes latency by design)
- File transfer or media payloads
- Anonymity from traffic analysis (DMP hides content, not metadata)

## Contributing

See [CONTRIBUTING.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/CONTRIBUTING.md). Every PR that changes behavior
needs a test. Security-sensitive changes in `dmp/core/crypto.py`,
`dmp/core/manifest.py`, `dmp/core/prekeys.py`, or the AEAD AAD surface
get an extra round of review.

## License

[AGPL-3.0](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/LICENSE). If you host DMP as a service you must publish
your source changes.

## Author

Oscar Valenzuela · AlkamoD
