# DNS Mesh Protocol

**End-to-end encrypted messaging with no central server, no app store, no
gatekeeper — delivered over DNS, on the relays and infrastructure the
internet already runs on.**

📖 **Full documentation → https://oscarvalenzuelab.github.io/DNSMeshProtocol/**

---

> **Status: alpha, pre-external-audit.** Full federation (client
> fan-out + union reader + node-side anti-entropy + manifest gossip),
> bootstrap discovery, and the formal protocol spec are shipped. The
> remaining path to `v1.0` is a certification backlog: external
> cryptographic audit, mobile/web clients, key rotation records,
> traffic-analysis hardening.
>
> **Don't route secrets through DMP until the external cryptographic
> audit is done.** The codebase has had ~40+ rounds of automated
> review across all milestones, but automated review is not a
> substitute for professional cryptanalysis — a human auditor catches
> a different class of bugs (crypto composition errors, side-channel
> weaknesses, protocol-level attacks, implementation-vs-spec drift)
> that no amount of LLM-driven pattern matching will find. The audit
> is a post-beta deliverable; until then treat DMP as experimental
> for confidentiality-critical traffic. See [SECURITY.md](SECURITY.md)
> and [ROADMAP.md](ROADMAP.md).

## The pitch

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

## Quick start

```bash
git clone https://github.com/oscarvalenzuelab/DNSMeshProtocol.git
cd DNSMeshProtocol

# Install the CLI
pip install -e .

# Build and run the node
docker build -t dmp-node:latest .
docker run -d -p 5353:5353/udp -p 8053:8053/tcp \
  -v dmp-data:/var/lib/dmp dmp-node:latest

# Set up an identity and send your first message
export DMP_PASSPHRASE=a-strong-passphrase
dmp init alice --domain mesh.local \
               --endpoint http://127.0.0.1:8053 \
               --dns-host 127.0.0.1 --dns-port 5353
dmp identity publish
```

Full walk-through with two users:
[Getting Started](https://oscarvalenzuelab.github.io/DNSMeshProtocol/getting-started).

## What you get

- **End-to-end encryption with forward secrecy** for prekey-consumed
  messages. Past messages stay safe if long-term keys leak later; see
  [Forward secrecy and prekeys](https://oscarvalenzuelab.github.io/DNSMeshProtocol/guide/forward-secrecy).
- **Signed sender authentication.** With pinned contacts, unknown
  signers are dropped. Without, receive runs in trust-on-first-use.
- **Zone-anchored identity addresses.** `alice@alice.example.com` —
  squatting requires compromising DNS for the zone.
- **Cross-chunk erasure coding.** Loss of up to `n-k` chunks still
  reconstructs the message.
- **Resolver resilience.** `ResolverPool` fans queries across multiple
  upstream resolvers with oracle-based demotion on lying resolvers.
  `dmp resolvers discover` auto-builds the pool from public resolvers.
- **Multi-node federation** (client AND node side). `FanoutWriter`
  publishes to every cluster node (quorum = `ceil(N/2)`); `UnionReader`
  reads the union with dedup. Nodes run pull-based anti-entropy
  against their peers so a node that was offline catches up when it
  rejoins. A 3-node `docker-compose.cluster.yml` is a checked-in
  operator starting point; see
  [Clustered deployment](https://oscarvalenzuelab.github.io/DNSMeshProtocol/deployment/cluster).
- **Zero-config onboarding via bootstrap discovery.** Given just
  `alice@example.com`, `dmp bootstrap discover me@my-domain --auto-pin`
  resolves the cluster, verifies the two-hop trust chain (bootstrap
  signer → cluster operator), and cuts over atomically.
- **Persistent, size-bounded node.** sqlite storage, TTL cleanup,
  token-bucket rate limits, bounded concurrency, Prometheus metrics.
- **Docker-first deploy.** `docker compose` for dev, Caddy + Let's
  Encrypt overlay for production.
- **Formal protocol spec.** Wire format, routing, flows, and threat
  model at
  [docs/protocol/](https://oscarvalenzuelab.github.io/DNSMeshProtocol/protocol/)
  — every constant cross-verified against the source; designed so a
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

## Project layout

```
dmp/
├── core/       Protocol primitives: crypto, chunking, erasure,
│               manifests, identity, prekeys, DNS encoding
├── network/    DNSRecordWriter / DNSRecordReader abstraction +
│               Cloudflare, Route53, BIND, in-memory backends
├── storage/    SqliteMailboxStore — persistent TTL-aware record store
├── server/     DMPNode: UDP DNS server, HTTP API, cleanup worker,
│               metrics, rate limiting, structured logging
├── client/     DMPClient — send / receive / identity / prekeys
└── cli.py      `dmp` command-line interface

docs/          Jekyll docs site (Just the Docs theme, GitHub Pages)
               Includes docs/protocol/ — the formal wire spec
tests/         670+ unit, integration, and docker-in-the-loop tests
Dockerfile, docker-compose.yml, docker-compose.prod.yml, Caddyfile
```

## Tests

```bash
pip install -e ".[dev]"
pytest                                         # ~678 tests
docker build -t dmp-node:latest .
pytest tests/test_docker_integration.py        # 4 docker tests
```

## Not a good fit for

- Real-time chat (seconds-to-minutes latency by design)
- File transfer or media payloads
- Anonymity from traffic analysis (DMP hides content, not metadata)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Every PR that changes behavior
needs a test. Security-sensitive changes in `dmp/core/crypto.py`,
`dmp/core/manifest.py`, `dmp/core/prekeys.py`, or the AEAD AAD surface
get an extra round of review.

## License

[AGPL-3.0](LICENSE). If you host DMP as a service you must publish
your source changes.

## Author

Oscar Valenzuela · AlkamoD
