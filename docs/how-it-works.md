---
title: How It Works
layout: default
nav_order: 2
---

# How DMP Works
{: .no_toc }

1. TOC
{:toc}

This page is for anyone deciding whether DMP fits their problem —
engineering leads, platform operators, founders picking infrastructure.
It answers the questions you actually ask before reading the protocol
spec: *what runs where, who operates what, and what's my deployment
story?*

If you already know you want to use it, skip to
[Getting Started]({{ site.baseurl }}/getting-started).

## The mental model

DMP has two kinds of things: **nodes** and **clients**.

**A node is infrastructure.** It's a small server (one Docker
container) that stores signed TXT records and serves them over DNS.
That's it. It has no user accounts, no login flow, no database of
users. Think *authoritative DNS server*, not *SaaS backend*. Operators
run nodes.

**A client is a user.** Every person messaging over DMP has a small
piece of software on their laptop or phone — a CLI, a library, or
eventually an app — that holds their **private keys** and talks to a
node. Clients encrypt and sign locally, then hand the resulting
ciphertext to a node to publish as TXT records.

```
    USER A's DEVICE                  DMP-NODE (VPS)                  USER B's DEVICE
    ────────────────                 ──────────────                  ────────────────
    ~/.dmp/config.yaml               serves signed TXT records:      ~/.dmp/config.yaml
      ├─ private Ed25519 key           ├─ identity records             ├─ pinned contacts
      ├─ username                      ├─ mailbox manifests            ├─ private keys
      └─ pinned contacts               └─ encrypted chunks             └─ received cache

         dmp init                      [HTTP publish API]              dmp identity fetch
         dmp send bob    ─── POST ──►  stores ciphertext   ◄─── DNS ───  dmp recv  (decrypts locally)
```

Everything on the wire is either **signed** (the node cannot forge it)
or **end-to-end encrypted** (the node cannot read it). Node operators
see ciphertext and public keys. They do not see message bodies. They
do not hold private keys.

The useful consequence: **the trust you place in a node operator is
much smaller than the trust you place in a messaging company.** You
still trust them to stay online and not drop your records, but not to
keep your secrets.

## Who operates what

| Role | What they run | Where |
|---|---|---|
| **User** | `dmp` CLI / library (eventually an app) | Their laptop or phone |
| **Node operator** | `dmp-node` Docker container | A VPS, a Raspberry Pi, a Droplet — anywhere reachable on UDP 53 |

A user and a node operator *can* be the same person — they don't have
to be.

## Does every user need their own node?

**No.** One node serves many users, the same way `1.1.1.1` serves
millions of DNS clients at once. Records are addressed by user-hash
and signed by the user, so users on a shared node cannot spoof each
other even though they share infrastructure.

How many users per node is a capacity question (disk + rate limits),
not a protocol question. A single $5/month VPS can comfortably host
thousands of low-volume users.

## Can the node live on a user's laptop?

**Technically yes, practically no for production identities.** The
node must be **reachable on UDP 53** by anyone who wants to resolve
the records it serves. A laptop behind NAT can't do that. Deployment
paths, in order of increasing seriousness:

| Scenario | Node placement | Good for |
|---|---|---|
| Local dev / self-tests | laptop | running [`examples/docker_e2e_demo.py`][demo], offline testing |
| Friends & family | one VPS someone in the group operates | trust-circle deployments, personal infra |
| Publicly reachable identity | one VPS with a public A/AAAA record | being findable at `alice@example.com` from anywhere on the internet |
| Federated (no single-operator outage) | 3+ VPS nodes stitched via `docker-compose.cluster.yml` + anti-entropy | resilient / public infra |

[demo]: https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/examples/docker_e2e_demo.py

For most users, the answer is: *use someone else's node* — a friend's
or a community one. For most teams, the answer is: *run one VPS for
the team*. For anyone who wants real sovereignty: *run your own*.

## The three deployment paths

### Path 1 — Join an existing node

For users who don't want to operate infrastructure.

```bash
pip install dnsmeshprotocol     # (once published; today: pip install -e .)
dmp init alice --domain dmp.yournode.com
dmp identity publish
```

The `dmp` CLI reaches out to `dmp.yournode.com` over the HTTPS publish
API, hands it a signed `IdentityRecord`, and the node stores it as a
TXT record. The user shares their address (`alice@dmp.yournode.com`)
with contacts. Done.

Operator hands users a bearer token if the node has publish auth
enabled (recommended). That's the only secret they need.

### Path 2 — Run your own single node

For operators who want a node for themselves, a team, or a community.

```bash
docker run -d --name dmp-node \
  -p 53:5353/udp \
  -p 8053:8053/tcp \
  -e DMP_OPERATOR_TOKEN=$(openssl rand -hex 32) \
  -v dmp-data:/var/lib/dmp \
  oscarvalenzuelab/dmp-node:latest
```

Point a DNS A record at the VPS's public IP. Front the HTTP port with
TLS (Caddy, nginx, Cloudflare) — see the
[production compose recipe][docker-deploy] that does this
automatically.

Now anyone the operator hands `dmp.yourdomain.com` + a bearer token
can onboard via Path 1.

[docker-deploy]: {{ site.baseurl }}/deployment/docker

### Path 3 — Federated cluster

For higher availability: three nodes that sync records to each other
via anti-entropy, so losing one doesn't lose anyone's messages.

```bash
docker compose -f docker-compose.cluster.yml up -d
```

End-to-end walkthrough lives in
[`examples/cluster_e2e_demo.py`](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/examples/cluster_e2e_demo.py)
and the operator guide is at
[Cluster deployment]({{ site.baseurl }}/deployment/cluster).

Same client experience — users don't know or care how many nodes sit
behind `dmp.example.com`.

## What a new user actually does

Concrete flow, from scratch:

1. **A node exists somewhere.** Either the user's, a friend's, or a
   community's. Let's say `dmp.example.com`.
2. **Install the CLI.**
   ```bash
   git clone https://github.com/oscarvalenzuelab/DNSMeshProtocol.git
   cd DNSMeshProtocol && pip install -e .
   ```
3. **Create a local identity.** This generates an Ed25519 signing
   keypair and an X25519 encryption keypair from a passphrase and
   stores the private halves in `~/.dmp/config.yaml`. The private keys
   **never leave the laptop**.
   ```bash
   dmp init alice --domain example.com
   ```
4. **Publish the public keys.** The CLI signs an `IdentityRecord`
   locally and POSTs it to the node. The node stores it as a TXT
   record that any DNS client can now resolve.
   ```bash
   dmp identity publish
   ```
5. **Share the address.** Tell friends: *I'm `alice@example.com`.*
6. **Friends fetch and pin.** Their client resolves the TXT record,
   verifies the Ed25519 signature, stores the public keys as a
   contact.
   ```bash
   dmp identity fetch alice@example.com --add
   ```
7. **Exchange messages.** `dmp send bob "hello"` on Alice's side →
   encrypt locally, chunk, publish chunks as TXT records keyed by a
   shared hash both sides can derive. `dmp recv` on Bob's side →
   resolve the chunks, verify, decrypt locally.

No account creation on the node side at any point. Users self-publish
signed records; the node is a dumb filestore.

## Trust model — three auth modes

The node's `/v1/records/*` publish API runs in one of three modes,
picked via `DMP_AUTH_MODE`:

- **`open`** (default when no token is configured). No auth, no
  TokenStore, no registration endpoints. Dev / trusted-LAN only.
  `dmp identity publish` works unauthenticated. Suitable for
  running a single-user node on your own laptop.

- **`legacy`** (implicit when `DMP_OPERATOR_TOKEN` / `DMP_HTTP_TOKEN`
  is set and `DMP_AUTH_MODE` isn't). Single shared bearer token.
  Everyone onboarded to the node holds the same secret. Fine for
  a team or small community where key holders trust each other;
  the token leaks the moment you hand it to a stranger. This is
  the pre-M5.5 behavior, still supported.

- **`multi-tenant`** (opt-in via `DMP_AUTH_MODE=multi-tenant`).
  Per-user publish tokens. Each user has their own bearer, minted
  either by the operator (`dmp-node-admin token issue`) or
  self-service (the user runs `dmp register`, proves key control
  with a signed challenge, and the node mints a token bound to
  their subject). Publish requests are scope-checked:
    - Alice's token can POST `dmp.alice.example.com` — her identity
      record — but not `dmp.bob.example.com`.
    - Any user's token can POST chunks + mailbox deliveries (the
      "deliver to anyone's inbox" SMTP analogy), rate-limited
      per-token.
    - Neither can POST into the operator namespace (cluster
      manifests, bootstrap records) — that still requires
      `DMP_OPERATOR_TOKEN`.
  Registration and the admin CLI are covered in the
  [User Guide]({{ site.baseurl }}/guide) and the
  [Deployment — Multi-tenant node]({{ site.baseurl }}/deployment/multi-tenant)
  guide.

**Scaling guidance:**

- Self-host / one-user node → `open`.
- Team / friends / one-trust-zone community → `legacy`.
- Public community node, or you want per-user audit / rate-limit /
  revocation → `multi-tenant`.

**Anonymity property of `multi-tenant`:** the shared-pool writes
(chunks + mailbox deliveries) do not log subject or token hash in
the durable audit. An operator compelled to hand over their
database cannot, from it alone, reconstruct which user delivered to
whom. Full sender anonymity against a powerful observer still needs
Tor / a mixnet — that's M6 territory.

## When NOT to use DMP

- **You need guaranteed delivery under seconds.** DNS caching and
  anti-entropy gossip give propagation delays in the single-digit
  seconds range — fine for messaging, wrong for trading signals.
- **You need metadata privacy against the node operator.** Message
  bodies are encrypted, but *who talks to whom* (traffic analysis)
  leaks to the node. Mix networks and onion routing exist for a
  reason; DMP is not one.
- **You're not comfortable with a non-certified-yet protocol.** DMP is
  pre-audit. The crypto primitives are standard (X25519, Ed25519,
  ChaCha20-Poly1305, Argon2id), but the composition has not been
  reviewed by a third party. See [SECURITY.md][security].
- **You need push notifications, read receipts, typing indicators.**
  DMP is a transport. Those are application features someone has to
  build on top.

[security]: https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md

## Next steps

- **Try it hands-on:** [Getting Started]({{ site.baseurl }}/getting-started)
- **Deploy a node:** [Deployment]({{ site.baseurl }}/deployment)
- **Day-to-day CLI + library use:** [User Guide]({{ site.baseurl }}/guide)
- **Protocol internals:** [Protocol]({{ site.baseurl }}/protocol)
