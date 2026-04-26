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

         dnsmesh init                      [DNS UPDATE + TSIG]             dnsmesh identity fetch
         dnsmesh send bob    ─── UPDATE ─►  stores ciphertext  ◄─── DNS ───  dnsmesh recv  (decrypts locally)
```

Everything on the wire is either **signed** (the node cannot forge it)
or **end-to-end encrypted** (the node cannot read it). Node operators
see ciphertext and public keys. They do not see message bodies. They
do not hold private keys.

The useful consequence: **the trust you place in a node operator is
much smaller than the trust you place in a messaging company.** You
still trust them to stay online and not drop your records, but not to
keep your secrets.

## Where bytes actually go

A common confusion: when Alice sends a message to Bob, does her
client talk to Bob's home node directly? **No.** Alice publishes to
her own home node. In the preferred M9 path, those writes are RFC 2136
DNS UPDATE messages signed with her TSIG key; older configs can still
fall back to HTTPS writes to the same home node. Bob later polls his
mailbox via DNS.

Concretely:

- Alice's send writes records like
  `slot-N.mb-{hash(bob)}.<alice's mesh_domain>` to **Alice's home node**.
- Bob's receive walks each of his **pinned contacts' zones** and
  queries each one via DNS. Alice's zone is in that walk because
  Bob has pinned her as a contact, so Bob's recv asks for
  `slot-N.mb-{hash(bob)}.<alice's mesh_domain>` over the public
  recursive chain.

This is what M8.1 (shipped in 0.4.0) restored: the original DMP
property that records live under the sender's zone and the recipient
walks senders' zones via the DNS chain. End-to-end works in every
realistic configuration:

| Setup | End-to-end works? |
|---|---|
| Alice + Bob both register at the same node, share `domain: mesh.gnu.cl` | ✅ |
| Alice + Bob in a federated 3-node cluster (anti-entropy syncs records between cluster members over HTTPS) | ✅ |
| Alice on `dnsmesh.io`, Bob on `dnsmesh.pro` with different `mesh_domain`s, **pinned contacts on each side** | ✅ via M8.1 cross-zone receive |
| Alice on `dnsmesh.io`, Bob on `dnsmesh.pro`, **unpinned stranger** reaches Bob for the first time | ✅ via M8.3 claim layer (requires a reachable claim provider both sides discover) |

Each user only ever needs to reach their own home node. In the
preferred M9 flow that means one HTTPS onboarding step, then DNS
UPDATE for writes. "Node-to-node"
delivery is the recursive DNS resolver chain doing what it already
does for every other lookup on the internet — typically
`Bob's CLI → public resolver → roots → Alice's authoritative node
→ record`. First-contact claims are now published with DNS UPDATE too;
the only remaining inter-node HTTP path is cluster anti-entropy inside
one operator's HA domain.

### What HTTP and DNS each do today

- **HTTPS, client-to-own-node:** onboarding and legacy fallback.
  `dnsmesh tsig register` uses HTTPS once to mint the per-user TSIG
  key. Older configs without TSIG can still fall back to HTTPS writes
  to the user's own node.
- **DNS UPDATE, client-to-own-node:** the preferred M9 write path.
  Publishing identity, sending messages, refreshing prekeys, and
  normal mailbox writes all go here once the user has a TSIG key.
- **DNS, anywhere-to-any-node:** every read goes here. Fetching
  identities, polling mailboxes, looking up cluster manifests. No
  auth. Networks that block port 53 entirely still block DMP today;
  the CLI does not yet speak DoH itself.
- **HTTPS, node-to-node (cluster only):** anti-entropy at
  `/v1/sync/digest` + `/v1/sync/pull`. This is the documented HA-only
  exception: cluster peers share one operator-signed manifest and live
  in one administrative trust domain.

Visual walkthrough in the
[How resolution works]({{ site.baseurl }}/how-resolution-works.html)
slide deck.

## Who operates what

| Role | What they run | Where |
|---|---|---|
| **User** | `dnsmesh` CLI / `dmp` Python library (eventually an app) | Their laptop or phone |
| **Node operator** | `dnsmesh-node` Docker container | A VPS, a Raspberry Pi, a Droplet — anywhere reachable on UDP 53 |

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
dnsmesh init alice --domain dmp.yournode.com
dnsmesh tsig register --node dmp.yournode.com
dnsmesh identity publish
```

The `dnsmesh` CLI talks to `dmp.yournode.com` over HTTPS once for the
TSIG registration ceremony, then publishes signed records with DNS
UPDATE to that node's DNS service. The user shares their address
(`alice@dmp.yournode.com`) with contacts. Done.

Operator can still hand users a bearer token for legacy / fallback
publish paths, but the preferred M9 user flow is TSIG-backed DNS
UPDATE.

### Path 2 — Run your own single node

For operators who want a node for themselves, a team, or a community.

```bash
docker run -d --name dnsmesh-node \
  -p 53:5353/udp \
  -p 8053:8053/tcp \
  -e DMP_OPERATOR_TOKEN=$(openssl rand -hex 32) \
  -v dnsmesh-data:/var/lib/dmp \
  ovalenzuela/dnsmesh-node:latest
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
   dnsmesh init alice --domain example.com
   ```
4. **Publish the public keys.** The CLI signs an `IdentityRecord`
   locally and POSTs it to the node. The node stores it as a TXT
   record that any DNS client can now resolve.
   ```bash
   dnsmesh identity publish
   ```
5. **Share the address.** Tell friends: *I'm `alice@example.com`.*
6. **Friends fetch and pin.** Their client resolves the TXT record,
   verifies the Ed25519 signature, stores the public keys as a
   contact.
   ```bash
   dnsmesh identity fetch alice@example.com --add
   ```
7. **Exchange messages.** `dnsmesh send bob "hello"` on Alice's side →
   encrypt locally, chunk, publish chunks as TXT records keyed by a
   shared hash both sides can derive. `dnsmesh recv` on Bob's side →
   resolve the chunks, verify, decrypt locally.

No account creation on the node side at any point. Users self-publish
signed records; the node is a dumb filestore.

## Trust model — DNS UPDATE + TSIG, with documented exceptions

After M9 the protocol is DNS both directions. Record writes use
RFC 2136 DNS UPDATE signed with RFC 8945 TSIG; reads are plain DNS
TXT queries. The user-to-own-node HTTPS hop survives only as the
one-time TSIG-key registration ceremony.

**The DNS UPDATE write path:**

The node opts into UPDATE handling via `DMP_DNS_UPDATE_ENABLED=1`.
Per-user TSIG keys are minted via `POST /v1/registration/tsig-confirm`
(same Ed25519 challenge/confirm ceremony the legacy bearer-token
path uses). The minted key carries a per-user pattern scope so
multiple users can share a zone without overwriting each other:

- `id-<sha256(subject)[:16]>.<zone>` — identity (suffix tail-match
  also covers `prekeys.id-<hash>.<zone>` siblings)
- `id-<sha256(subject)[:12]>.<zone>` — prekey hash truncation
- `slot-*.mb-*.<zone>` — mailbox slot writes, any recipient hash
- `chunk-*-*.<zone>` — chunk records, any chunk index + msg key
- `_dnsmesh-claim-*.<zone>` — claim records published under this
  user's zone

The keystore enforces these via wildcard suffix matching at
authorization time. Operator caps (`max_ttl`, `max_value_bytes`,
`max_values_per_name`) apply identically to UPDATE writes.

**The un-TSIG'd UPDATE exception:**

Cross-zone first-contact claim publishes
(`claim-N.mb-<hash12>.<provider-zone>`) accept un-TSIG'd UPDATE.
The wire is a signed `ClaimRecord` and the Ed25519 signature IS
the on-zone authentication — a sender from zone X never has a
TSIG account on provider zone Y, but the claim wire's own
signature is verifiable independently. Other un-TSIG'd UPDATE
surfaces are REFUSED. The provider's claim-publish acceptance is
gated on `DMP_CLAIM_PROVIDER` opt-in plus `DMP_DNS_UPDATE_ENABLED`.

**The cluster anti-entropy exception:**

`/v1/sync/digest` + `/v1/sync/pull` between cluster peers stays
HTTP. Cluster nodes are co-operated by one party, share a signed
manifest, and the digest/pull cursor protocol doesn't fit cleanly
into DNS — see
[the boundary doc]({{ site.baseurl }}/design/cluster-anti-entropy-http-boundary).

**Legacy fallbacks:**

`DMP_AUTH_MODE=legacy` (single shared bearer token) and open mode
(no auth) still exist for operator-side writes (cluster manifest,
bootstrap records) and for single-user laptop deployments. The
M9 user-facing flows ride on top of TSIG.

**Anonymity property:** the shared-pool DNS records (mailbox
slots + chunks) carry no subject or token-hash in the durable
audit. An operator handed their database cannot reconstruct who
delivered to whom from it alone. Full sender anonymity against a
powerful observer still needs Tor / a mixnet — that's M6
territory.

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
