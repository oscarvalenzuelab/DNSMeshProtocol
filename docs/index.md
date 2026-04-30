---
title: Home
layout: default
nav_order: 1
---

# DNS Mesh Protocol
{: .fs-9 }

End-to-end encrypted messaging with no central server, no app store, no
gatekeeper — delivered over DNS, on the relays and infrastructure the
internet already runs on.
{: .fs-6 .fw-300 }

[How it works]({{ site.baseurl }}/how-it-works){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Slide deck]({{ site.baseurl }}/how-resolution-works.html){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Try it in 5 minutes]({{ site.baseurl }}/getting-started){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Deploy a node]({{ site.baseurl }}/deployment){: .btn .fs-5 .mb-4 .mb-md-0 .mr-2 }
[GitHub](https://github.com/oscarvalenzuelab/DNSMeshProtocol){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Use dnsmesh.io as your starting point

You don't need to run your own node to try DMP. The reference public
node at **`https://dnsmesh.io`** is open to anyone:

```bash
pipx install dnsmesh
dnsmesh init alice --domain <your-zone> --endpoint dnsmesh.io
dnsmesh tsig register --node dnsmesh.io      # one-shot HTTPS, mints TSIG key
dnsmesh identity publish                      # DNS UPDATE under that key
```

What that node currently advertises
(`dig @dnsmesh.io _dnsmesh-heartbeat.dnsmesh.io TXT +short`):

- **Open registration over TSIG.** Anyone can mint a per-user TSIG
  key via `dnsmesh tsig register --node dnsmesh.io` — no operator
  approval, no account, no email. The TSIG key is what authorizes
  every subsequent record publish. The `tsig register` step is the
  only HTTPS exchange in the protocol; everything after is DNS
  UPDATE (RFC 2136 + RFC 8945).
- **Claim-provider role.** Strangers who know your address can reach
  you on a first message even before you've pinned them as a contact
  (M8 first-contact layer). Your CLI quarantines them in an `intro`
  queue that you review with `dnsmesh intro list / accept / trust /
  block`. Records hosted are tiny signed pointers — the ciphertext
  stays in the sender's zone.
- **Canonical bootstrap seed.** Other DMP nodes use `dnsmesh.io` as
  their default heartbeat-discovery seed, so federation works out of
  the box without operators having to coordinate.
- **Multi-node federation source.** Clients that pin `dnsmesh.io`'s
  `_dmp.<your-zone>` bootstrap record can resolve a cluster manifest
  via the two-hop trust chain.

If you'd rather self-host, the same capabilities are one
`deploy/native-ubuntu/install.sh` away — the public node is a
reference, not a dependency. **Both modes interoperate over DNS.**

---

## What it is

DNS Mesh Protocol (DMP) is an **open-source, end-to-end encrypted
messaging protocol** that uses the public DNS system as its delivery
network.

Instead of sending messages through a central server that you have to
trust — and that a regulator, an ISP, or an adversary can lean on — DMP
breaks each message into small pieces and writes them as DNS records on
a server *you choose*. The recipient looks those records up the same
way any computer looks up `google.com`.

If DNS works on your network, DMP works on your network. That's the
whole pitch.

## Why DNS

Most messaging products live inside one company's infrastructure. Block
the company's servers and you kill the product. Regulate the company
and every user is regulated with it.

DNS is different. It's run by thousands of independent operators,
every network on Earth allows it, and blocking DNS wholesale breaks
the internet. An attacker who wants to silence DMP has to either
compromise the recipient's node specifically (hard — it's your
hardware) or break DNS itself (much harder — they break everything).

The cost of that flexibility: DMP is not instant. A message takes
seconds to propagate, not milliseconds. DMP is designed for the same
speed envelope as email, not WhatsApp.

## Use cases where it fits

- **Journalists and sources** in countries where Signal and WhatsApp
  are blocked but DNS still resolves.
- **Internal communications** on restrictive corporate networks that
  let DNS through but block most apps.
- **Resilient backup channel** for organizations that already have
  Signal but want a fallback that works when Signal is down or
  unreachable.
- **Any product** that needs to deliver short messages from one person
  to another across an adversarial network.

It's **not** a good fit for:

- Real-time chat (seconds-to-minutes latency)
- File transfer or rich media (message-sized payloads only, by design)
- Anonymity from traffic analysis (DMP hides content, not metadata)

## What you get cryptographically

In plain English, and without the jargon:

- **Only the recipient can read the message.** Nobody in between — not
  the node operator, not the DNS servers — has the key to decrypt it.
  This uses the same building blocks as Signal and HTTPS.
- **Past messages stay safe if your keys leak later.** DMP rotates a
  pool of single-use keys on the receiver side. Once a message has
  been read, the key that could decrypt it is wiped from disk. This is
  called *forward secrecy* and it's the property most people intuitively
  think they have when they hear "end-to-end encrypted" — but many
  products don't.
- **Forged messages get rejected.** Every delivery carries a signature
  from the sender's long-term identity key. A stranger pretending to be
  Alice produces a signature that doesn't verify and gets dropped.
- **Name squatting is mitigated.** Users can anchor their identity to a
  DNS zone they control (think `alice@alice.example.com`) so only the
  real owner of that domain can publish as "alice". This borrows email's
  trust model — battle-tested for decades.

An honest list of what we *don't* protect (traffic analysis,
post-compromise recovery, shared-mesh-domain squatting) is in
[SECURITY.md](https://github.com/oscarvalenzuelab/DNSMeshProtocol/blob/main/SECURITY.md).

## How it works (30-second version)

```
┌────────────┐    1. encrypt          ┌────────────────┐
│  Alice's   │───────────────────────▶│  Alice's DMP   │
│    CLI     │    2. publish over     │     node       │
│            │       HTTP API         │  (Docker, on   │
│            │                        │   her server)  │
└────────────┘                        └───────┬────────┘
                                              │
                                    3. DNS TXT records
                                              │
                                              ▼
                                     ┌─────────────────┐
                                     │  Public DNS     │
                                     │  resolvers      │
                                     │  (8.8.8.8 etc.) │
                                     └───────┬─────────┘
                                              │
                                    4. Bob queries DNS
                                              │
                                              ▼
┌────────────┐    5. decrypt          ┌────────────────┐
│   Bob's    │◀───────────────────────│  Bob's CLI     │
│   inbox    │       (verify + fetch) │                │
└────────────┘                        └────────────────┘
```

1. Alice's command-line tool encrypts the message for Bob and signs it.
2. It publishes the ciphertext as a batch of DNS TXT records on her node.
3. Those records propagate through the normal global DNS system.
4. Bob's CLI polls for records addressed to him.
5. It verifies Alice's signature, decrypts, and displays the message.

There is **no central DMP server**. If every node but Bob's disappeared,
Bob could still run one and receive mail.

## What it costs to run

A production DMP node is a single Python process in a Docker container.
Plausible infrastructure for a small organization:

- A $6/month VPS
- A domain name
- A TLS certificate (Caddy takes care of this automatically)

No vendor, no proprietary runtime, no database cluster. The whole node
is a few thousand lines of Python plus SQLite.

## Current maturity

{: .warning }
DMP is **alpha, pre-external-audit software**. The protocol and API
are unstable. **Don't route secrets through DMP until the external
cryptographic audit is done.** The codebase has had ~40+ rounds of
automated code review (via OpenAI Codex) across all milestones, which
surfaced and closed many real issues — but automated review is not a
substitute for professional cryptanalysis. A human auditor catches a
different class of bugs (crypto composition errors, side channels,
protocol-level attacks, spec-vs-implementation drift) that pattern
matching cannot find. Until the audit is published, treat DMP as
non-certified-yet for confidentiality-critical traffic.

Actively shipping:

- Command-line client (`dnsmesh`, installable via
  [`pip install dnsmesh`](https://pypi.org/project/dnsmesh/) or
  from source).
- Dockerized node with sqlite storage, metrics, rate limiting.
- Forward-secret messaging via one-time prekeys (prekey-consumed
  messages only; long-term-key fallback does not get forward secrecy).
- Zone-anchored identity addresses (`user@zone.example.com`).
- Ed25519 signature verification pinned to contacts.
- Reed-Solomon erasure coding so lost chunks still reconstruct.
- **Resolver resilience** — a `ResolverPool` with oracle-based
  demotion survives a subset of upstream DNS resolvers lying about
  DMP-shaped names.
- **Multi-node federation** (client AND node side) — `dnsmesh cluster
  pin / enable` switches the client onto a signed `ClusterManifest`;
  writes quorum across the node set, reads union with dedup, refresh
  is atomic across reader + writer. Nodes run pull-based anti-entropy
  against their peers so records propagate across the cluster even
  after a node restart. `docker-compose.cluster.yml` is a
  checked-in 3-node operator starting point.
- **Bootstrap discovery** — `dnsmesh bootstrap discover me@my-domain
  --auto-pin` resolves the cluster from a user domain via a signed
  `_dmp.<user_domain>` TXT record, verifies the two-hop trust chain
  (bootstrap signer → cluster operator), and cuts over atomically.
- **Cross-zone receive + first-message claim layer (M8 / 0.4.0).**
  Restores the original DMP property that a sender publishes to
  *their own* DNS zone and the recipient pulls via the recursive
  resolver chain — no shared mesh required, just pin a contact's
  zone. For unpinned strangers, signed claim records hosted on
  capability-advertising nodes (`CAP_CLAIM_PROVIDER` bit in the
  heartbeat) give a working first-contact path without putting the
  recipient's home node on the open-write hot path. Claim records
  are tiny signed pointers; ciphertext stays in the sender's zone.
  Quarantined intros land in `dnsmesh intro list` for review.
- **Formal protocol specification** at
  [`docs/protocol/`]({{ site.baseurl }}/protocol/) — wire format,
  routing, end-to-end flows, and threat model, designed so an
  independent implementer can build interoperable clients.

Certification backlog — work on the path to `v1.0`, tracked as [GitHub issues](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues?q=is%3Aissue+label%3Acertification-backlog):

- **External cryptographic audit** (M4.2–M4.4). The gate for tagging
  `v0.2.0-beta` and for treating DMP as anything other than alpha
  software.
- **Mobile client** (M5.2), **web/WASM client** (M5.3).
- **Traffic-analysis resistance** (M6) — random publish delays, dummy
  chunks, chunk-order randomization. Best-effort research track.

## Next step

New to DMP? Take the
[five-minute Getting Started walkthrough]({{ site.baseurl }}/getting-started).
You'll stand up a local node, exchange keys between two identities, and
deliver your first end-to-end encrypted message.

Running a public node? Start with
[Deployment → Docker]({{ site.baseurl }}/deployment/docker) and then
the [Production checklist]({{ site.baseurl }}/deployment/production).

Curious how it actually works? The
[Protocol]({{ site.baseurl }}/protocol) section has the wire format,
crypto composition, and security model.
