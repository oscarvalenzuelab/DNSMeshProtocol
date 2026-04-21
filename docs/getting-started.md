---
title: Getting Started
layout: default
nav_order: 2
---

# Getting Started
{: .no_toc }

1. TOC
{:toc}

## Prerequisites

- Python 3.10 or newer
- Docker (for running the node; optional for library-only use)

## Install the CLI

```bash
git clone https://github.com/oscarvalenzuelab/DNSMeshProtocol.git
cd DNSMeshProtocol
pip install -e .
```

Verify:

```bash
dmp --help
```

## Run a node (local)

```bash
docker build -t dmp-node:latest .
docker run -d --name dmp-node \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dmp-data:/var/lib/dmp \
  dmp-node:latest

# Health check
curl http://127.0.0.1:8053/health
```

Ports:

- **5353/udp** — DNS server (map to `:53` in production; see
  [Deployment]({{ site.baseurl }}/deployment))
- **8053/tcp** — HTTP publish / metrics API

## Send your first message

Two terminal windows simulate two users. In practice you'd run two
machines, but separate `DMP_CONFIG_HOME` directories work fine on one box.

**Terminal 1 — Alice**

```bash
export DMP_CONFIG_HOME=/tmp/alice-home
export DMP_PASSPHRASE=alice-pass
dmp init alice --domain mesh.local \
               --endpoint http://127.0.0.1:8053 \
               --dns-host 127.0.0.1 --dns-port 5353
dmp identity publish
```

**Terminal 2 — Bob**

```bash
export DMP_CONFIG_HOME=/tmp/bob-home
export DMP_PASSPHRASE=bob-pass
dmp init bob --domain mesh.local \
             --endpoint http://127.0.0.1:8053 \
             --dns-host 127.0.0.1 --dns-port 5353

# Publish bob's identity + a pool of one-time prekeys for forward secrecy.
dmp identity publish
dmp identity refresh-prekeys

# Resolve alice's identity from DNS and pin her.
dmp identity fetch alice --add

# Send.
dmp send alice "hello alice"
```

**Terminal 1 — Alice reads**

```bash
# Resolve bob too so his signing key is pinned — receive then accepts
# only manifests from pinned signers, not TOFU.
dmp identity fetch bob --add

dmp recv
```

You should see:

```
from ef44bf…
  ts=1776721594
  hello alice
```

{: .tip }
Running `dmp recv` a second time in the same config home doesn't
re-deliver the same message — the replay cache persists to
`$DMP_CONFIG_HOME/replay_cache.json`.

## What just happened

1. Alice encrypted "hello alice" with a recipient prekey → ECDH shared
   secret → ChaCha20-Poly1305 ciphertext.
2. The ciphertext got cross-chunk erasure-coded and published as TXT
   records under the mesh domain.
3. A signed manifest naming alice's Ed25519 key + the prekey_id + total
   chunks went into one of bob's 10 mailbox slots.
4. Bob's `dmp recv` polled the slots, verified alice's signature (pinned
   contact), checked the replay cache, fetched chunks, ran erasure
   decode, and decrypted with the prekey's secret half.
5. The prekey's secret half was then **deleted** locally and from DNS —
   that message is now forward-secret even if alice's or bob's long-term
   key leaks.

## Running against a cluster

For resilience against single-node failure, point the CLI at a
multi-node *cluster* instead of one endpoint. The operator publishes
a signed `ClusterManifest` at `cluster.<base>` TXT listing the node
set; the client pins the operator's Ed25519 pubkey + the base domain
and fans every write to a majority of nodes while unioning every read.

```bash
# Pin the operator key + base domain once.
dmp cluster pin 3c6a...the32byteoperatorpubkeyinhex mesh.example.com

# Sanity-check that the signed manifest is published and verifiable.
dmp cluster fetch
# cluster: mesh.example.com
#   seq:   7
#   exp:   1816000000
#   nodes: 3
#     n01  http=https://n1.mesh.example.com:8053  dns=203.0.113.10:53
#     ...

# From here on every `dmp send` / `dmp recv` / `dmp identity publish`
# fans writes across ceil(N/2) nodes and unions reads across all N.
# Manifests refresh in the background on `cluster_refresh_interval`
# (default 3600 seconds).
```

When either `cluster_operator_spk` or `cluster_base_domain` is unset
the CLI falls back to the legacy single-endpoint mode, so existing
configs keep working unchanged. See
[User Guide → CLI reference → `dmp cluster`]({{ site.baseurl }}/guide/cli)
for the full subcommand list.

## Next

- [User Guide → CLI reference]({{ site.baseurl }}/guide/cli)
- [User Guide → Identity and contacts]({{ site.baseurl }}/guide/identity)
- [Deployment → Docker]({{ site.baseurl }}/deployment/docker)
