---
title: Getting Started
layout: default
nav_order: 3
---

# Getting Started
{: .no_toc }

1. TOC
{:toc}

## Prerequisites

- Python 3.10 or newer (for the PyPI install or source install)
- Docker (for running a node locally; not needed if you only use the
  CLI against someone else's node)

## Install the CLI

Pick one. The PyPI wheel is the fastest path; source install is for
contributors and people pinning to an unreleased commit.

### From PyPI (recommended)

```bash
pip install dnsmesh
```

### Standalone binary (no Python required)

Single-file executables are attached to every release on GitHub. Pick
the asset for your platform from the latest
[`cli-vX.Y.Z` release](https://github.com/oscarvalenzuelab/DNSMeshProtocol/releases).
Available for Linux x86_64, macOS arm64, and Windows x86_64.

```bash
# example: macOS arm64
curl -fsSL -o ~/.local/bin/dnsmesh \
    https://github.com/oscarvalenzuelab/DNSMeshProtocol/releases/latest/download/dnsmesh-macos-arm64
chmod +x ~/.local/bin/dnsmesh
```

### From source (contributors)

```bash
git clone https://github.com/oscarvalenzuelab/DNSMeshProtocol.git
cd DNSMeshProtocol
pip install -e ".[dev]"
```

Verify any of the above:

```bash
dnsmesh --help
```

## Run a node (local)

The pre-built image on Docker Hub is the easiest way:

```bash
docker run -d --name dnsmesh-node \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dnsmesh-data:/var/lib/dmp \
  ovalenzuela/dnsmesh-node:latest

# Health check
curl http://127.0.0.1:8053/health
```

To put a node on the public internet (with auto TLS, hardening, etc.),
follow [Deployment → DigitalOcean]({{ site.baseurl }}/deployment/digitalocean)
or any of the other deployment guides — the same Docker recipe runs
on any UDP-capable VPS.

If you'd rather build from source instead of pulling the published
image:

```bash
docker build -t dnsmesh-node:latest .
docker run -d --name dnsmesh-node \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dnsmesh-data:/var/lib/dmp \
  dnsmesh-node:latest
```

Ports:

- **5353/udp** — DNS server (map to `:53` in production; see
  [Deployment]({{ site.baseurl }}/deployment))
- **8053/tcp** — HTTP publish / metrics API

## Set your passphrase

Identity keys are derived from a passphrase + a per-identity random
salt (Argon2id). The CLI looks for the passphrase in three places, in
order:

1. The `DMP_PASSPHRASE` environment variable.
2. A file path named in your config's `passphrase_file` field.
3. An interactive `getpass` prompt as a last resort.

Pick the one that fits how you'll use the CLI.

{: .warning }
**The passphrase is the only thing protecting your keys.** Lose it →
identity unrecoverable (the salt is useless without it). Leak it →
full account compromise. Treat it like a password-manager entry: long,
random, and backed up.

### Option A — environment variable (quick, ephemeral)

Good for a quick test on a dev box. The shell prompts you silently
(no echo, no shell history):

```bash
read -rs DMP_PASSPHRASE
export DMP_PASSPHRASE
dnsmesh identity show
```

The passphrase lives in the shell's environment until you close the
shell, then it's gone. You'll re-enter it next session.

Avoid `export DMP_PASSPHRASE='hunter2'` directly — that lands in
`~/.zsh_history` (or `~/.bash_history`).

### Option B — passphrase file (durable, recommended)

What you want for a long-running setup or a server. The file is
read on every `dnsmesh` invocation; trailing whitespace is stripped.

```bash
umask 077                                   # new files default 0600
mkdir -p ~/.dmp

# Generate a strong random passphrase (or paste from a password manager):
openssl rand -base64 32 > ~/.dmp/passphrase
chmod 400 ~/.dmp/passphrase

# Tell the CLI where to find it:
echo 'passphrase_file: ~/.dmp/passphrase' >> ~/.dmp/config.yaml

dnsmesh identity show
```

After that, every `dnsmesh` command uses the file automatically. Back
up `~/.dmp/passphrase` to your password manager.

### Option C — interactive prompt

If neither the env var nor a file is configured, the CLI falls back
to a `getpass` prompt. Safest for one-off invocations on a machine
you don't fully trust, since nothing is stored. Annoying for
day-to-day use because every command prompts again.

### Verify

```bash
dnsmesh identity show
```

prints your Ed25519 + X25519 public keys + `user_id`. Run it twice
with the same passphrase: identical output (deterministic derivation).
Run with a wrong passphrase: silently different keys — and any record
you publish under that mistake is a fresh identity nobody has pinned.

## Send your first message

Two terminal windows simulate two users. In practice you'd run two
machines, but separate `DMP_CONFIG_HOME` directories work fine on one box.

**Terminal 1 — Alice**

```bash
export DMP_CONFIG_HOME=/tmp/alice-home
export DMP_PASSPHRASE=alice-pass
dnsmesh init alice --domain mesh.local \
               --endpoint http://127.0.0.1:8053 \
               --dns-host 127.0.0.1 --dns-port 5353
dnsmesh identity publish
```

**Terminal 2 — Bob**

```bash
export DMP_CONFIG_HOME=/tmp/bob-home
export DMP_PASSPHRASE=bob-pass
dnsmesh init bob --domain mesh.local \
             --endpoint http://127.0.0.1:8053 \
             --dns-host 127.0.0.1 --dns-port 5353

# Publish bob's identity + a pool of one-time prekeys for forward secrecy.
dnsmesh identity publish
dnsmesh identity refresh-prekeys

# Resolve alice's identity from DNS and pin her.
dnsmesh identity fetch alice --add

# Send.
dnsmesh send alice "hello alice"
```

**Terminal 1 — Alice reads**

```bash
# Resolve bob too so his signing key is pinned — receive then accepts
# only manifests from pinned signers, not TOFU.
dnsmesh identity fetch bob --add

dnsmesh recv
```

You should see:

```
from ef44bf…
  ts=1776721594
  hello alice
```

{: .tip }
Running `dnsmesh recv` a second time in the same config home doesn't
re-deliver the same message — the replay cache persists to
`$DMP_CONFIG_HOME/replay_cache.json`.

## What just happened

1. Alice encrypted "hello alice" with a recipient prekey → ECDH shared
   secret → ChaCha20-Poly1305 ciphertext.
2. The ciphertext got cross-chunk erasure-coded and published as TXT
   records under the mesh domain.
3. A signed manifest naming alice's Ed25519 key + the prekey_id + total
   chunks went into one of bob's 10 mailbox slots.
4. Bob's `dnsmesh recv` polled the slots, verified alice's signature (pinned
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
dnsmesh cluster pin 3c6a...the32byteoperatorpubkeyinhex mesh.example.com

# Sanity-check that the signed manifest is published and verifiable.
dnsmesh cluster fetch
# cluster: mesh.example.com
#   seq:   7
#   exp:   1816000000
#   nodes: 3
#     n01  http=https://n1.mesh.example.com:8053  dns=203.0.113.10:53
#     ...

# From here on every `dnsmesh send` / `dnsmesh recv` / `dnsmesh identity publish`
# fans writes across ceil(N/2) nodes and unions reads across all N.
# Manifests refresh in the background on `cluster_refresh_interval`
# (default 3600 seconds).
```

When either `cluster_operator_spk` or `cluster_base_domain` is unset
the CLI falls back to the legacy single-endpoint mode, so existing
configs keep working unchanged. See
[User Guide → CLI reference → `dnsmesh cluster`]({{ site.baseurl }}/guide/cli)
for the full subcommand list.

## Next

- [User Guide → CLI reference]({{ site.baseurl }}/guide/cli)
- [User Guide → Identity and contacts]({{ site.baseurl }}/guide/identity)
- [Deployment → Docker]({{ site.baseurl }}/deployment/docker)
