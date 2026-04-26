---
title: Getting Started
layout: default
nav_order: 3
---

# Getting Started
{: .no_toc }

End-to-end in seven steps: install the CLI, register on a public node,
publish your identity, add a friend, send a message. ~5 minutes.

1. TOC
{:toc}

## What you need

- Python 3.10+ (or use the standalone binary, no Python required)
- A passphrase you'll remember — it's the only thing protecting your keys

You **don't** need to run a node. This guide uses the public reference
node at `dnsmesh.io`. Run your own later if you want to —
see [Deployment]({{ site.baseurl }}/deployment).

## 1. Install the CLI

Pick one:

```bash
# PyPI (recommended)
pip install dnsmesh

# or single-file binary, no Python:
#   https://github.com/oscarvalenzuelab/DNSMeshProtocol/releases
```

Verify:

```bash
dnsmesh --help
```

## 2. Set a passphrase

The passphrase derives your identity keys (Argon2id). The CLI reads
it from `DMP_PASSPHRASE` first, then a file you point at, then an
interactive prompt.

The simplest persistent setup is a passphrase file:

```bash
umask 077
mkdir -p ~/.dmp
openssl rand -base64 32 > ~/.dmp/passphrase
chmod 400 ~/.dmp/passphrase
```

You'll point the config at it in step 3. Back this file up to a
password manager — **losing it loses your identity.**

{: .warning }
Don't `export DMP_PASSPHRASE='hunter2'` directly: that lands in
your shell history. Use `read -rs DMP_PASSPHRASE` if you really
want an env var.

## 3. Create your config

Pick a username. Addresses look like `<username>@dmp.dnsmesh.io`.

```bash
dnsmesh init alice \
    --domain dmp.dnsmesh.io \
    --endpoint https://dnsmesh.io
```

Then wire up the passphrase file:

```bash
echo 'passphrase_file: ~/.dmp/passphrase' >> ~/.dmp/config.yaml
```

Sanity-check that the keys derive cleanly:

```bash
dnsmesh identity show
```

That prints your Ed25519 + X25519 public keys. If you see them,
you're set — the first successful derive also writes a typo-tripwire
into the config so a wrong passphrase later fails loudly instead of
producing a silent second identity.

## 4. Register on the node

This is the one HTTPS hop in the entire flow. The node mints a per-user
TSIG key scoped to your identity's DNS owner names. Every record write
after this is RFC 2136 DNS UPDATE under that key — no further HTTPS.

```bash
dnsmesh tsig register --node dnsmesh.io
```

You'll see the minted key name and its scope (which owner names it
can write to). The token is saved to `~/.dmp/tokens/dnsmesh.io.json`.

## 5. Publish your identity

```bash
dnsmesh identity publish
dnsmesh identity refresh-prekeys
```

The first command publishes your identity record so others can resolve
you via DNS. The second pre-positions a pool of one-time prekeys for
forward secrecy — without them, your first inbound message degrades
to long-term-key encryption (still encrypted, just not forward-secret).

You're now reachable as `alice@dmp.dnsmesh.io`.

## 6. Add a friend

To send to someone, the CLI needs their identity record pinned. Get
it via DNS and add as a contact in one step:

```bash
dnsmesh identity fetch bob@dmp.dnsmesh.io --add
```

The `--add` flag pins their signing pubkey. Future messages from
unknown signers are rejected unless explicitly accepted via
[`dnsmesh intro`]({{ site.baseurl }}/guide/identity#intros).

## 7. Send and receive

```bash
# Send
dnsmesh send bob@dmp.dnsmesh.io "hello bob"

# On bob's side:
dnsmesh recv
```

That's the whole loop. Receive shows decrypted messages with the
sender's signing-key prefix and a timestamp.

## Try it with a friend

Two CLIs, two passphrases, two `DMP_CONFIG_HOME` directories — same
flow on one machine. Replace `alice`/`bob` and the passphrase paths:

```bash
# Terminal 1 — alice
export DMP_CONFIG_HOME=/tmp/alice
export DMP_PASSPHRASE="$(cat /path/to/alice-passphrase)"
dnsmesh init alice --domain dmp.dnsmesh.io --endpoint https://dnsmesh.io
dnsmesh tsig register --node dnsmesh.io
dnsmesh identity publish

# Terminal 2 — bob
export DMP_CONFIG_HOME=/tmp/bob
export DMP_PASSPHRASE="$(cat /path/to/bob-passphrase)"
dnsmesh init bob --domain dmp.dnsmesh.io --endpoint https://dnsmesh.io
dnsmesh tsig register --node dnsmesh.io
dnsmesh identity publish
dnsmesh identity fetch alice@dmp.dnsmesh.io --add
dnsmesh send alice@dmp.dnsmesh.io "hi alice"

# Back in terminal 1 — alice
dnsmesh identity fetch bob@dmp.dnsmesh.io --add
dnsmesh recv
```

## Troubleshooting

**`registration rate-limited (429)`** — public nodes cap registrations
per IP. Default budget is generous; hit it only if you're testing in
a tight loop. Wait a minute and retry.

**`subject already held by a different key (409)`** — your username
is taken on this node, OR you registered before from a different
machine and don't have the matching passphrase here. Pick another
username, or restore the passphrase that originally registered.

**`no identity record at id-...`** — the address you're fetching
hasn't published an identity yet, or hasn't published at the zone you
think they have. Verify with: `dig _dnsmesh-heartbeat.<their-zone> TXT`.

**`no claim provider accepted the discovery pointer`** — first-contact
reach needs a claim provider both ends agree on. The default
`dmp.dnsmesh.io` works for users on the public node. Operators of
private deployments can pin one with
`dnsmesh config set claim-provider <url>`.

## Next

- [User Guide → CLI reference]({{ site.baseurl }}/guide/cli) — every
  subcommand and flag, for when you need a specific option
- [User Guide → Identity and contacts]({{ site.baseurl }}/guide/identity) —
  TOFU, key rotation, intros
- [Deployment]({{ site.baseurl }}/deployment) — running your own node
- [Protocol → Wire format]({{ site.baseurl }}/protocol/wire-format) —
  what's actually on the wire
