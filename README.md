# DNS Mesh Protocol (DMP)

Decentralized peer-to-peer messaging that tunnels encrypted messages through DNS TXT records. Each message is end-to-end encrypted, signed by the sender's Ed25519 identity, chunked, and published as TXT records on a shared mesh domain. Recipients poll their mailbox slots, verify, reassemble, and decrypt.

> **Status: alpha.** The protocol and API are unstable. Known limits are documented in [SECURITY.md](SECURITY.md). Do not use for anything whose secrecy matters until it's reviewed by someone other than its author.

## What you get

- **End-to-end encryption.** X25519 ECDH + ChaCha20-Poly1305 with ephemeral per-message keys.
- **Real sender authentication.** Every slot manifest is Ed25519-signed; impersonation fails verification.
- **AEAD binds the full header.** `sender_id`, `recipient_id`, `msg_id`, `timestamp`, and `ttl` can't be mutated in transit without flipping decryption.
- **Replay protection.** Per-recipient `(sender_spk, msg_id)` cache rejects re-publications.
- **Per-chunk Reed-Solomon.** Bit errors within a chunk are recoverable; lost chunks still fail (cross-chunk erasure is future work).
- **Pluggable transport.** Any `DNSRecordWriter` / `DNSRecordReader` works — in-memory for tests, sqlite for nodes, Cloudflare/Route53/BIND for production.
- **Self-contained node.** One Python process serves UDP DNS + HTTP submissions from a persistent sqlite store, with a TTL cleanup worker.
- **Docker-first deploy.** `docker compose up` gives you a running node with persistence.

## Quick start (local)

Run a node, publish an identity to DNS, and receive your own message.

```bash
# 1. Build and start the node
docker build -t dmp-node:latest .
docker run -d --name dmp-node \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dmp-data:/var/lib/dmp \
  dmp-node:latest

# 2. Install the CLI
pip install -e .

# 3. Create an identity
export DMP_PASSPHRASE=my-pass
dmp init alice --domain mesh.local \
               --endpoint http://127.0.0.1:8053 \
               --dns-host 127.0.0.1 --dns-port 5353

# 4. Publish your identity record to DNS so others can look you up
dmp identity publish

# 5. Another process (simulating a friend) fetches, adds, and messages you
export DMP_CONFIG_HOME=/tmp/bob-home
export DMP_PASSPHRASE=bob-pass
dmp init bob --domain mesh.local \
             --endpoint http://127.0.0.1:8053 \
             --dns-host 127.0.0.1 --dns-port 5353
dmp identity fetch alice --add          # verifies signature, stores contact
dmp send alice "hello from bob"

# 6. Back in alice's shell
unset DMP_CONFIG_HOME
export DMP_PASSPHRASE=my-pass
dmp recv
```

Production deploys put Caddy in front for TLS:

```bash
export DMP_NODE_HOSTNAME=dmp.example.com   # must have DNS A/AAAA first
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                         DMPClient                          │
│   encrypt → chunk → publish → poll → verify → decrypt      │
└──────────────┬─────────────────────────────────────────────┘
               │ DNSRecordWriter           DNSRecordReader
               ▼                           ▼
     ┌─────────────────┐         ┌──────────────────────┐
     │  HTTP API       │         │   DNS resolver       │
     │  POST /v1/...   │         │   UDP query → TXT    │
     └────────┬────────┘         └──────────────────────┘
              ▼                           ▲
     ┌────────────────────────────────────┴───────────────┐
     │                    DMPNode                         │
     │   HTTP ──► SqliteMailboxStore ◄── DNS server       │
     │                     ▲                              │
     │                     │  CleanupWorker               │
     └────────────────────────────────────────────────────┘
```

The client talks to a node's HTTP API to publish records. Anyone in the world queries those records via DNS. Encryption and signing happen client-side; the node only sees opaque TXT blobs.

## Wire format

### Chunk record (≤255 bytes, single DNS TXT string)

```
chunk-NNNN-<msg_key12>.<mesh_domain>           IN TXT  "v=dmp1;t=chunk;d=<b64 payload>"
```

Each chunk carries 128 bytes of payload + 8-byte SHA-256 prefix checksum + 32 bytes of Reed-Solomon parity. `msg_key = sha256(msg_id + recipient_id + sender_spk)[:12]` so sender and recipient derive the same path without contact bootstrap.

### Slot manifest record (≤255 bytes, binary wire format)

```
slot-<N>.mb-<recipient_hash12>.<mesh_domain>   IN TXT  "v=dmp1;t=manifest;d=<b64 body||ed25519_sig>"
```

Binary body: `msg_id(16) || sender_spk(32) || recipient_id(32) || total_chunks(4) || ts(8) || exp(8)` = 100 bytes. Ed25519 signature covers the body; recipient verifies against the `sender_spk` embedded in the body.

## Running a node

### Docker (recommended)

```bash
docker build -t dmp-node:latest .
docker run -d \
  -p 5353:5353/udp -p 8053:8053/tcp \
  -v dmp-data:/var/lib/dmp \
  -e DMP_HTTP_TOKEN=shared-secret \
  dmp-node:latest
```

For production where you want real DNS port 53, remap with `-p 53:5353/udp` after stopping `systemd-resolved` (or anything else holding port 53) on the host.

### docker-compose

```bash
docker compose up -d
```

### As a Python process

```bash
pip install -e .
python -m dmp.server           # reads config from env vars
# or
dmp node --dns-port 5353 --http-port 8053
```

Environment variables: `DMP_DB_PATH`, `DMP_DNS_{HOST,PORT,TTL}`, `DMP_HTTP_{HOST,PORT,TOKEN}`, `DMP_CLEANUP_INTERVAL`, `DMP_LOG_LEVEL`.

## Using the library

```python
from dmp.client.client import DMPClient
from dmp.network.memory import InMemoryDNSStore

store = InMemoryDNSStore()
alice = DMPClient("alice", "alice-pass", domain="mesh.local", store=store)
bob = DMPClient("bob", "bob-pass", domain="mesh.local", store=store)
alice.add_contact("bob", bob.get_public_key_hex())

alice.send_message("bob", "hello")
for msg in bob.receive_messages():
    print(msg.plaintext.decode())
```

For a real deployment, swap `store=` for `writer=` (HTTP adapter) and `reader=` (DNS adapter). See [`dmp/cli.py`](dmp/cli.py) for working adapters.

## Testing

```bash
pip install -e ".[dev]"
pytest -v                                           # unit + integration, no docker
docker build -t dmp-node:latest . && pytest -v     # full suite including docker
```

## Project layout

```
dmp/
├── core/              Protocol primitives
│   ├── message.py     DMPMessage, DMPHeader
│   ├── crypto.py      X25519 + ChaCha20-Poly1305, Ed25519 signing, AEAD with header AAD
│   ├── chunking.py    Per-chunk Reed-Solomon + checksums
│   ├── dns.py         DNS record encoding helpers
│   └── manifest.py    Signed slot manifests + replay cache
├── network/           Transport abstraction
│   ├── base.py        DNSRecordWriter / DNSRecordReader / DNSRecordStore ABCs
│   ├── memory.py      InMemoryDNSStore
│   └── dns_publisher.py  Cloudflare / Route53 / BIND / dnsmasq backends
├── storage/
│   └── sqlite_store.py   Persistent TTL-aware DNSRecordStore
├── server/
│   ├── dns_server.py  UDP DNS server serving TXT from a store
│   ├── http_api.py    REST publish/query/delete
│   ├── cleanup.py     Background TTL reaper
│   └── node.py        DMPNode orchestrator
├── client/
│   └── client.py      DMPClient: encrypt/chunk/publish/poll/verify/decrypt
└── cli.py             `dmp` command-line interface
```

## License

[AGPL-3.0](LICENSE). If you host this as a service, you must publish your source changes.

## Author

Oscar Valenzuela B · oscar.valenzuela.b@gmail.com
