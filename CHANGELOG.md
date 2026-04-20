# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (ops hardening)

- Deep `/health`: probes the store (`query_txt_record` on a sentinel name).
  Returns 503 `{"status": "degraded"}` if the store raises. Kubernetes and
  DigitalOcean liveness probes now see actual health, not just "process alive."
- `/metrics` endpoint exposing Prometheus text format:
  `dmp_http_requests_total{method,status}`, `dmp_dns_queries_total{outcome}`,
  and a lazy `dmp_records` gauge backed by `SqliteMailboxStore.record_count()`.
- Per-source-IP token-bucket rate limiting on both the HTTP API and UDP DNS
  server. Opt-in via `DMP_HTTP_RATE`/`DMP_HTTP_BURST` and
  `DMP_DNS_RATE`/`DMP_DNS_BURST`. LRU-eviction at 10k keys bounds memory
  under distributed scans.
- `DMP_LOG_FORMAT=json` emits one-JSON-object-per-line logs with extras
  surfaced as top-level keys. Default stays human-readable.

### Added

- `dmp.cli` — `dmp` command: `init`, `identity show`, `contacts add/list`,
  `send`, `recv`, `node`. Config in `~/.dmp/config.yaml`; passphrase via
  `DMP_PASSPHRASE` env var or `passphrase_file`. Never stored in config.
- `dmp.storage.SqliteMailboxStore` — persistent TTL-aware `DNSRecordStore`.
  WAL journaling, survives process restart, `cleanup_expired()` for the
  background reaper.
- `dmp.server.DMPDnsServer` — minimal UDP DNS server answering TXT queries
  from any `DNSRecordReader`. Splits values > 255 bytes into multi-string
  TXT records.
- `dmp.server.DMPHttpApi` — REST API (`POST/DELETE/GET /v1/records/{name}`
  plus `/health`, `/stats`) for clients without direct authoritative DNS
  access. Optional bearer-token auth with constant-time compare.
- `dmp.server.CleanupWorker` — background TTL reaper that tolerates
  callable exceptions without killing the thread.
- `dmp.server.DMPNode` + `dmp.server.__main__` — orchestrator that wires
  storage, DNS, HTTP, and cleanup into one process. Entry: `python -m dmp.server`.
- `dmp.network.base` — `DNSRecordWriter`, `DNSRecordReader`, `DNSRecordStore`
  ABCs; splits read and write roles that earlier conflated.
- `dmp.network.memory.InMemoryDNSStore` — single-process mock for tests
  and demos.
- `dmp.core.manifest.SlotManifest` — binary 164-byte slot manifest,
  Ed25519-signed. Compact enough for one DNS TXT string.
- `dmp.core.manifest.ReplayCache` — `(sender_spk, msg_id)` dedupe with
  split `has_seen` / `record` API so transient fetch failures don't
  permanently blacklist a valid manifest. Optionally persists to disk
  via `persist_path`: writes are atomic (tmp + rename), expired entries
  drop on load, and corrupt files are ignored (start from empty state).
  The CLI wires this to `$DMP_CONFIG_HOME/replay_cache.json` by default
  so `dmp recv` doesn't re-deliver already-seen messages across calls.
- Dockerfile (multi-stage, non-root runtime user, healthcheck) and
  `docker-compose.yml`.
- GitHub Actions CI: pytest matrix over 3.10/3.11/3.12, `black --check`,
  `mypy`, and a separate job that builds the container and runs the
  docker integration tests.
- Ed25519 signing alongside X25519 encryption: `DMPCrypto.signing_key` +
  `signing_public_key`, deterministically derived from the X25519 private
  bytes via domain-separated SHA-256.
- `MessageEncryption.encrypt_with_header` / `decrypt_with_header` bind
  the full canonical `DMPHeader` bytes as AEAD AAD.

### Security

- Switched passphrase → X25519 seed from PBKDF2-HMAC-SHA256 (100k iters,
  fixed salt) to Argon2id (memory-hard, 32 MiB, t=2, p=2). The CLI now
  generates a 32-byte random salt at `dmp init` and stores it in the
  config file; two users who pick the same passphrase get independent
  keys, and an offline attacker has to repeat the memory-hard
  derivation per guess. The library API falls back to a fixed sentinel
  salt when none is passed — documented in SECURITY.md as weaker and
  intended only for demos/tests.

- Mailbox slots now use DNS-native append (RRset) semantics. Previously
  the node's stores (SqliteMailboxStore and InMemoryDNSStore) replaced
  the value at a name on every `publish_txt_record`; this let anyone
  who could reach the publish endpoint wipe other senders' manifests
  out of a recipient's slot. With append, an attacker can add entries
  but cannot evict legitimate ones — signature verification still
  filters their junk on the recipient side. Regression test
  `test_slot_squatting_attacker_cannot_evict_real_messages`.

### Changed

- `MessageChunker` switched from whole-message Reed-Solomon to **per-chunk**
  RS. Lost chunks still fail (no cross-chunk erasure) but each received
  chunk is independently self-validating and bit-error-recoverable.
- `DATA_PER_CHUNK` reduced from 200 to 128 so the full TXT record fits
  in one 255-byte DNS string.
- Chunk TXT records no longer carry a JSON metadata field — `chunk_num`
  and `msg_key` are already in the domain name.
- All `DNSRecordWriter` backends now accept fully-qualified names and
  share a unified `delete_txt_record(name, value=None)` signature.
- `DMPClient.__init__` now takes `store=`, `writer=`, or `reader=` params.
  Default is `InMemoryDNSStore` for tests.
- `DMPClient` `send_message` picks the first empty mailbox slot rather
  than a uniformly-random one, avoiding the 10% collision rate on
  back-to-back sends.

### Fixed

- `DMPCrypto.verify_signature` was a stub returning `True` for any 32-byte
  blob. Replaced with real Ed25519 verification.
- `MessageChunker._remove_error_correction` called `rstrip(b'\x00')` after
  RS decode, silently corrupting any valid payload ending in null bytes.
  Eliminated with the per-chunk RS refactor.
- `MessageAssembler._assemble_message` used `chunks[i]` over unvalidated
  indexes. Now requires a contiguous `set(range(total_chunks))` before
  assembly.
- RS decode failures used to silently return partial raw data. Now fail
  the chunk cleanly so callers don't deserialize garbage.
- `DMPClient.send_message` derived `recipient_id` by treating the
  recipient's X25519 **public** key as a **private** key. Now directly
  hashes the pubkey bytes.
- Slot manifest wire format (earlier JSON + separate signature) exceeded
  the 255-byte DNS TXT limit. Replaced with 164-byte binary format.
- Replay cache was recorded **before** fetching chunks. A transient DNS
  miss would permanently blacklist a valid manifest; now the cache is
  only written after a successful decrypt.
- `setup.py` had the wrong GitHub URL and `requirements.txt` was missing
  `requests` and `boto3` (both imported by `dmp.network.dns_publisher`).

### Security

- None of the hardening here has been reviewed by a third party.
  See [SECURITY.md](SECURITY.md) for known limits.

## [0.1.0] — 2025-08-15

- Initial scaffolding and unreviewed first pass. Predates this changelog.
  Treat anything tagged 0.1.0 as archival — do not use.
