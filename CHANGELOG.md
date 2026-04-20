# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (M1 — resolver resilience, partial)

- `ResolverPool.discover(candidates, timeout=2.0)` classmethod: probes
  each candidate with a cheap TXT query (defaults to `google.com`) and
  returns a new `ResolverPool` containing only the candidates that
  answered within `timeout`. Non-literal entries (hostnames, typos) are
  skipped with a logged warning instead of aborting the whole batch.
  Raises `ValueError` if zero candidates pass — empty pools are
  deliberately prohibited because every future query would silently
  fail, and callers are better served by a clear failure at the
  discovery boundary. Addresses ROADMAP milestone M1.3.
- `dmp.network.WELL_KNOWN_RESOLVERS`: module-level tuple of eight IPv4
  public resolvers across four operators (Google, Cloudflare, Quad9,
  OpenDNS). Operator diversity is the point — a single provider outage
  or blocklist doesn't take the pool down.
- `dmp resolvers discover [--save] [--timeout S]` CLI subcommand: runs
  `ResolverPool.discover(WELL_KNOWN_RESOLVERS)` and prints the working
  list. With `--save`, writes the result to config as `dns_resolvers`
  (creating the field if absent, so the command works even before
  M1.2's `--dns-resolvers` init flag lands).
- `dmp resolvers list`: prints the currently configured `dns_resolvers`.
- `CLIConfig.dns_resolvers`: optional list field on the config, default
  empty. Written by `dmp resolvers discover --save`; will be consumed
  by M1.2's multi-resolver `_make_client` wiring when that lands.
- `dmp.network.resolver_pool.ResolverPool`: a `DNSRecordReader` that wraps
  multiple upstream resolvers (IP literals only) with per-host health
  tracking and priority-ordered failover. Addresses ROADMAP milestone
  M1.1. Semantics refined through six Codex review rounds:
  - NXDOMAIN and NoAnswer on their own don't demote a resolver (they're
    legitimate answers, not health failures).
  - But when a later resolver returns a valid TXT for the same query,
    every earlier resolver that claimed NXDOMAIN is retroactively
    demoted — oracle-based demotion proves the earlier ones wrong.
  - When every resolver returns NXDOMAIN (no oracle fires), the streak
    counter resets for each — a genuine not-found is itself a healthy
    response and shouldn't compose with a later unrelated timeout into
    a spurious "consecutive" demotion.
  - Cooldown is a priority signal, not a ban: demoted resolvers still
    get queried in a fallback tier if the preferred tier is exhausted,
    so transient failures across all upstreams don't blackhole lookups.
  - Only specific network/transport exceptions (NoNameservers, Timeout,
    socket.timeout, OSError) count as health failures. Caller-side
    errors (malformed names) propagate.
  - 36 tests covering construction validation (IPv4/IPv6 literal parsing,
    rejection of hostnames), each failure mode, oracle demotion with 1
    and N demoted peers, cooldown semantics, promotion after recovery,
    and multi-threshold streak behavior.


### Added (onboarding + TLS)

- `dmp.core.identity.IdentityRecord`: signed, binary-encoded DMP identity
  record with `username`, `x25519_pk`, `ed25519_spk`, and `ts`. Signed
  by the identity's Ed25519 key; fits a single 255-byte DNS TXT string.
  Published at `id-{sha256(username)[:16]}.{domain}` so DNS labels
  don't expose the plaintext username.
- `dmp identity publish` — pushes the current identity record to the
  node's store. Default TTL is 86400 s; override with `--ttl`.
- `dmp identity fetch <username>` — resolves, verifies, and displays a
  remote identity record. `--add` saves it as a local contact after
  signature verification. `--domain` overrides the mesh domain. `--json`
  machine-readable output.
- `Caddyfile` + `docker-compose.prod.yml` — overlay that fronts the node
  with Caddy, automatic Let's Encrypt, and HTTP/3. Drops the raw 8053
  host port; Caddy handles TLS termination on 443. Activate with
  `DMP_NODE_HOSTNAME=... docker compose -f docker-compose.yml -f
  docker-compose.prod.yml up -d`.

### Changed (second-pass audit fixes)

Codex ran a second audit before beta and flagged two new P1s plus three
smaller issues introduced while fixing the first audit. All now fixed:

- `SlotManifest` enforces `MAX_TOTAL_CHUNKS = 1024` on parse and
  construction. Previously a signature-valid manifest could claim
  `total_chunks = 2^32 - 1` and the receiver's `range(total_chunks)`
  fetch loop would pin the process.
- Prekey consumption now deletes the matching published TXT record
  from the node's store, not just the local sqlite row. Otherwise
  consumed prekeys rotted in DNS and senders kept picking them,
  turning an increasing fraction of messages undecryptable.
  `PrekeyStore` gains a `wire_record` column and `record_wire` /
  `get_wire` helpers; `DMPClient._consume_prekey` does the
  local-sqlite drop + DNS DELETE together.
- `prekey_id` is now bound into the AEAD AAD. A lying sender who
  encrypts with one prekey but writes a different `prekey_id` in
  the manifest is caught at AEAD tag verification, not by a lower-
  level ECDH mismatch.
- Both the HTTP API and UDP DNS server enforce a bounded worker
  semaphore. New connections/packets beyond `http_max_concurrency`
  (default 64) or `dns_max_concurrency` (default 128) are dropped
  rather than spawning unbounded threads. Env vars
  `DMP_HTTP_MAX_CONCURRENCY` and `DMP_DNS_MAX_CONCURRENCY` override.
- README's "sender authentication pinned to contacts" bullet
  replaced with honest "pinned-or-TOFU" language. `dmp contacts add`
  without `--signing-key` now prints a multi-line stderr warning
  making the TOFU fallback explicit.
- Default rate limits raised: HTTP 10/s burst 100 (was 5/s burst 20).
  `dmp identity refresh-prekeys --count` default lowered from 50 to
  25 so a full pool fits in a single burst window.

### Added (zone-anchored identity)

- `CLIConfig.identity_domain` + `dmp init --identity-domain <zone>`:
  users who own a DNS zone can anchor identity there. `dmp identity
  publish` writes `dmp.<identity_domain>` instead of the hash-based
  shared-mesh name, and resolvers see a stable well-known name.
- Address parsing: `dmp identity fetch alice@alice.example.com`
  resolves `dmp.alice.example.com` and verifies the record's internal
  `username` matches the address's left half — so the zone owner
  can't publish a record for a different name and have it stored as
  that name in fetchers' contact lists.
- `dmp.core.identity.zone_anchored_identity_name` and
  `dmp.core.identity.parse_address` encode the convention; new tests
  in `test_identity.py` and `test_cli.py` exercise the publish/fetch
  round-trip and the username-mismatch rejection.
- Plain-username `dmp identity fetch alice` still uses the legacy
  hash-based name under the shared mesh domain for TOFU onboarding.
- SECURITY.md now calls zone-anchored identity out as the
  recommended posture for real deployments; shared-mesh identity
  is documented as TOFU-only.

### Added (forward secrecy)

- `dmp.core.prekeys`: X3DH-style one-time X25519 prekeys. A recipient
  generates a pool of single-use keypairs, stores the private halves
  locally in a sqlite-backed `PrekeyStore`, signs the public halves
  with their Ed25519 identity, and publishes them as a TXT RRset at
  `prekeys.id-<username_hash>.<domain>`. Wire format: 108-byte
  body || 64-byte signature, fits one 255-byte DNS TXT string.
- `DMPClient.refresh_prekeys(count, ttl_seconds)`: generate, sign, and
  publish a fresh pool. Call periodically so senders always find live
  prekeys.
- Sender picks a random verified prekey from the recipient's pool,
  does ECDH against the prekey pubkey instead of the long-term key,
  and records the `prekey_id` in the signed manifest. Falls back to
  the long-term key when the contact isn't pinned or no prekeys are
  reachable (no FS for that message, explicit in the manifest via
  `prekey_id = 0`).
- Recipient looks up the prekey sk in `PrekeyStore` during decrypt
  and calls `PrekeyStore.consume(prekey_id)` after a successful
  decrypt. That delete is the forward-secrecy property — once gone,
  the sk is unrecoverable even with a later long-term-key compromise.
- `SlotManifest` grows a `prekey_id` field. Wire size 168 → 172 bytes.
  Still fits one 255-byte TXT string.
- `DMPCrypto.decrypt_message` and `MessageEncryption.decrypt_with_header`
  accept a `private_key=` override so the receive path can route
  ECDH through a prekey sk instead of the instance's long-term key.
- CLI: `dmp identity refresh-prekeys [--count 50] [--ttl 86400]`.
- Prekey store path wired into the CLI via `_make_client` at
  `$DMP_CONFIG_HOME/prekeys.db`, 0o600 perms. Library callers pass
  `prekey_store_path=` to `DMPClient.__init__`; the default is
  `:memory:` which is fine for tests but drops on process exit.
- Tests (211 → 214 → 214): three end-to-end FS tests —
  `test_prekey_forward_secrecy_roundtrip` proves the prekey_sk is
  gone after decrypt; `test_fallback_to_long_term_when_no_prekeys`
  proves the unpinned contact path; `test_prekey_deleted_before_decrypt_drops_message`
  proves the FS property from the recipient side.

### Added (erasure coding)

- `dmp.core.erasure`: cross-chunk Reed-Solomon erasure coding via zfec.
  Plaintext is length-prefixed, padded to k data blocks, and zfec
  generates n-k parity blocks. Any k of n received blocks reconstruct.
  k is chosen adaptively per message based on size; n-k is ~30% of k
  (minimum one parity block). New regression tests:
  `test_lost_chunks_recover_via_erasure` and
  `test_lost_data_chunks_recover_via_parity` prove chunks can be
  deleted from the store and the message still delivers.
- `SlotManifest` gains a `data_chunks` field (k). Wire size grows from
  164 to 168 bytes; still fits one 255-byte DNS TXT string.
- `MessageChunker.wrap_block` / `unwrap_block`: public per-block
  primitives used by the erasure layer and exposed for callers that
  want explicit control over the per-chunk RS wrapper.
- New dependency: `zfec>=1.5.7`.

### Changed (security defaults)

- HTTP API and UDP DNS rate limits are now **on by default** with
  conservative values: 5 req/s burst 20 for HTTP, 50 q/s burst 200
  for DNS. Override with `DMP_HTTP_RATE`/`_BURST` and
  `DMP_DNS_RATE`/`_BURST`.
- New publish-side caps enforced in `DMPHttpApi`:
  `DMP_MAX_TTL` (default 86400s / 1 day),
  `DMP_MAX_VALUE_BYTES` (default 2048),
  `DMP_MAX_VALUES_PER_NAME` (default 64 — cap on RRset cardinality).
  Requests over the TTL or value cap return 400; requests that
  would grow an RRset past the cap return 413. Re-publishing an
  existing value is still idempotent.

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
  a canonical subset of the `DMPHeader` bytes as AEAD AAD —
  `version`, `message_type`, `message_id`, `sender_id`, `recipient_id`,
  `timestamp`, `ttl`. `total_chunks` and `chunk_number` are zeroed
  before AEAD (they're unknown at encrypt time) and bound separately
  via the signed manifest.

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
