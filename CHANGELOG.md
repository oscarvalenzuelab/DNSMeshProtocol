# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] — M8 cross-zone receive + first-message claim layer

### Fixed

- **Cross-zone receive bug.** The original DMP spec puts a sender's
  records under the sender's zone (Alice publishes to
  `slot-N.mb-{hash(bob)}.{alice-zone}`); recipient pulls from the same
  name via the recursive DNS chain. The receive path was hard-bound
  to the recipient's `self.domain`, silently restricting end-to-end
  delivery to same-mesh pairs (or same-cluster federated peers). M8.1
  walks each pinned contact's zone in addition to the local one, and
  hard-binds chunk fetches to the manifest's source zone (manifest-
  zone integrity — the load-bearing security property).

### Added

- **First-contact reach via signed claims.** Senders publish a tiny
  signed pointer (`v=dmp1;t=claim;...`) to one or more claim-provider
  nodes; recipients poll the providers via DNS and find pointers
  addressed to them by `hash12(recipient_id)`. The actual
  manifest+chunks stay in the sender's zone — claims are pointers,
  not ciphertext — so a malicious provider can drop or reorder but
  cannot forge or read. Anti-entropy gossip on the claim namespace
  (M8.4, hooked into the existing `/v1/sync/digest` + `/v1/sync/pull`
  machinery) closes drop-by-single-provider.

- **Claim-provider role.** Every DMP node with heartbeat enabled
  AND a `DMP_DOMAIN` configured automatically advertises
  `CAP_CLAIM_PROVIDER` (bit 0 of the new `capabilities` field in
  `HeartbeatRecord`, magic bumped `DMPHB01` → `DMPHB02`) and accepts
  `POST /v1/claim/publish`. Operators who don't want to host claims
  for arbitrary recipients opt out with `DMP_CLAIM_PROVIDER=0`. The
  served zone defaults to `DMP_CLAIM_PROVIDER_ZONE`, then
  `DMP_CLUSTER_BASE_DOMAIN`, then `DMP_DOMAIN`.

- **Provider discovery via SeenStore recency.** "Proximity" =
  recency-weighted gossip-reachability. Sender + recipient gossip
  through the same heartbeat fabric, so their SeenStore views
  overlap heavily and they pick the same providers most of the
  time. A built-in seed list (`https://dnsmesh.io`) is appended to
  every client's provider set so an empty / sparse seen-graph
  still has guaranteed cross-deployment overlap.

- **Pin-fence bypass with quarantine.** Claim-discovered messages
  from unknown senders no longer fall on the floor at the receive
  pin fence — they land in a sqlite-backed pending-intro queue
  (0600-permission DB) for user review. CLI surface:

  ```
  dnsmesh intro list
  dnsmesh intro accept <id>     # deliver this one, do NOT pin
  dnsmesh intro trust  <id>     # deliver + pin sender + (optionally)
                                #   record their remote username
  dnsmesh intro block  <id>     # drop + add sender_spk to denylist
  ```

  Intro commands are local-only — they do not touch DNS and work
  on a host with no network.

- **`GET /v1/info` discovery endpoint.** Returns each node's
  endpoint, operator pubkey, served claim zone, and capabilities
  bitfield. The CLI consults it during provider selection so a
  node that serves claims under a zone different from its HTTP
  host is still reachable.

### Changed

- **`HeartbeatRecord` wire format**: new uint16 `capabilities`
  bitfield, magic bumped to `DMPHB02`. Pre-0.4.0 nodes can't parse
  v02 records and vice versa — this is acceptable for the alpha
  (no production deployments rely on v01).

- **`identity fetch <user>@<zone> --add`** now upgrades a
  spk-only placeholder created by `intro trust` (matches by spk
  + empty pub regardless of label) instead of refusing to overwrite.

- **`send_message`** publishes claims to all configured providers
  whenever `claim_providers` is non-empty (no same-zone
  optimization). Reports per-provider success/failure via the
  optional `claim_outcomes` out-parameter; the CLI surfaces
  partial-failure as a `WARNING` on stderr.

- **Native-Ubuntu upgrade path** (`deploy/native-ubuntu/upgrade.sh`
  and the equivalent DigitalOcean flow) automatically backfills a
  commented `DMP_CLAIM_PROVIDER` hint in the existing `node.env`
  so operators see the new option without silent-behavior-change
  surprise.

## [0.3.7] — `identity fetch` shows the full address

### Changed

- **`dnsmesh identity fetch` now prints the full `<user>@<host>`
  address** along with the bare username. Without the host part, two
  different `alkamod`s on different nodes look identical in the
  output. The host comes from the @-form input, the `--domain` flag,
  or the local config's effective domain — whichever the lookup
  actually used. The `--json` payload gains a sibling `address` field
  alongside `username` so scripts can branch on either.

## [0.3.6] — `@-style fetch` falls back from zone-anchored to TOFU

### Fixed

- **`dnsmesh identity fetch alice@example.com`** used to query
  `dmp.example.com` only. If the publisher used the TOFU layout
  (record at `id-<hash16(alice)>.example.com`), the fetch returned
  "no identity record at dmp.example.com" with no fallback. Users on
  the same node who picked TOFU mode were unreachable through the
  @-style address — the bare-username form (`fetch alice`) still
  worked but only for the local user's own contacts list.
- New behavior: try zone-anchored first (squat-resistant), then fall
  back to the TOFU hash name on miss. Error message now names both
  candidates so operators can see which layouts were probed. Bare-
  username form is unchanged.

## [0.3.5] — `dnsmesh init` defaults dns_resolvers to 1.1.1.1 + 8.8.8.8

### Changed

- **`dnsmesh init` now writes `dns_resolvers: [1.1.1.1, 8.8.8.8]`** to
  the generated config by default. Previously it left the list empty
  and the CLI fell back to the system resolver, which often has stale
  negative caches (e.g. NXDOMAIN cached from before a delegation
  existed). Cloudflare first because their stated privacy posture is
  tighter than Google's; Google second for failover.
- New `--no-default-resolvers` flag on `dnsmesh init` to opt out —
  use it if you want every DMP query to go through your local /
  corporate / privacy resolver instead of public DNS.
- Existing configs are untouched. The default only kicks in for
  fresh `init` runs.

## [0.3.4] — upgrade scripts backfill DMP_HEARTBEAT_SEEDS

### Added

- **Upgrade scripts now backfill `DMP_HEARTBEAT_SEEDS`** into existing
  env files when missing. `deploy/native-ubuntu/upgrade.sh` and
  `deploy/digitalocean/upgrade.sh` both check for the line before
  appending; idempotent across re-runs. Closes the gap where a
  pre-0.3.3 deploy (whose env file was generated before the seed
  line existed in the install scripts) couldn't bootstrap into the
  federation without manual edits. Existing values are left alone —
  the backfill only kicks in when the line is absent entirely.

## [0.3.3] — self in peers table + DMP_HEARTBEAT_SEEDS bootstrap

### Fixed

- **Solo nodes showed an empty Recent peers table.** The heartbeat
  worker posts its own signed wire to peers but never ingests it
  into its own SeenStore, so a node with no `DMP_HEARTBEAT_SEEDS`
  configured had nothing in `/v1/nodes/seen` even though it
  obviously knows about itself. The render path (used by both
  `GET /` and `GET /nodes`) now synthesizes a self row at request
  time, deduped against any peer-gossiped self entry by
  `(operator_spk, endpoint)` keeping the highest ts. Result: the
  table is never artificially empty when heartbeat is on.

### Added

- **Bootstrap seeds in install scripts.** Both
  `deploy/native-ubuntu/install.sh` and
  `deploy/digitalocean/quickstart.sh` now write
  `DMP_HEARTBEAT_SEEDS=https://dnsmesh.io` to the generated env
  file by default. Federated discovery works on first heartbeat
  tick without operators having to read the heartbeat-deployment
  doc. The heartbeat-enable env vars are written commented-out
  with a clear how-to-enable block.

## [0.3.2] — registration block on the landing page

### Added

- **Landing page now shows the node's registration policy.** The
  `/` page renders one of four blocks depending on the auth_mode +
  registration env vars:
  - `multi-tenant` + `DMP_REGISTRATION_ENABLED=1`: copy-pasteable
    `dnsmesh init` + `dnsmesh register` snippet, plus the operator
    allowlist if any.
  - `multi-tenant` without registration: explains tokens are
    operator-issued and points at the operator.
  - `legacy`: explains a single operator bearer token gates all
    writes.
  - `open` (default): warns that the node accepts unauthenticated
    writes and links the multi-tenant deployment guide.
  Lets visitors landing at the node know whether they can self-onboard
  or have to ask the operator without having to read the source.

## [0.3.1] — HEAD-method support + seed dnsmesh.io

### Fixed

- **`HEAD /` returned 501** instead of the expected 200. Python's
  `BaseHTTPRequestHandler` 501s on any HTTP method without a
  matching `do_<METHOD>` handler. We had `do_GET`, `do_POST`,
  `do_DELETE` but not `do_HEAD`, so monitors, link-checkers, and
  `curl -I` all saw "Not Implemented". The new `do_HEAD` reuses
  the GET dispatcher; clients close the connection after reading
  status + headers, and the unread body is harmless. Fixes
  uptime monitoring and CDN preflight against any 0.3.x node.

### Changed

- **`directory/seeds.txt`** now lists `https://dnsmesh.io`. Next
  scheduled aggregator run picks it up and the canonical directory
  at `/DNSMeshProtocol/directory/` will list it.

## [0.3.0] — discovery surface, native install path, typo tripwire

Additive release on top of 0.2.0. No breaking changes for clients;
existing 0.2.0 configs upgrade in place. The biggest visible thing
is that hitting `https://<node>/` in a browser now shows a status
page instead of a 404, and the node can render its known peers as
HTML at `/nodes` once the operator opts into the heartbeat layer.

### Added

- **`GET /` landing page** on every node. Shows hostname, operator
  pubkey, record count, and either the recent-peers table (when
  heartbeat is on) or a hint about how to enable discovery (when
  off). Links out to `/health`, `/stats`, the project docs, and
  PyPI client. Cached 30s.
- **`GET /nodes`** human-readable HTML view of `/v1/nodes/seen`.
  Same data, rendered for browsers — operators can point a
  teammate at the URL without explaining JSON. 404 when heartbeat
  is disabled.
- **`dnsmesh peers <endpoint>`** new CLI subcommand. Hits
  `/v1/nodes/seen` on any node and prints a human-readable peer
  table (`--json` for raw output, `--timeout` for the HTTP
  budget).
- **Discovery startup logs.** After "DMP node up", the server
  emits explicit log lines saying whether heartbeat is enabled
  and where the JSON + HTML peer-list URLs live; when disabled,
  names the env vars to set to be discoverable.
- **Typo tripwire on the passphrase derivation.** `CLIConfig`
  gains a `verify_pubkey` field, populated on first successful
  derive. Subsequent derives compare against it and abort with
  a clear diagnostic on mismatch instead of silently producing
  a different identity. `DMP_PASSPHRASE_OVERRIDE_VERIFY=1` for
  the one-shot bypass; `dnsmesh identity rotate` updates the
  tripwire automatically.
- **`deploy/native-ubuntu/`** install path. Bare-metal install for
  operators who don't want a Docker daemon (~50 MB idle vs
  ~150 MB with Docker). Runs as a systemd unit under a `dnsmesh`
  user with `CAP_NET_BIND_SERVICE` plus the standard sandboxing
  directives (`NoNewPrivileges`, `ProtectSystem=strict`,
  `MemoryDenyWriteExecute`, etc.), Caddy fronts auto-TLS.
- **`deploy/digitalocean/quickstart.sh`** Docker-based one-shot
  for a single Droplet (any UDP-capable VPS).
- **`deploy/native-ubuntu/upgrade.sh`** + **`deploy/digitalocean/upgrade.sh`**
  for in-place upgrades. Both leave operator config + state
  untouched.
- **Canonical directory feed** at
  `https://ovalenzuela.com/DNSMeshProtocol/directory/`. Cron-driven
  workflow runs `examples/directory_aggregator.py` against
  `directory/seeds.txt` every 30 minutes; only commits when the
  rendered output changes (filtering out the cosmetic timestamp).
  Federated by design — anyone can run their own aggregator off
  any subset of seeds.

### Changed

- **Documentation:** `getting-started.md` now explains how to set
  the passphrase (env var, file, interactive prompt) and what the
  typo tripwire does. `guide/cli.md` got an expanded
  `Config and passphrase` section. README links cleaned up so the
  PyPI rendering doesn't 404 on repo-relative paths and protocol
  links go through the canonical custom domain. Em dashes in
  README replaced with periods/commas/colons per project style.
- **Daemon hardening.** `docker-compose.cluster.yml` was the only
  compose file missing `restart: unless-stopped`; added on all three
  cluster nodes. `deploy/native-ubuntu/dnsmesh-node.service` got
  explicit `KillSignal=SIGTERM`, `TimeoutStopSec=30s`,
  `LogRateLimitIntervalSec=0` for predictable lifecycle behavior.
- **Docker Hub repo page** auto-syncs from
  `deploy/docker/README.md` on every push to main via
  `peter-evans/dockerhub-description@v4`. Includes back-links to
  the GitHub project, PyPI client, and docs site (the page used
  to be empty).

### Fixed

- **Stale Docker Hub namespace** in 5 docs (`oscarvalenzuelab` →
  `ovalenzuela`). Anyone copy-pasting `docker pull
  oscarvalenzuelab/dnsmesh-node` was hitting a 404.
- **`Caddyfile`** still proxied to `dmp-node:8053` after the
  v0.2.0 image rename to `dnsmesh-node` — would have 502'd in
  production. Caught by codex review and fixed.
- **Directory aggregator's "skip cosmetic-only refresh" filter**
  used `grep -v` (basic-regex) on a pattern with `{3}`, where the
  quantifier is taken literally. Result: every cron tick committed
  an empty refresh because the file-header lines (---/+++) tripped
  the "real changes?" check. Fixed with `grep -vE`.
- **Bot identity in the directory workflow** used
  `noreply@anthropic.com`, which GitHub mapped to a real account.
  Switched to the canonical `github-actions[bot]` identity
  (UID 41898282).

### Changed — CLI rename (breaking for source installs)

- **CLI command renamed** from `dmp` to `dnsmesh`. The distribution on
  PyPI is `dnsmesh` (the `dmp` slug is squatted), so for brand
  consistency the binary and the admin CLI follow suit: `dmp` →
  `dnsmesh`, `dmp-node-admin` → `dnsmesh-node-admin`.
- **Docker image renamed** from `dmp-node` to `dnsmesh-node` (Docker
  Hub repo, Dockerfile label, all compose samples, cluster peer env
  files). The `python -m dmp.server` entrypoint and the `/var/lib/dmp`
  volume are unchanged, so in-container behavior is identical.
- **Migration:** `pip uninstall dmp` (if you had an editable install
  under the old name), then `pip install -e .` again. The shell
  commands become `dnsmesh ...` / `dnsmesh-node-admin ...`. For
  Docker, pull `<user>/dnsmesh-node:latest` instead of
  `<user>/dmp-node:latest` and update your compose file's
  `image:` / `container_name:` / volume name.

### Unchanged (deliberately)

- **Python import path** stays `import dmp` — same split as
  pyyaml → yaml. Scripts using the library do not need to change.
- **Wire protocol** (`v=dmp1;...`), **DNS subdomain conventions**
  (`dmp.<user>.<host>`, `_dmp-cluster.<name>`, `rotate.dmp.<host>`),
  **`DMP_*` environment variables**, **`~/.dmp/config.yaml` path**,
  **`dmp_*` Prometheus metric names**, and the in-container **`dmp`
  Unix user** are untouched. Existing operator configs and signed
  records keep working.

### Added (M5.5 — multi-tenant node auth) — SHIPPED (merge `01318569`)

- `DMP_AUTH_MODE=open|legacy|multi-tenant` env switch. Back-compat:
  unset derives to `open` / `legacy` from whether a token is
  configured — pre-M5.5 deploys need no config change.
- `DMP_OPERATOR_TOKEN` is the preferred name for the operator bearer;
  `DMP_HTTP_TOKEN` kept as a no-op alias.
- Per-user publish tokens in `multi-tenant` mode. `TokenStore`
  (sqlite) holds `sha256(token)` only — token material never
  persisted. Scope-enforced on every `/v1/records/*` write:
  owner-exclusive for identity / rotation / prekey names (`dmp.<user>.<domain>`,
  `rotate.dmp.<user>.<domain>`, `pk-*.<hash12>.<domain>`), shared-
  pool for mailbox slots + chunks (any live token), operator-only
  for cluster / bootstrap. Per-token rate limits stack with per-IP.
- **Split-audit policy:** shared-pool writes log only `ts` +
  `remote_addr` — no `subject`, no `token_hash`. An operator
  handed the DB cannot reconstruct which user delivered to whom.
- **Self-service registration.** `GET /v1/registration/challenge` +
  `POST /v1/registration/confirm`. Ed25519-signed challenge bound
  to the node's hostname. Gated by
  `DMP_REGISTRATION_ENABLED=1`, per-IP rate limit (5/hour default),
  optional `DMP_REGISTRATION_ALLOWLIST`. Anti-takeover: a live
  self-service token locks the subject to its `registered_spk`.
  Signature verified BEFORE policy to prevent 403/409 oracle.
  Atomic revoke-then-issue on rotation.
- **Full Ed25519 low-order pubkey block** on registration — closes
  the identity-point forgery (`A=01 00..00`, `sig = A || 0^32`
  verifies every message under permissive RFC 8032 verify).
- New CLI: `dnsmesh register --node <hostname> [--subject ...]`,
  `dnsmesh token list/forget`. Auto-attach from `~/.dmp/tokens/<host>.json`
  (mode 0600 via `os.open(O_EXCL, 0o600)`).
- New operator CLI: `dnsmesh-node-admin token issue/list/revoke/rotate`
  + `audit tail`.
- 104 new tests (token store, admin CLI, HTTP multi-tenant,
  registration, client token store, low-order-point regression).
  Total suite 1053 across 3 Python versions.
- Docs: `docs/guide/registration.md`, `docs/deployment/multi-tenant.md`,
  `docs/design/multi-tenant-auth.md`, How It Works trust-model rewrite.

### Added (M5.4 — key rotation + revocation) — SHIPPED (merge `fdd455f`)

- `RotationRecord` (`v=dmp1;t=rotation;`) and `RevocationRecord`
  (`v=dmp1;t=revocation;`) wire types in `dmp.core.rotation`.
  Co-signed by old and new key (rotation) / self-signed by revoked
  key (revocation). Subject types: user_identity (1),
  cluster_operator (2, reserved), bootstrap_signer (3, reserved).
- `dnsmesh identity rotate --experimental` CLI: publishes RotationRecord
  + fresh IdentityRecord. `--reason compromise|lost_key` also
  publishes a RevocationRecord; `--reason routine` (default) doesn't.
  `--yes` does an atomic on-disk swap (`kdf_salt` preserved; only
  the passphrase source rotates).
- `dmp.client.rotation_chain.RotationChain.resolve_current_spk` —
  chain-walker with max_hops=4, ambiguous-fork detection, seq
  monotonicity, revocation cross-check. Returns `None` to signal
  "don't trust any path from this key" (revocation or malformed).
- `DMPClient(rotation_chain_enabled=True)` opt-in: when a pinned
  `sender_spk` fails manifest verification, walk forward; also
  reject incoming manifests whose sender_spk matches a revoked
  key on the current RRset.
- Wire format is DRAFT — flagged in docstrings + spec registry;
  v0.3.0 may introduce a breaking `v=dmp2;t=rotation;` post-audit.
- Golden test vectors at `docs/protocol/vectors/rotation_record.json`.
- Fuzz harness: `tests/fuzz/test_fuzz_{rotation,revocation}_record.py`.
- Docker e2e coverage: `tests/test_docker_integration.py::test_container_rotation_*`.
- SDK demos: `examples/docker_e2e_demo.py` (single-node) and
  `examples/cluster_e2e_demo.py` (3-node federated).
- Docs: `docs/protocol/rotation.md`.

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
- `dnsmesh resolvers discover [--save] [--timeout S]` CLI subcommand: runs
  `ResolverPool.discover(WELL_KNOWN_RESOLVERS)` and prints the working
  list. With `--save`, writes the result to config as `dns_resolvers`
  (creating the field if absent, so the command works even before
  M1.2's `--dns-resolvers` init flag lands).
- `dnsmesh resolvers list`: prints the currently configured `dns_resolvers`.
- `CLIConfig.dns_resolvers`: optional list field on the config, default
  empty. Written by `dnsmesh resolvers discover --save`; will be consumed
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
- `dnsmesh identity publish` — pushes the current identity record to the
  node's store. Default TTL is 86400 s; override with `--ttl`.
- `dnsmesh identity fetch <username>` — resolves, verifies, and displays a
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
  replaced with honest "pinned-or-TOFU" language. `dnsmesh contacts add`
  without `--signing-key` now prints a multi-line stderr warning
  making the TOFU fallback explicit.
- Default rate limits raised: HTTP 10/s burst 100 (was 5/s burst 20).
  `dnsmesh identity refresh-prekeys --count` default lowered from 50 to
  25 so a full pool fits in a single burst window.

### Added (zone-anchored identity)

- `CLIConfig.identity_domain` + `dnsmesh init --identity-domain <zone>`:
  users who own a DNS zone can anchor identity there. `dnsmesh identity
  publish` writes `dmp.<identity_domain>` instead of the hash-based
  shared-mesh name, and resolvers see a stable well-known name.
- Address parsing: `dnsmesh identity fetch alice@alice.example.com`
  resolves `dmp.alice.example.com` and verifies the record's internal
  `username` matches the address's left half — so the zone owner
  can't publish a record for a different name and have it stored as
  that name in fetchers' contact lists.
- `dmp.core.identity.zone_anchored_identity_name` and
  `dmp.core.identity.parse_address` encode the convention; new tests
  in `test_identity.py` and `test_cli.py` exercise the publish/fetch
  round-trip and the username-mismatch rejection.
- Plain-username `dnsmesh identity fetch alice` still uses the legacy
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
- CLI: `dnsmesh identity refresh-prekeys [--count 50] [--ttl 86400]`.
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

- `dmp.cli` — `dnsmesh` command: `init`, `identity show`, `contacts add/list`,
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
  so `dnsmesh recv` doesn't re-deliver already-seen messages across calls.
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
  generates a 32-byte random salt at `dnsmesh init` and stores it in the
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
