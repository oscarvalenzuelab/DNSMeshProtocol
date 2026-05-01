# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.6] — 2026-05-01 — DNS 0x20 + free port 53 in installer

Fourth and (genuinely this time) final round of strict-resolver
compatibility fixes. After 0.6.3 (apex A), 0.6.4 (apex SOA + NS),
and 0.6.5 (RFC 2308/8020 negative responses), Google was *still*
NXDOMAINing every name under our zones. Codex CLI caught the actual
root cause on a third diagnostic pass: **DNS 0x20 case
randomization**. We were looking up TXT records with the QNAME
as-received, which broke whenever Google sent a case-randomized
qname (RFC 9018-style cache-poisoning defense, on by default).

Plus an operational follow-on: install.sh and upgrade.sh didn't
disable systemd-resolved, so on stock Ubuntu the DMP DNS server's
TCP/53 listener silently lost the bind to resolved's loopback
listener, and PR #14's RFC 1035 §4.2.2 fallback path was
half-effective on every fresh install.

Wire format, on-disk schema, and CLI surfaces are byte-identical to
0.6.5.

### Fixed

- **Case-insensitive TXT lookup.** RFC 1035 §2.3.3: DNS owner names
  are case-insensitive. Our auth was looking up records using the
  raw QNAME, which broke under DNS 0x20 case randomization (Google
  Public DNS does this by default). The fix normalizes the lookup
  key to lower-case while preserving the original case in the
  response (the 0x20 protocol relies on the auth echoing the query
  name byte-for-byte). Live proof of the bug from production:

      $ dig @<auth-ip> _dnsmesh-heartbeat.dmp.dnsmesh.io TXT
      → NOERROR + the heartbeat
      $ dig @<auth-ip> _DNSMESH-HEARTBEAT.dMp.DnSmEsH.iO TXT
      → NXDOMAIN

  This is what triggered the 9-hour Google NXDOMAIN saga. Google
  was getting the case-randomized NXDOMAIN response, treating it
  as authoritative, caching the apex SOA from 0.6.4/0.6.5, and
  using RFC 8020 NXDOMAIN-cut to synthesize NXDOMAIN for every
  descendant. The auth was doing the right thing for every probe
  that didn't hit Google's case-randomization layer. Diagnosis
  credit: codex CLI. (PR #27.)

- **install.sh / upgrade.sh now disable systemd-resolved.** Ubuntu
  ships resolved enabled by default, binding 127.0.0.53:53/tcp on
  loopback. The DMP DNS server's 0.0.0.0:53/tcp bind collides with
  that loopback listener and fails with EADDRINUSE — the server
  falls back to UDP-only, silently breaking the RFC 1035 §4.2.2
  TCP fallback path strict resolvers (Google, Level3) need for any
  RRset that exceeds the EDNS buffer. Both scripts now:
    * skip if `DMP_KEEP_SYSTEMD_RESOLVED=1` (opt-out)
    * skip if resolved isn't installed
    * skip if resolved already inactive
    * otherwise: disable + stop, replace `/etc/resolv.conf` with
      static 1.1.1.1 + 9.9.9.9 (handles the symlink-to-stub-resolv
      case so the rewrite touches the real file)
    * idempotent — re-running is a no-op
  Both `dnsmesh.io` and `dnsmesh.pro` were UDP-only-by-accident
  for the entire 0.6.x series because install.sh never freed the
  port. (PR #27.)

## [0.6.5] — 2026-05-01 — RFC 2308 + RFC 8020 negative responses

Third (and actual) round of strict-resolver compatibility fixes.
0.6.3 added apex A/AAAA. 0.6.4 added apex SOA + NS. Both were
necessary, neither was sufficient — Google Public DNS was still
NXDOMAINing every name under healthy DMP zones for **9+ hours**
after the 0.6.4 deploy. Diagnosis traced to two intertwined bugs
in the negative-response path that this release closes.

Validated independently via codex review of RFC 2308, RFC 8020,
and Google Public DNS security docs.

Wire format, on-disk schema, and CLI surfaces are byte-identical
to 0.6.4. Operators upgrade in place via
`pip install -U dnsmesh && systemctl restart dnsmesh-node`
(native install) or `docker compose pull && docker compose up -d`
(Docker).

### Fixed

- **NXDOMAIN at the zone apex for missing record types poisoned
  the entire zone via RFC 8020 NXDOMAIN-cut.** When a TXT lookup
  at the apex name (e.g. ``dmp.dnsmesh.io TXT``) found no record,
  the server returned NXDOMAIN. But the apex *exists* — the zone
  has SOA/NS/A records there from 0.6.4. The correct answer is
  NODATA (NOERROR + 0 answer), not NXDOMAIN. Per RFC 8020, a
  strict resolver caches NXDOMAIN at any ancestor and SYNTHESIZES
  NXDOMAIN for every descendant without re-querying — so a single
  bad apex NXDOMAIN poisoned every owner name under the zone.
  Server now returns NODATA at the apex regardless of which
  record type was queried, and only returns NXDOMAIN for genuine
  sub-name TXT-not-found cases. (PR #25.)
- **Naked NXDOMAIN and NODATA — no SOA in AUTHORITY.** RFC 2308
  §3 requires the zone SOA in the AUTHORITY section of every
  negative response so the resolver knows the negative-caching
  TTL. Without it RFC 2308 §5 says the response SHOULD NOT be
  cached, and Google specifically treats the exchange as
  malformed. Server now appends the apex SOA to NXDOMAIN AND
  NODATA responses when ``DMP_DNS_APEX_NS`` and
  ``DMP_DNS_APEX_SOA_RNAME`` are configured. Backward compat:
  legacy operators without the env vars get the unchanged "naked"
  behavior — RFC-non-compliant, no regression. (PR #25.)
- **Sub-name non-TXT queries return NODATA, not NXDOMAIN.** We
  don't track non-TXT records under sub-names, so we can't tell
  whether a sub-name "exists" for some other type. The
  conservative answer (NODATA) is safer than NXDOMAIN, which
  would propagate via NXDOMAIN-cut to TXT lookups under the same
  prefix. (PR #25.)

### Operator note

After upgrading, Google's poisoned NXDOMAIN cache for the apex
names will need to expire OR be flushed at
``https://dns.google/cache``. Once a fresh query lands, the new
NODATA-with-SOA response replaces the cached NXDOMAIN and the
zone unlocks for descendant queries.

## [0.6.4] — 2026-05-01 — apex SOA + NS records for strict-resolver delegations

Continuation of the strict-resolver compatibility work that started
in 0.6.3. Apex A alone wasn't enough on Google + Level3: those
resolvers also validate the delegation by querying the auth for SOA
+ NS at the zone apex. If either query returned NOERROR with an
empty answer (which 0.6.3 and earlier did — DMP only served TXT
plus the apex A from PR #18), the resolver concluded the auth
didn't own the zone, marked it "lame delegation", and NXDOMAINed
every name under it. Cloudflare and Quad9 skip that validation
which is why this hid until Google was involved.

Hit in production on dnsmesh.de — fresh delegation set up correctly
out-of-bailiwick (`dmp.dnsmesh.de NS ns1.dnsmesh.de`), apex A served
correctly via 0.6.3, ns1.dnsmesh.de A reachable from Google. Yet
Google still NXDOMAINing every subname despite resolving the apex A.
Diagnosis traced back to empty SOA + NS responses from the DMP
server.

Operators upgrade in place via
`pip install -U dnsmesh && systemctl restart dnsmesh-node`
(native install) or `docker compose pull && docker compose up -d`
(Docker). Wire format, on-disk schema, and CLI surfaces are
byte-identical to 0.6.3.

### Fixed

- **DMP DNS server now answers SOA + NS at the zone apex.** The
  server claimed authoritative (aa flag set) but returned empty
  answers for both — the standard pattern strict resolvers use to
  detect a lame delegation. Server now serves both when the
  required env vars are set, with sensible defaults for the SOA
  timing fields. (PR #23.)

### Added

- **`DMP_DNS_APEX_NS`** env var. The NS hostname served at the
  zone apex (e.g., `ns1.dnsmesh.de`). Should match what the
  parent zone delegates to. Used both as the apex NS RR target
  and as the SOA `MNAME` field. (PR #23.)
- **`DMP_DNS_APEX_SOA_RNAME`** env var. The SOA `RNAME` field —
  operator email-as-DNS-name format (e.g., `hostmaster.dnsmesh.de`
  for `hostmaster@dnsmesh.de`). The SOA RR is only emitted when
  both this AND `DMP_DNS_APEX_NS` are set, since RFC 1035 §3.3.13
  requires both fields for a valid SOA. (PR #23.)
- **Operator-facing doc:** new "Apex SOA + NS for strict resolvers
  (0.6.4+)" section in `docs/deployment/dns-delegation.md`. Lives
  right after the apex A doc, with diagnosis pattern + verification
  dig commands + Google flush-cache pointer. (PR #23.)

### SOA defaults

Operators don't typically tune these but they're documented for
the curious. The SERIAL is per-second wall clock (monotonic for
the next ~70 years inside RFC 1982 serial-number arithmetic),
matching how a fresh BIND zone tends to be set up:

  - SERIAL  = epoch-seconds at query time
  - REFRESH = 3600 (1 hour)
  - RETRY   = 600 (10 min)
  - EXPIRE  = 604800 (7 days)
  - MINIMUM = `DMP_DNS_TTL` (default 60s)

We don't have AXFR slaves so most of these are cosmetic; they're
chosen to look "right" to anyone running `dig SOA <zone>` to
sanity-check the configuration.

## [0.6.3] — 2026-05-01 — apex A/AAAA records for self-glued delegations

Single-fix release. Strict recursive resolvers (Google 8.8.8.8,
Level3 4.2.2.x) were NXDOMAINing every name under a DMP node's
served zone when the parent zone used a self-glued delegation —
the standard pattern produced by DigitalOcean's "create
subdomain" panel (`<sub> NS <sub>` with parent-side glue A).

Lenient resolvers (Cloudflare 1.1.1.1, Quad9 9.9.9.9) trust the
glue and never asked the node for its own apex A. Strict
resolvers re-resolve the NS-target name out-of-bailiwick — they
ask the DMP node itself "what's the A for `<DMP_DOMAIN>`?", and
the node, only serving TXT, returned nothing. Federation
discovery silently broke for ~33% of the public-resolver fleet
(2/6 in the directory page's reachability matrix). Symptom:
`dig @8.8.8.8 _dnsmesh-heartbeat.dmp.<your-zone>` returns
NXDOMAIN even though `dig @1.1.1.1 ...` works fine.

### Added

- **`DMP_DNS_APEX_A` / `DMP_DNS_APEX_AAAA`** env vars.
  When set, the DMP DNS server answers A and AAAA queries for
  the served-zone apex (`DMP_DOMAIN`) with the configured
  address(es). Strict resolvers stop NXDOMAINing the zone.
  Operators on a conventional out-of-bailiwick NS delegation
  (`mesh.example NS ns1.example` with no glue dependency) don't
  need this and can leave both unset — the apex fast-path stays
  inactive when neither value is configured. (PR #18.)
- **Operator-facing doc:** new "Self-glued delegation:
  `DMP_DNS_APEX_A`" section in
  `docs/deployment/dns-delegation.md` — symptoms, lenient-vs-
  strict resolver split, the env-var fix, and verification dig
  commands. Lives right after the existing glue-record edge
  case so operators looking up a related symptom land on the
  fix.

### Fixed

- **DNS server returns `NOERROR` (not `NXDOMAIN`) for A/AAAA at
  the apex when only one address family is configured.** Type-
  vs-name DNS semantics: a name that exists for one record type
  but not another shouldn't NXDOMAIN. Matters when an operator
  sets only `DMP_DNS_APEX_A` (no IPv6 box) — an AAAA query at
  apex returns `NOERROR` with empty answer, not NXDOMAIN, so a
  resolver doesn't poison its negative cache for the whole
  zone. (PR #18.)

### Changed

- **Apex TXT queries still route to the record store.** The
  apex fast-path only short-circuits A and AAAA. Operators
  publishing TXT records at `DMP_DOMAIN` (e.g. `v=spf1 -all`)
  see them served as before. (PR #18.)

## [0.6.2] — 2026-04-30 — federation discovery fix

Targeted patch release. The seen-graph DNS path
(`_dnsmesh-seen.<zone>`) was crashing on the public reference
nodes once a few heartbeat ticks had run, breaking federation
discovery for any RFC-strict recursive resolver. Three
independent bugs combined to produce the symptom; this release
fixes all three. Operators upgrade in place via
`pip install -U dnsmesh && systemctl restart dnsmesh-node`
(native install) or `docker compose pull && docker compose up -d`
(Docker). Wire format, on-disk schema, and CLI surfaces are
byte-identical to 0.6.1.

### Fixed

- **DNS server crashed on `dns.exception.TooBig` for oversized
  UDP responses.** When the response RRset exceeded the
  resolver's negotiated EDNS buffer (1232 bytes by default),
  `dns.message.to_wire()` raised, Python's socketserver swallowed
  the exception, and the UDP socket sent nothing. Recursive
  resolvers saw "no answer" and returned SERVFAIL with EDE=23
  ("Network Error") — silently breaking discovery. Server now
  catches `TooBig` on the UDP path and emits a valid TC=1
  truncated stub per RFC 1035 §4.2.2 so resolvers fall back to
  TCP. (PR #14.)
- **Authoritative DNS server didn't accept TCP at all.** The
  RFC 1035 §4.2.2 / RFC 7766 fallback path is mandatory for
  RFC-strict resolvers (Google 8.8.8.8, Level3 4.2.2.x). Without
  it, any TC=1 truncated UDP response was a dead end. New
  threading TCP listener at the same port as UDP, with
  bounded per-connection concurrency, slow-loris mitigation
  (lazy work-permit acquire after the message body is read,
  separate accept-cap semaphore for open sockets), and
  `request_queue_size = 128` so the kernel can absorb the
  "many recursors retrying TCP within milliseconds" burst.
  Six rounds of Codex review baked in. (PR #14.)
- **Self-wire leaked into the local SeenStore via peer
  gossip.** Once federation converged and a peer included our
  wire in its own `_dnsmesh-seen.<peer-zone>` RRset,
  `_fetch_and_ingest` accepted it and stored a self row.
  `_publish_seen_graph` then republished it under our own
  seen-zone, creating a discovery-graph self-loop and bloating
  the RRset toward the EDNS buffer cap (which then tripped
  the TooBig crash above). Fix: parse-and-verify each ingested
  wire and drop ones whose `operator_spk` matches our own
  before `SeenStore.accept`. (PR #16.)
- **Process-memory `_last_seen_wires` lost on restart.** The
  worker tracks "wires we published last tick" so it knows
  what to evict on the next tick. The map is
  process-memory only, so a worker restart left every prior
  wire in place — and `publish_txt_record` is append-with-
  content-keyed-dedup, so each tick layered fresh wires on top
  without removing the stale ones. Across upgrade cycles the
  RRset grew unbounded until each wire's exp fired (24h
  default). One-shot orphan sweep on first
  `_publish_seen_graph` invocation cleans them up — mirrors
  the round-22 sweep added for `_publish_own`. Cluster
  siblings' wires under a shared `_dnsmesh-seen.<shared-zone>`
  are left intact (matched by `(operator_spk, endpoint)` to
  avoid touching anything that isn't ours). (PR #16.)

### Added

- **`deploy/native-ubuntu/firewall.sh`** — optional helper that
  configures `ufw` for the canonical DMP port set: SSH 22, DNS
  53/udp+tcp, HTTP 80, HTTPS 443/tcp+udp. Idempotent. Three
  modes: `--check` (audit only), default (apply rules), `--enable`
  (apply + ufw enable). Driven by an operator note that the inline
  ufw block in `install.sh` was missing TCP 53. (PR #15.)

### Changed

- **All Docker compose files now publish both UDP and TCP for
  port 53.** Mandatory for RFC 1035 §4.2.2 fallback to work
  through the host port mapping. Affects `docker-compose.yml`,
  `docker-compose.prod.yml`, `docker-compose.cluster.yml`,
  `deploy/docker/compose.yml`, and the m9/m10 test harnesses
  under `scripts/`. (PR #14.)
- **`Dockerfile` `EXPOSE`** updated to declare `5353/udp`,
  `5353/tcp`, and `8053/tcp`. (PR #14.)
- **Container integration test reader** switched from
  `dns.query.udp()` to `dns.query.udp_with_fallback()` with EDNS0
  4096-byte buffer advertised, modeling what a real RFC-strict
  client does instead of the bare 512-byte default. (PR #14.)

## [0.6.1] — 2026-04-29 — publication-readiness pass

Cleanup release on top of 0.6.0. Wire format, on-disk schema, and
CLI surfaces are byte-identical to 0.6.0; operators upgrade
no-op via `pip install -U dnsmesh` followed by a service restart
(`systemctl restart dnsmesh-node` on the native install path or a
container restart on Docker). Anyone landing on the project for the
first time gets the polished docs path plus a working
`examples/directory_aggregator.py` and a fixed peer-list rendering
on each node's `GET /` page.

### Fixed

- **Heartbeat render path: peers older than 5 minutes silently
  disappeared from the node's HTML landing page.** The render
  call to `HeartbeatRecord.parse_and_verify(wire)` used the
  default `ts_skew_seconds=300` while the *publish* path used
  `10**9`. Result: a peer whose last harvested heartbeat was
  more than 5 minutes old got rejected at render time even
  though it was alive in the SeenStore and being republished
  in the seen-graph RRset. Most visible as
  `https://dnsmesh.io/` showing 1 peer (its own self-row) while
  `https://dnsmesh.pro/` showed 2 — display luck, not a real
  asymmetry. Render path now matches the publish path: the
  store-level `exp > now` filter is the freshness gate; the
  Ed25519 signature is the authenticity gate; the 300s ts-skew
  default that protects the WRITE path against future-dated
  forgery is dropped on the read/display path. (PR #9.)
- **`examples/directory_aggregator.py`** ported to DNS-native.
  Was calling `GET /v1/nodes/seen` (removed in M9 / 0.5.0) and
  silently producing zero-node feeds since that release. Now
  queries BOTH `_dnsmesh-heartbeat.<seed-zone>` (the seed's own
  self-row) AND `_dnsmesh-seen.<seed-zone>` (the seed's
  republished view of other peers) via a multi-upstream
  ResolverPool, feeding the same verification + aggregation
  pipeline. The heartbeat-fetch part was added after a Codex
  review caught that reading only the seen-graph drops the
  seed itself when the seed has heard no peers (a healthy
  single-node seed leaves the seen RRset empty). Smoke-tested
  live against `dmp.dnsmesh.io` + `dmp.dnsmesh.pro`.
- **GitHub Pages workflow.** `actions/configure-pages@v5` was
  missing `id: pages`, so `${{ steps.pages.outputs.base_path }}`
  evaluated to empty and Jekyll built every page with
  `--baseurl ""`. Asset paths shipped as root-relative and
  404'd on the `/DNSMeshProtocol/` subpath at the custom domain.
  Pre-existing bug; surfaced by happenstance during this pass.
- **CI test collection scope.** Added `pytest.ini` with
  `testpaths = tests` so pytest stops walking `scripts/` and
  trying to collect the m9/m10 e2e drivers as test modules.
- **Pip CVE-2026-3219.** Bumped pip 26.0.1 → 26.1 in
  `requirements-dev.lock` to clear the `pip-audit` strict-mode
  finding on the dev lockfile.

### Changed

- **m9/m10 e2e harnesses moved.** Repo-root cleanup: the two
  developer-only docker-compose stacks and their driver scripts
  now live under `scripts/m9-test/` and `scripts/m10-test/`.
  Repo root drops from 5 → 3 docker-compose files (base, prod
  overlay, cluster sample). `git mv` preserved blame history.
- **`directory/seeds.txt`** entries flipped from legacy
  `https://...` form to canonical zone names. Final shape after
  PR #8: `dmp.dnsmesh.io` and `dmp.dnsmesh.pro` — i.e. the
  served zones (`DMP_DOMAIN`) of the public reference nodes,
  not their apex hostnames. Earlier in this release the seeds
  briefly read `dnsmesh.io` / `dnsmesh.pro` (apex), but the
  heartbeat layer publishes under the served zone, so the
  aggregator queried the wrong RRsets and got empty results.
  Legacy `https://...` form still parses (the host is extracted
  as the zone) for back-compat with forks running older seed
  files.
- **Framing sweep across user-facing docs.** "alpha" /
  "experimental" prose references replaced with
  "non-certified" / "pre-1.0" for consistency. Code-flag
  references (`--experimental`) preserved as shipped CLI
  surface.
- **`docs/index.md` 30-second diagram** updated from the old
  "publish over HTTP API" framing to the M9 DNS UPDATE + TSIG
  flow. Compressed the dnsmesh.io section and the Actively
  shipping list.
- **`docs/design-intent/protocol.md` and
  `implementation-requirements.md` removed.** Pre-implementation
  LLM-flavored prose drafted before any code existed; their note
  banners said "historical" but the bodies still read as
  authoritative spec, contradicting the cleaner shipped docs.
  Kept `docs/design-intent/index.md` as a single-page
  spec-vs-shipped delta (retitled "Spec → Ship").
- **`docs/guide/identity.md` rotation section** rewritten —
  previously claimed M5.4 rotation hadn't shipped, when it has.
- **`docs/design/cluster-anti-entropy-http-boundary.md`**
  rewritten end-to-end to frame HTTP between cluster peers as
  the architecturally correct transport for HA-scoped
  replication, not a workaround. Issue #6 (cluster anti-entropy
  over DNS) closed as not-planned with a decision comment
  pointing at the boundary doc as authoritative rationale.

### Added

- **`docs/deployment/testing.md`** documenting the m9/m10 e2e
  harnesses for the first time. They were previously
  undiscoverable except by reading the workflow files.
- **README passphrase guidance.** The 5-minute walkthrough now
  shows a `read -rs DMP_PASSPHRASE` step and a one-paragraph
  callout that losing the passphrase = losing the identity (no
  recovery — the keys are derived from passphrase + per-identity
  salt via Argon2id). Same guidance added to the node landing
  page (`GET /`) registration block.
- **`.github/ISSUE_TEMPLATE/{bug_report,feature_request,config}.yml`**.
  Structured issue forms; security disclosures routed to
  SECURITY.md instead of the public issue tracker.
- **Repo topics** for GitHub discoverability: `dns`,
  `messaging`, `end-to-end-encryption`, `federated`,
  `protocol`, `tsig`, `python`, `decentralized`, `p2p`.

### Removed

- `info.txt` and `scripts/setup_ubuntu_server.sh` — local promo
  scratch and a stale pre-M9 installer with a placeholder URL,
  superseded by `deploy/native-ubuntu/install.sh` +
  `docs/deployment/native-ubuntu.md`.

## [0.6.0] — 2026-04-27 — M10: receiver-zone claim notifications

Latency-optimized receive path. New protocol opt-in surface, new
operator diagnostics, hardened across 15 rounds of independent
codex review. Existing 0.5.x deployments upgrade no-op (M10 defaults
off, schema fields default empty); operators who flip the M10 flag
should re-register their pre-upgrade TSIG users so the new
keystore column populates and the canonical mailbox-hash format
takes effect.

### Added — M10: receiver-zone claim notifications

Latency optimization for the receive path. Pre-M10 every `dnsmesh recv`
walks 10 slot RRsets per pinned contact per tick — the steady-state cost
scales with the contact list. M10 collapses that to one query per tick
plus one fetch per actual incoming message by routing a tiny signed
pointer ("claim") to the recipient's home zone alongside the chunks on
the sender's own zone. Reuses the M8.2 `DMPCL01` wire — no new on-zone
record types, no new HTTP routes.

- **Server**: extended ``dmp/server/dns_server.py`` un-TSIG'd UPDATE
  accept path to recognize ``claim-{slot}.mb-{hash12}.<served-zone>``
  when ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=1``. Independent opt-in from
  the M8.3 first-contact provider role (``DMP_CLAIM_PROVIDER``); a node
  can serve M10 claims for its own users without taking on the open
  provider role for arbitrary recipients. Per-recipient-hash token
  bucket keyed on the hash12 in the owner name (``DMP_CLAIM_RATE_PER_USER_PER_SEC``
  default 0.5, ``DMP_CLAIM_RATE_BURST`` default 30) — exhaustion is
  SERVFAIL (transient backoff) distinct from REFUSED (shape violation).
- **Client send**: ``send_message`` now publishes a second claim record
  to the recipient's zone (using the contact's ``domain`` field) after
  the chunk + manifest write to the sender's own zone. Best-effort —
  failures don't block delivery, the recipient's slot-walk fallback
  recovers within ``recv_secondary_interval_seconds``.
- **Client recv**: new ``receive_claims_from_own_zone`` method runs as
  phase 1 inside ``receive_messages``. Phase 2 (the existing slot walk)
  follows as a defense-in-depth fallback. The replay cache dedupes
  across both phases. Phase 1 is skipped in pure TOFU mode (zero pinned
  signing keys) to preserve the M9 receive contract for legacy callers.
- **CLI**: ``dnsmesh recv --primary-only`` runs phase 1 alone (diagnoses
  primary-path latency); ``dnsmesh recv --skip-primary`` runs phase 2
  alone (diagnoses missed claims). Three new persisted config knobs:
  ``recv_primary_interval_seconds`` (default 30),
  ``recv_secondary_interval_seconds`` (default 600),
  ``recv_secondary_disable`` (default false). The CLI itself is one-shot
  per invocation; cadences are consumed by external schedulers (cron,
  systemd timers).
- **Spec**: ``docs/protocol/notifications.md`` (RFC-style; covers wire
  format, owner-name conventions, sender/receiver behavior, threat-model
  deltas, and migration sequencing).
- **Tests**: 14 new cases in ``tests/test_m10_notifications.py`` covering
  the happy path, secondary fallback when claims drop, dedup across both
  phases, recipient/sender zone unreachable, cross-recipient replay,
  signature-passing claim from a non-pinned sender lands in intro queue,
  bad-signature server REFUSED, rate-limit exhaustion SERVFAIL, opt-out
  default REFUSED, M10 flag enables, ``primary_only`` /
  ``skip_primary`` diagnostic flags, and their mutual exclusion.

Migration is a no-op for existing 0.5.x deployments —
``DMP_RECEIVER_CLAIM_NOTIFICATIONS`` defaults to off. Operators opt in
explicitly. A pre-M10 sender that doesn't emit recipient-zone claims
stays interoperable; recipients fall through to phase 2.

### Added — operator UX: dnsmesh doctor + auto-probe

Hardening that came out of an extended codex review pass on the M10
implementation. Fifteen rounds of independent review surfaced layered
correctness, security, and operator-ergonomics issues across the
server gate, the client send path, the receive scheduling, the DNS
fallback chain, and the keystore migration story — all fixed.
Operator-facing additions:

- **`dnsmesh doctor`** — new diagnostic subcommand. Walks endpoint
  reachability, the local DNS endpoint (M10 same-zone publish target),
  ``dns_host`` ambiguity (warns when pointed at a public recursive
  resolver like 1.1.1.1 without ``local_node_dns_*`` pinned), and
  TSIG registration status. Each check produces PASS / WARN / FAIL
  with an actionable hint. Exit 0 on PASS/WARN, 1 on FAIL — safe for
  CI smoke gates. ``dnsmesh doctor --repair`` re-pins
  ``local_node_dns_*`` non-destructively (preserves identity, TSIG
  block, contacts) — use this instead of ``dnsmesh init --force``,
  which would clobber the user's identity by rebuilding ``kdf_salt``.
- **`dnsmesh init` auto-probe** — at init time, probes the endpoint
  host's DNS port (5353 then 53) for a DMP-specific signature: an
  un-TSIG'd, non-claim UPDATE that the server REFUSES. That's a
  load-bearing protocol contract on the DMP DNS server side, so the
  signal works on default node configs (heartbeat is opt-in and not
  required for the probe). When found, ``local_node_dns_*`` lands in
  config automatically. ``--no-probe-local-dns`` skips the probe for
  offline / CI setups.
- **`local_node_dns_server` / `local_node_dns_port` config fields** —
  self-describing schema for the same-zone M10 publish target.
  Disambiguates from ``dns_host`` (the read-side resolver, often a
  public recursive). Empty by default; populated by ``dnsmesh init``
  auto-probe or ``dnsmesh doctor --repair``. Existing configs upgrade
  cleanly without changes.
- **NS-chain fallback for split-host deployments** — when the zone
  apex has no A/AAAA record (auth DNS server delegated via NS to a
  sibling hostname), ``_resolve_to_ip`` follows NS records via the
  configured ``ResolverPool``. Strict-by-default: when a pool is
  given, the chase stays on the pool exclusively. Hybrid pools that
  can answer NS records but not external A lookups can opt into a
  system-resolver fallback via ``DMP_ALLOW_SYSTEM_DNS_FALLBACK=1``.

### Hardening — codex review fixes (rounds 1–15)

Server side:
- M10 admission gate restricts un-TSIG'd writes to recipient hashes
  registered on the served zone (``DMP_CLAIM_PROVIDER=0`` opt-out
  stays honored when M10 is on).
- Hash extraction uses ``registered_x25519_pub`` (new keystore
  column, idempotent ALTER on startup) so legacy keystores upgrade
  cleanly and ``DMP_TSIG_LOOSE_SCOPE=1`` users are admitted by
  recomputing the canonical hash from their pubkey.
- Mailbox-scope check requires the anchor entry to live directly
  under the zone — a row scoped only to a child subzone no longer
  qualifies for parent-zone admission.
- Registration's mailbox-hash convention corrected to two sha256
  rounds, matching the actual owner format (was one round, only
  worked because wildcard scopes covered it).

Client side:
- M8.3 first-contact ``claim_providers`` channel survives
  ``--primary-only`` / ``--skip-primary`` (orthogonal to M10 phase
  toggles).
- ``Contact.domain_explicit`` flag distinguishes legacy backfilled
  contacts from explicit same-zone entries — explicit same-zone
  publishes M10 (needed for ``recv --primary-only``); legacy
  backfill skips it.
- ``force_un_tsig_d=True`` in publish_claim takes priority over
  ``provider_writer`` — the M10 send path always exercises the
  recipient's home-node opt-in gate, never bypassed by a writer
  override.
- Same-zone M10 publishes target the explicit
  ``local_dns_server`` / ``local_dns_port`` (set by the CLI from
  the new config fields) — no global env-var override that would
  misroute cross-zone publishes.

Migration: any existing 0.5.x deployment upgrades cleanly. Schema
fields default to empty / no-op. ``dnsmesh doctor`` will surface
config drift on first run and ``--repair`` fixes it without
touching identity. Operators on multi-tenant nodes who registered
TSIG before this release should re-register so their keystore
gets ``registered_x25519_pub`` populated and the canonical mailbox
hash format — the M10 admission gate gracefully falls back to
suffix-scanning for pre-migration rows.

## [0.5.3] — CLI fixes: full-address contact keys + --config-home flag

CLI-only release. No node-side changes; existing 0.5.x nodes stay
compatible. Two bugs surfaced during a real human↔assistant cross-
node test on the live federation; both broke the canonical M9 happy
path enough to warrant a patch release so users on PyPI / pipx /
the standalone binary pick up the fix.

### Fixed

- **Contacts now stored under the full canonical address**
  (codex round-23 P1). `dnsmesh identity fetch user@host --add`
  used to store the contact under the bare username, but
  `dnsmesh send user@host` looked up by the full address as the
  dict key — so a freshly-pinned cross-zone contact would fail
  with "unknown contact" on the next send. Workaround was to send
  by bare name. Real fix: store under the full canonical address
  when the fetch arrives via the `user@host` form. Bare-name keying
  stays for shared-mesh / TOFU fetches without `@host`. The send
  path now does a two-step lookup (full address first, fall back
  to bare name) so legacy contacts keep working after upgrade.
  Two contacts with the same left-half on different zones (e.g.
  `alice@dmp.dnsmesh.io` vs `alice@dmp.dnsmesh.pro`) are now
  correctly distinguishable; previously they collided silently.
- **Reliable config isolation via `--config-home` CLI flag**
  (codex round-23 P1). The pre-fix only knob was the
  `DMP_CONFIG_HOME` env var, which proved leaky during a
  `pipx upgrade dnsmesh` upgrade scenario — a stale `~/.dmp/`
  config could shadow the env-var path and silently produce the
  wrong subject on `dnsmesh tsig register`. New top-level
  `--config-home PATH` flag wins over the env var and is the
  recommended way to isolate per-identity / per-tenant configs.
  Bonus: a single `--config-home` flag also defaults
  `DMP_TOKENS_HOME=<config-home>/tokens` so per-tenant isolation
  is one-knob (operator workflow).

### Added

- `--config-home PATH` top-level CLI flag.
- `--tokens-home PATH` top-level CLI flag.

### Tests

- 4 new `TestContactKeyByFullAddress` cases covering the fetch /
  send / back-compat matrix.
- 3 new `TestConfigHomeFlag` cases covering flag-vs-env-var
  precedence and the auto-derived `tokens-home` path.
- 1 existing test updated for the new full-address key shape.

1364 tests passing.

## [0.5.2] — Post-M9 patch: heartbeat RRset orphan sweep + self-row preference

Surfaced during the 0.5.1 deployment validation: the operator's own
"Recent peers" page on dnsmesh.io showed "(1)" with the stale
pre-upgrade version, even though messaging end-to-end was working
fine. Two related bugs, both fixed.

### Fixed

- **Heartbeat RRset accumulates orphan self-wires across restarts**
  (codex round-22 P1). ``HeartbeatWorker._publish_own`` tracks
  ``self._last_self_wire`` in process memory and uses it for
  delete-then-add cleanup — but every restart loses that tracking,
  and the prior process's wire stays at
  ``_dnsmesh-heartbeat.<own-zone>`` until its ``exp`` fires (24h
  default). Across multiple restarts (e.g. an upgrade cycle), the
  RRset grew to 10+ wires (each ~250 bytes), inflating the UDP DNS
  response past 512 bytes. Public recursors that don't gracefully
  retry over TCP (or whose negative-cache held the truncated state)
  returned empty for the heartbeat query, breaking the federation's
  discovery story even while messaging worked. Fix: a one-time
  startup sweep on first publish reads the current RRset, identifies
  every TXT value signed by the running process's operator key, and
  deletes them before the fresh publish. Other operators' wires on
  shared zones (cluster-mode siblings) are matched on operator_spk
  and left untouched. Four new tests:
  ``test_first_tick_sweeps_prior_process_self_wires``,
  ``test_sweep_does_not_touch_other_operators``,
  ``test_sweep_only_runs_once``,
  ``test_no_record_writer_skips_sweep_silently``.
- **Synthesized self-row was masked by stale peer-gossipped self**
  (codex round-22 P2). ``_directory_rows`` in ``http_api.py`` only
  synthesized the self-row when ``key not in merged`` — so a peer
  that gossipped back the operator's pre-upgrade heartbeat wire
  blocked the synthesis, and the operator's own ``/`` page reported
  the OLD version after every upgrade until peer harvest cycles
  caught up. Fix: synthesize self UNCONDITIONALLY using the running
  package version — the running process is authoritative for its
  own version + liveness, peer gossip is at most a stale snapshot.
  ``sources`` count is preserved from any peer-gossipped row so the
  out-of-band signal "N peers gossiping me back" stays visible.
  Two new tests in ``test_http_api.py``:
  ``test_self_row_uses_running_version_not_gossipped``,
  ``test_self_row_present_when_no_peer_gossip``.

### Operational note

Running 0.5.2 ``upgrade.sh`` on each existing 0.5.0 / 0.5.1 node
clears the orphan-wire backlog on the next ``systemctl restart``.
The first heartbeat tick after restart sweeps every prior-process
self-wire and publishes a single fresh one. Within one harvest
cycle (≤5 min), peers re-harvest the cleaned RRset and the public
DNS chain returns a sane response again.

## [0.5.1] — Post-M9 patch: hostname-aware DNS UPDATE + zone migration

Follow-up to 0.5.0. Two CLI bugs surfaced during the live cross-zone
test against `dnsmesh.io` <-> `dnsmesh.pro`, and the canonical
bootstrap zone moved from the apex to a delegated subzone
(`dmp.dnsmesh.io`). Wire format and crypto are unchanged — every
0.5.0 record stays valid.

### Fixed

- **DNS UPDATE writer accepts hostnames** (codex round-21 P1).
  `_DnsUpdateWriter` and `_publish_claim_via_dns_update` previously
  passed the operator's configured hostname straight to
  `dns.query.udp()`, which only accepts IP literals — every operator
  who set `tsig_dns_server: dnsmesh.io` or pinned a hostname-form
  `claim_provider_override` hit a `ValueError` deep in `dns.inet`.
  The new `_resolve_to_ip` helper resolves the hostname once at
  writer construction (per-call for claims, since target varies) and
  routes the lookup through the configured `ResolverPool` first
  (i.e. `DMP_HEARTBEAT_DNS_RESOLVERS`), falling back to
  `socket.getaddrinfo` only when no pool is configured. Routing
  UDP-destination resolution through the same pinned recursors as
  record reads avoids the system-resolver NXDOMAIN-cache stall that
  silently broke writes during the live zone-delegation move.
- **Resolution failure surfaces as `False`, not an uncaught exception**
  (codex round-21 P2). `_resolve_to_ip` now returns `None` on lookup
  failure (was: original hostname); `_DnsUpdateWriter._send` checks
  for that and surfaces `False` per the `DNSRecordWriter` contract.
  Hostile inputs (`None`, empty string, NUL byte, `UnicodeError`) all
  collapse to `None` defensively. New `TestResolveToIp` covers IPv4
  / IPv6 literal pass-through, localhost resolution, unresolvable
  `.invalid`, NUL-injected, pool-preferred, pool-failure-falls-back,
  pool-exception-doesn't-propagate, and end-to-end writer-with-no-A-
  record returns False without raising.
- **`upgrade.sh` rewrites stale apex seeds**, not just backfills
  (codex round-21 P1). Previously the migration only added
  `DMP_HEARTBEAT_SEEDS` when absent; existing 0.5.0 nodes already
  had `DMP_HEARTBEAT_SEEDS=https://dnsmesh.io` (apex), which after
  the subzone-delegation move would silently lose federation when
  the stale heartbeats expired (~24h). Both `deploy/native-ubuntu/`
  and `deploy/digitalocean/` `upgrade.sh` now detect the apex /
  scheme'd-apex / first-entry-of-comma-list patterns and rewrite to
  `dmp.dnsmesh.io` in place via `sed -i -E`, with a timestamped
  backup file. Regex doesn't false-match commented-out, already-
  migrated, or empty values.

### Changed

- **Built-in canonical bootstrap zone**: `dnsmesh.io` apex →
  `dmp.dnsmesh.io`. The dnsmesh-node DNS server is TXT-only, so the
  apex zone can't be self-served without losing the `https://dnsmesh.io`
  website's A record. Subzone delegation (DigitalOcean DNS publishes
  `dmp.dnsmesh.io NS ns1.dnsmesh.io` + glue) lets the node serve DMP
  records authoritatively while the apex stays on managed DNS for
  the website. `_BUILTIN_CLAIM_PROVIDER_SEEDS` in `dmp/cli.py`
  updated; `install.sh` and `quickstart.sh` write the new seed for
  fresh installs; `upgrade.sh` migrates existing ones.
- **`DMP_HEARTBEAT_DNS_RESOLVERS=1.1.1.1,9.9.9.9` is now a default**
  in `install.sh` / `upgrade.sh` / `quickstart.sh`. Previously unset,
  meaning the heartbeat worker fell through to the host's system
  resolver — fine on a healthy network, fragile during a federation-
  wide zone migration where one cached NXDOMAIN at the upstream
  recursor stalls discovery for the SOA negative-cache TTL (often
  30+ minutes). Pinning two known-good public recursors makes peer
  discovery deterministic.

### Added

- `ResolverPool.resolve_address(host)` — resolve a hostname to an
  IPv4 (preferred) or IPv6 literal through the pinned upstreams.
  Used internally by `_resolve_to_ip` so UDP-destination lookups
  follow the same path as record reads.
- `dnsmesh tsig` reference section in
  [User Guide → CLI reference](docs/guide/cli.md). The M9 happy-path
  command (`dnsmesh tsig register`) didn't have its own section
  alongside `init`, `identity`, `send`, etc. Now does, with flag
  table, scope-output example, and a "what can go wrong" table.
- Quick-reference "happy path in 6 commands" at the top of
  [User Guide → CLI reference](docs/guide/cli.md).

### Docs

- [Getting Started](docs/getting-started.md) rewritten as a focused
  7-step tutorial against the public node (286 → 202 lines). Drops
  the "run a node locally" detour, the three-options passphrase
  matrix, and the cluster section (those live elsewhere). New
  troubleshooting section covers the 4 errors a new user is likely
  to hit on first try.
- `docs/how-it-works.md` and `docs/how-resolution-works.html`
  refreshed for M9 (preferred path is DNS UPDATE; HTTPS fallback
  for older configs is documented but no longer the default).

## [0.5.0] — M9 DNS-native federation

The protocol speaks DNS both directions now. The only HTTPS exchange
left is the one-time TSIG-key registration step
(`POST /v1/registration/tsig-confirm`). Every record write — identity,
prekeys, mailbox slots, chunks, claim publishes — is RFC 2136 DNS
UPDATE signed with RFC 8945 TSIG. Reads are plain DNS TXT queries.
Cluster anti-entropy stays HTTP as the documented HA-only exception
inside one operator's trust domain (see
[design/cluster-anti-entropy-http-boundary](https://oscarvalenzuelab.github.io/DNSMeshProtocol/design/cluster-anti-entropy-http-boundary)).

### Added

- **DNS UPDATE handler with TSIG verification** (M9.2.1).
  `DMPDnsServer` accepts RFC 2136 UPDATE messages signed with TSIG
  (RFC 8945 HMAC-SHA*). Verified key-name + per-key suffix scope
  governs which owner names the UPDATE may mutate. `NOTAUTH` /
  `NOTZONE` / `REFUSED` map cleanly back to TSIG / zone /
  scope failures. Operator caps (`max_ttl`, `max_value_bytes`,
  `max_values_per_name`) apply identically to UPDATE writes.
- **TSIG keystore** (M9.2.2). Sqlite-backed registry of per-user
  TSIG keys with subject + registered-spk anti-takeover. Wildcard
  suffix matching (`slot-*.mb-*.<zone>`) lets the per-user scope
  cover content-addressed DMP record names without granting
  full-zone authority. Keystore drives the live keyring rebuild on
  every UPDATE so newly-registered users authorize without
  restarting the DNS server.
- **DNS-native registration flow** (M9.2.3). New
  `POST /v1/registration/tsig-confirm` route mints a per-user TSIG
  key via the same Ed25519 challenge/confirm ceremony the legacy
  bearer-token path used. Registered scope: identity (16-char and
  12-char hash variants for prekeys), claim records, mailbox /
  chunk wildcards. Atomic anti-takeover prevents two SPKs from
  claiming the same subject concurrently.
- **`_DnsUpdateWriter` client (M9.2.4 + M9.2.5).** New CLI command
  `dnsmesh tsig register --node <host>` walks the registration
  ceremony and persists the minted TSIG key into config. After
  that, `_make_client` builds `_DnsUpdateWriter` for every record
  publish. Cluster mode still routes the user's own writes through
  this DNS UPDATE writer (the cluster's HTTP anti-entropy
  propagates internally).
- **Claim publish over DNS UPDATE** (M9.2.6). `publish_claim`
  drops the HTTP path and uses an un-TSIG'd UPDATE to the
  provider's authoritative DNS server. The wire is a signed
  `ClaimRecord`; the on-zone authentication is the Ed25519
  signature in the record itself. Provider opt-in via
  `DMP_CLAIM_PROVIDER=1` + `DMP_DNS_UPDATE_ENABLED=1`. Claim
  lifetime is capped via `DMP_CLAIM_MAX_TTL`.
- **3-node DNS-only e2e harness** (`docker-compose.m9-test.yml` +
  `scripts/m9_e2e_test.py`). 12-step end-to-end validation of
  multi-node DNS coordination on real containers — heartbeat
  publish, transitive seen-graph discovery, TSIG registration,
  in-pattern + out-of-pattern UPDATE, cross-zone claim publish,
  anti-takeover.

### Changed

- **HeartbeatRecord wire format bumped to `DMPHB03`** (M9.1.1).
  Adds `claim_provider_zone` field. Legacy `DMPHB02` wires still
  parse for rolling-upgrade compatibility (treated as empty zone).
- **Heartbeat worker is DNS-native** (M9.1.2 + M9.1.3). Each tick:
  publishes own heartbeat at `_dnsmesh-heartbeat.<own-zone>`,
  republishes recently-verified peers at `_dnsmesh-seen.<own-zone>`
  as multi-value TXT, queries every seed zone via DNS for
  transitive discovery. The HTTP-gossip exchange is gone.
  `DMP_HEARTBEAT_SEEDS` accepts bare zone names; legacy URL form
  still parses.
- **CLI claim-provider discovery is DNS-native** (M9.1.3). The
  `_build_claim_providers` rewrite reads from
  `_dnsmesh-seen.<zone>` and seed `_dnsmesh-heartbeat.<zone>`
  records. `select_providers` pulls `claim_provider_zone` straight
  off each verified wire instead of probing `/v1/info`.
- **`dnsmesh peers <zone>`** queries DNS directly. Argument is now
  a zone name (URL form still accepted for back-compat).
- **Heartbeat-worker resolver source is operator-controlled.**
  `DMP_HEARTBEAT_DNS_RESOLVERS` env (comma-separated) feeds a
  `ResolverPool`; default falls back to dnspython's system
  resolver. The pre-M9 hardcoded 1.1.1.1/8.8.8.8 is gone.

### Removed

- `POST /v1/heartbeat` (peer push).
- `GET /v1/nodes/seen` (HTTP discovery feed).
- `GET /nodes` (HTML directory view).
- `POST /v1/claim/publish` (HTTP claim publish).
- `GET /v1/info` (replaced by the heartbeat wire's
  `claim_provider_zone` field).
- `tests/test_http_heartbeat.py` and `tests/test_http_claim.py`
  (the routes they exercised are gone). DNS UPDATE +
  claim-publish coverage moved into `test_dns_server.py`,
  `test_tsig_keystore.py`, `test_registration_tsig.py`,
  `test_dns_update_writer.py`, and the docker e2e harness.
- `scripts/m8_smoke.py` (used the removed HTTP endpoints).
- The old heartbeat-fixture block in `test_docker_integration.py`
  (4 tests + container fixture) — redundant with the M9 e2e.

### Fixed

- **No silent dropped UPDATEs.** `_build_update_response` checks
  the writer's bool return and answers `SERVFAIL` on failure
  (cluster fanout quorum-miss surfaces correctly to the client
  for retry instead of looking committed).
- **Heartbeat publish replaces the RRset every tick** instead of
  appending — readers no longer lock onto an arbitrarily old
  self-record after multiple ticks.
- **CAP_CLAIM_PROVIDER advertisement gated on
  `DMP_DNS_UPDATE_ENABLED`.** A node with the heartbeat layer
  enabled but no DNS UPDATE wired no longer falsely advertises
  claim-provider capability that it can't actually serve.
- **TSIG key names disambiguated by subject hash** so two subjects
  on different domains using the same Ed25519 key get distinct
  keystore rows.

### Documentation

- New `docs/design/cluster-anti-entropy-http-boundary.md` —
  authoritative reference for the trust-boundary decision keeping
  cluster anti-entropy HTTP. Linked from the anti-entropy module
  docstring + the `_build_cluster_writer_factory` docstring.
- README, `docs/index.md`, `docs/how-it-works.md`, and the Reveal.js
  `how-resolution-works.html` slides updated to reflect M9: HTTPS is
  the one-time `tsig register` step, every protocol write is DNS
  UPDATE.
- Node landing page (`GET /` HTML) shows the DNS UPDATE
  registration flow + the `_dnsmesh-heartbeat` / `_dnsmesh-seen`
  query examples instead of dead links to removed HTTP routes.

### GitHub issues

- Filed [#6](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/6)
  tracking the eventual DNS-native cluster anti-entropy redesign.
  Decision recorded: option (C) — accept HTTP for cluster-internal
  sync in 0.5.0, defer (A) pure-DNS digests / (B) DNS UPDATE-based
  push to a future major version.

## [0.4.4] — operator UX from live dnsmesh.io / dnsmesh.pro deployment

Three issues caught while validating the M8 stack on the public
reference deployments:

### Fixed

- **Heartbeat wire reports the real package version** instead of the
  literal `"dev"` fallback. The 0.4.1 patch fixed only the synthesized
  self-row in the directory UI; the SIGNED heartbeat record still went
  out as `version="dev"` whenever `DMP_HEARTBEAT_VERSION` wasn't
  explicitly set in the operator's env file. Result: every node showed
  "dev" for every other node's row in the `/nodes` UI even when both
  ran a real release. Now both code paths fall back to
  `dmp.__version__`.
- **Node landing page (`GET /`) registration example** now uses bare
  hostnames matching the 0.4.2 CLI ergonomics: `--endpoint dnsmesh.io`,
  `--node dnsmesh.io`, plus `dnsmesh init alice@<your-zone>` for
  consistency with the auto-parse fix. Operator-reported regression
  from the live dnsmesh.io landing page that still prompted users to
  paste the broken `--endpoint https://dnsmesh.io` form.

### Added

- **`docs/deployment/dns-delegation.md`** — step-by-step on the
  subdomain-delegation pattern that makes a DMP node's records
  reachable from the public DNS chain. Covers DigitalOcean,
  generic-registrar instructions, glue-record edge cases, troubleshooting
  table, and the io-vs-pro reference deployment status. Cross-linked
  from README ("Self-host" section), `docs/deployment/index.md`, and
  the training-guide presentation deck.
- **Presentation slide** "One step to make your node reachable from any
  network" — explains why operators hit the silent
  `dig @1.1.1.1 id-XXX TXT → empty` failure and the one-line fix.

## [0.4.3] — final pre-release codex sweep on the M8 path

Two P2 fixes from a release-readiness codex review of the cumulative
0.3.7 → 0.4.x diff.

### Fixed

- **Claim-discovered messages from a rotated contact now go straight
  to the inbox.** `receive_claims` only checked literal pinned
  `known_spks` membership; a contact who had rotated their Ed25519
  key would have had claim messages quarantined as an intro even
  though the same contact's same-zone messages were delivered via
  the rotation-chain walker. The claim path now mirrors the
  receive_messages logic: pinned ∪ rotated → inbox, everyone else →
  intro queue.
- **Claim publish now rejects overlong claims at parse time** rather
  than silently truncating only the DNS-record TTL. Capping the
  RRset TTL while leaving the signed `exp` untouched means an
  anti-entropy peer that pulls the wire (M8.4 gossip) would happily
  verify and re-publish under whatever TTL it picks — defeating the
  operator's `max_ttl` policy. Now the server returns 400 if
  `record.exp - now > max_ttl`.

## [0.4.2] — operator UX from a real deploy trace

Two follow-on fixes from a `dnsmesh.pro` install trace where the
operator hit confusing CLI behavior:

### Fixed

- **`dnsmesh register --node`** now strips a `<scheme>://` prefix
  before composing the registration URL. The natural copy-paste
  `--node https://dnsmesh.pro` previously produced
  `https://https://dnsmesh.pro` and a name-resolution error. The
  saved-token filename now uses the normalized hostname so the
  per-node bearer auto-attaches at publish time regardless of how
  the operator typed the `--node` arg.
- **`dnsmesh init alice@dnsmesh.pro`** now auto-splits the @-form
  into `username=alice` + `domain=dnsmesh.pro`. Previously the @
  form landed verbatim in the `username` field and the user had
  to remember to also pass `--domain dnsmesh.pro` (caught from a
  real install where the operator didn't, then chased the
  resulting passphrase-tripwire mismatches with multiple
  `--force` re-inits).
- **Presentation title** updated to "DNS Mesh Protocol — a
  training guide" so the browser tab matches the new
  business-oriented framing.

### Added

- **README** now documents the public-server endpoint convention:
  on a node fronted by Caddy at `dmp.example.com`, point
  `--endpoint dmp.example.com` (not `http://127.0.0.1:8053`) so
  the registration token saved at
  `~/.dmp/tokens/dmp.example.com.json` auto-attaches at publish
  time. The auto-attach is keyed by hostname; loopback endpoints
  produce a 401 even after a successful `register` because the
  hostname doesn't match.

## [0.4.1] — install/upgrade hardening + UX polish

### Fixed

- **`install.sh` now writes `DMP_DOMAIN=$DMP_NODE_HOSTNAME` into
  `node.env` at install time.** Without this, the M8 claim-provider
  zone-resolution chain (`DMP_CLAIM_PROVIDER_ZONE` →
  `DMP_CLUSTER_BASE_DOMAIN` → `DMP_DOMAIN`) returned empty on a
  fresh install, the heartbeat advertised `capabilities=0`, and
  `POST /v1/claim/publish` 404'd — silently disabling the
  claim-provider role even when the operator wanted it. This is
  what was happening on the public reference node at `dnsmesh.io`
  until the fix shipped.
- **`upgrade.sh` backfills `DMP_DOMAIN`** for pre-0.4.1 installs
  that never had it. Derived from `DMP_HEARTBEAT_SELF_ENDPOINT` (host
  part) or `DMP_NODE_HOSTNAME`, with a clear warning when neither is
  available.
- **`dnsmesh init --endpoint`** now accepts bare hostnames (e.g.
  `--endpoint dnsmesh.io`) and auto-prepends `https://`. Previously
  the docs showed `--endpoint https://dnsmesh.io`, but the bare form
  is more ergonomic and matches what the public site recommends.
  Existing fully-qualified URLs (including `http://127.0.0.1:8053`
  for local dev) pass through untouched.
- **Synthesized self-row in `/v1/nodes/seen` + `/nodes` UI** now
  shows the installed package version (`dmp.__version__`) instead of
  the hard-coded `"dev"` fallback, so a node running 0.4.x reports
  `0.4.x` in its directory entry. Operator override via
  `DMP_HEARTBEAT_VERSION` still wins for ops who want a build-number
  / git-sha string.

### Added

- **Website surfacing** of the public reference node's capabilities.
  `docs/index.md` now has a "Use dnsmesh.io as your starting point"
  section spelling out what the open public node actually offers
  (registration, claim-provider role, bootstrap seed, federation
  source) so users discover the path that doesn't require
  self-hosting first.

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
