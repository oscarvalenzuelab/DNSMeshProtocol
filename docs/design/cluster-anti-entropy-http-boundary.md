# Cluster anti-entropy: the HTTP boundary

**Status:** decided 2026-04-25 for the 0.5.0 release; reaffirmed
2026-04-29 after a full re-evaluation of options A and B.
**Issue:** [#6](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/6)
**Decision:** HTTP is the **correct** transport for cluster-internal
anti-entropy, not a workaround. A DNS-native redesign was evaluated
in detail and deferred indefinitely; it would regress on
confidentiality, observability, and code maturity without
materially advancing any goal that matters at the protocol's design
scope.

## The trust boundary, stated plainly

> **Federation and first-contact are DNS-only because they cross
> trust domains. Cluster replication is an operator-scoped HA
> mechanism inside one trust domain — and HTTP is the right
> transport for that scope.**

Federation paths run between nodes that don't trust each other —
two independent operators, two zones — and use DNS so neither side
exposes an authenticated HTTP surface to the other. Cluster
replication runs between nodes the **same operator** runs to scale
or survive failures; those peers verify each other through one
signed cluster manifest, share credentials, and exist inside one
administrative trust domain. The threat model is different, so the
transport choice is different. This isn't a compromise — it's the
result of matching transport to threat model.

## Where the boundary sits

After M9 the DMP code path table looks like this:

| Surface | Direction | Transport |
|---|---|---|
| User → own node | Auth (challenge / TSIG mint) | HTTPS |
| User → own node | Record writes | DNS UPDATE + TSIG |
| Sender → claim provider (foreign zone) | Claim publish | DNS UPDATE (un-TSIG'd, Ed25519-signed wire) |
| Node → peer node (different zone) | Heartbeat / discovery / seen-graph | DNS query |
| **Cluster peer → cluster peer** | **Anti-entropy (digest + pull)** | **HTTP** |

Everything except the last row is DNS-only. The last row stays HTTP
**by design** — see the next section for why this is the right
answer, not a temporary state.

## Why HTTP is the right transport here

This is the positive case for HTTP at this boundary, not a list of
excuses.

**1. HTTP gives confidentiality. DNS UPDATE doesn't.**

HTTPS between cluster peers encrypts the wire. TSIG-signed DNS
UPDATE provides authenticity (HMAC over the message) but ships
the payload in plaintext. Record *contents* are end-to-end
encrypted at the protocol layer regardless, but cluster sync
carries metadata — record names, slot activity timing, claim
traffic, replication cadence. HTTPS hides that from a network
observer; DNS UPDATE would expose it. This directly conflicts with
the M6 traffic-analysis-resistance goals on the roadmap.

**2. HTTP/2 multiplexes; DNS UPDATE doesn't.**

A cluster fanout writer holds one TCP connection to each peer and
streams writes over it. DNS UPDATE is one exchange per write —
no multiplexing, no connection reuse beyond the OS-level
keep-alive. Performance at the cluster's hot path favors HTTP/2
by design.

**3. HTTP has mature operator tooling. DNS UPDATE doesn't.**

`curl`, `tcpdump`, browser dev tools, Postman, every load
balancer, every proxy — all speak HTTP. The DNS UPDATE
ecosystem is `nsupdate` and not much else. When an operator
debugs *"what does node B think it has?"*, `curl
https://node-b/v1/sync/digest` is one command; the DNS-only
equivalent is "query every record name via dig and diff
yourself."

**4. Cluster anti-entropy isn't a protocol primitive.**

Federation between independent operators IS a protocol primitive
— two strangers' nodes have to interoperate. Cluster anti-entropy
is an HA implementation detail of how one operator scales or
survives failures. Other DMP installations don't need to
interoperate with a cluster's internal sync; only the cluster
operator does. The "no HTTP" rule defends the federation
boundary; applying it inside an HA cluster is rule-following for
its own sake.

**5. The digest/pull protocol is mature code.**

`dmp/server/anti_entropy.py` is 1346 lines, 55 tests, hardened
across multiple Codex review rounds. It handles compound
`(ts, name, value_hash)` cursors, TTL-refresh detection,
contiguous-prefix watermark advancement, and signed-record
re-verify on receive. Replacing it with a DNS-native equivalent
means rewriting working replication code — and replication bugs
are the worst kind: silent data divergence between nodes that no
test catches until production.

## What's NOT changed by this decision

- Heartbeat / discovery / seen-graph — DNS-only between any two
  nodes regardless of cluster membership. Unaffected.
- Claim publish from arbitrary senders to a provider — DNS-only,
  un-TSIG'd UPDATE gated by the wire's Ed25519 signature.
  Unaffected.
- TSIG-authorized record writes (identity / prekeys / mailbox /
  chunk) — DNS-only via `_DnsUpdateWriter`. Unaffected.
- A user with a registered TSIG key against a cluster node uses
  DNS UPDATE for their own writes; the cluster's anti-entropy
  worker propagates that write across cluster peers via HTTP.
  The user-facing path stays DNS; only the post-write replication
  uses HTTP.

## Single-node operators

If you're running one DMP node (not a cluster), the anti-entropy
worker isn't wired in at all — there are no peers to sync with —
and this exception doesn't apply to your deployment.

## Designs evaluated and deferred indefinitely

Two DNS-native redesigns were considered. Both were rejected on
substantive grounds, not deferred for lack of effort.

**Option A — Pure-DNS sync via custom RRsets.** Publish digests at
`_dnsmesh-digest.<peer-zone>` as multi-value TXT; consumers query
and diff locally. **Rejected:** no incremental cursor means every
consumer reads the full digest every tick. At ≤5 nodes per cluster
this is acceptable; at scale it's O(N²) per-tick read amplification
on the DNS infrastructure with no upside over option B.

**Option B — DNS UPDATE-based push.** Every local write fans out
to cluster peers via DNS UPDATE signed with a cluster-shared TSIG
key. Cold-start resync needs a separate "give me everything"
path. **Rejected** for these reasons:

- **Confidentiality regression.** TSIG signs but does not encrypt.
  Cluster sync metadata that's hidden by HTTPS today would become
  observable to anyone on the network path. This conflicts with
  M6.
- **Doesn't actually deliver "100% DNS."** The TSIG-key
  registration handshake (`POST /v1/registration/tsig-confirm`)
  and the human-facing landing page (`GET /`) are separate HTTP
  paths and would still exist. The marketing line *"100% DNS"*
  needs B + a registration-over-DNS milestone, not B alone.
- **Catchup is non-trivial new code.** Replacing 1300+ lines of
  Codex-hardened replication logic with a fresh wire format and
  a new protocol carries a real risk of silent regression.
- **Observability regression.** Loses the `curl /v1/sync/digest`
  debugging surface; replaces it with "query every record via
  `dig` and diff yourself."
- **6-9 weeks of opportunity cost** that displaces audit prep
  (M4.2-M4.4), reach work (M5.2/M5.3), and traffic-analysis
  hardening (M6) — all of which have larger user-visible payoffs.

Issue [#6](https://github.com/oscarvalenzuelab/DNSMeshProtocol/issues/6)
remains open as a tracker only. The decision is **not**
"deferred until we get around to it" — it is "rejected on the
current evidence; reopen only if a concrete operational forcing
function appears." Specifically, B becomes worth re-evaluating if
**any** of the following happens:

- A security audit finds the cluster HTTP path is
  attacker-reachable in a way the trust-domain framing doesn't
  address.
- An operator runs into TLS-cert-rotation failures on cluster
  peers severe enough to outweigh the metadata-confidentiality
  cost of moving to DNS.
- Cluster sizes grow past ~10 nodes per operator and the bearer-
  token-shared-between-peers auth model becomes the operational
  pain point.
- The protocol commits to "100% DNS" as a positioning goal
  AND scopes a registration-over-DNS milestone alongside, so B
  isn't a half-measure.

Until one of those happens, HTTP between cluster peers is the
right answer.

## Code references

- `dmp/server/anti_entropy.py` — the worker. Module docstring
  carries this boundary explanation.
- `dmp/cli.py` — `_build_cluster_writer_factory` constructs the
  per-node `_HttpWriter`. Docstring points back here.
- `dmp/cli.py` — `_make_client` already prefers `_DnsUpdateWriter`
  when the user has a TSIG block configured, so user-originated
  writes are DNS even in cluster mode (round-11 P1 fix).
