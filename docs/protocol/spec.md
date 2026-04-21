---
title: Spec overview
layout: default
parent: Protocol
nav_order: 0
---

# DMP protocol specification
{: .no_toc }

This page is the top-level reference for the DNS Mesh Protocol (DMP).
Per-record-type wire layouts, DNS naming conventions, and end-to-end
flows are broken into sibling pages; this page names the cross-cutting
invariants that every implementation must respect.

1. TOC
{:toc}

## 1. Purpose and scope

DMP is a store-and-forward **messaging protocol that rides DNS TXT
records** as its transport. The design premise is that DNS is the most
universally reachable substrate on the public internet: it traverses
NAT, survives corporate egress filters that break almost every other
port, and is served by resolvers in every jurisdiction.

DMP is:

- An end-to-end encrypted **delay-tolerant** messaging protocol. Senders
  publish ciphertext chunks and a signed manifest at predictable DNS
  owner names; receivers poll those owner names on their own schedule.
- Built on commodity authoritative DNS (BIND9, PowerDNS, Cloudflare,
  Route53, dnsmasq) with no non-standard DNS features required.
- Compatible with clusters of cooperating nodes under one operator,
  federated behind a signed [cluster manifest](cluster.md) and an
  optional upstream [bootstrap record](bootstrap.md).

DMP is **not**:

- A file-transfer system. Records are capped at 1200 wire bytes
  (see [wire-encoding](wire-encoding.md#wire-length-caps)); multi-KiB
  messages are supported via chunked manifests but the protocol is
  sized for text, not media.
- A real-time messaging protocol. DNS caching and polling cadence both
  introduce latency; DMP is deliberately delay-tolerant (minutes, not
  milliseconds).
- A group-messaging primitive. All traffic is 1:1 sender → recipient.
- An offline identity-recovery system. Identity material derives from
  `passphrase + salt` ([crypto.md](crypto.md#identity-derivation));
  losing the salt makes identities unrecoverable.

## 2. Versioning

Every DMP TXT record starts with an ASCII **wire prefix** of the form:

```
v=dmp1;t=<type>;
```

- `v=dmp1` — protocol version. A parser MUST reject any record whose
  version tag it does not understand. A future `v=dmp2` is reserved
  for a wire-breaking change and is not defined here.
- `t=<type>` — record type selector. The full registry is in §3.
- Trailing `;` (and optionally `d=` for types that carry a single
  base64 blob) follows the type tag. See
  [wire-encoding §Prefix conventions](wire-encoding.md#prefix-conventions)
  for the exact forms.

Unknown `v=` and `t=` values MUST cause the record to be dropped
silently. DMP treats unrecognized records as noise, not as errors.

## 3. Record type registry

The canonical registry of wire record types defined by DMP today:

| `t=` value  | Name                  | Wire prefix              | Spec page                              |
|-------------|-----------------------|--------------------------|----------------------------------------|
| `chunk`     | Ciphertext chunk      | `v=dmp1;t=chunk;d=`      | [wire-format §Chunks](wire-format.md#chunks) |
| `manifest`  | Slot manifest         | `v=dmp1;t=manifest;d=`   | [wire-format §Slot manifests](wire-format.md#slot-manifests) |
| `identity`  | Signed identity       | `v=dmp1;t=identity;d=`   | [wire-format §Identity records](wire-format.md#identity-records) |
| `prekey`    | One-time prekey       | `v=dmp1;t=prekey;d=`     | [wire-format §Prekeys](wire-format.md#prekeys) |
| `cluster`   | Cluster manifest      | `v=dmp1;t=cluster;`      | [cluster.md](cluster.md)               |
| `bootstrap` | Bootstrap record      | `v=dmp1;t=bootstrap;`    | [bootstrap.md](bootstrap.md)           |

Constants verified against `dmp/core/{manifest,identity,prekeys,cluster,
bootstrap}.py::RECORD_PREFIX` and
`dmp/core/chunking.py::MessageChunker.DATA_PER_CHUNK` docstring.

> **IMPLEMENTATION NOTE.** The `cluster` and `bootstrap` prefixes end
> at `;` (the body is emitted directly as a raw base64 string with no
> `d=` key), while `chunk`, `manifest`, `identity`, and `prekey` carry
> an explicit `d=<b64>` key-value after the prefix. This asymmetry
> exists because `chunk`, `manifest`, `identity`, and `prekey` predate
> the `DMPDNSRecord` key-value wrapper and the cluster / bootstrap
> record types were introduced later with a simpler base64-trailer
> layout. Both parsers strip their respective `RECORD_PREFIX` and
> base64-decode the remainder — no content difference — but a generic
> parser MUST key off the exact `RECORD_PREFIX` string, not assume a
> `d=` key is always present. See
> `dmp/core/cluster.py:57` and `dmp/core/bootstrap.py:60`.

## 4. Common invariants

Every signed DMP record type observes the following rules:

### 4.1 Wire prefix

Every record starts with `v=dmp1;t=<type>;` (see §2). The prefix is the
first thing a parser checks; mismatches are rejected before any further
decoding. See [wire-encoding §Prefix conventions](wire-encoding.md#prefix-conventions).

### 4.2 Base64 payload

The body + trailing Ed25519 signature is base64-encoded (standard
alphabet, with padding, `validate=True` on decode). The decoded blob
is split as `body = blob[:-64]`, `sig = blob[-64:]`. See
[wire-encoding §Base64 + signature layout](wire-encoding.md#base64-and-signature-layout).

### 4.3 Ed25519 signature placement

Every signed record carries a **trailing 64-byte Ed25519 signature**
over the body. This is uniform across every record type. Verified
against:

- `dmp/core/manifest.py:50` `_SIG_LEN = 64`
- `dmp/core/identity.py:37` `_SIG_LEN = 64`
- `dmp/core/prekeys.py:56` `_SIG_LEN = 64`
- `dmp/core/cluster.py:60` `_SIG_LEN = 64`
- `dmp/core/bootstrap.py:63` `_SIG_LEN = 64`

### 4.4 Embedded-signer cross-check

Records that carry a declared signer public key inside the body
(`sender_spk` on a slot manifest, `ed25519_spk` on an identity,
`operator_spk` on a cluster manifest, `signer_spk` on a bootstrap
record) MUST cross-check that embedded key against the caller-supplied
expected key in `parse_and_verify`. A record whose embedded key
disagrees with the expected one is rejected even if the signature
would otherwise verify against some other key. This defends against
accidentally passing the wrong pubkey (e.g. a config typo) producing a
false-accept.

Verified against:

- `dmp/core/cluster.py:553-558` (operator_spk embedded cross-check)
- `dmp/core/bootstrap.py:465-469` (signer_spk embedded cross-check)

Identity records are self-authenticating (the caller verifies against
the embedded `ed25519_spk` directly — there is no out-of-band expected
key, so the cross-check reduces to "verify against what the record
claims"). Slot manifests are likewise self-authenticating but the
**receiving client** applies a separate pinned-contact filter before
accepting the manifest (see [flows §Message receive](flows.md#message-receive)).

### 4.5 Expiry / timestamp enforcement

Records that carry an `exp` field (slot manifest, prekey, cluster
manifest, bootstrap record) MUST be rejected by `parse_and_verify` (or
by the caller immediately thereafter) when `exp < now`. Callers may
override `now` via a kwarg for deterministic tests. Verified:

- `dmp/core/cluster.py:562-564` (`manifest.exp < now_ts`)
- `dmp/core/bootstrap.py:472-474` (`record.exp < now_ts`)

### 4.6 DNS-name validation

Every field that ends up as part of a DNS owner name — `cluster_name`,
`cluster_base_domain`, `user_domain` — is validated against a shared
rule set:

- ASCII only (no IDN; the publishing path does not A-label encode).
- Each label 1..63 chars, letters / digits / `-` only, must not start
  or end with `-` (RFC 1123-style).
- No empty labels (rejects `""`, `".a"`, `"a..b"`, trailing `..`).
- A single trailing `.` is accepted (canonical FQDN form) and
  normalized away; doubled trailing dots are rejected.
- Byte cap per field (64 utf-8 bytes) on top of the per-label cap.

Verified in `dmp/core/cluster.py:80-134` (`_validate_dns_name`); the
bootstrap module imports the same function from `dmp.core.cluster` to
guarantee the two stay in lockstep (`dmp/core/bootstrap.py:58`).

### 4.7 Wire-length cap

Every record's signed wire form is capped at **1200 bytes** (measured
after prefix + base64 encoding, in UTF-8 bytes). `sign()` raises
`ValueError` on oversize and `parse_and_verify` returns `None` on
oversize. The cap is symmetric on sign and parse so a peer cannot
push a larger-than-limit record past a receiver. Verified:

- `dmp/core/cluster.py:141` `MAX_WIRE_LEN = 1200`
- `dmp/core/bootstrap.py:77` `MAX_WIRE_LEN = 1200`
- Slot manifest, identity, and prekey records are sized well below
  this cap by their fixed-width layouts
  (172, 108+username, and 108 bytes respectively; see
  [wire-format](wire-format.md)).

### 4.8 Multi-string TXT

Values exceeding 255 bytes are published as a DNS TXT RRset with
multiple character-strings. Readers reassemble with
`b"".join(rdata.strings)`. Every built-in publisher
(`DNSUpdatePublisher`, `CloudflarePublisher`, `Route53Publisher`,
`LocalDNSPublisher`, `InMemoryDNSStore`) handles the split
automatically; the split utility is
`dmp/network/dns_publisher.py::_split_txt_value`
(`dmp/network/dns_publisher.py:39`). See
[wire-encoding §Multi-string TXT](wire-encoding.md#multi-string-txt).

### 4.9 Symmetric sign / parse validation

Every validation check on the sign path (length caps, DNS-name
validity, non-empty-list requirements, duplicate detection) is
mirrored on the parse path. A correctly-signed record from a buggy or
malicious publisher that violates a sign-side invariant MUST still be
rejected at parse time. Verified in the `_validate()` / `from_body_bytes()`
bodies of each record type.

## 5. Trust model

DMP's trust model is layered. From the receiver's perspective, each
layer has its own out-of-band-pinned Ed25519 public key:

1. **Bootstrap signer** (zone operator). Signs the
   [bootstrap record](bootstrap.md) at `_dmp.<user_domain>`. Pinned
   out-of-band by the receiving client (CLI flow:
   `dmp bootstrap pin <user_domain> <fingerprint>`). Authority: "I am
   the domain operator; these are the clusters I endorse for this
   user domain."
2. **Cluster operator**. Signs the
   [cluster manifest](cluster.md) at `cluster.<cluster_base_domain>`.
   Pinned out-of-band or discovered via a verified bootstrap record.
   Authority: "I operate this cluster; these are its nodes."
3. **User signing identity** (Ed25519 identity key). Signs
   [identity records](wire-format.md#identity-records),
   [slot manifests](wire-format.md#slot-manifests), and
   [prekeys](wire-format.md#prekeys). Pinned out-of-band by contacts
   who want squat resistance; otherwise TOFU. Authority: "This
   message / these prekeys came from the user claiming this Ed25519
   key."

The chain runs *downward*: bootstrap → cluster manifest → records
inside the cluster. Compromise of one layer does **not** imply
compromise of a layer beneath or above it:

- Compromise of the bootstrap signer lets an attacker redirect a user
  domain to a hostile cluster, but the hostile cluster's manifest
  cannot forge records under an existing (non-compromised) cluster's
  name.
- Compromise of a cluster operator lets an attacker serve bogus
  records within *that* cluster, but cannot rewrite which cluster a
  user domain points at.
- Compromise of a user's Ed25519 identity lets an attacker sign
  messages as that user, but does not let them publish cluster or
  bootstrap records.

See [threat-model.md](threat-model.md) for the full enumeration of
defended and out-of-scope attacks.

## 6. Reference implementation

- **Parser / serializer code**: `dmp/core/`. Each record type is one
  module: `manifest.py`, `identity.py`, `prekeys.py`, `cluster.py`,
  `bootstrap.py`. Each exports `RECORD_PREFIX`, a dataclass with
  `sign()` and `parse_and_verify()` classmethods, and (where
  relevant) a `*_rrset_name()` helper that returns the DNS owner
  name.
- **Wire publishing**: `dmp/network/dns_publisher.py` (RFC 2136 DNS
  UPDATE, Cloudflare, Route53, local dnsmasq), plus
  `dmp/network/memory.py` for in-process testing.
- **Fan-out / union / composite**: `dmp/network/fanout_writer.py`,
  `union_reader.py`, `composite_reader.py` — the cluster-mode
  read/write path.
- **Client orchestration**: `dmp/client/client.py` (send / receive),
  `cluster_bootstrap.py` (cluster-mode refresh),
  `bootstrap_discovery.py` (user-domain → cluster fetch).
- **Interop test vectors**: `tests/test_*.py`. The test suite is the
  authoritative interop benchmark — an independent implementation
  should run against the same fixtures. Of particular interest for a
  new parser:
  - `tests/test_manifest.py` — slot manifest wire vectors.
  - `tests/test_identity.py` — identity wire vectors.
  - `tests/test_prekeys.py` — prekey wire vectors.
  - `tests/test_cluster_manifest.py` — cluster manifest wire vectors.
  - `tests/test_bootstrap_record.py` — bootstrap record wire vectors.

## 7. Cross-references

- [Wire encoding conventions](wire-encoding.md) — the exact byte-level
  rules for prefix, base64, signature placement, magic bytes, and
  multi-string TXT.
- [DNS name routing](routing.md) — how every record's owner name is
  computed.
- [End-to-end flows](flows.md) — the send, receive, publish, fetch,
  and discover sequences.
- [Threat model](threat-model.md) — defended attacks, residual
  risks, out-of-scope items.
- [Cryptography](crypto.md) — key-derivation, AEAD, AAD.
- [Cluster manifest](cluster.md) and [bootstrap record](bootstrap.md)
  — the two "discovery" record types that gate entry to the system.
