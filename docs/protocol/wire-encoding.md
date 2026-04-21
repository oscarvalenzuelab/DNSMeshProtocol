---
title: Wire encoding
layout: default
parent: Protocol
nav_order: 1
---

# Wire encoding conventions
{: .no_toc }

This page codifies the cross-cutting wire rules that apply to every
DMP record type. Per-record-type byte-by-byte layouts live on the
[slot manifest](wire-format.md), [cluster](cluster.md), and
[bootstrap](bootstrap.md) pages, and are cross-linked from
[spec.md §3](spec.md#3-record-type-registry).

1. TOC
{:toc}

## Prefix conventions

Every DMP TXT record starts with a stable ASCII prefix so a DMP-aware
resolver (or a generic resolver handing records to a DMP library) can
dispatch to the correct parser before any base64 decoding.

| Record type | `RECORD_PREFIX` (verbatim)       | Source                          |
|-------------|----------------------------------|---------------------------------|
| `chunk`     | `v=dmp1;t=chunk;d=`              | `dmp/core/chunking.py:44`       |
| `manifest`  | `v=dmp1;t=manifest;d=`           | `dmp/core/manifest.py:48`       |
| `identity`  | `v=dmp1;t=identity;d=`           | `dmp/core/identity.py:36`       |
| `prekey`    | `v=dmp1;t=prekey;d=`             | `dmp/core/prekeys.py:54`        |
| `cluster`   | `v=dmp1;t=cluster;`              | `dmp/core/cluster.py:57`        |
| `bootstrap` | `v=dmp1;t=bootstrap;`            | `dmp/core/bootstrap.py:60`      |

> **IMPLEMENTATION NOTE.** The `cluster` and `bootstrap` prefixes end
> at the type-terminating `;` with no `d=` key; the record body is
> emitted directly as raw base64 trailing the prefix. The `chunk`,
> `manifest`, `identity`, and `prekey` prefixes end with `d=` because
> they predate the cluster / bootstrap record types and use the older
> `DMPDNSRecord` key-value wrapping. Both parse identically after
> `RECORD_PREFIX` is stripped (base64 the remainder), but a generic
> parser MUST key off the full `RECORD_PREFIX` string rather than
> assuming a `d=` key is always present.

Parsers MUST reject any record that does not start with a known
`RECORD_PREFIX`. Unknown prefixes are silently dropped — they may
belong to a different DMP version or to an unrelated protocol that
happens to share the TXT RRset (some authoritative zones mix DMP
records with SPF, DKIM, verification tokens, etc.).

## Base64 and signature layout

After stripping `RECORD_PREFIX`, every DMP signed record is a single
base64 string (standard alphabet, with padding). Decoding rules:

- Use **`validate=True`** on the decoder so whitespace and
  non-alphabet characters fail loudly rather than being silently
  skipped. Verified in:
  - `dmp/core/cluster.py:528` `base64.b64decode(..., validate=True)`
  - `dmp/core/bootstrap.py:440` `base64.b64decode(..., validate=True)`
- Base64 decode errors MUST return `None` (not raise) from
  `parse_and_verify`. DNS is noisy; a single malformed record should
  not kill an RRset scan.

The decoded blob is always:

```
blob = body || signature         # len(signature) == 64
body = blob[:-64]
signature = blob[-64:]
```

The 64-byte Ed25519 signature is **always** the trailing 64 bytes of
the decoded blob. This is uniform across every signed record type and
is spelled out in `_SIG_LEN = 64` in each module. Verification MUST
happen against `body` before any fields inside `body` are parsed (so
`from_body_bytes()` is never fed an attacker-chosen byte sequence that
could trip a parser bug pre-signature-check). See e.g.
`dmp/core/cluster.py:538-552`:

```python
# 4. Verify signature against the caller-supplied operator key.
# This is the trust anchor — we do NOT parse body fields first.
if not DMPCrypto.verify_signature(body, signature, bytes(operator_spk)):
    return None
# 5. Unpack body.
try:
    manifest = cls.from_body_bytes(body)
except ValueError:
    return None
```

## Signed-body layout pattern

Every signed record body starts with a fixed-width header followed by
length-prefixed variable fields. The common pattern for records
introduced in M2+ (cluster, bootstrap) is:

```
magic(7) || seq(uint64 BE) || exp(uint64 BE) || signer_pubkey(32) ||
<type-specific length-prefixed variable fields>
```

Older records (manifest, identity, prekey) predate the `magic` +
`seq` + `exp` common header and use type-specific fixed layouts; see
per-record pages linked from [spec.md §3](spec.md#3-record-type-registry)
for exact byte offsets.

## Magic bytes

Record types with a fixed magic tag as the first 7 body bytes:

| Record type | `_MAGIC`     | Source                   |
|-------------|--------------|--------------------------|
| `cluster`   | `b"DMPCL01"` | `dmp/core/cluster.py:59` |
| `bootstrap` | `b"DMPBS01"` | `dmp/core/bootstrap.py:62` |

`DMPCL01` = "DMP CLuster, body revision 01". `DMPBS01` = "DMP BootStrap,
body revision 01". The `01` suffix reserves namespace for future body
revisions — bumping the magic is how the protocol can wire-evolve a
record type without bumping the `v=dmp1` version tag (though any such
bump MUST be documented as a compat break).

Records of types `manifest`, `identity`, `prekey`, and `chunk` do not
carry a magic header; their body length + field layout is
self-describing by position. A future body revision for those types
would be introduced as a new `t=` value rather than a new magic.

## Wire length caps

| Record type | Cap (wire bytes) | Enforcement (sign + parse) |
|-------------|------------------|----------------------------|
| `chunk`     | 255 (one TXT string) | `dmp/core/chunking.py:41-45` (sizing comment) |
| `manifest`  | 252 (fits one TXT string) | `dmp/core/manifest.py:22-23` (sizing comment) |
| `identity`  | variable, bounded by `_USERNAME_MAX=64` | `dmp/core/identity.py:41` |
| `prekey`    | 162 (fits one TXT string) | `dmp/core/prekeys.py:30-32` |
| `cluster`   | 1200 bytes | `dmp/core/cluster.py:141` `MAX_WIRE_LEN = 1200` |
| `bootstrap` | 1200 bytes | `dmp/core/bootstrap.py:77` `MAX_WIRE_LEN = 1200` |

The 1200-byte cap on cluster and bootstrap records is applied on
**both** sign (`sign()` raises `ValueError`) and parse
(`parse_and_verify` returns `None`). Asymmetric enforcement would let
a peer push a larger-than-limit record past a receiver that trusts
its own publisher.

## Multi-string TXT

DNS TXT records carry RDATA as a sequence of `<character-string>`
values, each prefixed by a single-byte length, so the maximum payload
per character-string is 255 bytes (RFC 1035 §3.3.14). A DMP record
whose wire form exceeds 255 bytes is emitted as **multiple
character-strings within the same RR** — not as a single over-long
string (many servers and clients either reject or truncate that).

The split utility is
`dmp/network/dns_publisher.py::_split_txt_value`
(`dmp/network/dns_publisher.py:39`). It splits on 255-byte boundaries
for ASCII-only values. Non-ASCII values exceeding 255 bytes are
rejected explicitly (a naive byte split can land mid-codepoint and
corrupt UTF-8); the caller should base64-encode non-ASCII payloads
before publishing. Every DMP record is pure ASCII (prefix is ASCII,
base64 body is ASCII), so this path is always safe for DMP today.

### Publisher behavior

- **`DNSUpdatePublisher`** (RFC 2136 / BIND9 / PowerDNS): passes the
  split list directly to `dns.rdata.from_text` with each chunk quoted.
- **`CloudflarePublisher`**: Cloudflare's API auto-splits the
  `content` field at 255-byte boundaries, so DMP can submit the
  unsplit value.
- **`Route53Publisher`**: Route53 requires TXT values as a
  space-separated sequence of quoted 255-byte chunks (e.g.
  `"part1" "part2"`), which the publisher constructs from the split
  list.
- **`LocalDNSPublisher`** (dnsmasq / BIND zone files): each split
  chunk is emitted as a separate quoted string on the same RR line.
- **`InMemoryDNSStore`** (test backend): stores the value as a
  single string; the split is only observable at serialization time.

### Reader behavior

dnspython represents a multi-string TXT RR as a tuple
`rdata.strings = (b"part1", b"part2", ...)`. DMP readers MUST
reassemble with:

```python
raw = b"".join(rdata.strings).decode("ascii")
```

before handing the value to any record's `parse_and_verify`. The
publisher split boundaries are **not** semantic — readers MUST NOT
rely on any particular chunk size or count.

## DNS-name validation rules

Every field that ends up as part of a DNS owner name
(`cluster_name`, `cluster_base_domain`, `user_domain`) is validated
against the shared `_validate_dns_name` rule set in
`dmp/core/cluster.py:80-134`. The `bootstrap` module imports the
same function (`dmp/core/bootstrap.py:58`) to guarantee zero drift.

Rules:

- **Non-empty** after stripping a single trailing `.` (canonical FQDN
  form is accepted; `cluster_rrset_name` / `bootstrap_rrset_name`
  already normalize).
- **ASCII only** — no IDN, because the publishing path does not
  A-label encode. Violation: `"café.example"` raises
  `ValueError("cluster_name must be ASCII (no IDN support)")`.
- **Each label 1..63 chars**, matching the RFC 1035 label octet cap.
  Verified at `dmp/core/cluster.py:77` `MAX_DNS_LABEL_LEN = 63`.
- **Letters / digits / `-` only**, and **labels must not start or end
  with `-`** (RFC 1123 §2.1). Enforced label-by-label at
  `dmp/core/cluster.py:116-134`.
- **No empty labels** — rejects `""`, `".a"`, `"a..b"`, and doubled
  trailing dots `"example.com.."`. Note that a single trailing dot
  `"example.com."` is *accepted* and stripped on both sign and parse
  so externally produced records compare equal to internally produced
  ones (`dmp/core/cluster.py:100-107`).
- **Byte cap 64 UTF-8 bytes** per field on top of the per-label cap
  (`MAX_CLUSTER_NAME_LEN = 64`, `MAX_USER_DOMAIN_LEN = 64`,
  `MAX_BASE_DOMAIN_LEN = 64`).

Validation happens on **both** sign and parse. A correctly-signed
record produced by a buggy publisher that carries an unpublishable
name MUST still be rejected at parse time
(`dmp/core/cluster.py:415`, `dmp/core/bootstrap.py:335`).

## Back-reference

- [spec.md](spec.md) — top-level reference; this page is the deep-dive
  companion to [spec.md §4 Common invariants](spec.md#4-common-invariants).
