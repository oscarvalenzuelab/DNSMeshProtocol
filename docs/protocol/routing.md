---
title: DNS name routing
layout: default
parent: Protocol
nav_order: 2
---

# DNS name routing
{: .no_toc }

Every DMP record has a deterministic DNS owner name. Senders and
recipients derive identical names from shared inputs (recipient
identity, message id, username, user domain, cluster name) without
prior coordination; the names themselves are the rendezvous.

This page tabulates every owner-name convention the protocol defines
today. Back-reference: [spec.md §3](spec.md#3-record-type-registry).
Per-record layouts and security properties live on the spec pages
linked from each row.

1. TOC
{:toc}

## Summary

| Record type     | DNS owner name                                           | Helper function                                                              |
|-----------------|----------------------------------------------------------|------------------------------------------------------------------------------|
| Mailbox slot    | `slot-<N>.mb-<hash12(recipient_id)>.<domain>`            | `DMPClient._slot_domain` (`dmp/client/client.py:136-137`)                    |
| Message chunk   | `chunk-<NNNN>-<msg_key>.<domain>`                        | `DMPClient._chunk_domain` (`dmp/client/client.py:143-144`)                   |
| Identity (hashed) | `id-<hash16(username)>.<domain>`                       | `identity_domain` (`dmp/core/identity.py:44-57`)                             |
| Identity (zone-anchored) | `dmp.<identity_domain>`                         | `zone_anchored_identity_name` (`dmp/core/identity.py:60-72`)                 |
| Prekey pool     | `prekeys.id-<hash12(username)>.<domain>`                 | `prekey_rrset_name` (`dmp/core/prekeys.py:60-67`)                            |
| Cluster manifest | `cluster.<cluster_base_domain>`                         | `cluster_rrset_name` (`dmp/core/cluster.py:144-158`)                         |
| Bootstrap record | `_dmp.<user_domain>`                                    | `bootstrap_rrset_name` (`dmp/core/bootstrap.py:80-94`)                       |

## Mailbox slots

```
slot-<N>.mb-<recipient_hash12>.<domain>
```

- `<N>` ∈ `0..9` — 10 slots per recipient. The sender picks a slot
  deterministically from the message id so load is roughly even
  across slots and a recipient always polls all 10 on each cycle.
  Slot selection: `int.from_bytes(msg_id[:4], "big") % SLOT_COUNT`
  (`dmp/client/client.py:418`, `SLOT_COUNT = 10`
  `dmp/client/client.py:24`).
- `<recipient_hash12>` — first 12 hex chars of
  `sha256(recipient_user_id)` where `recipient_user_id =
  sha256(recipient_x25519_pub)`. So the hash on the owner name is
  effectively `sha256(sha256(recipient_x25519_pub))[:12]`. Verified
  at `dmp/client/client.py:133-137`:

```python
@staticmethod
def _hash12(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:12]

def _slot_domain(self, recipient_id: bytes, slot: int) -> str:
    return f"slot-{slot}.mb-{self._hash12(recipient_id)}.{self.domain}"
```

### Sharding rationale

The 12-hex-char truncation (48 bits) and 10-slot fan-out exist to:

- Keep every mailbox owner name comfortably under the 63-char DNS
  label limit and the 253-char total-domain limit.
- Spread senders across multiple RRsets so no single slot RRset grows
  pathologically large. A single popular recipient receiving N
  messages is distributed across ~10 RRsets of size ~N/10.
- Avoid revealing the recipient's `user_id` (sha256 of their X25519
  pub) in the DNS label — 48-bit truncation is cheap against a
  targeted lookup but raises the cost of exhaustive enumeration.

> **IMPLEMENTATION NOTE.** There is a legacy helper in
> `dmp/core/dns.py:105-108` (`DNSEncoder.encode_mailbox_domain`)
> that returns `mb-<hash12>-<slot:02d>.<base>`. The current client
> does NOT use this form — the production path uses
> `slot-<N>.mb-<hash12>.<base>` as shown above. The legacy form is
> retained for back-compat with older tests and external callers;
> new publishers MUST emit the production form.

## Message chunks

```
chunk-<NNNN>-<msg_key>.<domain>
```

- `<NNNN>` — zero-padded 4-digit chunk index (`0000..total_chunks-1`).
  `total_chunks` is capped at `MAX_TOTAL_CHUNKS = 1024`
  (`dmp/core/manifest.py:64`).
- `<msg_key>` — `sha256(msg_id || recipient_id || sender_spk)[:12]`,
  as hex. Verified at `dmp/client/client.py:139-144`:

```python
@staticmethod
def _msg_key(msg_id: bytes, recipient_id: bytes, sender_spk: bytes) -> str:
    return hashlib.sha256(msg_id + recipient_id + sender_spk).hexdigest()[:12]

def _chunk_domain(self, msg_key: str, chunk_num: int) -> str:
    return f"chunk-{chunk_num:04d}-{msg_key}.{self.domain}"
```

The `msg_key` is an HMAC-style opaque tag derived from three inputs
the sender and the recipient both hold *after* the recipient has
parsed the signed manifest (which carries `msg_id`, `recipient_id`,
and `sender_spk` internally). A third party observing DNS traffic
cannot derive `msg_key` without knowing the sender's signing key and
the message id.

## Identity records

Two owner-name forms are defined. A client MAY publish at either (or
both) depending on their deployment.

### Hashed form (shared mesh domain)

```
id-<hash16(username)>.<domain>
```

- `<hash16(username)>` = `sha256(username.encode("utf-8"))[:16]` as
  hex (16 hex chars = 8 bytes = 64-bit truncation). Verified at
  `dmp/core/identity.py:56`:

```python
name_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:16]
return f"id-{name_hash}.{base_domain.rstrip('.')}"
```

- Used under a **shared mesh domain** (e.g. `mesh.example.com`)
  where many users co-resident on the zone and squatting is only
  mitigated by out-of-band fingerprint pinning. Anyone with publish
  access to the shared zone can publish a record claiming someone
  else's `username`; clients MUST rely on the embedded signature and
  their pinned contact list to distinguish.

### Zone-anchored form

```
dmp.<identity_domain>
```

- `<identity_domain>` is a zone the identity owner controls (e.g.
  `alice.example.com`). The address is written `user@identity_domain`
  (e.g. `alice@alice.example.com`). Verified at
  `dmp/core/identity.py:60-72`:

```python
def zone_anchored_identity_name(identity_domain_str: str) -> str:
    return f"dmp.{identity_domain_str.rstrip('.')}"
```

- The fetcher requires `record.username == address.user` so a zone
  owner cannot publish a body naming someone else under their zone
  (`dmp/cli.py` identity-fetch command applies this check; see
  [flows §Identity fetch](flows.md#identity-fetch)).

### Security tradeoff

The hashed form is convenient for shared-mesh deployments but offers
**no squat resistance** — anyone with zone-publish access can publish
a record claiming any username. The zone-anchored form pushes the
squat resistance into the zone-ownership layer: only the operator of
`alice.example.com` can publish at `dmp.alice.example.com`.

For production use with untrusted zone co-residents, prefer the
zone-anchored form. See
[security-model.md](security-model.md) for the pin / TOFU flow.

## Prekeys

```
prekeys.id-<hash12(username)>.<domain>
```

- `<hash12(username)>` = `sha256(username.encode("utf-8"))[:12]` as
  hex. Verified at `dmp/core/prekeys.py:60-67`:

```python
def prekey_rrset_name(username: str, base_domain: str) -> str:
    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]
    return f"prekeys.id-{username_hash}.{base_domain.rstrip('.')}"
```

- Many prekey records share the same owner name — the RRset is a
  pool of signed one-time prekeys, each a separate TXT value. The
  sender fetches all of them in one query and picks a random
  signature-verifying, non-expired entry.

> **IMPLEMENTATION NOTE.** The hash truncations differ between
> identity (`16 hex chars`) and prekeys (`12 hex chars`). This is
> historical — the prekey RRset was added later with the tighter
> truncation to leave more budget for the `prekeys.` prefix under
> the 63-char DNS label cap. Implementers MUST NOT assume a unified
> truncation width; each helper is the source of truth.

## Cluster manifest

```
cluster.<cluster_base_domain>
```

- `cluster_base_domain` is the DNS zone where the cluster's
  manifest TXT lives (e.g. `mesh.example.com`). Validated as a DNS
  name (see [wire-encoding §DNS-name validation rules](wire-encoding.md#dns-name-validation-rules)).
  Verified at `dmp/core/cluster.py:144-158`:

```python
def cluster_rrset_name(cluster_name: str) -> str:
    _validate_dns_name(cluster_name)
    normalized = cluster_name[:-1] if cluster_name.endswith(".") else cluster_name
    return f"cluster.{normalized}"
```

The helper is kept as a function so the convention can evolve
(e.g. to `_dmp-cluster.<cluster_name>` SRV-style) without churning
call sites.

## Bootstrap record

```
_dmp.<user_domain>
```

- `user_domain` is the user's email-address right-hand side (e.g.
  `example.com` for `alice@example.com`). The `_dmp` leading label
  follows the SMTP MX / DKIM / SPF convention of underscore-prefixed
  service labels. Validated as a DNS name. Verified at
  `dmp/core/bootstrap.py:80-94`:

```python
def bootstrap_rrset_name(user_domain: str) -> str:
    _validate_dns_name(user_domain)
    normalized = user_domain[:-1] if user_domain.endswith(".") else user_domain
    return f"_dmp.{normalized}"
```

The helper is a function for the same forward-compat reason as
`cluster_rrset_name`.

## Cross-references

- [Wire encoding](wire-encoding.md) — how a record's wire form is
  computed once its owner name is decided.
- [End-to-end flows](flows.md) — how these owner names are read and
  written in practice during send / receive / discover.
- [spec.md §3](spec.md#3-record-type-registry) — record-type
  registry with links back to each type's wire layout.
