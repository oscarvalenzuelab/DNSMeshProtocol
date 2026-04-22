# Wire-format test vectors

This directory holds the canonical byte-level test vectors for every
DMP record type. A third-party implementation verifies interop by
running these vectors: given the documented inputs, its `sign` routine
must produce the same `expected_wire_hex`, and its `parse_and_verify`
must return the documented result for the signature-failure / expired
cases.

## Files

| File | Record type | Cases |
|------|-------------|-------|
| `cluster_manifest.json`  | `ClusterManifest`  | round-trip, max-FQDN boundary (multi-string TXT), signature failure, expired |
| `bootstrap_record.json`  | `BootstrapRecord`  | round-trip, multi-entry boundary (multi-string TXT), signature failure, expired |
| `identity_record.json`   | `IdentityRecord`   | round-trip, 64-byte username boundary, signature failure (corrupt trailer) |
| `slot_manifest.json`     | `SlotManifest`     | round-trip (1 chunk, no prekey), 64-chunk erasure boundary, signature failure |
| `prekey.json`            | `Prekey`           | round-trip, max uint32 `prekey_id` boundary, signature failure, expired |

Each file is a JSON array of cases. Every case carries:

- `description` — short human-readable label.
- `expected_wire_hex` — the canonical wire bytes, hex-encoded. These
  are UTF-8 bytes of the wire string (`v=dmp1;t=<type>;...`), not the
  decoded base64 body.
- `inputs` OR `wire_from_case` — either the structured inputs needed
  to reconstruct the wire, or a pointer back to another case's wire
  (used by the signature-failure cases that share the round-trip wire
  with a different verification key).
- A seed field (`operator_seed_hex`, `signer_seed_hex`,
  `identity_seed_hex`, `sender_seed_hex`) — 32 bytes,
  `sha256("vectors/...")` of a short label, feeds into
  `DMPCrypto.from_private_bytes` to produce both halves of the
  identity deterministically.
- Outcome fields — one of `expected_parse_<field>` (on the success
  cases), `expected_parse_result: "none"` (on the failure cases),
  plus `verify_with_<key>_hex` or `verify_with_now` when the case
  wants a different verification context than the round-trip inputs.

## Regenerating

The generator is deterministic:

```bash
./venv/bin/python docs/protocol/vectors/_generate.py
```

Running it twice MUST produce byte-identical files. If it doesn't,
stop and fix the non-determinism before landing. The
`test_generator_is_reproducible` test in `tests/test_vectors.py`
guards this invariant.

## When the vectors go stale

If `tests/test_vectors.py` turns red after a change to `dmp/core/`,
ONE of these is true:

1. **The wire format was intentionally changed.** Regenerate the
   vectors, call out the break in `CHANGELOG.md`, and bump the
   protocol version in `spec.md` if the change is
   non-backwards-compatible (a new magic byte, an added field, a
   reordered field).
2. **The impl drifted unintentionally.** Fix the impl — the vectors
   are the source of truth. Every case here was reviewed and signed
   off on when it was added; a surprise wire-change means somebody
   broke interop.
