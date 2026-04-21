"""Tests for signed bootstrap records (M3.1).

Covers:
- BootstrapEntry construction validation.
- Round-trip: sign -> wire -> parse -> verify with all fields preserved.
- Priority sorting: entries come out sorted by priority; best_entry()
  returns entries[0].
- Duplicate entry detection.
- Security: wrong-signer, tampered body/sig, mismatched embedded key,
  malformed prefix/base64/truncation all return None.
- Expiry: future accepted, past rejected, `now` kwarg override.
- Size: 1-entry and 16-entry realistic records fit under 1200 bytes;
  17 entries raises; empty entries list rejected.
- DNS-name validation on user_domain (identical semantics to
  ClusterManifest.cluster_name).
- expected_user_domain binding (case-insensitive, trailing-dot norm).
- bootstrap_rrset_name convention.
"""

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.bootstrap import (
    BootstrapEntry,
    BootstrapRecord,
    MAX_BASE_DOMAIN_LEN,
    MAX_ENTRY_COUNT,
    MAX_USER_DOMAIN_LEN,
    MAX_WIRE_LEN,
    RECORD_PREFIX,
    bootstrap_rrset_name,
)

# ---- fixtures / helpers ---------------------------------------------------


def _make_signer() -> DMPCrypto:
    return DMPCrypto()


def _make_spk() -> bytes:
    """Fresh Ed25519 pubkey bytes — doesn't matter whose, 32 bytes are 32 bytes."""
    return DMPCrypto().get_signing_public_key_bytes()


def _make_entry(
    priority: int = 10,
    cluster_base_domain: str = "mesh.example.com",
    operator_spk: bytes | None = None,
) -> BootstrapEntry:
    return BootstrapEntry(
        priority=priority,
        cluster_base_domain=cluster_base_domain,
        operator_spk=operator_spk if operator_spk is not None else _make_spk(),
    )


def _make_record(
    signer: DMPCrypto,
    entries: list[BootstrapEntry] | None = None,
    *,
    user_domain: str = "example.com",
    seq: int = 1,
    exp_delta: int = 3600,
) -> BootstrapRecord:
    return BootstrapRecord(
        user_domain=user_domain,
        signer_spk=signer.get_signing_public_key_bytes(),
        entries=entries if entries is not None else [_make_entry()],
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


# ---- BootstrapEntry -------------------------------------------------------


class TestBootstrapEntry:
    def test_construction_minimal(self):
        e = BootstrapEntry(
            priority=10,
            cluster_base_domain="mesh.example.com",
            operator_spk=b"\x00" * 32,
        )
        assert e.priority == 10
        assert e.cluster_base_domain == "mesh.example.com"
        assert e.operator_spk == b"\x00" * 32

    def test_roundtrip_bytes(self):
        original = _make_entry(priority=42, cluster_base_domain="mesh.example.com")
        body = original.to_body_bytes()
        parsed, offset = BootstrapEntry.from_body_bytes(body, 0)
        assert offset == len(body)
        assert parsed.priority == original.priority
        assert parsed.cluster_base_domain == original.cluster_base_domain
        assert parsed.operator_spk == original.operator_spk

    def test_priority_out_of_range_rejected(self):
        e = BootstrapEntry(
            priority=-1,
            cluster_base_domain="mesh.example.com",
            operator_spk=b"\x00" * 32,
        )
        with pytest.raises(ValueError, match="priority"):
            e.to_body_bytes()
        e2 = BootstrapEntry(
            priority=0x10000,
            cluster_base_domain="mesh.example.com",
            operator_spk=b"\x00" * 32,
        )
        with pytest.raises(ValueError, match="priority"):
            e2.to_body_bytes()

    def test_base_domain_too_long_rejected(self):
        # 62-char label + ".co" = 65 bytes, over MAX_BASE_DOMAIN_LEN=64.
        e = BootstrapEntry(
            priority=10,
            cluster_base_domain=("a" * 62) + ".co",
            operator_spk=b"\x00" * 32,
        )
        with pytest.raises(ValueError, match="cluster_base_domain too long"):
            e.to_body_bytes()

    def test_base_domain_empty_rejected(self):
        e = BootstrapEntry(
            priority=10,
            cluster_base_domain="",
            operator_spk=b"\x00" * 32,
        )
        with pytest.raises(ValueError, match="cluster_base_domain"):
            e.to_body_bytes()

    def test_operator_spk_wrong_length_rejected(self):
        e = BootstrapEntry(
            priority=10,
            cluster_base_domain="mesh.example.com",
            operator_spk=b"\x00" * 16,
        )
        with pytest.raises(ValueError, match="operator_spk"):
            e.to_body_bytes()

    def test_base_domain_dns_name_rules_enforced(self):
        # Underscore is rejected — same DNS-name rules as ClusterManifest.
        e = BootstrapEntry(
            priority=10,
            cluster_base_domain="mesh_bad.example.com",
            operator_spk=b"\x00" * 32,
        )
        with pytest.raises(ValueError, match="invalid character"):
            e.to_body_bytes()


# ---- round-trip -----------------------------------------------------------


class TestBootstrapRecord:
    def test_sign_parse_roundtrip(self):
        signer = _make_signer()
        e1 = _make_entry(priority=10, cluster_base_domain="primary.example.com")
        e2 = _make_entry(priority=20, cluster_base_domain="secondary.example.com")
        original = _make_record(
            signer,
            entries=[e1, e2],
            user_domain="example.com",
            seq=42,
        )
        wire = original.sign(signer)
        assert wire.startswith(RECORD_PREFIX)

        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.user_domain == original.user_domain
        assert parsed.signer_spk == original.signer_spk
        assert parsed.seq == original.seq
        assert parsed.exp == original.exp
        assert len(parsed.entries) == 2
        for p, o in zip(parsed.entries, [e1, e2]):
            assert p.priority == o.priority
            assert p.cluster_base_domain == o.cluster_base_domain
            assert p.operator_spk == o.operator_spk

    def test_entries_sorted_by_priority_after_sign(self):
        """Input entries with mixed priorities come out sorted; best_entry
        returns the priority-0 entry regardless of insertion order."""
        signer = _make_signer()
        e_hi = _make_entry(priority=100, cluster_base_domain="third.example.com")
        e_lo = _make_entry(priority=0, cluster_base_domain="first.example.com")
        e_mid = _make_entry(priority=50, cluster_base_domain="second.example.com")
        record = _make_record(signer, entries=[e_hi, e_lo, e_mid])
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert [e.priority for e in parsed.entries] == [0, 50, 100]
        assert parsed.best_entry().priority == 0
        assert parsed.best_entry().cluster_base_domain == "first.example.com"
        # Sign-side ordering too: the original record's entries were
        # sorted in-place by _validate().
        assert [e.priority for e in record.entries] == [0, 50, 100]

    def test_best_entry_with_tied_priorities_is_stable(self):
        """Ties resolve to insertion order — Python's sort is stable."""
        signer = _make_signer()
        e_a = _make_entry(priority=10, cluster_base_domain="a.example.com")
        e_b = _make_entry(priority=10, cluster_base_domain="b.example.com")
        e_c = _make_entry(priority=20, cluster_base_domain="c.example.com")
        record = _make_record(signer, entries=[e_a, e_b, e_c])
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.best_entry().cluster_base_domain == "a.example.com"
        # Second-choice on best-entry failure:
        assert parsed.entries[1].cluster_base_domain == "b.example.com"

    def test_duplicate_entry_rejected(self):
        """Two entries with the same (priority, cluster_base_domain) pair
        is a publisher mistake that wastes wire space; reject on sign."""
        signer = _make_signer()
        dup_a = _make_entry(priority=10, cluster_base_domain="mesh.example.com")
        dup_b = _make_entry(priority=10, cluster_base_domain="mesh.example.com")
        record = _make_record(signer, entries=[dup_a, dup_b])
        with pytest.raises(ValueError, match="duplicate entry"):
            record.sign(signer)

    def test_duplicate_priority_distinct_base_allowed(self):
        """SMTP MX allows ties; we do too. Only exact pair duplicates
        are rejected."""
        signer = _make_signer()
        e_a = _make_entry(priority=10, cluster_base_domain="a.example.com")
        e_b = _make_entry(priority=10, cluster_base_domain="b.example.com")
        record = _make_record(signer, entries=[e_a, e_b])
        # No raise.
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert len(parsed.entries) == 2

    def test_duplicate_entry_case_insensitive(self):
        """DNS owner names are case-insensitive, so entries with the
        same priority and base domain modulo case are still duplicates."""
        signer = _make_signer()
        e_a = _make_entry(priority=10, cluster_base_domain="Mesh.Example.COM")
        e_b = _make_entry(priority=10, cluster_base_domain="mesh.example.com")
        record = _make_record(signer, entries=[e_a, e_b])
        with pytest.raises(ValueError, match="duplicate entry"):
            record.sign(signer)

    def test_sign_mismatched_signer_spk_raises(self):
        """sign() insists the caller's key matches the declared signer_spk."""
        signer = _make_signer()
        other = _make_signer()
        record = BootstrapRecord(
            user_domain="example.com",
            signer_spk=other.get_signing_public_key_bytes(),
            entries=[_make_entry()],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="signing key"):
            record.sign(signer)


# ---- security -------------------------------------------------------------


class TestBootstrapRecordSecurity:
    def test_wrong_signer_rejected(self):
        real = _make_signer()
        impostor = _make_signer()
        record = _make_record(real)
        wire = record.sign(real)
        assert (
            BootstrapRecord.parse_and_verify(
                wire, impostor.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_body_rejected(self):
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        raw[0] ^= 0xFF  # flip magic
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            BootstrapRecord.parse_and_verify(
                tampered, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_body_mid_entry_rejected(self):
        signer = _make_signer()
        record = _make_record(
            signer,
            entries=[
                _make_entry(priority=10, cluster_base_domain="a.example.com"),
                _make_entry(priority=20, cluster_base_domain="b.example.com"),
            ],
        )
        wire = record.sign(signer)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        raw[len(raw) // 2] ^= 0xFF  # flip a byte somewhere in the middle
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            BootstrapRecord.parse_and_verify(
                tampered, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_signature_rejected(self):
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        raw[-1] ^= 0xFF
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            BootstrapRecord.parse_and_verify(
                tampered, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_embedded_signer_spk_must_match_arg(self):
        """Defense in depth: even with valid signature, embedded
        signer_spk must match the caller-supplied arg. Signing with key
        A and verifying with key B fails at step 4 (signature check),
        which is the same invariant."""
        a = _make_signer()
        b = _make_signer()
        record = _make_record(a)
        wire = record.sign(a)
        assert (
            BootstrapRecord.parse_and_verify(wire, b.get_signing_public_key_bytes())
            is None
        )

    def test_missing_prefix_rejected(self):
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        no_prefix = wire[len(RECORD_PREFIX) :]
        assert (
            BootstrapRecord.parse_and_verify(
                no_prefix, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_wrong_prefix_rejected(self):
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        wrong = "v=dmp1;t=cluster;" + wire[len(RECORD_PREFIX) :]
        assert (
            BootstrapRecord.parse_and_verify(
                wrong, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_malformed_base64_rejected(self):
        signer = _make_signer()
        bad = RECORD_PREFIX + "not-valid-base64!!!@@@"
        assert (
            BootstrapRecord.parse_and_verify(bad, signer.get_signing_public_key_bytes())
            is None
        )

    def test_empty_payload_rejected(self):
        signer = _make_signer()
        empty = RECORD_PREFIX + base64.b64encode(b"").decode("ascii")
        assert (
            BootstrapRecord.parse_and_verify(
                empty, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_truncated_body_rejected(self):
        """Truncated wire is rejected (returns None), not raised as an
        exception. The task explicitly mandates this: a peer pushing a
        truncated record must not crash the receiver."""
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        raw = base64.b64decode(wire[len(RECORD_PREFIX) :])
        truncated_raw = raw[:-80]
        truncated = RECORD_PREFIX + base64.b64encode(truncated_raw).decode("ascii")
        assert (
            BootstrapRecord.parse_and_verify(
                truncated, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_non_string_wire_rejected(self):
        signer = _make_signer()
        assert (
            BootstrapRecord.parse_and_verify(
                b"bytes-not-str", signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_non_bytes_signer_spk_rejected(self):
        signer = _make_signer()
        record = _make_record(signer)
        wire = record.sign(signer)
        assert BootstrapRecord.parse_and_verify(wire, "notbytes") is None  # type: ignore
        assert BootstrapRecord.parse_and_verify(wire, b"\x00" * 16) is None

    def test_bad_magic_rejected(self):
        """Hand-sign a body with wrong magic; sig verifies but
        from_body_bytes rejects."""
        signer = _make_signer()
        spk = signer.get_signing_public_key_bytes()
        seq = (1).to_bytes(8, "big")
        exp = (int(time.time()) + 3600).to_bytes(8, "big")
        name = b"example.com"
        entry_spk = _make_spk()
        base_name = b"mesh.example.com"
        body = (
            b"BADMAGX"  # 7 bytes, wrong magic
            + seq
            + exp
            + spk
            + len(name).to_bytes(1, "big")
            + name
            + (1).to_bytes(1, "big")  # entry_count = 1
            + (10).to_bytes(2, "big")  # priority
            + len(base_name).to_bytes(1, "big")
            + base_name
            + entry_spk
        )
        sig = signer.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        assert BootstrapRecord.parse_and_verify(wire, spk) is None


# ---- expiry ---------------------------------------------------------------


class TestBootstrapRecordExpiry:
    def test_future_exp_verifies(self):
        signer = _make_signer()
        record = _make_record(signer, exp_delta=3600)
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None

    def test_past_exp_returns_none(self):
        signer = _make_signer()
        now = int(time.time())
        record = BootstrapRecord(
            user_domain="example.com",
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_make_entry()],
            seq=1,
            exp=now - 10,
        )
        wire = record.sign(signer)
        assert (
            BootstrapRecord.parse_and_verify(
                wire, signer.get_signing_public_key_bytes()
            )
            is None
        )

    def test_now_kwarg_overrides_wall_clock(self):
        signer = _make_signer()
        now = int(time.time())
        record = BootstrapRecord(
            user_domain="example.com",
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_make_entry()],
            seq=1,
            exp=now + 3600,
        )
        wire = record.sign(signer)
        # now far in future -> expired.
        assert (
            BootstrapRecord.parse_and_verify(
                wire,
                signer.get_signing_public_key_bytes(),
                now=now + 7200,
            )
            is None
        )
        # now far in past -> not yet expired.
        parsed = BootstrapRecord.parse_and_verify(
            wire,
            signer.get_signing_public_key_bytes(),
            now=now,
        )
        assert parsed is not None

    def test_is_expired_helper(self):
        now = int(time.time())
        future = BootstrapRecord(
            user_domain="example.com",
            signer_spk=b"\x00" * 32,
            entries=[_make_entry()],
            seq=1,
            exp=now + 60,
        )
        past = BootstrapRecord(
            user_domain="example.com",
            signer_spk=b"\x00" * 32,
            entries=[_make_entry()],
            seq=1,
            exp=now - 60,
        )
        assert not future.is_expired()
        assert past.is_expired()


# ---- size -----------------------------------------------------------------


class TestBootstrapRecordSize:
    def test_one_entry_fits_comfortably(self):
        signer = _make_signer()
        record = _make_record(signer, entries=[_make_entry()])
        wire = record.sign(signer)
        wire_len = len(wire.encode("utf-8"))
        assert wire_len <= MAX_WIRE_LEN
        # 1-entry record is ~260 bytes — generously under cap.
        assert wire_len <= 400, f"1-entry wire is {wire_len} bytes, expected < 400"

    def test_sixteen_realistic_entries_fit(self):
        """Protocol gate: a MAX_ENTRY_COUNT=16 record with realistic
        base-domain widths serializes to <= MAX_WIRE_LEN=1200 bytes."""
        signer = _make_signer()
        # Realistic deployment: short cluster-base-domain labels like
        # `m01.ex.com`, `m02.ex.com`, ... Within 12 bytes each.
        entries = [
            BootstrapEntry(
                priority=i,
                cluster_base_domain=f"m{i:02d}.ex.com",
                operator_spk=_make_spk(),
            )
            for i in range(MAX_ENTRY_COUNT)
        ]
        record = _make_record(signer, entries=entries)
        wire = record.sign(signer)
        wire_len = len(wire.encode("utf-8"))
        assert (
            wire_len <= MAX_WIRE_LEN
        ), f"16-entry wire {wire_len} exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"

    def test_seventeen_entries_raises(self):
        """Above the MAX_ENTRY_COUNT protocol cap."""
        signer = _make_signer()
        entries = [
            BootstrapEntry(
                priority=i,
                cluster_base_domain=f"m{i:02d}.ex.com",
                operator_spk=_make_spk(),
            )
            for i in range(MAX_ENTRY_COUNT + 1)
        ]
        record = _make_record(signer, entries=entries)
        with pytest.raises(ValueError, match="too many entries"):
            record.sign(signer)

    def test_empty_entries_rejected(self):
        """Silent-data-loss guard: a 0-entry record gives clients nothing
        to pin and can paper over a publisher mistake."""
        signer = _make_signer()
        with pytest.raises(ValueError, match="at least one entry"):
            _make_record(signer, entries=[]).sign(signer)

    def test_oversized_wire_rejected_on_parse(self, monkeypatch):
        """Symmetric wire-length check: parse_and_verify rejects an
        oversized wire even when signature, base64, and body structure
        are otherwise valid. We have to relax MAX_WIRE_LEN during sign()
        to *produce* such a wire, then restore the real cap for the
        parse-side check."""
        import dmp.core.bootstrap as bootstrap_mod

        signer = _make_signer()
        # Fill MAX_ENTRY_COUNT with max-width base_domain to push past
        # 1200 bytes while staying within per-field caps.
        fat_base = "a" * 60 + ".co"  # 63 bytes, under MAX_BASE_DOMAIN_LEN=64
        assert len(fat_base) == 63
        entries = [
            BootstrapEntry(
                priority=i,
                cluster_base_domain=f"{i:02d}" + fat_base[2:],
                operator_spk=_make_spk(),
            )
            for i in range(MAX_ENTRY_COUNT)
        ]
        record = _make_record(signer, entries=entries)

        monkeypatch.setattr(bootstrap_mod, "MAX_WIRE_LEN", 100_000)
        wire = record.sign(signer)
        assert len(wire.encode("utf-8")) > 1200

        monkeypatch.setattr(bootstrap_mod, "MAX_WIRE_LEN", 1200)
        assert (
            BootstrapRecord.parse_and_verify(
                wire, signer.get_signing_public_key_bytes()
            )
            is None
        )

        # Sanity: same wire parses fine under relaxed cap.
        monkeypatch.setattr(bootstrap_mod, "MAX_WIRE_LEN", 100_000)
        assert (
            BootstrapRecord.parse_and_verify(
                wire, signer.get_signing_public_key_bytes()
            )
            is not None
        )

    def test_oversize_user_domain_raises(self):
        signer = _make_signer()
        record = BootstrapRecord(
            user_domain="a" * (MAX_USER_DOMAIN_LEN + 1),
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_make_entry()],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="user_domain"):
            record.sign(signer)


# ---- user_domain DNS-name validation --------------------------------------


class TestBootstrapRecordNameValidation:
    """Identical set to TestClusterManifestNameValidation in test_cluster.py
    — the two record types share the same DNS-name validator."""

    @pytest.mark.parametrize(
        "name",
        [
            "example.com",
            "a.b",
            "x.y.z.w",
            "node-1.mesh.example.com",
            "example.com.",  # canonical FQDN form
            "A.B.C",  # uppercase allowed
            "a1.b2.c3",  # digits
        ],
    )
    def test_valid_names_accepted(self, name):
        signer = _make_signer()
        record = _make_record(signer, user_domain=name)
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.user_domain == name.rstrip(".")

    def test_trailing_dot_roundtrips_and_rrset_strips_it(self):
        signer = _make_signer()
        record = _make_record(signer, user_domain="example.com.")
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire, signer.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert bootstrap_rrset_name(parsed.user_domain) == "_dmp.example.com"

    @pytest.mark.parametrize(
        "bad_name,reason_substr",
        [
            ("", "non-empty"),
            ("a" * 64, "63 chars"),
            ("under_score.example.com", "invalid character"),
            ("café.example.com", "ASCII"),
            ("mesh..example.com", "empty label"),
            (".example.com", "empty label"),
            ("-bad.example.com", "start or end with '-'"),
            ("bad-.example.com", "start or end with '-'"),
            ("example.com/", "invalid character"),
            ("example com", "invalid character"),
            ("example.com..", "empty label"),
        ],
    )
    def test_invalid_names_rejected(self, bad_name, reason_substr):
        signer = _make_signer()
        record = BootstrapRecord(
            user_domain=bad_name,
            signer_spk=signer.get_signing_public_key_bytes(),
            entries=[_make_entry()],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match=reason_substr):
            record.sign(signer)

    def test_externally_produced_trailing_dot_normalized_on_parse(self):
        """Hand-sign a body with `example.com.` in the wire; parsed form
        has the trailing dot stripped, matching our sign-side form."""
        signer = _make_signer()
        spk = signer.get_signing_public_key_bytes()
        name = b"example.com."
        entry_spk = _make_spk()
        base_name = b"mesh.example.com"
        body = (
            b"DMPBS01"
            + (1).to_bytes(8, "big")
            + (int(time.time()) + 3600).to_bytes(8, "big")
            + spk
            + len(name).to_bytes(1, "big")
            + name
            + (1).to_bytes(1, "big")
            + (10).to_bytes(2, "big")
            + len(base_name).to_bytes(1, "big")
            + base_name
            + entry_spk
        )
        sig = signer.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        parsed = BootstrapRecord.parse_and_verify(wire, spk)
        assert parsed is not None
        assert parsed.user_domain == "example.com"

    def test_externally_produced_64byte_entry_with_trailing_dot_parses(self):
        """Entry cluster_base_domain at the 64-byte boundary with a
        canonical FQDN trailing dot (65 bytes on wire) must parse —
        sign()'s cap is on the normalized form, parse must match so we
        interoperate with publishers that preserve the dot."""
        signer = _make_signer()
        spk = signer.get_signing_public_key_bytes()
        user_name = b"example.com"
        # 63 bytes of label content + trailing dot = 64 byte normalized,
        # 65 byte wire form.
        core = "a" * 55 + ".bcd.efg"  # 55 + 1 + 3 + 1 + 3 = 63 bytes
        entry_name_str = core + "a"  # 64 bytes of label content
        assert len(entry_name_str) == 64
        entry_wire_name = (entry_name_str + ".").encode("ascii")
        assert len(entry_wire_name) == 65
        entry_spk = _make_spk()
        body = (
            b"DMPBS01"
            + (1).to_bytes(8, "big")
            + (int(time.time()) + 3600).to_bytes(8, "big")
            + spk
            + len(user_name).to_bytes(1, "big")
            + user_name
            + (1).to_bytes(1, "big")
            + (10).to_bytes(2, "big")
            + len(entry_wire_name).to_bytes(1, "big")
            + entry_wire_name
            + entry_spk
        )
        sig = signer.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        parsed = BootstrapRecord.parse_and_verify(wire, spk)
        assert parsed is not None
        # Trailing dot stripped so it compares equal to sign-side form.
        assert parsed.entries[0].cluster_base_domain == entry_name_str


# ---- expected_user_domain binding ----------------------------------------


class TestBootstrapRecordBinding:
    def test_expected_user_domain_match(self):
        signer = _make_signer()
        record = _make_record(signer, user_domain="example.com")
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire,
            signer.get_signing_public_key_bytes(),
            expected_user_domain="example.com",
        )
        assert parsed is not None

    def test_expected_user_domain_mismatch_rejected(self):
        """Caller fetched at zone A but signed record is for zone B."""
        signer = _make_signer()
        record = _make_record(signer, user_domain="a.example.com")
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire,
            signer.get_signing_public_key_bytes(),
            expected_user_domain="b.example.com",
        )
        assert parsed is None

    def test_expected_user_domain_trailing_dot_normalized(self):
        signer = _make_signer()
        record = _make_record(signer, user_domain="example.com")
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire,
            signer.get_signing_public_key_bytes(),
            expected_user_domain="example.com.",
        )
        assert parsed is not None

    def test_expected_user_domain_case_insensitive(self):
        signer = _make_signer()
        record = _make_record(signer, user_domain="Example.COM")
        wire = record.sign(signer)
        parsed = BootstrapRecord.parse_and_verify(
            wire,
            signer.get_signing_public_key_bytes(),
            expected_user_domain="example.com",
        )
        assert parsed is not None


# ---- bootstrap_rrset_name ------------------------------------------------


class TestBootstrapRrsetName:
    def test_basic_convention(self):
        assert bootstrap_rrset_name("example.com") == "_dmp.example.com"

    def test_trailing_dot_stripped(self):
        assert bootstrap_rrset_name("example.com.") == "_dmp.example.com"

    def test_doubled_trailing_dot_rejected(self):
        with pytest.raises(ValueError, match="empty label"):
            bootstrap_rrset_name("example.com..")

    def test_invalid_names_rejected(self):
        for bad in (
            "",
            ".example.com",
            "mesh..example.com",
            "under_score.example.com",
            "café.example.com",
        ):
            with pytest.raises(ValueError):
                bootstrap_rrset_name(bad)
