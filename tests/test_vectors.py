"""Golden wire-format vectors — the cross-implementation interop contract.

Every JSON file under ``docs/protocol/vectors/`` holds a list of test
cases covering one record type. Each case either:

1. Reconstructs the wire from a deterministic seed + structured inputs,
   signs it with the reference Python impl, and asserts the result is
   byte-identical to ``expected_wire_hex`` — OR
2. Takes the wire from another case (``wire_from_case``) or ships a
   pre-corrupted wire (``expected_wire_hex`` with an extra override
   field like ``verify_with_operator_spk_hex``) and asserts
   ``parse_and_verify`` returns the documented outcome.

When the Python impl changes the wire format, this suite turns red. If
the change is intentional, regenerate the vectors with
``docs/protocol/vectors/_generate.py`` AFTER confirming the change is
documented. If it's unintentional, fix the impl. The vectors are the
source of truth — third-party implementers verify against them.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from dmp.core.bootstrap import BootstrapEntry, BootstrapRecord
from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.core.crypto import DMPCrypto
from dmp.core.identity import IdentityRecord
from dmp.core.manifest import SlotManifest
from dmp.core.prekeys import Prekey
from dmp.core.rotation import RevocationRecord, RotationRecord

VECTORS_DIR = Path(__file__).resolve().parent.parent / "docs" / "protocol" / "vectors"


def _load(name: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _wire_from_hex(case: dict[str, Any]) -> str:
    return bytes.fromhex(case["expected_wire_hex"]).decode("utf-8")


# --- ClusterManifest --------------------------------------------------------


class TestClusterManifestVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("cluster_manifest")

    def test_round_trip_byte_identical(self, cases):
        case = cases[0]
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["operator_seed_hex"]))
        manifest = ClusterManifest(
            cluster_name=inputs["cluster_name"],
            operator_spk=bytes.fromhex(inputs["operator_spk_hex"]),
            nodes=[
                ClusterNode(
                    node_id=n["node_id"],
                    http_endpoint=n["http_endpoint"],
                    dns_endpoint=n.get("dns_endpoint"),
                )
                for n in inputs["nodes"]
            ],
            seq=inputs["seq"],
            exp=inputs["exp"],
        )
        assert manifest.sign(crypto) == _wire_from_hex(case)

    def test_boundary_fqdn_max_nodes_byte_identical(self, cases):
        case = cases[1]
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["operator_seed_hex"]))
        manifest = ClusterManifest(
            cluster_name=inputs["cluster_name"],
            operator_spk=bytes.fromhex(inputs["operator_spk_hex"]),
            nodes=[
                ClusterNode(
                    node_id=n["node_id"],
                    http_endpoint=n["http_endpoint"],
                    dns_endpoint=n.get("dns_endpoint"),
                )
                for n in inputs["nodes"]
            ],
            seq=inputs["seq"],
            exp=inputs["exp"],
        )
        wire = manifest.sign(crypto)
        assert wire == _wire_from_hex(case)
        # Confirm it's actually in multi-string territory.
        assert len(wire) > 255

    def test_signature_failure_wrong_operator(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        wrong_op = bytes.fromhex(case["verify_with_operator_spk_hex"])
        assert ClusterManifest.parse_and_verify(wire, wrong_op) is None

    def test_expired_rejected(self, cases):
        case = cases[3]
        wire = _wire_from_hex(case)
        op_spk = bytes.fromhex(case["inputs"]["operator_spk_hex"])
        assert (
            ClusterManifest.parse_and_verify(wire, op_spk, now=case["verify_with_now"])
            is None
        )


# --- BootstrapRecord --------------------------------------------------------


class TestBootstrapRecordVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("bootstrap_record")

    def _build(self, case: dict[str, Any]) -> tuple[str, BootstrapRecord, DMPCrypto]:
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["signer_seed_hex"]))
        rec = BootstrapRecord(
            user_domain=inputs["user_domain"],
            signer_spk=bytes.fromhex(inputs["signer_spk_hex"]),
            entries=[
                BootstrapEntry(
                    priority=e["priority"],
                    cluster_base_domain=e["cluster_base_domain"],
                    operator_spk=bytes.fromhex(e["operator_spk_hex"]),
                )
                for e in inputs["entries"]
            ],
            seq=inputs["seq"],
            exp=inputs["exp"],
        )
        return rec.sign(crypto), rec, crypto

    def test_round_trip_byte_identical(self, cases):
        case = cases[0]
        wire, _, _ = self._build(case)
        assert wire == _wire_from_hex(case)

    def test_boundary_multi_entry_byte_identical(self, cases):
        case = cases[1]
        wire, _, _ = self._build(case)
        assert wire == _wire_from_hex(case)
        assert len(wire) > 255

    def test_signature_failure_wrong_signer(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        wrong_spk = bytes.fromhex(case["verify_with_signer_spk_hex"])
        assert BootstrapRecord.parse_and_verify(wire, wrong_spk) is None

    def test_expired_rejected(self, cases):
        case = cases[3]
        wire = _wire_from_hex(case)
        spk = bytes.fromhex(case["inputs"]["signer_spk_hex"])
        assert (
            BootstrapRecord.parse_and_verify(wire, spk, now=case["verify_with_now"])
            is None
        )


# --- IdentityRecord ---------------------------------------------------------


class TestIdentityRecordVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("identity_record")

    def _build(self, case: dict[str, Any]) -> str:
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["identity_seed_hex"]))
        rec = IdentityRecord(
            username=inputs["username"],
            x25519_pk=bytes.fromhex(inputs["x25519_pk_hex"]),
            ed25519_spk=bytes.fromhex(inputs["ed25519_spk_hex"]),
            ts=inputs["ts"],
        )
        return rec.sign(crypto)

    def test_round_trip_byte_identical(self, cases):
        case = cases[0]
        assert self._build(case) == _wire_from_hex(case)

    def test_boundary_username_max_byte_identical(self, cases):
        case = cases[1]
        assert self._build(case) == _wire_from_hex(case)

    def test_signature_failure_corrupt_trailer(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        assert IdentityRecord.parse_and_verify(wire) is None


# --- SlotManifest -----------------------------------------------------------


class TestSlotManifestVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("slot_manifest")

    def _build(self, case: dict[str, Any]) -> str:
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["sender_seed_hex"]))
        m = SlotManifest(
            msg_id=bytes.fromhex(inputs["msg_id_hex"]),
            sender_spk=bytes.fromhex(inputs["sender_spk_hex"]),
            recipient_id=bytes.fromhex(inputs["recipient_id_hex"]),
            total_chunks=inputs["total_chunks"],
            data_chunks=inputs["data_chunks"],
            prekey_id=inputs["prekey_id"],
            ts=inputs["ts"],
            exp=inputs["exp"],
        )
        return m.sign(crypto)

    def test_round_trip_byte_identical(self, cases):
        case = cases[0]
        assert self._build(case) == _wire_from_hex(case)

    def test_boundary_64_chunks_byte_identical(self, cases):
        case = cases[1]
        assert self._build(case) == _wire_from_hex(case)

    def test_signature_failure_corrupt_trailer(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        assert SlotManifest.parse_and_verify(wire) is None


# --- Prekey -----------------------------------------------------------------


class TestPrekeyVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("prekey")

    def _build(self, case: dict[str, Any]) -> str:
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["signer_seed_hex"]))
        pk = Prekey(
            prekey_id=inputs["prekey_id"],
            public_key=bytes.fromhex(inputs["public_key_hex"]),
            exp=inputs["exp"],
        )
        return pk.sign(crypto)

    def test_round_trip_byte_identical(self, cases):
        case = cases[0]
        assert self._build(case) == _wire_from_hex(case)

    def test_boundary_max_prekey_id_byte_identical(self, cases):
        case = cases[1]
        assert self._build(case) == _wire_from_hex(case)

    def test_signature_failure_wrong_signer(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        wrong_spk = bytes.fromhex(case["verify_with_signer_spk_hex"])
        assert Prekey.parse_and_verify(wire, wrong_spk) is None

    def test_expired_still_parses_but_is_expired(self, cases):
        case = cases[3]
        wire = _wire_from_hex(case)
        spk = bytes.fromhex(case["verify_with_signer_spk_hex"])
        pk = Prekey.parse_and_verify(wire, spk)
        assert pk is not None
        # Prekey.parse_and_verify does not enforce expiry — caller does.
        assert pk.is_expired(now=case["inputs"]["exp"] + 1)


# --- RotationRecord (EXPERIMENTAL — M5.4) -----------------------------------


class TestRotationRecordVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("rotation_record")

    def _build(self, case: dict[str, Any]) -> str:
        inputs = case["inputs"]
        old_crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["old_seed_hex"]))
        new_crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["new_seed_hex"]))
        rec = RotationRecord(
            subject_type=inputs["subject_type"],
            subject=inputs["subject"],
            old_spk=bytes.fromhex(inputs["old_spk_hex"]),
            new_spk=bytes.fromhex(inputs["new_spk_hex"]),
            seq=inputs["seq"],
            ts=inputs["ts"],
            exp=inputs["exp"],
        )
        return rec.sign(old_crypto, new_crypto)

    def test_round_trip_user_byte_identical(self, cases):
        case = cases[0]
        assert self._build(case) == _wire_from_hex(case)

    def test_round_trip_cluster_byte_identical(self, cases):
        case = cases[1]
        assert self._build(case) == _wire_from_hex(case)

    def test_round_trip_bootstrap_byte_identical(self, cases):
        case = cases[2]
        assert self._build(case) == _wire_from_hex(case)

    def test_cosign_failure_rejected(self, cases):
        case = cases[3]
        wire = _wire_from_hex(case)
        assert RotationRecord.parse_and_verify(wire) is None

    def test_expired_rejected(self, cases):
        case = cases[4]
        wire = _wire_from_hex(case)
        assert (
            RotationRecord.parse_and_verify(wire, now=case["verify_with_now"]) is None
        )


# --- RevocationRecord (EXPERIMENTAL — M5.4) ---------------------------------


class TestRevocationRecordVectors:
    @pytest.fixture(scope="class")
    def cases(self) -> list[dict[str, Any]]:
        return _load("revocation_record")

    def _build(self, case: dict[str, Any]) -> str:
        inputs = case["inputs"]
        crypto = DMPCrypto.from_private_bytes(bytes.fromhex(case["revoked_seed_hex"]))
        rec = RevocationRecord(
            subject_type=inputs["subject_type"],
            subject=inputs["subject"],
            revoked_spk=bytes.fromhex(inputs["revoked_spk_hex"]),
            reason_code=inputs["reason_code"],
            ts=inputs["ts"],
        )
        return rec.sign(crypto)

    def test_round_trip_user_byte_identical(self, cases):
        case = cases[0]
        wire = self._build(case)
        assert wire == _wire_from_hex(case)
        # And parse-with-now-in-range succeeds.
        parsed = RevocationRecord.parse_and_verify(wire, now=case["verify_with_now"])
        assert parsed is not None

    def test_round_trip_cluster_byte_identical(self, cases):
        case = cases[1]
        assert self._build(case) == _wire_from_hex(case)

    def test_binding_failure_wrong_revoked_spk(self, cases):
        case = cases[2]
        wire = _wire_from_hex(case)
        wrong = bytes.fromhex(case["verify_with_expected_revoked_spk_hex"])
        assert (
            RevocationRecord.parse_and_verify(
                wire,
                expected_revoked_spk=wrong,
                now=case["verify_with_now"],
            )
            is None
        )

    def test_stale_revocation_rejected(self, cases):
        case = cases[3]
        wire = _wire_from_hex(case)
        assert (
            RevocationRecord.parse_and_verify(wire, now=case["verify_with_now"]) is None
        )


# --- Regen-sanity: make sure every JSON file can be parsed. -----------------


@pytest.mark.parametrize(
    "name",
    [
        "cluster_manifest",
        "bootstrap_record",
        "identity_record",
        "slot_manifest",
        "prekey",
        "rotation_record",
        "revocation_record",
    ],
)
def test_vector_file_is_well_formed(name: str):
    cases = _load(name)
    assert isinstance(cases, list) and cases, f"{name}.json must be a non-empty list"
    for case in cases:
        assert "description" in case
        assert "expected_wire_hex" in case
        # Round-tripping the hex back and forth catches corruption.
        hex_str = case["expected_wire_hex"]
        assert hex_str == bytes.fromhex(hex_str).hex()


def test_generator_is_reproducible(tmp_path):
    """Running the generator twice MUST produce byte-identical files.

    Non-determinism breaks the interop contract — a third-party impl
    that matches the vectors today should still match them tomorrow if
    no one changed the wire format.
    """
    import importlib.util
    import sys

    before = {
        p.name: p.read_bytes() for p in VECTORS_DIR.iterdir() if p.suffix == ".json"
    }

    spec = importlib.util.spec_from_file_location(
        "vectors_generate", VECTORS_DIR / "_generate.py"
    )
    module = importlib.util.module_from_spec(spec)
    # Redirect writes to tmp_path by monkey-patching VECTORS_DIR.
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[arg-type]
    try:
        module.VECTORS_DIR = tmp_path
        module.main()
    finally:
        sys.modules.pop("vectors_generate", None)

    after = {p.name: p.read_bytes() for p in tmp_path.iterdir() if p.suffix == ".json"}
    assert set(before.keys()) == set(after.keys())
    for name in before:
        assert (
            before[name] == after[name]
        ), f"{name} differs between generator runs — non-determinism introduced"
