"""Deterministic generator for the canonical wire-format test vectors.

Third-party implementers verify against the JSON files in this directory
to prove byte-level interop with the reference Python implementation.
Running this script must be reproducible — identical inputs must
produce byte-identical ``expected_wire_hex`` values. Non-determinism
would turn every regen into a noisy diff even when the wire format did
not actually change.

To regenerate:

    ./venv/bin/python docs/protocol/vectors/_generate.py

The ``tests/test_vectors.py`` suite then asserts that the current code
still produces the same wires from the same inputs.

Design choices:
- Every seed is a 32-byte value derived from a short human-readable
  label (``sha256(label)``), so a vector's operator / signer key is
  immediately traceable to the label without shipping the raw private
  bytes around. DMPCrypto.from_private_bytes accepts a 32-byte X25519
  seed and deterministically derives the Ed25519 signing key from it.
- Timestamps are fixed UNIX seconds. ``2035-01-01T00:00:00Z`` for
  ``exp`` (still future at test time; adjust in ~2030); ``ts`` and
  signature timestamps use epoch values that are round numbers.
- Signature-failure and expired cases re-use the round-trip inputs but
  flip one critical byte or roll ``exp`` back to 1970.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from dmp.core.bootstrap import BootstrapEntry, BootstrapRecord
from dmp.core.cluster import ClusterManifest, ClusterNode
from dmp.core.crypto import DMPCrypto
from dmp.core.identity import IdentityRecord
from dmp.core.manifest import SlotManifest
from dmp.core.prekeys import Prekey
from dmp.core.rotation import (
    REASON_COMPROMISE,
    REASON_ROUTINE,
    RevocationRecord,
    RotationRecord,
    SUBJECT_TYPE_BOOTSTRAP_SIGNER,
    SUBJECT_TYPE_CLUSTER_OPERATOR,
    SUBJECT_TYPE_USER_IDENTITY,
)

VECTORS_DIR = Path(__file__).parent

# Fixed, obviously-not-real future timestamp. ts=2030-01-01, exp=2035-01-01.
TS_2030 = 1893456000  # 2030-01-01T00:00:00Z
EXP_2035 = 2051222400  # 2035-01-01T00:00:00Z
EXP_EXPIRED = 100  # 1970-01-01T00:01:40Z — rejected by any reasonable now()


def seed_from_label(label: str) -> bytes:
    """Deterministic 32-byte seed from a human-readable label."""
    return hashlib.sha256(label.encode("utf-8")).digest()


def crypto_from_label(label: str) -> DMPCrypto:
    """Build a DMPCrypto identity from a label."""
    return DMPCrypto.from_private_bytes(seed_from_label(label))


# --- ClusterManifest --------------------------------------------------------


def gen_cluster_manifest_cases() -> list[dict[str, Any]]:
    op = crypto_from_label("vectors/cluster/operator")
    op_spk = op.get_signing_public_key_bytes()
    op_seed = seed_from_label("vectors/cluster/operator")

    cases: list[dict[str, Any]] = []

    # 1. Minimal round-trip: 1 node.
    manifest_min = ClusterManifest(
        cluster_name="mesh.example.com",
        operator_spk=op_spk,
        nodes=[
            ClusterNode(
                node_id="n01",
                http_endpoint="https://n1.example.com:8053",
            )
        ],
        seq=1,
        exp=EXP_2035,
    )
    wire_min = manifest_min.sign(op)
    cases.append(
        {
            "description": "round-trip: minimal 1-node cluster",
            "operator_seed_hex": op_seed.hex(),
            "inputs": {
                "cluster_name": "mesh.example.com",
                "operator_spk_hex": op_spk.hex(),
                "nodes": [
                    {
                        "node_id": "n01",
                        "http_endpoint": "https://n1.example.com:8053",
                        "dns_endpoint": None,
                    }
                ],
                "seq": 1,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_min.encode("utf-8").hex(),
            "expected_parse_cluster_name": "mesh.example.com",
            "expected_parse_seq": 1,
        }
    )

    # 2. Boundary: max cluster_name length (64 ASCII bytes) + 4 nodes.
    #    Each label <= 63 chars; 4 x "a"*15 + 3 dots = 63 chars, so we
    #    build a FQDN that hits exactly 64 bytes after normalization.
    label = "a" * 15  # 15 chars
    max_name = ".".join([label, label, label, label])  # 15*4 + 3 = 63 bytes
    # Grow to exactly 64 utf-8 bytes — extend final label by one char.
    max_name = max_name + "b"  # 64 bytes
    assert len(max_name.encode("utf-8")) == 64
    nodes = [
        ClusterNode(
            node_id=f"n{i:02d}",
            http_endpoint=f"https://n{i}.example.com:8053",
            dns_endpoint=f"203.0.113.{i}:53",
        )
        for i in range(1, 5)
    ]
    manifest_max = ClusterManifest(
        cluster_name=max_name,
        operator_spk=op_spk,
        nodes=nodes,
        seq=42,
        exp=EXP_2035,
    )
    wire_max = manifest_max.sign(op)
    cases.append(
        {
            "description": (
                "boundary: cluster_name at 64-byte FQDN cap with 4 nodes "
                "(multi-string TXT territory)"
            ),
            "operator_seed_hex": op_seed.hex(),
            "inputs": {
                "cluster_name": max_name,
                "operator_spk_hex": op_spk.hex(),
                "nodes": [
                    {
                        "node_id": n.node_id,
                        "http_endpoint": n.http_endpoint,
                        "dns_endpoint": n.dns_endpoint,
                    }
                    for n in nodes
                ],
                "seq": 42,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_max.encode("utf-8").hex(),
            "expected_parse_cluster_name": max_name,
            "expected_parse_seq": 42,
            "expected_multi_string": len(wire_max) > 255,
        }
    )

    # 3. Signature-failure: wire from case 1, but caller supplies a
    #    DIFFERENT operator_spk. parse_and_verify must return None.
    wrong_op = crypto_from_label("vectors/cluster/wrong-operator")
    wrong_op_spk = wrong_op.get_signing_public_key_bytes()
    cases.append(
        {
            "description": "signature failure: correct wire, wrong operator_spk",
            "operator_seed_hex": op_seed.hex(),
            "wire_from_case": 0,  # reuse case 0's wire
            "expected_wire_hex": wire_min.encode("utf-8").hex(),
            "verify_with_operator_spk_hex": wrong_op_spk.hex(),
            "expected_parse_result": "none",
        }
    )

    # 4. Expired case: same shape as case 1, exp rolled back to 1970.
    manifest_expired = ClusterManifest(
        cluster_name="mesh.example.com",
        operator_spk=op_spk,
        nodes=[
            ClusterNode(
                node_id="n01",
                http_endpoint="https://n1.example.com:8053",
            )
        ],
        seq=1,
        exp=EXP_EXPIRED,
    )
    wire_expired = manifest_expired.sign(op)
    cases.append(
        {
            "description": "expired: exp in the distant past is rejected",
            "operator_seed_hex": op_seed.hex(),
            "inputs": {
                "cluster_name": "mesh.example.com",
                "operator_spk_hex": op_spk.hex(),
                "nodes": [
                    {
                        "node_id": "n01",
                        "http_endpoint": "https://n1.example.com:8053",
                        "dns_endpoint": None,
                    }
                ],
                "seq": 1,
                "exp": EXP_EXPIRED,
            },
            "expected_wire_hex": wire_expired.encode("utf-8").hex(),
            "verify_with_now": EXP_EXPIRED + 1,
            "expected_parse_result": "none",
        }
    )

    return cases


# --- BootstrapRecord --------------------------------------------------------


def gen_bootstrap_record_cases() -> list[dict[str, Any]]:
    signer = crypto_from_label("vectors/bootstrap/signer")
    signer_spk = signer.get_signing_public_key_bytes()
    signer_seed = seed_from_label("vectors/bootstrap/signer")

    cluster_op = crypto_from_label("vectors/bootstrap/cluster-operator")
    cluster_op_spk = cluster_op.get_signing_public_key_bytes()

    cases: list[dict[str, Any]] = []

    # 1. Minimal round-trip: 1 entry.
    rec_min = BootstrapRecord(
        user_domain="example.com",
        signer_spk=signer_spk,
        entries=[
            BootstrapEntry(
                priority=10,
                cluster_base_domain="mesh.example.com",
                operator_spk=cluster_op_spk,
            ),
        ],
        seq=1,
        exp=EXP_2035,
    )
    wire_min = rec_min.sign(signer)
    cases.append(
        {
            "description": "round-trip: minimal 1-entry bootstrap",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "user_domain": "example.com",
                "signer_spk_hex": signer_spk.hex(),
                "entries": [
                    {
                        "priority": 10,
                        "cluster_base_domain": "mesh.example.com",
                        "operator_spk_hex": cluster_op_spk.hex(),
                    }
                ],
                "seq": 1,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_min.encode("utf-8").hex(),
            "expected_parse_user_domain": "example.com",
            "expected_parse_seq": 1,
        }
    )

    # 2. Boundary: 4 entries of priorities 10/20/30/40, large base domains.
    entries = [
        BootstrapEntry(
            priority=p,
            cluster_base_domain=f"mesh{idx}.example.com",
            operator_spk=crypto_from_label(
                f"vectors/bootstrap/cluster-op-{idx}"
            ).get_signing_public_key_bytes(),
        )
        for idx, p in enumerate([10, 20, 30, 40], start=1)
    ]
    rec_boundary = BootstrapRecord(
        user_domain="corp.example.com",
        signer_spk=signer_spk,
        entries=entries,
        seq=7,
        exp=EXP_2035,
    )
    wire_boundary = rec_boundary.sign(signer)
    cases.append(
        {
            "description": "boundary: 4 entries; multi-string TXT territory",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "user_domain": "corp.example.com",
                "signer_spk_hex": signer_spk.hex(),
                "entries": [
                    {
                        "priority": e.priority,
                        "cluster_base_domain": e.cluster_base_domain,
                        "operator_spk_hex": bytes(e.operator_spk).hex(),
                    }
                    for e in entries
                ],
                "seq": 7,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_boundary.encode("utf-8").hex(),
            "expected_parse_user_domain": "corp.example.com",
            "expected_parse_seq": 7,
            "expected_multi_string": len(wire_boundary) > 255,
        }
    )

    # 3. Signature failure: correct wire, wrong signer_spk.
    wrong_signer = crypto_from_label("vectors/bootstrap/wrong-signer")
    wrong_signer_spk = wrong_signer.get_signing_public_key_bytes()
    cases.append(
        {
            "description": "signature failure: correct wire, wrong signer_spk",
            "signer_seed_hex": signer_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": wire_min.encode("utf-8").hex(),
            "verify_with_signer_spk_hex": wrong_signer_spk.hex(),
            "expected_parse_result": "none",
        }
    )

    # 4. Expired.
    rec_expired = BootstrapRecord(
        user_domain="example.com",
        signer_spk=signer_spk,
        entries=[
            BootstrapEntry(
                priority=10,
                cluster_base_domain="mesh.example.com",
                operator_spk=cluster_op_spk,
            ),
        ],
        seq=1,
        exp=EXP_EXPIRED,
    )
    wire_expired = rec_expired.sign(signer)
    cases.append(
        {
            "description": "expired: exp in the distant past is rejected",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "user_domain": "example.com",
                "signer_spk_hex": signer_spk.hex(),
                "entries": [
                    {
                        "priority": 10,
                        "cluster_base_domain": "mesh.example.com",
                        "operator_spk_hex": cluster_op_spk.hex(),
                    }
                ],
                "seq": 1,
                "exp": EXP_EXPIRED,
            },
            "expected_wire_hex": wire_expired.encode("utf-8").hex(),
            "verify_with_now": EXP_EXPIRED + 1,
            "expected_parse_result": "none",
        }
    )

    return cases


# --- IdentityRecord ---------------------------------------------------------


def gen_identity_record_cases() -> list[dict[str, Any]]:
    alice = crypto_from_label("vectors/identity/alice")
    alice_seed = seed_from_label("vectors/identity/alice")

    cases: list[dict[str, Any]] = []

    # 1. Round-trip.
    rec = IdentityRecord(
        username="alice",
        x25519_pk=alice.get_public_key_bytes(),
        ed25519_spk=alice.get_signing_public_key_bytes(),
        ts=TS_2030,
    )
    wire = rec.sign(alice)
    cases.append(
        {
            "description": "round-trip: minimal identity for alice",
            "identity_seed_hex": alice_seed.hex(),
            "inputs": {
                "username": "alice",
                "x25519_pk_hex": alice.get_public_key_bytes().hex(),
                "ed25519_spk_hex": alice.get_signing_public_key_bytes().hex(),
                "ts": TS_2030,
            },
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "expected_parse_username": "alice",
        }
    )

    # 2. Boundary: 64-byte max username.
    long_name = "u" * 64
    rec_long = IdentityRecord(
        username=long_name,
        x25519_pk=alice.get_public_key_bytes(),
        ed25519_spk=alice.get_signing_public_key_bytes(),
        ts=TS_2030,
    )
    wire_long = rec_long.sign(alice)
    cases.append(
        {
            "description": "boundary: 64-byte max username length",
            "identity_seed_hex": alice_seed.hex(),
            "inputs": {
                "username": long_name,
                "x25519_pk_hex": alice.get_public_key_bytes().hex(),
                "ed25519_spk_hex": alice.get_signing_public_key_bytes().hex(),
                "ts": TS_2030,
            },
            "expected_wire_hex": wire_long.encode("utf-8").hex(),
            "expected_parse_username": long_name,
        }
    )

    # 3. Signature failure: flip one byte in the signature trailer.
    #    Identity records self-sign, so we corrupt the wire itself.
    blob = base64.b64decode(wire.split(";d=", 1)[1])
    corrupted = blob[:-1] + bytes([(blob[-1] ^ 0x01) & 0xFF])
    corrupted_wire = (
        wire.split(";d=", 1)[0] + ";d=" + base64.b64encode(corrupted).decode("ascii")
    )
    cases.append(
        {
            "description": "signature failure: last byte of signature flipped",
            "identity_seed_hex": alice_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": corrupted_wire.encode("utf-8").hex(),
            "expected_parse_result": "none",
            "notes": (
                "Identity records self-sign (signer spk embedded in body); "
                "we corrupt the wire trailer to force sig failure."
            ),
        }
    )

    return cases


# --- SlotManifest -----------------------------------------------------------


def gen_slot_manifest_cases() -> list[dict[str, Any]]:
    sender = crypto_from_label("vectors/manifest/sender")
    sender_seed = seed_from_label("vectors/manifest/sender")

    recipient_id = hashlib.sha256(b"recipient-x25519-pk").digest()  # 32 bytes
    msg_id = bytes.fromhex("00112233445566778899aabbccddeeff")  # 16 bytes

    cases: list[dict[str, Any]] = []

    # 1. Round-trip: single chunk, no prekey.
    m = SlotManifest(
        msg_id=msg_id,
        sender_spk=sender.get_signing_public_key_bytes(),
        recipient_id=recipient_id,
        total_chunks=1,
        data_chunks=1,
        prekey_id=0,
        ts=TS_2030,
        exp=EXP_2035,
    )
    wire = m.sign(sender)
    cases.append(
        {
            "description": "round-trip: 1 chunk, no prekey",
            "sender_seed_hex": sender_seed.hex(),
            "inputs": {
                "msg_id_hex": msg_id.hex(),
                "sender_spk_hex": sender.get_signing_public_key_bytes().hex(),
                "recipient_id_hex": recipient_id.hex(),
                "total_chunks": 1,
                "data_chunks": 1,
                "prekey_id": 0,
                "ts": TS_2030,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "expected_parse_total_chunks": 1,
        }
    )

    # 2. Boundary: 64-chunk erasure manifest with threshold 32.
    m_big = SlotManifest(
        msg_id=msg_id,
        sender_spk=sender.get_signing_public_key_bytes(),
        recipient_id=recipient_id,
        total_chunks=64,
        data_chunks=32,
        prekey_id=7,
        ts=TS_2030,
        exp=EXP_2035,
    )
    wire_big = m_big.sign(sender)
    cases.append(
        {
            "description": "boundary: 64-chunk erasure with prekey_id=7",
            "sender_seed_hex": sender_seed.hex(),
            "inputs": {
                "msg_id_hex": msg_id.hex(),
                "sender_spk_hex": sender.get_signing_public_key_bytes().hex(),
                "recipient_id_hex": recipient_id.hex(),
                "total_chunks": 64,
                "data_chunks": 32,
                "prekey_id": 7,
                "ts": TS_2030,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_big.encode("utf-8").hex(),
            "expected_parse_total_chunks": 64,
        }
    )

    # 3. Signature failure: flip one byte in the base64'd body|sig.
    blob = base64.b64decode(wire.split(";d=", 1)[1])
    corrupted = blob[:-1] + bytes([(blob[-1] ^ 0x01) & 0xFF])
    corrupted_wire = (
        wire.split(";d=", 1)[0] + ";d=" + base64.b64encode(corrupted).decode("ascii")
    )
    cases.append(
        {
            "description": "signature failure: last byte of trailer flipped",
            "sender_seed_hex": sender_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": corrupted_wire.encode("utf-8").hex(),
            "expected_parse_result": "none",
        }
    )

    return cases


# --- Prekey -----------------------------------------------------------------


def gen_prekey_cases() -> list[dict[str, Any]]:
    signer = crypto_from_label("vectors/prekey/identity")
    signer_seed = seed_from_label("vectors/prekey/identity")
    signer_spk = signer.get_signing_public_key_bytes()

    # The prekey's public_key is its own X25519 pub — a different key
    # from the identity key. We derive it deterministically from a seed.
    prekey_x25519_seed = seed_from_label("vectors/prekey/prekey-0001")
    prekey_x25519 = DMPCrypto.from_private_bytes(prekey_x25519_seed)
    prekey_pub = prekey_x25519.get_public_key_bytes()

    cases: list[dict[str, Any]] = []

    # 1. Round-trip.
    pk = Prekey(prekey_id=1, public_key=prekey_pub, exp=EXP_2035)
    wire = pk.sign(signer)
    cases.append(
        {
            "description": "round-trip: prekey_id=1",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "prekey_id": 1,
                "public_key_hex": prekey_pub.hex(),
                "exp": EXP_2035,
            },
            "verify_with_signer_spk_hex": signer_spk.hex(),
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "expected_parse_prekey_id": 1,
        }
    )

    # 2. Boundary: uint32-max prekey_id (common in long-lived rotating pools).
    pk_max = Prekey(prekey_id=(1 << 32) - 1, public_key=prekey_pub, exp=EXP_2035)
    wire_max = pk_max.sign(signer)
    cases.append(
        {
            "description": "boundary: max uint32 prekey_id",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "prekey_id": (1 << 32) - 1,
                "public_key_hex": prekey_pub.hex(),
                "exp": EXP_2035,
            },
            "verify_with_signer_spk_hex": signer_spk.hex(),
            "expected_wire_hex": wire_max.encode("utf-8").hex(),
            "expected_parse_prekey_id": (1 << 32) - 1,
        }
    )

    # 3. Signature failure: correct wire, wrong signer_spk.
    wrong_signer = crypto_from_label("vectors/prekey/wrong-identity")
    wrong_signer_spk = wrong_signer.get_signing_public_key_bytes()
    cases.append(
        {
            "description": "signature failure: correct wire, wrong signer_spk",
            "signer_seed_hex": signer_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "verify_with_signer_spk_hex": wrong_signer_spk.hex(),
            "expected_parse_result": "none",
        }
    )

    # 4. Expired.
    pk_expired = Prekey(prekey_id=1, public_key=prekey_pub, exp=EXP_EXPIRED)
    wire_expired = pk_expired.sign(signer)
    cases.append(
        {
            "description": "expired: prekey exp in the past (caller-enforced)",
            "signer_seed_hex": signer_seed.hex(),
            "inputs": {
                "prekey_id": 1,
                "public_key_hex": prekey_pub.hex(),
                "exp": EXP_EXPIRED,
            },
            "verify_with_signer_spk_hex": signer_spk.hex(),
            "expected_wire_hex": wire_expired.encode("utf-8").hex(),
            "expected_parse_prekey_id": 1,
            "notes": (
                "Prekey.parse_and_verify does not check expiry itself; the "
                "caller checks is_expired(). This vector still parses to a "
                "valid Prekey; test_vectors.py asserts is_expired() is True."
            ),
        }
    )

    return cases


# --- RotationRecord ---------------------------------------------------------


def gen_rotation_record_cases() -> list[dict[str, Any]]:
    """EXPERIMENTAL wire type (M5.4). Subject to post-audit revision.

    Vectors cover the three subject_types + a co-sign-failure + expired
    case so third-party implementers exercise both signature paths.
    """
    old = crypto_from_label("vectors/rotation/old-user")
    new = crypto_from_label("vectors/rotation/new-user")
    old_spk = old.get_signing_public_key_bytes()
    new_spk = new.get_signing_public_key_bytes()
    old_seed = seed_from_label("vectors/rotation/old-user")
    new_seed = seed_from_label("vectors/rotation/new-user")

    cases: list[dict[str, Any]] = []

    # 1. Round-trip: user identity rotation.
    rec_user = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject="alice@example.com",
        old_spk=old_spk,
        new_spk=new_spk,
        seq=1,
        ts=TS_2030,
        exp=EXP_2035,
    )
    wire_user = rec_user.sign(old, new)
    cases.append(
        {
            "description": "round-trip: user-identity rotation (alice@example.com)",
            "old_seed_hex": old_seed.hex(),
            "new_seed_hex": new_seed.hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_USER_IDENTITY,
                "subject": "alice@example.com",
                "old_spk_hex": old_spk.hex(),
                "new_spk_hex": new_spk.hex(),
                "seq": 1,
                "ts": TS_2030,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_user.encode("utf-8").hex(),
            "expected_parse_subject": "alice@example.com",
            "expected_parse_seq": 1,
        }
    )

    # 2. Cluster-operator rotation.
    cluster_old = crypto_from_label("vectors/rotation/old-cluster-op")
    cluster_new = crypto_from_label("vectors/rotation/new-cluster-op")
    rec_cluster = RotationRecord(
        subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        subject="mesh.example.com",
        old_spk=cluster_old.get_signing_public_key_bytes(),
        new_spk=cluster_new.get_signing_public_key_bytes(),
        seq=7,
        ts=TS_2030,
        exp=EXP_2035,
    )
    wire_cluster = rec_cluster.sign(cluster_old, cluster_new)
    cases.append(
        {
            "description": "round-trip: cluster-operator rotation (mesh.example.com)",
            "old_seed_hex": seed_from_label("vectors/rotation/old-cluster-op").hex(),
            "new_seed_hex": seed_from_label("vectors/rotation/new-cluster-op").hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_CLUSTER_OPERATOR,
                "subject": "mesh.example.com",
                "old_spk_hex": cluster_old.get_signing_public_key_bytes().hex(),
                "new_spk_hex": cluster_new.get_signing_public_key_bytes().hex(),
                "seq": 7,
                "ts": TS_2030,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_cluster.encode("utf-8").hex(),
            "expected_parse_subject": "mesh.example.com",
            "expected_parse_seq": 7,
        }
    )

    # 3. Bootstrap-signer rotation.
    bs_old = crypto_from_label("vectors/rotation/old-bootstrap")
    bs_new = crypto_from_label("vectors/rotation/new-bootstrap")
    rec_bs = RotationRecord(
        subject_type=SUBJECT_TYPE_BOOTSTRAP_SIGNER,
        subject="example.com",
        old_spk=bs_old.get_signing_public_key_bytes(),
        new_spk=bs_new.get_signing_public_key_bytes(),
        seq=2,
        ts=TS_2030,
        exp=EXP_2035,
    )
    wire_bs = rec_bs.sign(bs_old, bs_new)
    cases.append(
        {
            "description": "round-trip: bootstrap-signer rotation (example.com)",
            "old_seed_hex": seed_from_label("vectors/rotation/old-bootstrap").hex(),
            "new_seed_hex": seed_from_label("vectors/rotation/new-bootstrap").hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_BOOTSTRAP_SIGNER,
                "subject": "example.com",
                "old_spk_hex": bs_old.get_signing_public_key_bytes().hex(),
                "new_spk_hex": bs_new.get_signing_public_key_bytes().hex(),
                "seq": 2,
                "ts": TS_2030,
                "exp": EXP_2035,
            },
            "expected_wire_hex": wire_bs.encode("utf-8").hex(),
            "expected_parse_subject": "example.com",
            "expected_parse_seq": 2,
        }
    )

    # 4. Cosign failure: case 0's body but sig_new replaced by a forgery
    #    from an unrelated key. parse_and_verify must return None.
    blob_user = base64.b64decode(wire_user.split(";", 2)[2])
    body_len = len(blob_user) - 128
    body = blob_user[:body_len]
    sig_old = blob_user[body_len : body_len + 64]
    imposter = crypto_from_label("vectors/rotation/imposter")
    forged_sig_new = imposter.sign_data(body)
    forged = body + sig_old + forged_sig_new
    # The ;t=rotation; prefix has no d= key.
    from dmp.core.rotation import RECORD_PREFIX_ROTATION

    forged_wire = RECORD_PREFIX_ROTATION + base64.b64encode(forged).decode("ascii")
    cases.append(
        {
            "description": "cosign failure: sig_new forged by a third key",
            "old_seed_hex": old_seed.hex(),
            "new_seed_hex": new_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": forged_wire.encode("utf-8").hex(),
            "expected_parse_result": "none",
        }
    )

    # 5. Expired.
    rec_expired = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject="alice@example.com",
        old_spk=old_spk,
        new_spk=new_spk,
        seq=1,
        ts=TS_2030,
        exp=EXP_EXPIRED,
    )
    wire_expired = rec_expired.sign(old, new)
    cases.append(
        {
            "description": "expired: exp in the distant past is rejected",
            "old_seed_hex": old_seed.hex(),
            "new_seed_hex": new_seed.hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_USER_IDENTITY,
                "subject": "alice@example.com",
                "old_spk_hex": old_spk.hex(),
                "new_spk_hex": new_spk.hex(),
                "seq": 1,
                "ts": TS_2030,
                "exp": EXP_EXPIRED,
            },
            "expected_wire_hex": wire_expired.encode("utf-8").hex(),
            "verify_with_now": EXP_EXPIRED + 1,
            "expected_parse_result": "none",
        }
    )

    return cases


# --- RevocationRecord -------------------------------------------------------


def gen_revocation_record_cases() -> list[dict[str, Any]]:
    """EXPERIMENTAL wire type (M5.4). Subject to post-audit revision."""
    revoked = crypto_from_label("vectors/revocation/revoked-user")
    revoked_spk = revoked.get_signing_public_key_bytes()
    revoked_seed = seed_from_label("vectors/revocation/revoked-user")

    cases: list[dict[str, Any]] = []

    # 1. Round-trip: user revocation, compromise.
    rec = RevocationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject="alice@example.com",
        revoked_spk=revoked_spk,
        reason_code=REASON_COMPROMISE,
        ts=TS_2030,
    )
    wire = rec.sign(revoked)
    cases.append(
        {
            "description": "round-trip: user-identity revocation (compromise)",
            "revoked_seed_hex": revoked_seed.hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_USER_IDENTITY,
                "subject": "alice@example.com",
                "revoked_spk_hex": revoked_spk.hex(),
                "reason_code": REASON_COMPROMISE,
                "ts": TS_2030,
            },
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "expected_parse_subject": "alice@example.com",
            "expected_parse_reason_code": REASON_COMPROMISE,
            # Revocations have a freshness window; use a `now` close to
            # ts so default 1-year max_age_seconds accepts it.
            "verify_with_now": TS_2030 + 60,
        }
    )

    # 2. Round-trip: cluster revocation, routine rotation.
    c_revoked = crypto_from_label("vectors/revocation/revoked-cluster-op")
    c_spk = c_revoked.get_signing_public_key_bytes()
    rec_cluster = RevocationRecord(
        subject_type=SUBJECT_TYPE_CLUSTER_OPERATOR,
        subject="mesh.example.com",
        revoked_spk=c_spk,
        reason_code=REASON_ROUTINE,
        ts=TS_2030,
    )
    wire_cluster = rec_cluster.sign(c_revoked)
    cases.append(
        {
            "description": "round-trip: cluster-operator revocation (routine)",
            "revoked_seed_hex": seed_from_label(
                "vectors/revocation/revoked-cluster-op"
            ).hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_CLUSTER_OPERATOR,
                "subject": "mesh.example.com",
                "revoked_spk_hex": c_spk.hex(),
                "reason_code": REASON_ROUTINE,
                "ts": TS_2030,
            },
            "expected_wire_hex": wire_cluster.encode("utf-8").hex(),
            "expected_parse_subject": "mesh.example.com",
            "expected_parse_reason_code": REASON_ROUTINE,
            "verify_with_now": TS_2030 + 60,
        }
    )

    # 3. Signature failure: correct wire, wrong expected_revoked_spk.
    wrong = crypto_from_label("vectors/revocation/wrong-key")
    wrong_spk = wrong.get_signing_public_key_bytes()
    cases.append(
        {
            "description": "signature/binding failure: wrong expected_revoked_spk",
            "revoked_seed_hex": revoked_seed.hex(),
            "wire_from_case": 0,
            "expected_wire_hex": wire.encode("utf-8").hex(),
            "verify_with_expected_revoked_spk_hex": wrong_spk.hex(),
            "verify_with_now": TS_2030 + 60,
            "expected_parse_result": "none",
        }
    )

    # 4. Stale revocation with EXPLICIT max_age_seconds.
    #
    # Revocations are permanent assertions under the default
    # (max_age_seconds=None, no cap). This vector instead exercises
    # the OPTIONAL caller-provided freshness window: a client that
    # deliberately wants to prune old revocations (forensic replay
    # windows, audit tools) passes an explicit integer, and the
    # classical ts + max_age < now gate kicks back in.
    rec_stale = RevocationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject="alice@example.com",
        revoked_spk=revoked_spk,
        reason_code=REASON_COMPROMISE,
        ts=TS_2030,
    )
    wire_stale = rec_stale.sign(revoked)
    cases.append(
        {
            "description": (
                "stale-with-explicit-cap: revocation rejected only when "
                "the caller opts in to max_age_seconds"
            ),
            "revoked_seed_hex": revoked_seed.hex(),
            "inputs": {
                "subject_type": SUBJECT_TYPE_USER_IDENTITY,
                "subject": "alice@example.com",
                "revoked_spk_hex": revoked_spk.hex(),
                "reason_code": REASON_COMPROMISE,
                "ts": TS_2030,
            },
            "expected_wire_hex": wire_stale.encode("utf-8").hex(),
            # Two years after ts, caller passes 1-year explicit cap → reject.
            "verify_with_now": TS_2030 + 86400 * 365 * 2,
            "verify_with_max_age_seconds": 86400 * 365,
            "expected_parse_result": "none",
            "notes": (
                "Permanent-assertion model: the default "
                "max_age_seconds=None accepts this same wire. The "
                "rejection here requires the explicit cap in "
                "verify_with_max_age_seconds."
            ),
        }
    )

    return cases


# --- driver -----------------------------------------------------------------


def write_vectors(name: str, cases: list[dict[str, Any]]) -> None:
    target = VECTORS_DIR / f"{name}.json"
    # sort_keys=True + indent=2 so diffs are minimal and reviewable.
    payload = json.dumps(cases, indent=2, sort_keys=True) + "\n"
    target.write_text(payload, encoding="utf-8")
    print(f"wrote {len(cases)} cases → {target.relative_to(VECTORS_DIR.parent.parent)}")


def main() -> None:
    write_vectors("cluster_manifest", gen_cluster_manifest_cases())
    write_vectors("bootstrap_record", gen_bootstrap_record_cases())
    write_vectors("identity_record", gen_identity_record_cases())
    write_vectors("slot_manifest", gen_slot_manifest_cases())
    write_vectors("prekey", gen_prekey_cases())
    write_vectors("rotation_record", gen_rotation_record_cases())
    write_vectors("revocation_record", gen_revocation_record_cases())


if __name__ == "__main__":
    main()
