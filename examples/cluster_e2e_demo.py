#!/usr/bin/env python3
"""Federated 3-node cluster e2e demo.

Brings up ``docker-compose.cluster.yml`` (node-a / node-b / node-c),
has Alice publish via node-a's HTTP API, and has Bob read via
node-b's DNS — so every receive path exercises anti-entropy sync
across the federated mesh.

Scenarios:
  1. Baseline message: Alice → node-a → [anti-entropy] → node-b → Bob.
  2. Routine rotation: Alice rotates against node-a. Bob's rotation-
     aware client (reading node-b) chain-walks to the new key.
  3. Compromise rotation: Alice rotates with REASON_COMPROMISE. Bob's
     chain walker (still reading node-b) correctly returns None.

Prerequisites:
  docker build -t dmp-node:latest .

Usage:
  python examples/cluster_e2e_demo.py

The cluster manifest is generated automatically on first run.

Compared to ``examples/docker_e2e_demo.py`` (single-node): this one
proves M5.4 rotation propagates across federation, not just within
one node — which is what a real production deployment looks like.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from dmp.client.client import DMPClient  # noqa: E402
from dmp.core.crypto import DMPCrypto  # noqa: E402
from dmp.core.identity import identity_domain, make_record  # noqa: E402
from dmp.core.rotation import (  # noqa: E402
    REASON_COMPROMISE,
    RevocationRecord,
    RotationRecord,
    SUBJECT_TYPE_USER_IDENTITY,
    rotation_rrset_name_user_identity,
)

DOMAIN = "mesh.demo"
COMPOSE_FILE = _REPO / "docker-compose.cluster.yml"
MANIFEST_PATH = _REPO / "docker" / "cluster" / "cluster-manifest.wire"
OPERATOR_KEY_PATH = _REPO / "docker" / "cluster" / "operator-ed25519.hex"
GENERATE_SCRIPT = _REPO / "docker" / "cluster" / "generate-cluster-manifest.py"

# Container port -> 127.0.0.1 host ports (from docker-compose.cluster.yml).
NODES = {
    "a": {"http": 8101, "dns": 5301},
    "b": {"http": 8102, "dns": 5302},
    "c": {"http": 8103, "dns": 5303},
}

# Anti-entropy interval in the sample env files is 2s. Give it 2x that
# before reading from a different node than we wrote to.
SYNC_GRACE_SECONDS = 4.0


# ---------------------------------------------------------------------------
# Transport adapters — copy of the shapes used in examples/docker_e2e_demo.py
# ---------------------------------------------------------------------------


class HttpWriter:
    def __init__(self, http_port: int) -> None:
        import requests

        self._requests = requests
        self._base = f"http://127.0.0.1:{http_port}"

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        r = self._requests.post(
            f"{self._base}/v1/records/{name}",
            json={"value": value, "ttl": ttl},
            timeout=5,
        )
        return r.status_code == 201

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        r = self._requests.delete(
            f"{self._base}/v1/records/{name}",
            json={"value": value} if value else None,
            timeout=5,
        )
        return r.status_code == 204


class DnsReader:
    def __init__(self, dns_port: int) -> None:
        self._port = dns_port

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        import dns.message
        import dns.query
        import dns.rdatatype

        req = dns.message.make_query(name, dns.rdatatype.TXT)
        try:
            resp = dns.query.udp(req, "127.0.0.1", port=self._port, timeout=3.0)
        except Exception:
            return None
        if resp.rcode() != 0 or not resp.answer:
            return None
        out: List[str] = []
        for rrset in resp.answer:
            for rdata in rrset:
                out.append(b"".join(rdata.strings).decode("utf-8"))
        return out or None


# ---------------------------------------------------------------------------
# Compose lifecycle + cluster manifest generation
# ---------------------------------------------------------------------------


def ensure_manifest() -> None:
    if MANIFEST_PATH.exists():
        return
    print("Generating cluster manifest (first run)…")
    subprocess.run(
        [
            sys.executable,
            str(GENERATE_SCRIPT),
            "--cluster-name",
            DOMAIN,
            "--manifest-out",
            str(MANIFEST_PATH),
            "--operator-key-out",
            str(OPERATOR_KEY_PATH),
        ],
        check=True,
    )


def compose_up() -> None:
    print(f"Bringing up 3-node cluster ({COMPOSE_FILE.name})…")
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "up", "-d"],
        check=True,
        capture_output=True,
    )
    import requests

    deadline = time.time() + 30.0
    pending = set(NODES)
    while pending and time.time() < deadline:
        for nid in list(pending):
            try:
                if (
                    requests.get(
                        f"http://127.0.0.1:{NODES[nid]['http']}/health",
                        timeout=1,
                    ).status_code
                    == 200
                ):
                    pending.discard(nid)
            except Exception:
                pass
        if pending:
            time.sleep(0.5)
    if pending:
        compose_down()
        raise RuntimeError(f"nodes not healthy in 30s: {sorted(pending)}")
    print(f"  node-a http={NODES['a']['http']} dns={NODES['a']['dns']}")
    print(f"  node-b http={NODES['b']['http']} dns={NODES['b']['dns']}")
    print(f"  node-c http={NODES['c']['http']} dns={NODES['c']['dns']}")


def compose_down() -> None:
    print(f"\nTearing down cluster ({COMPOSE_FILE.name})…")
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_FILE), "down", "-v"],
        capture_output=True,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Rotation helper (same shape as examples/docker_e2e_demo.py)
# ---------------------------------------------------------------------------


def rotate_identity(
    old_client: DMPClient,
    new_passphrase: str,
    kdf_salt: bytes,
    *,
    revoke_reason: Optional[int] = None,
    ttl: int = 300,
    exp_seconds: int = 86400 * 180,
) -> DMPClient:
    old_crypto = old_client.crypto
    new_crypto = DMPCrypto.from_passphrase(new_passphrase, salt=kdf_salt)
    assert (
        new_crypto.get_signing_public_key_bytes()
        != old_crypto.get_signing_public_key_bytes()
    )

    subject = f"{old_client.username}@{old_client.domain}"
    ts = int(time.time())
    seq = int(time.time() * 1000)

    rotation = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        old_spk=old_crypto.get_signing_public_key_bytes(),
        new_spk=new_crypto.get_signing_public_key_bytes(),
        seq=seq,
        ts=ts,
        exp=ts + exp_seconds,
    )
    rrset = rotation_rrset_name_user_identity(old_client.username, old_client.domain)
    assert old_client.writer.publish_txt_record(
        rrset, rotation.sign(old_crypto, new_crypto), ttl=ttl
    ), "RotationRecord publish failed"

    if revoke_reason is not None:
        revocation = RevocationRecord(
            subject_type=SUBJECT_TYPE_USER_IDENTITY,
            subject=subject,
            revoked_spk=old_crypto.get_signing_public_key_bytes(),
            reason_code=revoke_reason,
            ts=ts,
        )
        assert old_client.writer.publish_txt_record(
            rrset, revocation.sign(old_crypto), ttl=ttl
        ), "RevocationRecord publish failed"

    identity_rrset = identity_domain(old_client.username, old_client.domain)
    new_identity = make_record(new_crypto, old_client.username)
    assert old_client.writer.publish_txt_record(
        identity_rrset,
        new_identity.sign(new_crypto),
        ttl=ttl,
    ), "new IdentityRecord publish failed"

    return DMPClient(
        old_client.username,
        new_passphrase,
        domain=old_client.domain,
        writer=old_client.writer,
        reader=old_client.reader,
        kdf_salt=kdf_salt,
        rotation_chain_enabled=old_client.rotation_chain_enabled,
    )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------


def step(n: int, title: str) -> None:
    print(f"\n[{n}] {title}")
    print("-" * (len(title) + 4))


def wait_for_federation(note: str) -> None:
    print(f"  waiting {SYNC_GRACE_SECONDS}s for anti-entropy ({note})…")
    time.sleep(SYNC_GRACE_SECONDS)


def main() -> int:
    ensure_manifest()
    compose_up()
    try:
        # Alice writes via node-a; Bob reads via node-b. Every verification
        # that Bob does traverses the anti-entropy path.
        alice_writer = HttpWriter(NODES["a"]["http"])
        alice_reader = DnsReader(NODES["a"]["dns"])
        bob_writer = HttpWriter(NODES["b"]["http"])
        bob_reader = DnsReader(NODES["b"]["dns"])

        step(1, "Create Alice (on node-a) + Bob (on node-b)")
        alice_salt = os.urandom(32)
        bob_salt = os.urandom(32)
        alice = DMPClient(
            "alice",
            "alice-pass-v1",
            domain=DOMAIN,
            writer=alice_writer,
            reader=alice_reader,
            kdf_salt=alice_salt,
        )
        bob = DMPClient(
            "bob",
            "bob-pass",
            domain=DOMAIN,
            writer=bob_writer,
            reader=bob_reader,
            kdf_salt=bob_salt,
            rotation_chain_enabled=True,
        )
        alice.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex(),
        )
        bob.add_contact(
            "alice",
            alice.get_public_key_hex(),
            signing_key_hex=alice.crypto.get_signing_public_key_bytes().hex(),
        )

        step(2, "Baseline: Alice sends via node-a, Bob receives via node-b")
        # Alice publishes identity + sends on node-a.
        rrset = identity_domain("alice", DOMAIN)
        assert alice_writer.publish_txt_record(
            rrset,
            make_record(alice.crypto, "alice").sign(alice.crypto),
            ttl=300,
        )
        assert alice.send_message("bob", "hello across the federation")
        wait_for_federation("chunks + manifest → node-b")
        inbox = bob.receive_messages()
        assert any(m.plaintext == b"hello across the federation" for m in inbox), inbox
        print(f"  bob received via node-b: {inbox[-1].plaintext!r}")

        step(3, "Routine rotation: published on node-a, chain-walked via node-b")
        alice_v2 = rotate_identity(alice, "alice-pass-v2", alice_salt)
        wait_for_federation("rotation RRset → node-b")
        resolved = bob._rotation_chain.resolve_current_spk(
            alice.crypto.get_signing_public_key_bytes(),
            f"alice@{DOMAIN}",
            SUBJECT_TYPE_USER_IDENTITY,
        )
        assert (
            resolved == alice_v2.crypto.get_signing_public_key_bytes()
        ), f"chain walk via node-b failed; got {resolved!r}"
        print("  node-b chain walk → new key ✓")

        # Re-pin + deliver under the rotated key.
        bob.add_contact(
            "alice", alice_v2.get_public_key_hex(), signing_key_hex=resolved.hex()
        )
        alice_v2.add_contact(
            "bob",
            bob.get_public_key_hex(),
            signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex(),
        )
        assert alice_v2.send_message("bob", "hello under v2 key")
        wait_for_federation("v2 message → node-b")
        inbox = bob.receive_messages()
        assert any(m.plaintext == b"hello under v2 key" for m in inbox), inbox
        print("  bob received v2 message via node-b ✓")

        step(4, "Compromise rotation: revocation federates too")
        rotate_identity(
            alice_v2,
            "alice-pass-v3",
            alice_salt,
            revoke_reason=REASON_COMPROMISE,
        )
        wait_for_federation("revocation RRset → node-b")
        resolved = bob._rotation_chain.resolve_current_spk(
            alice_v2.crypto.get_signing_public_key_bytes(),
            f"alice@{DOMAIN}",
            SUBJECT_TYPE_USER_IDENTITY,
        )
        assert (
            resolved is None
        ), f"chain walker must refuse revoked path; got {resolved!r}"
        print("  node-b: chain from v2 → None (revoked) ✓")

        print("\nAll federated steps passed.")
        return 0
    finally:
        compose_down()


if __name__ == "__main__":
    sys.exit(main())
