#!/usr/bin/env python3
"""End-to-end demo against a real dmp-node Docker container.

Drives two DMPClient instances (Alice, Bob) through a locally-running
dmp-node container via the node's HTTP publish API + UDP DNS resolver.
Exercises three flows:

  1. Baseline send/receive (pre-rotation).
  2. Routine key rotation — Bob's rotation-aware client chain-walks
     Alice's new key without re-pinning.
  3. Compromise rotation — Alice publishes a RevocationRecord for the
     old key, and Bob's client refuses further messages signed with it.

Prerequisites:
  docker build -t dmp-node:latest .

Usage:
  python examples/docker_e2e_demo.py

The script is meant as a starter for an SDK / application built on
DMPClient: the adapter classes and rotation helper are the same
primitives a real integration would use.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import uuid
from typing import List, Optional

# Allow running from a checkout without installing.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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
IMAGE = "dmp-node:latest"


# ---------------------------------------------------------------------------
# Transport adapters — same shape as tests/test_docker_integration.py
# ---------------------------------------------------------------------------


class HttpWriter:
    """Publishes TXT records to a dmp-node via its HTTP API."""

    def __init__(self, base_url: str, token: Optional[str] = None) -> None:
        import requests

        self._requests = requests
        self._base = base_url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        r = self._requests.post(
            f"{self._base}/v1/records/{name}",
            json={"value": value, "ttl": ttl},
            headers=self._headers,
            timeout=5,
        )
        return r.status_code == 201

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        payload = {"value": value} if value else None
        r = self._requests.delete(
            f"{self._base}/v1/records/{name}",
            json=payload,
            headers=self._headers,
            timeout=5,
        )
        return r.status_code == 204


class DnsReader:
    """Reads TXT records via UDP DNS against the node's DNS port."""

    def __init__(self, host: str, port: int) -> None:
        self._host = host
        self._port = port

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        import dns.message
        import dns.query
        import dns.rdatatype

        req = dns.message.make_query(name, dns.rdatatype.TXT)
        try:
            resp = dns.query.udp(req, self._host, port=self._port, timeout=3.0)
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
# Container lifecycle
# ---------------------------------------------------------------------------


def _free_port(kind: int = socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def start_node() -> dict:
    import requests

    name = f"dmp-demo-{uuid.uuid4().hex[:8]}"
    http_port = _free_port(socket.SOCK_STREAM)
    dns_port = _free_port(socket.SOCK_DGRAM)

    subprocess.run(
        [
            "docker", "run", "--rm", "-d", "--name", name,
            "-p", f"127.0.0.1:{dns_port}:5353/udp",
            "-p", f"127.0.0.1:{http_port}:8053/tcp",
            "-e", "DMP_LOG_LEVEL=WARNING",
            IMAGE,
        ],
        check=True,
        capture_output=True,
    )

    deadline = time.time() + 15.0
    while time.time() < deadline:
        try:
            if requests.get(f"http://127.0.0.1:{http_port}/health", timeout=1).status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        logs = subprocess.run(["docker", "logs", name], capture_output=True, text=True).stdout
        subprocess.run(["docker", "stop", name], capture_output=True)
        raise RuntimeError(f"container failed health check; logs:\n{logs}")

    return {"name": name, "http_port": http_port, "dns_port": dns_port}


def stop_node(node: dict) -> None:
    subprocess.run(["docker", "stop", node["name"]], capture_output=True, timeout=10)


# ---------------------------------------------------------------------------
# Rotation — mirrors dmp.cli.cmd_identity_rotate without the CLI wrapping
# ---------------------------------------------------------------------------


def publish_identity(client: DMPClient, ttl: int = 300) -> bool:
    """Publish the signed IdentityRecord for `client` to its writer."""
    rrset = identity_domain(client.username, client.domain)
    record = make_record(client.crypto, client.username)
    return client.writer.publish_txt_record(rrset, record.sign(client.crypto), ttl=ttl)


def rotate_identity(
    old_client: DMPClient,
    new_passphrase: str,
    kdf_salt: bytes,
    *,
    revoke_reason: Optional[int] = None,
    ttl: int = 300,
    exp_seconds: int = 86400 * 180,
) -> DMPClient:
    """Rotate `old_client` to a new signing key.

    Publishes a co-signed RotationRecord and a fresh IdentityRecord for
    the new key. When ``revoke_reason`` is set (REASON_COMPROMISE /
    REASON_LOST_KEY), also publishes a self-signed RevocationRecord so
    rotation-aware peers refuse the old key.

    ``kdf_salt`` must be the same salt used to derive ``old_client`` —
    the atomic-swap invariant is that the salt stays constant while
    the passphrase rotates. The salt is not retrievable from the
    client/crypto, so callers must track it.

    Returns a NEW DMPClient derived from ``new_passphrase`` with the
    same kdf_salt + writer + reader — the shape a real application
    would keep around after rotation.
    """
    old_crypto = old_client.crypto
    new_crypto = DMPCrypto.from_passphrase(new_passphrase, salt=kdf_salt)

    if new_crypto.get_signing_public_key_bytes() == old_crypto.get_signing_public_key_bytes():
        raise ValueError("new passphrase derives the same key as the old one")

    subject = f"{old_client.username}@{old_client.domain}"
    ts = int(time.time())
    seq = int(time.time() * 1000)  # ms resolution — matches the CLI

    rotation = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        old_spk=old_crypto.get_signing_public_key_bytes(),
        new_spk=new_crypto.get_signing_public_key_bytes(),
        seq=seq,
        ts=ts,
        exp=ts + exp_seconds,
    )
    rotation_wire = rotation.sign(old_crypto, new_crypto)

    rrset = rotation_rrset_name_user_identity(old_client.username, old_client.domain)

    if not old_client.writer.publish_txt_record(rrset, rotation_wire, ttl=ttl):
        raise RuntimeError(f"publish of RotationRecord to {rrset} failed")

    if revoke_reason is not None:
        revocation = RevocationRecord(
            subject_type=SUBJECT_TYPE_USER_IDENTITY,
            subject=subject,
            revoked_spk=old_crypto.get_signing_public_key_bytes(),
            reason_code=revoke_reason,
            ts=ts,
        )
        if not old_client.writer.publish_txt_record(rrset, revocation.sign(old_crypto), ttl=ttl):
            raise RuntimeError(f"publish of RevocationRecord to {rrset} failed")

    # New IdentityRecord for the new key — non-rotation-aware peers
    # still need a plain identity lookup to return the new key.
    identity_rrset = identity_domain(old_client.username, old_client.domain)
    new_identity = make_record(new_crypto, old_client.username)
    if not old_client.writer.publish_txt_record(
        identity_rrset, new_identity.sign(new_crypto), ttl=ttl
    ):
        raise RuntimeError(f"publish of new IdentityRecord to {identity_rrset} failed")

    # Hand back a fully-formed client for the rotated identity.
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
# Demo flow
# ---------------------------------------------------------------------------


def step(n: int, title: str) -> None:
    print(f"\n[{n}] {title}")
    print("-" * (len(title) + 4))


def main() -> int:
    print("Starting dmp-node container…")
    node = start_node()
    print(f"  name={node['name']}  http=127.0.0.1:{node['http_port']}  dns=127.0.0.1:{node['dns_port']}")
    try:
        writer = HttpWriter(f"http://127.0.0.1:{node['http_port']}")
        reader = DnsReader("127.0.0.1", node["dns_port"])

        step(1, "Create Alice + Bob, pin each other")
        # Per-identity random salts; kept across rotations so the same
        # salt + new passphrase derives the rotated keypair. Real
        # applications persist this (e.g. ~/.dmp/config.yaml.kdf_salt).
        alice_salt = os.urandom(32)
        bob_salt = os.urandom(32)
        alice = DMPClient(
            "alice", "alice-pass-v1",
            domain=DOMAIN, writer=writer, reader=reader,
            kdf_salt=alice_salt,
        )
        # Bob is rotation-aware so he'll chain-walk Alice's key in step 3.
        bob = DMPClient(
            "bob", "bob-pass-v1",
            domain=DOMAIN, writer=writer, reader=reader,
            kdf_salt=bob_salt,
            rotation_chain_enabled=True,
        )
        alice.add_contact("bob", bob.get_public_key_hex(),
                          signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex())
        bob.add_contact("alice", alice.get_public_key_hex(),
                        signing_key_hex=alice.crypto.get_signing_public_key_bytes().hex())
        print(f"  alice spk = {alice.crypto.get_signing_public_key_bytes().hex()}")
        print(f"  bob   spk = {bob.crypto.get_signing_public_key_bytes().hex()}")

        step(2, "Baseline: Alice → Bob (pre-rotation)")
        assert publish_identity(alice), "alice identity publish failed"
        assert alice.send_message("bob", "hello from alice, key v1"), "send failed"
        inbox = bob.receive_messages()
        assert len(inbox) == 1 and inbox[0].plaintext == b"hello from alice, key v1", inbox
        print(f"  bob received: {inbox[0].plaintext!r}")

        step(3, "Routine rotation: Alice → new key, Bob chain-walks")
        alice_v2 = rotate_identity(alice, "alice-pass-v2", alice_salt)  # no revocation
        print(f"  new alice spk = {alice_v2.crypto.get_signing_public_key_bytes().hex()}")

        # Bob's pinned contact still has Alice's OLD spk. A rotation-aware
        # client uses resolve_current_spk to walk forward to the new head.
        from dmp.core.rotation import SUBJECT_TYPE_USER_IDENTITY as _SUBJ
        resolved = bob._rotation_chain.resolve_current_spk(
            alice.crypto.get_signing_public_key_bytes(),
            f"alice@{DOMAIN}",
            _SUBJ,
        )
        assert resolved == alice_v2.crypto.get_signing_public_key_bytes(), (
            f"chain-walk didn't reach new key; got {resolved!r}"
        )
        print("  rotation chain walk → new key ✓")

        # Re-pin with the resolved key so send/receive uses it.
        bob.add_contact(
            "alice", alice_v2.get_public_key_hex(),
            signing_key_hex=resolved.hex(),
        )
        # Alice must re-pin Bob too (her client is new).
        alice_v2.add_contact(
            "bob", bob.get_public_key_hex(),
            signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex(),
        )

        assert alice_v2.send_message("bob", "hello from alice, key v2"), "v2 send failed"
        inbox = bob.receive_messages()
        # Bob's inbox accumulates; find the new message.
        new_msgs = [m for m in inbox if m.plaintext == b"hello from alice, key v2"]
        assert new_msgs, f"v2 message not delivered; inbox={[m.plaintext for m in inbox]}"
        print(f"  bob received under rotated key: {new_msgs[0].plaintext!r}")

        step(4, "Compromise rotation: Alice → new key + revoke old")
        alice_v3 = rotate_identity(
            alice_v2, "alice-pass-v3", alice_salt,
            revoke_reason=REASON_COMPROMISE,
        )
        print(f"  new alice spk = {alice_v3.crypto.get_signing_public_key_bytes().hex()}")
        print("  revocation of v2 key published")

        # The chain walker refuses ANY path from a revoked key, so a Bob
        # still pinned on v2 now gets None back — the correct response
        # to a compromise signal.
        resolved = bob._rotation_chain.resolve_current_spk(
            alice_v2.crypto.get_signing_public_key_bytes(),
            f"alice@{DOMAIN}",
            _SUBJ,
        )
        assert resolved is None, (
            f"chain-walker must refuse a revoked path; got {resolved!r}"
        )
        print("  chain walk from v2 → None (revoked) ✓")

        # Out-of-band re-pin is required after compromise. Bob re-pins v3
        # directly (how a real contact would: fetch + human verify).
        bob.add_contact(
            "alice", alice_v3.get_public_key_hex(),
            signing_key_hex=alice_v3.crypto.get_signing_public_key_bytes().hex(),
        )
        alice_v3.add_contact(
            "bob", bob.get_public_key_hex(),
            signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex(),
        )
        assert alice_v3.send_message("bob", "hello from alice, key v3"), "v3 send failed"
        inbox = bob.receive_messages()
        assert any(m.plaintext == b"hello from alice, key v3" for m in inbox), inbox
        print("  bob received under re-pinned v3 key ✓")

        print("\nAll steps passed.")
        return 0
    finally:
        print(f"\nStopping container {node['name']}…")
        stop_node(node)


if __name__ == "__main__":
    sys.exit(main())
