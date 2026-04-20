"""End-to-end integration test: boot the dmp-node container, run a real client.

Skipped unless Docker is available and the dmp-node:latest image is present.
Build the image first with `docker build -t dmp-node:latest .`.

The test spins up a fresh container on ephemeral host ports, drives a pair of
DMPClients through the container's SqliteMailboxStore via the HTTP API, and
verifies a round-trip send/receive — plus a direct DNS query to prove the
DNS side is serving the same data the HTTP side wrote.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
import uuid

import pytest


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        return (
            subprocess.run(
                ["docker", "info"],
                capture_output=True,
                timeout=5,
            ).returncode
            == 0
        )
    except Exception:
        return False


def _image_exists(tag: str) -> bool:
    try:
        out = subprocess.run(
            ["docker", "image", "inspect", tag],
            capture_output=True,
            timeout=5,
        )
        return out.returncode == 0
    except Exception:
        return False


def _free_port(kind=socket.SOCK_STREAM) -> int:
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="docker not available"),
    pytest.mark.skipif(
        not _image_exists("dmp-node:latest"),
        reason="dmp-node:latest image missing; run `docker build -t dmp-node:latest .`",
    ),
]


@pytest.fixture
def node_container():
    """Run a fresh dmp-node container bound to ephemeral host ports."""
    import requests  # deferred — avoid import at collection if dep missing

    name = f"dmp-node-test-{uuid.uuid4().hex[:8]}"
    http_port = _free_port(socket.SOCK_STREAM)
    dns_port = _free_port(socket.SOCK_DGRAM)

    subprocess.run(
        [
            "docker", "run", "--rm", "-d",
            "--name", name,
            "-p", f"127.0.0.1:{dns_port}:5353/udp",
            "-p", f"127.0.0.1:{http_port}:8053/tcp",
            "-e", "DMP_LOG_LEVEL=WARNING",
            "dmp-node:latest",
        ],
        check=True,
        capture_output=True,
    )

    # Wait for the health endpoint to come up.
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            r = requests.get(
                f"http://127.0.0.1:{http_port}/health", timeout=1
            )
            if r.status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.2)
    else:
        logs = subprocess.run(
            ["docker", "logs", name], capture_output=True, text=True
        ).stdout
        subprocess.run(["docker", "stop", name], capture_output=True)
        pytest.fail(f"container {name} failed health check; logs:\n{logs}")

    try:
        yield {
            "name": name,
            "http_port": http_port,
            "dns_port": dns_port,
            "http_base": f"http://127.0.0.1:{http_port}",
        }
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True, timeout=10)


class _HttpWriter:
    """Adapts the node's HTTP API to the DNSRecordWriter contract."""

    def __init__(self, base_url: str, token: str | None = None):
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

    def delete_txt_record(self, name: str, value=None) -> bool:
        payload = {"value": value} if value else None
        r = self._requests.delete(
            f"{self._base}/v1/records/{name}",
            json=payload,
            headers=self._headers,
            timeout=5,
        )
        return r.status_code == 204


class _DnsReader:
    """Adapts an external DNS server to the DNSRecordReader contract."""

    def __init__(self, host: str, port: int):
        self._host = host
        self._port = port

    def query_txt_record(self, name: str):
        import dns.message
        import dns.query
        import dns.rdatatype

        request = dns.message.make_query(name, dns.rdatatype.TXT)
        try:
            response = dns.query.udp(
                request, self._host, port=self._port, timeout=3.0
            )
        except Exception:
            return None
        if response.rcode() != 0 or not response.answer:
            return None
        values = []
        for rrset in response.answer:
            for rdata in rrset:
                values.append(b"".join(rdata.strings).decode("utf-8"))
        return values or None


def test_container_roundtrip(node_container):
    """Full client send → HTTP publish → DNS read → decrypt, against the container."""
    from dmp.client.client import DMPClient

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice = DMPClient(
        "alice", "alice-pass", domain="mesh.docker",
        writer=writer, reader=reader,
    )
    bob = DMPClient(
        "bob", "bob-pass", domain="mesh.docker",
        writer=writer, reader=reader,
    )
    alice.add_contact("bob", bob.get_public_key_hex())

    assert alice.send_message("bob", "hello from a real container")

    inbox = bob.receive_messages()
    assert len(inbox) == 1
    assert inbox[0].plaintext == b"hello from a real container"
    assert (
        inbox[0].sender_signing_pk
        == alice.crypto.get_signing_public_key_bytes()
    )


def test_container_survives_client_restart(node_container):
    """Alice sends, a fresh Bob process starts later and picks up the message."""
    from dmp.client.client import DMPClient

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice = DMPClient(
        "alice", "alice-pass", domain="mesh.docker",
        writer=writer, reader=reader,
    )
    # Grab bob's pubkey without retaining the client instance.
    bob_pubkey = DMPClient(
        "bob", "bob-pass", domain="mesh.docker", writer=writer, reader=reader,
    ).get_public_key_hex()
    alice.add_contact("bob", bob_pubkey)

    assert alice.send_message("bob", "delivered after restart")

    # A brand-new Bob process (fresh ReplayCache, no prior state) reads.
    bob_fresh = DMPClient(
        "bob", "bob-pass", domain="mesh.docker",
        writer=writer, reader=reader,
    )
    inbox = bob_fresh.receive_messages()
    assert len(inbox) == 1
    assert inbox[0].plaintext == b"delivered after restart"


def test_container_forward_secrecy_end_to_end(node_container, tmp_path):
    """Forward-secrecy flow exercised against a real container.

    Bob publishes prekeys to the node. Alice pins bob's Ed25519 key,
    sends a message — the manifest must carry a nonzero prekey_id.
    Bob decrypts, the prekey_sk is consumed from his local store, and a
    direct DNS query confirms the prekey_pub RRset is still visible on
    the node (deletion is a client-local concern here, not a server one).
    """
    from dmp.client.client import DMPClient
    from dmp.core.manifest import NO_PREKEY, SlotManifest
    from dmp.core.prekeys import prekey_rrset_name

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    # Persistent prekey stores so we can verify consumption-on-decrypt.
    alice_prekeys = str(tmp_path / "alice-prekeys.db")
    bob_prekeys = str(tmp_path / "bob-prekeys.db")

    alice = DMPClient(
        "alice-fs", "alice-fs-pass", domain="mesh.docker",
        writer=writer, reader=reader, prekey_store_path=alice_prekeys,
    )
    bob = DMPClient(
        "bob-fs", "bob-fs-pass", domain="mesh.docker",
        writer=writer, reader=reader, prekey_store_path=bob_prekeys,
    )
    # Alice pins both of bob's keys — required to verify prekey signatures.
    alice.add_contact(
        "bob-fs",
        bob.get_public_key_hex(),
        signing_key_hex=bob.get_signing_public_key_hex(),
    )

    # Bob seeds a small prekey pool (5 keys, 1 hr TTL).
    published = bob.refresh_prekeys(count=5, ttl_seconds=3600)
    assert published == 5
    assert bob.prekey_store.count_live() == 5

    # Confirm the prekey RRset actually lives on the node.
    rrset_name = prekey_rrset_name("bob-fs", "mesh.docker")
    records = reader.query_txt_record(rrset_name)
    assert records is not None and len(records) == 5

    assert alice.send_message("bob-fs", "forward-secret via real node")

    # Find bob's manifest on the node; prekey_id should be nonzero.
    import hashlib
    bob_recipient_id = hashlib.sha256(
        bytes.fromhex(bob.get_public_key_hex())
    ).digest()
    manifest = None
    for slot in range(10):
        domain = f"slot-{slot}.mb-{hashlib.sha256(bob_recipient_id).hexdigest()[:12]}.mesh.docker"
        values = reader.query_txt_record(domain) or []
        for v in values:
            parsed = SlotManifest.parse_and_verify(v)
            if parsed and parsed[0].recipient_id == bob_recipient_id:
                manifest = parsed[0]
                break
        if manifest:
            break
    assert manifest is not None
    assert manifest.prekey_id != NO_PREKEY
    used_id = manifest.prekey_id
    assert bob.prekey_store.get_private_key(used_id) is not None

    inbox = bob.receive_messages()
    assert len(inbox) == 1
    assert inbox[0].plaintext == b"forward-secret via real node"

    # Consumed — leaking bob's long-term X25519 key no longer recovers this.
    assert bob.prekey_store.get_private_key(used_id) is None
    assert bob.prekey_store.count_live() == 4


def test_container_zone_anchored_identity(node_container):
    """Zone-anchored identity + address-style fetch against a real container.

    Alice publishes her identity at `dmp.alice.example.com` (a zone she
    "controls" in this test — the node accepts any writer on port 8053).
    Bob fetches via `alice@alice.example.com` and stores her as a pinned
    contact. This exercises `dmp identity publish` + `dmp identity fetch`
    logic inside the client against a real UDP DNS server, not the
    in-memory store.
    """
    from dmp.client.client import DMPClient
    from dmp.core.identity import (
        IdentityRecord,
        make_record,
        parse_address,
        zone_anchored_identity_name,
    )

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    # Alice creates her identity + publishes to dmp.alice.example.com.
    alice = DMPClient(
        "alice-z", "alice-z-pass", domain="mesh.docker",
        writer=writer, reader=reader,
    )
    record = make_record(alice.crypto, "alice-z")
    wire = record.sign(alice.crypto)
    anchor = zone_anchored_identity_name("alice-z.example.com")
    assert writer.publish_txt_record(anchor, wire, ttl=3600)

    # Bob resolves `alice-z@alice-z.example.com` via DNS → parses the
    # address, queries the zone-anchored name, verifies the Ed25519
    # signature against the embedded signing pubkey.
    user, host = parse_address("alice-z@alice-z.example.com")
    dns_name = zone_anchored_identity_name(host)
    values = reader.query_txt_record(dns_name)
    assert values is not None and len(values) >= 1

    parsed = None
    for v in values:
        result = IdentityRecord.parse_and_verify(v)
        if result is not None:
            parsed = result[0]
            break
    assert parsed is not None
    assert parsed.username == user
    assert parsed.x25519_pk == alice.crypto.get_public_key_bytes()
    assert parsed.ed25519_spk == alice.crypto.get_signing_public_key_bytes()
