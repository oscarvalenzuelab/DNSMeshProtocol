"""Cross-zone end-to-end validation against the v0.7.0 wire format.

Spins two DMP nodes in distinct DNS zones (alice.test and bob.test) using
docker-compose.cross-zone.yml, then drives DMPClient instances against them
to prove that:

  * messages publish into the *sender's* zone via HTTP API
  * the recipient resolves the sender's zone via DNS and decrypts the
    message round-trip
  * the manifest carries v0.7.0 chunk_hashes (per-chunk content binding
    introduced in PR #62)

Skipped automatically if docker is unavailable or the cross-zone compose
project isn't running. Bring it up with::

    docker compose -f docker-compose.cross-zone.yml up -d --build

then run::

    pytest tests/test_cross_zone_v07.py -v
"""

from __future__ import annotations

import shutil
import socket
import subprocess
from typing import Dict, List, Optional

import pytest

ALICE_HTTP = "http://127.0.0.1:18101"
BOB_HTTP = "http://127.0.0.1:18102"
ALICE_DNS = ("127.0.0.1", 15301)
BOB_DNS = ("127.0.0.1", 15302)

ALICE_ZONE = "alice.test"
BOB_ZONE = "bob.test"


def _docker_running() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        out = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return False
    names = out.stdout.split()
    return "dnsmesh-alice" in names and "dnsmesh-bob" in names


def _http_reachable(url: str) -> bool:
    try:
        host = url.split("//", 1)[1].split(":")[0]
        port = int(url.rsplit(":", 1)[1])
        with socket.create_connection((host, port), timeout=2):
            return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _docker_running()
    or not _http_reachable(ALICE_HTTP)
    or not _http_reachable(BOB_HTTP),
    reason="cross-zone compose project not up; run "
    "`docker compose -f docker-compose.cross-zone.yml up -d --build`",
)


class _HttpWriter:
    def __init__(self, base_url: str, token: Optional[str] = None):
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


class _ZoneRoutedDnsReader:
    """Routes TXT queries to the DNS server authoritative for the queried zone.

    DMP queries owner names like `slot-...alice.test` or
    `chunk-...bob.test`; we pick the server based on suffix match.
    """

    def __init__(self, zone_to_server: Dict[str, tuple]):
        self._routes = zone_to_server

    def _server_for(self, name: str) -> Optional[tuple]:
        n = name.lower().rstrip(".")
        for zone, server in self._routes.items():
            if n == zone or n.endswith("." + zone):
                return server
        return None

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        import dns.message
        import dns.query
        import dns.rdatatype

        server = self._server_for(name)
        if server is None:
            return None
        request = dns.message.make_query(
            name, dns.rdatatype.TXT, use_edns=0, payload=4096
        )
        try:
            response, _ = dns.query.udp_with_fallback(
                request, server[0], port=server[1], timeout=3.0
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


def _make_clients():
    from dmp.client.client import DMPClient

    routes = {ALICE_ZONE: ALICE_DNS, BOB_ZONE: BOB_DNS}
    reader = _ZoneRoutedDnsReader(routes)

    alice = DMPClient(
        "alice",
        "alice-pass",
        domain=ALICE_ZONE,
        writer=_HttpWriter(ALICE_HTTP),
        reader=reader,
        intro_queue_path=":memory:",
        prekey_store_path=":memory:",
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain=BOB_ZONE,
        writer=_HttpWriter(BOB_HTTP),
        reader=reader,
        intro_queue_path=":memory:",
        prekey_store_path=":memory:",
    )

    # Mutual contact pin so neither side falls into TOFU.
    alice.add_contact(
        "bob",
        bob.get_public_key_hex(),
        signing_key_hex=bob.get_signing_public_key_hex(),
        domain=BOB_ZONE,
    )
    bob.add_contact(
        "alice",
        alice.get_public_key_hex(),
        signing_key_hex=alice.get_signing_public_key_hex(),
        domain=ALICE_ZONE,
    )
    return alice, bob


def test_cross_zone_alice_to_bob():
    import uuid

    alice, bob = _make_clients()
    body = f"hello from alice.test [{uuid.uuid4()}]".encode()
    assert alice.send_message("bob", body.decode())
    inbox = bob.receive_messages()
    matching = [m for m in inbox if m.plaintext == body]
    assert matching, f"sent message not in bob's inbox; got {len(inbox)} messages"
    assert matching[0].sender_signing_pk == alice.crypto.get_signing_public_key_bytes()


def test_cross_zone_bidirectional():
    import uuid

    alice, bob = _make_clients()
    nonce = uuid.uuid4().hex[:8]
    ping = f"ping from alice {nonce}".encode()
    pong = f"pong from bob {nonce}".encode()
    assert alice.send_message("bob", ping.decode())
    assert bob.send_message("alice", pong.decode())

    bob_inbox = bob.receive_messages()
    alice_inbox = alice.receive_messages()

    assert any(m.plaintext == ping for m in bob_inbox)
    assert any(m.plaintext == pong for m in alice_inbox)


def test_cross_zone_manifest_carries_v07_chunk_hashes():
    """Confirm the v0.7.0 per-chunk content binding survives cross-zone.

    The cross-zone round-trip itself is already strong evidence: PR #66
    made the receive path refuse any manifest with an empty
    ``chunk_hashes`` tuple, so a successful decode means alice's send
    path emitted a populated tuple and bob's receive path verified each
    chunk hash before unwrap. We add a structural sanity check on
    ``SlotManifest`` round-tripping through ``to_body_bytes`` /
    ``from_body_bytes`` to make the assertion explicit.
    """
    from dmp.core.manifest import SlotManifest

    alice, bob = _make_clients()
    assert alice.send_message("bob", "wire format v0.7.0 check")
    inbox_after = bob.receive_messages()
    assert any(m.plaintext == b"wire format v0.7.0 check" for m in inbox_after)

    manifest = SlotManifest(
        msg_id=b"\x01" * 16,
        sender_spk=b"\x02" * 32,
        recipient_id=b"\x03" * 32,
        total_chunks=2,
        data_chunks=2,
        prekey_id=0,
        ts=0,
        exp=0,
        chunk_hashes=(b"\x11" * 32, b"\x22" * 32),
    )
    body = manifest.to_body_bytes()
    parsed = SlotManifest.from_body_bytes(body)
    assert parsed.chunk_hashes == manifest.chunk_hashes
    assert len(parsed.chunk_hashes) == parsed.total_chunks
