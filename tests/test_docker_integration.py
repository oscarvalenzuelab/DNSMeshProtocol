"""End-to-end integration test: boot the dnsmesh-node container, run a real client.

Skipped unless Docker is available and the dnsmesh-node:latest image is present.
Build the image first with `docker build -t dnsmesh-node:latest .`.

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
        not _image_exists("dnsmesh-node:latest"),
        reason="dnsmesh-node:latest image missing; run `docker build -t dnsmesh-node:latest .`",
    ),
]


@pytest.fixture
def node_container():
    """Run a fresh dnsmesh-node container bound to ephemeral host ports."""
    import requests  # deferred — avoid import at collection if dep missing

    name = f"dnsmesh-node-test-{uuid.uuid4().hex[:8]}"
    http_port = _free_port(socket.SOCK_STREAM)
    dns_port = _free_port(socket.SOCK_DGRAM)

    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            name,
            "-p",
            f"127.0.0.1:{dns_port}:5353/udp",
            "-p",
            f"127.0.0.1:{http_port}:8053/tcp",
            "-e",
            "DMP_LOG_LEVEL=WARNING",
            "dnsmesh-node:latest",
        ],
        check=True,
        capture_output=True,
    )

    # Wait for the health endpoint to come up.
    deadline = time.time() + 10.0
    while time.time() < deadline:
        try:
            r = requests.get(f"http://127.0.0.1:{http_port}/health", timeout=1)
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

        request = dns.message.make_query(
            name, dns.rdatatype.TXT, use_edns=0, payload=4096
        )
        try:
            response, _used_tcp = dns.query.udp_with_fallback(
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
        "alice",
        "alice-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    )
    alice.add_contact("bob", bob.get_public_key_hex())

    assert alice.send_message("bob", "hello from a real container")

    inbox = bob.receive_messages()
    assert len(inbox) == 1
    assert inbox[0].plaintext == b"hello from a real container"
    assert inbox[0].sender_signing_pk == alice.crypto.get_signing_public_key_bytes()


def test_container_survives_client_restart(node_container):
    """Alice sends, a fresh Bob process starts later and picks up the message."""
    from dmp.client.client import DMPClient

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice = DMPClient(
        "alice",
        "alice-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    )
    # Grab bob's pubkey without retaining the client instance.
    bob_pubkey = DMPClient(
        "bob",
        "bob-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    ).get_public_key_hex()
    alice.add_contact("bob", bob_pubkey)

    assert alice.send_message("bob", "delivered after restart")

    # A brand-new Bob process (fresh ReplayCache, no prior state) reads.
    bob_fresh = DMPClient(
        "bob",
        "bob-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
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
        "alice-fs",
        "alice-fs-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
        prekey_store_path=alice_prekeys,
    )
    bob = DMPClient(
        "bob-fs",
        "bob-fs-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
        prekey_store_path=bob_prekeys,
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

    bob_recipient_id = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
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
    contact. This exercises `dnsmesh identity publish` + `dnsmesh identity fetch`
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
        "alice-z",
        "alice-z-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
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


# ---------------------------------------------------------------------------
# M5.4 rotation — end-to-end against the container. Unit + fuzz coverage
# already exercises the wire formats; these add the missing "does it round-
# trip through a real published record plus a live chain walker" layer.
# ---------------------------------------------------------------------------


def _rotate_identity(
    old_client,
    new_passphrase: str,
    kdf_salt: bytes,
    *,
    revoke_reason=None,
    ttl: int = 300,
    exp_seconds: int = 86400 * 180,
):
    """Inline mirror of examples/docker_e2e_demo.py::rotate_identity.

    Duplicated here (rather than imported from examples/) because tests
    shouldn't depend on demo scripts. If this logic grows, promote it
    to dmp.client.
    """
    import time as _time

    from dmp.client.client import DMPClient
    from dmp.core.crypto import DMPCrypto
    from dmp.core.identity import identity_domain, make_record
    from dmp.core.rotation import (
        RevocationRecord,
        RotationRecord,
        SUBJECT_TYPE_USER_IDENTITY,
        rotation_rrset_name_user_identity,
    )

    old_crypto = old_client.crypto
    new_crypto = DMPCrypto.from_passphrase(new_passphrase, salt=kdf_salt)
    assert (
        new_crypto.get_signing_public_key_bytes()
        != old_crypto.get_signing_public_key_bytes()
    )

    subject = f"{old_client.username}@{old_client.domain}"
    ts = int(_time.time())
    seq = int(_time.time() * 1000)

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
    )
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
        )
    identity_rrset = identity_domain(old_client.username, old_client.domain)
    new_identity = make_record(new_crypto, old_client.username)
    assert old_client.writer.publish_txt_record(
        identity_rrset, new_identity.sign(new_crypto), ttl=ttl
    )

    return DMPClient(
        old_client.username,
        new_passphrase,
        domain=old_client.domain,
        writer=old_client.writer,
        reader=old_client.reader,
        kdf_salt=kdf_salt,
        rotation_chain_enabled=old_client.rotation_chain_enabled,
    )


def test_container_rotation_routine_chain_walk(node_container):
    """Alice rotates (routine, no revocation). Bob's rotation-aware client
    walks the chain from the pinned old spk to the new head and receives
    a message signed with the new key — no re-pin required."""
    from dmp.client.client import DMPClient
    from dmp.core.rotation import SUBJECT_TYPE_USER_IDENTITY

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice_salt = os.urandom(32)
    bob_salt = os.urandom(32)
    alice = DMPClient(
        "alice",
        "alice-pass-v1",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
        kdf_salt=alice_salt,
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
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

    alice_v2 = _rotate_identity(alice, "alice-pass-v2", alice_salt)

    resolved = bob._rotation_chain.resolve_current_spk(
        alice.crypto.get_signing_public_key_bytes(),
        f"alice@mesh.docker",
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert resolved == alice_v2.crypto.get_signing_public_key_bytes()

    # Re-pin with resolved head + deliver under the new key.
    bob.add_contact(
        "alice",
        alice_v2.get_public_key_hex(),
        signing_key_hex=resolved.hex(),
    )
    alice_v2.add_contact(
        "bob",
        bob.get_public_key_hex(),
        signing_key_hex=bob.crypto.get_signing_public_key_bytes().hex(),
    )
    assert alice_v2.send_message("bob", "post-rotation ping")
    inbox = bob.receive_messages()
    assert any(m.plaintext == b"post-rotation ping" for m in inbox), inbox


def test_container_rotation_compromise_revokes_old_key(node_container):
    """Compromise rotation publishes a RevocationRecord of the old key.
    The chain walker must refuse ANY path whose head or intermediate
    hops include a revoked key — return None rather than trusting
    forward."""
    from dmp.client.client import DMPClient
    from dmp.core.rotation import REASON_COMPROMISE, SUBJECT_TYPE_USER_IDENTITY

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice_salt = os.urandom(32)
    bob_salt = os.urandom(32)
    alice = DMPClient(
        "alice",
        "alice-pass-v1",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
        kdf_salt=alice_salt,
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
        kdf_salt=bob_salt,
        rotation_chain_enabled=True,
    )

    _rotate_identity(
        alice,
        "alice-pass-v2",
        alice_salt,
        revoke_reason=REASON_COMPROMISE,
    )

    # Bob still pinned on v1 — walker must refuse forward from a
    # key whose revocation is live on the RRset.
    resolved = bob._rotation_chain.resolve_current_spk(
        alice.crypto.get_signing_public_key_bytes(),
        f"alice@mesh.docker",
        SUBJECT_TYPE_USER_IDENTITY,
    )
    assert resolved is None


def test_container_concurrent_receive_delivers_exactly_once(node_container):
    """Atomic claim_for_decode prevents duplicate delivery under concurrent
    receive workers (P0-2).

    Setup: alice sends ONE message via a real dnsmesh-node container. Bob
    has a single DMPClient (one shared in-memory ReplayCache) and spawns
    16 threads that all call receive_messages() simultaneously against the
    same DNS+HTTP backend.

    Without the atomic claim/finalize/release on ReplayCache, all 16
    threads pass `has_seen` (still False), all 16 fetch+decrypt, all 16
    append the same plaintext to their result list, and the user observes
    duplicate delivery. With the fix, exactly one thread wins the
    claim_for_decode race and the rest see False and skip without
    decrypting.

    This is the end-to-end equivalent of the unit test
    test_concurrent_claims_only_one_wins, but exercises the real
    receive_messages pipeline (DNS query, manifest verify, chunk fetch,
    AEAD decrypt) against a real container — proves the wiring at the
    call site in client.py is correct, not just the ReplayCache primitive.
    """
    import threading

    from dmp.client.client import DMPClient

    writer = _HttpWriter(node_container["http_base"])
    reader = _DnsReader("127.0.0.1", node_container["dns_port"])

    alice = DMPClient(
        "alice-conc",
        "alice-conc-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    )
    bob = DMPClient(
        "bob-conc",
        "bob-conc-pass",
        domain="mesh.docker",
        writer=writer,
        reader=reader,
    )
    alice.add_contact("bob-conc", bob.get_public_key_hex())

    # Single message — exactly-once delivery is the property under test.
    payload = "concurrent-receive payload for the race test"
    payload_bytes = payload.encode("utf-8")
    assert alice.send_message("bob-conc", payload)

    # Confirm a single-threaded receive sees the message before we race —
    # otherwise a "0 winners" outcome could be misread as the property
    # holding when in fact the message just isn't there.
    sanity = bob.receive_messages()
    assert len(sanity) == 1, "sanity precheck: single-threaded recv saw nothing"
    assert sanity[0].plaintext == payload_bytes
    # That receive consumed the slot; re-publish to give the race something
    # to fight over.
    assert alice.send_message("bob-conc", payload)

    results: list = []
    results_lock = threading.Lock()
    start = threading.Event()
    errors: list = []

    def worker():
        start.wait()
        try:
            inbox = bob.receive_messages()
        except Exception as exc:  # bubble unexpected exceptions to the test
            with results_lock:
                errors.append(exc)
            return
        with results_lock:
            results.extend(inbox)

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join(timeout=30)

    assert not errors, f"workers raised: {errors}"
    # Total delivered messages across ALL threads must be exactly 1, even
    # though 16 threads raced to the same (sender_spk, msg_id).
    delivered_payloads = [m.plaintext for m in results]
    assert len(delivered_payloads) == 1, (
        f"duplicate delivery: 16 concurrent receivers produced "
        f"{len(delivered_payloads)} messages (expected 1)"
    )
    assert delivered_payloads[0] == payload_bytes
    # The seen set should now contain exactly the one (spk, msg_id).
    assert bob.replay_cache.size() == 2  # the precheck-delivered + the raced one
