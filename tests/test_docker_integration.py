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
            "dmp-node:latest",
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

        request = dns.message.make_query(name, dns.rdatatype.TXT)
        try:
            response = dns.query.udp(request, self._host, port=self._port, timeout=3.0)
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


# ---------------------------------------------------------------------------
# M5.8 heartbeat / directory surface — verify the endpoints are actually
# wired in the published docker image. Caught once by hand after merging
# M5.8 against a stale locally-tagged image; this keeps it caught.
# ---------------------------------------------------------------------------


@pytest.fixture
def heartbeat_node_container(tmp_path):
    """Run a dmp-node container with the heartbeat layer opted in."""
    import requests

    seed = os.urandom(32)
    key_path = tmp_path / "operator-ed25519.hex"
    key_path.write_text(seed.hex())
    key_path.chmod(0o400)

    name = f"dmp-node-hb-{uuid.uuid4().hex[:8]}"
    http_port = _free_port(socket.SOCK_STREAM)
    dns_port = _free_port(socket.SOCK_DGRAM)

    # Self-endpoint must pass _validate_endpoint (rejects loopback /
    # private IPs), so use a public-looking hostname. We never actually
    # resolve it — the worker has no seed peers configured, so outbound
    # ticks are a no-op and only our test's POST exercises the store.
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
            "-e",
            "DMP_HEARTBEAT_ENABLED=1",
            "-e",
            "DMP_HEARTBEAT_SELF_ENDPOINT=https://dmp-test-self.example.com",
            "-e",
            "DMP_HEARTBEAT_OPERATOR_KEY_PATH=/etc/dmp/operator.hex",
            "-e",
            # High interval so the worker's own tick doesn't race the test.
            "DMP_HEARTBEAT_INTERVAL_SECONDS=3600",
            "-v",
            f"{key_path}:/etc/dmp/operator.hex:ro",
            "dmp-node:latest",
        ],
        check=True,
        capture_output=True,
    )

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
            "http_base": f"http://127.0.0.1:{http_port}",
            "self_endpoint": "https://dmp-test-self.example.com",
            "self_spk_hex": None,  # filled in by first /v1/nodes/seen call
        }
    finally:
        subprocess.run(["docker", "stop", name], capture_output=True, timeout=10)


def _make_heartbeat_wire(
    endpoint: str,
    *,
    ttl_seconds: int = 3600,
    version: str = "test-1",
) -> tuple[str, str]:
    """Build + sign a HeartbeatRecord from a fresh operator seed.

    Returns (wire, operator_spk_hex) so the test can match it back in
    the server's /v1/nodes/seen output.
    """
    import time as _time

    from dmp.core.heartbeat import HeartbeatRecord
    from dmp.core.operator_signer import OperatorSigner

    signer = OperatorSigner(os.urandom(32))
    now = int(_time.time())
    record = HeartbeatRecord(
        endpoint=endpoint,
        operator_spk=signer.get_signing_public_key_bytes(),
        version=version,
        ts=now,
        exp=now + ttl_seconds,
    )
    wire = record.sign(signer)
    return wire, signer.get_signing_public_key_bytes().hex()


def test_container_heartbeat_self_listing(heartbeat_node_container):
    """GET /v1/nodes/seen on a fresh heartbeat-enabled container.

    Proves the endpoint is wired, the operator key loaded, and the
    self-identity block echoes what the operator configured. Does
    NOT require the worker to have ticked yet.
    """
    import requests

    r = requests.get(
        f"{heartbeat_node_container['http_base']}/v1/nodes/seen", timeout=3
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["version"] == 1
    assert body["self"]["endpoint"] == heartbeat_node_container["self_endpoint"]
    assert body["self"]["enabled"] is True
    spk_hex = body["self"]["operator_spk_hex"]
    assert isinstance(spk_hex, str) and len(spk_hex) == 64
    bytes.fromhex(spk_hex)  # valid hex
    assert isinstance(body["seen"], list)


def test_container_heartbeat_submit_and_observe(heartbeat_node_container):
    """POST a signed heartbeat, then GET /v1/nodes/seen — must see it.

    Verifies the full M5.8 surface end-to-end against the published
    container: POST route, signature verification, seen-store write,
    gossip-on-ping response, GET route re-emission.
    """
    import requests

    from dmp.core.heartbeat import HeartbeatRecord

    wire, peer_spk_hex = _make_heartbeat_wire("https://peer-a.example.com")

    post = requests.post(
        f"{heartbeat_node_container['http_base']}/v1/heartbeat",
        json={"wire": wire},
        timeout=3,
    )
    assert post.status_code == 200, post.text
    post_body = post.json()
    assert post_body["ok"] is True
    assert post_body["accepted_operator_spk_hex"] == peer_spk_hex
    # Fresh node has no other operators yet — gossip list is empty.
    assert post_body["seen"] == []

    # GET shows the submitted heartbeat (re-verify it server-side too).
    get = requests.get(
        f"{heartbeat_node_container['http_base']}/v1/nodes/seen", timeout=3
    )
    assert get.status_code == 200, get.text
    seen = get.json()["seen"]
    wires = [e["wire"] for e in seen if isinstance(e, dict) and "wire" in e]
    assert wire in wires

    parsed = HeartbeatRecord.parse_and_verify(wire)
    assert parsed is not None
    assert parsed.endpoint == "https://peer-a.example.com"
    assert bytes(parsed.operator_spk).hex() == peer_spk_hex


def test_container_heartbeat_rejects_unsigned(heartbeat_node_container):
    """POST /v1/heartbeat must 4xx on any wire that fails parse_and_verify.

    Forged signature (random 64 bytes in the sig slot) is the
    canonical attacker shape; the server's public contract says the
    signature is the auth, so a server that accepts this has silently
    lost the whole trust model.
    """
    import base64
    import requests

    from dmp.core.heartbeat import HeartbeatRecord
    from dmp.core.operator_signer import OperatorSigner

    signer = OperatorSigner(os.urandom(32))
    import time as _time

    now = int(_time.time())
    record = HeartbeatRecord(
        endpoint="https://forged.example.com",
        operator_spk=signer.get_signing_public_key_bytes(),
        version="test-1",
        ts=now,
        exp=now + 3600,
    )
    body = record.to_body_bytes()
    # Replace the real signature with zeros — parse_and_verify must
    # reject at the Ed25519 verify step.
    forged = "v=dmp1;t=heartbeat;" + base64.b64encode(body + b"\x00" * 64).decode(
        "ascii"
    )

    r = requests.post(
        f"{heartbeat_node_container['http_base']}/v1/heartbeat",
        json={"wire": forged},
        timeout=3,
    )
    assert r.status_code == 400, r.text

    # And it must NOT appear in the public feed.
    get = requests.get(
        f"{heartbeat_node_container['http_base']}/v1/nodes/seen", timeout=3
    )
    wires = [e.get("wire") for e in get.json().get("seen", [])]
    assert forged not in wires


def test_container_heartbeat_aggregator_roundtrip(heartbeat_node_container, tmp_path):
    """Run examples/directory_aggregator.py against the live container.

    End-to-end proof that (a) the container's /v1/nodes/seen is
    aggregator-compatible, (b) aggregate() verifies the submitted
    wire, and (c) the emitted feed.json + index.html carry that
    operator.
    """
    import json
    import requests

    wire, peer_spk_hex = _make_heartbeat_wire("https://peer-b.example.com")
    r = requests.post(
        f"{heartbeat_node_container['http_base']}/v1/heartbeat",
        json={"wire": wire},
        timeout=3,
    )
    assert r.status_code == 200, r.text

    out_dir = tmp_path / "public"
    from examples.directory_aggregator import main as aggregator_main

    rc = aggregator_main(
        [
            "--seed",
            heartbeat_node_container["http_base"],
            "--out-dir",
            str(out_dir),
            "--log-level",
            "ERROR",
        ]
    )
    assert rc == 0

    feed_path = out_dir / "feed.json"
    index_path = out_dir / "index.html"
    assert feed_path.exists() and index_path.exists()

    feed = json.loads(feed_path.read_text())
    nodes = feed.get("nodes") or feed.get("seen") or []
    spk_hexes = {n.get("operator_spk_hex") for n in nodes if isinstance(n, dict)}
    assert peer_spk_hex in spk_hexes, feed

    html = index_path.read_text()
    assert "peer-b.example.com" in html
    # HTML abbreviates the spk to first 8 + last 4 hex chars in a
    # <code> block (see examples/directory_aggregator.py::emit_html).
    assert peer_spk_hex[:8] in html
    assert peer_spk_hex[-4:] in html
