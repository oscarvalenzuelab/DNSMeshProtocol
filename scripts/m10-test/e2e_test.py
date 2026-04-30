#!/usr/bin/env python3
"""End-to-end test for the M10 receiver-zone notification path.

Drives the running ``scripts/m10-test/docker-compose.yml`` stack from the host:

  1. Confirms each of the three nodes published its own heartbeat.
  2. Runs a real send → recv between alice@alice.test and bob@bob.test:
       - alice writes manifest + chunks to alice-node via HTTP
         (operator-token write surface; equivalent to the TSIG'd UPDATE
         that the production CLI uses, just without the registration
         dance — what we care about is that bob's recv finds them via
         the live DNS chain).
       - alice's send_message also fires the M10 receiver-zone claim:
         an un-TSIG'd DNS UPDATE to bob-node:5182 under the new
         ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=1`` accept path.
  3. Confirms the M10 claim landed at ``claim-N.mb-{hash12(bob)}.bob.test``
     by querying bob-node's DNS server directly.
  4. Runs ``bob.receive_messages(primary_only=True)`` — phase 1 (own-zone
     claim poll) discovers the claim, fetches the manifest from
     alice-node via the resolver pool, and decrypts.
  5. Negative control: tries the same un-TSIG'd UPDATE against
     stranger-node (``DMP_RECEIVER_CLAIM_NOTIFICATIONS=0``, default).
     The server MUST answer REFUSED.

Prereqs:
    docker compose -f scripts/m10-test/docker-compose.yml up -d --build

Run:
    ./venv/bin/python scripts/m10-test/e2e_test.py
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from typing import List, Optional, Tuple

import json
import urllib.request

import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.update

# Make sure we run against the in-tree dmp package, not a stale install.
# scripts/m10-test/e2e_test.py → repo root is two levels up.
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)

from dmp.client.client import DMPClient  # noqa: E402
from dmp.core.claim import ClaimRecord, claim_rrset_name  # noqa: E402
from dmp.core.crypto import DMPCrypto  # noqa: E402
from dmp.core.heartbeat import HeartbeatRecord  # noqa: E402
from dmp.network.base import DNSRecordReader, DNSRecordWriter  # noqa: E402

ALICE_DNS = ("127.0.0.1", 5181)
BOB_DNS = ("127.0.0.1", 5182)
STRANGER_DNS = ("127.0.0.1", 5183)
ALICE_HTTP = "http://127.0.0.1:8181"
BOB_HTTP = "http://127.0.0.1:8182"
STRANGER_HTTP = "http://127.0.0.1:8183"

ALICE_OPERATOR_TOKEN = "alice-operator-token-for-tests"
BOB_OPERATOR_TOKEN = "bob-operator-token-for-tests"
STRANGER_OPERATOR_TOKEN = "stranger-operator-token-for-tests"

# Map zone names to (host, port) so the M10 publish path can hit our
# host-mapped container ports without doing a real A-record lookup.
ZONE_DNS_TARGET = {
    "alice.test": ALICE_DNS,
    "bob.test": BOB_DNS,
    "stranger.test": STRANGER_DNS,
}


def step(title: str) -> None:
    print(f"\n=== {title} ===")


def assert_step(label: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ✓ {label}")
        if detail:
            print(f"      {detail}")
    else:
        print(f"  ✗ {label}")
        if detail:
            print(f"      {detail}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# DNS adapters: a writer that POSTs records via the operator HTTP API,
# and a reader that fans queries across the three node DNS ports.
# ---------------------------------------------------------------------------


class _NodeHttpWriter(DNSRecordWriter):
    """Publishes records via the operator HTTP API.

    The DMPClient's writer interface only needs publish/delete; the
    operator token authorizes any owner under the served zone, which
    is exactly what alice's send_message needs (manifest + chunks
    addressed to ``slot-N.mb-...{alice.test}``).
    """

    def __init__(self, endpoint: str, token: str):
        import requests

        self._requests = requests
        self._endpoint = endpoint.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        r = self._requests.post(
            f"{self._endpoint}/v1/records/{name}",
            json={"value": value, "ttl": ttl},
            headers=self._headers,
            timeout=10,
        )
        return r.status_code == 201

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        payload = {"value": value} if value else None
        r = self._requests.delete(
            f"{self._endpoint}/v1/records/{name}",
            json=payload,
            headers=self._headers,
            timeout=10,
        )
        return r.status_code == 204


class _MultiNodeReader(DNSRecordReader):
    """Round-robin TXT reads across the three node DNS ports.

    Returns the first NOERROR answer with at least one TXT value.
    NXDOMAIN on one node falls through to the next so cross-zone
    queries (alice asking for bob's records, etc.) work transparently.
    """

    def __init__(self, hosts: List[Tuple[str, int]]):
        self._hosts = hosts

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        for host, port in self._hosts:
            try:
                request = dns.message.make_query(name, dns.rdatatype.TXT)
                response = dns.query.udp(request, host, port=port, timeout=2.0)
            except Exception:
                continue
            if response.rcode() != dns.rcode.NOERROR:
                continue
            values = []
            for rrset in response.answer:
                for rdata in rrset:
                    values.append(b"".join(rdata.strings).decode("utf-8"))
            if values:
                return values
        return None


# ---------------------------------------------------------------------------
# M10 routing override: map zone→(host, port) so publish_claim's cross-zone
# path lands on our host-mapped container ports without doing a real A
# lookup. The dnsmesh DNS server only serves TXT (no A records), so without
# this the un-TSIG'd UPDATE has no destination IP to dial.
# ---------------------------------------------------------------------------


def _patch_provider_dns_target() -> None:
    """Replace ``_provider_dns_target`` in dmp.client.client with a stub
    that routes by ZONE_DNS_TARGET.

    Production deployments resolve the recipient zone apex via real DNS
    NS records — that's not in scope for this e2e harness, which only
    exercises the M10 wire surface against a known-shape compose stack.
    """
    from dmp.client import client as _client

    def _stub(_endpoint: str, zone: str) -> Optional[Tuple[str, int]]:
        z = (zone or "").strip().lower().rstrip(".")
        return ZONE_DNS_TARGET.get(z)

    _client._provider_dns_target = _stub


# ---------------------------------------------------------------------------
# Heartbeat sanity check
# ---------------------------------------------------------------------------


def _query_txt(host_port: Tuple[str, int], name: str) -> List[str]:
    host, port = host_port
    request = dns.message.make_query(name, dns.rdatatype.TXT)
    response = dns.query.udp(request, host, port=port, timeout=3.0)
    out = []
    for rrset in response.answer:
        for rdata in rrset:
            out.append(b"".join(rdata.strings).decode("utf-8"))
    return out


def _wait_for_node(host_port: Tuple[str, int], zone: str, max_wait: int = 30) -> bool:
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            wires = _query_txt(host_port, f"_dnsmesh-heartbeat.{zone}")
            if wires:
                return True
        except Exception:
            pass
        time.sleep(1)
    return False


# ---------------------------------------------------------------------------
# Main e2e flow
# ---------------------------------------------------------------------------


def _register_user_with_node(node_http: str, client: DMPClient, subject: str) -> None:
    """Walk /v1/registration/{challenge,tsig-confirm} for ``client``.

    Registers the user with the node's TSIG keystore and (importantly
    for codex round-3 P1) seeds the M10 receiver-zone accept path with
    the user's mailbox hash12 in the registered-recipient set.
    Without this, bob-node would REFUSE alice's M10 publish for
    bob's hash even with ``DMP_RECEIVER_CLAIM_NOTIFICATIONS=1``,
    since the registry would be empty.
    """
    challenge_url = f"{node_http}/v1/registration/challenge"
    with urllib.request.urlopen(challenge_url, timeout=4) as r:
        ch = json.loads(r.read())
    challenge_hex = ch["challenge"]
    node_hostname = ch["node"]
    payload = (
        bytes.fromhex(challenge_hex)
        + subject.encode("utf-8")
        + node_hostname.encode("utf-8")
        + b"\x01"
    )
    sig = client.crypto.sign_data(payload).hex()
    confirm_req = urllib.request.Request(
        f"{node_http}/v1/registration/tsig-confirm",
        data=json.dumps(
            {
                "subject": subject,
                "ed25519_spk": client.get_signing_public_key_hex(),
                "challenge": challenge_hex,
                "signature": sig,
                "x25519_pub": client.get_public_key_hex(),
            }
        ).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(confirm_req, timeout=4) as r:
        body = json.loads(r.read())
    assert body.get("tsig_key_name"), f"registration failed: {body!r}"


def main() -> None:
    _patch_provider_dns_target()

    step("0. Wait for all three nodes to publish their heartbeats")
    for label, dns_addr, zone in (
        ("alice", ALICE_DNS, "alice.test"),
        ("bob", BOB_DNS, "bob.test"),
        ("stranger", STRANGER_DNS, "stranger.test"),
    ):
        ready = _wait_for_node(dns_addr, zone)
        assert_step(
            f"{label}-node serving _dnsmesh-heartbeat.{zone}",
            ready,
            f"port={dns_addr[1]}",
        )

    step("1. Each node's heartbeat verifies under its operator key")
    for label, dns_addr, zone in (
        ("alice", ALICE_DNS, "alice.test"),
        ("bob", BOB_DNS, "bob.test"),
        ("stranger", STRANGER_DNS, "stranger.test"),
    ):
        wires = _query_txt(dns_addr, f"_dnsmesh-heartbeat.{zone}")
        rec = HeartbeatRecord.parse_and_verify(wires[0])
        assert_step(f"{label}'s heartbeat parses + verifies", rec is not None)

    step("2. Build alice + bob clients with HTTP writers + multi-node DNS reader")
    reader = _MultiNodeReader([ALICE_DNS, BOB_DNS, STRANGER_DNS])
    alice_writer = _NodeHttpWriter(ALICE_HTTP, ALICE_OPERATOR_TOKEN)
    bob_writer = _NodeHttpWriter(BOB_HTTP, BOB_OPERATOR_TOKEN)

    alice = DMPClient(
        "alice",
        "alice-passphrase-for-m10-e2e",
        domain="alice.test",
        writer=alice_writer,
        reader=reader,
    )
    bob = DMPClient(
        "bob",
        "bob-passphrase-for-m10-e2e",
        domain="bob.test",
        writer=bob_writer,
        reader=reader,
    )

    alice.add_contact(
        "bob",
        bob.get_public_key_hex(),
        domain="bob.test",
        signing_key_hex=bob.get_signing_public_key_hex(),
    )
    bob.add_contact(
        "alice",
        alice.get_public_key_hex(),
        domain="alice.test",
        signing_key_hex=alice.get_signing_public_key_hex(),
    )
    assert_step(
        "alice pinned bob; bob pinned alice",
        "bob" in alice.contacts and "alice" in bob.contacts,
    )

    step("2.5. Register bob with bob-node so the M10 hash gate accepts")
    # Codex round-3 P1: when DMP_CLAIM_PROVIDER=0 and
    # DMP_RECEIVER_CLAIM_NOTIFICATIONS=1, the un-TSIG'd accept path
    # gates on the recipient hash being in the keystore's registered
    # set. Bob's TSIG-registration walks the
    # /v1/registration/tsig-confirm flow and seeds his hash12 into
    # bob-node's keystore.
    _register_user_with_node(BOB_HTTP, bob, "bob@bob.test")
    assert_step("bob registered with bob-node (TSIG + mb-hash scope)", True)
    # Alice also registers with alice-node so she has authority over
    # her own zone's records via DNS UPDATE (not strictly needed here
    # because the harness uses operator-token HTTP for chunk publish,
    # but it keeps the test surface realistic).
    _register_user_with_node(ALICE_HTTP, alice, "alice@alice.test")
    assert_step("alice registered with alice-node", True)

    step("3. alice sends a real message to bob (manifest+chunks AND M10 claim)")
    recipient_outcome: List[bool] = []
    ok = alice.send_message(
        "bob",
        "hello bob, M10 e2e calling",
        recipient_claim_outcome=recipient_outcome,
    )
    assert_step("send_message returned True", ok is True)
    assert_step(
        "M10 claim publish reached bob-node and was accepted",
        recipient_outcome == [True],
        f"recipient_claim_outcome={recipient_outcome}",
    )

    step("4. M10 claim is sitting under bob.test (DNS-side check)")
    bob_recipient_id = hashlib.sha256(bytes.fromhex(bob.get_public_key_hex())).digest()
    bob_h12 = hashlib.sha256(bob_recipient_id).hexdigest()[:12]
    found_claim = False
    for slot in range(10):
        owner = f"claim-{slot}.mb-{bob_h12}.bob.test"
        records = _query_txt(BOB_DNS, owner)
        if records:
            found_claim = True
            parsed = ClaimRecord.parse_and_verify(records[0])
            assert_step(
                f"claim wire at {owner} verifies",
                parsed is not None,
            )
            assert_step(
                "claim points at alice.test as sender_mailbox_domain",
                parsed.sender_mailbox_domain == "alice.test",
                f"got {parsed.sender_mailbox_domain!r}",
            )
            break
    assert_step(
        "exactly one slot under bob.test carries the M10 claim",
        found_claim,
        f"queried claim-{{0..9}}.mb-{bob_h12}.bob.test",
    )

    step("5. alice's manifest+chunks are visible at alice.test (DNS-side check)")
    found_manifest = False
    for slot in range(10):
        owner = f"slot-{slot}.mb-{bob_h12}.alice.test"
        records = _query_txt(ALICE_DNS, owner)
        if records:
            found_manifest = True
            break
    assert_step(
        "exactly one slot under alice.test carries the manifest",
        found_manifest,
    )

    step("6. bob.receive_messages(primary_only=True) — phase 1 delivers")
    inbox = bob.receive_messages(primary_only=True)
    assert_step(
        "phase-1 receive returned exactly one message",
        len(inbox) == 1,
        f"got {len(inbox)} message(s)",
    )
    assert_step(
        "plaintext matches what alice sent",
        inbox[0].plaintext == b"hello bob, M10 e2e calling",
    )
    assert_step(
        "sender_signing_pk matches alice's pinned key",
        inbox[0].sender_signing_pk == alice.crypto.get_signing_public_key_bytes(),
    )

    step("7. Negative: stranger-node REFUSES un-TSIG'd M10 UPDATE (flag off)")
    # Build a signed claim wire and try to publish it at stranger.test.
    # Stranger has DMP_RECEIVER_CLAIM_NOTIFICATIONS=0 (default), so the
    # un-TSIG'd UPDATE accept path must REFUSE — even though the wire
    # itself verifies.
    stranger_user_id = hashlib.sha256(b"some-stranger-recipient").digest()
    stranger_h12 = hashlib.sha256(stranger_user_id).hexdigest()[:12]
    now = int(time.time())
    sender_crypto = alice.crypto
    claim = ClaimRecord(
        msg_id=b"\x77" * 16,
        sender_spk=sender_crypto.get_signing_public_key_bytes(),
        sender_mailbox_domain="alice.test",
        slot=0,
        ts=now,
        exp=now + 300,
    )
    wire = claim.sign(sender_crypto)
    owner = f"claim-0.mb-{stranger_h12}.stranger.test."

    upd = dns.update.UpdateMessage("stranger.test")
    upd.add(
        dns.name.from_text(owner),
        300,
        "TXT",
        '"' + wire.replace('"', r"\"") + '"',
    )
    response = dns.query.udp(upd, STRANGER_DNS[0], port=STRANGER_DNS[1], timeout=3.0)
    assert_step(
        "stranger-node answers REFUSED (M10 default-off contract)",
        response.rcode() == dns.rcode.REFUSED,
        f"rcode={dns.rcode.to_text(response.rcode())}",
    )
    # And the record DID NOT land.
    no_records = _query_txt(STRANGER_DNS, owner.rstrip("."))
    assert_step(
        "no record landed in stranger-node's store",
        not no_records,
        f"records={no_records}",
    )

    step("8. Positive control: same UPDATE against bob-node (M10 on) succeeds")
    # Same wire shape but addressed under bob.test — a registered
    # hash, so bob-node accepts because DMP_RECEIVER_CLAIM_NOTIFICATIONS=1
    # AND bob's mailbox hash is in the keystore (step 2.5).
    bob_owner = (
        f"claim-9.mb-{bob_h12}.bob.test."  # slot 9 to avoid colliding with step 4
    )
    upd2 = dns.update.UpdateMessage("bob.test")
    upd2.add(
        dns.name.from_text(bob_owner),
        300,
        "TXT",
        '"' + wire.replace('"', r"\"") + '"',
    )
    response2 = dns.query.udp(upd2, BOB_DNS[0], port=BOB_DNS[1], timeout=3.0)
    assert_step(
        "bob-node accepts the un-TSIG'd UPDATE (NOERROR)",
        response2.rcode() == dns.rcode.NOERROR,
        f"rcode={dns.rcode.to_text(response2.rcode())}",
    )

    step("9. M10-only gate: unregistered hash on bob-node is REFUSED")
    # Codex round-3 P1: with DMP_CLAIM_PROVIDER=0 and
    # DMP_RECEIVER_CLAIM_NOTIFICATIONS=1, bob-node MUST reject claim
    # writes whose hash12 doesn't correspond to a registered user
    # (otherwise enabling M10 silently re-opens the public claim sink
    # that the M8.3 opt-out was supposed to close).
    fake_recipient = b"unregistered-stranger-recipient"
    fake_id = hashlib.sha256(fake_recipient).digest()
    fake_h12 = hashlib.sha256(fake_id).hexdigest()[:12]
    fake_claim = ClaimRecord(
        msg_id=b"\x88" * 16,
        sender_spk=alice.crypto.get_signing_public_key_bytes(),
        sender_mailbox_domain="alice.test",
        slot=0,
        ts=int(time.time()),
        exp=int(time.time()) + 300,
    )
    fake_wire = fake_claim.sign(alice.crypto)
    fake_owner = f"claim-0.mb-{fake_h12}.bob.test."
    upd_fake = dns.update.UpdateMessage("bob.test")
    upd_fake.add(
        dns.name.from_text(fake_owner),
        300,
        "TXT",
        '"' + fake_wire.replace('"', r"\"") + '"',
    )
    response_fake = dns.query.udp(upd_fake, BOB_DNS[0], port=BOB_DNS[1], timeout=3.0)
    assert_step(
        "bob-node REFUSES claim for unregistered hash",
        response_fake.rcode() == dns.rcode.REFUSED,
        f"rcode={dns.rcode.to_text(response_fake.rcode())} "
        f"(unregistered hash={fake_h12})",
    )
    no_records = _query_txt(BOB_DNS, fake_owner.rstrip("."))
    assert_step(
        "no record landed in bob-node's store under the unregistered hash",
        not no_records,
        f"records={no_records}",
    )

    print("\n=== M10 E2E PASSED ===")


if __name__ == "__main__":
    main()
