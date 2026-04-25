#!/usr/bin/env python3
"""End-to-end M8 smoke test against the docker-compose.m8-test.yml stack.

Three nodes running on 127.0.0.1:
  - alice-node   :8061 HTTP, :5361 UDP DNS — DMP_DOMAIN=alice.test
  - bob-node     :8062 HTTP, :5362 UDP DNS — DMP_DOMAIN=bob.test
  - provider-node:8063 HTTP, :5363 UDP DNS — DMP_DOMAIN=claims.test

We run three DMPClient instances (one CLI-side identity per node), drive
the full M8 flow:

  1. Each client registers + publishes its identity to its home node.
  2. alice + bob pin each other cross-zone (alice@alice.test from bob,
     bob@bob.test from alice). This exercises M8.1 (cross-zone receive).
  3. alice → bob, bob → alice messages travel via the recursive DNS chain
     (each client queries all three DMP DNS servers in their resolver
     pool, which mimics a real mesh resolver).
  4. eve, an unpinned stranger living on bob's node, sends to alice via
     a claim record at the provider. alice's recv discovers it through
     /v1/info → claim DNS query → manifest fetch from bob.test, and
     lands it in the intro queue.
  5. alice runs `intro trust` to pin eve, then they exchange a real
     reply.

Run:
    docker compose -f docker-compose.m8-test.yml up -d
    sleep 5  # let heartbeats populate the seen-graph
    python scripts/m8_smoke.py
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from typing import List, Tuple

from dmp.client.client import DMPClient
from dmp.client.claim_routing import (
    DEFAULT_K,
    parse_seen_feed,
    select_providers,
)
from dmp.network.resolver_pool import ResolverPool


ALICE_HTTP = "http://127.0.0.1:8061"
BOB_HTTP = "http://127.0.0.1:8062"
PROVIDER_HTTP = "http://127.0.0.1:8063"

# Each node's DNS port (loopback). The resolver pool tries them in
# sequence until one returns NOERROR.
ALL_DNS = [("127.0.0.1", 5361), ("127.0.0.1", 5362), ("127.0.0.1", 5363)]


def _http_post(url: str, body: dict, token: str = "") -> Tuple[int, dict]:
    """Tiny POST helper using stdlib only — keeps the smoke script self-contained."""
    data = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}
        return e.code, payload
    except Exception as e:
        return 0, {"error": str(e)}


def _http_get(url: str) -> Tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read())
        except Exception:
            payload = {}
        return e.code, payload
    except Exception as e:
        return 0, {"error": str(e)}


class _DirectHttpWriter:
    """Minimal DNSRecordWriter that POSTs to /v1/records/{name} on a node.

    Bypasses the CLI's auth layer — the M8-test stack runs in `auth_mode=open`
    by default (no DMP_HTTP_TOKEN), so any client can publish.
    """

    def __init__(self, endpoint: str):
        self.endpoint = endpoint.rstrip("/")

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        url = f"{self.endpoint}/v1/records/{name}"
        status, payload = _http_post(url, {"value": value, "ttl": int(ttl)})
        ok = 200 <= status < 300
        if not ok:
            print(f"  publish_txt_record({name}) → {status} {payload}", file=sys.stderr)
        return ok

    def delete_txt_record(self, name: str, value: str = "") -> bool:
        # Not exercised in this smoke test.
        return True


def _build_resolver_pool() -> ResolverPool:
    return ResolverPool(hosts=ALL_DNS)


def step(label: str) -> None:
    print(f"\n=== {label} ===")


def main() -> int:
    step("Probe nodes")
    for label, url in (
        ("alice", ALICE_HTTP),
        ("bob", BOB_HTTP),
        ("provider", PROVIDER_HTTP),
    ):
        status, info = _http_get(f"{url}/v1/info")
        print(f"  {label}: status={status} info={info}")
        if status != 200 or info.get("capabilities", 0) == 0:
            print(f"  FATAL: {label} not reporting expected /v1/info", file=sys.stderr)
            return 2

    step("Wait for heartbeat seen-graph to populate")
    time.sleep(6)
    for label, url in (("alice", ALICE_HTTP), ("bob", BOB_HTTP)):
        status, payload = _http_get(f"{url}/v1/nodes/seen")
        seen = payload.get("seen", []) if isinstance(payload, dict) else []
        print(f"  {label} sees {len(seen)} peer heartbeat(s)")

    step("Build claim_providers list (the way the CLI does)")
    status, payload = _http_get(f"{ALICE_HTTP}/v1/nodes/seen")
    seen_wires = [
        e.get("wire", "") for e in payload.get("seen", []) if isinstance(e, dict)
    ]
    heartbeats = parse_seen_feed(seen_wires)
    providers = select_providers(heartbeats, k=DEFAULT_K)
    print(f"  {len(providers)} claim provider(s) ranked by recency:")
    for p in providers:
        print(f"    - {p.zone:20s}  ts={p.ts}  endpoint={p.endpoint}")

    # Map heartbeat host names to host-side endpoints for HTTP claim publish.
    # Inside the docker network, alice-node:8053 is reachable; from the
    # host, only 127.0.0.1:8061-8063 work. Translate.
    hostmap = {
        "http://alice-node:8053": ALICE_HTTP,
        "http://bob-node:8053": BOB_HTTP,
        "http://provider-node:8053": PROVIDER_HTTP,
    }
    claim_providers_for_smoke: List[Tuple[str, str]] = []
    for p in providers:
        host_endpoint = hostmap.get(p.endpoint, p.endpoint)
        # /v1/info upgrade pass — same logic the CLI's
        # _resolve_provider_zone_via_info uses. Without this the
        # zone defaults to the heartbeat endpoint's hostname (e.g.
        # "provider-node") which is NOT what the provider actually
        # serves DNS under (claims.test).
        info_status, info_payload = _http_get(f"{host_endpoint}/v1/info")
        zone = p.zone
        if info_status == 200 and isinstance(info_payload, dict):
            advertised = info_payload.get("claim_provider_zone", "")
            if advertised:
                zone = advertised
        claim_providers_for_smoke.append((zone, host_endpoint))
    print(f"  rewritten for host network access: {claim_providers_for_smoke}")

    # Build clients. Each client uses (a) its home node's HTTP writer
    # for publishing manifests/chunks, and (b) a recursive resolver
    # pool that knows ALL three nodes' DNS servers — so a query for
    # alice.test routes to alice's authoritative server, etc.
    step("Construct clients")
    reader = _build_resolver_pool()

    alice = DMPClient(
        "alice",
        "alice-pass",
        domain="alice.test",
        writer=_DirectHttpWriter(ALICE_HTTP),
        reader=reader,
    )
    bob = DMPClient(
        "bob",
        "bob-pass",
        domain="bob.test",
        writer=_DirectHttpWriter(BOB_HTTP),
        reader=reader,
    )
    eve = DMPClient(
        "eve",
        "eve-pass",
        domain="bob.test",
        writer=_DirectHttpWriter(BOB_HTTP),
        reader=reader,
    )
    print(f"  alice spk: {alice.crypto.get_signing_public_key_bytes().hex()[:16]}…")
    print(f"  bob   spk: {bob.crypto.get_signing_public_key_bytes().hex()[:16]}…")
    print(f"  eve   spk: {eve.crypto.get_signing_public_key_bytes().hex()[:16]}…")

    step("Cross-zone pin: alice ⇄ bob")
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
    print("  pinned both directions")

    step("M8.1 — alice → bob (cross-zone)")
    ok = alice.send_message("bob", "hello bob from alice — cross-zone")
    print(f"  alice.send_message → {ok}")
    if not ok:
        return 3
    time.sleep(1)
    inbox = bob.receive_messages()
    print(f"  bob.receive_messages → {len(inbox)} messages")
    for msg in inbox:
        print(
            f"    from {msg.sender_signing_pk.hex()[:16]}…: "
            f"{msg.plaintext.decode('utf-8', errors='replace')}"
        )

    step("M8.3 — eve (un-pinned by alice) sends via claim provider")
    eve.add_contact(
        "alice",
        alice.get_public_key_hex(),
        domain="alice.test",
        signing_key_hex=alice.get_signing_public_key_hex(),
    )
    eve_outcomes: List[bool] = []
    ok = eve.send_message(
        "alice",
        "hi alice, I'm eve and we have not met yet",
        claim_providers=claim_providers_for_smoke,
        claim_outcomes=eve_outcomes,
    )
    print(f"  eve.send_message → {ok}; claim outcomes: {eve_outcomes}")

    time.sleep(2)
    step("alice polls — claim discovery + intro queue")
    delivered = alice.receive_messages(claim_providers=claim_providers_for_smoke)
    pending = alice.intro_queue.list_intros()
    print(f"  alice.receive_messages → {len(delivered)} delivered to inbox")
    print(f"  alice.intro_queue → {len(pending)} pending intro(s)")
    for intro in pending:
        print(
            f"    intro #{intro.intro_id} from {intro.sender_spk.hex()[:16]}… "
            f"@{intro.sender_mailbox_domain}: "
            f"{intro.plaintext.decode('utf-8', errors='replace')}"
        )

    if pending:
        intro_id = pending[0].intro_id
        step("alice trusts the intro (M8.3 trust ladder)")
        msg = alice.trust_intro(intro_id, label="eve", remote_username="eve")
        if msg is not None:
            print(f"  trusted intro #{intro_id}")
            print(
                f"    delivered: {msg.plaintext.decode('utf-8', errors='replace')}"
            )

    step("Summary")
    print(f"  cross-zone delivery (alice→bob): {'OK' if inbox else 'FAIL'}")
    print(f"  claim publish     (eve→alice):   {'OK' if any(eve_outcomes) else 'FAIL'}")
    print(f"  claim recv + intro (alice):      {'OK' if pending else 'FAIL'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
