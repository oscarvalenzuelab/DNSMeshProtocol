---
title: Manual end-to-end testing
layout: default
parent: Deployment
nav_order: 9
---

# Manual end-to-end testing
{: .no_toc }

1. TOC
{:toc}

The repository ships two self-contained docker-compose stacks plus
matching driver scripts that exercise the full DNS-native federation
path against real containers. They're the same harnesses used to
validate every M9 and M10 release; running them locally is the
quickest way to confirm a build works end-to-end on your machine
before deploying.

These are developer-facing harnesses — they're not wired into CI and
don't run as part of `pytest`. The unit and integration suites under
`tests/` cover the same logic with mocked containers.

## M9 — DNS-only federation stack

Three nodes wired against each other with the heartbeat layer + DNS
UPDATE write path. Validates that the only HTTPS hop on the protocol
path is the one-time TSIG registration.

```bash
docker compose -f docker-compose.m9-test.yml up -d
./venv/bin/python scripts/m9_e2e_test.py
```

What the driver covers, in order:

1. Each node published its own heartbeat at
   `_dnsmesh-heartbeat.<own-zone>`.
2. Transitive discovery — each node's `_dnsmesh-seen.<own-zone>`
   carries verified wires for the other two nodes.
3. TSIG key registration via `POST /v1/registration/tsig-confirm`
   (the one HTTPS hop).
4. DMP identity record published via RFC 2136 UPDATE under the
   minted TSIG key.
5. Record readable via the DNS chain on the publishing node.
6. Cross-node read — query alice's identity from bob-node to
   confirm container-to-container DNS works.

Tear down with `docker compose -f docker-compose.m9-test.yml down`.

## M10 — receiver-zone claim notifications

Three-node stack that exercises the M10 phase-1 fast-path receive
flow. Validates both the happy path (claim accepted on the
opted-in node) and the negative control (claim REFUSED on a node
that hasn't enabled `DMP_RECEIVER_CLAIM_NOTIFICATIONS`).

```bash
docker compose -f docker-compose.m10-test.yml up -d --build
./venv/bin/python scripts/m10_e2e_test.py
```

What the driver covers:

1. All three nodes' heartbeats are visible.
2. End-to-end send: alice publishes manifest + chunks; her send
   also fires the M10 receiver-zone claim to bob-node.
3. The claim is queryable at
   `claim-N.mb-{hash12(bob)}.bob.test` on bob-node's DNS server.
4. `bob.receive_messages(primary_only=True)` discovers the claim
   via phase 1, fetches the manifest, and decrypts.
5. Negative control: same un-TSIG'd UPDATE against a
   non-opted-in stranger-node returns REFUSED.

Tear down with `docker compose -f docker-compose.m10-test.yml down`.

## When to use which

- After a `git pull` or local change that touches the DNS server,
  TSIG keystore, registration flow, anti-entropy worker, or claim
  publish path — run the M9 harness first; M10 builds on it.
- When investigating a reported issue tied to receive-side latency
  or claim-provider behavior — the M10 harness is the closest local
  reproduction of a real two-zone deployment.
- Before cutting a release tag — both harnesses should pass on a
  clean build.

## What these harnesses don't cover

- **Cluster anti-entropy.** That path lives inside one operator's
  trust domain (see
  [the boundary doc]({{ site.baseurl }}/design/cluster-anti-entropy-http-boundary))
  and is exercised by `tests/test_compose_cluster.py` against
  `docker-compose.cluster.yml` — a different harness.
- **Production deployment concerns** — TLS chain, real DNS
  delegation, public reachability. Use the deployment guides
  for those.
