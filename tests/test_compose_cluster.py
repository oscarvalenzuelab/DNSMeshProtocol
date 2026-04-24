"""M2.5 — 3-node compose cluster integration test.

Skipped unless:
- Docker is available AND
- The ``dnsmesh-node:latest`` image exists AND
- ``docker compose`` is available.

Build the image first with ``docker build -t dnsmesh-node:latest .`` and
the test will spin up ``docker-compose.cluster.yml`` with a freshly
generated (dev-only) cluster manifest, exercise the anti-entropy
convergence story across the three nodes, and tear everything down.

Tests cover:
- A record published at node-a becomes visible at node-b and node-c
  within ``2 * sync_interval`` seconds.
- A node that is stopped, misses a write, and restarts eventually
  catches up via anti-entropy from its living peers.
- The ``/v1/sync/digest`` endpoint refuses requests without the
  shared peer token (403).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import pytest

_REPO_ROOT = Path(__file__).resolve().parent.parent
_COMPOSE_FILE = _REPO_ROOT / "docker-compose.cluster.yml"
_GEN_SCRIPT = _REPO_ROOT / "docker" / "cluster" / "generate-cluster-manifest.py"

# The compose file maps the three nodes to these host-side ports.
_HTTP_PORTS = {"node-a": 8101, "node-b": 8102, "node-c": 8103}
_DNS_PORTS = {"node-a": 5301, "node-b": 5302, "node-c": 5303}


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


def _compose_available() -> bool:
    if not _docker_available():
        return False
    try:
        return (
            subprocess.run(
                ["docker", "compose", "version"],
                capture_output=True,
                timeout=5,
            ).returncode
            == 0
        )
    except Exception:
        return False


def _image_exists(tag: str) -> bool:
    try:
        return (
            subprocess.run(
                ["docker", "image", "inspect", tag],
                capture_output=True,
                timeout=5,
            ).returncode
            == 0
        )
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(not _compose_available(), reason="docker compose not available"),
    pytest.mark.skipif(
        not _image_exists("dnsmesh-node:latest"),
        reason="dnsmesh-node:latest missing; run `docker build -t dnsmesh-node:latest .`",
    ),
    pytest.mark.skipif(
        not _COMPOSE_FILE.exists(),
        reason=f"{_COMPOSE_FILE} missing",
    ),
]


def _compose(
    *args: str, check: bool = True, capture: bool = True
) -> subprocess.CompletedProcess:
    """Run ``docker compose -f docker-compose.cluster.yml <args>``."""
    return subprocess.run(
        ["docker", "compose", "-f", str(_COMPOSE_FILE), *args],
        capture_output=capture,
        text=True,
        check=check,
    )


def _wait_for_health(host_port: int, timeout: float = 30.0) -> bool:
    """Poll a node's /health until it returns 200 or the deadline hits."""
    import urllib.error
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(
                f"http://127.0.0.1:{host_port}/health", timeout=1.0
            ) as resp:
                if resp.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionRefusedError, OSError):
            pass
        time.sleep(0.3)
    return False


@pytest.fixture(scope="module")
def compose_cluster():
    """Bring up the 3-node cluster, yield a context dict, tear down.

    Regenerates ``cluster-manifest.wire`` per run (module scope) so the
    operator key never leaks onto disk in a checked-in form. The env
    files still carry the ``dev-cluster-token-change-me`` placeholder;
    the test assertions don't depend on a production-grade token.
    """
    # Make sure any prior run's volumes / containers are gone.
    _compose("down", "-v", check=False)

    # Generate a fresh signed manifest + operator key into the compose
    # mount path. The manifest is not actually consumed by the
    # anti-entropy worker in this test (peers come from
    # DMP_SYNC_PEERS), but the compose file still mounts it so a real
    # run looks realistic.
    cluster_dir = _REPO_ROOT / "docker" / "cluster"
    manifest_path = cluster_dir / "cluster-manifest.wire"
    operator_key = cluster_dir / "operator-ed25519.hex"
    subprocess.run(
        [
            sys.executable,
            str(_GEN_SCRIPT),
            "--manifest-out",
            str(manifest_path),
            "--operator-key-out",
            str(operator_key),
        ],
        check=True,
        capture_output=True,
    )

    _compose("up", "-d")
    all_healthy = all(
        _wait_for_health(_HTTP_PORTS[name], timeout=40.0)
        for name in ("node-a", "node-b", "node-c")
    )
    if not all_healthy:
        logs = _compose("logs", "--no-color", check=False).stdout
        _compose("down", "-v", check=False)
        pytest.fail(f"cluster failed to come up; compose logs:\n{logs}")

    ctx = {
        "http_ports": _HTTP_PORTS,
        "dns_ports": _DNS_PORTS,
        "manifest_path": str(manifest_path),
        "operator_key": str(operator_key),
        "sync_token": "dev-cluster-token-change-me",
    }
    try:
        yield ctx
    finally:
        _compose("down", "-v", check=False)
        # Clean up the freshly-generated files so the checkout isn't
        # dirty after tests run.
        for p in (manifest_path, operator_key):
            try:
                os.remove(p)
            except FileNotFoundError:
                pass


def _publish(host_port: int, name: str, value: str, ttl: int = 300) -> int:
    """POST a TXT record via a node's HTTP API. Returns the HTTP status."""
    import urllib.request

    req = urllib.request.Request(
        f"http://127.0.0.1:{host_port}/v1/records/{name}",
        data=json.dumps({"value": value, "ttl": ttl}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=3.0) as resp:
            return resp.status
    except Exception:
        return 0


def _dns_query(host_port: int, name: str) -> Optional[list[str]]:
    """UDP TXT query against a node's mapped DNS port. Returns values or None."""
    import dns.message
    import dns.query
    import dns.rdatatype

    q = dns.message.make_query(name, dns.rdatatype.TXT)
    try:
        resp = dns.query.udp(q, "127.0.0.1", port=host_port, timeout=2.0)
    except Exception:
        return None
    if resp.rcode() != 0 or not resp.answer:
        return None
    out = []
    for rrset in resp.answer:
        for rdata in rrset:
            out.append(b"".join(rdata.strings).decode("utf-8"))
    return out or None


def _wait_for_value(
    host_port: int, name: str, expected: str, timeout: float = 10.0
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        values = _dns_query(host_port, name)
        if values and expected in values:
            return True
        time.sleep(0.5)
    return False


class TestComposeCluster:
    def test_all_three_nodes_converge_on_publish(self, compose_cluster):
        """Publish at node-a; node-b and node-c catch up via anti-entropy."""
        # Sync interval is 2s (see docker/cluster/node-*.env). Give the
        # worker a handful of ticks to propagate.
        name = "converge.mesh.test"
        value = "v=dmp1;t=chunk;d=test-converge-abc"
        assert _publish(compose_cluster["http_ports"]["node-a"], name, value) == 201

        # node-a should already have it (direct write).
        assert _wait_for_value(
            compose_cluster["dns_ports"]["node-a"], name, value, timeout=2.0
        )
        # node-b and node-c pick it up via anti-entropy.
        assert _wait_for_value(
            compose_cluster["dns_ports"]["node-b"], name, value, timeout=10.0
        ), "node-b never picked up the record via anti-entropy"
        assert _wait_for_value(
            compose_cluster["dns_ports"]["node-c"], name, value, timeout=10.0
        ), "node-c never picked up the record via anti-entropy"

    def test_kill_and_rejoin_node_catches_up(self, compose_cluster):
        """Stop node-b, write to node-a, restart node-b; it backfills."""
        name = "rejoin.mesh.test"
        value_before = "v=dmp1;t=chunk;d=written-while-b-was-up"
        value_during = "v=dmp1;t=chunk;d=written-while-b-was-DOWN"

        # Seed a record so node-b has the baseline.
        assert (
            _publish(compose_cluster["http_ports"]["node-a"], name, value_before) == 201
        )
        assert _wait_for_value(
            compose_cluster["dns_ports"]["node-b"], name, value_before, timeout=10.0
        )

        # Stop node-b. node-a and node-c keep serving.
        _compose("stop", "node-b")
        try:
            # Write a second value while b is down.
            new_name = "rejoin-delta.mesh.test"
            assert (
                _publish(
                    compose_cluster["http_ports"]["node-a"], new_name, value_during
                )
                == 201
            )
            # node-c picks it up from node-a.
            assert _wait_for_value(
                compose_cluster["dns_ports"]["node-c"],
                new_name,
                value_during,
                timeout=10.0,
            )
        finally:
            _compose("start", "node-b")
        assert _wait_for_health(compose_cluster["http_ports"]["node-b"], timeout=30.0)

        # After rejoin, node-b must backfill the delta it missed.
        assert _wait_for_value(
            compose_cluster["dns_ports"]["node-b"],
            "rejoin-delta.mesh.test",
            value_during,
            timeout=15.0,
        ), "node-b did not backfill the record written while it was down"

    def test_peer_auth_enforced_end_to_end(self, compose_cluster):
        """``/v1/sync/digest`` without the shared token returns 403."""
        import urllib.error
        import urllib.request

        port = compose_cluster["http_ports"]["node-a"]
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/v1/sync/digest?cursor=0:%3Ainit",
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                status = resp.status
        except urllib.error.HTTPError as e:
            status = e.code
        assert status in (
            401,
            403,
        ), f"expected 401/403 on unauthenticated sync request; got {status}"
