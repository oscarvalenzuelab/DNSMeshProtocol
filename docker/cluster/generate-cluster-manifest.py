#!/usr/bin/env python3
"""Sign a 3-node ClusterManifest for the docker-compose.cluster sample.

Usage:
    python docker/cluster/generate-cluster-manifest.py \\
        --cluster-name mesh.local \\
        --manifest-out docker/cluster/cluster-manifest.wire \\
        --operator-key-out docker/cluster/operator-ed25519.hex

Generates a fresh Ed25519 operator keypair (hex-encoded) and writes the
signed cluster manifest alongside. The manifest lists the three nodes
that ``docker-compose.cluster.yml`` stands up (``dmp-node-a``,
``dmp-node-b``, ``dmp-node-c``) with their in-docker-network HTTP + DNS
endpoints.

IMPORTANT: this key is for dev/test only. Do NOT reuse the emitted
operator key in production — real deployments must manage the Ed25519
signing key through the operator's KMS process (HSM, offline signing,
hardware key, etc.), not drop it on disk as a hex file.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

# Ensure `dmp` imports resolve when this script is run from a repo checkout.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from dmp.core.cluster import ClusterManifest, ClusterNode  # noqa: E402
from dmp.core.crypto import DMPCrypto  # noqa: E402


def _build_manifest(
    operator: DMPCrypto,
    *,
    cluster_name: str,
    exp_delta_seconds: int,
    seq: int,
) -> ClusterManifest:
    """Three nodes addressed by their compose container names.

    The dns_endpoint points at the node's DNS listener inside the
    dmp-cluster docker network; clients outside that network see the
    ports mapped by ``docker-compose.cluster.yml`` (5301/5302/5303 on
    127.0.0.1 by default).
    """
    nodes = [
        ClusterNode(
            node_id=f"node-{letter}",
            http_endpoint=f"http://dmp-node-{letter}:8053",
            dns_endpoint=f"dmp-node-{letter}:5353",
        )
        for letter in ("a", "b", "c")
    ]
    return ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=operator.get_signing_public_key_bytes(),
        nodes=nodes,
        seq=seq,
        exp=int(time.time()) + exp_delta_seconds,
    )


def _read_existing_seq(manifest_out: Path) -> int:
    """Best-effort: if a manifest already exists at this path, peek at
    its seq and return ``seq + 1``. Returns 1 if no prior manifest.

    Fanout/Union readers reject manifests whose seq isn't strictly
    greater than the currently pinned one, so a re-run that stamps
    seq=1 again makes rotated endpoints / extended expiry invisible
    to every already-bootstrapped client.
    """
    if not manifest_out.exists():
        return 1
    try:
        wire = manifest_out.read_text()
        # Peek without full signature verification — we're bumping our
        # own prior output. parse_and_verify needs the operator key
        # which we haven't generated yet at this point; a lighter
        # parse_body path would work but isn't public. Fall back to
        # pattern scrape.
        import base64
        import struct

        PREFIX = "v=dmp1;t=cluster;"
        if not wire.startswith(PREFIX):
            return 1
        blob = base64.b64decode(wire[len(PREFIX) :], validate=True)
        # Body layout: MAGIC(7) + seq(8 BE) + ...
        body = blob[:-64]  # strip signature
        if len(body) < 15 or not body.startswith(b"DMPCL01"):
            return 1
        prior_seq = struct.unpack(">Q", body[7:15])[0]
        return prior_seq + 1
    except Exception:
        # Malformed prior manifest — caller can override via --seq.
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--cluster-name",
        default="mesh.local",
        help="DNS-valid cluster base domain (default: mesh.local)",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        required=True,
        help="path to write the signed ClusterManifest wire bytes",
    )
    parser.add_argument(
        "--operator-key-out",
        type=Path,
        required=True,
        help=(
            "path to write the hex-encoded Ed25519 operator private key. "
            "Treat this file like any other secret."
        ),
    )
    parser.add_argument(
        "--exp-days",
        type=int,
        default=365,
        help="manifest expiry horizon in days (default: 365)",
    )
    parser.add_argument(
        "--seq",
        type=int,
        default=None,
        help=(
            "manifest sequence number (default: autoincrement from the "
            "existing --manifest-out if present, else 1). Clients reject "
            "a regenerated manifest whose seq isn't strictly greater "
            "than the currently pinned one, so rotation requires bump."
        ),
    )
    args = parser.parse_args(argv)

    print("=" * 72)
    print(
        "WARNING: this script generates a FRESH Ed25519 operator key for "
        "the\n         docker-compose.cluster sample. DO NOT REUSE THIS KEY "
        "IN PRODUCTION."
    )
    print(
        "         Real deployments must manage the operator signing key "
        "through a\n         KMS / HSM / offline-signing workflow, never a "
        "hex file on disk."
    )
    print("=" * 72)

    seq = args.seq if args.seq is not None else _read_existing_seq(args.manifest_out)
    operator = DMPCrypto()
    manifest = _build_manifest(
        operator,
        cluster_name=args.cluster_name,
        exp_delta_seconds=args.exp_days * 86400,
        seq=seq,
    )
    wire = manifest.sign(operator)
    print(f"manifest seq: {seq}")

    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.write_text(wire)

    # The project's DMPCrypto derives both X25519 and Ed25519 keypairs
    # deterministically from a single 32-byte seed (the X25519 private
    # key bytes). Persisting that seed is sufficient to reconstruct the
    # full operator identity later — feed it to DMPCrypto.from_private_bytes.
    seed_hex = operator.get_private_key_bytes().hex()
    pub_hex = operator.get_signing_public_key_bytes().hex()
    args.operator_key_out.parent.mkdir(parents=True, exist_ok=True)
    args.operator_key_out.write_text(
        f"# Dev-only operator keypair for the docker-compose.cluster sample.\n"
        f"# DO NOT REUSE IN PRODUCTION.\n"
        f"#\n"
        f"# operator_seed_hex is the 32-byte X25519 seed from which both\n"
        f"# the X25519 and Ed25519 keypairs derive. Load it via\n"
        f"#   DMPCrypto.from_private_bytes(bytes.fromhex(<seed>))\n"
        f"operator_seed_hex={seed_hex}\n"
        f"operator_public_hex={pub_hex}\n"
    )
    try:
        args.operator_key_out.chmod(0o600)
    except OSError:
        pass

    print(f"wrote manifest: {args.manifest_out} ({len(wire.encode('utf-8'))} bytes)")
    print(f"wrote operator key: {args.operator_key_out}")
    print()
    print("Next steps:")
    print(
        f"  1. Paste operator_public_hex into each node-{{a,b,c}}.env's\n"
        f"     DMP_SYNC_OPERATOR_SPK= line. (Current public key: {pub_hex})"
    )
    print(
        "  2. Change DMP_SYNC_PEER_TOKEN in every node-*.env from the\n"
        "     placeholder to a strong random string (the same value in all\n"
        "     three files)."
    )
    print(
        "  3. `docker compose -f docker-compose.cluster.yml up -d` to start\n"
        "     the three-node cluster."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
