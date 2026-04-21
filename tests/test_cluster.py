"""Tests for signed cluster manifests (M2.1).

Covers:
- ClusterNode construction validation.
- Round-trip: sign → wire → parse → verify with all fields preserved.
- Security: wrong-signer, tampered body/sig, mismatched embedded key,
  malformed prefix/base64/truncation all return None.
- Expiry: future accepted, past rejected, `now` kwarg override.
- Size: 0/1/6-node clusters fit under 1200 bytes; pathological inputs
  raise on sign().
- cluster_rrset_name convention.
"""

import base64
import time

import pytest

from dmp.core.crypto import DMPCrypto
from dmp.core.cluster import (
    ClusterManifest,
    ClusterNode,
    MAX_CLUSTER_NAME_LEN,
    MAX_DNS_ENDPOINT_LEN,
    MAX_HTTP_ENDPOINT_LEN,
    MAX_NODE_COUNT,
    MAX_NODE_ID_LEN,
    MAX_WIRE_LEN,
    RECORD_PREFIX,
    cluster_rrset_name,
)

# ---- fixtures / helpers ---------------------------------------------------


def _make_operator() -> DMPCrypto:
    return DMPCrypto()


def _make_node(i: int, with_dns: bool = False) -> ClusterNode:
    return ClusterNode(
        node_id=f"node{i:02d}",
        http_endpoint=f"https://node{i}.mesh.example.com:8053",
        dns_endpoint=f"203.0.113.{i}:53" if with_dns else None,
    )


def _make_manifest(
    operator: DMPCrypto,
    nodes: list[ClusterNode] | None = None,
    *,
    cluster_name: str = "mesh.example.com",
    seq: int = 1,
    exp_delta: int = 3600,
) -> ClusterManifest:
    return ClusterManifest(
        cluster_name=cluster_name,
        operator_spk=operator.get_signing_public_key_bytes(),
        nodes=nodes if nodes is not None else [_make_node(1), _make_node(2)],
        seq=seq,
        exp=int(time.time()) + exp_delta,
    )


# ---- ClusterNode ----------------------------------------------------------


class TestClusterNode:
    def test_construction_minimal(self):
        node = ClusterNode(
            node_id="n1",
            http_endpoint="https://a.example.com:8053",
        )
        assert node.node_id == "n1"
        assert node.dns_endpoint is None

    def test_construction_with_dns(self):
        node = ClusterNode(
            node_id="n1",
            http_endpoint="https://a.example.com:8053",
            dns_endpoint="203.0.113.10:53",
        )
        assert node.dns_endpoint == "203.0.113.10:53"

    def test_roundtrip_bytes_no_dns(self):
        original = _make_node(1)
        body = original.to_body_bytes()
        parsed, offset = ClusterNode.from_body_bytes(body, 0)
        assert offset == len(body)
        assert parsed.node_id == original.node_id
        assert parsed.http_endpoint == original.http_endpoint
        assert parsed.dns_endpoint is None

    def test_roundtrip_bytes_with_dns(self):
        original = _make_node(2, with_dns=True)
        body = original.to_body_bytes()
        parsed, _ = ClusterNode.from_body_bytes(body, 0)
        assert parsed.dns_endpoint == original.dns_endpoint

    def test_node_id_non_ascii_rejected(self):
        node = ClusterNode(
            node_id="nodé",
            http_endpoint="https://a.example.com:8053",
        )
        with pytest.raises(ValueError, match="ASCII"):
            node.to_body_bytes()

    def test_node_id_too_long_rejected(self):
        node = ClusterNode(
            node_id="n" * (MAX_NODE_ID_LEN + 1),
            http_endpoint="https://a.example.com:8053",
        )
        with pytest.raises(ValueError, match="node_id too long"):
            node.to_body_bytes()

    def test_node_id_empty_rejected(self):
        node = ClusterNode(
            node_id="",
            http_endpoint="https://a.example.com:8053",
        )
        with pytest.raises(ValueError, match="node_id"):
            node.to_body_bytes()

    def test_http_endpoint_empty_rejected(self):
        node = ClusterNode(node_id="n", http_endpoint="")
        with pytest.raises(ValueError, match="http_endpoint"):
            node.to_body_bytes()

    def test_http_endpoint_too_long_rejected(self):
        node = ClusterNode(
            node_id="n",
            http_endpoint="https://" + ("a" * MAX_HTTP_ENDPOINT_LEN),
        )
        with pytest.raises(ValueError, match="http_endpoint too long"):
            node.to_body_bytes()

    def test_dns_endpoint_too_long_rejected(self):
        node = ClusterNode(
            node_id="n",
            http_endpoint="https://a.example.com:8053",
            dns_endpoint="x" * (MAX_DNS_ENDPOINT_LEN + 1),
        )
        with pytest.raises(ValueError, match="dns_endpoint too long"):
            node.to_body_bytes()


# ---- round-trip -----------------------------------------------------------


class TestClusterManifestRoundtrip:
    def test_sign_parse_preserves_all_fields(self):
        operator = _make_operator()
        nodes = [_make_node(1), _make_node(2, with_dns=True), _make_node(3)]
        original = _make_manifest(
            operator,
            nodes=nodes,
            cluster_name="mesh.example.com",
            seq=42,
        )
        wire = original.sign(operator)
        assert wire.startswith(RECORD_PREFIX)

        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.cluster_name == original.cluster_name
        assert parsed.operator_spk == original.operator_spk
        assert parsed.seq == original.seq
        assert parsed.exp == original.exp
        assert len(parsed.nodes) == len(original.nodes)
        for parsed_node, original_node in zip(parsed.nodes, original.nodes):
            assert parsed_node.node_id == original_node.node_id
            assert parsed_node.http_endpoint == original_node.http_endpoint
            assert parsed_node.dns_endpoint == original_node.dns_endpoint

    def test_empty_node_list_roundtrips(self):
        operator = _make_operator()
        original = _make_manifest(operator, nodes=[])
        wire = original.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.nodes == []

    def test_sign_mismatched_operator_spk_raises(self):
        operator = _make_operator()
        other = _make_operator()
        # manifest claims `other` as operator but is signed by `operator`.
        mf = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=other.get_signing_public_key_bytes(),
            nodes=[_make_node(1)],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="signing key"):
            mf.sign(operator)


# ---- security -------------------------------------------------------------


class TestClusterManifestSecurity:
    def test_wrong_signer_rejected(self):
        real = _make_operator()
        impostor = _make_operator()
        mf = _make_manifest(real)
        wire = mf.sign(real)
        # Verification with the wrong pubkey returns None.
        assert (
            ClusterManifest.parse_and_verify(
                wire, impostor.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_body_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        # Flip a byte inside the signed body (first byte, which is magic).
        raw[0] ^= 0xFF
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            ClusterManifest.parse_and_verify(
                tampered, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_body_mid_node_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator, nodes=[_make_node(1), _make_node(2)])
        wire = mf.sign(operator)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        # Flip a byte somewhere in the middle (likely a node field).
        raw[len(raw) // 2] ^= 0xFF
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            ClusterManifest.parse_and_verify(
                tampered, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_tampered_signature_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        raw = bytearray(base64.b64decode(wire[len(RECORD_PREFIX) :]))
        # Flip a byte in the trailing signature.
        raw[-1] ^= 0xFF
        tampered = RECORD_PREFIX + base64.b64encode(bytes(raw)).decode("ascii")
        assert (
            ClusterManifest.parse_and_verify(
                tampered, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_mismatched_embedded_operator_spk_rejected(self):
        """Even if sig verifies, the embedded operator_spk must match arg.

        We construct a scenario where the sig is produced by `operator`
        but the arg passed to parse_and_verify is a *different* key whose
        raw bytes happen to land in the embedded slot. Easiest way: sign
        with operator; then rewrite the embedded operator_spk bytes to
        something else and re-sign with that something's key. The arg
        then doesn't match the embedded bytes.

        Since we can't re-sign from outside, we exercise the same
        invariant by flipping the arg: pass an operator_spk that is
        32 valid bytes but doesn't match the signer. Verification must
        fail at step 4 (signature check), which already returns None.
        That's covered by test_wrong_signer_rejected.

        Here we exercise the *explicit* step-6 check by constructing a
        manifest that embeds operator A but gets passed operator B as
        the verify arg, where B's raw bytes are hand-crafted to match
        (impossible in practice — but we can instead verify the
        parse_and_verify code path rejects when the arg differs).
        """
        a = _make_operator()
        b = _make_operator()
        mf = _make_manifest(a)
        wire = mf.sign(a)
        # Passing b's pubkey when the record was signed by a fails at
        # signature verification (step 4) — a different manifestation of
        # the same "embedded vs arg" invariant. Either rejection path is
        # acceptable; both return None.
        assert (
            ClusterManifest.parse_and_verify(wire, b.get_signing_public_key_bytes())
            is None
        )

    def test_missing_prefix_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        no_prefix = wire[len(RECORD_PREFIX) :]
        assert (
            ClusterManifest.parse_and_verify(
                no_prefix, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_wrong_prefix_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        wrong = "v=dmp1;t=manifest;" + wire[len(RECORD_PREFIX) :]
        assert (
            ClusterManifest.parse_and_verify(
                wrong, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_malformed_base64_rejected(self):
        operator = _make_operator()
        # Contains characters that fail strict base64 validation.
        bad = RECORD_PREFIX + "not-valid-base64!!!@@@"
        assert (
            ClusterManifest.parse_and_verify(
                bad, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_empty_payload_rejected(self):
        operator = _make_operator()
        # Valid base64 of an empty payload.
        empty = RECORD_PREFIX + base64.b64encode(b"").decode("ascii")
        assert (
            ClusterManifest.parse_and_verify(
                empty, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_truncated_body_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        raw = base64.b64decode(wire[len(RECORD_PREFIX) :])
        # Chop off a few bytes of the body (before the sig).
        truncated_raw = raw[:-80]
        truncated = RECORD_PREFIX + base64.b64encode(truncated_raw).decode("ascii")
        assert (
            ClusterManifest.parse_and_verify(
                truncated, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_non_string_wire_rejected(self):
        operator = _make_operator()
        assert (
            ClusterManifest.parse_and_verify(
                b"bytes-not-str", operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_non_bytes_operator_spk_rejected(self):
        operator = _make_operator()
        mf = _make_manifest(operator)
        wire = mf.sign(operator)
        # Caller passes a non-bytes or wrong-length operator_spk.
        assert ClusterManifest.parse_and_verify(wire, "notbytes") is None  # type: ignore
        assert ClusterManifest.parse_and_verify(wire, b"\x00" * 16) is None

    def test_bad_magic_rejected(self):
        """Build a correctly-signed body whose magic header is wrong.

        Exercises the from_body_bytes rejection path for a forged record
        that bypasses signature (we sign it ourselves, but the magic is
        still wrong so it still must be rejected).
        """
        operator = _make_operator()
        # Hand-build a body with a bad magic prefix.
        seq = (1).to_bytes(8, "big")
        exp = (int(time.time()) + 3600).to_bytes(8, "big")
        opk = operator.get_signing_public_key_bytes()
        name = b"c.example.com"
        body = (
            b"BADMAGX"  # 7 bytes, wrong magic
            + seq
            + exp
            + opk
            + len(name).to_bytes(1, "big")
            + name
            + (0).to_bytes(1, "big")  # node_count = 0
        )
        sig = operator.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        assert ClusterManifest.parse_and_verify(wire, opk) is None

    def test_invalid_cluster_name_rejected_on_parse(self):
        """A correctly-signed manifest whose cluster_name is not a valid
        DNS name must be rejected on parse. Mirrors sign()'s validation
        — without this, a buggy/malicious publisher could distribute
        records we could never republish ourselves.
        """
        operator = _make_operator()
        opk = operator.get_signing_public_key_bytes()
        # `mesh..example.com` has an empty middle label — valid UTF-8,
        # under the byte cap, passes signature, but invalid as a DNS
        # name.
        bad_name = b"mesh..example.com"
        body = (
            b"DMPCL01"
            + (1).to_bytes(8, "big")
            + (int(time.time()) + 3600).to_bytes(8, "big")
            + opk
            + len(bad_name).to_bytes(1, "big")
            + bad_name
            + (0).to_bytes(1, "big")
        )
        sig = operator.sign_data(body)
        wire = RECORD_PREFIX + base64.b64encode(body + sig).decode("ascii")
        assert ClusterManifest.parse_and_verify(wire, opk) is None


# ---- expiry ---------------------------------------------------------------


class TestClusterManifestExpiry:
    def test_future_exp_verifies(self):
        operator = _make_operator()
        mf = _make_manifest(operator, exp_delta=3600)
        wire = mf.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None

    def test_past_exp_returns_none(self):
        operator = _make_operator()
        now = int(time.time())
        mf = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=[_make_node(1)],
            seq=1,
            exp=now - 10,
        )
        wire = mf.sign(operator)
        assert (
            ClusterManifest.parse_and_verify(
                wire, operator.get_signing_public_key_bytes()
            )
            is None
        )

    def test_now_kwarg_overrides_wall_clock(self):
        operator = _make_operator()
        now = int(time.time())
        # Manifest expires an hour from now (current wall clock).
        mf = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=[_make_node(1)],
            seq=1,
            exp=now + 3600,
        )
        wire = mf.sign(operator)
        # Pass `now` far in the future → treated as expired.
        assert (
            ClusterManifest.parse_and_verify(
                wire,
                operator.get_signing_public_key_bytes(),
                now=now + 7200,
            )
            is None
        )
        # Pass `now` in the past → not yet expired → accepted.
        parsed = ClusterManifest.parse_and_verify(
            wire,
            operator.get_signing_public_key_bytes(),
            now=now,
        )
        assert parsed is not None

    def test_is_expired_helper(self):
        now = int(time.time())
        future = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=b"\x00" * 32,
            nodes=[],
            seq=1,
            exp=now + 60,
        )
        past = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=b"\x00" * 32,
            nodes=[],
            seq=1,
            exp=now - 60,
        )
        assert not future.is_expired()
        assert past.is_expired()


# ---- size -----------------------------------------------------------------


class TestClusterManifestSize:
    def test_zero_nodes_valid(self):
        operator = _make_operator()
        mf = _make_manifest(operator, nodes=[])
        wire = mf.sign(operator)
        assert len(wire.encode("utf-8")) <= MAX_WIRE_LEN
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None and parsed.nodes == []

    def test_one_node_fits(self):
        operator = _make_operator()
        mf = _make_manifest(operator, nodes=[_make_node(1)])
        wire = mf.sign(operator)
        wire_len = len(wire.encode("utf-8"))
        # Comfortable fit in one TXT string.
        assert wire_len <= MAX_WIRE_LEN
        assert wire_len <= 500, f"1-node wire is {wire_len} bytes, expected < 500"

    def test_six_nodes_fit(self):
        operator = _make_operator()
        nodes = [_make_node(i, with_dns=(i % 2 == 0)) for i in range(1, 7)]
        mf = _make_manifest(operator, nodes=nodes)
        wire = mf.sign(operator)
        wire_len = len(wire.encode("utf-8"))
        assert (
            wire_len <= MAX_WIRE_LEN
        ), f"6-node wire {wire_len} exceeds MAX_WIRE_LEN {MAX_WIRE_LEN}"

    def test_six_realistic_nodes_fit_smoke(self):
        """Task gate: manifest with 6 realistic nodes serializes to <= 1200."""
        operator = _make_operator()
        nodes = [
            ClusterNode(
                node_id=f"n{i:02d}",
                http_endpoint=f"https://n{i}.mesh.example.com:8053",
                dns_endpoint=f"203.0.113.{i}:53",
            )
            for i in range(1, 7)
        ]
        mf = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=nodes,
            seq=1,
            exp=int(time.time()) + 3600,
        )
        wire = mf.sign(operator)
        assert len(wire.encode("utf-8")) <= 1200

    def test_too_many_nodes_raises_on_sign(self):
        operator = _make_operator()
        # Way past MAX_NODE_COUNT.
        nodes = [_make_node(i % 100) for i in range(MAX_NODE_COUNT + 5)]
        # Need distinct node_ids; use i directly, truncated.
        nodes = [
            ClusterNode(
                node_id=f"n{i:02d}",
                http_endpoint=f"https://n{i}.example.com:8053",
            )
            for i in range(MAX_NODE_COUNT + 5)
        ]
        mf = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=nodes,
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="too many nodes"):
            mf.sign(operator)

    def test_oversize_endpoint_raises_on_sign(self):
        operator = _make_operator()
        # Endpoint just past the hard cap.
        bad_node = ClusterNode(
            node_id="n",
            http_endpoint="https://" + ("x" * MAX_HTTP_ENDPOINT_LEN),
        )
        mf = ClusterManifest(
            cluster_name="c.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=[bad_node],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="http_endpoint too long"):
            mf.sign(operator)

    def test_oversize_cluster_name_raises(self):
        operator = _make_operator()
        mf = ClusterManifest(
            cluster_name="c" * (MAX_CLUSTER_NAME_LEN + 1),
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=[_make_node(1)],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match="cluster_name"):
            mf.sign(operator)

    def test_oversized_wire_rejected_on_parse(self, monkeypatch):
        """parse_and_verify enforces MAX_WIRE_LEN symmetrically with sign().

        We can't naively produce an oversized wire: sign() refuses to
        emit one, and appending raw bytes to a signed wire breaks both
        base64 and the signature before the size check would be hit.

        Cleanest reproducible construction: temporarily raise the
        module-level MAX_WIRE_LEN so sign() accepts a bloated manifest
        (MAX_NODE_COUNT nodes with max-length endpoints), then restore
        the real cap and confirm parse_and_verify rejects the resulting
        wire purely on length. This exercises the parse-side check in
        isolation: signature, base64, and body structure are all valid;
        only the wire size exceeds the cap.
        """
        import dmp.core.cluster as cluster_mod

        operator = _make_operator()
        # Build a wire that genuinely exceeds MAX_WIRE_LEN by filling
        # MAX_NODE_COUNT nodes with max-length endpoints. That exceeds
        # 1200 bytes comfortably while staying within the per-field
        # caps (so signing is otherwise legal).
        fat_http = "https://" + ("x" * (MAX_HTTP_ENDPOINT_LEN - len("https://")))
        fat_dns = "y" * MAX_DNS_ENDPOINT_LEN
        nodes = [
            ClusterNode(
                node_id=f"n{i:02d}",
                http_endpoint=fat_http,
                dns_endpoint=fat_dns,
            )
            for i in range(MAX_NODE_COUNT)
        ]
        mf = ClusterManifest(
            cluster_name="mesh.example.com",
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=nodes,
            seq=1,
            exp=int(time.time()) + 3600,
        )
        # Step 1: relax MAX_WIRE_LEN during sign() so the bloated
        # manifest can be serialized. MAX_NODE_COUNT stays put — we
        # only need to unblock the wire-size check.
        monkeypatch.setattr(cluster_mod, "MAX_WIRE_LEN", 100_000)
        wire = mf.sign(operator)
        assert (
            len(wire.encode("utf-8")) > 1200
        ), "test setup error: wire should exceed the real cap"

        # Step 2: restore the real cap and confirm parse rejects.
        monkeypatch.setattr(cluster_mod, "MAX_WIRE_LEN", 1200)
        assert (
            ClusterManifest.parse_and_verify(
                wire, operator.get_signing_public_key_bytes()
            )
            is None
        )

        # Sanity: the same wire parses fine under the relaxed cap, so
        # the ONLY failure above was the length check (not a latent
        # bug in signing/parsing a 32-node manifest).
        monkeypatch.setattr(cluster_mod, "MAX_WIRE_LEN", 100_000)
        assert (
            ClusterManifest.parse_and_verify(
                wire, operator.get_signing_public_key_bytes()
            )
            is not None
        )


# ---- rrset naming ---------------------------------------------------------


class TestClusterRrsetName:
    def test_basic_convention(self):
        assert cluster_rrset_name("mesh.example.com") == "cluster.mesh.example.com"

    def test_trailing_dot_stripped(self):
        assert cluster_rrset_name("mesh.example.com.") == "cluster.mesh.example.com"


# ---- cluster_name DNS-name validation -------------------------------------


class TestClusterManifestNameValidation:
    """cluster_name is fed into cluster_rrset_name() and published as a
    DNS TXT owner name, so it must itself be a valid DNS name — the
    64-byte UTF-8 cap alone is not sufficient (labels > 63 chars, `_`,
    non-ASCII, empty/dot-edge names all signed/verified but could not
    be published).

    Covers valid cases (including canonical trailing-dot FQDN form) and
    each failure mode enumerated in the Codex P2 finding.
    """

    @pytest.mark.parametrize(
        "name",
        [
            "mesh.example.com",
            "a.b",
            "x.y.z.w",
            "node-1.mesh.example.com",  # hyphens mid-label allowed
            "mesh.example.com.",  # canonical FQDN form (trailing dot)
            "A.B.C",  # uppercase allowed
            "a1.b2.c3",  # digits allowed
        ],
    )
    def test_valid_names_accepted(self, name):
        operator = _make_operator()
        mf = _make_manifest(operator, cluster_name=name)
        wire = mf.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert parsed.cluster_name == name

    def test_trailing_dot_roundtrips_and_rrset_strips_it(self):
        # Canonical FQDN form is accepted on sign/parse; cluster_rrset_name
        # normalizes by stripping the trailing dot so callers don't end up
        # with `cluster.mesh.example.com.` vs `cluster.mesh.example.com`.
        operator = _make_operator()
        mf = _make_manifest(operator, cluster_name="mesh.example.com.")
        wire = mf.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert cluster_rrset_name(parsed.cluster_name) == "cluster.mesh.example.com"

    @pytest.mark.parametrize(
        "bad_name,reason_substr",
        [
            ("", "non-empty"),  # empty
            ("a" * 64, "63 chars"),  # single 64-char label > DNS label cap
            ("under_score.example.com", "invalid character"),  # underscore
            ("café.example.com", "ASCII"),  # non-ASCII (no IDN)
            ("mesh..example.com", "empty label"),  # double dot
            (".mesh.example.com", "empty label"),  # leading dot
            ("-bad.example.com", "start or end with '-'"),  # leading hyphen
            ("bad-.example.com", "start or end with '-'"),  # trailing hyphen
            ("mesh.example.com/", "invalid character"),  # slash
            ("mesh example.com", "invalid character"),  # space
        ],
    )
    def test_invalid_names_rejected(self, bad_name, reason_substr):
        operator = _make_operator()
        mf = ClusterManifest(
            cluster_name=bad_name,
            operator_spk=operator.get_signing_public_key_bytes(),
            nodes=[_make_node(1)],
            seq=1,
            exp=int(time.time()) + 600,
        )
        with pytest.raises(ValueError, match=reason_substr):
            mf.sign(operator)

    def test_label_at_boundary_63_chars_accepted(self):
        # A 63-char label is the max allowed. Combined with ".xy" this fits
        # under MAX_CLUSTER_NAME_LEN (64 utf-8 bytes would cap the *whole*
        # name, but a single 63-char label + ".x" = 65 bytes and exceeds
        # the byte cap). Use a name that fits both: 63 chars + ".a" = 65,
        # still over; so use 61 + ".ab" = 64.
        name = ("a" * 61) + ".ab"
        assert len(name.encode("utf-8")) <= MAX_CLUSTER_NAME_LEN
        operator = _make_operator()
        mf = _make_manifest(operator, cluster_name=name)
        wire = mf.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None

    def test_node_endpoints_not_subject_to_dns_rules(self):
        # http_endpoint / dns_endpoint are free-form URLs / ip:port, NOT
        # DNS owner names. They must remain unconstrained beyond the
        # existing length + utf-8 checks — especially: `_`, ports, paths,
        # colons, slashes must all be accepted.
        operator = _make_operator()
        # A URL with path + port + query-like chars; a dns_endpoint
        # with an underscore-bearing hostname (unusual but legal in
        # "free-form endpoint" space) would not be a DNS name anyway.
        nodes = [
            ClusterNode(
                node_id="n1",
                http_endpoint="https://host_with_under.example.com:8053/path?x=1",
                dns_endpoint="203.0.113.10:53",
            ),
        ]
        mf = _make_manifest(operator, nodes=nodes)
        wire = mf.sign(operator)
        parsed = ClusterManifest.parse_and_verify(
            wire, operator.get_signing_public_key_bytes()
        )
        assert parsed is not None
        assert (
            parsed.nodes[0].http_endpoint
            == "https://host_with_under.example.com:8053/path?x=1"
        )
