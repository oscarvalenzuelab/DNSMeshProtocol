"""Tests for CompositeReader — cluster-local vs. external routing.

Covers:
- ``_is_under_domain`` suffix logic (exact, case-insensitive, trailing
  dot, label boundary, empty base).
- ``CompositeReader.query_txt_record`` dispatch to exactly one of the
  underlying readers, with no fallback chaining.
"""

from __future__ import annotations

from typing import List, Optional

from dmp.network.base import DNSRecordReader
from dmp.network.composite_reader import CompositeReader, _is_under_domain


class FakeReader(DNSRecordReader):
    """Minimal DNSRecordReader test double.

    Records every name it's queried with in ``calls`` so tests can
    assert "exactly one of cluster/external was queried per call".
    ``result`` is returned verbatim (copy) on every query.
    """

    def __init__(self, result: Optional[List[str]] = None) -> None:
        self.result = result
        self.calls: List[str] = []

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        self.calls.append(name)
        return list(self.result) if self.result is not None else None


# ---------------------------------------------------------------------
# _is_under_domain
# ---------------------------------------------------------------------


class TestIsUnderDomain:
    def test_child_name(self):
        assert _is_under_domain("foo.mesh.example.com", "mesh.example.com") is True

    def test_unrelated_name(self):
        assert _is_under_domain("foo.other.com", "mesh.example.com") is False

    def test_exact_match(self):
        assert _is_under_domain("mesh.example.com", "mesh.example.com") is True

    def test_empty_base_never_matches(self):
        assert _is_under_domain("mesh.example.com", "") is False
        assert _is_under_domain("anything", "") is False
        # Even an empty name with empty base: empty base short-circuits.
        assert _is_under_domain("", "") is False

    def test_case_insensitive(self):
        assert _is_under_domain("FOO.MESH.EXAMPLE.COM", "mesh.example.com") is True
        assert _is_under_domain("foo.mesh.example.com", "MESH.EXAMPLE.COM") is True
        assert _is_under_domain("Foo.Mesh.Example.Com", "Mesh.Example.Com") is True

    def test_trailing_dot_on_name(self):
        assert _is_under_domain("foo.mesh.example.com.", "mesh.example.com") is True

    def test_trailing_dot_on_base(self):
        assert _is_under_domain("foo.mesh.example.com", "mesh.example.com.") is True

    def test_trailing_dot_on_both(self):
        assert _is_under_domain("foo.mesh.example.com.", "mesh.example.com.") is True

    def test_must_not_match_prefix_beyond_label_boundary(self):
        """`mesh.example.comxyz` must NOT match `mesh.example.com`.

        A bare ``endswith`` would incorrectly accept this, letting an
        attacker route an external name they control into the cluster
        reader.
        """
        assert _is_under_domain("mesh.example.comxyz", "mesh.example.com") is False
        assert _is_under_domain("xmesh.example.com", "mesh.example.com") is False

    def test_partial_label_does_not_match(self):
        """`foomesh.example.com` must NOT match `mesh.example.com`.

        Only a full-label boundary (the '.' before ``mesh``) counts.
        """
        assert _is_under_domain("foomesh.example.com", "mesh.example.com") is False

    def test_shorter_name_never_matches(self):
        assert _is_under_domain("example.com", "mesh.example.com") is False


# ---------------------------------------------------------------------
# CompositeReader.query_txt_record
# ---------------------------------------------------------------------


class TestCompositeReaderRouting:
    def test_in_zone_name_routes_to_cluster(self):
        cluster = FakeReader(result=["cluster-answer"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("dmp.alice.mesh.example.com")
        assert out == ["cluster-answer"]
        assert cluster.calls == ["dmp.alice.mesh.example.com"]
        assert external.calls == []

    def test_out_of_zone_name_routes_to_external(self):
        cluster = FakeReader(result=["cluster-answer"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("dmp.alice.other-domain.com")
        assert out == ["external-answer"]
        assert cluster.calls == []
        assert external.calls == ["dmp.alice.other-domain.com"]

    def test_exact_base_routes_to_cluster(self):
        cluster = FakeReader(result=["manifest-wire"])
        external = FakeReader(result=["SHOULD-NOT-BE-RETURNED"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("mesh.example.com")
        assert out == ["manifest-wire"]
        assert cluster.calls == ["mesh.example.com"]
        assert external.calls == []

    def test_case_insensitive_routing(self):
        cluster = FakeReader(result=["cluster-answer"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("DMP.Alice.MESH.EXAMPLE.COM")
        assert out == ["cluster-answer"]
        assert cluster.calls == ["DMP.Alice.MESH.EXAMPLE.COM"]
        assert external.calls == []

    def test_trailing_dot_routing(self):
        cluster = FakeReader(result=["cluster-answer"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("dmp.alice.mesh.example.com.")
        assert out == ["cluster-answer"]
        assert cluster.calls == ["dmp.alice.mesh.example.com."]
        assert external.calls == []

    def test_label_boundary_safe_routing(self):
        """`mesh.example.comxyz` is NOT under `mesh.example.com`.

        Must route to the external reader, not the cluster reader.
        """
        cluster = FakeReader(result=["SHOULD-NOT-BE-RETURNED"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("mesh.example.comxyz")
        assert out == ["external-answer"]
        assert cluster.calls == []
        assert external.calls == ["mesh.example.comxyz"]

    def test_cluster_none_does_not_fall_back_to_external(self):
        """A None from the cluster reader means "not found" — not a
        trigger to retry via external DNS."""
        cluster = FakeReader(result=None)
        external = FakeReader(result=["SHOULD-NOT-BE-RETURNED"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("dmp.alice.mesh.example.com")
        assert out is None
        assert cluster.calls == ["dmp.alice.mesh.example.com"]
        assert external.calls == []

    def test_external_none_returns_none(self):
        cluster = FakeReader(result=["SHOULD-NOT-BE-RETURNED"])
        external = FakeReader(result=None)
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="mesh.example.com",
        )
        out = reader.query_txt_record("dmp.alice.other-domain.com")
        assert out is None
        assert cluster.calls == []
        assert external.calls == ["dmp.alice.other-domain.com"]

    def test_empty_cluster_base_routes_everything_external(self):
        """With an empty ``cluster_base_domain`` (defensive), every
        query falls through to the external reader."""
        cluster = FakeReader(result=["SHOULD-NOT-BE-RETURNED"])
        external = FakeReader(result=["external-answer"])
        reader = CompositeReader(
            cluster_reader=cluster,
            external_reader=external,
            cluster_base_domain="",
        )
        # Any name at all.
        for name in ("mesh.example.com", "foo.other.com", "bare"):
            external.calls.clear()
            out = reader.query_txt_record(name)
            assert out == ["external-answer"]
            assert cluster.calls == []
            assert external.calls == [name]
