"""Composite reader: route DNS queries by owner-name suffix.

DMP in cluster mode runs in two overlapping DNS namespaces:

1. **Cluster-local** — mailbox slots, identity records, prekey rrsets
   for users inside the pinned cluster's zone (everything under
   ``cluster_base_domain``). These records live on the cluster's
   authoritative nodes; the :class:`UnionReader` queries every node and
   returns the dedup'd answer, which is what gives read-after-write
   consistency for newly-fanned writes.

2. **External** — identity records for users in *other* domains (e.g.
   ``alice@other-domain.com``). The authoritative cluster nodes will
   NXDOMAIN these, because they have no delegation for the external
   zone. The right path for these queries is the bootstrap recursive
   resolver that already knows how to walk public DNS.

Without a split between the two, a user who pins a cluster breaks
every cross-domain workflow the moment they do so: ``dnsmesh identity
fetch alice@other-domain.com`` stops resolving because the union
reader hits all-NXDOMAIN from the pinned cluster nodes.

The :class:`CompositeReader` solves this with a single routing rule:
match the query name's suffix against ``cluster_base_domain``. Names
equal to or ending in ``.cluster_base_domain`` go to the cluster
reader; everything else goes to the external reader. There is
deliberately **no fallback chaining** — a cluster-local name that
doesn't resolve in the cluster is a legitimate "not found" answer,
not a trigger to re-query via external DNS.

Normalization mirrors the :class:`ClusterManifest` layer:
case-insensitive match plus a stripped trailing FQDN dot. So
``Mesh.Example.COM`` and ``mesh.example.com`` and
``mesh.example.com.`` all route together.

Label-boundary safety is non-negotiable: ``mesh.example.comxyz``
must NOT match ``mesh.example.com``. The helper checks for exact
equality or a ``.base`` suffix — never a bare string prefix.
"""

from __future__ import annotations

from typing import List, Optional

from dmp.network.base import DNSRecordReader


def _is_under_domain(name: str, base: str) -> bool:
    """Return True iff DNS-owner-name ``name`` falls under zone ``base``.

    The match is:
    - case-insensitive (both sides ``casefold()``-ed);
    - trailing-dot normalized (both sides' trailing ``.`` stripped);
    - **label-boundary safe** — either ``name`` equals ``base``
      exactly, or ``name`` ends in ``"." + base``. A bare string
      ``.endswith`` would let ``mesh.example.comxyz`` match
      ``mesh.example.com``, which is a security-relevant bug: it
      would route an attacker-controlled external name into the
      cluster reader.
    - If ``base`` is empty after normalization, returns False for
      every ``name``. Defensive against an accidentally unconfigured
      ``cluster_base_domain``; the caller should fall through to
      routing everything to the external reader.
    """

    norm_base = base.casefold().rstrip(".")
    if not norm_base:
        return False
    norm_name = name.casefold().rstrip(".")
    if norm_name == norm_base:
        return True
    return norm_name.endswith("." + norm_base)


class CompositeReader(DNSRecordReader):
    """Route DNS queries between a cluster-local reader and an external one.

    Construct with two :class:`DNSRecordReader` implementations (the
    cluster's union reader and the bootstrap recursive resolver, in
    practice) plus the cluster base domain used as the routing key.
    :meth:`query_txt_record` inspects the owner name and dispatches to
    exactly one of the two readers.

    There is no fallback chain. A cluster-local name that returns None
    from the cluster reader returns None from the composite too — the
    cluster's authoritative nodes are the source of truth for their
    own zone, and an empty answer there is a real "not found", not an
    excuse to retry elsewhere. Symmetrically, an external name that
    returns None from the bootstrap resolver returns None from the
    composite.

    Empty ``cluster_base_domain`` (should not happen in practice, but
    defensive): every query routes to ``external_reader``. That
    matches the fall-through semantics of :func:`_is_under_domain`
    for an unconfigured base.
    """

    def __init__(
        self,
        cluster_reader: DNSRecordReader,
        external_reader: DNSRecordReader,
        cluster_base_domain: str,
    ) -> None:
        self._cluster_reader = cluster_reader
        self._external_reader = external_reader
        self._cluster_base_domain = cluster_base_domain

    def query_txt_record(self, name: str) -> Optional[List[str]]:
        """Route by DNS-owner-name suffix.

        Names equal to or ending in ``.cluster_base_domain`` go to the
        cluster reader. Everything else goes to the external reader.
        Case-insensitive; trailing FQDN dot normalized. No fallback
        chaining between the two readers.
        """
        if _is_under_domain(name, self._cluster_base_domain):
            return self._cluster_reader.query_txt_record(name)
        return self._external_reader.query_txt_record(name)
