"""Fetch-verify a bootstrap record for a user domain.

M3.2-wire — bridging the leaf-module :mod:`dmp.core.bootstrap` record
type (M3.1) into the live client call path. Given an address like
``alice@example.com``, the client needs to translate the right-hand
``example.com`` into a concrete cluster (``cluster_base_domain`` +
``operator_spk``) without prior configuration beyond a single trust
anchor: the zone operator's Ed25519 public key.

This module mirrors :mod:`dmp.client.cluster_bootstrap` in shape: a
``fetch_*`` helper that does a DNS read, wire-format parse, signature
verification, and expected-name binding — returning ``None`` on any
failure rather than raising. Failures on the bootstrap path are common
(unpublished record, DNS outage, operator rotation mid-flight) and the
caller's job is to fall back gracefully, not to swallow a traceback.

Two-hop trust chain
-------------------
Bootstrap records and cluster manifests live at different DNS owner
names, are signed by different Ed25519 keys, and encode different trust
statements:

1. The **zone operator** controls ``_dmp.<user_domain>`` TXT and signs
   the :class:`BootstrapRecord` with ``signer_spk``. This is the trust
   anchor a client must have out-of-band (e.g. via ``dmp bootstrap
   pin`` on a fingerprint published by the user's home domain).
2. The **cluster operator** controls ``cluster.<cluster_base_domain>``
   TXT and signs the :class:`ClusterManifest` with a separate
   ``operator_spk``. In a multi-tenant setup these two operators may
   be different entities; in a self-hosted deployment they may be the
   same human with two distinct keys.

Compromising the zone operator lets an attacker point a user domain at
a cluster they control, but they still cannot forge records inside an
existing cluster without the cluster operator's key. Symmetrically,
compromising a cluster operator lets them serve bogus mailbox data on
their own cluster but cannot rewrite which cluster a user domain
points at. The two keys are independent trust domains and the client
must verify BOTH in sequence during auto-discovery: first the
bootstrap record against ``signer_spk``, then the cluster manifest
against the ``operator_spk`` carried inside the bootstrap entry.

:class:`ClusterClient` and the M2.wire infrastructure remain the
single place where cluster-manifest verification happens; this module
never touches that layer directly.
"""

from __future__ import annotations

import logging
from typing import Optional

from dmp.core.bootstrap import BootstrapRecord, bootstrap_rrset_name
from dmp.network.base import DNSRecordReader

log = logging.getLogger(__name__)


def fetch_bootstrap_record(
    user_domain: str,
    signer_spk: bytes,
    bootstrap_reader: DNSRecordReader,
    *,
    now: Optional[int] = None,
) -> Optional[BootstrapRecord]:
    """Fetch TXT at ``_dmp.<user_domain>`` and return a verified record.

    Scans every TXT record at the RRset name and returns the verifying
    :class:`BootstrapRecord` with the highest ``seq``. Returns ``None``
    if:

    - the bootstrap reader raises or returns no records,
    - every parsed record fails signature verification against
      ``signer_spk``,
    - every parsed record is expired,
    - every parsed record's signed ``user_domain`` fails to bind to the
      requested ``user_domain`` (case-insensitive, trailing-dot
      normalized).

    Mirrors :func:`fetch_cluster_manifest`'s highest-seq selection so a
    rollout window with both old and new records co-resident on the
    zone is resolved in favor of the freshest signed record rather
    than whichever one happens to be served first.

    ``expected_user_domain`` binding is enforced internally — callers
    do not need to pass it separately; the function uses
    ``user_domain`` as both the query name input and the expected
    value to :meth:`BootstrapRecord.parse_and_verify`.

    This function does not raise on ordinary fetch failures. A bad
    ``user_domain`` (empty, malformed label, over-long) still
    propagates out of :func:`bootstrap_rrset_name` — that's a
    programming error the caller should surface loudly.
    """
    rrset_name = bootstrap_rrset_name(user_domain)
    try:
        records = bootstrap_reader.query_txt_record(rrset_name)
    except Exception as exc:
        log.warning("bootstrap record fetch failed: %s", exc)
        return None
    if not records:
        return None
    # Scan the whole RRset and pick the highest-seq verifying record.
    # Returning the first verifying match would pin the client to the
    # stale entry set whenever both old and new records are briefly
    # co-resident in DNS (e.g. during a zone operator rollout with
    # append-semantics publishing or short-TTL resolver caching).
    best: Optional[BootstrapRecord] = None
    for wire in records:
        try:
            record = BootstrapRecord.parse_and_verify(
                wire,
                signer_spk,
                now=now,
                expected_user_domain=user_domain,
            )
        except Exception as exc:  # pragma: no cover - defense in depth
            # parse_and_verify already swallows all the expected failure
            # modes (bad prefix, base64 errors, signature mismatch,
            # malformed fields) and returns None. Anything that escapes
            # is unexpected.
            log.warning("bootstrap record parse raised: %s", exc)
            continue
        if record is None:
            continue
        if best is None or record.seq > best.seq:
            best = record
    return best
