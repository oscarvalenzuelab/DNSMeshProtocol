"""Fetch-verify-install the cluster manifest and build Fanout + Union.

M2.wire — bridging standalone FanoutWriter (M2.2) + UnionReader (M2.3)
into the live client call path.

Given:
- a cluster base domain (e.g. ``"mesh.example.com"``) — the DNS zone
  where ``cluster.<base>`` TXT records live,
- the operator's Ed25519 public key (bytes) — the trust anchor for
  manifest signatures,
- an underlying bootstrap DNS reader (e.g. ``ResolverPool``) that can
  fetch the cluster manifest RRset,
- a ``writer_factory(ClusterNode)`` and ``reader_factory(ClusterNode)``
  that build per-node writers/readers (for M2.wire: HTTP writer factory
  and DNS-over-UDP reader factory),

this module provides:

- :func:`fetch_cluster_manifest` — one-shot fetch + verify.
- :class:`ClusterClient` — owns the :class:`FanoutWriter` +
  :class:`UnionReader` + an optional background refresh thread. Exposes
  ``writer`` and ``reader`` properties for injection into
  :class:`DMPClient`. ``close()`` stops the refresh thread and releases
  the underlying executors.

Security boundary
-----------------
Signature verification happens exactly once — in
:func:`fetch_cluster_manifest`, which calls
:meth:`ClusterManifest.parse_and_verify` with the operator public key
and the expected cluster name. Downstream ``install_manifest`` calls on
the fanout / union modules trust the :class:`ClusterManifest` struct
they are handed; they only re-check seq-monotonicity and expiry.
"""

from __future__ import annotations

import copy
import logging
import threading
from typing import Optional

from dmp.core.cluster import ClusterManifest, cluster_rrset_name
from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.network.fanout_writer import FanoutWriter, WriterFactory
from dmp.network.union_reader import ReaderFactory, UnionReader

log = logging.getLogger(__name__)


def fetch_cluster_manifest(
    base_domain: str,
    operator_spk: bytes,
    bootstrap_reader: DNSRecordReader,
    *,
    now: Optional[int] = None,
) -> Optional[ClusterManifest]:
    """Fetch the TXT RRset at ``cluster.<base_domain>``; parse-verify-bind.

    Returns the first :class:`ClusterManifest` that parses and verifies
    against ``operator_spk`` and binds to ``base_domain`` as its
    expected cluster name. Returns ``None`` if:

    - the query fails (bootstrap reader raises or returns None/empty),
    - no TXT record in the RRset carries a well-formed signed manifest,
    - every parsed record fails signature verification, is expired, or
      carries a ``cluster_name`` other than ``base_domain``.

    This function does not raise on ordinary fetch failures — DNS is
    unreliable, and the caller (``ClusterClient``) treats ``None`` as
    "keep using the last-known manifest". Programming errors (e.g. an
    invalid ``base_domain``) still propagate out of
    :func:`cluster_rrset_name`.
    """
    rrset_name = cluster_rrset_name(base_domain)
    try:
        records = bootstrap_reader.query_txt_record(rrset_name)
    except Exception as exc:
        log.warning("cluster manifest fetch failed: %s", exc)
        return None
    if not records:
        return None
    # Scan every TXT record in the RRset and return the manifest with
    # the highest seq. Taking the first valid match would pin the
    # client to a stale node set whenever both old and new manifests
    # are briefly co-resident in DNS (e.g. during an operator rollout
    # with append-semantics publishing or short-TTL resolver caching).
    best: Optional[ClusterManifest] = None
    for wire in records:
        try:
            manifest = ClusterManifest.parse_and_verify(
                wire,
                operator_spk,
                now=now,
                expected_cluster_name=base_domain,
            )
        except Exception as exc:  # pragma: no cover - defense in depth
            # parse_and_verify already swallows all the expected failure
            # modes and returns None; anything that escapes is unexpected.
            log.warning("cluster manifest parse raised: %s", exc)
            continue
        if manifest is None:
            continue
        if best is None or manifest.seq > best.seq:
            best = manifest
    return best


class ClusterClient:
    """Owns :class:`FanoutWriter` + :class:`UnionReader` + manifest refresh.

    Construct from an already-fetched, already-verified manifest (use
    :func:`fetch_cluster_manifest` first). The constructor:

    1. Builds a :class:`FanoutWriter` and :class:`UnionReader` from the
       manifest + per-node factories.
    2. If ``refresh_interval`` is set, spawns a daemon thread that calls
       :meth:`refresh_now` on that cadence.

    :meth:`refresh_now` re-fetches from ``bootstrap_reader`` and
    installs the new manifest iff its ``seq`` is strictly greater than
    the currently installed one (delegated to the underlying
    fanout/union modules' ``install_manifest``).

    If the bootstrap reader goes down the ``ClusterClient`` retains the
    last-known manifest — reads/writes continue to operate against the
    existing node set until a future refresh succeeds.

    The object is a context manager: ``with ClusterClient(...) as cc:``
    guarantees ``close()`` runs on exit.
    """

    def __init__(
        self,
        manifest: ClusterManifest,
        *,
        operator_spk: bytes,
        base_domain: str,
        bootstrap_reader: DNSRecordReader,
        writer_factory: WriterFactory,
        reader_factory: ReaderFactory,
        refresh_interval: Optional[float] = None,
        publish_timeout: float = 5.0,
        read_timeout: float = 5.0,
        max_workers: Optional[int] = None,
    ) -> None:
        if refresh_interval is not None and refresh_interval <= 0:
            raise ValueError("refresh_interval must be > 0 when provided")
        # Operator key is canonicalized to bytes (caller may pass a
        # bytearray or memoryview). A deepcopy of the manifest is not
        # needed here — FanoutWriter and UnionReader each deepcopy on
        # install, so mutations to our reference don't affect them.
        self._operator_spk = bytes(operator_spk)
        self._base_domain = base_domain
        self._bootstrap_reader = bootstrap_reader
        self._writer_factory = writer_factory
        self._reader_factory = reader_factory
        self._writer = FanoutWriter(
            manifest,
            writer_factory,
            timeout=publish_timeout,
            max_workers=max_workers,
        )
        self._reader = UnionReader(
            manifest,
            reader_factory,
            timeout=read_timeout,
            max_workers=max_workers,
        )
        # Refresh-thread plumbing. ``_stop`` wakes the thread for a
        # deterministic exit on close(); ``_refresh_thread`` is set only
        # when a positive refresh_interval was supplied.
        self._refresh_interval = refresh_interval
        self._stop = threading.Event()
        self._refresh_thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._closed = False
        if refresh_interval is not None:
            self._refresh_thread = threading.Thread(
                target=self._refresh_loop,
                name="cluster-client-refresh",
                daemon=True,
            )
            self._refresh_thread.start()

    # ------------------------------------------------------------------ properties

    @property
    def writer(self) -> DNSRecordWriter:
        """The :class:`FanoutWriter`, suitable to inject into DMPClient."""
        return self._writer

    @property
    def reader(self) -> DNSRecordReader:
        """The :class:`UnionReader`, suitable to inject into DMPClient."""
        return self._reader

    @property
    def manifest(self) -> ClusterManifest:
        """The currently installed manifest (reflects fanout + union state)."""
        # FanoutWriter and UnionReader both deepcopy on install and keep
        # their own copy; reading from the writer is sufficient because
        # install_manifest on a ClusterClient always installs to both.
        return self._writer.manifest

    # ------------------------------------------------------------------ refresh

    def refresh_now(self) -> bool:
        """Fetch, parse-verify-bind, install iff seq > current. Returns True iff installed.

        This is the single-step refresh entry point. Callers can use
        this directly as a synchronous "tick" even when no background
        thread is running.

        Failures that return ``False`` (not raise):
        - bootstrap reader returns no record / all records fail verify,
        - newly fetched manifest has ``seq <= current.seq`` (the
          underlying install returns False for stale),
        - the new manifest is already expired.

        Truly unexpected exceptions (e.g. a bug in a factory) are
        allowed to propagate so they surface in logs rather than being
        silently swallowed by the refresh loop.
        """
        new_manifest = fetch_cluster_manifest(
            self._base_domain,
            self._operator_spk,
            self._bootstrap_reader,
        )
        if new_manifest is None:
            return False
        # FanoutWriter / UnionReader both enforce seq-monotonicity and
        # expiry internally. Install atomically: if the reader install
        # raises (e.g. a reader_factory can't parse a new dns_endpoint),
        # we must not have already swapped the writer — otherwise
        # writes would land on the new node set while reads stay on
        # the old one, and newly published messages become invisible.
        # Try reader first: it has the richer failure surface (its
        # factory consumes dns_endpoint, which ClusterManifest does
        # not validate). If reader install succeeds, writer install
        # for the same seq is guaranteed to succeed (same
        # monotonicity rules, writer_factory consumes http_endpoint
        # which is also unvalidated — if it raises here, we at worst
        # have reader-ahead-of-writer for one cycle, which the next
        # refresh will reconcile).
        #
        # Both sides receive their own deepcopy of the same fetched
        # manifest so install-time mutation on one side can't
        # contaminate the other's retained comparison state.
        reader_ok = self._reader.install_manifest(copy.deepcopy(new_manifest))
        writer_ok = self._writer.install_manifest(copy.deepcopy(new_manifest))
        return writer_ok and reader_ok

    def _refresh_loop(self) -> None:
        """Daemon loop: tick ``refresh_now`` every ``refresh_interval`` seconds.

        Wakes immediately on ``close()`` so teardown is deterministic.
        Exceptions from ``refresh_now`` are caught and logged; a failed
        tick never crashes the thread or aborts future ticks.
        """
        assert self._refresh_interval is not None  # construction invariant
        interval = float(self._refresh_interval)
        while True:
            # Event.wait returns True iff the event was set during the
            # wait; that means close() ran, so we exit cleanly.
            if self._stop.wait(timeout=interval):
                return
            try:
                self.refresh_now()
            except Exception:
                # Catch broadly inside the refresh loop: the thread must
                # survive any per-tick failure (factory bug, transient
                # network exception, install_manifest edge case).
                # logger.exception emits a traceback at WARNING so
                # operators see the issue without the process dying.
                log.exception("cluster manifest refresh tick failed")

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        """Stop the refresh thread and close the writer/reader cleanly.

        Idempotent. Joins the refresh thread with a short timeout so a
        buggy background call doesn't hang the caller forever.
        """
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._stop.set()
        thread = self._refresh_thread
        if thread is not None:
            # Join with a timeout. The refresh loop wakes on self._stop
            # immediately, so this should return in milliseconds under
            # normal conditions. A longer join could block on an
            # in-flight refresh_now; we bound it so CLI teardown
            # doesn't hang indefinitely on a wedged fetch.
            thread.join(timeout=5.0)
        # FanoutWriter.close and UnionReader.close each wait for
        # in-flight futures and then drain retired resources. Close
        # both; one failing is not a reason to skip the other.
        try:
            self._writer.close()
        finally:
            self._reader.close()

    def __enter__(self) -> "ClusterClient":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()
