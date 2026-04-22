"""`dmp` command-line interface.

A thin wrapper around DMPClient for identity, contact, and message operations
against a DMP node. Pairs well with `python -m dmp.server` on the node side.

Config lives at $DMP_CONFIG_HOME/config.yaml (default: ~/.dmp/config.yaml).
Passphrases are never written to config — either set DMP_PASSPHRASE in the
environment or point `passphrase_file` at a file readable only by you.

    dmp init alice --domain mesh.example.com --endpoint http://node:8053
    dmp identity show
    dmp contacts add bob 3f...a9
    dmp contacts list
    dmp send bob "hello bob"
    dmp recv
    dmp node            # convenience: launch a dmp-node in the foreground

Exit codes: 0 success, 1 user/config error, 2 network/backend error.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import json
import os
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from dmp.client.bootstrap_discovery import fetch_bootstrap_record
from dmp.client.client import DMPClient
from dmp.client.cluster_bootstrap import ClusterClient, fetch_cluster_manifest
from dmp.core.bootstrap import bootstrap_rrset_name
from dmp.core.cluster import ClusterNode
from dmp.network.base import DNSRecordReader, DNSRecordWriter
from dmp.network.composite_reader import CompositeReader
from dmp.network.resolver_pool import ResolverPool, WELL_KNOWN_RESOLVERS

# ----------------------------- config ----------------------------------------


DEFAULT_CONFIG_HOME = Path.home() / ".dmp"
CONFIG_FILENAME = "config.yaml"


@dataclass
class CLIConfig:
    username: str = ""
    domain: str = "mesh.local"
    endpoint: str = ""  # HTTP API base URL of the node
    http_token: Optional[str] = None
    dns_host: Optional[str] = None  # host:port of the DNS resolver
    dns_port: int = 5353
    # Multi-resolver pool entries. Each entry is either a bare IP literal
    # ("8.8.8.8", "2001:4860:4860::8888") or `host:port` (IPv4) /
    # `[host]:port` (IPv6). When non-empty, the CLI builds a
    # `ResolverPool` over these and `dns_host` / `dns_port` are ignored
    # for reads. Populated by `dmp init --dns-resolvers` or
    # `dmp resolvers discover --save`. Empty list preserves the legacy
    # single-host behavior.
    dns_resolvers: List[str] = field(default_factory=list)
    passphrase_file: Optional[str] = None  # alternative to DMP_PASSPHRASE
    # 32 random bytes generated at `dmp init`, stored as hex. Combined with
    # the passphrase under Argon2id to derive the X25519 seed. Two users who
    # happen to share a passphrase still get independent identities; an
    # attacker who captures the public identity has to do a per-user
    # offline brute force rather than a single rainbow table.
    kdf_salt: str = ""
    # Optional DNS zone under which the user publishes / queries identity
    # records. When set, identity publish writes `dmp.<identity_domain>`
    # and `dmp identity fetch <user>@<host>` resolves addresses in this
    # shape. Leaving this empty falls back to the hash-based name under
    # the shared mesh `domain` (squat-prone, TOFU only).
    identity_domain: str = ""
    # Cluster-mode configuration (M2.wire). When both
    # `cluster_base_domain` AND `cluster_operator_spk` are set,
    # `_make_client` boots the federation path: fetch the signed cluster
    # manifest from `cluster.<base>` TXT, verify under the pinned
    # operator key, build FanoutWriter + UnionReader from the node list,
    # and inject both into the DMPClient. Leaving either empty falls
    # back to the legacy single-endpoint mode. See docs/guide/cli.md.
    cluster_base_domain: str = ""
    cluster_operator_spk: str = ""  # hex-encoded Ed25519 public key
    # Background manifest refresh cadence in seconds (0 or negative
    # disables the refresh thread). Default 3600 matches a
    # once-per-hour rollover cadence for operator-side node-set changes.
    cluster_refresh_interval: int = 3600
    # Optional bearer token used when a per-node HTTP writer talks to
    # a cluster node's publish API. Separate from `http_token` because
    # operators may want distinct creds for the cluster-federation path.
    # When empty, falls back to `http_token` if set; otherwise no auth.
    cluster_node_token: str = ""
    # Explicit cluster-mode activation switch. Decouples "I pinned the
    # anchors" from "I want every networked command to go through the
    # cluster path". Flipped True by `dmp cluster enable` only after a
    # live manifest fetch succeeds; `dmp cluster pin` leaves it False
    # so operators can `cluster fetch` to verify before cutting over.
    # Back-compat: older configs load as False even when both anchors
    # are pinned — upgrading requires a one-time `dmp cluster enable`.
    cluster_enabled: bool = False
    # Bootstrap-discovery anchors (M3.2-wire). When pinned via
    # `dmp bootstrap pin <user_domain> <signer_spk_hex>`, subsequent
    # `dmp bootstrap fetch / discover` and `dmp identity fetch
    # alice@<host> --via-bootstrap` commands translate a user domain
    # into the cluster handling its mailboxes. This is a SEPARATE
    # trust domain from `cluster_*`: the zone operator signing
    # `_dmp.<user_domain>` TXT is not (necessarily) the same party
    # as the cluster operator signing the cluster manifest.
    # Compromising one does not imply compromising the other; the
    # bootstrap discover → cluster pin flow verifies both hops before
    # writing any config. Empty on a fresh init; back-compat for
    # older configs loads as empty. No auto-activation — the user
    # must explicitly `bootstrap pin` or pass anchors per-call.
    bootstrap_user_domain: str = ""  # e.g. "example.com"
    bootstrap_signer_spk: str = ""  # hex Ed25519 pubkey of the zone operator
    # Each contact is {"pub": <x25519 hex>, "spk": <ed25519 hex or "">,
    # "domain": <remote host or "">}.
    # `spk` may be empty for contacts added before Ed25519 pinning landed
    # (and for the `contacts add` shortcut that doesn't require a signing
    # key). Pinned `spk` is what gates incoming manifests from that sender.
    # `domain` holds the remote host for a contact added via
    # `dmp identity fetch user@host --add`; it's consulted by the
    # rotation fallback so chain walks resolve against the remote zone
    # (not the operator's local effective domain). Legacy configs predating
    # this field leave it empty and fall back to the local effective
    # domain for all addressing (back-compat).
    contacts: Dict[str, Dict[str, str]] = field(default_factory=dict)

    @classmethod
    def load(cls, path: Path) -> "CLIConfig":
        if not path.exists():
            raise FileNotFoundError(
                f"no config at {path} — run `dmp init <username>` first"
            )
        data = yaml.safe_load(path.read_text()) or {}
        raw_contacts = data.get("contacts", {}) or {}
        contacts: Dict[str, Dict[str, str]] = {}
        for name, value in raw_contacts.items():
            if isinstance(value, str):
                # Legacy format: username -> pubkey_hex.
                contacts[name] = {"pub": value, "spk": "", "domain": ""}
            elif isinstance(value, dict):
                # `domain` is optional (added post-M5.4 for cross-zone
                # rotation-chain walks). Absent means "use the local
                # effective domain" — preserves behavior for pre-existing
                # `{pub, spk}` entries.
                contacts[name] = {
                    "pub": value.get("pub", ""),
                    "spk": value.get("spk", ""),
                    "domain": value.get("domain", ""),
                }
        raw_resolvers = data.get("dns_resolvers", []) or []
        # Be generous in what we accept: a single-string config (legacy
        # typo) shouldn't crash the loader.
        if isinstance(raw_resolvers, str):
            raw_resolvers = [raw_resolvers]
        dns_resolvers: List[str] = [str(r) for r in raw_resolvers]
        return cls(
            username=data.get("username", ""),
            domain=data.get("domain", "mesh.local"),
            endpoint=data.get("endpoint", ""),
            http_token=data.get("http_token"),
            dns_host=data.get("dns_host"),
            dns_port=int(data.get("dns_port", 5353)),
            dns_resolvers=dns_resolvers,
            passphrase_file=data.get("passphrase_file"),
            kdf_salt=data.get("kdf_salt", ""),
            identity_domain=data.get("identity_domain", ""),
            cluster_base_domain=data.get("cluster_base_domain", "") or "",
            cluster_operator_spk=data.get("cluster_operator_spk", "") or "",
            cluster_refresh_interval=int(data.get("cluster_refresh_interval", 3600)),
            cluster_node_token=data.get("cluster_node_token", "") or "",
            # Back-compat: an older config (pinned anchors, no
            # cluster_enabled key) must NOT silently enter cluster mode
            # on upgrade. Default to False; the operator must run
            # `dmp cluster enable` once to cut over.
            cluster_enabled=bool(data.get("cluster_enabled", False)),
            # Bootstrap-discovery anchors (M3.2-wire). Load as empty on
            # pre-M3.2 configs; no auto-activation. Persisted alongside
            # the cluster_* block for consistency.
            bootstrap_user_domain=data.get("bootstrap_user_domain", "") or "",
            bootstrap_signer_spk=data.get("bootstrap_signer_spk", "") or "",
            contacts=contacts,
        )

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(asdict(self), sort_keys=True))
        # Tighten permissions — config can leak your node endpoint + token.
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def _config_path() -> Path:
    home = os.environ.get("DMP_CONFIG_HOME")
    return (
        Path(home) / CONFIG_FILENAME if home else DEFAULT_CONFIG_HOME / CONFIG_FILENAME
    )


def _load_passphrase(config: CLIConfig) -> str:
    if passphrase := os.environ.get("DMP_PASSPHRASE"):
        return passphrase
    if config.passphrase_file:
        fp = Path(config.passphrase_file).expanduser()
        if fp.exists():
            return fp.read_text().strip()
    # Interactive prompt as last resort.
    return getpass.getpass(f"Passphrase for {config.username or 'identity'}: ")


# ----------------------------- transport adapters ----------------------------


class _HttpWriter(DNSRecordWriter):
    """Publishes records via the node's HTTP API."""

    def __init__(self, endpoint: str, token: Optional[str] = None):
        import requests

        self._requests = requests
        self._endpoint = endpoint.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

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


class _DnsReader(DNSRecordReader):
    """Reads records via a configured DNS resolver (or the system default)."""

    def __init__(self, host: Optional[str], port: int = 5353):
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        if host:
            self._resolver.nameservers = [host]
            self._resolver.port = port
        self._resolver.timeout = 3.0
        self._resolver.lifetime = 6.0

    def query_txt_record(self, name: str):
        import dns.resolver

        try:
            answers = self._resolver.resolve(name, "TXT")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            return None
        values = []
        for rdata in answers:
            values.append(b"".join(rdata.strings).decode("utf-8"))
        return values or None


def _parse_resolver_entry(entry: str) -> Tuple[str, Optional[int]]:
    """Parse one `--dns-resolvers` entry into `(ip_literal, port_or_None)`.

    Accepted forms:
      - `8.8.8.8`                         → ("8.8.8.8", None)
      - `8.8.8.8:53`                      → ("8.8.8.8", 53)
      - `2001:4860:4860::8888`            → (..., None)
      - `[2001:4860:4860::8888]:53`       → (..., 53)

    IPv6 literals contain colons themselves, so a port is only allowed
    when the address is wrapped in brackets. Bare IPv6 with a trailing
    `:port` is ambiguous and rejected.

    Raises ValueError with a user-facing message on any malformed input,
    including hostnames — `ResolverPool` refuses to resolve those anyway
    (it would reintroduce the DNS-ordering problem the pool solves).
    """
    entry = entry.strip()
    if not entry:
        raise ValueError("resolver entry is empty")

    host: str
    port: Optional[int] = None

    if entry.startswith("["):
        # Bracketed IPv6, optionally followed by :port.
        close = entry.find("]")
        if close == -1:
            raise ValueError(f"resolver entry {entry!r}: unmatched '['")
        host = entry[1:close]
        rest = entry[close + 1 :]
        if rest:
            if not rest.startswith(":"):
                raise ValueError(
                    f"resolver entry {entry!r}: expected ':port' after ']'"
                )
            port = _parse_port(rest[1:], entry)
    elif entry.count(":") == 1:
        # IPv4 with port.
        host, _, port_str = entry.partition(":")
        port = _parse_port(port_str, entry)
    else:
        # Bare IPv4 or bare IPv6 (zero or multiple colons).
        host = entry

    # IP-literal-only policy matches ResolverPool's own rule.
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError(
            f"resolver entry {entry!r}: {host!r} is not a valid IPv4 or IPv6 "
            f"literal; hostnames are not accepted"
        ) from exc

    return host, port


def _parse_port(raw: str, entry: str) -> int:
    try:
        port = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"resolver entry {entry!r}: port {raw!r} is not an integer"
        ) from exc
    if not 1 <= port <= 65535:
        raise ValueError(
            f"resolver entry {entry!r}: port {port} out of range (1-65535)"
        )
    return port


def _parse_resolver_list(raw: str) -> List[Tuple[str, Optional[int]]]:
    """Parse the full comma-separated `--dns-resolvers` value.

    Returns a list of `(ip, port_or_None)` tuples. An empty or
    all-whitespace value is rejected — if the user passed the flag at
    all, they meant something.
    """
    entries = [e for e in (s.strip() for s in raw.split(",")) if e]
    if not entries:
        raise ValueError("--dns-resolvers was empty")
    return [_parse_resolver_entry(e) for e in entries]


def _effective_domain(config: CLIConfig) -> str:
    """Return the mailbox/identity/prekey zone for this config.

    When cluster mode is pinned, every DMP-addressable RRset (mailbox
    slots, identity records, prekeys) lives under the cluster base
    domain — the same zone the operator signs the cluster manifest
    for. Without this, a fresh config that keeps the default
    ``mesh.local`` would publish identities and prekeys into one
    zone while fanning mailbox writes into another, silently breaking
    every cross-command flow.
    """
    if config.cluster_base_domain and config.cluster_operator_spk:
        return config.cluster_base_domain
    return config.domain


def _make_reader(config: CLIConfig) -> DNSRecordReader:
    """Build the reader backend from config.

    If `dns_resolvers` is populated, return a `ResolverPool` across them
    — this takes precedence over the legacy single-host fields and lets
    the CLI fail over between resolvers when one misbehaves. Otherwise
    fall back to the single-host `_DnsReader` for back-compat with
    existing configs.

    Per-host ports: `ResolverPool` accepts `(ip, port)` tuples so each
    entry carries its own port. Entries without an explicit port inherit
    `ResolverPool`'s default (53 — the standard DNS port). The
    `_DnsReader` fallback still honors `dns_port` unchanged, so
    upgrading from the legacy single-host setup is transparent.
    """
    if config.dns_resolvers:
        parsed = _parse_resolver_list(",".join(config.dns_resolvers))
        # Hand each upstream through with its own port, or a bare IP
        # when the entry was portless (ResolverPool inherits its own
        # default of 53 for those).
        pool_hosts = [(h, p) if p is not None else h for h, p in parsed]
        return ResolverPool(pool_hosts)
    return _DnsReader(config.dns_host, config.dns_port)


def _cluster_mode_enabled(config: CLIConfig) -> bool:
    """A config is in cluster mode when both anchors are pinned AND enabled.

    Three fields gate cluster mode: the base domain we fetch
    `cluster.<X>` TXT from, the operator public key we trust signatures
    against, and the explicit `cluster_enabled` activation switch.
    Missing any of the three means we fall back to the single-endpoint
    legacy path.

    The `cluster_enabled` flag separates "I pinned the anchors" (setup)
    from "I want every networked command to use the cluster path"
    (activation). This lets operators pin + verify via
    `dmp cluster fetch` before cutting over with `dmp cluster enable`.
    """
    return bool(
        config.cluster_base_domain
        and config.cluster_operator_spk
        and config.cluster_enabled
    )


def _cluster_anchors_pinned(config: CLIConfig) -> bool:
    """Return True when both cluster anchors are set, regardless of enable.

    Used by read-only diagnostic commands (`cluster fetch`,
    `cluster status`) that operate on the pinned manifest without
    requiring the activation switch. Also used by `cluster enable`
    and `cluster disable` as their precondition check.
    """
    return bool(config.cluster_base_domain and config.cluster_operator_spk)


def _build_cluster_writer_factory(config: CLIConfig):
    """Return a writer_factory(ClusterNode) -> `_HttpWriter`.

    Each cluster node has an `http_endpoint`; we hand that to
    `_HttpWriter`. For auth, prefer `cluster_node_token` (cluster-specific
    token), else fall back to the generic `http_token`, else no auth.
    """
    token = config.cluster_node_token or config.http_token or None

    def factory(node: ClusterNode) -> DNSRecordWriter:
        return _HttpWriter(node.http_endpoint, token)

    return factory


class _NodeDnsReader(DNSRecordReader):
    """UDP DNS reader bound to one cluster node's `dns_endpoint`.

    Parses `host`, `host:port`, or `[ipv6]:port` forms. When no port is
    given, defaults to 53. Uses `dns.query.udp` directly so the reader
    has a single deterministic destination — we do NOT fall back to
    the system resolver on failure (that would hide an unreachable
    cluster node from the union).
    """

    def __init__(self, dns_endpoint: str, *, timeout: float = 3.0) -> None:
        host, port = _parse_host_port(dns_endpoint, default_port=53)
        self._host = host
        self._port = port
        self._timeout = float(timeout)

    def query_txt_record(self, name: str):
        import dns.exception
        import dns.flags
        import dns.message
        import dns.query
        import dns.rcode
        import dns.rdatatype

        # Distinguish "successful empty answer" (return None — healthy
        # miss, UnionReader treats as not-an-error) from "transport or
        # protocol failure" (raise — UnionReader counts as per-node
        # failure and increments consecutive_failures). Coalescing both
        # to None would make dead DNS endpoints look perpetually
        # healthy in `cluster status` and defeat the pool's demotion.
        request = dns.message.make_query(name, dns.rdatatype.TXT)
        response = dns.query.udp(
            request,
            self._host,
            port=self._port,
            timeout=self._timeout,
        )
        # Real DMP RRsets (prekey sets, multi-chunk slot manifests) can
        # exceed the UDP 512-byte ceiling. When that happens the node
        # sets the TC (truncated) bit and the answer section is useless;
        # we MUST retry over TCP to see the full rrset. Reuse the same
        # request so the question section + id matches.
        if response.flags & dns.flags.TC:
            response = dns.query.tcp(
                request,
                self._host,
                port=self._port,
                timeout=self._timeout,
            )
        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            return None  # Healthy "no such name" answer.
        if rcode != dns.rcode.NOERROR:
            raise RuntimeError(
                f"DNS rcode {dns.rcode.to_text(rcode)} from {self._host}"
            )
        values: List[str] = []
        for rrset in response.answer:
            for rdata in rrset:
                values.append(b"".join(rdata.strings).decode("utf-8"))
        return values or None


def _parse_host_port(entry: str, *, default_port: int) -> Tuple[str, int]:
    """Parse `host`, `host:port`, or `[ipv6]:port`.

    Returns `(host, port)`. Hostnames are accepted here (unlike the
    resolver pool which is IP-only) because a cluster manifest may
    legitimately publish a hostname for a node's DNS endpoint; the
    operator controls those addresses.
    """
    entry = entry.strip()
    if not entry:
        raise ValueError("dns_endpoint is empty")
    if entry.startswith("["):
        close = entry.find("]")
        if close == -1:
            raise ValueError(f"dns_endpoint {entry!r}: unmatched '['")
        host = entry[1:close]
        rest = entry[close + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":"):
            raise ValueError(f"dns_endpoint {entry!r}: expected ':port' after ']'")
        return host, _parse_port(rest[1:], entry)
    # IPv4 or hostname. IPv6 without brackets is ambiguous — either the
    # whole thing is an address, or the trailing `:port` is a port.
    # We disambiguate by counting colons: exactly one colon => host:port.
    if entry.count(":") == 1:
        host, _, port_str = entry.partition(":")
        return host, _parse_port(port_str, entry)
    return entry, default_port


def _make_cluster_reader_factory(
    config: CLIConfig,
    bootstrap_reader: DNSRecordReader,
):
    """Return a reader_factory(ClusterNode) -> DNSRecordReader.

    Node has `dns_endpoint`: build a `_NodeDnsReader` pointed at that
    host:port. Node has no `dns_endpoint`: fall back to the bootstrap
    reader (the same resolver pool used to fetch the cluster manifest).
    The fallback keeps the read-side union non-empty for nodes that
    only run HTTP ingress — they still contribute via the public DNS
    plane (which should carry their records on propagation).
    """

    def factory(node: ClusterNode) -> DNSRecordReader:
        if node.dns_endpoint:
            return _NodeDnsReader(node.dns_endpoint)
        return bootstrap_reader

    return factory


class _OfflineWriter(DNSRecordWriter):
    """Placeholder writer used by local-only CLI commands in cluster mode.

    `dmp identity show` and similar commands only read the local identity
    state — no writer needed. But the legacy code path hands every client
    a real `_HttpWriter`; when cluster mode is enabled we'd otherwise try
    to fetch the cluster manifest at startup, which fails with exit 2 any
    time DNS is unreachable (captive wi-fi, plane, DNS outage). That
    breaks local-only commands that never intended to touch the network.

    Using this placeholder keeps the local path working, and any
    accidental network call fails loudly so a buggy command doesn't
    silently swallow writes that should have hit DNS.
    """

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        raise RuntimeError(
            "network unavailable: this command was built without cluster "
            "bootstrap (local-only mode); publish_txt_record is not supported"
        )

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        raise RuntimeError(
            "network unavailable: this command was built without cluster "
            "bootstrap (local-only mode); delete_txt_record is not supported"
        )


class _OfflineReader(DNSRecordReader):
    """Placeholder reader mirror of `_OfflineWriter`. Raises on use."""

    def query_txt_record(self, name: str):
        raise RuntimeError(
            "network unavailable: this command was built without cluster "
            "bootstrap (local-only mode); query_txt_record is not supported"
        )


def _make_client(
    config: CLIConfig,
    passphrase: str,
    *,
    requires_network: bool = True,
) -> DMPClient:
    """Build a DMPClient, routing through the cluster or legacy path.

    When cluster mode is enabled (both `cluster_base_domain` AND
    `cluster_operator_spk` populated), the returned client uses the
    FanoutWriter + UnionReader produced by a `ClusterClient`. The
    `ClusterClient` is attached to the returned DMPClient via a
    `_cluster_client` attribute so the CLI wrapper can close it on exit
    (see `_close_client`).

    When cluster mode is disabled, behavior is unchanged from the
    legacy single-endpoint path.

    `requires_network=False` is an escape hatch for commands that only
    need local state (e.g. `dmp identity show`, which just prints
    username + derived keys). In that mode we skip the cluster manifest
    fetch entirely and hand the client offline placeholder writer/reader
    objects that raise on use. This keeps offline CLI use working (no
    DNS required) without silencing real network failures for commands
    that DO need the wire — those still pass `requires_network=True`
    (the default) and still fail loudly on bootstrap failure.
    """
    cluster_client: Optional[ClusterClient] = None
    if _cluster_mode_enabled(config):
        try:
            operator_spk = bytes.fromhex(config.cluster_operator_spk)
        except ValueError:
            _die(
                1,
                "cluster_operator_spk is not valid hex; run "
                "`dmp cluster pin <hex> <base_domain>` to fix",
            )
        if len(operator_spk) != 32:
            _die(
                1,
                "cluster_operator_spk must be 32 bytes (64 hex chars); got "
                f"{len(operator_spk)} bytes",
            )
        if not requires_network:
            # Local-only mode: don't touch DNS. A subsequent network call
            # on this client will raise via the offline placeholders.
            writer: DNSRecordWriter = _OfflineWriter()
            reader: DNSRecordReader = _OfflineReader()
        else:
            bootstrap_reader = _make_reader(config)
            manifest = fetch_cluster_manifest(
                config.cluster_base_domain,
                operator_spk,
                bootstrap_reader,
            )
            if manifest is None:
                _die(
                    2,
                    f"cluster manifest fetch failed for {config.cluster_base_domain}. "
                    "Check that `cluster.<base>` TXT is published, signed by the "
                    "pinned operator key, and not expired.",
                )
            refresh_interval: Optional[float] = (
                float(config.cluster_refresh_interval)
                if config.cluster_refresh_interval > 0
                else None
            )
            cluster_client = ClusterClient(
                manifest,
                operator_spk=operator_spk,
                base_domain=config.cluster_base_domain,
                bootstrap_reader=bootstrap_reader,
                writer_factory=_build_cluster_writer_factory(config),
                reader_factory=_make_cluster_reader_factory(config, bootstrap_reader),
                refresh_interval=refresh_interval,
            )
            writer = cluster_client.writer
            # Cross-domain reads (e.g. `dmp identity fetch
            # alice@other-domain.com`) would NXDOMAIN through the
            # cluster's authoritative nodes because those nodes have
            # no delegation for the external zone. Wrap the union
            # reader with a CompositeReader that routes cluster-local
            # names to the union and external names through the
            # bootstrap recursive resolver.
            reader = CompositeReader(
                cluster_reader=cluster_client.reader,
                external_reader=bootstrap_reader,
                cluster_base_domain=config.cluster_base_domain,
            )
    else:
        if not config.endpoint:
            if not requires_network:
                # Legacy mode with no endpoint: still usable for local
                # commands. Hand back placeholders so `dmp identity show`
                # works on a bare config that never got an --endpoint.
                writer = _OfflineWriter()
                reader = _OfflineReader()
            else:
                _die(
                    1,
                    "no endpoint configured — run `dmp init` with --endpoint, or edit "
                    f"{_config_path()}",
                )
        else:
            writer = _HttpWriter(config.endpoint, config.http_token)
            reader = _make_reader(config)
    # Persist the replay cache next to the config so repeated `dmp recv` calls
    # across separate CLI processes don't re-deliver the same message.
    replay_path = str(_config_path().parent / "replay_cache.json")
    # Prekey store sits in the same config dir; forward-secrecy property
    # depends on this file's permissions matching the passphrase file.
    prekey_path = str(_config_path().parent / "prekeys.db")
    # Prefer the per-identity salt from config; fall back to the library
    # default only if this config predates the kdf_salt field.
    kdf_salt = bytes.fromhex(config.kdf_salt) if config.kdf_salt else None
    # In cluster mode, mailbox RRsets live under the cluster base domain
    # (the same zone the operator controls and signs the manifest for).
    # Using config.domain here would silently target the legacy mesh
    # zone — fetching the cluster manifest from foo.com but then writing
    # mailbox records under mesh.local would break send/recv entirely.
    effective_domain = _effective_domain(config)
    client = DMPClient(
        config.username,
        passphrase,
        domain=effective_domain,
        writer=writer,
        reader=reader,
        replay_cache_path=replay_path,
        kdf_salt=kdf_salt,
        prekey_store_path=prekey_path,
    )
    # Attach the cluster handle (if any) so the CLI can close it at
    # exit. Setting an attribute on DMPClient after construction is
    # intentionally unintrusive — we do not modify DMPClient itself,
    # per the M2.wire hard-rules constraint.
    client._cluster_client = cluster_client  # type: ignore[attr-defined]
    # Contacts must use the same effective domain as the client itself
    # for mailbox-local addressing (slot/chunk RRsets); otherwise
    # send_message() builds prekey_rrset_name under the legacy domain
    # while refresh_prekeys publishes under the cluster base, silently
    # disabling forward secrecy on every send.
    #
    # For CROSS-ZONE contacts (pinned via `dmp identity fetch
    # alice@other-zone.example --add`), we persist the remote host as
    # `entry.domain`. Using that here lets the rotation-chain walker
    # resolve against the remote zone's `rotate.dmp.<remote-host>`
    # RRset. Legacy contacts (no `domain` field) fall back to the
    # local effective domain — back-compat for pre-M5.4 configs.
    for name, entry in config.contacts.items():
        contact_domain = entry.get("domain", "") or effective_domain
        client.add_contact(
            name,
            entry.get("pub", ""),
            domain=contact_domain,
            signing_key_hex=entry.get("spk", ""),
        )
    return client


def _close_client(client: DMPClient) -> None:
    """Release the cluster-client handle if one is attached.

    Called at CLI exit to stop the refresh thread and drain the
    FanoutWriter / UnionReader cleanly. Safe to call on legacy clients
    (the attribute is set to None in that case).
    """
    cluster_client: Optional[ClusterClient] = getattr(client, "_cluster_client", None)
    if cluster_client is not None:
        try:
            cluster_client.close()
        except Exception:
            pass


# ----------------------------- commands --------------------------------------


def _die(code: int, msg: str) -> None:
    print(f"dmp: {msg}", file=sys.stderr)
    sys.exit(code)


def cmd_init(args: argparse.Namespace) -> int:
    path = _config_path()
    if path.exists() and not args.force:
        _die(1, f"config already exists at {path} (use --force to overwrite)")

    # Parse --dns-resolvers eagerly so a malformed value fails init (non-
    # zero exit) rather than silently landing in config and exploding on
    # the first read. When set, the multi-resolver pool takes precedence
    # over the single-host --dns-host/--dns-port fields.
    dns_resolvers: List[str] = []
    if args.dns_resolvers:
        try:
            parsed = _parse_resolver_list(args.dns_resolvers)
        except ValueError as exc:
            _die(1, f"invalid --dns-resolvers: {exc}")
        # Re-serialize to the canonical form we store in config: bare IP
        # for portless entries, `ip:port` for IPv4+port, `[ip]:port` for
        # IPv6+port. Round-tripping through the parser on load catches
        # hand-edited config breakage the same way the CLI does.
        for host, port in parsed:
            if port is None:
                dns_resolvers.append(host)
            elif ":" in host:
                dns_resolvers.append(f"[{host}]:{port}")
            else:
                dns_resolvers.append(f"{host}:{port}")

    cfg = CLIConfig(
        username=args.username,
        domain=args.domain,
        endpoint=args.endpoint or "",
        http_token=args.http_token,
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        dns_resolvers=dns_resolvers,
        # Per-identity random salt so two users with the same passphrase
        # still derive different keys. 32 bytes is well above Argon2's
        # minimum (8) and matches our key length.
        kdf_salt=os.urandom(32).hex(),
        identity_domain=(args.identity_domain or "").strip(),
    )
    cfg.save(path)
    print(f"wrote config to {path}")
    print(
        "Next: set DMP_PASSPHRASE or create a passphrase file, then `dmp identity show`."
    )
    print(
        "Keep this config file. If you lose the kdf_salt you cannot "
        "recover this identity even with the passphrase."
    )
    return 0


def cmd_identity_show(args: argparse.Namespace) -> int:
    # `identity show` only prints local-config state + keys derived from
    # the passphrase; it never touches DNS. Skip the cluster manifest
    # fetch so this command works offline (captive wi-fi, flight, DNS
    # outage) even when cluster mode is pinned in config.
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase, requires_network=False)
    try:
        info = client.get_user_info()
        if args.json:
            print(json.dumps(info, indent=2))
        else:
            for key in (
                "username",
                "domain",
                "public_key",
                "signing_public_key",
                "user_id",
            ):
                print(f"{key}: {info[key]}")
        return 0
    finally:
        _close_client(client)


def cmd_identity_publish(args: argparse.Namespace) -> int:
    """Publish a signed identity record to DNS so contacts can resolve us."""
    from dmp.core.identity import (
        identity_domain,
        make_record,
        zone_anchored_identity_name,
    )

    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        record = make_record(client.crypto, cfg.username)
        wire = record.sign(client.crypto)

        if cfg.identity_domain:
            # Zone-anchored: user controls <identity_domain>. Squat
            # resistance comes from the DNS zone's access control, not
            # from a hash.
            name = zone_anchored_identity_name(cfg.identity_domain)
            resolve_hint = f"dmp identity fetch {cfg.username}@{cfg.identity_domain}"
        else:
            name = identity_domain(cfg.username, _effective_domain(cfg))
            resolve_hint = f"dmp identity fetch {cfg.username}"

        ok = client.writer.publish_txt_record(name, wire, ttl=args.ttl)
        if not ok:
            _die(2, "publish failed — see node logs")
        print(f"published identity to {name}")
        print(f"  others can resolve you with: {resolve_hint}")
        return 0
    finally:
        _close_client(client)


def cmd_identity_refresh_prekeys(args: argparse.Namespace) -> int:
    """Generate and publish a fresh pool of one-time prekeys.

    Run this before you expect traffic and periodically afterward. Each
    prekey is a single-use X25519 keypair; the recipient deletes its
    private half after the first successful decrypt, so once consumed the
    message is cryptographically unrecoverable without the original
    ciphertext — that is the forward-secrecy property.
    """
    from dmp.core.prekeys import prekey_rrset_name

    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        published = client.refresh_prekeys(count=args.count, ttl_seconds=args.ttl)
        name = prekey_rrset_name(cfg.username, _effective_domain(cfg))
        print(f"published {published}/{args.count} prekeys to {name}")
        print(f"  local live prekey count: {client.prekey_store.count_live()}")
        if published < args.count:
            print(
                "  (note: some publishes were rejected — check node rate limits and caps)"
            )
        return 0
    finally:
        _close_client(client)


def cmd_identity_rotate(args: argparse.Namespace) -> int:
    """EXPERIMENTAL (M5.4): rotate the user identity key.

    Publishes a co-signed RotationRecord at the user's rotation RRset,
    a self-signed RevocationRecord for the OLD key at the same RRset
    (so non-rotation-aware fetches can filter the old IdentityRecord
    out of the mailbox-name RRset), plus a fresh IdentityRecord for
    the new key.

    With ``--yes``, the command ALSO performs the local swap atomically:
    the config's ``kdf_salt`` stays the same, the ``passphrase_file``
    is pointed at the new passphrase file (if ``--new-passphrase-file``
    was provided), so the next config load + passphrase derive yields
    the same keypair the rotation just published. Without ``--yes``
    the command still publishes (after the interactive confirmation),
    but leaves the on-disk identity untouched — the operator must
    manually point their passphrase source at the new passphrase; do
    NOT regenerate ``kdf_salt``, because the current salt + new
    passphrase is what derives the rotated keypair.

    Wire format subject to revision after the M4 external crypto audit;
    v0.3.0 may introduce a breaking ``v=dmp2;t=rotation;``. See
    ``docs/protocol/rotation.md``.
    """
    if not getattr(args, "experimental", False):
        _die(
            1,
            "key rotation is EXPERIMENTAL and subject to revision after the "
            "external crypto audit — re-run with --experimental to proceed.",
        )

    # Print a loud banner so the operator cannot miss the caveat.
    print(
        "WARNING: identity rotation is EXPERIMENTAL.",
        file=sys.stderr,
    )
    print(
        "  The wire format for rotation + revocation records is draft and "
        "may change in v0.3.0 after the external crypto audit.",
        file=sys.stderr,
    )
    print(
        "  See docs/protocol/rotation.md for the threat model and limits.",
        file=sys.stderr,
    )

    from dmp.core.identity import (
        identity_domain,
        make_record,
        zone_anchored_identity_name,
    )
    from dmp.core.rotation import (
        REASON_COMPROMISE,
        REASON_ROUTINE,
        RevocationRecord,
        RotationRecord,
        SUBJECT_TYPE_USER_IDENTITY,
        rotation_rrset_name_user_identity,
        rotation_rrset_name_zone_anchored,
    )

    cfg = CLIConfig.load(_config_path())

    # Load the CURRENT identity via the usual passphrase path.
    old_passphrase = _load_passphrase(cfg)

    # Load the NEW identity material from --new-passphrase-file, or an
    # env var, or an interactive prompt. We deliberately avoid accepting
    # the new passphrase on argv — it would end up in shell history.
    new_passphrase: Optional[str] = None
    if args.new_passphrase_file:
        fp = Path(args.new_passphrase_file).expanduser()
        if not fp.exists():
            _die(1, f"--new-passphrase-file: {fp} does not exist")
        new_passphrase = fp.read_text().strip()
    elif env_pw := os.environ.get("DMP_NEW_PASSPHRASE"):
        new_passphrase = env_pw
    else:
        new_passphrase = getpass.getpass("New passphrase: ")
    if not new_passphrase:
        _die(1, "new passphrase is empty")

    # Build the two DMPCrypto identities. Both use the SAME kdf_salt as
    # the existing config: two passphrases with the same salt produce
    # different keys, and re-using the salt matches how a real operator
    # would rotate (they don't want to re-randomize the salt mid-flow).
    kdf_salt = bytes.fromhex(cfg.kdf_salt) if cfg.kdf_salt else None
    from dmp.core.crypto import DMPCrypto

    old_crypto = DMPCrypto.from_passphrase(old_passphrase, salt=kdf_salt)
    new_crypto = DMPCrypto.from_passphrase(new_passphrase, salt=kdf_salt)

    if (
        old_crypto.get_signing_public_key_bytes()
        == new_crypto.get_signing_public_key_bytes()
    ):
        _die(
            1,
            "new passphrase derives the same key as the current one — "
            "choose a distinct passphrase for rotation to take effect",
        )

    # Confirmation gate unless --yes. Rotation is a protocol-visible
    # event and we want the operator to eyeball the new fingerprint
    # before publishing.
    new_spk_hex = new_crypto.get_signing_public_key_bytes().hex()
    print(f"current signing key: {old_crypto.get_signing_public_key_bytes().hex()}")
    print(f"new signing key:     {new_spk_hex}")
    if not args.yes:
        resp = input("Publish RotationRecord? [y/N] ").strip().lower()
        if resp not in ("y", "yes"):
            print("aborted.")
            return 1

    # Construct the subject. We use the zone-anchored form when the
    # config has identity_domain set (so subject = user@identity_domain);
    # otherwise fall back to user@effective_domain.
    effective_domain = _effective_domain(cfg)
    if cfg.identity_domain:
        subject = f"{cfg.username}@{cfg.identity_domain}"
    else:
        subject = f"{cfg.username}@{effective_domain}"

    # Seq numbering: start at unix-seconds so a fresh CLI run always
    # produces a strictly monotonic seq across multiple rotations. A
    # longer-horizon store-backed counter is out of scope for this pass;
    # the audit may recommend a different scheme.
    now_ts = int(time.time())
    seq = now_ts
    ts = now_ts

    rotation = RotationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        old_spk=old_crypto.get_signing_public_key_bytes(),
        new_spk=new_crypto.get_signing_public_key_bytes(),
        seq=seq,
        ts=ts,
        exp=ts + int(args.exp_seconds),
    )
    try:
        rotation_wire = rotation.sign(old_crypto, new_crypto)
    except ValueError as exc:
        _die(1, f"failed to co-sign RotationRecord: {exc}")

    # Self-signed revocation of the OLD key at the rotate RRset. Lets
    # non-rotation-aware `dmp identity fetch` filter the old
    # IdentityRecord out of the mailbox-name RRset (append semantics
    # leaves both old and new records there otherwise, triggering the
    # "multiple valid records, ambiguous" exit). See Finding 3 /
    # Option C in docs/protocol/rotation.md.
    reason_str = getattr(args, "reason", "routine") or "routine"
    reason_code = (
        REASON_COMPROMISE if reason_str.lower() == "compromise" else REASON_ROUTINE
    )
    revocation = RevocationRecord(
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject=subject,
        revoked_spk=old_crypto.get_signing_public_key_bytes(),
        reason_code=reason_code,
        ts=ts,
    )
    try:
        revocation_wire = revocation.sign(old_crypto)
    except ValueError as exc:
        _die(1, f"failed to sign RevocationRecord: {exc}")

    # Publish. Needs a writer; go through _make_client to get the same
    # transport the rest of the CLI uses. We use the OLD passphrase for
    # this client — it's still the on-disk identity.
    client = _make_client(cfg, old_passphrase)
    try:
        if cfg.identity_domain:
            rrset_name = rotation_rrset_name_zone_anchored(cfg.identity_domain)
            identity_rrset = zone_anchored_identity_name(cfg.identity_domain)
        else:
            rrset_name = rotation_rrset_name_user_identity(
                cfg.username, effective_domain
            )
            identity_rrset = identity_domain(cfg.username, effective_domain)

        ok = client.writer.publish_txt_record(
            rrset_name, rotation_wire, ttl=int(args.ttl)
        )
        if not ok:
            _die(2, f"publish of RotationRecord to {rrset_name} failed")
        print(f"published RotationRecord to {rrset_name}")

        # Revocation publishes at the same rrset_name so a single RRset
        # read surfaces both the chain-forward hint (rotation) and the
        # filter-out-old-identity hint (revocation).
        ok_rev = client.writer.publish_txt_record(
            rrset_name, revocation_wire, ttl=int(args.ttl)
        )
        if not ok_rev:
            print(
                f"warning: RotationRecord published, but RevocationRecord "
                f"of the old key FAILED to publish at {rrset_name} — "
                f"non-rotation-aware `dmp identity fetch` will see BOTH "
                f"the old and new IdentityRecords and exit ambiguous. "
                f"Re-publish the revocation manually.",
                file=sys.stderr,
            )
        else:
            print(f"published RevocationRecord (old key) to {rrset_name}")

        # Also publish a fresh IdentityRecord for the NEW key so that
        # non-rotation-aware contacts still see the new key pinned
        # correctly on a plain `dmp identity fetch`.
        new_identity = make_record(new_crypto, cfg.username)
        ok = client.writer.publish_txt_record(
            identity_rrset, new_identity.sign(new_crypto), ttl=int(args.ttl)
        )
        if not ok:
            print(
                f"warning: RotationRecord published, but IdentityRecord "
                f"for the new key FAILED to publish at {identity_rrset} — "
                f"re-run `dmp identity publish` after updating the local "
                f"config to the new passphrase.",
                file=sys.stderr,
            )
        else:
            print(f"published new IdentityRecord to {identity_rrset}")
    finally:
        _close_client(client)

    # Atomic local identity swap under --yes. The load-bearing insight:
    # the same kdf_salt + new passphrase derives the new keypair the
    # rotation just published. So we keep the salt, point the passphrase
    # source at the new passphrase file, and the next config load yields
    # the rotated identity with no re-init required.
    swapped_locally = False
    if args.yes:
        new_pp_file = args.new_passphrase_file
        if new_pp_file:
            cfg.passphrase_file = str(Path(new_pp_file).expanduser())
            cfg.save(_config_path())
            swapped_locally = True
            print(
                f"local identity swapped atomically (config.yaml "
                f"passphrase_file -> {cfg.passphrase_file}; kdf_salt "
                f"preserved). Local pubkey: {new_spk_hex}"
            )
        else:
            # New passphrase came from DMP_NEW_PASSPHRASE or interactive
            # prompt — no file path to persist. The operator must set
            # DMP_PASSPHRASE=<new> on subsequent invocations (or
            # subsequently point `passphrase_file` at a new file and
            # re-run) for the on-disk identity to match the published
            # rotation. kdf_salt stays as-is.
            print(
                "note: --yes without --new-passphrase-file leaves the "
                "config's passphrase source untouched; set "
                "DMP_PASSPHRASE=<new> on subsequent invocations. "
                f"kdf_salt is preserved; current salt + new passphrase "
                f"derives pubkey {new_spk_hex}."
            )

    print()
    print("Next steps:")
    print(
        "  1. Pinned contacts running with rotation_chain_enabled=True will "
        "pick up the new key automatically."
    )
    print(
        "  2. Other contacts must manually re-pin: "
        "`dmp identity fetch <user>@<host> --add` against the new key."
    )
    if swapped_locally:
        print(
            "  3. The local identity has already been swapped atomically; "
            "`dmp identity show` will report the new pubkey. `dmp identity "
            "publish` will re-publish the new IdentityRecord under the "
            "rotated key."
        )
    else:
        print(
            "  3. Point your passphrase source at the new passphrase "
            "(edit `passphrase_file` in config.yaml, or set DMP_PASSPHRASE). "
            "Do NOT regenerate kdf_salt — the current salt + new passphrase "
            "derives the rotated keypair. Re-running `dmp init --force` "
            "would break local adoption."
        )
    return 0


def cmd_identity_fetch(args: argparse.Namespace) -> int:
    """Resolve an identity record from DNS and optionally add it as a contact.

    Two address forms:
      - `alice@alice.example.com`  — zone-anchored; queries
        `dmp.alice.example.com`. Squat resistance relies on DNS zone
        control.
      - `alice`                    — legacy / TOFU; queries
        `id-{sha256(alice)[:16]}.<domain>` where <domain> is either
        `--domain` or the config's mesh domain.

    `--via-bootstrap` (M3.2-wire): when the address has `user@host`
    form, discover the cluster that serves `host` on-the-fly via a
    pinned `bootstrap_signer_spk`, route the identity query through a
    one-shot `ClusterClient` pointed at the discovered cluster, then
    tear it down. No config is written — this is a lookup convenience
    for cross-domain addresses, not a cluster-mode cutover.
    """
    import hashlib
    from dmp.core.identity import (
        IdentityRecord,
        identity_domain,
        parse_address,
        zone_anchored_identity_name,
    )

    cfg = CLIConfig.load(_config_path())
    # Fetch is read-only — no passphrase needed. Build a minimal reader
    # path without going through _make_client (which loads the identity
    # key). In cluster mode the identity record lives inside the
    # cluster's zone and is fanned across the node set, so we read via
    # the union reader for read-after-write consistency — reading only
    # the bootstrap resolver can miss a just-published record until
    # recursive DNS catches up.
    bootstrap_reader = _make_reader(cfg)
    cluster_handle: Optional[ClusterClient] = None

    # ---- --via-bootstrap: one-shot discovery then cluster-routed fetch.
    if getattr(args, "via_bootstrap", False):
        parsed_addr = parse_address(args.username)
        if parsed_addr is None:
            _die(
                1,
                f"--via-bootstrap requires an address in user@host form; "
                f"got {args.username!r}",
            )
        _, host = parsed_addr
        # parse_address only asserts `user@host` shape; host can still be
        # a malformed DNS name like ".example.com" or "bad_host" that
        # would raise ValueError out of bootstrap_rrset_name below.
        # Validate here so bad input surfaces as a clean CLI exit.
        from dmp.core.cluster import _validate_dns_name as _validate_host_dns

        try:
            _validate_host_dns(host)
        except ValueError as exc:
            _die(1, f"--via-bootstrap: invalid host in address: {exc}")
        if cfg.bootstrap_user_domain.casefold() != host.casefold():
            _die(
                1,
                f"--via-bootstrap: no bootstrap signer pinned for {host!r}; "
                f"run `dmp bootstrap pin {host} <signer_spk_hex>` first",
            )
        signer_spk = _decode_signer_spk(
            cfg.bootstrap_signer_spk, field_name="bootstrap_signer_spk"
        )
        record = fetch_bootstrap_record(host, signer_spk, bootstrap_reader)
        if record is None:
            _die(
                2,
                f"--via-bootstrap: no verifying bootstrap record at _dmp.{host}",
            )
        # Second trust hop: the cluster manifest must verify under the
        # operator_spk carried by each bootstrap entry. Compromising the
        # zone signer cannot silently impersonate a legitimate cluster
        # (the cluster's own operator key is the gate there).
        #
        # Walk entries in priority order and also probe the per-node
        # factories — a malformed endpoint in a signed manifest must
        # not crash ClusterClient construction below. Shared helper
        # keeps this consistent with auto-pin and manual discover.
        manifest, best = _pick_usable_bootstrap_entry(record, cfg, bootstrap_reader)
        if manifest is None or best is None:
            _die(
                2,
                f"--via-bootstrap: no usable cluster manifest in the "
                f"bootstrap record for {host} "
                f"(tried {len(record.entries)} in priority order)",
            )
        # One-shot ClusterClient: no refresh thread. It lives only for
        # the duration of this identity fetch and is closed in the
        # `finally` block below, so this command never persists any
        # cluster state or leaves background work behind.
        cluster_handle = ClusterClient(
            manifest,
            operator_spk=best.operator_spk,
            base_domain=best.cluster_base_domain,
            bootstrap_reader=bootstrap_reader,
            writer_factory=_build_cluster_writer_factory(cfg),
            reader_factory=_make_cluster_reader_factory(cfg, bootstrap_reader),
            refresh_interval=None,
        )
        # Route the identity lookup DIRECTLY through the union reader.
        # The identity record for `alice@host` lives at `dmp.<host>`,
        # which is NOT under the cluster's `cluster_base_domain`
        # (e.g. mesh.example.com). A CompositeReader would therefore
        # route it to the external resolver, defeating the whole point
        # of --via-bootstrap. We trust the cluster's nodes to be
        # authoritative (or delegated) for the user's zone — that's
        # the deployment contract a bootstrap record implies.
        reader = cluster_handle.reader
    elif _cluster_mode_enabled(cfg):
        try:
            op_spk = bytes.fromhex(cfg.cluster_operator_spk)
        except ValueError:
            _die(1, "cluster_operator_spk in config is not valid hex")
        if len(op_spk) != 32:
            _die(1, "cluster_operator_spk must be 32 bytes (64 hex chars)")
        manifest = fetch_cluster_manifest(
            cfg.cluster_base_domain, op_spk, bootstrap_reader
        )
        if manifest is None:
            _die(
                2,
                f"cluster manifest fetch failed for {cfg.cluster_base_domain}",
            )
        cluster_handle = ClusterClient(
            manifest,
            operator_spk=op_spk,
            base_domain=cfg.cluster_base_domain,
            bootstrap_reader=bootstrap_reader,
            writer_factory=_build_cluster_writer_factory(cfg),
            reader_factory=_make_cluster_reader_factory(cfg, bootstrap_reader),
            refresh_interval=None,  # one-shot; no background thread.
        )
        # Identity fetch is the cross-domain workflow — `dmp identity
        # fetch alice@other-domain.com` queries a zone the pinned
        # cluster doesn't own. Without the composite split, those
        # queries NXDOMAIN through the authoritative cluster nodes.
        # Route cluster-local names (the common cross-DMP case) to
        # the union and external names to the bootstrap resolver.
        reader = CompositeReader(
            cluster_reader=cluster_handle.reader,
            external_reader=bootstrap_reader,
            cluster_base_domain=cfg.cluster_base_domain,
        )
    else:
        reader = bootstrap_reader

    parsed_addr = parse_address(args.username)
    if parsed_addr is not None:
        user, host = parsed_addr
        resolved_username = user
        name = zone_anchored_identity_name(host)
    else:
        resolved_username = args.username
        name = identity_domain(args.username, args.domain or _effective_domain(cfg))

    try:
        records = reader.query_txt_record(name)
    finally:
        if cluster_handle is not None:
            cluster_handle.close()
    if not records:
        _die(2, f"no identity record at {name}")

    # Append-semantics mailbox means the identity domain can hold multiple
    # valid records. If we just take the first verifying one we hand the
    # squatter a win. Collect ALL valid records and force the user to choose
    # via out-of-band fingerprint comparison when there's more than one.
    valid: list[IdentityRecord] = []
    for record in records:
        parsed = IdentityRecord.parse_and_verify(record)
        if parsed is not None:
            valid.append(parsed[0])
    if not valid:
        _die(2, f"found TXT records at {name} but none verified as a DMP identity")

    # Rotation-aware filter (M5.4 Option C): fetch the same subject's
    # rotate RRset (if any), collect self-signed RevocationRecords, and
    # drop any IdentityRecord whose ed25519_spk matches a revocation.
    # This closes the "ambiguous after rotate" hole where the old + new
    # IdentityRecords coexist under append semantics. A compromised key
    # that re-publishes the old IdentityRecord is still filtered because
    # the revocation sits alongside it; see docs/protocol/rotation.md
    # "Revocation model" for the trade-off.
    from dmp.core.rotation import (
        RECORD_PREFIX_REVOCATION,
        RevocationRecord,
        SUBJECT_TYPE_USER_IDENTITY,
        _normalize_subject,
        rotation_rrset_name_user_identity,
        rotation_rrset_name_zone_anchored,
    )

    if parsed_addr is not None:
        _user, _host = parsed_addr
        fetch_subject = f"{_user}@{_host}"
        # Try BOTH forms of the rotate RRset for robustness — a peer
        # might publish the rotation under either. Zone-anchored first
        # (the preferred form for zone-anchored identities); then the
        # hash form as a fallback.
        rotate_rrset_candidates = [
            rotation_rrset_name_zone_anchored(_host),
            rotation_rrset_name_user_identity(_user, _host),
        ]
    else:
        fetch_subject = f"{resolved_username}@{args.domain or _effective_domain(cfg)}"
        rotate_rrset_candidates = [
            rotation_rrset_name_user_identity(
                resolved_username, args.domain or _effective_domain(cfg)
            ),
        ]

    revoked_spks: set[bytes] = set()
    for candidate in rotate_rrset_candidates:
        try:
            rotate_records = reader.query_txt_record(candidate)
        except Exception:
            rotate_records = None
        if not rotate_records:
            continue
        for txt in rotate_records:
            if not isinstance(txt, str):
                continue
            if not txt.startswith(RECORD_PREFIX_REVOCATION):
                continue
            rev = RevocationRecord.parse_and_verify(txt)
            if rev is None:
                continue
            if rev.subject_type != SUBJECT_TYPE_USER_IDENTITY:
                continue
            # Subject match is loose here: the fetch_subject is
            # user@effective-domain, and zone-anchored RotationRecords
            # carry user@identity_domain (which might differ from the
            # mesh domain). Matching too strictly would let the
            # operator's own rotation fail to filter. We accept any
            # revocation whose subject's user half matches and whose
            # host half matches the rotate-RRset zone — effectively,
            # the RRset name is the trust anchor, not the embedded
            # subject.
            if _normalize_subject(rev.subject_type, rev.subject) != _normalize_subject(
                rev.subject_type, fetch_subject
            ):
                # Still keep the revocation if the username half matches
                # and we're querying the unanchored form — the publisher
                # may use a different domain in the subject than the
                # one we queried under. Conservative: only accept exact
                # subject matches.
                continue
            revoked_spks.add(bytes(rev.revoked_spk))

    if revoked_spks:
        filtered = [rec for rec in valid if bytes(rec.ed25519_spk) not in revoked_spks]
        # If filtering drops ALL candidates, don't silently explode:
        # surface the state so the caller can re-pin out-of-band.
        if not filtered:
            _die(
                2,
                f"all IdentityRecords at {name} are revoked by a matching "
                f"RevocationRecord at the rotate RRset — re-pin out-of-band.",
            )
        valid = filtered

    def _fingerprint(rec: IdentityRecord) -> str:
        # 16-char hex fingerprint over (x25519_pk || ed25519_spk).
        raw = rec.x25519_pk + rec.ed25519_spk
        return hashlib.sha256(raw).hexdigest()[:16]

    identity: IdentityRecord
    if len(valid) == 1:
        identity = valid[0]
    else:
        # Multiple valid records at one name — someone is squatting, or a
        # legitimate rotation never cleaned up the old one. Refuse to
        # auto-pick. The user has to compare fingerprints out-of-band and
        # re-run with --accept-fingerprint=<16-hex>.
        want = getattr(args, "accept_fingerprint", None)
        match = None
        if want:
            for rec in valid:
                if _fingerprint(rec) == want.lower():
                    match = rec
                    break
        if match is None:
            print(
                f"ambiguous: {len(valid)} valid identity records at {name}",
                file=sys.stderr,
            )
            for rec in valid:
                print(
                    f"  fingerprint={_fingerprint(rec)}  "
                    f"x25519={rec.x25519_pk.hex()[:16]}...  "
                    f"ed25519={rec.ed25519_spk.hex()[:16]}...  "
                    f"ts={rec.ts}",
                    file=sys.stderr,
                )
            print(
                "verify out-of-band and rerun with --accept-fingerprint=<16-hex>",
                file=sys.stderr,
            )
            sys.exit(2)
        identity = match

    if args.json:
        print(
            json.dumps(
                {
                    "username": identity.username,
                    "public_key": identity.x25519_pk.hex(),
                    "signing_public_key": identity.ed25519_spk.hex(),
                    "ts": identity.ts,
                    "dns_name": name,
                },
                indent=2,
            )
        )
    else:
        print(f"username:           {identity.username}")
        print(f"public_key:         {identity.x25519_pk.hex()}")
        print(f"signing_public_key: {identity.ed25519_spk.hex()}")
        print(f"published at:       {identity.ts}")

    if args.add:
        # For zone-anchored fetches, require the record's internal
        # username to match the left half of the address so an attacker
        # can't publish a record named "bob" at `dmp.alice.example.com`
        # and have it stored under "bob" in alice's contact list.
        if parsed_addr is not None and identity.username != resolved_username:
            _die(
                2,
                f"record at {name} carries username {identity.username!r}, "
                f"not {resolved_username!r} as the address implied",
            )
        contact_key = identity.username
        if contact_key in cfg.contacts:
            print(f"(contact `{contact_key}` already exists — not overwriting)")
        else:
            # Persist the remote host so the rotation fallback can walk
            # chains against the right zone. `parsed_addr` is non-None
            # only for `user@host` form; legacy bare-username adds
            # leave `domain` empty and inherit the local effective
            # domain at _make_client time (pre-M5.4-followup behavior).
            entry: Dict[str, str] = {
                "pub": identity.x25519_pk.hex(),
                "spk": identity.ed25519_spk.hex(),
                "domain": parsed_addr[1] if parsed_addr is not None else "",
            }
            cfg.contacts[contact_key] = entry
            cfg.save(_config_path())
            print(f"added contact {contact_key} (pinned signing key)")
    return 0


def cmd_contacts_add(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    try:
        if len(bytes.fromhex(args.pubkey)) != 32:
            raise ValueError
    except ValueError:
        _die(1, "public key must be 32 bytes (64 hex characters)")

    spk_hex = ""
    if args.signing_key:
        try:
            if len(bytes.fromhex(args.signing_key)) != 32:
                raise ValueError
        except ValueError:
            _die(1, "signing key must be 32 bytes (64 hex characters)")
        spk_hex = args.signing_key.lower()

    # `domain` empty here: `dmp contacts add` takes no remote host, so
    # cross-zone rotation-chain resolution isn't available via this
    # path — the client falls back to the local effective domain.
    # Use `dmp identity fetch user@host --add` to persist the remote
    # host and enable chain walks against the remote zone.
    cfg.contacts[args.name] = {
        "pub": args.pubkey.lower(),
        "spk": spk_hex,
        "domain": "",
    }
    cfg.save(_config_path())
    if spk_hex:
        print(f"added contact {args.name} (pinned signing key)")
    else:
        print(
            f"added contact {args.name}\n"
            f"  WARNING: no Ed25519 signing key pinned. Until at least one\n"
            f"  contact has a pinned signing key, `dmp recv` runs in\n"
            f"  trust-on-first-use mode — any signature-valid manifest\n"
            f"  addressed to you will be delivered, including from senders\n"
            f"  you never added. Re-run with --signing-key <64-hex>, or\n"
            f"  bootstrap via `dmp identity fetch <user> --add` which\n"
            f"  pins both keys.",
            file=sys.stderr,
        )
    return 0


def cmd_contacts_list(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    if not cfg.contacts:
        print(
            "(no contacts yet — `dmp contacts add <name> <pubkey_hex>` or `dmp identity fetch <user> --add`)"
        )
        return 0
    width = max(len(n) for n in cfg.contacts)
    for name, entry in sorted(cfg.contacts.items()):
        pin = "pinned" if entry.get("spk") else "UNPINNED"
        print(f"{name:<{width}}  {entry.get('pub', '')}  ({pin})")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    if args.recipient not in cfg.contacts:
        _die(
            1,
            f"unknown contact `{args.recipient}` — add it first with `dmp contacts add`",
        )
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        ok = client.send_message(args.recipient, args.message)
        if not ok:
            _die(2, f"send failed (see node logs for details)")
        print(f"sent → {args.recipient}")
        return 0
    finally:
        _close_client(client)


def cmd_recv(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        inbox = client.receive_messages()
        if not inbox:
            print("(no new messages)")
            return 0

        # Reverse-lookup sender_signing_pk against known contacts when
        # possible. This requires the contact to match on the derived
        # Ed25519 pubkey, which is itself derived from their X25519
        # pubkey — cross-reference locally.
        from dmp.core.crypto import DMPCrypto

        known = {}
        for name, pubkey_hex in cfg.contacts.items():
            try:
                contact_crypto = DMPCrypto.from_private_bytes(bytes.fromhex(pubkey_hex))
            except Exception:
                continue
            # We can't actually derive the contact's signing key from
            # just their public key (the ED25519 seed is derived from
            # the X25519 *private* bytes). So we can't reverse-lookup
            # names here — just show the hex.
            known[name] = pubkey_hex

        for msg in inbox:
            print(f"from {msg.sender_signing_pk.hex()[:16]}...")
            print(f"  ts={msg.timestamp}")
            try:
                print(f"  {msg.plaintext.decode('utf-8')}")
            except UnicodeDecodeError:
                print(f"  (binary, {len(msg.plaintext)} bytes)")
            print()
        return 0
    finally:
        _close_client(client)


def cmd_resolvers_discover(args: argparse.Namespace) -> int:
    """Probe WELL_KNOWN_RESOLVERS and print (or save) the working subset.

    Without `--save`, this is a read-only diagnostic — useful on a
    captive network to sanity-check which upstreams are reachable
    before committing to them. With `--save`, the working list is
    written to config as `dns_resolvers`; a subsequent `dmp resolvers
    list` (and, once M1.2 lands, the normal client read path) will
    pick it up.

    If every candidate fails, `ResolverPool.discover` raises
    ValueError. We surface that as exit code 2 (network/backend
    error) rather than creating a useless empty pool.
    """
    try:
        pool = ResolverPool.discover(WELL_KNOWN_RESOLVERS, timeout=args.timeout)
    except ValueError as exc:
        _die(2, f"resolver discovery failed: {exc}")

    working = [snap["host"] for snap in pool.snapshot()]
    print(f"discovered {len(working)} working resolver(s):")
    for host in working:
        print(f"  {host}")

    if args.save:
        # `dmp init` may not have run yet on a fresh machine; in that
        # case there's no config to update and the user should init
        # first. If the config does exist, we just set the new field
        # (creating it if absent) and persist.
        path = _config_path()
        if not path.exists():
            _die(
                1,
                f"no config at {path} — run `dmp init <username>` before "
                f"`dmp resolvers discover --save`",
            )
        cfg = CLIConfig.load(path)
        cfg.dns_resolvers = working
        cfg.save(path)
        print(f"saved {len(working)} resolvers to {path}")
    return 0


def cmd_resolvers_list(args: argparse.Namespace) -> int:
    """Print the currently configured `dns_resolvers` list.

    On a fresh install with no `config.yaml`, this used to raise
    `FileNotFoundError` from `CLIConfig.load` and dump a traceback —
    unfriendly for `dmp resolvers list` as a diagnostic command.
    Check for the config up front and surface a clean exit-1 with the
    same "run `dmp init` first" hint other commands use via `_die`.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    if not cfg.dns_resolvers:
        print(
            "(no dns_resolvers configured — run `dmp resolvers discover "
            "--save` to populate)"
        )
        return 0
    for host in cfg.dns_resolvers:
        print(host)
    return 0


def cmd_cluster_pin(args: argparse.Namespace) -> int:
    """Pin a cluster operator key + base domain in config.

    Writes anchors to config; does NOT fetch and does NOT activate
    cluster mode. Activation is a separate step: the operator first
    runs `dmp cluster fetch` to confirm the manifest resolves and
    verifies, then `dmp cluster enable` to flip `cluster_enabled=True`
    so subsequent networked commands route through the cluster path.

    This decoupling means pinning an operator who hasn't published
    their manifest yet is safe — it won't wedge every `dmp send` /
    `dmp recv` on a failed bootstrap. It also gives operators a
    reversible activation: `dmp cluster disable` drops back to the
    legacy endpoint without clearing the pinned anchors.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    try:
        raw = bytes.fromhex(args.operator_spk)
    except ValueError:
        _die(1, "operator_spk must be 64 hex chars (32 bytes Ed25519)")
    if len(raw) != 32:
        _die(1, f"operator_spk must be 32 bytes; got {len(raw)}")
    # Validate the base domain the same way cluster_rrset_name will:
    # reject anything that can't be a DNS owner name. Otherwise the
    # pin succeeds but the next cluster-backed command raises
    # ValueError out of main() instead of a normal CLI error.
    from dmp.core.cluster import _validate_dns_name as _validate_cluster_dns

    try:
        _validate_cluster_dns(args.base_domain)
    except ValueError as exc:
        _die(1, f"invalid base_domain: {exc}")
    cfg.cluster_operator_spk = args.operator_spk.lower()
    cfg.cluster_base_domain = args.base_domain
    # Explicitly do NOT touch `cluster_enabled` here. A fresh pin leaves
    # it at its default (False). Repinning over an already-enabled
    # config also drops activation so the operator re-verifies via
    # `cluster fetch` + `cluster enable` against the new anchors.
    cfg.cluster_enabled = False
    cfg.save(path)
    print(f"pinned cluster operator key and base domain {args.base_domain}")
    print("next:")
    print("  1. `dmp cluster fetch` to verify the manifest resolves")
    print("  2. `dmp cluster enable` to cut over from the legacy endpoint")
    return 0


def cmd_cluster_enable(args: argparse.Namespace) -> int:
    """Activate cluster mode after a live manifest-fetch sanity check.

    Requires both anchors pinned (`dmp cluster pin` beforehand). Runs a
    `fetch_cluster_manifest` against the pinned base domain; if the
    fetch fails (nothing published, signature mismatch, expired),
    leaves `cluster_enabled=False` and exits 2 so the operator can
    diagnose before cutting over. On success, prints the manifest
    summary, sets `cluster_enabled=True`, and persists.

    Idempotent: running enable on an already-enabled config re-runs
    the fetch sanity check and reports the current state — useful as
    a post-rollover health check.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster anchors not pinned — run `dmp cluster pin "
            "<operator_spk_hex> <base_domain>` first",
        )
    try:
        operator_spk = bytes.fromhex(cfg.cluster_operator_spk)
    except ValueError:
        _die(1, "cluster_operator_spk in config is not valid hex")
    if len(operator_spk) != 32:
        _die(1, "cluster_operator_spk must be 32 bytes (64 hex chars)")

    bootstrap_reader = _make_reader(cfg)
    manifest = fetch_cluster_manifest(
        cfg.cluster_base_domain, operator_spk, bootstrap_reader
    )
    if manifest is None:
        # Keep cluster_enabled at its current value (typically False);
        # do NOT flip True on a failed fetch. The operator needs to
        # fix whatever broke the bootstrap before activating.
        print(
            f"dmp: cluster manifest fetch failed for {cfg.cluster_base_domain} — "
            "nothing at `cluster.<base>` TXT verified under the pinned operator key. "
            "Cluster mode NOT enabled. Run `dmp cluster fetch` for diagnostics.",
            file=sys.stderr,
        )
        sys.exit(2)

    print(f"cluster: {manifest.cluster_name}")
    print(f"  seq:   {manifest.seq}")
    print(f"  exp:   {manifest.exp}")
    print(f"  nodes: {len(manifest.nodes)}")
    already_enabled = cfg.cluster_enabled
    cfg.cluster_enabled = True
    cfg.save(path)
    if already_enabled:
        print("cluster mode already enabled — manifest verified, state unchanged.")
    else:
        print("cluster mode enabled.")
    return 0


def cmd_cluster_disable(args: argparse.Namespace) -> int:
    """Turn cluster mode off without clearing the pinned anchors.

    Sets `cluster_enabled=False`. Subsequent networked commands use
    the legacy single-endpoint path (`config.endpoint` + the
    configured reader). The cluster anchors
    (`cluster_base_domain` + `cluster_operator_spk`) stay put so
    re-enabling later doesn't require a re-pin.

    Idempotent: running disable on an already-disabled config just
    reports the current state and returns 0.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    was_enabled = cfg.cluster_enabled
    cfg.cluster_enabled = False
    cfg.save(path)
    if was_enabled:
        print(
            "cluster mode disabled — next commands will use the legacy endpoint path."
        )
    else:
        print("cluster mode already disabled — state unchanged.")
    return 0


def cmd_cluster_fetch(args: argparse.Namespace) -> int:
    """One-shot: fetch + verify the cluster manifest, print a summary.

    Does not install anything. Useful before enabling cluster mode to
    confirm the manifest is published, correctly signed, not expired,
    and addresses the expected cluster name.

    `--save` dumps the raw wire to `cluster_manifest.wire` in the config
    dir. Future offline-bootstrap work may consume that cache on
    startup when DNS is unavailable.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster not configured — run `dmp cluster pin <operator_spk_hex> "
            "<base_domain>` first",
        )
    try:
        operator_spk = bytes.fromhex(cfg.cluster_operator_spk)
    except ValueError:
        _die(1, "cluster_operator_spk in config is not valid hex")
    if len(operator_spk) != 32:
        _die(1, "cluster_operator_spk must be 32 bytes (64 hex chars)")

    bootstrap_reader = _make_reader(cfg)
    manifest = fetch_cluster_manifest(
        cfg.cluster_base_domain, operator_spk, bootstrap_reader
    )
    if manifest is None:
        _die(
            2,
            f"no verifying cluster manifest at cluster.{cfg.cluster_base_domain}",
        )
    print(f"cluster: {manifest.cluster_name}")
    print(f"  seq:   {manifest.seq}")
    print(f"  exp:   {manifest.exp}")
    print(f"  nodes: {len(manifest.nodes)}")
    for node in manifest.nodes:
        dns = node.dns_endpoint or "(via bootstrap reader)"
        print(f"    {node.node_id}  http={node.http_endpoint}  dns={dns}")

    if args.save:
        # Re-sign is not available from just the parsed manifest (we
        # don't have the operator private key here). Persist the raw
        # wire string. We re-fetch the rrset rather than round-tripping
        # through sign() to keep the original signed blob byte-identical,
        # then select the highest-seq valid record — matching what
        # fetch_cluster_manifest returned above, so the persisted wire
        # corresponds to the manifest summary we just printed.
        from dmp.core.cluster import cluster_rrset_name

        rrset = cluster_rrset_name(cfg.cluster_base_domain)
        raw_records = bootstrap_reader.query_txt_record(rrset)
        if raw_records:
            wire_path = _config_path().parent / "cluster_manifest.wire"
            from dmp.core.cluster import ClusterManifest

            best_wire: Optional[str] = None
            best_seq: int = -1
            for wire in raw_records:
                parsed = ClusterManifest.parse_and_verify(
                    wire,
                    operator_spk,
                    expected_cluster_name=cfg.cluster_base_domain,
                )
                if parsed is None:
                    continue
                if parsed.seq > best_seq:
                    best_seq = parsed.seq
                    best_wire = wire
            if best_wire is not None:
                wire_path.parent.mkdir(parents=True, exist_ok=True)
                wire_path.write_text(best_wire)
                print(f"saved signed manifest wire to {wire_path}")
    return 0


def cmd_cluster_status(args: argparse.Namespace) -> int:
    """Build the cluster client and print health snapshots.

    Unlike `dmp cluster fetch`, this actually spins up the full
    ClusterClient (including per-node writers/readers) so the
    fanout/union health snapshots have data to report. We shut it
    down immediately after printing — no background refresh thread
    is left running.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster not configured — run `dmp cluster pin <operator_spk_hex> "
            "<base_domain>` first",
        )
    try:
        operator_spk = bytes.fromhex(cfg.cluster_operator_spk)
    except ValueError:
        _die(1, "cluster_operator_spk in config is not valid hex")
    if len(operator_spk) != 32:
        _die(1, "cluster_operator_spk must be 32 bytes (64 hex chars)")

    bootstrap_reader = _make_reader(cfg)
    manifest = fetch_cluster_manifest(
        cfg.cluster_base_domain, operator_spk, bootstrap_reader
    )
    if manifest is None:
        _die(2, f"no verifying cluster manifest at cluster.{cfg.cluster_base_domain}")

    cc = ClusterClient(
        manifest,
        operator_spk=operator_spk,
        base_domain=cfg.cluster_base_domain,
        bootstrap_reader=bootstrap_reader,
        writer_factory=_build_cluster_writer_factory(cfg),
        reader_factory=_make_cluster_reader_factory(cfg, bootstrap_reader),
        refresh_interval=None,  # no background refresh for a one-shot status
    )
    try:
        m = cc.manifest
        print(f"cluster: {m.cluster_name} (seq={m.seq}, exp={m.exp})")
        # Surface the activation flag so operators running `status` can
        # tell whether commands are actually using cluster mode. A
        # snapshot showing pinned anchors + enabled=False is a common
        # pre-cutover state we want to make visible.
        print(f"cluster_enabled: {cfg.cluster_enabled}")
        print("fan-out writer snapshot:")
        for row in cc.writer.snapshot():  # type: ignore[attr-defined]
            print(
                f"  {row['node_id']}  http={row['http_endpoint']}  "
                f"fails={row['consecutive_failures']}  err={row['last_error']}"
            )
        print("union reader snapshot:")
        for row in cc.reader.snapshot():  # type: ignore[attr-defined]
            print(
                f"  {row['node_id']}  http={row['http_endpoint']}  "
                f"fails={row['consecutive_failures']}  err={row['last_error']}"
            )
    finally:
        cc.close()
    return 0


def _decode_signer_spk(hex_value: str, *, field_name: str = "signer_spk") -> bytes:
    """Decode + validate a 32-byte Ed25519 pubkey from hex.

    Centralizes the check so every bootstrap subcommand reports the
    same errors and exit code. Returns the raw bytes; calls `_die(1)`
    on malformed hex or wrong length.
    """
    try:
        raw = bytes.fromhex(hex_value)
    except ValueError:
        _die(1, f"{field_name} must be 64 hex chars (32 bytes Ed25519)")
    if len(raw) != 32:
        _die(1, f"{field_name} must be 32 bytes; got {len(raw)}")
    return raw


def cmd_bootstrap_pin(args: argparse.Namespace) -> int:
    """Pin a bootstrap trust anchor (zone operator) for a user domain.

    Writes `bootstrap_user_domain` + `bootstrap_signer_spk` to config.
    Does NOT fetch — pinning is cheap and reversible, while a failing
    fetch during pin would wedge every subsequent command on DNS
    availability. Mirrors the `dmp cluster pin` ergonomics.

    Validation:
    - `user_domain` goes through `bootstrap_rrset_name` which runs the
      shared DNS-name validator (empty, leading dot, oversized label,
      non-ASCII all raise). Pinning a malformed name would fail later
      inside `fetch_bootstrap_record` with a less helpful traceback.
    - `signer_spk_hex` must be 64 hex chars decoding to 32 bytes.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    # Validate the user domain the same way bootstrap_rrset_name will
    # — reject malformed names here so the error surfaces at pin time,
    # not deep inside a later fetch.
    try:
        bootstrap_rrset_name(args.user_domain)
    except ValueError as exc:
        _die(1, f"invalid user_domain: {exc}")
    _decode_signer_spk(args.signer_spk_hex, field_name="signer_spk")
    cfg.bootstrap_user_domain = args.user_domain.rstrip(".")
    cfg.bootstrap_signer_spk = args.signer_spk_hex.lower()
    cfg.save(path)
    print(f"pinned bootstrap signer for {cfg.bootstrap_user_domain}")
    print("next:")
    print(
        f"  1. `dmp bootstrap fetch` to verify the record at "
        f"_dmp.{cfg.bootstrap_user_domain} resolves"
    )
    print(
        f"  2. `dmp bootstrap discover <user>@{cfg.bootstrap_user_domain}` "
        "to see which cluster(s) the domain points at"
    )
    return 0


def _norm_dns_name(name: str) -> str:
    """Canonicalize a DNS owner name for comparison: strip a single
    trailing dot and casefold. DNS names are case-insensitive, and
    ``example.com.`` / ``example.com`` denote the same zone."""
    return name.rstrip(".").casefold()


def _pick_usable_bootstrap_entry(
    record,
    cfg: CLIConfig,
    bootstrap_reader: DNSRecordReader,
):
    """Walk `record.entries` in priority order, return (manifest, entry)
    for the first entry whose cluster manifest fetches, verifies, AND
    whose per-node factories can construct a writer+reader for every
    node.

    Returns (None, None) if no entry is usable. Used by bootstrap
    discover / auto-pin / identity fetch --via-bootstrap so all three
    code paths agree on the fallback semantics and don't diverge on
    "manifest verifies but is unusable" cases.

    Note: a manifest where every node has ``dns_endpoint=None`` IS
    considered usable. ``_make_cluster_reader_factory`` falls back to
    the shared bootstrap reader for such nodes, which means
    ``--via-bootstrap`` reads for ``dmp.<host>`` land on whatever
    resolver the bootstrap layer is configured with (typically the
    public DNS system). That is a legitimate deployment shape — the
    cluster may publish via ``nsupdate`` to a public zone and have no
    per-node DNS ingress — but it does mean cluster-routed reads in
    that case are only as fresh as public DNS propagation. Operators
    who want guaranteed cluster-local reads should publish manifests
    where at least one node has a ``dns_endpoint``.
    """
    for entry in record.entries:
        m = fetch_cluster_manifest(
            entry.cluster_base_domain, entry.operator_spk, bootstrap_reader
        )
        if m is None:
            continue
        writer_factory = _build_cluster_writer_factory(cfg)
        reader_factory = _make_cluster_reader_factory(cfg, bootstrap_reader)
        ok = True
        for node in m.nodes:
            try:
                writer_factory(node)
                reader_factory(node)
            except Exception:
                ok = False
                break
        if ok:
            return m, entry
    return None, None


def _resolve_bootstrap_anchors(
    cfg: CLIConfig,
    *,
    cli_user_domain: Optional[str],
    cli_signer_spk: Optional[str],
) -> Tuple[str, bytes]:
    """Pick `(user_domain, signer_spk_bytes)` from CLI args or config.

    CLI args take precedence over pinned config — so an operator can
    verify a fresh anchor one-shot before committing to pin. Either
    BOTH must be supplied together, or both can be left off (fall
    back to pinned config). Mixing a CLI user_domain with a config
    signer_spk for a different user_domain would be a silent trust
    error; we refuse it.
    """
    user_domain = cli_user_domain or cfg.bootstrap_user_domain
    signer_hex = cli_signer_spk or cfg.bootstrap_signer_spk
    if not user_domain or not signer_hex:
        _die(
            1,
            "no bootstrap anchors available — pass --user-domain + "
            "--signer-spk, or pin with `dmp bootstrap pin <user_domain> "
            "<signer_spk_hex>` first",
        )
    # If CLI supplied only one side, complain rather than silently
    # mixing with the pinned value for the other side.
    if cli_user_domain and not cli_signer_spk and not cfg.bootstrap_signer_spk:
        _die(1, "--user-domain given but no --signer-spk and no pinned anchor")
    if cli_signer_spk and not cli_user_domain and not cfg.bootstrap_user_domain:
        _die(1, "--signer-spk given but no --user-domain and no pinned anchor")
    # DNS names are case-insensitive and a trailing dot is canonical —
    # normalize both sides before rejecting the mismatch so users can
    # pass `--user-domain EXAMPLE.com` or `--user-domain example.com.`
    # against a config pinned to `example.com` without being forced to
    # redundantly re-pass --signer-spk.
    if (
        cli_user_domain
        and cfg.bootstrap_user_domain
        and _norm_dns_name(cli_user_domain) != _norm_dns_name(cfg.bootstrap_user_domain)
        and not cli_signer_spk
    ):
        # User supplied a CLI domain that differs from the pinned one
        # but didn't override the signer — the pinned signer trusts a
        # different zone and would never verify records here.
        _die(
            1,
            "--user-domain differs from pinned bootstrap_user_domain; "
            "pass --signer-spk to override the trust anchor too",
        )
    signer_spk = _decode_signer_spk(signer_hex, field_name="signer_spk")
    # Validate the user_domain as a DNS name before handing it off to
    # any downstream code that assumes it's publishable (bootstrap_rrset_name
    # will raise ValueError with a traceback otherwise on malformed
    # input like ".example.com" or "bad_host").
    from dmp.core.cluster import _validate_dns_name as _validate_bootstrap_dns

    try:
        _validate_bootstrap_dns(user_domain)
    except ValueError as exc:
        _die(1, f"invalid bootstrap user_domain: {exc}")
    return user_domain, signer_spk


def cmd_bootstrap_fetch(args: argparse.Namespace) -> int:
    """One-shot: fetch + verify the bootstrap record, print a summary.

    Resolves `_dmp.<user_domain>` TXT, picks the highest-seq record
    that verifies under the signer_spk anchor, and prints entries
    sorted by priority. This is a diagnostic — no state is written.

    Anchor resolution:
    - If `--user-domain` or `--signer-spk` is supplied, it overrides
      the pinned config value (useful for verifying a candidate
      anchor before pinning it).
    - Otherwise both come from `bootstrap_user_domain` +
      `bootstrap_signer_spk` in config.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)
    user_domain, signer_spk = _resolve_bootstrap_anchors(
        cfg,
        cli_user_domain=args.user_domain,
        cli_signer_spk=args.signer_spk,
    )
    bootstrap_reader = _make_reader(cfg)
    record = fetch_bootstrap_record(user_domain, signer_spk, bootstrap_reader)
    if record is None:
        _die(
            2,
            f"no verifying bootstrap record at _dmp.{user_domain}. "
            "Check that the TXT is published, signed by the pinned "
            "signer key, not expired, and binds to this user_domain.",
        )
    print(f"user_domain: {record.user_domain}")
    print(f"seq:         {record.seq}")
    print(f"expires:     {record.exp}")
    print("entries (sorted by priority):")
    for entry in record.entries:
        spk_short = entry.operator_spk.hex()[:16] + "..."
        print(
            f"  priority={entry.priority}  "
            f"cluster={entry.cluster_base_domain}  "
            f"operator_spk={spk_short}"
        )
    return 0


def cmd_bootstrap_discover(args: argparse.Namespace) -> int:
    """End-to-end discovery for an external address.

    Given `alice@example.com`:
    1. Parse into `(user, host)`.
    2. Resolve bootstrap anchors: require pin for `host` (via
       `bootstrap pin`) OR explicit `--signer-spk`.
    3. Fetch + verify the bootstrap record for `host`.
    4. Pick `best_entry()` (lowest priority — SMTP MX semantics).
    5. Without `--auto-pin`: print the `dmp cluster pin` /
       `dmp cluster enable` steps the operator would run. Do NOT
       write anything to config — this is a diagnostic that bridges
       discovery to cluster handoff so the operator approves.
    6. With `--auto-pin`: ALSO fetch + verify the cluster manifest
       at the returned anchor against the entry's `operator_spk`,
       THEN write BOTH bootstrap and cluster config + set
       `cluster_enabled=True`. If either verification step fails,
       exit 2 and leave config untouched — a half-written config
       (bootstrap pinned but cluster not) is worse than nothing.
    """
    from dmp.core.identity import parse_address

    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dmp init <username>` first")
    cfg = CLIConfig.load(path)

    parsed = parse_address(args.address)
    if parsed is None:
        _die(1, f"could not parse address {args.address!r}; expected user@host")
    user, host = parsed

    # Trust anchor resolution: CLI --signer-spk wins; otherwise the
    # pinned config must have bootstrap_user_domain matching the host.
    signer_hex: Optional[str] = args.signer_spk
    if not signer_hex:
        if cfg.bootstrap_user_domain.casefold() != host.casefold():
            _die(
                1,
                f"no bootstrap signer pinned for {host!r} — run "
                f"`dmp bootstrap pin {host} <signer_spk_hex>` first, or "
                "pass --signer-spk <hex> on this call",
            )
        signer_hex = cfg.bootstrap_signer_spk
        if not signer_hex:
            _die(
                1,
                f"no bootstrap signer pinned for {host!r} — run "
                f"`dmp bootstrap pin {host} <signer_spk_hex>` first",
            )
    signer_spk = _decode_signer_spk(signer_hex, field_name="signer_spk")

    # parse_address only asserts user@host shape; host can still be a
    # malformed DNS name. Validate before fetch so bad input is a clean
    # CLI exit instead of a traceback out of bootstrap_rrset_name.
    from dmp.core.cluster import _validate_dns_name as _validate_discover_host

    try:
        _validate_discover_host(host)
    except ValueError as exc:
        _die(1, f"invalid host in address: {exc}")

    bootstrap_reader = _make_reader(cfg)
    record = fetch_bootstrap_record(host, signer_spk, bootstrap_reader)
    if record is None:
        _die(
            2,
            f"no verifying bootstrap record at _dmp.{host}. "
            "Check the TXT is published, signed by the pinned signer, "
            "not expired, and binds to this user_domain.",
        )
    if not args.auto_pin:
        # Diagnostic mode: show the operator what the pinning would
        # look like so they can approve/deny with full visibility.
        # Walk the same fallback ladder --auto-pin uses so the guidance
        # points at a cluster that actually works, not just the
        # highest-priority entry that may be down. If nothing usable,
        # fall back to best_entry() for visibility with a clear warning.
        _usable_manifest, chosen = _pick_usable_bootstrap_entry(
            record, cfg, bootstrap_reader
        )
        shown = chosen if chosen is not None else record.best_entry()
        print(f"address:     {user}@{host}")
        print(f"user_domain: {host}  (seq={record.seq}, exp={record.exp})")
        if chosen is None:
            print(
                "WARNING: no entry in this record has a reachable + "
                "factory-buildable cluster manifest right now. Showing "
                "the highest-priority entry for visibility only — "
                "pinning it would immediately break cluster commands."
            )
        print(f"shown entry: priority={shown.priority}")
        print(f"  cluster_base_domain: {shown.cluster_base_domain}")
        print(f"  operator_spk:        {shown.operator_spk.hex()}")
        print()
        print("to pin this cluster manually, run:")
        print(
            f"  dmp cluster pin {shown.operator_spk.hex()} {shown.cluster_base_domain}"
        )
        print("  dmp cluster fetch  # verify manifest")
        print("  dmp cluster enable # activate cluster mode")
        print()
        print("or re-run with --auto-pin to do all of the above atomically.")
        return 0

    # --auto-pin mutates the caller's own global cluster_* config and
    # flips cluster_enabled=True, which rehomes every subsequent
    # `dmp send` / `dmp recv` / `identity publish` onto the discovered
    # cluster. Running it against ANY address (e.g. to look at a
    # recipient alice@example.com) would rehome the operator's local
    # mailbox state to someone else's cluster — a silent hijack.
    #
    # Guard: require the discovered host to match bootstrap_user_domain
    # pinned in config. That makes auto-pin an explicit two-step flow:
    #   1. `dmp bootstrap pin <my-domain> <my-signer-spk>`  — acknowledge
    #      trust anchor for the zone you actually live on
    #   2. `dmp bootstrap discover me@my-domain --auto-pin`
    # Inspecting a recipient's cluster is still possible without
    # --auto-pin (diagnostic mode) or via --via-bootstrap on
    # identity fetch.
    if not cfg.bootstrap_user_domain or _norm_dns_name(host) != _norm_dns_name(
        cfg.bootstrap_user_domain
    ):
        _die(
            1,
            f"--auto-pin refuses to rehome config onto {host!r}: it is "
            f"not the bootstrap_user_domain pinned in config "
            f"({cfg.bootstrap_user_domain!r}). Pin your own home domain "
            f"first with `dmp bootstrap pin {host} <signer_spk_hex>`, "
            f"then re-run --auto-pin. For one-off discovery of a "
            f"recipient's cluster, omit --auto-pin (diagnostic mode) "
            f"or use `dmp identity fetch alice@host --via-bootstrap`.",
        )

    # Verify the cluster manifest at the returned anchor BEFORE writing
    # any config. Two-hop trust chain:
    # 1. bootstrap record verified against pinned bootstrap_signer_spk
    #    (above, via fetch_bootstrap_record).
    # 2. cluster manifest verified against the entry's operator_spk
    #    (below, via fetch_cluster_manifest).
    # Only after BOTH succeed do we persist. A half-written config
    # (bootstrap pinned but no cluster) is worse than none at all —
    # `dmp send` would wedge on cluster-mode enabled with no manifest.
    #
    # Walk entries in priority order. Accept only an entry whose
    # cluster manifest verifies AND whose per-node factories can
    # actually build writer/reader instances — dry-run matches the
    # "all-or-nothing" contract. Shared helper keeps this consistent
    # with --via-bootstrap and manual discover output.
    manifest, chosen = _pick_usable_bootstrap_entry(record, cfg, bootstrap_reader)
    if manifest is None or chosen is None:
        _die(
            2,
            f"no usable cluster manifest in the bootstrap record for {host} "
            f"(tried {len(record.entries)} in priority order). "
            "Either no preferred cluster is published yet, a signer key "
            "rotation is mid-flight, all entries are expired, or every "
            "reachable manifest carries endpoints the local factories "
            "can't build. No config written.",
        )

    # Both records verified: commit both to config atomically.
    # Pin the bootstrap anchor on the caller's behalf so future
    # discover/fetch calls don't need --signer-spk. Pin the cluster
    # anchors and set cluster_enabled=True so the next `dmp send` /
    # `dmp recv` routes through the federation path.
    #
    # Clear cluster_node_token AND http_token: both were scoped to the
    # previous operator. _build_cluster_writer_factory falls back from
    # cluster_node_token to http_token, so clearing only the former
    # would still send the legacy token to the newly discovered cluster
    # — a cross-trust-domain credential leak. The operator can
    # repopulate either via `dmp config set` or by editing the config
    # file if the new cluster requires auth.
    cfg.bootstrap_user_domain = host.rstrip(".")
    cfg.bootstrap_signer_spk = signer_hex.lower()
    cfg.cluster_base_domain = chosen.cluster_base_domain
    cfg.cluster_operator_spk = chosen.operator_spk.hex()
    cfg.cluster_node_token = ""
    cfg.http_token = None
    cfg.cluster_enabled = True
    cfg.save(path)

    print(f"address:     {user}@{host}")
    print(f"user_domain: {host}  (seq={record.seq})")
    print(
        f"cluster:     {manifest.cluster_name}  "
        f"(seq={manifest.seq}, nodes={len(manifest.nodes)})"
    )
    print()
    print("wrote config:")
    print(f"  bootstrap_user_domain = {cfg.bootstrap_user_domain}")
    print(f"  bootstrap_signer_spk  = {cfg.bootstrap_signer_spk}")
    print(f"  cluster_base_domain   = {cfg.cluster_base_domain}")
    print(f"  cluster_operator_spk  = {cfg.cluster_operator_spk}")
    print(f"  cluster_enabled       = True")
    return 0


def cmd_node(args: argparse.Namespace) -> int:
    """Convenience: launch a dmp-node in the foreground."""
    from dmp.server.node import DMPNode, DMPNodeConfig

    overrides = {}
    if args.db_path:
        overrides["db_path"] = args.db_path
    if args.dns_port:
        overrides["dns_port"] = args.dns_port
    if args.http_port:
        overrides["http_port"] = args.http_port
    config = DMPNodeConfig(**{**asdict(DMPNodeConfig.from_env()), **overrides})
    node = DMPNode(config)
    node.start()
    node.wait()
    return 0


# ----------------------------- argparse wiring -------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dmp", description="DNS Mesh Protocol CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    # init
    p_init = sub.add_parser("init", help="create a fresh config")
    p_init.add_argument("username")
    p_init.add_argument("--domain", default="mesh.local")
    p_init.add_argument("--endpoint", help="HTTP API endpoint of your node")
    p_init.add_argument("--http-token", help="optional bearer token for the HTTP API")
    p_init.add_argument("--dns-host", help="DNS resolver host (default: system)")
    p_init.add_argument("--dns-port", type=int, default=5353)
    p_init.add_argument(
        "--dns-resolvers",
        default="",
        help="Comma-separated list of resolver IP literals with optional "
        "ports, e.g. `8.8.8.8,1.1.1.1` or `8.8.8.8:53,[2001:4860:4860::8888]:53`. "
        "When set, the CLI builds a ResolverPool with automatic failover; "
        "--dns-host / --dns-port are ignored. Hostnames are rejected.",
    )
    p_init.add_argument(
        "--identity-domain",
        default="",
        help="DNS zone you control (e.g. alice.example.com). Identity records "
        "go to dmp.<zone>; senders resolve you via <user>@<zone>. "
        "Real squat resistance comes from controlling this zone.",
    )
    p_init.add_argument(
        "--force", action="store_true", help="overwrite existing config"
    )
    p_init.set_defaults(func=cmd_init)

    # identity
    p_id = sub.add_parser("identity", help="identity commands")
    sub_id = p_id.add_subparsers(dest="sub", required=True)
    p_id_show = sub_id.add_parser("show", help="print identity keys")
    p_id_show.add_argument("--json", action="store_true")
    p_id_show.set_defaults(func=cmd_identity_show)

    p_id_pub = sub_id.add_parser(
        "publish", help="publish a signed identity record to DNS"
    )
    p_id_pub.add_argument(
        "--ttl",
        type=int,
        default=86400,
        help="TXT record TTL in seconds (default: 86400 = 1 day)",
    )
    p_id_pub.set_defaults(func=cmd_identity_publish)

    p_id_pk = sub_id.add_parser(
        "refresh-prekeys",
        help="generate and publish a fresh pool of one-time X3DH prekeys",
    )
    p_id_pk.add_argument(
        "--count",
        type=int,
        default=25,
        help="number of prekeys to generate (default 25 — stays under a "
        "default node HTTP burst so the full pool publishes in one shot)",
    )
    p_id_pk.add_argument(
        "--ttl",
        type=int,
        default=86400,
        help="per-prekey TTL in seconds (default: 86400 = 1 day)",
    )
    p_id_pk.set_defaults(func=cmd_identity_refresh_prekeys)

    p_id_rotate = sub_id.add_parser(
        "rotate",
        help="EXPERIMENTAL (M5.4): rotate to a new identity key. "
        "Co-signs a RotationRecord and publishes it + a fresh IdentityRecord "
        "for the new key. Wire format subject to revision after the crypto audit.",
    )
    p_id_rotate.add_argument(
        "--new-passphrase-file",
        dest="new_passphrase_file",
        default=None,
        help="path to a file containing the new passphrase. Alternative: "
        "DMP_NEW_PASSPHRASE env var, or interactive prompt.",
    )
    p_id_rotate.add_argument(
        "--ttl",
        type=int,
        default=86400,
        help="TTL seconds for the published TXT records (default 86400)",
    )
    p_id_rotate.add_argument(
        "--exp-seconds",
        dest="exp_seconds",
        type=int,
        default=86400 * 365,
        help="seconds until the RotationRecord's exp field (default 1 year)",
    )
    p_id_rotate.add_argument(
        "--yes",
        action="store_true",
        help="skip the interactive confirmation prompt",
    )
    p_id_rotate.add_argument(
        "--reason",
        choices=("routine", "compromise"),
        default="routine",
        help="reason_code for the RevocationRecord of the OLD key. "
        "'routine' (default) marks a normal key rollover; 'compromise' "
        "flags the old key as assumed-leaked so chain-walkers abort trust "
        "immediately instead of merely following the chain forward.",
    )
    p_id_rotate.add_argument(
        "--experimental",
        action="store_true",
        help="required — acknowledges the feature is experimental and "
        "subject to revision after the external crypto audit.",
    )
    p_id_rotate.set_defaults(func=cmd_identity_rotate)

    p_id_fetch = sub_id.add_parser(
        "fetch", help="resolve someone's identity record from DNS"
    )
    p_id_fetch.add_argument("username")
    p_id_fetch.add_argument(
        "--domain",
        help="override the mesh domain (defaults to our own)",
    )
    p_id_fetch.add_argument(
        "--add",
        action="store_true",
        help="save the resolved identity as a local contact",
    )
    p_id_fetch.add_argument(
        "--accept-fingerprint",
        dest="accept_fingerprint",
        default=None,
        help="when multiple identity records exist at this name, require "
        "this 16-hex fingerprint to disambiguate (verify out-of-band first)",
    )
    p_id_fetch.add_argument("--json", action="store_true")
    p_id_fetch.add_argument(
        "--via-bootstrap",
        dest="via_bootstrap",
        action="store_true",
        help="discover the cluster serving the address's right-hand host "
        "via the pinned bootstrap signer, then route the lookup through "
        "a one-shot ClusterClient. Requires `dmp bootstrap pin <host> "
        "<signer_spk_hex>` first. No config is written.",
    )
    p_id_fetch.set_defaults(func=cmd_identity_fetch)

    # contacts
    p_c = sub.add_parser("contacts", help="manage contacts")
    sub_c = p_c.add_subparsers(dest="sub", required=True)
    p_c_add = sub_c.add_parser("add", help="add a contact")
    p_c_add.add_argument("name")
    p_c_add.add_argument("pubkey", help="recipient's X25519 pubkey (64 hex chars)")
    p_c_add.add_argument(
        "--signing-key",
        default="",
        help="recipient's Ed25519 signing pubkey (64 hex) — pins identity; "
        "without this, incoming manifests from this contact fall back "
        "to TOFU",
    )
    p_c_add.set_defaults(func=cmd_contacts_add)
    p_c_list = sub_c.add_parser("list", help="list contacts")
    p_c_list.set_defaults(func=cmd_contacts_list)

    # send
    p_s = sub.add_parser("send", help="send a message to a contact")
    p_s.add_argument("recipient")
    p_s.add_argument("message")
    p_s.set_defaults(func=cmd_send)

    # recv
    p_r = sub.add_parser("recv", help="poll for new messages")
    p_r.set_defaults(func=cmd_recv)

    # resolvers (discover / list public upstream DNS resolvers)
    p_rv = sub.add_parser("resolvers", help="manage upstream DNS resolvers")
    sub_rv = p_rv.add_subparsers(dest="sub", required=True)
    p_rv_discover = sub_rv.add_parser(
        "discover",
        help="probe well-known public resolvers and print the working set",
    )
    p_rv_discover.add_argument(
        "--save",
        action="store_true",
        help="persist the working resolvers to config as dns_resolvers",
    )
    p_rv_discover.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="per-resolver probe timeout in seconds (default: 2.0)",
    )
    p_rv_discover.set_defaults(func=cmd_resolvers_discover)
    p_rv_list = sub_rv.add_parser(
        "list", help="print the currently configured dns_resolvers"
    )
    p_rv_list.set_defaults(func=cmd_resolvers_list)

    # cluster (federation mode: fetch-verify manifest, build Fanout/Union)
    p_cl = sub.add_parser(
        "cluster",
        help="manage cluster-mode federation (M2.wire)",
    )
    sub_cl = p_cl.add_subparsers(dest="sub", required=True)
    p_cl_pin = sub_cl.add_parser(
        "pin",
        help="store operator Ed25519 pubkey + cluster base domain in config",
    )
    p_cl_pin.add_argument(
        "operator_spk",
        help="32-byte Ed25519 public key of the cluster operator, hex",
    )
    p_cl_pin.add_argument(
        "base_domain",
        help="cluster base domain (e.g. mesh.example.com); manifest RRset "
        "lives at cluster.<base_domain>",
    )
    p_cl_pin.set_defaults(func=cmd_cluster_pin)
    p_cl_fetch = sub_cl.add_parser(
        "fetch",
        help="one-shot fetch + verify the cluster manifest; print summary",
    )
    p_cl_fetch.add_argument(
        "--save",
        action="store_true",
        help="cache the signed manifest wire to `cluster_manifest.wire` "
        "in the config dir for future offline bootstrap",
    )
    p_cl_fetch.set_defaults(func=cmd_cluster_fetch)
    p_cl_status = sub_cl.add_parser(
        "status",
        help="build the cluster client and print fanout/union health",
    )
    p_cl_status.set_defaults(func=cmd_cluster_status)
    p_cl_enable = sub_cl.add_parser(
        "enable",
        help="activate cluster mode after a successful manifest fetch "
        "(flips cluster_enabled=True)",
    )
    p_cl_enable.set_defaults(func=cmd_cluster_enable)
    p_cl_disable = sub_cl.add_parser(
        "disable",
        help="deactivate cluster mode without clearing the pinned anchors "
        "(flips cluster_enabled=False)",
    )
    p_cl_disable.set_defaults(func=cmd_cluster_disable)

    # bootstrap (M3.2-wire: user-domain → cluster discovery)
    p_bs = sub.add_parser(
        "bootstrap",
        help="manage bootstrap-discovery trust anchors (M3.2-wire)",
    )
    sub_bs = p_bs.add_subparsers(dest="sub", required=True)
    p_bs_pin = sub_bs.add_parser(
        "pin",
        help="store the zone operator's Ed25519 pubkey + user_domain in config",
    )
    p_bs_pin.add_argument(
        "user_domain",
        help="user domain to pin a trust anchor for (e.g. example.com)",
    )
    p_bs_pin.add_argument(
        "signer_spk_hex",
        help="32-byte Ed25519 public key of the zone operator, hex-encoded",
    )
    p_bs_pin.set_defaults(func=cmd_bootstrap_pin)
    p_bs_fetch = sub_bs.add_parser(
        "fetch",
        help="one-shot fetch + verify the bootstrap record; print summary",
    )
    p_bs_fetch.add_argument(
        "--user-domain",
        default=None,
        help="override pinned user_domain for this fetch",
    )
    p_bs_fetch.add_argument(
        "--signer-spk",
        default=None,
        help="override pinned signer_spk (hex) for this fetch",
    )
    p_bs_fetch.set_defaults(func=cmd_bootstrap_fetch)
    p_bs_discover = sub_bs.add_parser(
        "discover",
        help="resolve user@host → cluster anchors; with --auto-pin, commit",
    )
    p_bs_discover.add_argument(
        "address",
        help="external address in user@host form (e.g. alice@example.com)",
    )
    p_bs_discover.add_argument(
        "--signer-spk",
        default=None,
        help="bootstrap signer_spk (hex) for this host; required when the "
        "host has not been pinned via `dmp bootstrap pin`",
    )
    p_bs_discover.add_argument(
        "--auto-pin",
        action="store_true",
        help="after verifying the bootstrap record AND the cluster manifest "
        "at the returned anchor, write both to config and enable cluster "
        "mode. All-or-nothing: on any failure the config is left untouched.",
    )
    p_bs_discover.set_defaults(func=cmd_bootstrap_discover)

    # node (convenience launcher)
    p_n = sub.add_parser("node", help="run a dmp node in the foreground")
    p_n.add_argument("--db-path")
    p_n.add_argument("--dns-port", type=int)
    p_n.add_argument("--http-port", type=int)
    p_n.set_defaults(func=cmd_node)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
