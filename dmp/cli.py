"""`dnsmesh` command-line interface.

A thin wrapper around DMPClient for identity, contact, and message operations
against a DMP node. Pairs well with `python -m dmp.server` on the node side.

Config lives at $DMP_CONFIG_HOME/config.yaml (default: ~/.dmp/config.yaml).
Passphrases are never written to config — either set DMP_PASSPHRASE in the
environment or point `passphrase_file` at a file readable only by you.

    dnsmesh init alice --domain mesh.example.com --endpoint http://node:8053
    dnsmesh identity show
    dnsmesh contacts add bob 3f...a9
    dnsmesh contacts list
    dnsmesh send bob "hello bob"
    dnsmesh recv
    dnsmesh node        # convenience: launch a dnsmesh-node in the foreground

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
from typing import Dict, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlsplit

import yaml

from dmp.client.bootstrap_discovery import fetch_bootstrap_record
from dmp.client.client import Contact, DMPClient
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
    # for reads. Populated by `dnsmesh init --dns-resolvers` or
    # `dnsmesh resolvers discover --save`. Empty list preserves the legacy
    # single-host behavior.
    dns_resolvers: List[str] = field(default_factory=list)
    passphrase_file: Optional[str] = None  # alternative to DMP_PASSPHRASE
    # 32 random bytes generated at `dnsmesh init`, stored as hex. Combined with
    # the passphrase under Argon2id to derive the X25519 seed. Two users who
    # happen to share a passphrase still get independent identities; an
    # attacker who captures the public identity has to do a per-user
    # offline brute force rather than a single rainbow table.
    kdf_salt: str = ""
    # Optional DNS zone under which the user publishes / queries identity
    # records. When set, identity publish writes `dmp.<identity_domain>`
    # and `dnsmesh identity fetch <user>@<host>` resolves addresses in this
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
    # cluster path". Flipped True by `dnsmesh cluster enable` only after a
    # live manifest fetch succeeds; `dnsmesh cluster pin` leaves it False
    # so operators can `cluster fetch` to verify before cutting over.
    # Back-compat: older configs load as False even when both anchors
    # are pinned — upgrading requires a one-time `dnsmesh cluster enable`.
    cluster_enabled: bool = False
    # Bootstrap-discovery anchors (M3.2-wire). When pinned via
    # `dnsmesh bootstrap pin <user_domain> <signer_spk_hex>`, subsequent
    # `dnsmesh bootstrap fetch / discover` and `dnsmesh identity fetch
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
    # `dnsmesh identity fetch user@host --add`; it's consulted by the
    # rotation fallback so chain walks resolve against the remote zone
    # (not the operator's local effective domain). Legacy configs predating
    # this field leave it empty and fall back to the local effective
    # domain for all addressing (back-compat).
    contacts: Dict[str, Dict[str, str]] = field(default_factory=dict)
    # Canonical Ed25519 signing pubkey (hex) established on first
    # successful key derivation. Used as a typo-tripwire only: every
    # subsequent passphrase derive compares against this and aborts on
    # mismatch. NOT a secret — it's a public key by definition. Empty
    # on a fresh `dnsmesh init`; populated lazily on first
    # `_make_client` call. Updated by `dnsmesh identity rotate`.
    verify_pubkey: str = ""

    # M8.3 — claim-provider override. When non-empty, send/recv use
    # this single endpoint as the claim provider, skipping seen-feed
    # ranking. Use case: pin all first-contact reach through a known
    # node (e.g. dnsmesh.io). The zone is auto-derived from the URL
    # host unless `claim_provider_zone` is also set.
    claim_provider_override: str = ""
    claim_provider_zone: str = ""

    # M9.2.5 — TSIG block for the DNS UPDATE write path. When all four
    # required fields are populated, ``_make_client`` constructs a
    # ``_DnsUpdateWriter`` instead of ``_HttpWriter`` and every
    # subsequent publish goes over RFC 2136 UPDATE + RFC 8945 TSIG
    # to the user's home node's DNS port. Empty values fall back to
    # the legacy HTTP path so older configs upgrade transparently.
    # Populated by ``dnsmesh tsig register``.
    tsig_key_name: str = ""  # dnspython key name, with trailing dot
    tsig_secret_hex: str = ""  # raw secret bytes, hex-encoded
    tsig_algorithm: str = "hmac-sha256"
    tsig_zone: str = ""  # zone the key is authoritative for
    # DNS server + port to send the UPDATE to. Default 53; dev nodes
    # often use 5353. Empty server falls back to the host parsed out
    # of ``endpoint`` so single-host setups don't have to repeat it.
    tsig_dns_server: str = ""
    tsig_dns_port: int = 53

    @classmethod
    def load(cls, path: Path) -> "CLIConfig":
        if not path.exists():
            raise FileNotFoundError(
                f"no config at {path} — run `dnsmesh init <username>` first"
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
                # `remote_username` is the protocol-level identity name
                # used by prekey + rotation lookups. It comes from the
                # M8.3 `dnsmesh intro trust --username` flow; absent
                # falls back to the dict key (back-compat for legacy
                # contacts where username == local label).
                contacts[name] = {
                    "pub": value.get("pub", ""),
                    "spk": value.get("spk", ""),
                    "domain": value.get("domain", ""),
                    "remote_username": value.get("remote_username", ""),
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
            verify_pubkey=data.get("verify_pubkey", "") or "",
            identity_domain=data.get("identity_domain", ""),
            cluster_base_domain=data.get("cluster_base_domain", "") or "",
            cluster_operator_spk=data.get("cluster_operator_spk", "") or "",
            cluster_refresh_interval=int(data.get("cluster_refresh_interval", 3600)),
            cluster_node_token=data.get("cluster_node_token", "") or "",
            # Back-compat: an older config (pinned anchors, no
            # cluster_enabled key) must NOT silently enter cluster mode
            # on upgrade. Default to False; the operator must run
            # `dnsmesh cluster enable` once to cut over.
            cluster_enabled=bool(data.get("cluster_enabled", False)),
            # Bootstrap-discovery anchors (M3.2-wire). Load as empty on
            # pre-M3.2 configs; no auto-activation. Persisted alongside
            # the cluster_* block for consistency.
            bootstrap_user_domain=data.get("bootstrap_user_domain", "") or "",
            bootstrap_signer_spk=data.get("bootstrap_signer_spk", "") or "",
            contacts=contacts,
            claim_provider_override=data.get("claim_provider_override", "") or "",
            claim_provider_zone=data.get("claim_provider_zone", "") or "",
            tsig_key_name=data.get("tsig_key_name", "") or "",
            tsig_secret_hex=data.get("tsig_secret_hex", "") or "",
            tsig_algorithm=data.get("tsig_algorithm", "hmac-sha256") or "hmac-sha256",
            tsig_zone=data.get("tsig_zone", "") or "",
            tsig_dns_server=data.get("tsig_dns_server", "") or "",
            tsig_dns_port=int(data.get("tsig_dns_port", 53)),
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


def _normalize_endpoint(endpoint: str) -> str:
    """Return ``endpoint`` with a scheme prefix and no trailing slash.

    The CLI accepts bare hostnames (e.g. ``dnsmesh.io``) for ergonomic
    parity with the website's recommended example — prepend ``https://``
    when there's no scheme so downstream code (``requests.post(url +
    "/v1/...")``) doesn't choke. Existing fully-qualified URLs pass
    through untouched, including ``http://`` for local-dev addresses
    like ``http://127.0.0.1:8053``.

    Heuristic: a leading ``<word>://`` is treated as a scheme; anything
    else is bare. We do NOT normalize the host case or strip ports —
    that's the resolver's / requests' responsibility.
    """
    if not endpoint:
        return ""
    s = endpoint.strip().rstrip("/")
    if "://" not in s:
        s = f"https://{s}"
    return s


class _HttpWriter(DNSRecordWriter):
    """Publishes records via the node's HTTP API.

    M5.5 auto-attach: if ``token`` is None, fall back to a saved
    per-node bearer at ``~/.dmp/tokens/<host>.json`` (written by
    ``dnsmesh register``). An explicit ``token`` wins — operators who
    hand out a shared ``DMP_OPERATOR_TOKEN`` keep using that path.
    """

    def __init__(self, endpoint: str, token: Optional[str] = None):
        import requests
        from dmp.client.node_tokens import bearer_for_endpoint

        self._requests = requests
        # Normalize bare hostnames to https:// so old configs and
        # users who pass `--endpoint dnsmesh.io` (without scheme)
        # both work. cmd_init also normalizes at save time.
        self._endpoint = _normalize_endpoint(endpoint)
        if not token:
            token = bearer_for_endpoint(self._endpoint)
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}
        # Diagnostics from the most recent call. The DNSRecordWriter
        # interface returns bool, which collapsed every failure mode
        # (auth scope, rate limit, backend down) into the same opaque
        # "publish failed" message. Stashing status + parsed error here
        # lets cmd_identity_publish surface the actual reason without
        # changing the abstract interface used by other backends.
        self.last_status: Optional[int] = None
        self.last_error: Optional[str] = None

    def _capture(self, r) -> None:
        self.last_status = r.status_code
        try:
            body = r.json()
            self.last_error = (
                body.get("error") if isinstance(body, dict) else None
            ) or r.text[:200]
        except ValueError:
            self.last_error = r.text[:200] if r.text else None

    def publish_txt_record(self, name: str, value: str, ttl: int = 300) -> bool:
        r = self._requests.post(
            f"{self._endpoint}/v1/records/{name}",
            json={"value": value, "ttl": ttl},
            headers=self._headers,
            timeout=10,
        )
        self._capture(r)
        return r.status_code == 201

    def delete_txt_record(self, name: str, value: Optional[str] = None) -> bool:
        payload = {"value": value} if value else None
        r = self._requests.delete(
            f"{self._endpoint}/v1/records/{name}",
            json=payload,
            headers=self._headers,
            timeout=10,
        )
        self._capture(r)
        return r.status_code == 204


def _publish_failure_msg(writer: "_HttpWriter", name: str) -> str:
    """Build a one-line failure message that surfaces the actual HTTP
    status + server-side reason instead of "see node logs"."""
    status = writer.last_status
    err = writer.last_error or ""
    base = f"publish to {name} failed"
    if status is None:
        return f"{base} — no response captured"
    msg = f"{base}: HTTP {status}"
    if err:
        msg = f"{msg} — {err}"
    if status == 403:
        msg += (
            " (per-user token may not own this record namespace; "
            "if you are the operator, retry with DMP_HTTP_TOKEN=<operator-token>)"
        )
    return msg


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


def _build_writer(config: "CLIConfig") -> DNSRecordWriter:
    """Pick the right writer for ``config``.

    M9.2.5: when the TSIG block in ``config`` is populated, every
    publish goes over RFC 2136 UPDATE + RFC 8945 TSIG to the user's
    home node's DNS port. Empty TSIG fields fall back to the legacy
    HTTP path, so an existing config without ``dnsmesh tsig register``
    keeps working.

    The DNS server defaults to the host parsed out of ``config.endpoint``
    so a single-host setup doesn't have to repeat itself; an explicit
    ``tsig_dns_server`` overrides that.
    """
    if config.tsig_key_name and config.tsig_secret_hex:
        from dmp.network.dns_update_writer import _DnsUpdateWriter

        try:
            secret = bytes.fromhex(config.tsig_secret_hex)
        except ValueError:
            _die(1, "tsig_secret_hex in config is not valid hex")
        zone = (config.tsig_zone or "").strip()
        if not zone:
            _die(
                1,
                "tsig_zone in config is empty — re-run `dnsmesh tsig register` "
                "to repopulate the TSIG block",
            )
        server = (config.tsig_dns_server or "").strip()
        if not server:
            server = _zone_from_endpoint_url(config.endpoint or "")
        if not server:
            _die(
                1,
                "could not resolve a DNS server for the TSIG writer — set "
                "`tsig_dns_server` in config or pass --endpoint with a hostname",
            )
        return _DnsUpdateWriter(
            zone=zone,
            server=server,
            tsig_key_name=config.tsig_key_name,
            tsig_secret=secret,
            tsig_algorithm=config.tsig_algorithm or "hmac-sha256",
            port=int(config.tsig_dns_port) or 53,
        )
    return _HttpWriter(config.endpoint, config.http_token)


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
    `dnsmesh cluster fetch` before cutting over with `dnsmesh cluster enable`.
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

    `dnsmesh identity show` and similar commands only read the local identity
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
    need local state (e.g. `dnsmesh identity show`, which just prints
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
                "`dnsmesh cluster pin <hex> <base_domain>` to fix",
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
            # Cross-domain reads (e.g. `dnsmesh identity fetch
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
                # commands. Hand back placeholders so `dnsmesh identity show`
                # works on a bare config that never got an --endpoint.
                writer = _OfflineWriter()
                reader = _OfflineReader()
            else:
                _die(
                    1,
                    "no endpoint configured — run `dnsmesh init` with --endpoint, or edit "
                    f"{_config_path()}",
                )
        else:
            writer = _build_writer(config)
            reader = _make_reader(config)
    # Persist the replay cache next to the config so repeated `dnsmesh recv` calls
    # across separate CLI processes don't re-deliver the same message.
    replay_path = str(_config_path().parent / "replay_cache.json")
    # Prekey store sits in the same config dir; forward-secrecy property
    # depends on this file's permissions matching the passphrase file.
    prekey_path = str(_config_path().parent / "prekeys.db")
    # M8.3 — intro queue persistence. Pending first-contact intros must
    # survive across CLI invocations so `dnsmesh intro list` after a
    # `dnsmesh recv` shows what was just quarantined. Same dir as
    # the prekey store; same permission expectations.
    intro_queue_path = str(_config_path().parent / "intros.db")
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
        intro_queue_path=intro_queue_path,
    )
    # Attach the cluster handle (if any) so the CLI can close it at
    # exit. Setting an attribute on DMPClient after construction is
    # intentionally unintrusive — we do not modify DMPClient itself,
    # per the M2.wire hard-rules constraint.
    client._cluster_client = cluster_client  # type: ignore[attr-defined]

    # Passphrase-typo tripwire. The keypair is derived purely from
    # passphrase + kdf_salt, so any string produces some valid keypair
    # — there's no built-in "wrong passphrase" detection. We compare
    # the derived signing pubkey against the canonical we stored on
    # first derive. Mismatch is almost always a typo (or a config
    # someone copied without the matching passphrase).
    derived_spk_hex = client.crypto.get_signing_public_key_bytes().hex()
    if not config.verify_pubkey:
        # First derive on this config: write the derived pubkey as the
        # canonical. NOT a secret; it's published when identity is.
        config.verify_pubkey = derived_spk_hex
        try:
            config.save(_config_path())
        except OSError as e:
            # Don't take the command down if config is read-only;
            # subsequent runs just skip the tripwire.
            print(
                f"warning: could not persist verify_pubkey to config: {e}",
                file=sys.stderr,
            )
    elif config.verify_pubkey != derived_spk_hex:
        if os.environ.get("DMP_PASSPHRASE_OVERRIDE_VERIFY") == "1":
            print(
                "warning: passphrase derives a different identity than the "
                f"one saved in config ({derived_spk_hex} != "
                f"{config.verify_pubkey}); proceeding because "
                "DMP_PASSPHRASE_OVERRIDE_VERIFY=1.",
                file=sys.stderr,
            )
        else:
            _die(
                1,
                "passphrase mismatch: the derived signing pubkey does "
                "not match the one this config was first used with.\n"
                f"  expected: {config.verify_pubkey}\n"
                f"  derived:  {derived_spk_hex}\n\n"
                "Almost certainly a typo. Re-enter the passphrase that "
                "produced your published identity. If you genuinely "
                "intended a different identity, run `dnsmesh init "
                "--force` (loses the current identity) or set "
                "DMP_PASSPHRASE_OVERRIDE_VERIFY=1 to bypass once.",
            )
    # Contacts must use the same effective domain as the client itself
    # for mailbox-local addressing (slot/chunk RRsets); otherwise
    # send_message() builds prekey_rrset_name under the legacy domain
    # while refresh_prekeys publishes under the cluster base, silently
    # disabling forward secrecy on every send.
    #
    # For CROSS-ZONE contacts (pinned via `dnsmesh identity fetch
    # alice@other-zone.example --add`), we persist the remote host as
    # `entry.domain`. Using that here lets the rotation-chain walker
    # resolve against the remote zone's `rotate.dmp.<remote-host>`
    # RRset. Legacy contacts (no `domain` field) fall back to the
    # local effective domain — back-compat for pre-M5.4 configs.
    for name, entry in config.contacts.items():
        contact_domain = entry.get("domain", "") or effective_domain
        remote_username = entry.get("remote_username", "")
        ok = client.add_contact(
            name,
            entry.get("pub", ""),
            domain=contact_domain,
            signing_key_hex=entry.get("spk", ""),
        )
        if not ok or name not in client.contacts:
            continue
        # Codex P2 round 5 fix: a trusted-intro contact persisted
        # WITHOUT a known remote username (the user ran
        # `dnsmesh intro trust` without --username, and hasn't yet
        # run identity-fetch to fill it in) needs Contact.username
        # to remain empty so prekey + rotation-chain lookups skip
        # gracefully — querying _prekey.<intro-XXX>.<zone> would
        # always miss. add_contact defaults Contact.username to the
        # dict key (`name`); for these intro-trust placeholders we
        # explicitly OVERRIDE with the empty string.
        #
        # Detection: pub="" + spk!="" is the unambiguous marker for
        # the intro-trust origin. Once identity-fetch upgrades the
        # entry (pub gets filled in), this branch stops matching
        # and the remote_username (now set) takes precedence below.
        is_intro_placeholder = not entry.get("pub", "") and entry.get("spk", "")
        if is_intro_placeholder:
            existing = client.contacts[name]
            client.contacts[name] = Contact(
                username=remote_username,  # may be empty intentionally
                public_key_bytes=existing.public_key_bytes,
                signing_key_bytes=existing.signing_key_bytes,
                domain=existing.domain,
            )
        elif remote_username:
            # Normal contact with an explicit remote_username
            # override (set by `dnsmesh identity fetch --add` after
            # an intro-trust upgrade, OR by a future flow that
            # diverges local label from remote name). Honor it.
            existing = client.contacts[name]
            client.contacts[name] = Contact(
                username=remote_username,
                public_key_bytes=existing.public_key_bytes,
                signing_key_bytes=existing.signing_key_bytes,
                domain=existing.domain,
            )
    return client


# Built-in seed claim providers — shipped with the package so every
# client has a baseline for first-contact reach even before the local
# seen-graph populates. Codex P1 round 3 caught the bug where Alice's
# top-K and Bob's top-K can be disjoint when each computes from their
# own home node's /v1/nodes/seen; including these seeds in BOTH lists
# guarantees overlap until anti-entropy gossip on claim records
# (M8.4) converges the two views.
#
# The seeds are intentionally also entries in `directory/seeds.txt`
# so a user can drop a node from one and still have the other path.
# Operators who want a different default fleet override via
# `claim_provider_override` in their config.
_BUILTIN_CLAIM_PROVIDER_SEEDS: List[Tuple[str, str]] = [
    ("dnsmesh.io", "https://dnsmesh.io"),
]


def _zone_from_endpoint_url(url: str) -> str:
    """Best-effort URL-host → DNS-zone projection.

    Same idea as ``dmp.client.claim_routing._zone_from_endpoint`` but
    returns ``""`` on failure (callers want a string they can also
    pass to ``DNSRecordReader.query_txt_record``). IP literals and
    localhost variants come back empty — there's no plausible
    authoritative DNS zone to query.
    """
    if not isinstance(url, str) or not url:
        return ""
    try:
        parts = urlsplit(url if "://" in url else "https://" + url)
    except ValueError:
        return ""
    host = (parts.hostname or "").strip().lower()
    if not host:
        return ""
    if host.replace(".", "").isdigit() or ":" in host:
        return ""
    if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return ""
    return host


def _candidate_seen_zones(
    cfg: "CLIConfig", client: Optional[DMPClient] = None
) -> List[str]:
    """Return the ordered list of DNS zones to query for the seen-graph.

    M9.1.3 — replaces ``_candidate_seen_endpoints``. The CLI no
    longer talks to ``/v1/nodes/seen``; instead it queries
    ``_dnsmesh-seen.<zone>`` over the recursive DNS chain.

    Resolution order:

      1. ``cfg.cluster_base_domain`` — when cluster mode is pinned,
         the operator publishes the cluster's seen-graph under the
         cluster anchor zone. Most authoritative source.
      2. Cluster manifest node endpoints — each node's URL host is
         the zone that node publishes its own seen-graph under. Lets
         a recipient discover providers from any node in the cluster
         even when the cluster anchor is briefly unreachable.
      3. ``cfg.endpoint`` — legacy single-node hint, also used
         outside cluster mode.

    Empty list when nothing is configured; caller falls back to the
    built-in seeds.

    Codex round-8 P2: do NOT derive zones from cluster manifest node
    HTTP hostnames. In clustered deployments where each node's HTTP
    host sits BENEATH the served zone (``api.node.example.com`` /
    ``example.com``), the worker publishes the seen-graph at the
    served zone; querying ``_dnsmesh-seen.api.node.example.com``
    returns NXDOMAIN and discovery silently collapses to seeds. The
    cluster anchor (``cluster_base_domain``) is the right cluster-
    wide candidate, and ``cfg.endpoint`` covers the single-node case.
    """
    out: List[str] = []
    seen: Set[str] = set()

    def _push(zone: str) -> None:
        z = (zone or "").strip().lower()
        if not z or z in seen:
            return
        seen.add(z)
        out.append(z)

    if cfg.cluster_base_domain:
        _push(cfg.cluster_base_domain)
    _push(_zone_from_endpoint_url(cfg.endpoint))
    return out


def _fetch_seen_feed_dns(
    reader: DNSRecordReader, zones: Sequence[str]
) -> List[str]:
    """Query ``_dnsmesh-seen.<zone>`` for each zone, return first hit
    that yields at least one verifiable wire.

    Codex round-7 P2: stopping at the first non-empty RRset broke
    discovery whenever the cluster anchor's seen-graph contained
    only malformed / unverifiable wires — ``parse_seen_feed`` would
    drop everything and the caller never moved on to the next
    candidate zone. Now we re-verify here too and only return the
    first zone that actually produced a usable record.

    The returned list is the raw wire strings (multi-value TXT
    publishes one wire per value); the caller still re-verifies via
    ``parse_seen_feed``. Re-verifying twice is cheap relative to the
    DNS round-trip we'd otherwise miss.
    """
    from dmp.client.claim_routing import parse_seen_feed
    from dmp.server.heartbeat_worker import seen_rrset_name

    for zone in zones:
        if not zone:
            continue
        try:
            name = seen_rrset_name(zone)
        except ValueError:
            continue
        try:
            values = reader.query_txt_record(name)
        except Exception:
            continue
        if not values:
            continue
        wires = [v for v in values if isinstance(v, str)]
        if not wires:
            continue
        # Quick verification pass — if every wire is bad, fall through
        # so a sibling zone still gets a chance to contribute.
        if not parse_seen_feed(wires):
            continue
        return wires
    return []


def _seed_provider_via_dns(
    reader: DNSRecordReader, seed_zone: str, seed_endpoint: str
) -> Optional[Tuple[str, str]]:
    """Query a built-in seed's heartbeat over DNS.

    Returns ``(zone, endpoint)`` from the verified wire when present
    and the seed advertises ``CAP_CLAIM_PROVIDER``. Returns ``None``
    when the seed has no record OR has explicitly opted out of the
    claim-provider role; the caller drops the seed.

    Codex round-7 P2: ``DNSRecordReader.query_txt_record`` collapses
    NXDOMAIN, NoAnswer, and any transient transport error to ``None``,
    so we cannot distinguish "operator stopped publishing" from "my
    resolver timed out" at this layer. To avoid splitting sender and
    recipient onto disjoint provider sets after a single transient
    DNS hiccup, ``None`` and exceptions BOTH fall back to the static
    seed tuple. An explicit opted-out signal still drops the seed —
    that's the path where a verified wire arrives without
    CAP_CLAIM_PROVIDER set, which IS unambiguous operator intent.
    """
    from dmp.core.heartbeat import CAP_CLAIM_PROVIDER, HeartbeatRecord
    from dmp.server.heartbeat_worker import heartbeat_rrset_name

    try:
        name = heartbeat_rrset_name(seed_zone)
    except ValueError:
        return (seed_zone, seed_endpoint)
    try:
        values = reader.query_txt_record(name)
    except Exception:
        return (seed_zone, seed_endpoint)
    if not values:
        # Could be NXDOMAIN, NoAnswer, or a transient resolver miss.
        # Static fallback preserves baseline reach.
        return (seed_zone, seed_endpoint)
    saw_verified_optout = False
    for wire in values:
        if not isinstance(wire, str):
            continue
        rec = HeartbeatRecord.parse_and_verify(wire)
        if rec is None:
            continue
        if not (rec.capabilities & CAP_CLAIM_PROVIDER):
            # Verified wire WITHOUT the cap bit = operator advertised
            # they aren't a claim provider anymore. Drop the seed.
            saw_verified_optout = True
            continue
        zone = (rec.claim_provider_zone or "").strip().lower() or seed_zone
        return (zone, rec.endpoint or seed_endpoint)
    if saw_verified_optout:
        return None
    # Records existed but none verified — likely a malformed RRset.
    # Static fallback so a single bad publisher doesn't disable the
    # baseline.
    return (seed_zone, seed_endpoint)


def _build_claim_providers(
    cfg: "CLIConfig", client: Optional[DMPClient] = None
) -> List[Tuple[str, str]]:
    """Build the ranked claim-provider list for send/recv (M8.3, M9.1.3).

    Resolution order:

      1. ``cfg.claim_provider_override`` — explicit pin. Returned as
         a single ``(zone, endpoint)`` tuple; ``zone`` defaults to
         the URL host unless ``cfg.claim_provider_zone`` is also set.
      2. Query the home node's seen-graph at
         ``_dnsmesh-seen.<home-zone>`` over the recursive DNS chain.
         The wires are signed HeartbeatRecords — :mod:`parse_seen_feed`
         verifies each signature, :mod:`select_providers` ranks by
         recency and reads the operator-advertised
         ``claim_provider_zone`` straight off each wire (M9.1.1
         absorbed the old ``GET /v1/info`` zone discovery).
      3. Always APPEND the built-in seeds. Each seed's heartbeat is
         re-checked over DNS; an opted-out seed is dropped, an
         opted-in seed contributes its operator-advertised zone.
      4. On any exception in steps 2-3, return whatever was built so
         far + any seeds that resolved. Send/recv handle the empty
         case by skipping claim publish/poll — first-contact reach
         degrades gracefully to "pinned-only" mode.

    The whole flow is now DNS-only — no HTTP between the CLI and any
    peer node beyond the user's own home node (which the user already
    talks HTTP to for register/send writes).

    Returns a list of ``(provider_zone, provider_endpoint)`` tuples
    suitable for passing into ``send_message(claim_providers=...)``
    or ``receive_messages(claim_providers=...)``.
    """
    from dmp.client.claim_routing import (
        DEFAULT_K,
        parse_seen_feed,
        select_providers,
    )

    if cfg.claim_provider_override:
        out = select_providers(
            [],
            override=cfg.claim_provider_override,
            override_zone=cfg.claim_provider_zone or None,
        )
        return [(p.zone, p.endpoint) for p in out]

    out: List[Tuple[str, str]] = []
    seen_endpoints: Set[str] = set()

    def _add(zone: str, endpoint: str) -> None:
        if not zone or not endpoint:
            return
        canon = endpoint.rstrip("/").lower()
        if canon in seen_endpoints:
            return
        seen_endpoints.add(canon)
        out.append((zone, endpoint))

    reader = _make_reader(cfg)
    candidate_zones = _candidate_seen_zones(cfg, client=client)
    seen_wires = _fetch_seen_feed_dns(reader, candidate_zones)
    if seen_wires:
        heartbeats = parse_seen_feed(seen_wires)
        for p in select_providers(heartbeats, k=DEFAULT_K):
            if not p.zone or not p.endpoint:
                continue
            _add(p.zone, p.endpoint)

    for seed_zone, seed_endpoint in _BUILTIN_CLAIM_PROVIDER_SEEDS:
        resolved = _seed_provider_via_dns(reader, seed_zone, seed_endpoint)
        if resolved is None:
            continue
        _add(resolved[0], resolved[1])
    return out


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
    print(f"dnsmesh: {msg}", file=sys.stderr)
    sys.exit(code)


def cmd_init(args: argparse.Namespace) -> int:
    path = _config_path()
    if path.exists() and not args.force:
        _die(1, f"config already exists at {path} (use --force to overwrite)")

    # Operator-friendly: accept `dnsmesh init alice@dnsmesh.pro` and
    # split into username + domain. Without this, the @-form lands in
    # the username field verbatim and the user has to remember to
    # also pass `--domain dnsmesh.pro` (real bug from a dnsmesh.pro
    # install where the operator typed `dnsmesh init alice@dnsmesh.pro`
    # and ended up with username="alice@dnsmesh.pro" + the default
    # mesh.local domain).  An explicit `--domain` still wins so
    # operators can override.
    if "@" in args.username:
        try:
            user_part, host_part = args.username.split("@", 1)
        except ValueError:
            _die(1, f"could not parse {args.username!r} as user@host")
        if not user_part or not host_part:
            _die(1, f"both user and host must be non-empty in {args.username!r}")
        args.username = user_part
        # Only auto-fill --domain when the caller didn't pass one
        # AND the parser default was still in place. The --domain
        # default is "mesh.local"; treat that as "unset by user".
        if not args.domain or args.domain == "mesh.local":
            args.domain = host_part

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
    elif not args.no_default_resolvers:
        # Default to a small pool of well-known public resolvers so a
        # fresh install can fetch records the moment delegation lands,
        # without depending on whatever the system resolver happens to
        # have cached (or NXDOMAIN'd before the delegation existed).
        # Cloudflare first because their stated privacy posture is
        # tighter than Google's; Google second for failover.
        # Operators who care about routing every DMP query through
        # their own resolver can pass --no-default-resolvers at init,
        # or edit the field in config.yaml afterward.
        dns_resolvers = ["1.1.1.1", "8.8.8.8"]

    cfg = CLIConfig(
        username=args.username,
        domain=args.domain,
        # Normalize bare hostnames (e.g. `dnsmesh.io`) into full URLs
        # so the website example `dnsmesh init alice --endpoint
        # dnsmesh.io` works without users having to remember the
        # scheme. http://127.0.0.1:8053 + https://dmp.example.com
        # pass through untouched.
        endpoint=_normalize_endpoint(args.endpoint or ""),
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
        "Next: set DMP_PASSPHRASE or create a passphrase file, then `dnsmesh identity show`."
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
            resolve_hint = (
                f"dnsmesh identity fetch {cfg.username}@{cfg.identity_domain}"
            )
        else:
            name = identity_domain(cfg.username, _effective_domain(cfg))
            resolve_hint = f"dnsmesh identity fetch {cfg.username}"

        ok = client.writer.publish_txt_record(name, wire, ttl=args.ttl)
        if not ok:
            _die(2, _publish_failure_msg(client.writer, name))
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
            hint = ""
            if isinstance(client.writer, _HttpWriter) and client.writer.last_status:
                hint = f" — last response: {_publish_failure_msg(client.writer, name)}"
            print(
                f"  (note: some publishes were rejected — check node rate limits and caps){hint}"
            )
        return 0
    finally:
        _close_client(client)


def cmd_identity_rotate(args: argparse.Namespace) -> int:
    """EXPERIMENTAL (M5.4): rotate the user identity key.

    Publishes a co-signed RotationRecord at the user's rotation RRset
    plus a fresh IdentityRecord for the new key at the user's identity
    RRset.

    With ``--reason compromise`` or ``--reason lost_key`` (opt-in; NOT
    the default ``routine``), the command ALSO publishes a self-signed
    RevocationRecord for the OLD key at the rotation RRset. A
    revocation tells rotation-aware fetchers to refuse the old key
    forever. Routine rotations deliberately skip the revocation: the
    chain walker aborts trust if any key on the walked path is revoked,
    so publishing a revocation on every rotation would break the
    headline auto-follow workflow.

    Clients that can't walk a chain (older versions, or legacy flows)
    disambiguate the identity RRset via the RotationRecord ``old_spk``
    list: any IdentityRecord whose ed25519_spk appears as an ``old_spk``
    is treated as superseded.

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
        REASON_LOST_KEY,
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

    # Seq numbering: millisecond-resolution unix time. Chosen so two
    # rotations fired back-to-back within the same second (a test
    # re-rotate, a scripted disaster recovery cutover) still produce
    # strictly-monotonic seq values — the chain walker rejects
    # same-seq hops (seq must STRICTLY increase), so second-resolution
    # would leave the second rotation invisible until contacts re-pin
    # manually. Uses uint64; ms epoch won't overflow until ~year 292M.
    # Documented as ms in docs/protocol/rotation.md alongside ts (which
    # stays at second resolution — seq is NOT a wall-clock timestamp,
    # it's a monotonic ordering number that happens to be clock-derived).
    now_ms = int(time.time() * 1000)
    seq = now_ms
    ts = int(time.time())

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

    # Revocation policy depends on --reason.
    #
    # compromise / lost_key: publish a RevocationRecord for the old
    # key. Contacts using rotation-chain walking will ABORT trust on
    # the old key entirely (correct — it's no longer safe to follow
    # ANY chain starting from the compromised key; holders of the old
    # key must re-pin out-of-band). Non-rotation-aware contacts
    # running `dnsmesh identity fetch` will filter the old identity
    # record out of the mailbox-name RRset and see only the new one.
    #
    # routine: do NOT publish a revocation. A routine rotation is a
    # hygiene step, not a compromise; contacts should auto-follow
    # A→B via chain walk, which would be impossible if we published
    # a revocation of A (the walker aborts on any path-revocation).
    # For non-rotation-aware fetchers, the multi-record ambiguity
    # is resolved by `cmd_identity_fetch` which now prefers the
    # chain-head identity when a rotation exists — see finding-3
    # follow-up in docs/protocol/rotation.md.
    reason_str = (getattr(args, "reason", "routine") or "routine").lower()
    revocation_wire: Optional[str] = None
    if reason_str in ("compromise", "lost_key"):
        reason_code = (
            REASON_COMPROMISE if reason_str == "compromise" else REASON_LOST_KEY
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

        # Revocation publish is conditional on --reason. Routine rotations
        # deliberately skip it so contacts can auto-follow via chain walk.
        # See revocation-policy docstring above.
        if revocation_wire is not None:
            ok_rev = client.writer.publish_txt_record(
                rrset_name, revocation_wire, ttl=int(args.ttl)
            )
            if not ok_rev:
                print(
                    f"warning: RotationRecord published, but RevocationRecord "
                    f"of the old key FAILED to publish at {rrset_name} — "
                    f"non-rotation-aware `dnsmesh identity fetch` will see BOTH "
                    f"the old and new IdentityRecords and exit ambiguous. "
                    f"Re-publish the revocation manually.",
                    file=sys.stderr,
                )
            else:
                print(
                    f"published RevocationRecord (old key, "
                    f"reason={reason_str}) to {rrset_name}"
                )
        else:
            print(
                "reason=routine: skipping RevocationRecord so "
                "rotation_chain_enabled contacts can auto-follow the new key"
            )

        # Also publish a fresh IdentityRecord for the NEW key so that
        # non-rotation-aware contacts still see the new key pinned
        # correctly on a plain `dnsmesh identity fetch`.
        new_identity = make_record(new_crypto, cfg.username)
        ok = client.writer.publish_txt_record(
            identity_rrset, new_identity.sign(new_crypto), ttl=int(args.ttl)
        )
        if not ok:
            print(
                f"warning: RotationRecord published, but IdentityRecord "
                f"for the new key FAILED to publish at {identity_rrset} — "
                f"re-run `dnsmesh identity publish` after updating the local "
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
    env_passphrase_mismatch = False
    if args.yes:
        new_pp_file = args.new_passphrase_file
        if new_pp_file:
            # Subtle footgun: `_load_passphrase` prefers DMP_PASSPHRASE
            # over the file. If the operator rotated while the OLD
            # DMP_PASSPHRASE is still exported in their shell, every
            # subsequent `dmp *` command keeps deriving the OLD
            # identity — "atomic swap" would be a lie. Detect the
            # mismatch and refuse to claim success; a matching env var
            # (operator already rotated their shell) is silently fine.
            env_pp = os.environ.get("DMP_PASSPHRASE")
            if env_pp is not None:
                try:
                    new_pp_contents = Path(new_pp_file).expanduser().read_text().strip()
                except OSError as exc:
                    _die(
                        1,
                        f"--new-passphrase-file {new_pp_file!r} is not readable: {exc}",
                    )
                if env_pp != new_pp_contents:
                    env_passphrase_mismatch = True
            cfg.passphrase_file = str(Path(new_pp_file).expanduser())
            # Identity changed: refresh the typo-tripwire to the
            # post-rotation pubkey, otherwise every subsequent command
            # would die on the (now intentional) mismatch.
            cfg.verify_pubkey = new_spk_hex
            cfg.save(_config_path())
            swapped_locally = True
            print(
                f"local identity swapped atomically (config.yaml "
                f"passphrase_file -> {cfg.passphrase_file}; kdf_salt "
                f"preserved). Local pubkey: {new_spk_hex}"
            )
            if env_passphrase_mismatch:
                # Non-zero exit so the operator can't miss it in a script.
                # The rotation was published (publish succeeded above) and
                # the config file was rewritten — there's nothing to
                # unwind. The operator just needs to fix their shell.
                print(
                    "WARNING: DMP_PASSPHRASE is set in your environment "
                    "and does not match the contents of "
                    f"--new-passphrase-file ({new_pp_file}); "
                    "`_load_passphrase` prefers the env var over the "
                    "file, so subsequent `dmp` commands in this shell "
                    "will keep deriving the OLD identity. Run "
                    "`unset DMP_PASSPHRASE` or "
                    "`export DMP_PASSPHRASE=<new>` to finish the swap.",
                    file=sys.stderr,
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
        "`dnsmesh identity fetch <user>@<host> --add` against the new key."
    )
    if swapped_locally:
        print(
            "  3. The local identity has already been swapped atomically; "
            "`dnsmesh identity show` will report the new pubkey. `dnsmesh identity "
            "publish` will re-publish the new IdentityRecord under the "
            "rotated key."
        )
    else:
        print(
            "  3. Point your passphrase source at the new passphrase "
            "(edit `passphrase_file` in config.yaml, or set DMP_PASSPHRASE). "
            "Do NOT regenerate kdf_salt — the current salt + new passphrase "
            "derives the rotated keypair. Re-running `dnsmesh init --force` "
            "would break local adoption."
        )
    # Non-zero exit when the env-passphrase mismatch was detected so a
    # script can tell that the rotation published correctly BUT the
    # operator needs to fix their shell before the next invocation.
    # Rotation wire is already on the DNS; no rollback.
    if env_passphrase_mismatch:
        return 3
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
                f"run `dnsmesh bootstrap pin {host} <signer_spk_hex>` first",
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
        # Identity fetch is the cross-domain workflow — `dnsmesh identity
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
        # @-style address: try the squat-resistant zone-anchored
        # name first (dmp.<host>); if no record there, fall back to
        # the TOFU hash name (id-<hash16(user)>.<host>). The
        # publisher chose ONE of these layouts at init time —
        # without an out-of-band hint about which, the fetcher tries
        # both. Zone-anchored first because it's the more secure
        # shape; the operator of <host> can squat the TOFU name
        # under append semantics, but the zone-anchored name is
        # M5.5-token-scoped to a specific subject.
        candidate_names = [
            zone_anchored_identity_name(host),
            identity_domain(user, host),
        ]
    else:
        resolved_username = args.username
        candidate_names = [
            identity_domain(args.username, args.domain or _effective_domain(cfg)),
        ]

    # Keep cluster_handle OPEN across both the identity lookup AND the
    # subsequent rotation-RRset revocation filter. Closing after only
    # the first query runs the revocation check through a closed
    # UnionReader (which returns None), silently disabling the filter
    # in cluster mode. The broader try/finally closes after the full
    # revocation filter completes below.
    name = candidate_names[0]
    records = reader.query_txt_record(name)
    for fallback_name in candidate_names[1:]:
        if records:
            break
        name = fallback_name
        records = reader.query_txt_record(name)
    if not records:
        if cluster_handle is not None:
            cluster_handle.close()
        if len(candidate_names) > 1:
            _die(
                2,
                f"no identity record at {candidate_names[0]} "
                f"or {candidate_names[1]}",
            )
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
        if cluster_handle is not None:
            cluster_handle.close()
            cluster_handle = None
        _die(2, f"found TXT records at {name} but none verified as a DMP identity")

    # Rotation-aware filter (M5.4): fetch the same subject's rotate
    # RRset (if any), collect verifying RotationRecords + self-signed
    # RevocationRecords, and drop any IdentityRecord whose ed25519_spk
    # matches. This closes two "ambiguous after rotate" holes in one
    # pass:
    #
    #   1. Revocation filter — drops any IdentityRecord whose ed25519_spk
    #      appears as a revoked_spk in a RevocationRecord. Only fires
    #      for compromise/lost_key rotations (routine rotations do NOT
    #      publish revocations, see cmd_identity_rotate).
    #   2. Chain-head filter — drops any IdentityRecord whose ed25519_spk
    #      appears as old_spk in a verifying RotationRecord. This is
    #      the path routine rotations rely on: the old key still has
    #      a valid IdentityRecord and no revocation, but a co-signed
    #      rotation points from it to the new key, so non-rotation-aware
    #      fetches can still auto-disambiguate.
    #
    # A compromised key that re-publishes the old IdentityRecord is
    # still filtered because both the rotation and the revocation (if
    # any) sit alongside it; see docs/protocol/rotation.md "Revocation
    # model" for the trade-off.
    from dmp.core.rotation import (
        RECORD_PREFIX_REVOCATION,
        RECORD_PREFIX_ROTATION,
        RevocationRecord,
        RotationRecord,
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
    superseded_spks: set[bytes] = set()
    norm_fetch_subject = _normalize_subject(SUBJECT_TYPE_USER_IDENTITY, fetch_subject)
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
            if txt.startswith(RECORD_PREFIX_REVOCATION):
                rev = RevocationRecord.parse_and_verify(txt)
                if rev is None:
                    continue
                if rev.subject_type != SUBJECT_TYPE_USER_IDENTITY:
                    continue
                # Subject match is strict: the RRset name is the trust
                # anchor, but we still require the embedded subject to
                # match the fetched subject so a stray record from a
                # different publisher at the same name can't poison the
                # filter.
                if (
                    _normalize_subject(rev.subject_type, rev.subject)
                    != norm_fetch_subject
                ):
                    continue
                revoked_spks.add(bytes(rev.revoked_spk))
            elif txt.startswith(RECORD_PREFIX_ROTATION):
                rot = RotationRecord.parse_and_verify(txt)
                if rot is None:
                    continue
                if rot.subject_type != SUBJECT_TYPE_USER_IDENTITY:
                    continue
                if (
                    _normalize_subject(rot.subject_type, rot.subject)
                    != norm_fetch_subject
                ):
                    continue
                # old_spk has been rotated away from. Its IdentityRecord
                # at the mailbox name is superseded even without a
                # revocation. The rotation is co-signed by BOTH old and
                # new keys, so we trust the supersession.
                superseded_spks.add(bytes(rot.old_spk))

    if revoked_spks:
        filtered = [rec for rec in valid if bytes(rec.ed25519_spk) not in revoked_spks]
        # If filtering drops ALL candidates, don't silently explode:
        # surface the state so the caller can re-pin out-of-band.
        if not filtered:
            if cluster_handle is not None:
                cluster_handle.close()
                cluster_handle = None
            _die(
                2,
                f"all IdentityRecords at {name} are revoked by a matching "
                f"RevocationRecord at the rotate RRset — re-pin out-of-band.",
            )
        valid = filtered

    # Chain-head filter: after dropping revoked records, if we still
    # have more than one, drop any whose ed25519_spk is an old_spk in
    # the rotation set. The remaining record(s) are chain-head
    # candidates. Only collapse when exactly one candidate remains —
    # zero or >1 means something pathological (all records superseded
    # with no head published, or two concurrent rotations not yet
    # reconciled), and we fall through to the ambiguous-error branch
    # so the user can inspect out-of-band.
    if len(valid) > 1 and superseded_spks:
        chain_filtered = [
            rec for rec in valid if bytes(rec.ed25519_spk) not in superseded_spks
        ]
        if len(chain_filtered) == 1:
            valid = chain_filtered

    # Revocation + chain-head filters done — safe to close the one-shot
    # cluster client now. Any remaining work (fingerprint display,
    # contact save) only touches local state.
    if cluster_handle is not None:
        cluster_handle.close()
        cluster_handle = None

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

    # Build a display address that includes the host part the lookup
    # actually used. The IdentityRecord stores just the username, but
    # without the host part `alkamod` on dnsmesh.io is indistinguishable
    # from `alkamod` on some other node — operators need to see the full
    # address they fetched.
    if parsed_addr is not None:
        _user, _host = parsed_addr
        display_address = f"{identity.username}@{_host}"
    elif args.domain:
        display_address = f"{identity.username}@{args.domain}"
    else:
        display_address = f"{identity.username}@{_effective_domain(cfg)}"

    if args.json:
        print(
            json.dumps(
                {
                    "username": identity.username,
                    "address": display_address,
                    "public_key": identity.x25519_pk.hex(),
                    "signing_public_key": identity.ed25519_spk.hex(),
                    "ts": identity.ts,
                    "dns_name": name,
                },
                indent=2,
            )
        )
    else:
        print(f"address:            {display_address}")
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
        if parsed_addr is not None:
            remote_host = parsed_addr[1]
        elif args.domain:
            remote_host = args.domain
        else:
            remote_host = ""
        fetched_spk = identity.ed25519_spk.hex()

        # M8.3 codex P2 round 6 fix: search the WHOLE contact list
        # for a trusted-intro placeholder with matching spk + empty
        # pub, regardless of label. The default `dnsmesh intro trust`
        # without --username keys the placeholder under
        # `intro-<spk-prefix>`, so looking up only by
        # identity.username would miss the upgrade and create a
        # second contact (codex P2 round 4 + 6).
        upgrade_label = None
        for existing_label, entry_dict in cfg.contacts.items():
            if (
                not entry_dict.get("pub", "")
                and entry_dict.get("spk", "") == fetched_spk
            ):
                upgrade_label = existing_label
                break

        existing_at_username = cfg.contacts.get(contact_key)
        # Three branches:
        #   (A) a placeholder under any label has matching spk →
        #       upgrade THAT entry under its existing label.
        #   (B) a normal entry exists at `contact_key` → preserve
        #       the "already exists" no-op (legacy behavior;
        #       prevents identity-fetch from clobbering a manually
        #       added contact).
        #   (C) clean add — create a new entry under `contact_key`.
        if upgrade_label is not None:
            existing = cfg.contacts[upgrade_label]
            entry: Dict[str, str] = {
                "pub": identity.x25519_pk.hex(),
                "spk": fetched_spk,
                "domain": remote_host or existing.get("domain", ""),
                # Codex P2 round 7 fix: ALWAYS use the just-verified
                # identity.username, even when the placeholder
                # already had a remote_username. The placeholder's
                # value may be a user-typo'd `--username` from
                # `dnsmesh intro trust`, in which case prekey +
                # rotation lookups would keep querying the wrong
                # RRset. The fetch verifies the spk signature over
                # this username, so it's the authoritative source.
                "remote_username": identity.username,
            }
            cfg.contacts[upgrade_label] = entry
            cfg.save(_config_path())
            print(
                f"upgraded contact `{upgrade_label}` "
                f"(filled in X25519 pubkey for {identity.username})"
            )
        elif existing_at_username is not None:
            print(f"(contact `{contact_key}` already exists — not overwriting)")
        else:
            entry = {
                "pub": identity.x25519_pk.hex(),
                "spk": fetched_spk,
                "domain": remote_host,
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

    # `domain` empty here: `dnsmesh contacts add` takes no remote host, so
    # cross-zone rotation-chain resolution isn't available via this
    # path — the client falls back to the local effective domain.
    # Use `dnsmesh identity fetch user@host --add` to persist the remote
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
            f"  contact has a pinned signing key, `dnsmesh recv` runs in\n"
            f"  trust-on-first-use mode — any signature-valid manifest\n"
            f"  addressed to you will be delivered, including from senders\n"
            f"  you never added. Re-run with --signing-key <64-hex>, or\n"
            f"  bootstrap via `dnsmesh identity fetch <user> --add` which\n"
            f"  pins both keys.",
            file=sys.stderr,
        )
    return 0


def cmd_contacts_list(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    if not cfg.contacts:
        print(
            "(no contacts yet — `dnsmesh contacts add <name> <pubkey_hex>` or `dnsmesh identity fetch <user> --add`)"
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
            f"unknown contact `{args.recipient}` — add it first with `dnsmesh contacts add`",
        )
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        # M8.3 — build the claim-provider list once per CLI invocation.
        # Empty list (no providers configured / fetchable) means we
        # skip the claim publish; the message itself still goes out.
        # Pass `client` so cluster-mode deployments can route the
        # /v1/nodes/seen lookup through the cluster manifest's nodes
        # (codex P1 round 6) instead of a stale cfg.endpoint.
        claim_providers = _build_claim_providers(cfg, client=client)
        # Codex P2 round 5: collect each claim's success/failure so
        # we can warn the user when first-contact reach silently
        # breaks (every claim provider rejected or unreachable).
        claim_outcomes: List[bool] = []
        ok = client.send_message(
            args.recipient,
            args.message,
            claim_providers=claim_providers,
            claim_outcomes=claim_outcomes,
        )
        if not ok:
            _die(2, f"send failed (see node logs for details)")
        suffix = ""
        if claim_providers:
            ok_count = sum(1 for r in claim_outcomes if r)
            total = len(claim_outcomes)
            suffix = f" (+ {ok_count}/{total} claim publishes)"
        print(f"sent → {args.recipient}{suffix}")
        if claim_providers and not any(claim_outcomes):
            # Every provider rejected or was unreachable. The
            # message is still on our zone (cross-zone receivers
            # who have us pinned will get it), but un-pinned
            # recipients will never discover it.
            print(
                "  WARNING: no claim provider accepted the discovery "
                "pointer — first-contact reach is unavailable. "
                "Pin a known provider with `dnsmesh config set "
                "claim-provider <url>` or check provider "
                "reachability.",
                file=sys.stderr,
            )
        return 0
    finally:
        _close_client(client)


def cmd_intro_list(args: argparse.Namespace) -> int:
    """List pending first-contact intros awaiting review (M8.3).

    Codex P2 round 6 fix: intro management is purely local
    (sqlite + config); never touches DNS / cluster bootstrap. Pass
    ``requires_network=False`` so a user without network can still
    review their queue.
    """
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase, requires_network=False)
    try:
        intros = client.intro_queue.list_intros()
        if not intros:
            print("(no pending intros)")
            return 0
        now = int(time.time())
        for intro in intros:
            spk_hex = intro.sender_spk.hex()
            expires_in = intro.msg_exp - now
            status = "fresh" if expires_in > 0 else "EXPIRED"
            label = intro.sender_label or f"intro-{spk_hex[:12]}"
            print(f"#{intro.intro_id}  {label}  [{status}]")
            print(f"  sender_spk: {spk_hex}")
            print(f"  from zone:  {intro.sender_mailbox_domain}")
            print(f"  received:   {intro.received_at}")
            try:
                preview = intro.plaintext.decode("utf-8")
                if len(preview) > 120:
                    preview = preview[:120] + "…"
            except UnicodeDecodeError:
                preview = f"(binary, {len(intro.plaintext)} bytes)"
            print(f"  message:    {preview}")
            print()
        return 0
    finally:
        _close_client(client)


def cmd_intro_accept(args: argparse.Namespace) -> int:
    """Deliver one pending intro into the inbox; do NOT pin the sender.

    Local-only — no network needed (codex P2 round 6).
    """
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase, requires_network=False)
    try:
        msg = client.accept_intro(int(args.intro_id))
        if msg is None:
            _die(1, f"no pending intro with id {args.intro_id}")
        print(f"accepted intro #{args.intro_id}")
        try:
            print(f"  {msg.plaintext.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"  (binary, {len(msg.plaintext)} bytes)")
        print(
            "  (sender NOT pinned — `dnsmesh intro trust` if you want future "
            "messages from this key to bypass quarantine)"
        )
        return 0
    finally:
        _close_client(client)


def cmd_intro_trust(args: argparse.Namespace) -> int:
    """Deliver + pin the sender as a trusted contact.

    Local-only — no network needed (codex P2 round 6).
    """
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase, requires_network=False)
    try:
        intro = client.intro_queue.get_intro(int(args.intro_id))
        if intro is None:
            _die(1, f"no pending intro with id {args.intro_id}")
        remote_username = args.username or ""
        # Codex P2 round 3 fix: when the user passes --username, the
        # trusted contact's dict key defaults to that name so a
        # follow-up `dnsmesh identity fetch <username>@<zone> --add`
        # keys to the SAME entry and fills in pub. Without this
        # alignment, identity-fetch creates a second contact under
        # the username while the trust label stays spk-only forever.
        # Explicit --label still wins for users who want a custom
        # local nickname (they accept the trade-off).
        if args.label:
            label = args.label
        elif remote_username:
            label = remote_username
        else:
            label = f"intro-{intro.sender_spk.hex()[:12]}"

        # Codex P2 round 4 fix: refuse to clobber an existing
        # pinned contact. A first-contact intro for "alice@other.zone"
        # must NOT overwrite the user's existing "alice" contact at
        # a different zone (or with a different signing key) — that
        # would silently lose the pinned X25519 pubkey of the
        # legitimate alice and rebind future receives to the
        # impersonator. Same-spk + same-zone is the upgrade path
        # (legacy spk-only stub re-trusted from a fresh intro), so
        # we permit it. Codex P1 round 7 fix: when permitted, we
        # PRESERVE the existing pub/spk metadata rather than
        # overwriting with empty pub (which would silently downgrade
        # a sendable contact into a placeholder).
        existing = cfg.contacts.get(label)
        existing_pub = ""
        if existing is not None:
            existing_spk = existing.get("spk", "")
            existing_domain = existing.get("domain", "")
            existing_pub = existing.get("pub", "")
            new_spk = intro.sender_spk.hex()
            new_domain = intro.sender_mailbox_domain
            if existing_spk and existing_spk != new_spk:
                _die(
                    1,
                    f"contact `{label}` already pinned to a different "
                    f"signing key ({existing_spk[:16]}…); refusing to "
                    f"overwrite with {new_spk[:16]}…. Re-run with "
                    f"--label <a-different-name> to keep both.",
                )
            if existing_domain and existing_domain != new_domain:
                _die(
                    1,
                    f"contact `{label}` already pinned at zone "
                    f"`{existing_domain}`; this intro is from `{new_domain}`. "
                    f"Re-run with --label <a-different-name> to keep both.",
                )
        msg = client.trust_intro(
            int(args.intro_id), label=label, remote_username=remote_username
        )
        if msg is None:
            _die(2, "trust_intro failed (raced removal?)")
        # Persist the new contact in the config so it survives across
        # CLI invocations. Pin signing key only — X25519 stays empty
        # until `dnsmesh identity fetch user@host --add` fills it in.
        # The protocol-level username (used for prekey + rotation
        # lookups) lives in `pub_username`; an empty value means
        # "skip those lookups until identity fetch fills it in."
        cfg.contacts[label] = {
            # Preserve any existing X25519 pubkey on a same-label
            # in-place re-trust (codex P1 round 7) — otherwise we'd
            # silently downgrade a sendable contact into a placeholder.
            "pub": existing_pub,
            "spk": intro.sender_spk.hex(),
            "domain": intro.sender_mailbox_domain,
            "remote_username": remote_username,
        }
        cfg.save(_config_path())
        print(f"trusted intro #{args.intro_id} as `{label}`")
        try:
            print(f"  {msg.plaintext.decode('utf-8')}")
        except UnicodeDecodeError:
            print(f"  (binary, {len(msg.plaintext)} bytes)")
        if remote_username:
            print(
                "  pinned signing key only — run `dnsmesh identity fetch "
                f"{remote_username}@{intro.sender_mailbox_domain} --add` to "
                "fill in the X25519 key needed to reply."
            )
        else:
            print(
                "  pinned signing key only — run `dnsmesh identity fetch "
                f"<remote-username>@{intro.sender_mailbox_domain} --add` to "
                "fill in the X25519 key needed to reply (pass --username on "
                "trust to skip the prompt next time)."
            )
        return 0
    finally:
        _close_client(client)


def cmd_intro_block(args: argparse.Namespace) -> int:
    """Drop the intro and add the sender to the local denylist.

    Local-only — no network needed (codex P2 round 6).
    """
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase, requires_network=False)
    try:
        intro = client.intro_queue.get_intro(int(args.intro_id))
        if intro is None:
            _die(1, f"no pending intro with id {args.intro_id}")
        ok = client.block_intro(int(args.intro_id), note=args.note or "")
        if not ok:
            _die(2, "block_intro failed")
        print(f"blocked intro #{args.intro_id}")
        print(f"  sender_spk: {intro.sender_spk.hex()}")
        print("  future claims signed by this key will be silently dropped.")
        return 0
    finally:
        _close_client(client)


def cmd_recv(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    try:
        # M8.3 — also poll claim providers in the same recv pass.
        # Pinned-sender claims roll into `inbox`; un-pinned ones land
        # in the intro queue (`dnsmesh intro list` to review).
        # Pass `client` for cluster-mode discovery (codex P1 round 6).
        claim_providers = _build_claim_providers(cfg, client=client)
        intro_queue_size_before = len(client.intro_queue.list_intros())
        inbox = client.receive_messages(claim_providers=claim_providers)
        intro_queue_size_after = len(client.intro_queue.list_intros())
        new_intros = intro_queue_size_after - intro_queue_size_before
        if not inbox and new_intros == 0:
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
        if new_intros > 0:
            print(
                f"({new_intros} new intro(s) from un-pinned senders — "
                "review with `dnsmesh intro list`)"
            )
        return 0
    finally:
        _close_client(client)


def cmd_register(args: argparse.Namespace) -> int:
    """M5.5 phase 4: self-service registration for a per-user publish token.

    Walks the two-step ``/v1/registration/{challenge,confirm}`` flow
    against a multi-tenant node:

      1. GET /v1/registration/challenge.
      2. Sign ``challenge || subject || node || version`` with the
         local Ed25519 signing key (the same key that signs
         IdentityRecords — no new keypair needed).
      3. POST /v1/registration/confirm.
      4. Save the returned token to ``~/.dmp/tokens/<node>.json``.
         Every subsequent ``dnsmesh identity publish`` / ``dnsmesh send`` /
         ``dnsmesh identity refresh-prekeys`` to this node will auto-
         attach it as a Bearer header.

    Subject defaults to ``<username>@<effective-domain>`` from the
    local config; override with ``--subject`` if you're registering
    under a different address (e.g. for a zone-anchored identity).
    """
    import requests

    from dmp.client.node_tokens import save_token

    cfg = CLIConfig.load(_config_path())
    if not cfg.username:
        _die(
            1,
            "no local config — run `dnsmesh init <username>` before `dnsmesh register`",
        )

    subject = args.subject or f"{cfg.username}@{_effective_domain(cfg)}"

    # Rebuild the local signer so we can sign the challenge.
    passphrase = _load_passphrase(cfg)
    kdf_salt = bytes.fromhex(cfg.kdf_salt) if cfg.kdf_salt else None
    from dmp.core.crypto import DMPCrypto

    crypto = DMPCrypto.from_passphrase(passphrase, salt=kdf_salt)
    spk_hex = crypto.get_signing_public_key_bytes().hex()

    # Codex-style nit (operator-reported, dnsmesh.pro install): users
    # naturally pass `--node https://dnsmesh.pro` because that's the
    # URL they see in the address bar; the old code concatenated the
    # scheme onto whatever they passed, producing
    # `https://https://dnsmesh.pro` and a name-resolution error. Strip
    # any `<scheme>://` prefix from `args.node` before composing the
    # URL so both bare hostnames AND copy-pasted full URLs work.
    node_host = args.node.strip()
    if "://" in node_host:
        node_host = node_host.split("://", 1)[1]
    node_host = node_host.rstrip("/")
    base = f"{args.scheme}://{node_host}"
    try:
        r = requests.get(f"{base}/v1/registration/challenge", timeout=10)
    except requests.RequestException as exc:
        _die(2, f"cannot reach {base}: {exc}")
    if r.status_code == 404:
        _die(
            1,
            f"{args.node} did not accept the challenge request (404). The node "
            "may not have DMP_REGISTRATION_ENABLED=1, or auth_mode is not "
            "multi-tenant. Ask the operator.",
        )
    if r.status_code == 429:
        _die(2, f"registration rate-limited (429). Try again later.")
    if r.status_code != 200:
        _die(2, f"challenge request failed: HTTP {r.status_code}: {r.text}")
    try:
        ch = r.json()
    except ValueError:
        _die(2, f"challenge response is not JSON: {r.text!r}")

    challenge_hex = ch.get("challenge")
    node_hostname = ch.get("node")
    if not challenge_hex or not node_hostname:
        _die(2, f"malformed challenge response: {ch!r}")

    # Sign the challenge. Payload MUST match the server's
    # _build_signing_payload exactly: challenge_bytes || subject-utf8
    # || node-utf8 || version byte (0x01).
    payload = (
        bytes.fromhex(challenge_hex)
        + subject.encode("utf-8")
        + node_hostname.encode("utf-8")
        + b"\x01"
    )
    signature_hex = crypto.sign_data(payload).hex()

    try:
        r2 = requests.post(
            f"{base}/v1/registration/confirm",
            json={
                "subject": subject,
                "ed25519_spk": spk_hex,
                "challenge": challenge_hex,
                "signature": signature_hex,
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        _die(2, f"confirm request failed to reach node: {exc}")

    if r2.status_code == 401:
        _die(
            1,
            "node rejected the signature (401). Usually means the signing "
            "key stored in ~/.dmp/config.yaml doesn't match the one the "
            "user thinks it does — re-check the passphrase.",
        )
    if r2.status_code == 403:
        _die(
            1,
            f"subject {subject!r} is not in the node's allowlist (403). "
            "Ask the operator to add your domain, or register for a "
            "subject on a domain the operator permits.",
        )
    if r2.status_code == 409:
        _die(
            1,
            f"subject {subject!r} is already held by a different key (409). "
            "If you previously registered on another machine, use that same "
            "passphrase here, or ask the operator to revoke the prior "
            "token via `dnsmesh-node-admin token revoke <subject>`.",
        )
    if r2.status_code != 200:
        _die(2, f"confirm failed: HTTP {r2.status_code}: {r2.text}")

    body = r2.json()
    token = body.get("token")
    if not isinstance(token, str) or not token:
        _die(2, f"confirm returned no token: {body!r}")

    # Use the normalized hostname for the saved-token filename so a
    # copy-pasted `--node https://dnsmesh.pro` saves to the same path
    # as a bare `--node dnsmesh.pro` — and both match what the
    # _HttpWriter looks up at publish time via bearer_for_endpoint().
    path = save_token(
        node_host,
        token=token,
        subject=body.get("subject", subject),
        expires_at=body.get("expires_at"),
        registered_spk=spk_hex,
    )
    print(f"registered {subject} on {node_host}")
    print(f"  token saved to {path} (mode 0600)")
    if body.get("expires_at"):
        import time

        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(body["expires_at"])))
        print(f"  expires at {ts}")
    print(
        "  subsequent `dnsmesh identity publish` / `dnsmesh send` to this node "
        "will use this token automatically."
    )
    return 0


def cmd_tsig_register(args: argparse.Namespace) -> int:
    """M9.2.5: register for a TSIG key on a multi-tenant node and
    persist it into the local config.

    Walks the same Ed25519 challenge/confirm dance as ``dnsmesh
    register``, but POSTs to ``/v1/registration/tsig-confirm``.
    The minted TSIG key block (name, secret, algorithm, scope zone)
    lands in ``~/.dmp/config.yaml`` so subsequent ``dnsmesh send`` /
    ``dnsmesh identity publish`` go over RFC 2136 UPDATE through
    the node's DNS port instead of HTTP.

    Default DNS port for the writer is 53; pass ``--dns-port 5353``
    against a dev node that runs DNS on a high port.
    """
    import requests

    cfg = CLIConfig.load(_config_path())
    if not cfg.username:
        _die(
            1,
            "no local config — run `dnsmesh init <username>` before `dnsmesh tsig register`",
        )

    subject = args.subject or f"{cfg.username}@{_effective_domain(cfg)}"

    passphrase = _load_passphrase(cfg)
    kdf_salt = bytes.fromhex(cfg.kdf_salt) if cfg.kdf_salt else None
    from dmp.core.crypto import DMPCrypto

    crypto = DMPCrypto.from_passphrase(passphrase, salt=kdf_salt)
    spk_hex = crypto.get_signing_public_key_bytes().hex()
    x25519_pub_hex = crypto.get_public_key_bytes().hex()

    node_host = args.node.strip()
    if "://" in node_host:
        node_host = node_host.split("://", 1)[1]
    node_host = node_host.rstrip("/")
    base = f"{args.scheme}://{node_host}"
    try:
        r = requests.get(f"{base}/v1/registration/challenge", timeout=10)
    except requests.RequestException as exc:
        _die(2, f"cannot reach {base}: {exc}")
    if r.status_code == 404:
        _die(
            1,
            f"{args.node} does not expose /v1/registration/challenge (404). "
            "Operator must set DMP_REGISTRATION_ENABLED=1 + DMP_AUTH_MODE=multi-tenant.",
        )
    if r.status_code == 429:
        _die(2, "registration rate-limited (429). Try again later.")
    if r.status_code != 200:
        _die(2, f"challenge request failed: HTTP {r.status_code}: {r.text}")
    try:
        ch = r.json()
    except ValueError:
        _die(2, f"challenge response is not JSON: {r.text!r}")

    challenge_hex = ch.get("challenge")
    node_hostname = ch.get("node")
    if not challenge_hex or not node_hostname:
        _die(2, f"malformed challenge response: {ch!r}")

    payload = (
        bytes.fromhex(challenge_hex)
        + subject.encode("utf-8")
        + node_hostname.encode("utf-8")
        + b"\x01"
    )
    signature_hex = crypto.sign_data(payload).hex()

    try:
        r2 = requests.post(
            f"{base}/v1/registration/tsig-confirm",
            json={
                "subject": subject,
                "ed25519_spk": spk_hex,
                "challenge": challenge_hex,
                "signature": signature_hex,
                # M9.2.3 + M9.2.5: shipping the X25519 public key extends
                # the minted scope to mailbox / claim records.
                "x25519_pub": x25519_pub_hex,
            },
            timeout=10,
        )
    except requests.RequestException as exc:
        _die(2, f"tsig-confirm request failed: {exc}")
    if r2.status_code == 401:
        _die(1, "node rejected the signature (401). Re-check the passphrase.")
    if r2.status_code == 403:
        _die(1, f"subject {subject!r} not in the node's allowlist (403).")
    if r2.status_code == 409:
        _die(
            1,
            f"subject {subject!r} already owned by a different key (409). "
            "Use the same passphrase you registered with, or have the "
            "operator revoke the prior key.",
        )
    if r2.status_code == 404:
        _die(
            1,
            f"{args.node} does not expose /v1/registration/tsig-confirm (404). "
            "Operator must set DMP_DNS_UPDATE_ENABLED=1 to mint TSIG keys.",
        )
    if r2.status_code != 200:
        _die(2, f"tsig-confirm failed: HTTP {r2.status_code}: {r2.text}")
    body = r2.json()

    name = body.get("tsig_key_name")
    secret_hex = body.get("tsig_secret_hex")
    algorithm = body.get("tsig_algorithm", "hmac-sha256")
    zone = body.get("zone")
    suffixes = body.get("allowed_suffixes") or []
    expires_at = body.get("expires_at")
    if not (isinstance(name, str) and isinstance(secret_hex, str) and zone):
        _die(2, f"tsig-confirm returned malformed body: {body!r}")

    cfg.tsig_key_name = name
    cfg.tsig_secret_hex = secret_hex
    cfg.tsig_algorithm = algorithm or "hmac-sha256"
    cfg.tsig_zone = zone
    # Resolve the DNS server: --dns-server > --node host > endpoint host.
    # Strip any HTTP-port suffix from the node host — ``_DnsUpdateWriter``
    # passes the host string directly to dns.query.udp and hands the
    # port separately, so a "host:8053" string here would break every
    # publish. (Codex round-8 P1.)
    dns_server = (args.dns_server or "").strip()
    if not dns_server:
        bare = node_host
        if bare.startswith("[") and "]" in bare:
            bare = bare[: bare.find("]") + 1]  # IPv6 literal — keep brackets
        elif ":" in bare and bare.count(":") == 1:
            bare = bare.split(":", 1)[0]
        dns_server = bare
    cfg.tsig_dns_server = dns_server
    cfg.tsig_dns_port = int(args.dns_port) if args.dns_port else 53
    cfg.save(_config_path())

    print(f"registered {subject} on {node_host}")
    print(f"  TSIG key:  {name}")
    print(f"  algorithm: {algorithm}")
    print(f"  zone:      {zone}")
    print(f"  DNS:       {dns_server}:{cfg.tsig_dns_port}/udp")
    if suffixes:
        print("  scope:")
        for s in suffixes:
            print(f"    - {s}")
    if isinstance(expires_at, int) and expires_at > 0:
        import time as _time

        print(
            "  expires:   "
            + _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(expires_at))
        )
    print(
        "  subsequent `dnsmesh identity publish` / `dnsmesh send` will "
        "go over DNS UPDATE through the node's DNS port."
    )
    return 0


def cmd_token_list(args: argparse.Namespace) -> int:
    import json

    from dmp.client.node_tokens import list_tokens

    rows = list(list_tokens())
    if args.json:
        # Strip the raw token material — `dnsmesh token list --json` is
        # for scripting / inventory, not for dumping credentials to
        # stdout. Show prefix + length so the operator can confirm
        # "the right token" without ever printing the full value.
        safe = []
        for r in rows:
            t = r.get("token", "")
            safe.append(
                {
                    **{k: v for k, v in r.items() if k != "token"},
                    "token_prefix": t[:16] + ("…" if len(t) > 16 else ""),
                    "token_len": len(t),
                }
            )
        print(json.dumps(safe, indent=2))
        return 0

    if not rows:
        print("(no saved tokens)")
        return 0
    print(f"{'NODE':<30} {'SUBJECT':<30} {'EXPIRES':<22}")
    for r in rows:
        exp = r.get("expires_at")
        exp_str = "-"
        if isinstance(exp, int):
            import time

            exp_str = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(exp))
        print(
            f"{r.get('node', '?'):<30} "
            f"{r.get('subject', '?'):<30} "
            f"{exp_str:<22}"
        )
    return 0


def cmd_token_forget(args: argparse.Namespace) -> int:
    from dmp.client.node_tokens import delete_token

    if delete_token(args.node):
        print(f"forgot token for {args.node}")
        return 0
    print(f"no saved token for {args.node}", file=sys.stderr)
    return 1


def cmd_resolvers_discover(args: argparse.Namespace) -> int:
    """Probe WELL_KNOWN_RESOLVERS and print (or save) the working subset.

    Without `--save`, this is a read-only diagnostic — useful on a
    captive network to sanity-check which upstreams are reachable
    before committing to them. With `--save`, the working list is
    written to config as `dns_resolvers`; a subsequent `dnsmesh resolvers
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
        # `dnsmesh init` may not have run yet on a fresh machine; in that
        # case there's no config to update and the user should init
        # first. If the config does exist, we just set the new field
        # (creating it if absent) and persist.
        path = _config_path()
        if not path.exists():
            _die(
                1,
                f"no config at {path} — run `dnsmesh init <username>` before "
                f"`dnsmesh resolvers discover --save`",
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
    unfriendly for `dnsmesh resolvers list` as a diagnostic command.
    Check for the config up front and surface a clean exit-1 with the
    same "run `dnsmesh init` first" hint other commands use via `_die`.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
    cfg = CLIConfig.load(path)
    if not cfg.dns_resolvers:
        print(
            "(no dns_resolvers configured — run `dnsmesh resolvers discover "
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
    runs `dnsmesh cluster fetch` to confirm the manifest resolves and
    verifies, then `dnsmesh cluster enable` to flip `cluster_enabled=True`
    so subsequent networked commands route through the cluster path.

    This decoupling means pinning an operator who hasn't published
    their manifest yet is safe — it won't wedge every `dnsmesh send` /
    `dnsmesh recv` on a failed bootstrap. It also gives operators a
    reversible activation: `dnsmesh cluster disable` drops back to the
    legacy endpoint without clearing the pinned anchors.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
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
    print("  1. `dnsmesh cluster fetch` to verify the manifest resolves")
    print("  2. `dnsmesh cluster enable` to cut over from the legacy endpoint")
    return 0


def cmd_cluster_enable(args: argparse.Namespace) -> int:
    """Activate cluster mode after a live manifest-fetch sanity check.

    Requires both anchors pinned (`dnsmesh cluster pin` beforehand). Runs a
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
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster anchors not pinned — run `dnsmesh cluster pin "
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
            f"dnsmesh: cluster manifest fetch failed for {cfg.cluster_base_domain} — "
            "nothing at `cluster.<base>` TXT verified under the pinned operator key. "
            "Cluster mode NOT enabled. Run `dnsmesh cluster fetch` for diagnostics.",
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
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
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
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster not configured — run `dnsmesh cluster pin <operator_spk_hex> "
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

    Unlike `dnsmesh cluster fetch`, this actually spins up the full
    ClusterClient (including per-node writers/readers) so the
    fanout/union health snapshots have data to report. We shut it
    down immediately after printing — no background refresh thread
    is left running.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
    cfg = CLIConfig.load(path)
    if not _cluster_anchors_pinned(cfg):
        _die(
            1,
            "cluster not configured — run `dnsmesh cluster pin <operator_spk_hex> "
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
    availability. Mirrors the `dnsmesh cluster pin` ergonomics.

    Validation:
    - `user_domain` goes through `bootstrap_rrset_name` which runs the
      shared DNS-name validator (empty, leading dot, oversized label,
      non-ASCII all raise). Pinning a malformed name would fail later
      inside `fetch_bootstrap_record` with a less helpful traceback.
    - `signer_spk_hex` must be 64 hex chars decoding to 32 bytes.
    """
    path = _config_path()
    if not path.exists():
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
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
        f"  1. `dnsmesh bootstrap fetch` to verify the record at "
        f"_dmp.{cfg.bootstrap_user_domain} resolves"
    )
    print(
        f"  2. `dnsmesh bootstrap discover <user>@{cfg.bootstrap_user_domain}` "
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
            "--signer-spk, or pin with `dnsmesh bootstrap pin <user_domain> "
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
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
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
    5. Without `--auto-pin`: print the `dnsmesh cluster pin` /
       `dnsmesh cluster enable` steps the operator would run. Do NOT
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
        _die(1, f"no config at {path} — run `dnsmesh init <username>` first")
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
                f"`dnsmesh bootstrap pin {host} <signer_spk_hex>` first, or "
                "pass --signer-spk <hex> on this call",
            )
        signer_hex = cfg.bootstrap_signer_spk
        if not signer_hex:
            _die(
                1,
                f"no bootstrap signer pinned for {host!r} — run "
                f"`dnsmesh bootstrap pin {host} <signer_spk_hex>` first",
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
            f"  dnsmesh cluster pin {shown.operator_spk.hex()} {shown.cluster_base_domain}"
        )
        print("  dnsmesh cluster fetch  # verify manifest")
        print("  dnsmesh cluster enable # activate cluster mode")
        print()
        print("or re-run with --auto-pin to do all of the above atomically.")
        return 0

    # --auto-pin mutates the caller's own global cluster_* config and
    # flips cluster_enabled=True, which rehomes every subsequent
    # `dnsmesh send` / `dnsmesh recv` / `identity publish` onto the discovered
    # cluster. Running it against ANY address (e.g. to look at a
    # recipient alice@example.com) would rehome the operator's local
    # mailbox state to someone else's cluster — a silent hijack.
    #
    # Guard: require the discovered host to match bootstrap_user_domain
    # pinned in config. That makes auto-pin an explicit two-step flow:
    #   1. `dnsmesh bootstrap pin <my-domain> <my-signer-spk>`  — acknowledge
    #      trust anchor for the zone you actually live on
    #   2. `dnsmesh bootstrap discover me@my-domain --auto-pin`
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
            f"first with `dnsmesh bootstrap pin {host} <signer_spk_hex>`, "
            f"then re-run --auto-pin. For one-off discovery of a "
            f"recipient's cluster, omit --auto-pin (diagnostic mode) "
            f"or use `dnsmesh identity fetch alice@host --via-bootstrap`.",
        )

    # Verify the cluster manifest at the returned anchor BEFORE writing
    # any config. Two-hop trust chain:
    # 1. bootstrap record verified against pinned bootstrap_signer_spk
    #    (above, via fetch_bootstrap_record).
    # 2. cluster manifest verified against the entry's operator_spk
    #    (below, via fetch_cluster_manifest).
    # Only after BOTH succeed do we persist. A half-written config
    # (bootstrap pinned but no cluster) is worse than none at all —
    # `dnsmesh send` would wedge on cluster-mode enabled with no manifest.
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
    # anchors and set cluster_enabled=True so the next `dnsmesh send` /
    # `dnsmesh recv` routes through the federation path.
    #
    # Clear cluster_node_token AND http_token: both were scoped to the
    # previous operator. _build_cluster_writer_factory falls back from
    # cluster_node_token to http_token, so clearing only the former
    # would still send the legacy token to the newly discovered cluster
    # — a cross-trust-domain credential leak. The operator can
    # repopulate either via `dnsmesh config set` or by editing the config
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


def cmd_peers(args: argparse.Namespace) -> int:
    """Show the heartbeat-discovery view a node publishes at
    ``_dnsmesh-seen.<zone>`` and ``_dnsmesh-heartbeat.<zone>``.

    No config required: queries DNS directly with the system resolver
    (or whatever ``--dns-resolvers`` was last persisted in the user's
    config, if one exists). Useful for "I just spun up a node, what
    does its directory look like?" and for surveying a peer before
    pinning it. ``--json`` emits a list of decoded heartbeat records
    for piping into jq.

    Argument is now a DNS zone (``dnsmesh.io``) — but a legacy URL
    (``https://dnsmesh.io``) is accepted and the host is extracted,
    so existing operator muscle memory keeps working through M9.
    """
    import json as _json
    import time as _time

    from dmp.core.heartbeat import HeartbeatRecord
    from dmp.server.heartbeat_worker import (
        heartbeat_rrset_name,
        seen_rrset_name,
    )

    raw = (args.endpoint or "").strip()
    if not raw:
        _die(1, "missing zone argument")
    zone = _zone_from_endpoint_url(raw) if "://" in raw else raw.lower()
    if not zone:
        _die(
            1,
            f"could not derive a DNS zone from {raw!r} — pass a zone like "
            "`dnsmesh.io` or a URL with a non-IP hostname",
        )

    # Build a reader. If a config exists we honor the user's resolver
    # pool; otherwise fall back to a default `_DnsReader` (system DNS).
    try:
        cfg = CLIConfig.load(_config_path())
        reader = _make_reader(cfg)
    except FileNotFoundError:
        reader = _DnsReader(host=None, port=53)

    own_wire: Optional[str] = None
    self_record: Optional[HeartbeatRecord] = None
    try:
        own_values = reader.query_txt_record(heartbeat_rrset_name(zone))
    except Exception as exc:
        _die(2, f"DNS query for _dnsmesh-heartbeat.{zone} failed: {exc}")
    if own_values:
        for v in own_values:
            if not isinstance(v, str):
                continue
            rec = HeartbeatRecord.parse_and_verify(v)
            if rec is not None:
                own_wire = v
                self_record = rec
                break

    try:
        seen_values = reader.query_txt_record(seen_rrset_name(zone)) or []
    except Exception as exc:
        _die(2, f"DNS query for _dnsmesh-seen.{zone} failed: {exc}")

    seen_records: List[HeartbeatRecord] = []
    for v in seen_values:
        if not isinstance(v, str):
            continue
        rec = HeartbeatRecord.parse_and_verify(v)
        if rec is not None:
            seen_records.append(rec)

    if args.json:
        payload = {
            "zone": zone,
            "self": (
                {
                    "endpoint": self_record.endpoint,
                    "operator_spk_hex": bytes(self_record.operator_spk).hex(),
                    "claim_provider_zone": self_record.claim_provider_zone,
                    "version": self_record.version,
                    "ts": self_record.ts,
                    "wire": own_wire or "",
                }
                if self_record is not None
                else None
            ),
            "seen": [
                {
                    "endpoint": r.endpoint,
                    "operator_spk_hex": bytes(r.operator_spk).hex(),
                    "claim_provider_zone": r.claim_provider_zone,
                    "version": r.version,
                    "ts": r.ts,
                }
                for r in seen_records
            ],
        }
        print(_json.dumps(payload, indent=2))
        return 0

    # Human-readable.
    print(f"zone:    {zone}")
    if self_record is None:
        print("  (_dnsmesh-heartbeat.{zone} not published yet)".format(zone=zone))
    else:
        print(f"  self endpoint: {self_record.endpoint}")
        print(f"  operator spk:  {bytes(self_record.operator_spk).hex()}")
        print(f"  claim zone:    {self_record.claim_provider_zone or '-'}")
        print(f"  version:       {self_record.version}")
    print()
    if not seen_records:
        print("(no peers seen yet)")
        return 0
    now = int(_time.time())
    print(f"peers ({len(seen_records)}):")
    for r in seen_records:
        spk = bytes(r.operator_spk).hex()
        spk_short = (spk[:8] + "..." + spk[-4:]) if len(spk) > 16 else spk
        age = max(0, now - int(r.ts))
        if age < 60:
            age_str = f"{age}s ago"
        elif age < 3600:
            age_str = f"{age // 60}m ago"
        else:
            age_str = f"{age // 3600}h ago"
        version = r.version or "-"
        print(f"  {r.endpoint}")
        print(f"    spk={spk_short}  version={version}  last heard {age_str}")
    return 0


def cmd_node(args: argparse.Namespace) -> int:
    """Convenience: launch a dnsmesh-node in the foreground."""
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
    p = argparse.ArgumentParser(prog="dnsmesh", description="DNS Mesh Protocol CLI")
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
        "--dns-host / --dns-port are ignored. Hostnames are rejected. "
        "Default when unset: 1.1.1.1, 8.8.8.8 (Cloudflare + Google).",
    )
    p_init.add_argument(
        "--no-default-resolvers",
        action="store_true",
        help="Skip the default 1.1.1.1 + 8.8.8.8 pool. Falls back to the "
        "system resolver. Use when you want every DMP query to go through "
        "your local / corporate / privacy resolver instead of public DNS.",
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
        choices=("routine", "compromise", "lost_key"),
        default="routine",
        help="reason_code for the rotation. 'routine' (default) is a "
        "normal key rollover: publishes a RotationRecord only — no "
        "RevocationRecord — so chain walkers auto-follow the new key. "
        "'compromise' and 'lost_key' both additionally publish a "
        "self-signed RevocationRecord of the old key so chain walkers "
        "abort trust instead of following forward. Use 'compromise' if "
        "the key was leaked and 'lost_key' if the old material is "
        "genuinely gone.",
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
        "a one-shot ClusterClient. Requires `dnsmesh bootstrap pin <host> "
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

    # intro — M8.3 first-contact quarantine queue. Claim-discovered
    # messages from un-pinned senders land here; the user reviews
    # and decides whether to accept (deliver only), trust (deliver
    # + pin), or block (denylist the sender).
    p_intro = sub.add_parser(
        "intro",
        help="manage pending first-contact intros (M8.3)",
    )
    sub_intro = p_intro.add_subparsers(dest="intro_cmd", required=True)

    p_intro_list = sub_intro.add_parser(
        "list", help="list pending intros awaiting review"
    )
    p_intro_list.set_defaults(func=cmd_intro_list)

    p_intro_accept = sub_intro.add_parser(
        "accept",
        help="deliver one intro into the inbox without pinning the sender",
    )
    p_intro_accept.add_argument("intro_id", type=int)
    p_intro_accept.set_defaults(func=cmd_intro_accept)

    p_intro_trust = sub_intro.add_parser(
        "trust",
        help="deliver + pin the sender as a trusted contact",
    )
    p_intro_trust.add_argument("intro_id", type=int)
    p_intro_trust.add_argument(
        "--label",
        default="",
        help="local nickname for the new contact " "(default: intro-<spk-prefix>)",
    )
    p_intro_trust.add_argument(
        "--username",
        default="",
        help="sender's actual identity name on their home node — "
        "used by prekey + rotation-chain lookups. Empty (default) "
        "skips those lookups until you run `dnsmesh identity fetch`.",
    )
    p_intro_trust.set_defaults(func=cmd_intro_trust)

    p_intro_block = sub_intro.add_parser(
        "block",
        help="drop the intro and add the sender to the local denylist",
    )
    p_intro_block.add_argument("intro_id", type=int)
    p_intro_block.add_argument(
        "--note",
        default="",
        help="reason recorded alongside the denylist entry",
    )
    p_intro_block.set_defaults(func=cmd_intro_block)

    # register — mint a per-user publish token via the node's
    # /v1/registration/* endpoints (M5.5 phase 3). Saves the
    # resulting token to ~/.dmp/tokens/<hostname>.json; the
    # _HttpWriter auto-attaches it on subsequent publishes.
    p_reg = sub.add_parser(
        "register",
        help="register for a per-user publish token on a multi-tenant node",
    )
    p_reg.add_argument(
        "--node",
        required=True,
        help="node hostname (e.g. dmp.example.com)",
    )
    p_reg.add_argument(
        "--subject",
        help="subject to register (default: <username>@<effective-domain>)",
    )
    p_reg.add_argument(
        "--scheme",
        choices=("https", "http"),
        default="https",
        help="URL scheme for the node (default: https; http only for local dev)",
    )
    p_reg.set_defaults(func=cmd_register)

    # tsig — DNS UPDATE credential management. ``tsig register`` walks
    # /v1/registration/tsig-confirm and persists the minted key into
    # the local config, after which _make_client builds a
    # _DnsUpdateWriter for every publish.
    p_tsig = sub.add_parser(
        "tsig",
        help="DNS UPDATE credential management (M9.2.5)",
    )
    p_tsig_sub = p_tsig.add_subparsers(dest="tsig_cmd", required=True)
    p_tsig_reg = p_tsig_sub.add_parser(
        "register",
        help="register for a TSIG key on a multi-tenant node",
    )
    p_tsig_reg.add_argument(
        "--node",
        required=True,
        help="node hostname (e.g. dmp.example.com)",
    )
    p_tsig_reg.add_argument(
        "--subject",
        help="subject to register (default: <username>@<effective-domain>)",
    )
    p_tsig_reg.add_argument(
        "--scheme",
        choices=("https", "http"),
        default="https",
        help="URL scheme for the registration call (default: https)",
    )
    p_tsig_reg.add_argument(
        "--dns-server",
        default="",
        help="DNS server to send UPDATEs to (default: --node host)",
    )
    p_tsig_reg.add_argument(
        "--dns-port",
        type=int,
        default=53,
        help="DNS port (default: 53; use 5353 for dev)",
    )
    p_tsig_reg.set_defaults(func=cmd_tsig_register)

    # token — inspect / manage locally-stored per-node tokens.
    p_tok = sub.add_parser(
        "token",
        help="manage per-node publish tokens saved under ~/.dmp/tokens/",
    )
    sub_tok = p_tok.add_subparsers(dest="sub", required=True)
    p_tok_list = sub_tok.add_parser(
        "list", help="list locally-saved tokens by node / subject / expiry"
    )
    p_tok_list.add_argument("--json", action="store_true")
    p_tok_list.set_defaults(func=cmd_token_list)
    p_tok_forget = sub_tok.add_parser(
        "forget", help="delete the saved token for a node"
    )
    p_tok_forget.add_argument("node", help="hostname as stored (e.g. dmp.example.com)")
    p_tok_forget.set_defaults(func=cmd_token_forget)

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
        "host has not been pinned via `dnsmesh bootstrap pin`",
    )
    p_bs_discover.add_argument(
        "--auto-pin",
        action="store_true",
        help="after verifying the bootstrap record AND the cluster manifest "
        "at the returned anchor, write both to config and enable cluster "
        "mode. All-or-nothing: on any failure the config is left untouched.",
    )
    p_bs_discover.set_defaults(func=cmd_bootstrap_discover)

    # peers (DNS-native discovery feed of a single zone)
    p_peers = sub.add_parser(
        "peers",
        help="show the heartbeat directory a node publishes at "
        "_dnsmesh-seen.<zone>",
    )
    p_peers.add_argument(
        "endpoint",
        help="DNS zone of the node to query (e.g. dnsmesh.io). A legacy "
        "URL like https://dnsmesh.io is accepted and the host is used.",
    )
    p_peers.add_argument(
        "--json",
        action="store_true",
        help="emit a JSON payload of decoded heartbeat records instead of a table",
    )
    p_peers.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="(unused; kept for back-compat with the pre-M9 HTTP form)",
    )
    p_peers.set_defaults(func=cmd_peers)

    # node (convenience launcher)
    p_n = sub.add_parser("node", help="run a dnsmesh node in the foreground")
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
