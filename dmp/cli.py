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
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml

from dmp.client.client import DMPClient
from dmp.client.cluster_bootstrap import ClusterClient, fetch_cluster_manifest
from dmp.core.cluster import ClusterNode
from dmp.network.base import DNSRecordReader, DNSRecordWriter
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
    # Each contact is {"pub": <x25519 hex>, "spk": <ed25519 hex or "">}.
    # `spk` may be empty for contacts added before Ed25519 pinning landed
    # (and for the `contacts add` shortcut that doesn't require a signing
    # key). Pinned `spk` is what gates incoming manifests from that sender.
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
                contacts[name] = {"pub": value, "spk": ""}
            elif isinstance(value, dict):
                contacts[name] = {
                    "pub": value.get("pub", ""),
                    "spk": value.get("spk", ""),
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
    """A config is in cluster mode when both anchors are pinned.

    Two fields gate cluster mode: the base domain we fetch `cluster.<X>`
    TXT from, and the operator public key we trust signatures against.
    Either one missing means we fall back to the single-endpoint legacy
    path.
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
        import dns.message
        import dns.query
        import dns.rcode
        import dns.rdatatype

        try:
            request = dns.message.make_query(name, dns.rdatatype.TXT)
            response = dns.query.udp(
                request,
                self._host,
                port=self._port,
                timeout=self._timeout,
            )
        except Exception:
            # Any transport-level error (socket, timeout, malformed
            # packet) coalesces to "not seen" for this node. The
            # UnionReader counts this as a per-node failure and keeps
            # going with the other nodes.
            return None
        if response.rcode() != dns.rcode.NOERROR:
            return None
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


def _make_client(config: CLIConfig, passphrase: str) -> DMPClient:
    """Build a DMPClient, routing through the cluster or legacy path.

    When cluster mode is enabled (both `cluster_base_domain` AND
    `cluster_operator_spk` populated), the returned client uses the
    FanoutWriter + UnionReader produced by a `ClusterClient`. The
    `ClusterClient` is attached to the returned DMPClient via a
    `_cluster_client` attribute so the CLI wrapper can close it on exit
    (see `_close_client`).

    When cluster mode is disabled, behavior is unchanged from the
    legacy single-endpoint path.
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
        writer: DNSRecordWriter = cluster_client.writer
        reader: DNSRecordReader = cluster_client.reader
    else:
        if not config.endpoint:
            _die(
                1,
                "no endpoint configured — run `dmp init` with --endpoint, or edit "
                f"{_config_path()}",
            )
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
    client = DMPClient(
        config.username,
        passphrase,
        domain=config.domain,
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
    for name, entry in config.contacts.items():
        client.add_contact(
            name,
            entry.get("pub", ""),
            domain=config.domain,
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
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
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
            name = identity_domain(cfg.username, cfg.domain)
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
        name = prekey_rrset_name(cfg.username, cfg.domain)
        print(f"published {published}/{args.count} prekeys to {name}")
        print(f"  local live prekey count: {client.prekey_store.count_live()}")
        if published < args.count:
            print(
                "  (note: some publishes were rejected — check node rate limits and caps)"
            )
        return 0
    finally:
        _close_client(client)


def cmd_identity_fetch(args: argparse.Namespace) -> int:
    """Resolve an identity record from DNS and optionally add it as a contact.

    Two address forms:
      - `alice@alice.example.com`  — zone-anchored; queries
        `dmp.alice.example.com`. Squat resistance relies on DNS zone
        control.
      - `alice`                    — legacy / TOFU; queries
        `id-{sha256(alice)[:16]}.<domain>` where <domain> is either
        `--domain` or the config's mesh domain.
    """
    import hashlib
    from dmp.core.identity import (
        IdentityRecord,
        identity_domain,
        parse_address,
        zone_anchored_identity_name,
    )

    cfg = CLIConfig.load(_config_path())
    # Fetch is read-only — no passphrase needed. Build a minimal reader path
    # without going through _make_client (which loads the identity key).
    reader = _make_reader(cfg)

    parsed_addr = parse_address(args.username)
    if parsed_addr is not None:
        user, host = parsed_addr
        resolved_username = user
        name = zone_anchored_identity_name(host)
    else:
        resolved_username = args.username
        name = identity_domain(args.username, args.domain or cfg.domain)

    records = reader.query_txt_record(name)
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
            cfg.contacts[contact_key] = {
                "pub": identity.x25519_pk.hex(),
                "spk": identity.ed25519_spk.hex(),
            }
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

    cfg.contacts[args.name] = {
        "pub": args.pubkey.lower(),
        "spk": spk_hex,
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

    Writes to config; does NOT fetch. Run `dmp cluster fetch` after to
    sanity-check that the manifest is published + verifiable.
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
    cfg.cluster_operator_spk = args.operator_spk.lower()
    cfg.cluster_base_domain = args.base_domain
    cfg.save(path)
    print(f"pinned cluster operator key and base domain {args.base_domain}")
    print(
        "next: `dmp cluster fetch` to confirm the manifest is "
        "published and verifiable"
    )
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
    cfg = CLIConfig.load(_config_path())
    if not _cluster_mode_enabled(cfg):
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
        # wire string off the *first* matching TXT record so an offline
        # bootstrap has something to load. We re-fetch the rrset rather
        # than round-tripping through sign() to keep the original
        # signed blob byte-identical.
        from dmp.core.cluster import cluster_rrset_name

        rrset = cluster_rrset_name(cfg.cluster_base_domain)
        raw_records = bootstrap_reader.query_txt_record(rrset)
        if raw_records:
            wire_path = _config_path().parent / "cluster_manifest.wire"
            # Pick the first record that parses + verifies with the
            # same constraints as fetch_cluster_manifest, to ensure we
            # cache the same manifest the runtime would use.
            from dmp.core.cluster import ClusterManifest

            for wire in raw_records:
                if (
                    ClusterManifest.parse_and_verify(
                        wire,
                        operator_spk,
                        expected_cluster_name=cfg.cluster_base_domain,
                    )
                    is not None
                ):
                    wire_path.parent.mkdir(parents=True, exist_ok=True)
                    wire_path.write_text(wire)
                    print(f"saved signed manifest wire to {wire_path}")
                    break
    return 0


def cmd_cluster_status(args: argparse.Namespace) -> int:
    """Build the cluster client and print health snapshots.

    Unlike `dmp cluster fetch`, this actually spins up the full
    ClusterClient (including per-node writers/readers) so the
    fanout/union health snapshots have data to report. We shut it
    down immediately after printing — no background refresh thread
    is left running.
    """
    cfg = CLIConfig.load(_config_path())
    if not _cluster_mode_enabled(cfg):
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
