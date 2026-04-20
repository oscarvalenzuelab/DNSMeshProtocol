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
import json
import os
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, Optional

import yaml

from dmp.client.client import DMPClient
from dmp.network.base import DNSRecordReader, DNSRecordWriter


# ----------------------------- config ----------------------------------------


DEFAULT_CONFIG_HOME = Path.home() / ".dmp"
CONFIG_FILENAME = "config.yaml"


@dataclass
class CLIConfig:
    username: str = ""
    domain: str = "mesh.local"
    endpoint: str = ""                          # HTTP API base URL of the node
    http_token: Optional[str] = None
    dns_host: Optional[str] = None              # host:port of the DNS resolver
    dns_port: int = 5353
    passphrase_file: Optional[str] = None       # alternative to DMP_PASSPHRASE
    # 32 random bytes generated at `dmp init`, stored as hex. Combined with
    # the passphrase under Argon2id to derive the X25519 seed. Two users who
    # happen to share a passphrase still get independent identities; an
    # attacker who captures the public identity has to do a per-user
    # offline brute force rather than a single rainbow table.
    kdf_salt: str = ""
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
        return cls(
            username=data.get("username", ""),
            domain=data.get("domain", "mesh.local"),
            endpoint=data.get("endpoint", ""),
            http_token=data.get("http_token"),
            dns_host=data.get("dns_host"),
            dns_port=int(data.get("dns_port", 5353)),
            passphrase_file=data.get("passphrase_file"),
            kdf_salt=data.get("kdf_salt", ""),
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
    return Path(home) / CONFIG_FILENAME if home else DEFAULT_CONFIG_HOME / CONFIG_FILENAME


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


def _make_client(config: CLIConfig, passphrase: str) -> DMPClient:
    if not config.endpoint:
        _die(
            1,
            "no endpoint configured — run `dmp init` with --endpoint, or edit "
            f"{_config_path()}",
        )
    writer = _HttpWriter(config.endpoint, config.http_token)
    reader = _DnsReader(config.dns_host, config.dns_port)
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
    for name, entry in config.contacts.items():
        client.add_contact(
            name,
            entry.get("pub", ""),
            domain=config.domain,
            signing_key_hex=entry.get("spk", ""),
        )
    return client


# ----------------------------- commands --------------------------------------


def _die(code: int, msg: str) -> None:
    print(f"dmp: {msg}", file=sys.stderr)
    sys.exit(code)


def cmd_init(args: argparse.Namespace) -> int:
    path = _config_path()
    if path.exists() and not args.force:
        _die(1, f"config already exists at {path} (use --force to overwrite)")
    cfg = CLIConfig(
        username=args.username,
        domain=args.domain,
        endpoint=args.endpoint or "",
        http_token=args.http_token,
        dns_host=args.dns_host,
        dns_port=args.dns_port,
        # Per-identity random salt so two users with the same passphrase
        # still derive different keys. 32 bytes is well above Argon2's
        # minimum (8) and matches our key length.
        kdf_salt=os.urandom(32).hex(),
    )
    cfg.save(path)
    print(f"wrote config to {path}")
    print("Next: set DMP_PASSPHRASE or create a passphrase file, then `dmp identity show`.")
    print(
        "Keep this config file. If you lose the kdf_salt you cannot "
        "recover this identity even with the passphrase."
    )
    return 0


def cmd_identity_show(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    info = client.get_user_info()
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        for key in ("username", "domain", "public_key", "signing_public_key", "user_id"):
            print(f"{key}: {info[key]}")
    return 0


def cmd_identity_publish(args: argparse.Namespace) -> int:
    """Publish a signed identity record to DNS so contacts can resolve us."""
    from dmp.core.identity import make_record, identity_domain

    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    record = make_record(client.crypto, cfg.username)
    wire = record.sign(client.crypto)
    name = identity_domain(cfg.username, cfg.domain)
    ok = client.writer.publish_txt_record(name, wire, ttl=args.ttl)
    if not ok:
        _die(2, "publish failed — see node logs")
    print(f"published identity to {name}")
    print(f"  others can resolve you with: dmp identity fetch {cfg.username}")
    return 0


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

    published = client.refresh_prekeys(count=args.count, ttl_seconds=args.ttl)
    name = prekey_rrset_name(cfg.username, cfg.domain)
    print(f"published {published}/{args.count} prekeys to {name}")
    print(f"  local live prekey count: {client.prekey_store.count_live()}")
    if published < args.count:
        print("  (note: some publishes were rejected — check node rate limits and caps)")
    return 0


def cmd_identity_fetch(args: argparse.Namespace) -> int:
    """Resolve an identity record from DNS and optionally add it as a contact."""
    import hashlib
    from dmp.core.identity import IdentityRecord, identity_domain

    cfg = CLIConfig.load(_config_path())
    # Fetch is read-only — no passphrase needed. Build a minimal reader path
    # without going through _make_client (which loads the identity key).
    reader = _DnsReader(cfg.dns_host, cfg.dns_port)
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
        print(json.dumps({
            "username": identity.username,
            "public_key": identity.x25519_pk.hex(),
            "signing_public_key": identity.ed25519_spk.hex(),
            "ts": identity.ts,
            "dns_name": name,
        }, indent=2))
    else:
        print(f"username:           {identity.username}")
        print(f"public_key:         {identity.x25519_pk.hex()}")
        print(f"signing_public_key: {identity.ed25519_spk.hex()}")
        print(f"published at:       {identity.ts}")

    if args.add:
        if identity.username in cfg.contacts:
            print(f"(contact `{identity.username}` already exists — not overwriting)")
        else:
            cfg.contacts[identity.username] = {
                "pub": identity.x25519_pk.hex(),
                "spk": identity.ed25519_spk.hex(),
            }
            cfg.save(_config_path())
            print(f"added contact {identity.username} (pinned signing key)")
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
            f"added contact {args.name} (WARNING: no signing key pinned — "
            f"incoming messages from this contact will fall back to "
            f"trust-on-first-use until you re-add with --signing-key)"
        )
    return 0


def cmd_contacts_list(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    if not cfg.contacts:
        print("(no contacts yet — `dmp contacts add <name> <pubkey_hex>` or `dmp identity fetch <user> --add`)")
        return 0
    width = max(len(n) for n in cfg.contacts)
    for name, entry in sorted(cfg.contacts.items()):
        pin = "pinned" if entry.get("spk") else "UNPINNED"
        print(f"{name:<{width}}  {entry.get('pub', '')}  ({pin})")
    return 0


def cmd_send(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    if args.recipient not in cfg.contacts:
        _die(1, f"unknown contact `{args.recipient}` — add it first with `dmp contacts add`")
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    ok = client.send_message(args.recipient, args.message)
    if not ok:
        _die(2, f"send failed (see node logs for details)")
    print(f"sent → {args.recipient}")
    return 0


def cmd_recv(args: argparse.Namespace) -> int:
    cfg = CLIConfig.load(_config_path())
    passphrase = _load_passphrase(cfg)
    client = _make_client(cfg, passphrase)
    inbox = client.receive_messages()
    if not inbox:
        print("(no new messages)")
        return 0

    # Reverse-lookup sender_signing_pk against known contacts when possible.
    # This requires the contact to match on the derived Ed25519 pubkey, which
    # is itself derived from their X25519 pubkey — cross-reference locally.
    from dmp.core.crypto import DMPCrypto
    known = {}
    for name, pubkey_hex in cfg.contacts.items():
        try:
            contact_crypto = DMPCrypto.from_private_bytes(bytes.fromhex(pubkey_hex))
        except Exception:
            continue
        # We can't actually derive the contact's signing key from just their
        # public key (the ED25519 seed is derived from the X25519 *private*
        # bytes). So we can't reverse-lookup names here — just show the hex.
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
    p_init.add_argument("--force", action="store_true", help="overwrite existing config")
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
        "--ttl", type=int, default=86400,
        help="TXT record TTL in seconds (default: 86400 = 1 day)",
    )
    p_id_pub.set_defaults(func=cmd_identity_publish)

    p_id_pk = sub_id.add_parser(
        "refresh-prekeys",
        help="generate and publish a fresh pool of one-time X3DH prekeys",
    )
    p_id_pk.add_argument(
        "--count", type=int, default=50,
        help="number of prekeys to generate (default 50)",
    )
    p_id_pk.add_argument(
        "--ttl", type=int, default=86400,
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
        "--add", action="store_true",
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
