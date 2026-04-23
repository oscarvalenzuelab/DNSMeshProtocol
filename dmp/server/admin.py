"""Operator-side CLI for the per-user token store (M5.5).

Runs directly against the node's sqlite token DB. Intended to be
invoked from the host (or via ``docker exec``) by the node operator.

Entry point: ``dmp-node-admin`` (see setup.py console_scripts).

Commands:

  token issue <subject> [--expires DURATION] [--rate RATE] [--burst N]
                         [--note TEXT] [--with-prekey-scope X25519_HEX]
  token list   [--subject SUBJECT] [--include-revoked] [--json]
  token revoke <subject-or-hash-prefix>
  token rotate <subject>                    (revoke old, mint new)
  audit tail   [--event EVENT] [--limit N] [--json]

DB location: picked up from ``DMP_TOKEN_DB_PATH`` (default:
sibling of ``DMP_DB_PATH`` with ``_tokens`` suffix; falls back to
``/var/lib/dmp/tokens.db`` when neither is set). Override with
``--db`` for ad-hoc inspection.
"""

from __future__ import annotations

import argparse
import binascii
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Optional

from dmp.server.tokens import (
    DEFAULT_RATE_BURST,
    DEFAULT_RATE_PER_SEC,
    SUBJECT_TYPE_USER_IDENTITY,
    TokenRow,
    TokenStore,
    subject_hash12_for_x25519,
)


# ---------------------------------------------------------------------------
# DB resolution
# ---------------------------------------------------------------------------


def _default_db_path() -> str:
    """Resolve the token DB path with the same precedence the node uses."""
    if env := os.environ.get("DMP_TOKEN_DB_PATH"):
        return env
    record_db = os.environ.get("DMP_DB_PATH")
    if record_db:
        # Sibling filename: dmp.db -> dmp_tokens.db
        p = Path(record_db)
        stem = p.stem + "_tokens"
        return str(p.with_name(stem + p.suffix))
    return "/var/lib/dmp/tokens.db"


# ---------------------------------------------------------------------------
# Duration parsing — used by --expires
# ---------------------------------------------------------------------------


_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 86400 * 7}

# ASCII-strict duration shape. Deliberately tight: a bare digit run
# (seconds) or digits followed by exactly one of s/m/h/d/w. Rejects
# Unicode digits (Arabic-Indic, Devanagari, etc.) and non-ASCII
# whitespace that Python's .isdigit() and int() both silently accept.
_DURATION_RE = re.compile(r"^[0-9]+[smhdw]?$")


def parse_duration(s: str) -> int:
    """Parse '90d' / '12h' / '45m' / '300s' / '4w'. Bare digits = seconds.

    ASCII-strict: non-ASCII digits and non-ASCII whitespace are
    rejected, not silently coerced. ``int('١٠')`` returns 10 (Arabic-
    Indic digits); we want ``--expires ١٠s`` to fail loudly so an
    operator copy-pasting from a mixed-locale context gets an error
    instead of a surprising value.
    """
    if not isinstance(s, str):
        raise ValueError("duration must be a string")
    # strip() removes non-ASCII whitespace too; we only want to be
    # forgiving of leading/trailing ASCII space, so match-on-stripped
    # and also reject anything outside our regex.
    s = s.strip(" \t\r\n")
    if not s:
        raise ValueError("empty duration")
    if not _DURATION_RE.match(s):
        raise ValueError(
            f"bad duration {s!r}: expected digits with optional unit s/m/h/d/w"
        )
    if s[-1].isascii() and s[-1] in _DURATION_UNITS:
        unit = s[-1]
        n = int(s[:-1])
        return n * _DURATION_UNITS[unit]
    return int(s)


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------


def _row_to_dict(row: TokenRow) -> dict:
    return {
        "token_hash": row.token_hash,
        "subject": row.subject,
        "subject_type": row.subject_type,
        "subject_hash12": row.subject_hash12,
        "rate_per_sec": row.rate_per_sec,
        "rate_burst": row.rate_burst,
        "issued_at": row.issued_at,
        "expires_at": row.expires_at,
        "revoked_at": row.revoked_at,
        "issuer": row.issuer,
        "note": row.note,
        "live": row.is_live(),
    }


def _fmt_ts(ts: Optional[int]) -> str:
    if ts is None:
        return "-"
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def _print_row_table(rows: list) -> None:
    if not rows:
        print("(no tokens)")
        return
    header = ("HASH-PREFIX", "SUBJECT", "ISSUED", "EXPIRES", "REVOKED", "STATUS")
    print("  ".join(f"{h:<20}" for h in header))
    for r in rows:
        status = "live" if r.is_live() else "inactive"
        print("  ".join([
            f"{r.token_hash[:16]:<20}",
            f"{r.subject:<20}",
            f"{_fmt_ts(r.issued_at):<20}",
            f"{_fmt_ts(r.expires_at):<20}",
            f"{_fmt_ts(r.revoked_at):<20}",
            f"{status:<20}",
        ]))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_token_issue(args: argparse.Namespace, store: TokenStore) -> int:
    expires_in: Optional[int] = None
    if args.expires:
        try:
            expires_in = parse_duration(args.expires)
        except ValueError as exc:
            print(f"error: --expires: {exc}", file=sys.stderr)
            return 2

    subject_hash12: Optional[str] = None
    if args.with_prekey_scope:
        try:
            x25519_pk = binascii.unhexlify(args.with_prekey_scope)
        except binascii.Error:
            print(
                "error: --with-prekey-scope: value must be hex "
                "(32 bytes / 64 chars)",
                file=sys.stderr,
            )
            return 2
        if len(x25519_pk) != 32:
            print(
                f"error: --with-prekey-scope: expected 32-byte x25519 pubkey, "
                f"got {len(x25519_pk)} bytes",
                file=sys.stderr,
            )
            return 2
        subject_hash12 = subject_hash12_for_x25519(x25519_pk)

    token, row = store.issue(
        args.subject,
        subject_type=SUBJECT_TYPE_USER_IDENTITY,
        subject_hash12=subject_hash12,
        rate_per_sec=args.rate,
        rate_burst=args.burst,
        expires_in_seconds=expires_in,
        issuer=f"admin:{os.environ.get('USER', 'unknown')}",
        note=args.note or "",
    )

    if args.json:
        print(json.dumps({
            "token": token,
            "subject": row.subject,
            "subject_hash12": row.subject_hash12,
            "expires_at": row.expires_at,
            "rate_per_sec": row.rate_per_sec,
            "rate_burst": row.rate_burst,
        }, indent=2))
    else:
        print(f"  subject:    {row.subject}")
        if row.subject_hash12:
            print(f"  prekey h12: {row.subject_hash12}")
        print(f"  rate:       {row.rate_per_sec} req/s  burst={row.rate_burst}")
        print(f"  expires:    {_fmt_ts(row.expires_at)}")
        print()
        print(f"  token (copy this NOW — it will never be shown again):")
        print(f"      {token}")
        print()
        if row.note:
            print(f"  note: {row.note}")
    return 0


def cmd_token_list(args: argparse.Namespace, store: TokenStore) -> int:
    rows = store.list(
        include_revoked=args.include_revoked,
        subject=args.subject,
    )
    if args.json:
        print(json.dumps([_row_to_dict(r) for r in rows], indent=2))
    else:
        _print_row_table(rows)
    return 0


def cmd_token_revoke(args: argparse.Namespace, store: TokenStore) -> int:
    target = args.target
    # First try as an exact subject match.
    by_subject = store.revoke_by_subject(target)
    if by_subject > 0:
        print(f"revoked {by_subject} token(s) for subject {target!r}")
        return 0
    # Otherwise treat target as a token-hash prefix; require unambiguous match.
    matches = [
        r for r in store.list(include_revoked=False)
        if r.token_hash.startswith(target.lower())
    ]
    if not matches:
        print(f"no live token found for subject or hash-prefix {target!r}",
              file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(
            f"hash prefix {target!r} is ambiguous — matches {len(matches)} "
            "tokens. Use a longer prefix or an exact subject.",
            file=sys.stderr,
        )
        return 2
    ok = store.revoke(matches[0].token_hash)
    if ok:
        print(f"revoked token {matches[0].token_hash[:16]}… "
              f"(subject {matches[0].subject})")
        return 0
    print("revoke failed (race?)", file=sys.stderr)
    return 1


def cmd_token_rotate(args: argparse.Namespace, store: TokenStore) -> int:
    # Rotate: revoke all live tokens for subject, mint a fresh one.
    # Deliberately NOT atomic across processes — if the operator runs
    # two rotates simultaneously the second one revokes the first's
    # new token on its revoke-by-subject pass. That's their problem;
    # don't do that.
    revoked = store.revoke_by_subject(args.subject)
    token, row = store.issue(
        args.subject,
        rate_per_sec=args.rate, rate_burst=args.burst,
        expires_in_seconds=parse_duration(args.expires) if args.expires else None,
        issuer=f"admin:{os.environ.get('USER', 'unknown')}:rotate",
        note="rotation",
    )
    print(f"revoked {revoked} old token(s) for {args.subject!r}")
    print(f"new token:")
    print(f"  {token}")
    return 0


def cmd_audit_tail(args: argparse.Namespace, store: TokenStore) -> int:
    rows = store.audit_rows(event=args.event, limit=args.limit)
    if args.json:
        out = [
            {
                "ts": ts, "event": ev, "token_hash": th, "subject": sj,
                "remote_addr": ra, "detail": de,
            }
            for (ts, ev, th, sj, ra, de) in rows
        ]
        print(json.dumps(out, indent=2))
    else:
        for ts, ev, th, sj, ra, de in rows:
            th_disp = (th[:12] + "…") if th else "-"
            print(
                f"{_fmt_ts(ts)}  {ev:<10}  "
                f"subject={sj or '-':<24}  "
                f"hash={th_disp}  "
                f"addr={ra or '-':<16}  "
                f"{de or ''}"
            )
    return 0


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmp-node-admin",
        description="Operator CLI for the dmp-node multi-tenant token store.",
    )
    p.add_argument(
        "--db",
        default=None,
        help="Path to the token sqlite DB "
             "(default: $DMP_TOKEN_DB_PATH or /var/lib/dmp/tokens.db)",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # ---- token ----
    p_tok = sub.add_parser("token", help="manage publish tokens")
    p_tok_sub = p_tok.add_subparsers(dest="tok_cmd", required=True)

    p_issue = p_tok_sub.add_parser("issue", help="mint a new token for a subject")
    p_issue.add_argument("subject", help="e.g. alice@example.com")
    p_issue.add_argument("--expires", help="duration like 90d, 12h, 300s; default: no expiry")
    p_issue.add_argument("--rate", type=float, default=DEFAULT_RATE_PER_SEC,
                         help=f"req/s (default: {DEFAULT_RATE_PER_SEC})")
    p_issue.add_argument("--burst", type=int, default=DEFAULT_RATE_BURST,
                         help=f"burst budget (default: {DEFAULT_RATE_BURST})")
    p_issue.add_argument("--note", help="free-form operator annotation")
    p_issue.add_argument(
        "--with-prekey-scope",
        metavar="X25519_HEX",
        help="32-byte hex X25519 pubkey — binds the token's prekey scope "
             "(pk-*.<hash12>.*) to that key's hash. Required for the user "
             "to publish their own prekeys.",
    )
    p_issue.add_argument("--json", action="store_true",
                         help="emit JSON instead of the human-readable banner")
    p_issue.set_defaults(func=cmd_token_issue)

    p_list = p_tok_sub.add_parser("list", help="list tokens")
    p_list.add_argument("--subject", help="filter to one subject")
    p_list.add_argument("--include-revoked", action="store_true",
                        help="include revoked tokens in the output")
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_token_list)

    p_rev = p_tok_sub.add_parser("revoke",
                                  help="revoke by exact subject OR by token-hash prefix")
    p_rev.add_argument("target", help="subject (e.g. alice@example.com) or hash prefix")
    p_rev.set_defaults(func=cmd_token_revoke)

    p_rot = p_tok_sub.add_parser(
        "rotate",
        help="revoke all live tokens for a subject and mint a fresh one",
    )
    p_rot.add_argument("subject")
    p_rot.add_argument("--expires")
    p_rot.add_argument("--rate", type=float, default=DEFAULT_RATE_PER_SEC)
    p_rot.add_argument("--burst", type=int, default=DEFAULT_RATE_BURST)
    p_rot.set_defaults(func=cmd_token_rotate)

    # ---- audit ----
    p_audit = sub.add_parser("audit", help="inspect the audit log")
    p_audit_sub = p_audit.add_subparsers(dest="audit_cmd", required=True)
    p_tail = p_audit_sub.add_parser("tail", help="tail recent audit rows")
    p_tail.add_argument("--event",
                        help="filter: issued|revoked|used|rejected")
    p_tail.add_argument("--limit", type=int, default=50)
    p_tail.add_argument("--json", action="store_true")
    p_tail.set_defaults(func=cmd_audit_tail)

    return p


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    db_path = args.db or _default_db_path()
    parent = Path(db_path).parent
    if not parent.exists():
        # Operator is pointing at a bogus path OR the node has never
        # started. Fail loud rather than silently creating a DB in a
        # surprising location.
        print(
            f"error: DB parent directory does not exist: {parent}. "
            f"Start the node at least once, or pass --db explicitly.",
            file=sys.stderr,
        )
        return 2

    store = TokenStore(db_path)
    try:
        return int(args.func(args, store))
    finally:
        store.close()


if __name__ == "__main__":
    sys.exit(main())
