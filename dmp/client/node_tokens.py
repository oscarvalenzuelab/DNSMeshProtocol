"""Client-side per-node bearer token storage (M5.5 phase 4).

The node side of M5.5 issues per-user publish tokens via the
``/v1/registration/*`` endpoints. This module is the *client* side
of that contract: a tiny on-disk store under ``~/.dmp/tokens/`` that
remembers which token to send to which node, plus helpers so the
existing ``_HttpWriter`` can auto-attach the right bearer header
without every CLI command having to wire it explicitly.

Design anchor: ``docs/design/multi-tenant-auth.md`` (§ "Client-side
onboarding").

One file per node hostname under ``$DMP_TOKENS_HOME`` (default
``~/.dmp/tokens``), mode 0600. Files are JSON so an operator
eyeballing them can read the subject/expiry without launching a
tool. The raw token material is stored in plaintext — if an
attacker has read access to ``$HOME`` we have bigger problems than
token exfiltration, and encrypting at rest would require a passphrase
prompt on every publish which breaks the unattended flows (cron
jobs, scripted sends) we want to keep working.
"""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path
from typing import Iterable, Iterator, Optional
from urllib.parse import urlsplit


def tokens_home() -> Path:
    """Resolve the tokens directory, respecting ``DMP_TOKENS_HOME``.

    Matches the shape of other DMP config env vars. Fresh-install
    layout:
        ~/.dmp/config.yaml
        ~/.dmp/tokens/<host>.json
    """
    env = os.environ.get("DMP_TOKENS_HOME", "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".dmp" / "tokens"


# Limit filename characters to ASCII letters / digits / a small
# punctuation set so a malicious / typo'd hostname can't traverse
# out of the tokens dir.
_SAFE_HOSTNAME_RE = re.compile(r"^[a-z0-9](?:[a-z0-9.\-]{0,252}[a-z0-9])?$")


def _sanitize_hostname(hostname: str) -> str:
    """Lowercase, strip trailing dot, and verify against ASCII shape.

    Raises ``ValueError`` on anything that doesn't look like a plain
    DNS hostname. Matches the server's canonicalization (ASCII-only,
    no IDN for v1).
    """
    if not isinstance(hostname, str):
        raise ValueError("hostname must be a string")
    h = hostname.strip().strip(".").lower()
    if not h or not _SAFE_HOSTNAME_RE.match(h):
        raise ValueError(f"refusing unsafe token-dir filename: {hostname!r}")
    return h


def host_from_endpoint(endpoint: str) -> Optional[str]:
    """Extract a token-key hostname from a node HTTP endpoint URL.

    Returns ``None`` when the URL is malformed. Used by the
    ``_HttpWriter`` auto-attach path: caller passes the full
    endpoint URL, we reduce it to the hostname.
    """
    if not isinstance(endpoint, str):
        return None
    try:
        parsed = urlsplit(endpoint if "://" in endpoint else f"http://{endpoint}")
    except ValueError:
        return None
    host = parsed.hostname
    if not host:
        return None
    try:
        return _sanitize_hostname(host)
    except ValueError:
        return None


def _path_for(hostname: str) -> Path:
    safe = _sanitize_hostname(hostname)
    return tokens_home() / f"{safe}.json"


def save_token(
    hostname: str,
    *,
    token: str,
    subject: str,
    expires_at: Optional[int] = None,
    registered_spk: Optional[str] = None,
) -> Path:
    """Persist a token for ``hostname``. Mode 0600, atomic write.

    Overwrites any existing file for the same hostname.
    """
    target = _path_for(hostname)
    target.parent.mkdir(parents=True, exist_ok=True)
    # Tighten the parent dir mode if we just created it; don't
    # reset for existing ones (may be shared with other config).
    if (target.parent.stat().st_mode & 0o777) & 0o077:
        try:
            target.parent.chmod(0o700)
        except OSError:
            pass  # best-effort; caller sees the token write succeed or fail

    body = {
        "version": 1,
        "node": hostname,
        "subject": subject,
        "token": token,
        "expires_at": expires_at,
        "registered_spk": registered_spk,
        "saved_at": int(time.time()),
    }
    tmp = target.with_suffix(".json.tmp")
    # Open the tmp file with mode 0600 from the very first syscall
    # (os.open+O_CREAT honors the `mode` arg, unlike plain open()
    # which honors the process umask). Under a normal umask 022,
    # `open("w")` would create 0644 and only later chmod down —
    # a brief window during which another local user could read
    # the bearer. Using O_CREAT|O_EXCL also refuses to stomp on an
    # existing tmp left over from a prior crashed write.
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_TRUNC
    # O_EXCL fails if tmp exists (e.g. previous crash). Clear it so
    # the atomic write still goes through.
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(body, f, indent=2)
    except Exception:
        # Don't leave a partial write around on failure.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    os.replace(tmp, target)
    return target


def load_token(hostname: str) -> Optional[dict]:
    """Return the saved token record for ``hostname``, or ``None``.

    Silently ignores malformed files (returns ``None``) rather than
    raising — the auto-attach path must not break every publish just
    because one token file got corrupted.
    """
    try:
        safe = _sanitize_hostname(hostname)
    except ValueError:
        return None
    path = tokens_home() / f"{safe}.json"
    if not path.exists():
        return None
    try:
        with open(path, encoding="utf-8") as f:
            body = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(body, dict) or "token" not in body:
        return None
    return body


def delete_token(hostname: str) -> bool:
    """Remove the saved token for ``hostname`` if it exists."""
    try:
        path = _path_for(hostname)
    except ValueError:
        return False
    if not path.exists():
        return False
    try:
        path.unlink()
    except OSError:
        return False
    return True


def list_tokens() -> Iterator[dict]:
    """Yield every saved token record under the tokens home."""
    home = tokens_home()
    if not home.exists():
        return
    for path in sorted(home.glob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                body = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(body, dict) and "token" in body:
            yield body


def bearer_for_endpoint(endpoint: str) -> Optional[str]:
    """Look up the token material for an endpoint URL.

    Used by the ``_HttpWriter`` auto-attach path:
        token = bearer_for_endpoint("http://dmp.example.com:443/")
        -> "dmp_v1_..." if ~/.dmp/tokens/dmp.example.com.json exists,
           else None.

    Silently returns ``None`` on any lookup failure — callers fall
    through to their existing bearer source (env var / config).
    """
    host = host_from_endpoint(endpoint)
    if host is None:
        return None
    body = load_token(host)
    if body is None:
        return None
    token = body.get("token")
    if not isinstance(token, str) or not token:
        return None
    # Soft expiry check with clock-skew grace. If the file says
    # expires_at is deep in the past, refuse — sending it is a
    # guaranteed server-side 401 and an eager client-side reject
    # gives a cleaner CLI error. BUT: a client whose clock is a
    # few seconds fast (or a server whose clock is a few seconds
    # slow) would turn a perfectly valid token into a local
    # false-negative. Allow a 5-minute grace window and let the
    # server be authoritative for anything inside it.
    # `None` expires_at means "unknown / never expires".
    exp = body.get("expires_at")
    if isinstance(exp, (int, float)) and exp > 0:
        grace = 300  # seconds of client/server clock-skew tolerance
        if time.time() >= exp + grace:
            return None
    return token
