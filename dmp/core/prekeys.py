"""X3DH-style one-time prekeys for forward secrecy.

Without prekeys, DMP's sender-ephemeral / recipient-long-term ECDH design
means anyone who later captures the recipient's long-term X25519 key can
decrypt all past stored ciphertexts — no forward secrecy.

With prekeys, the recipient publishes a pool of single-use X25519
keypairs signed by their Ed25519 identity. Senders pick an unused
prekey, use it in ECDH instead of the long-term key, and the recipient
deletes the matching prekey_sk after the first successful decrypt. Once
deleted, compromise of the long-term key does not decrypt that past
message — that is the forward-secrecy property.

This is not the full Signal X3DH: there is no pre-agreement ratchet, no
post-compromise security, and collisions between two senders choosing
the same prekey will lose the later sender's message. It is also
best-effort: a process crash between decrypt and deletion leaves the sk
on disk. The real win is the rotation model — refresh frequently, old
sks go away, past traffic becomes undecodable to anyone without the
session ciphertext.

Wire format (one TXT record per prekey, all at the same RRset name):

    prekeys.id-<username_hash12>.<domain>  IN TXT  "v=dmp1;t=prekey;d=<b64>"

body = prekey_id(4) || x25519_pub(32) || exp(8)   =  44 bytes
sig  = Ed25519 signature over body                =  64 bytes
total                                             = 108 bytes
base64                                            = 144 chars
prefix `v=dmp1;t=prekey;d=`                       =  18 chars
wire                                              = 162 chars (fits one TXT string)
"""

from __future__ import annotations

import base64
import hashlib
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass
from threading import RLock
from typing import List, Optional, Tuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from dmp.core.crypto import DMPCrypto

RECORD_PREFIX = "v=dmp1;t=prekey;d="
_BODY_LEN = 4 + 32 + 8  # prekey_id + pub + exp = 44
_SIG_LEN = 64
_WIRE_LEN = _BODY_LEN + _SIG_LEN  # 108 bytes

# Upper bound on how far in the future a prekey's signed `exp` can
# be. Operators typically refresh prekey pools daily; 30 days is
# generous headroom while bounding the local-store bloat a sender
# could induce by publishing pools with year-3000 expiries.
MAX_EXP_FUTURE_SECONDS = 30 * 86400


def prekey_rrset_name(username: str, base_domain: str) -> str:
    """DNS name at which a user's prekey pool is published.

    Matches the identity-record hashing scheme so callers don't need to
    juggle two different label formats.
    """
    username_hash = hashlib.sha256(username.encode("utf-8")).hexdigest()[:12]
    return f"prekeys.id-{username_hash}.{base_domain.rstrip('.')}"


@dataclass
class Prekey:
    """A single one-time prekey record (public side)."""

    prekey_id: int  # 4-byte unsigned, unique within an identity's pool
    public_key: bytes  # 32-byte X25519 pub
    exp: int  # unix seconds after which recipient may drop

    def to_body_bytes(self) -> bytes:
        # ``prekey_id == 0`` is reserved as the manifest sentinel
        # ``NO_PREKEY`` (see dmp.core.manifest); a signed record
        # carrying it would be ambiguous with the "no prekey
        # selected, fall back to long-term X25519" path on the
        # receiver. Refuse to construct such a record at all.
        if not (1 <= self.prekey_id < (1 << 32)):
            raise ValueError(
                "prekey_id out of range (must be 1..2^32-1; "
                "0 is reserved as NO_PREKEY)"
            )
        if len(self.public_key) != 32:
            raise ValueError("public_key must be 32 bytes")
        return (
            self.prekey_id.to_bytes(4, "big")
            + self.public_key
            + self.exp.to_bytes(8, "big")
        )

    @classmethod
    def from_body_bytes(cls, body: bytes) -> "Prekey":
        if len(body) != _BODY_LEN:
            raise ValueError(f"prekey body must be {_BODY_LEN} bytes, got {len(body)}")
        prekey_id = int.from_bytes(body[0:4], "big")
        # Reject the reserved NO_PREKEY value at parse time so a
        # malicious or buggy peer can't publish a signed prekey
        # record that the sender then picks, silently bypassing
        # forward secrecy on the manifest wire.
        if prekey_id == 0:
            raise ValueError(
                "prekey_id 0 is reserved as NO_PREKEY and not valid "
                "in a signed prekey record"
            )
        return cls(
            prekey_id=prekey_id,
            public_key=body[4:36],
            exp=int.from_bytes(body[36:44], "big"),
        )

    def sign(self, identity_crypto: DMPCrypto) -> str:
        body = self.to_body_bytes()
        sig = identity_crypto.sign_data(body)
        return f"{RECORD_PREFIX}{base64.b64encode(body + sig).decode('ascii')}"

    @classmethod
    def parse_and_verify(
        cls, record: str, expected_signer_spk: bytes
    ) -> Optional["Prekey"]:
        """Parse and verify a prekey TXT record.

        Returns the Prekey on success, None if malformed or signature fails
        against `expected_signer_spk`. Caller is responsible for supplying
        the right Ed25519 key — prekey records do not self-identify the
        signer (unlike SlotManifest).
        """
        if not record.startswith(RECORD_PREFIX):
            return None
        try:
            wire = base64.b64decode(record[len(RECORD_PREFIX) :])
        except Exception:
            return None
        if len(wire) != _WIRE_LEN:
            return None
        body, sig = wire[:_BODY_LEN], wire[_BODY_LEN:]
        try:
            pk = cls.from_body_bytes(body)
        except ValueError:
            return None
        if not DMPCrypto.verify_signature(body, sig, expected_signer_spk):
            return None
        # Refuse prekeys whose expiry is far in the future. A real
        # pool refreshes every day or so; a year-3000 `exp` would
        # let a sender pin a prekey in every recipient's local store
        # for the lifetime of the universe, blocking ID rotation
        # and consuming disk.
        if pk.exp - int(time.time()) > MAX_EXP_FUTURE_SECONDS:
            return None
        return pk

    def is_expired(self, now: Optional[int] = None) -> bool:
        now = int(time.time()) if now is None else now
        return now > self.exp


# Schema v1 as individual statements (NOT a script). ``executescript``
# does an implicit COMMIT before running, which would end the
# ``BEGIN IMMEDIATE`` transaction in ``_migrate`` and let two concurrent
# migrations race the ALTER. We issue each statement via ``execute`` to
# stay inside the explicit transaction.
_SCHEMA_V1_STATEMENTS: Tuple[str, ...] = (
    """
    CREATE TABLE IF NOT EXISTS prekeys (
        prekey_id INTEGER PRIMARY KEY,
        private_key BLOB NOT NULL,
        public_key BLOB NOT NULL,
        exp INTEGER NOT NULL,
        created_at INTEGER NOT NULL
    )
    """,
    "CREATE INDEX IF NOT EXISTS idx_prekeys_exp ON prekeys(exp)",
)

# v1 → v2: add wire_record so the client can DELETE the published
# prekey_pub from DNS when its sk is consumed. Without this, the
# published RRset would rot in DNS — senders keep picking sks that
# the recipient has already eaten.
_MIGRATION_V1_TO_V2 = "ALTER TABLE prekeys ADD COLUMN wire_record TEXT DEFAULT ''"

# Latest schema version this code understands. Bump on every schema-
# affecting change and add a v(N-1) → v(N) step in ``_migrate``.
_SCHEMA_VERSION = 2


class PrekeyStore:
    """Local, sqlite-backed store of one-time prekey *private* keys.

    Thread-safe via a per-store RLock. Opening the same db_path twice in
    one process hands out two independent connections; that's fine because
    sqlite itself handles cross-connection locking.

    The prekey_sk rows are the forward-secrecy secret. Protect the sqlite
    file with the same filesystem perms as the identity passphrase file
    (the CLI's `_make_client` wires them both out of `$DMP_CONFIG_HOME`).

    Schema versioning (P1): tracked via ``PRAGMA user_version``. Each
    bump adds a step to ``_migrate`` and increments ``_SCHEMA_VERSION``.
    Refuses to open databases stamped at a HIGHER version than this code
    knows — silently downgrading would risk dropping fields a newer
    binary added.
    """

    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        parent = os.path.dirname(db_path) or "."
        os.makedirs(parent, exist_ok=True)
        self._lock = RLock()
        # 30s busy-timeout: ``_migrate`` takes a reserved write lock via
        # ``BEGIN IMMEDIATE`` so concurrent opens on the same file
        # serialize. The default sqlite3 timeout (5s) is too tight under
        # load — when many other sqlite stores in the same process are
        # also active (test suite, busy CI), threads waiting on the
        # migration lock can hit ``database is locked`` before the
        # leader's transaction completes. 30s leaves headroom without
        # masking real deadlocks.
        self._conn = sqlite3.connect(
            db_path, isolation_level=None, check_same_thread=False, timeout=30.0
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._migrate()
        try:
            os.chmod(db_path, 0o600)
        except OSError:
            pass

    def _migrate(self) -> None:
        """Apply schema migrations atomically and idempotently.

        Versions:
          0 → 1: create the v1 schema (or no-op if tables already exist
                 from a pre-versioning binary; the original schema bytes
                 match the v1 definition).
          1 → 2: ADD COLUMN wire_record so consume-on-decrypt can DELETE
                 the published prekey_pub. Pre-existing v0 (unstamped)
                 databases that already have wire_record (from the
                 previous in-place migration) skip the ALTER and just
                 stamp version 2.

        Future schema bumps add v(N) → v(N+1) steps below.

        Concurrency: the per-instance ``RLock`` serializes within ONE
        ``PrekeyStore`` instance, but two instances on the same db file
        share nothing in-process. Without ``BEGIN IMMEDIATE`` below,
        both can read ``user_version=0``, both check ``wire_record``
        not present, and both attempt the ALTER — sqlite raises
        ``duplicate column name`` on the second. ``BEGIN IMMEDIATE``
        takes a sqlite-level reserved write lock, so concurrent
        migrations serialize via the file lock; the second connection
        waits, then sees the post-migration version and no-ops.
        """
        # autocommit (isolation_level=None) means we drive transactions
        # explicitly. BEGIN IMMEDIATE acquires the reserved lock now,
        # which is what makes read-then-write atomic against other
        # connections. A DEFERRED begin would let two transactions both
        # read user_version=0 and race the ALTER.
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            cur_version = self._conn.execute("PRAGMA user_version").fetchone()[0]
            if cur_version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"prekey store at {self.db_path!r} has schema version "
                    f"{cur_version}, but this binary only understands up to "
                    f"{_SCHEMA_VERSION}. Refusing to open — using an older "
                    f"client against a newer database would risk silently "
                    f"dropping fields."
                )
            # v0 → v1: ensure the v1 tables exist. Idempotent against
            # either a brand-new file OR an existing v0/v1/v2 file
            # (CREATE TABLE IF NOT EXISTS is a no-op when the table is
            # there).
            if cur_version < 1:
                for stmt in _SCHEMA_V1_STATEMENTS:
                    self._conn.execute(stmt)
                cur_version = 1
            # v1 → v2: add wire_record. Some pre-versioning databases
            # already have this column from the old in-place migration
            # — in that case skip the ALTER but still stamp the version.
            if cur_version < 2:
                cols = {
                    row[1]
                    for row in self._conn.execute(
                        "PRAGMA table_info(prekeys)"
                    ).fetchall()
                }
                if "wire_record" not in cols:
                    self._conn.execute(_MIGRATION_V1_TO_V2)
                cur_version = 2
            self._conn.execute(f"PRAGMA user_version = {cur_version}")
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def __enter__(self) -> "PrekeyStore":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    # ---- generation --------------------------------------------------------

    def generate_pool(
        self,
        count: int,
        ttl_seconds: int,
    ) -> List[Tuple[Prekey, X25519PrivateKey]]:
        """Generate `count` fresh prekeys and persist the private halves.

        Returns the (Prekey, X25519PrivateKey) list so the caller can
        immediately sign and publish the public side. The prekey_id is a
        32-bit random value; collisions with existing rows are retried.
        Callers should then call `record_wire(prekey_id, wire)` with the
        signed TXT record bytes so `consume()` can also DELETE the
        published record from DNS.
        """
        now = int(time.time())
        exp = now + ttl_seconds
        out: List[Tuple[Prekey, X25519PrivateKey]] = []
        with self._lock:
            for _ in range(count):
                # Random prekey_id, retry on collision OR on the
                # reserved value 0. ``NO_PREKEY = 0`` is the manifest
                # sentinel for "no prekey, fall back to long-term key"
                # (see dmp/core/manifest.py); a generator that returns 0
                # would silently strip forward secrecy from senders that
                # picked it, with the receiver indistinguishable from
                # the legitimate long-term-key path. The collision
                # probability against ``randbits(32)`` is 2^-32 per
                # draw, but rare events fire under enough load — the
                # one-line ``pid == 0`` check costs nothing and removes
                # the failure mode entirely.
                for _retry in range(10):
                    pid = secrets.randbits(32)
                    if pid == 0:
                        continue
                    exists = self._conn.execute(
                        "SELECT 1 FROM prekeys WHERE prekey_id = ?", (pid,)
                    ).fetchone()
                    if not exists:
                        break
                else:
                    raise RuntimeError("could not allocate unique prekey_id")

                sk = X25519PrivateKey.generate()
                sk_bytes = sk.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption(),
                )
                pk_bytes = sk.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )

                self._conn.execute(
                    "INSERT INTO prekeys "
                    "(prekey_id, private_key, public_key, exp, created_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (pid, sk_bytes, pk_bytes, exp, now),
                )
                out.append((Prekey(prekey_id=pid, public_key=pk_bytes, exp=exp), sk))
        return out

    def record_wire(self, prekey_id: int, wire_record: str) -> None:
        """Remember the signed TXT record bytes we published for this prekey.

        `consume()` uses it to DELETE the prekey from DNS so senders don't
        keep picking consumed entries. Callers should do this right after
        a successful publish.
        """
        with self._lock:
            self._conn.execute(
                "UPDATE prekeys SET wire_record = ? WHERE prekey_id = ?",
                (wire_record, prekey_id),
            )

    def get_wire(self, prekey_id: int) -> Optional[str]:
        """Return the stored wire-record string for `prekey_id`, or None."""
        with self._lock:
            row = self._conn.execute(
                "SELECT wire_record FROM prekeys WHERE prekey_id = ?",
                (prekey_id,),
            ).fetchone()
        if row is None or not row[0]:
            return None
        return str(row[0])

    # ---- lookup + consumption ---------------------------------------------

    def get_private_key(self, prekey_id: int) -> Optional[X25519PrivateKey]:
        """Return the sk for a given prekey_id, or None if absent / expired."""
        # Refuse the reserved sentinel even if a legacy/imported db
        # has a row at prekey_id=0. The manifest wire encodes "no
        # prekey, fall back to long-term key" as 0; a successful
        # lookup here would silently strip forward secrecy from a
        # session that the receiver was meant to recognize as the
        # legacy fallback path.
        if prekey_id == 0:
            return None
        with self._lock:
            row = self._conn.execute(
                "SELECT private_key FROM prekeys WHERE prekey_id = ? AND exp > ?",
                (prekey_id, int(time.time())),
            ).fetchone()
        if row is None:
            return None
        return X25519PrivateKey.from_private_bytes(row[0])

    def consume(self, prekey_id: int) -> bool:
        """Delete the sk for this prekey_id. Returns True if something was deleted.

        Called by the recipient right after a successful decrypt; once the
        row is gone, a later leak of the long-term X25519 key cannot
        recover the same session key.
        """
        # Same refusal as ``get_private_key``: the reserved sentinel
        # is not a consumable prekey. Don't delete a legacy id=0
        # row here either — leave it alone so an operator can audit
        # how it got there. (A separate one-off cleanup migration
        # could remove zero rows; out of scope for this fix.)
        if prekey_id == 0:
            return False
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM prekeys WHERE prekey_id = ?", (prekey_id,)
            )
            return cur.rowcount > 0

    # ---- bookkeeping -------------------------------------------------------

    def count_live(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM prekeys WHERE exp > ?",
                (int(time.time()),),
            ).fetchone()
        return int(row[0])

    def cleanup_expired(self) -> int:
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM prekeys WHERE exp <= ?", (int(time.time()),)
            )
            return cur.rowcount

    def list_live_ids(self) -> List[int]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT prekey_id FROM prekeys WHERE exp > ? ORDER BY prekey_id",
                (int(time.time()),),
            ).fetchall()
        return [int(r[0]) for r in rows]
