"""Tests for dmp.server.tokens — the per-user token store (M5.5 phase 1)."""

from __future__ import annotations

import hashlib
import os
import tempfile
import time
from pathlib import Path

import pytest

from dmp.server.tokens import (
    DEFAULT_RATE_BURST,
    DEFAULT_RATE_PER_SEC,
    ScopeClass,
    SUBJECT_TYPE_USER_IDENTITY,
    TokenStore,
    _sha256_hex,
    classify_name,
    generate_token,
    subject_hash12_for_x25519,
    token_looks_valid,
)

# ---------------------------------------------------------------------------
# Token generation + shape checks
# ---------------------------------------------------------------------------


class TestTokenShape:
    def test_generate_is_unique(self) -> None:
        # 2^256 random — collisions here would indicate a broken RNG.
        seen = {generate_token() for _ in range(256)}
        assert len(seen) == 256

    def test_generate_is_recognizable(self) -> None:
        t = generate_token()
        assert t.startswith("dmp_v1_")
        assert token_looks_valid(t)

    def test_looks_valid_rejects_shape_mismatches(self) -> None:
        assert not token_looks_valid("")
        assert not token_looks_valid("dmp_v1_")
        assert not token_looks_valid("wrongprefix_" + "A" * 52)
        assert not token_looks_valid("dmp_v1_" + "a" * 52)  # lowercase body
        assert not token_looks_valid("dmp_v1_" + "A" * 51)  # one short
        assert not token_looks_valid("dmp_v1_" + "A" * 53)  # one long
        assert not token_looks_valid("Bearer dmp_v1_" + "A" * 52)


# ---------------------------------------------------------------------------
# Name classification
# ---------------------------------------------------------------------------


class TestClassifyName:
    def test_identity_record_is_owner_exclusive(self) -> None:
        s = classify_name("dmp.alice.example.com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "alice@example.com"

    def test_identity_record_multi_label_domain(self) -> None:
        s = classify_name("dmp.alice.sub.example.co.uk")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "alice@sub.example.co.uk"

    def test_rotation_zone_anchored_is_owner_exclusive(self) -> None:
        s = classify_name("rotate.dmp.alice.example.com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "alice@example.com"

    def test_rotation_hash_form_is_operator_only(self) -> None:
        # Deliberately rejected from end-user tokens in v1; operators
        # can still publish via DMP_OPERATOR_TOKEN.
        s = classify_name("rotate.dmp.id-abc123def456.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY

    def test_prekey_is_owner_exclusive_hash_scoped(self) -> None:
        s = classify_name("pk-7.abcdef012345.example.com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        # Marked as hash-form via the '#' prefix in subject, to
        # distinguish from a literal username containing 'abcdef'.
        assert s.subject == "#abcdef012345"

    def test_mailbox_slot_is_shared_pool(self) -> None:
        s = classify_name("slot-3.mb-abcdef012345.example.com")
        assert s.kind == ScopeClass.SHARED_POOL

    def test_chunk_is_shared_pool(self) -> None:
        s = classify_name("chunk-0007-abcdef012345.example.com")
        assert s.kind == ScopeClass.SHARED_POOL

    def test_case_insensitive(self) -> None:
        s = classify_name("DMP.Alice.Example.Com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "alice@example.com"

    def test_trailing_dot_is_stripped(self) -> None:
        s = classify_name("dmp.alice.example.com.")
        assert s.subject == "alice@example.com"

    def test_unknown_prefix_is_operator_only(self) -> None:
        # Fail-closed: anything we don't recognize is OPERATOR_ONLY,
        # not SHARED_POOL. Forgetting to extend the classifier must
        # not accidentally widen what an end-user token can publish.
        s = classify_name("cluster.mesh.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY

        s = classify_name("bootstrap.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY

        s = classify_name("random.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY

    def test_empty_or_malformed_is_unknown(self) -> None:
        assert classify_name("").kind == ScopeClass.UNKNOWN
        assert classify_name("singlelabel").kind == ScopeClass.UNKNOWN
        assert classify_name("dmp").kind == ScopeClass.UNKNOWN


class TestClassifyRegressions:
    """Regression tests for codex-flagged fail-open bypasses."""

    def test_slot_with_empty_label_rejected(self) -> None:
        # Without strict shape validation, `slot-1..example.com` would
        # classify as SHARED_POOL on first-label prefix alone.
        s = classify_name("slot-1..example.com")
        assert s.kind == ScopeClass.UNKNOWN

    def test_slot_without_mb_label_rejected(self) -> None:
        # A name whose first label is slot-* but whose second label
        # isn't `mb-<hash12>` is malformed, not a mailbox.
        s = classify_name("slot-1.dmp.alice.example.com")
        assert s.kind != ScopeClass.SHARED_POOL

    def test_slot_bogus_hash12_rejected(self) -> None:
        # hash12 must be exactly 12 hex chars; a shorter string
        # would previously sneak through.
        s = classify_name("slot-1.mb-abc.example.com")
        assert s.kind != ScopeClass.SHARED_POOL

    def test_chunk_with_bootstrap_suffix_rejected(self) -> None:
        # `chunk-x.bootstrap.example.com` used to be SHARED_POOL on
        # first-label startswith match; now rejected.
        s = classify_name("chunk-x.bootstrap.example.com")
        assert s.kind != ScopeClass.SHARED_POOL

    def test_chunk_wrong_prefix_shape_rejected(self) -> None:
        s = classify_name("chunk-foo-bar.example.com")
        assert s.kind != ScopeClass.SHARED_POOL

    def test_non_ascii_name_rejected(self) -> None:
        # Unicode labels must not slip through — DMP names are ASCII
        # only. Uses fullwidth Latin 'a' which lowercases differently
        # but looks like ASCII.
        s = classify_name("dmp.ａlice.example.com")
        assert s.kind == ScopeClass.UNKNOWN

    def test_leading_or_trailing_dot_rejected(self) -> None:
        assert classify_name(".dmp.alice.example.com").kind == ScopeClass.UNKNOWN

    def test_identity_requires_single_label_user(self) -> None:
        # dmp.<user>.<domain> — user must be a single label, otherwise
        # user/domain split is ambiguous.
        s = classify_name("dmp.alice.sub.example.com")
        # alice, sub.example.com — this is the intended interpretation.
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "alice@sub.example.com"


class TestCanonicalizeSubject:
    """Regression tests for the Unicode-homoglyph subject-compare P1."""

    def test_plain_ascii_passes_through(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        assert canonicalize_subject("alice@example.com") == "alice@example.com"

    def test_case_is_lowered(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        assert canonicalize_subject("Alice@Example.Com") == "alice@example.com"

    def test_nfkc_compatibility_character_rejected_or_canonicalized(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        # Fullwidth Latin 'a' (U+FF41) normalizes to ASCII 'a' under
        # NFKC; after normalization it passes ASCII + shape.
        out = canonicalize_subject("ａlice@example.com")
        assert out == "alice@example.com"

    def test_non_nfkc_unicode_rejected(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        # Cyrillic 'а' (U+0430) looks like Latin 'a' but has no ASCII
        # NFKC mapping — must be rejected.
        with pytest.raises(ValueError):
            canonicalize_subject("аlice@example.com")

    def test_empty_subject_rejected(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        with pytest.raises(ValueError):
            canonicalize_subject("")
        with pytest.raises(ValueError):
            canonicalize_subject("   ")

    def test_malformed_shape_rejected(self) -> None:
        from dmp.server.tokens import canonicalize_subject

        for bad in [
            "noatsign",
            "@example.com",
            "alice@",
            "alice@example",  # need >=2 domain labels
            "alice with space@example.com",
        ]:
            with pytest.raises(ValueError, match="subject"):
                canonicalize_subject(bad)

    def test_issue_canonicalizes(self, store: TokenStore) -> None:
        _, row = store.issue("Alice@Example.COM")
        assert row.subject == "alice@example.com"

    def test_issue_rejects_non_ascii(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            store.issue("аlice@example.com")  # Cyrillic 'а'

    def test_homoglyph_does_not_authorize(self, store: TokenStore) -> None:
        """The headline P1 regression: a token for one subject must
        not authorize writes under a visually-identical but distinct
        subject."""
        # Token for Cyrillic-а subject cannot be issued at all.
        with pytest.raises(ValueError):
            store.issue("аlice@example.com")
        # Plain ASCII token cannot publish under a Cyrillic-lookalike
        # record name either — classify_name rejects non-ASCII.
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "dmp.аlice.example.com")
        assert not r.ok


# ---------------------------------------------------------------------------
# Store: issuance / revocation / lookup
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: Path) -> TokenStore:
    db = str(tmp_path / "tokens.db")
    s = TokenStore(db)
    yield s
    s.close()


class TestIssuanceAndLookup:
    def test_issue_returns_token_and_row(self, store: TokenStore) -> None:
        token, row = store.issue("alice@example.com", issuer="test", note="unit")
        assert token.startswith("dmp_v1_")
        assert row.subject == "alice@example.com"
        assert row.subject_type == SUBJECT_TYPE_USER_IDENTITY
        assert row.rate_per_sec == DEFAULT_RATE_PER_SEC
        assert row.rate_burst == DEFAULT_RATE_BURST
        assert row.revoked_at is None
        assert row.issuer == "test"
        assert row.note == "unit"
        # The hash stored MUST be sha256 of the token material.
        assert row.token_hash == _sha256_hex(token)

    def test_token_material_is_never_persisted(self, store: TokenStore) -> None:
        """The literal token string must not appear in the DB file."""
        token, _ = store.issue("alice@example.com")
        with open(store._path, "rb") as f:
            raw = f.read()
        assert (
            token.encode("ascii") not in raw
        ), "Token material leaked into on-disk sqlite"

    def test_issue_is_monotonic(self, store: TokenStore) -> None:
        t1, r1 = store.issue("alice@example.com")
        time.sleep(0.001)
        t2, r2 = store.issue("bob@example.com")
        assert t1 != t2
        assert r1.token_hash != r2.token_hash

    def test_list_excludes_revoked_by_default(self, store: TokenStore) -> None:
        _, a = store.issue("alice@example.com")
        _, b = store.issue("bob@example.com")
        assert store.revoke(a.token_hash) is True

        live = store.list()
        assert [r.subject for r in live] == ["bob@example.com"]

        all_rows = store.list(include_revoked=True)
        assert sorted(r.subject for r in all_rows) == [
            "alice@example.com",
            "bob@example.com",
        ]

    def test_revoke_is_idempotent(self, store: TokenStore) -> None:
        _, row = store.issue("alice@example.com")
        assert store.revoke(row.token_hash) is True
        assert store.revoke(row.token_hash) is False  # already revoked

    def test_revoke_by_subject(self, store: TokenStore) -> None:
        store.issue("alice@example.com", note="a")
        store.issue("alice@example.com", note="b")
        store.issue("bob@example.com", note="c")

        n = store.revoke_by_subject("alice@example.com")
        assert n == 2

        live = store.list()
        assert len(live) == 1
        assert live[0].subject == "bob@example.com"


# ---------------------------------------------------------------------------
# Store: expiry
# ---------------------------------------------------------------------------


class TestExpiry:
    def test_expired_token_is_not_live(self, store: TokenStore) -> None:
        token, row = store.issue("alice@example.com", expires_in_seconds=-1)
        assert row.is_live() is False

    def test_expired_token_rejected_from_authorize(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com", expires_in_seconds=-1)
        result = store.authorize_write(token, "dmp.alice.example.com")
        assert not result.ok
        assert "expired" in result.reason.lower() or "revoked" in result.reason.lower()


# ---------------------------------------------------------------------------
# Store: authorize_write — the security core
# ---------------------------------------------------------------------------


class TestAuthorizeOwnerExclusive:
    def test_owner_can_publish_own_identity(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "dmp.alice.example.com")
        assert r.ok
        assert r.scope.kind == ScopeClass.OWNER_EXCLUSIVE

    def test_owner_cannot_publish_other_identity(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "dmp.bob.example.com")
        assert not r.ok
        assert "subject" in r.reason.lower()

    def test_owner_can_publish_own_rotation(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "rotate.dmp.alice.example.com")
        assert r.ok

    def test_owner_cannot_publish_other_rotation(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "rotate.dmp.mallory.example.com")
        assert not r.ok

    def test_prekey_requires_matching_hash12(self, store: TokenStore) -> None:
        x25519_pk = b"\x01" * 32
        h12 = subject_hash12_for_x25519(x25519_pk)
        token, _ = store.issue(
            "alice@example.com",
            subject_hash12=h12,
        )
        name_ok = f"pk-7.{h12}.example.com"
        r = store.authorize_write(token, name_ok)
        assert r.ok

        # Different hash12 must be rejected.
        h12_other = "a" * 12
        r = store.authorize_write(token, f"pk-7.{h12_other}.example.com")
        assert not r.ok

    def test_prekey_without_subject_hash12_on_token_rejected(
        self, store: TokenStore
    ) -> None:
        token, _ = store.issue("alice@example.com")  # no subject_hash12
        r = store.authorize_write(token, "pk-0.abcdef012345.example.com")
        assert not r.ok

    def test_case_insensitive_subject_match(self, store: TokenStore) -> None:
        token, _ = store.issue("Alice@Example.Com")
        r = store.authorize_write(token, "dmp.alice.example.com")
        assert r.ok


class TestClassifyHashedNames:
    """The CLI's default unanchored flow publishes identity at
    ``id-<hash16>.<domain>`` and prekeys at ``prekeys.id-<hash12>.<domain>``.
    Both must classify as OWNER_EXCLUSIVE so per-user tokens can write
    them; otherwise the multi-tenant flow only works for zone-anchored
    deployments (the much rarer case)."""

    def test_hashed_identity_is_owner_exclusive(self) -> None:
        s = classify_name("id-abcdef0123456789.example.com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "#id16:abcdef0123456789@example.com"

    def test_hashed_identity_multi_label_domain(self) -> None:
        s = classify_name("id-abcdef0123456789.sub.example.co.uk")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "#id16:abcdef0123456789@sub.example.co.uk"

    def test_hashed_identity_wrong_length_is_operator_only(self) -> None:
        # 12 hex chars where 16 are expected — fail closed.
        s = classify_name("id-abcdef012345.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY

    def test_prekey_pool_is_owner_exclusive(self) -> None:
        s = classify_name("prekeys.id-abcdef012345.example.com")
        assert s.kind == ScopeClass.OWNER_EXCLUSIVE
        assert s.subject == "#prekeys:abcdef012345@example.com"

    def test_prekey_pool_wrong_length_is_operator_only(self) -> None:
        s = classify_name("prekeys.id-abcdef0123456789.example.com")
        assert s.kind == ScopeClass.OPERATOR_ONLY


class TestAuthorizeHashedIdentityAndPrekeys:
    """Per-user token must be able to write its own hashed identity +
    prekey pool, but not someone else's, and not its own under a
    different domain."""

    @staticmethod
    def _h(s: str, n: int) -> str:
        return hashlib.sha256(s.encode("utf-8")).hexdigest()[:n]

    def test_owner_publishes_own_hashed_identity(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        name = f"id-{self._h('alice', 16)}.example.com"
        r = store.authorize_write(token, name)
        assert r.ok
        assert r.scope.kind == ScopeClass.OWNER_EXCLUSIVE

    def test_owner_blocked_from_other_users_hashed_identity(
        self, store: TokenStore
    ) -> None:
        token, _ = store.issue("alice@example.com")
        name = f"id-{self._h('bob', 16)}.example.com"
        r = store.authorize_write(token, name)
        assert not r.ok
        assert "hashed" in r.reason.lower()

    def test_owner_blocked_from_own_hash_in_other_domain(
        self, store: TokenStore
    ) -> None:
        # alice@example.com cannot publish id-<h(alice)>.evil.com even
        # though the hash matches — the domain half of the sentinel
        # binds the record to the token's home zone.
        token, _ = store.issue("alice@example.com")
        name = f"id-{self._h('alice', 16)}.evil.com"
        r = store.authorize_write(token, name)
        assert not r.ok

    def test_owner_publishes_own_prekey_pool(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        name = f"prekeys.id-{self._h('alice', 12)}.example.com"
        r = store.authorize_write(token, name)
        assert r.ok

    def test_owner_blocked_from_other_users_prekey_pool(
        self, store: TokenStore
    ) -> None:
        token, _ = store.issue("alice@example.com")
        name = f"prekeys.id-{self._h('bob', 12)}.example.com"
        r = store.authorize_write(token, name)
        assert not r.ok


class TestAuthorizeSharedPool:
    def test_any_live_token_can_publish_mailbox(self, store: TokenStore) -> None:
        alice_token, _ = store.issue("alice@example.com")
        # Alice can deliver to bob's mailbox without any scope match.
        r = store.authorize_write(alice_token, "slot-3.mb-abcdef012345.example.com")
        assert r.ok
        assert r.is_shared_pool

    def test_any_live_token_can_publish_chunk(self, store: TokenStore) -> None:
        alice_token, _ = store.issue("alice@example.com")
        r = store.authorize_write(alice_token, "chunk-0001-abcdef012345.example.com")
        assert r.ok
        assert r.is_shared_pool

    def test_revoked_token_cannot_publish_shared_pool(self, store: TokenStore) -> None:
        token, row = store.issue("alice@example.com")
        store.revoke(row.token_hash)
        r = store.authorize_write(token, "chunk-0001-abcdef012345.example.com")
        assert not r.ok


class TestAuthorizeOperatorOnly:
    def test_end_user_token_cannot_publish_cluster(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "cluster.mesh.example.com")
        assert not r.ok
        assert "operator" in r.reason.lower()

    def test_end_user_token_cannot_publish_bootstrap(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "bootstrap.example.com")
        assert not r.ok

    def test_end_user_token_cannot_publish_hash_form_rotation(
        self, store: TokenStore
    ) -> None:
        # Rotation hash form is reserved for operators in v1.
        token, _ = store.issue("alice@example.com")
        r = store.authorize_write(token, "rotate.dmp.id-abc123def456.example.com")
        assert not r.ok


class TestAuthorizeMalformed:
    def test_malformed_token_rejected_fast(self, store: TokenStore) -> None:
        r = store.authorize_write("not-a-real-token", "dmp.alice.example.com")
        assert not r.ok
        assert "malformed" in r.reason.lower()

    def test_unknown_token_rejected(self, store: TokenStore) -> None:
        # Well-formed but not in DB.
        bogus = generate_token()
        r = store.authorize_write(bogus, "dmp.alice.example.com")
        assert not r.ok
        assert "unknown" in r.reason.lower()


# ---------------------------------------------------------------------------
# Audit policy — the anonymity-preserving split
# ---------------------------------------------------------------------------


class TestAuditSplit:
    def test_issuance_logs_subject(self, store: TokenStore) -> None:
        _, row = store.issue("alice@example.com", issuer="admin")
        rows = store.audit_rows(event="issued")
        assert len(rows) == 1
        ts, event, tok, subj, addr, detail = rows[0]
        assert event == "issued"
        assert subj == "alice@example.com"
        assert tok == row.token_hash

    def test_revocation_logs_subject(self, store: TokenStore) -> None:
        _, row = store.issue("alice@example.com")
        store.revoke(row.token_hash)
        rows = store.audit_rows(event="revoked")
        assert len(rows) == 1
        _, _, tok, subj, _, _ = rows[0]
        assert subj == "alice@example.com"
        assert tok == row.token_hash

    def test_owner_write_logs_subject(self, store: TokenStore) -> None:
        token, row = store.issue("alice@example.com")
        store.authorize_write(token, "dmp.alice.example.com")
        # The "used" audit row should carry subject + token_hash.
        used = [r for r in store.audit_rows(event="used")]
        assert len(used) == 1
        _, _, tok, subj, _, detail = used[0]
        assert subj == "alice@example.com"
        assert tok == row.token_hash
        assert "owner" in (detail or "").lower()

    def test_shared_pool_write_does_NOT_log_subject_or_token(
        self, store: TokenStore
    ) -> None:
        """The headline anonymity property: a shared-pool write leaves
        only ts + remote_addr in the durable audit. An operator handed
        this sqlite cannot reconstruct who-sent-to-whom."""
        token, row = store.issue("alice@example.com")
        store.authorize_write(
            token,
            "chunk-0001-abcdef012345.example.com",
            remote_addr="10.0.0.7",
        )
        used = store.audit_rows(event="used")
        assert len(used) == 1
        ts, event, tok, subj, addr, detail = used[0]
        assert event == "used"
        assert tok is None, f"shared-pool audit must not carry token_hash; got {tok!r}"
        assert subj is None, f"shared-pool audit must not carry subject; got {subj!r}"
        assert addr == "10.0.0.7"  # remote_addr is intentionally kept
        assert "shared" in (detail or "").lower()

    def test_rejected_writes_logged(self, store: TokenStore) -> None:
        token, _ = store.issue("alice@example.com")
        store.authorize_write(token, "dmp.bob.example.com", remote_addr="10.0.0.7")
        rejects = store.audit_rows(event="rejected")
        assert len(rejects) == 1
        _, _, _, _, addr, _ = rejects[0]
        assert addr == "10.0.0.7"


class TestSchemaVersioning:
    """Migration ladder for TokenStore.

    Versions:
      v1 = original schema (no registered_spk column)
      v2 = current schema (registered_spk inline)

    Pre-versioning binaries either already ran the inline ALTER (no
    user_version stamp) or never did (legacy v1 schema). The ladder
    handles both.
    """

    def test_fresh_db_is_stamped_at_current_version(self, tmp_path):
        from dmp.server.tokens import _SCHEMA_VERSION, TokenStore

        store = TokenStore(str(tmp_path / "fresh.db"))
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == _SCHEMA_VERSION
            cols = {
                row[1]
                for row in store._conn.execute("PRAGMA table_info(tokens)").fetchall()
            }
            assert "registered_spk" in cols
        finally:
            store.close()

    def test_legacy_v1_db_migrates_to_v2(self, tmp_path):
        """A db created by the original tokens schema (no
        registered_spk, user_version=0) gets the column added on
        open and the version stamped. Existing rows are preserved.
        """
        import sqlite3

        from dmp.server.tokens import TokenStore

        path = str(tmp_path / "legacy.db")
        legacy = sqlite3.connect(path)
        legacy.executescript("""
            CREATE TABLE tokens (
                token_hash     TEXT PRIMARY KEY,
                subject        TEXT NOT NULL,
                subject_type   INTEGER NOT NULL,
                subject_hash12 TEXT,
                rate_per_sec   REAL NOT NULL DEFAULT 10.0,
                rate_burst     INTEGER NOT NULL DEFAULT 50,
                issued_at      INTEGER NOT NULL,
                expires_at     INTEGER,
                revoked_at     INTEGER,
                issuer         TEXT NOT NULL DEFAULT '',
                note           TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE token_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL,
                token_hash TEXT,
                subject TEXT,
                remote_addr TEXT,
                detail TEXT
            );
            """)
        legacy.execute(
            "INSERT INTO tokens(token_hash, subject, subject_type, "
            "issued_at, issuer, note) VALUES(?, ?, ?, ?, ?, ?)",
            ("h0", "alice@example", 1, 100, "test", ""),
        )
        legacy.commit()
        legacy.close()

        store = TokenStore(path)
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 2
            cols = {
                row[1]
                for row in store._conn.execute("PRAGMA table_info(tokens)").fetchall()
            }
            assert "registered_spk" in cols
            row = store._conn.execute("SELECT token_hash FROM tokens").fetchone()
            assert row[0] == "h0"
        finally:
            store.close()

    def test_legacy_v1_5_with_registered_spk_but_unstamped(self, tmp_path):
        """A pre-versioning binary that already ran the inline
        registered_spk ALTER but never stamped ``user_version`` opens
        cleanly: the ALTER hits ``duplicate column`` (caught), and the
        version is stamped to v2.
        """
        import sqlite3

        from dmp.server.tokens import TokenStore

        path = str(tmp_path / "legacy_with_spk.db")
        legacy = sqlite3.connect(path)
        # Same as v1 schema but with registered_spk pre-added (matches
        # what the pre-versioning binary's inline ALTER produced).
        legacy.executescript("""
            CREATE TABLE tokens (
                token_hash TEXT PRIMARY KEY,
                subject TEXT NOT NULL,
                subject_type INTEGER NOT NULL,
                subject_hash12 TEXT,
                rate_per_sec REAL NOT NULL DEFAULT 10.0,
                rate_burst INTEGER NOT NULL DEFAULT 50,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER,
                revoked_at INTEGER,
                issuer TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                registered_spk TEXT
            );
            CREATE TABLE token_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts INTEGER NOT NULL,
                event TEXT NOT NULL,
                token_hash TEXT,
                subject TEXT,
                remote_addr TEXT,
                detail TEXT
            );
            """)
        legacy.commit()
        legacy.close()

        store = TokenStore(path)
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 2
        finally:
            store.close()

    def test_future_version_db_refuses_to_open(self, tmp_path):
        import sqlite3

        from dmp.server.tokens import TokenStore, _SCHEMA, _SCHEMA_VERSION

        path = str(tmp_path / "future.db")
        future = sqlite3.connect(path)
        future.executescript(_SCHEMA)
        future.execute(f"PRAGMA user_version = {_SCHEMA_VERSION + 5}")
        future.commit()
        future.close()

        with pytest.raises(RuntimeError, match="schema version"):
            TokenStore(path)
