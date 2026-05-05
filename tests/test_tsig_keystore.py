"""Tests for dmp.server.tsig_keystore (M9.2.2)."""

from __future__ import annotations

import time
from pathlib import Path

import dns.name
import dns.tsig
import pytest

from dmp.server.tsig_keystore import (
    DEFAULT_ALGORITHM,
    TSIGKey,
    TSIGKeyStore,
    _suffix_match,
)


@pytest.fixture
def store(tmp_path: Path) -> TSIGKeyStore:
    s = TSIGKeyStore(str(tmp_path / "tsig.db"))
    yield s
    s.close()


class TestSuffixMatch:
    def test_exact_match(self):
        assert _suffix_match("alice.example.com", "alice.example.com")

    def test_subdomain_match(self):
        assert _suffix_match("foo.alice.example.com", "alice.example.com")

    def test_unrelated_owner_does_not_match(self):
        assert not _suffix_match("bob.example.com", "alice.example.com")

    def test_partial_label_does_not_match(self):
        """A suffix of ``alice.example.com`` must NOT match
        ``maliceful.example.com`` — the boundary has to be on a
        label, not a substring."""
        assert not _suffix_match("maliceful.example.com", "alice.example.com")

    def test_trailing_dots_normalized(self):
        assert _suffix_match("alice.example.com.", "alice.example.com")
        assert _suffix_match("foo.alice.example.com", ".alice.example.com")

    def test_empty_suffix_matches_nothing(self):
        assert not _suffix_match("alice.example.com", "")

    def test_wildcard_label_matches_any_value_within_label(self):
        """M9.2.6 round-14: ``slot-*.mb-*.alice.test`` matches the
        content-addressed mailbox slot names DMPClient.send_message
        publishes."""
        assert _suffix_match(
            "slot-3.mb-abc123def456.alice.test", "slot-*.mb-*.alice.test"
        )

    def test_wildcard_does_not_cross_label_boundary(self):
        """``mb-*.alice.test`` matches ``mb-abc.alice.test`` but NOT
        ``mb-abc.bob.alice.test`` — the wildcard stays in one label."""
        assert _suffix_match("mb-abc.alice.test", "mb-*.alice.test")
        # Subdomain extension still works (suffix tail-match preserved).
        assert _suffix_match("extra.mb-abc.alice.test", "mb-*.alice.test")
        # Different zone — NOT in scope.
        assert not _suffix_match("mb-abc.bob.test", "mb-*.alice.test")

    def test_wildcard_owner_too_short_rejected(self):
        """A pattern with N labels rejects owners that have fewer
        than N labels — no implicit zero-label match."""
        assert not _suffix_match("alice.test", "slot-*.mb-*.alice.test")


class TestPutAndGet:
    def test_round_trip(self, store):
        secret = b"\x10" * 32
        key = store.put(
            name="client",
            secret=secret,
            allowed_suffixes=("alice.example.com",),
        )
        assert key.name == "client."
        assert key.secret == secret
        assert key.allowed_suffixes == ("alice.example.com",)
        # Re-read picks up the same row.
        fetched = store.get("client.")
        assert fetched is not None
        assert fetched.secret == secret

    def test_put_replaces_existing(self, store):
        store.put(
            name="client",
            secret=b"a" * 32,
            allowed_suffixes=("alice.example.com",),
        )
        # Re-issue with a new secret for the same name (e.g. user
        # lost their key and re-registered).
        store.put(
            name="client",
            secret=b"b" * 32,
            allowed_suffixes=("alice.example.com",),
        )
        # Old secret is gone.
        fetched = store.get("client")
        assert fetched.secret == b"b" * 32

    def test_empty_suffix_list_rejected(self, store):
        with pytest.raises(ValueError):
            store.put(name="x", secret=b"\x01" * 32, allowed_suffixes=())

    def test_empty_secret_rejected(self, store):
        with pytest.raises(ValueError):
            store.put(name="x", secret=b"", allowed_suffixes=("a.example",))

    def test_get_missing_returns_none(self, store):
        assert store.get("ghost.") is None


class TestMint:
    def test_generates_random_secret(self, store):
        a = store.mint(name="alice", allowed_suffixes=("alice.example.com",))
        b = store.mint(name="bob", allowed_suffixes=("bob.example.com",))
        assert a.secret != b.secret
        assert len(a.secret) == 32

    def test_minted_key_is_active(self, store):
        k = store.mint(name="x", allowed_suffixes=("x.example",))
        assert k.is_active()


class TestRevoke:
    def test_revoke_marks_inactive(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
        )
        assert store.revoke("alice") is True
        fetched = store.get("alice")
        assert fetched is not None
        assert fetched.revoked is True
        assert not fetched.is_active()

    def test_revoke_missing_returns_false(self, store):
        assert store.revoke("ghost") is False

    def test_revoked_keys_excluded_from_active(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
        )
        store.put(
            name="bob",
            secret=b"\x02" * 32,
            allowed_suffixes=("bob.example",),
        )
        store.revoke("alice")
        names = {k.name for k in store.list_active()}
        assert names == {"bob."}


class TestExpiry:
    def test_expired_key_excluded_from_active(self, store):
        now = int(time.time())
        store.put(
            name="short-lived",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
            expires_at=now + 60,
        )
        # Past the expiry window.
        active = store.list_active(now=now + 120)
        assert active == []

    def test_unset_expiry_means_no_expiry(self, store):
        store.put(
            name="forever",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
            expires_at=0,
        )
        # Far future — still active.
        active = store.list_active(now=int(time.time()) + 10**9)
        assert len(active) == 1


class TestKeyringProjection:
    def test_keyring_contains_active_keys_only(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
        )
        store.put(
            name="revoked",
            secret=b"\x02" * 32,
            allowed_suffixes=("revoked.example",),
        )
        store.revoke("revoked")
        keyring = store.build_keyring()
        assert dns.name.from_text("alice.") in keyring
        assert dns.name.from_text("revoked.") not in keyring
        # Each entry is a real dns.tsig.Key with the right algorithm.
        k = keyring[dns.name.from_text("alice.")]
        assert isinstance(k, dns.tsig.Key)


class TestAuthorizer:
    def test_in_scope_owner_authorized(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example.com",),
        )
        authorize = store.build_authorizer()
        assert authorize(dns.name.from_text("alice."), "add", "foo.alice.example.com")

    def test_out_of_scope_owner_rejected(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example.com",),
        )
        authorize = store.build_authorizer()
        assert not authorize(dns.name.from_text("alice."), "add", "bob.example.com")

    def test_revoke_after_keyring_build_blocks_authorize(self, store):
        """A live revoke between TSIG verification and applying the
        write must reject the operation. Otherwise a key revoked
        seconds before an attacker's UPDATE lands could still publish."""
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example",),
        )
        authorize = store.build_authorizer()
        store.revoke("alice")
        assert not authorize(dns.name.from_text("alice."), "add", "alice.example")

    def test_unknown_key_rejected(self, store):
        authorize = store.build_authorizer()
        assert not authorize(dns.name.from_text("ghost."), "add", "anything.example")

    def test_wildcard_scoped_key_can_add_chunks(self, store):
        # Self-service registration grants wildcard suffixes (the
        # chunk namespace is shared across users), so ADD on any
        # chunk name in scope must succeed.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("chunk-*-*.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "add",
            "chunk-0001-abc123def456.shared.example",
        )

    def test_wildcard_scoped_key_cannot_delete_chunks(self, store):
        # The shared chunk namespace has no per-record ownership,
        # so a wildcard-scoped key letting any holder DELETE other
        # users' chunks is the same threat as the HTTP shared-pool
        # delete bug fixed in #52, just on the DNS UPDATE side.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("chunk-*-*.shared.example",),
        )
        authorize = store.build_authorizer()
        assert not authorize(
            dns.name.from_text("alice."),
            "delete",
            "chunk-0001-abc123def456.shared.example",
        )

    def test_wildcard_slot_mailbox_cannot_delete(self, store):
        # ``slot-*.mb-*`` is granted to every registrant so anyone
        # can deliver to any mailbox. DELETE through it would let
        # one user wipe another user's mailbox slot — refused.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("slot-*.mb-*.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "add",
            "slot-3.mb-abcdef012345.shared.example",
        )
        assert not authorize(
            dns.name.from_text("alice."),
            "delete",
            "slot-3.mb-abcdef012345.shared.example",
        )

    def test_owner_exclusive_suffix_can_still_delete(self, store):
        # The user's OWN mailbox suffix (literal, no wildcards) is
        # owner-exclusive — they can ADD AND DELETE their own slot
        # records. This is the legitimate rotate-old-publish-new
        # path; if delete were globally refused it would block
        # operators from cleaning up after themselves.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("mb-abcdef012345.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "delete",
            "slot-3.mb-abcdef012345.shared.example",
        )

    def test_underscore_claim_wildcard_cannot_delete(self, store):
        # ``_dnsmesh-claim-*`` is the M10 first-contact claim
        # namespace, also wildcard-granted. Same rule.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("_dnsmesh-claim-*.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "add",
            "_dnsmesh-claim-abc123.shared.example",
        )
        assert not authorize(
            dns.name.from_text("alice."),
            "delete",
            "_dnsmesh-claim-abc123.shared.example",
        )

    def test_claim_mailbox_wildcard_cannot_delete(self, store):
        # ``claim-*.mb-*`` is the same-zone claim namespace
        # (granted to every registrant for self-service claim
        # publishing). Same rule.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("claim-*.mb-*.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "add",
            "claim-3.mb-abcdef012345.shared.example",
        )
        assert not authorize(
            dns.name.from_text("alice."),
            "delete",
            "claim-3.mb-abcdef012345.shared.example",
        )

    def test_literal_claim_owner_can_delete(self, store):
        # ``_dnsmesh-claim-{spk16}.{zone}`` is the user's own
        # claim record (literal, no wildcards). Owner-exclusive,
        # delete authority is the legitimate "rotate-and-republish"
        # path.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("_dnsmesh-claim-1234567890abcdef.shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("alice."),
            "delete",
            "_dnsmesh-claim-1234567890abcdef.shared.example",
        )

    def test_bare_zone_loose_scope_can_delete(self, store):
        # ``DMP_TSIG_LOOSE_SCOPE=1`` admin-issued keys carry the
        # bare zone as the only scope. The bare zone is literal —
        # no wildcards — so DELETE remains authorized: the
        # operator escape hatch is preserved.
        store.put(
            name="admin",
            secret=b"\x01" * 32,
            allowed_suffixes=("shared.example",),
        )
        authorize = store.build_authorizer()
        assert authorize(
            dns.name.from_text("admin."),
            "delete",
            "anything.shared.example",
        )

    def test_mixed_literal_and_wildcard_for_same_owner_allows_delete(self, store):
        # If a key has BOTH a wildcard AND a literal suffix that
        # match the same owner name, the literal must still
        # authorize DELETE — the wildcard is skipped only on a
        # delete and the loop continues to find the literal.
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=(
                "slot-*.mb-*.shared.example",
                "mb-abcdef012345.shared.example",
            ),
        )
        authorize = store.build_authorizer()
        # Slot under alice's own mailbox: matches BOTH the wildcard
        # and the literal mailbox suffix. DELETE must be allowed.
        assert authorize(
            dns.name.from_text("alice."),
            "delete",
            "slot-3.mb-abcdef012345.shared.example",
        )


class TestEndToEndWithDnsServer:
    """Sanity-check that dns_server picks up the keystore-built
    keyring + authorizer end-to-end. Catches signature mismatches
    between the modules without needing a full integration harness."""

    def test_dns_update_succeeds_for_in_scope_key(self, store, tmp_path):
        import base64
        import socket

        import dns.message
        import dns.query
        import dns.rcode
        import dns.tsigkeyring
        import dns.update

        from dmp.network.memory import InMemoryDNSStore
        from dmp.server.dns_server import DMPDnsServer

        secret = b"\x42" * 32
        store.put(
            name="alice",
            secret=secret,
            allowed_suffixes=("alice.example.com",),
        )

        # Build the client-side keyring with the same secret bytes.
        client_keyring = dns.tsigkeyring.from_text(
            {"alice.": base64.b64encode(secret).decode("ascii")}
        )

        record_store = InMemoryDNSStore()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = DMPDnsServer(
            record_store,
            host="127.0.0.1",
            port=port,
            writer=record_store,
            tsig_keyring=store.build_keyring(),
            allowed_zones=("example.com",),
            update_authorizer=store.build_authorizer(),
        )
        with server:
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text("foo.alice.example.com."),
                300,
                "TXT",
                '"v=dmp1;t=test"',
            )
            upd.use_tsig(client_keyring, keyname=dns.name.from_text("alice."))
            response = dns.query.udp(upd, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == dns.rcode.NOERROR
        assert record_store.query_txt_record("foo.alice.example.com") == [
            "v=dmp1;t=test"
        ]

    def test_live_keystore_picks_up_keys_minted_after_server_start(
        self, store, tmp_path
    ):
        """Pass tsig_keystore (not tsig_keyring) and confirm a key
        minted AFTER the server is running can be used to publish.
        Critical for M9.2.3 — the registration HTTP endpoint mints
        new keys at runtime and the very next UPDATE has to honor
        them without restarting the DNS server."""
        import base64
        import socket

        import dns.message
        import dns.query
        import dns.rcode
        import dns.tsigkeyring
        import dns.update

        from dmp.network.memory import InMemoryDNSStore
        from dmp.server.dns_server import DMPDnsServer

        record_store = InMemoryDNSStore()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        # Start the server with the keystore but no keys yet.
        server = DMPDnsServer(
            record_store,
            host="127.0.0.1",
            port=port,
            writer=record_store,
            tsig_keystore=store,
            allowed_zones=("example.com",),
        )
        with server:
            # Mint the key AFTER startup.
            secret = b"\x99" * 32
            store.put(
                name="late",
                secret=secret,
                allowed_suffixes=("alice.example.com",),
            )
            client_keyring = dns.tsigkeyring.from_text(
                {"late.": base64.b64encode(secret).decode("ascii")}
            )
            upd = dns.update.UpdateMessage("example.com")
            upd.add(
                dns.name.from_text("alice.example.com."),
                300,
                "TXT",
                '"v=hello"',
            )
            upd.use_tsig(client_keyring, keyname=dns.name.from_text("late."))
            response = dns.query.udp(upd, "127.0.0.1", port=port, timeout=2.0)
        assert response.rcode() == dns.rcode.NOERROR
        assert record_store.query_txt_record("alice.example.com") == ["v=hello"]

    def test_dns_update_rejected_for_out_of_scope_owner(self, store, tmp_path):
        import base64
        import socket

        import dns.message
        import dns.query
        import dns.rcode
        import dns.tsigkeyring
        import dns.update

        from dmp.network.memory import InMemoryDNSStore
        from dmp.server.dns_server import DMPDnsServer

        secret = b"\x42" * 32
        store.put(
            name="alice",
            secret=secret,
            allowed_suffixes=("alice.example.com",),
        )

        client_keyring = dns.tsigkeyring.from_text(
            {"alice.": base64.b64encode(secret).decode("ascii")}
        )
        record_store = InMemoryDNSStore()

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        server = DMPDnsServer(
            record_store,
            host="127.0.0.1",
            port=port,
            writer=record_store,
            tsig_keyring=store.build_keyring(),
            allowed_zones=("example.com",),
            update_authorizer=store.build_authorizer(),
        )
        with server:
            upd = dns.update.UpdateMessage("example.com")
            # Owner is example.com but not under alice.example.com,
            # so alice's key is out of scope.
            upd.add(
                dns.name.from_text("bob.example.com."),
                300,
                "TXT",
                '"impostor"',
            )
            upd.use_tsig(client_keyring, keyname=dns.name.from_text("alice."))
            response = dns.query.udp(upd, "127.0.0.1", port=port, timeout=2.0)

        assert response.rcode() == dns.rcode.REFUSED
        assert record_store.query_txt_record("bob.example.com") is None


class TestSchemaVersioning:
    """Migration ladder for TSIGKeyStore (schema v4).

    Versions:
      v1 = original (name, algorithm, secret, allowed_suffixes, created_at,
           expires_at, revoked)
      v2 = + subject
      v3 = + registered_spk
      v4 = + registered_x25519_pub (current)

    Pre-versioning binaries blindly ran every ALTER swallowing
    ``duplicate column``; the new ladder preserves that idempotency
    while stamping ``user_version`` on the way out.
    """

    def test_fresh_db_is_stamped_at_current_version(self, tmp_path):
        from dmp.server.tsig_keystore import _SCHEMA_VERSION, TSIGKeyStore

        store = TSIGKeyStore(str(tmp_path / "fresh.db"))
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == _SCHEMA_VERSION
            cols = {
                row[1]
                for row in store._conn.execute(
                    "PRAGMA table_info(tsig_keys)"
                ).fetchall()
            }
            assert {"subject", "registered_spk", "registered_x25519_pub"} <= cols
        finally:
            store.close()

    def test_legacy_v1_db_gets_all_three_columns_added(self, tmp_path):
        """A pre-versioning v1 keystore (only the original 7 columns)
        opens cleanly: all three v2/v3/v4 columns get ALTERed in,
        ``user_version`` is stamped to 4."""
        import sqlite3

        from dmp.server.tsig_keystore import TSIGKeyStore

        path = str(tmp_path / "legacy.db")
        legacy = sqlite3.connect(path)
        legacy.executescript("""
            CREATE TABLE tsig_keys (
                name TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
                secret BLOB NOT NULL,
                allowed_suffixes TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            """)
        legacy.execute(
            "INSERT INTO tsig_keys(name, secret, created_at) VALUES(?, ?, ?)",
            ("k0.", b"\xaa" * 32, 100),
        )
        legacy.commit()
        legacy.close()

        store = TSIGKeyStore(path)
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 4
            cols = {
                row[1]
                for row in store._conn.execute(
                    "PRAGMA table_info(tsig_keys)"
                ).fetchall()
            }
            assert {"subject", "registered_spk", "registered_x25519_pub"} <= cols
            row = store._conn.execute("SELECT name FROM tsig_keys").fetchone()
            assert row[0] == "k0."
        finally:
            store.close()

    def test_future_version_db_refuses_to_open(self, tmp_path):
        import sqlite3

        from dmp.server.tsig_keystore import TSIGKeyStore, _SCHEMA, _SCHEMA_VERSION

        path = str(tmp_path / "future.db")
        future = sqlite3.connect(path)
        future.executescript(_SCHEMA)
        future.execute(f"PRAGMA user_version = {_SCHEMA_VERSION + 5}")
        future.commit()
        future.close()

        with pytest.raises(RuntimeError, match="schema version"):
            TSIGKeyStore(path)

    def test_legacy_v2_with_subject_already_present_but_unstamped(self, tmp_path):
        """A pre-versioning binary that already ran the inline ``subject``
        ALTER (and possibly more) but never stamped ``user_version`` opens
        cleanly: the ALTER for ``subject`` hits ``duplicate column``
        (caught), the ALTERs for the columns that don't exist yet succeed,
        and the version is stamped to 4.
        """
        import sqlite3

        from dmp.server.tsig_keystore import TSIGKeyStore

        path = str(tmp_path / "legacy_v2.db")
        legacy = sqlite3.connect(path)
        # v2 shape: original v1 columns + subject (codex flagged the
        # missing test for this half-migrated case).
        legacy.executescript("""
            CREATE TABLE tsig_keys (
                name TEXT PRIMARY KEY,
                algorithm TEXT NOT NULL DEFAULT 'hmac-sha256',
                secret BLOB NOT NULL,
                allowed_suffixes TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                subject TEXT NOT NULL DEFAULT ''
            );
            """)
        legacy.execute(
            "INSERT INTO tsig_keys(name, secret, created_at, subject) "
            "VALUES(?, ?, ?, ?)",
            ("k0.", b"\xaa" * 32, 100, "alice@example.com"),
        )
        legacy.commit()
        legacy.close()

        store = TSIGKeyStore(path)
        try:
            stored = store._conn.execute("PRAGMA user_version").fetchone()[0]
            assert stored == 4
            cols = {
                row[1]
                for row in store._conn.execute(
                    "PRAGMA table_info(tsig_keys)"
                ).fetchall()
            }
            # All v4 columns present, including the v3/v4 ones added
            # by the ladder on top of the v2 starting point.
            assert {"subject", "registered_spk", "registered_x25519_pub"} <= cols
            row = store._conn.execute("SELECT name, subject FROM tsig_keys").fetchone()
            assert row == ("k0.", "alice@example.com")
        finally:
            store.close()

    def test_unrelated_operational_error_propagates(self, tmp_path, monkeypatch):
        """Codex P1 catch: the ALTER swallow must filter to only
        ``duplicate column`` / ``no such table``. Any OTHER
        OperationalError — a real SQL mistake in a future migration —
        must propagate rather than silently leaving the schema
        half-migrated AND stamping the new version."""
        import sqlite3

        from dmp.server import tsig_keystore as mod

        # Pre-create the table so the bogus ALTER hits a real error
        # rather than ``no such table`` (which is intentionally
        # swallowed for the v0→v* fresh-db case).
        path = str(tmp_path / "unrelated_err.db")
        seed = sqlite3.connect(path)
        seed.executescript(
            "CREATE TABLE tsig_keys ("
            "name TEXT PRIMARY KEY, secret BLOB NOT NULL, "
            "created_at INTEGER NOT NULL"
            ");"
        )
        seed.commit()
        seed.close()
        # Inject a bogus ALTER. ``ADD COLUMN ... PRIMARY KEY`` is
        # rejected by sqlite ("Cannot add a PRIMARY KEY column") with
        # an OperationalError whose message contains neither swallowed
        # phrase — so the migration must propagate, not silently stamp
        # v4 over a half-migrated schema.
        bogus = "ALTER TABLE tsig_keys ADD COLUMN bogus INTEGER PRIMARY KEY"
        monkeypatch.setattr(mod, "_MIGRATIONS", (bogus,))

        with pytest.raises(sqlite3.OperationalError):
            mod.TSIGKeyStore(path)


class TestTSIGKeystoreFilePerms:
    # The DB holds TSIG shared secrets — local disclosure lets any
    # reader forge DNS UPDATE writes for every scope a key covers.
    # Pre-#53 the store had no chmod at all (codex P2 on the
    # post-#52 fresh audit).

    def test_db_and_wal_shm_are_0600_after_init(self, tmp_path):
        import os
        import stat

        path = str(tmp_path / "secrets" / "tsig.db")
        s = TSIGKeyStore(path)
        try:
            # Force WAL/SHM siblings to materialize via a write.
            s.mint(
                name="alice-7d2f.example.com.",
                allowed_suffixes=("alice.example.com",),
                subject="alice@example.com",
            )
            for suffix in ("", "-wal", "-shm"):
                p = path + suffix
                if not os.path.exists(p):
                    continue
                mode = stat.S_IMODE(os.stat(p).st_mode)
                assert mode & 0o077 == 0, f"{p!r} too permissive: 0o{mode:o}"
        finally:
            s.close()

    def test_parent_dir_is_0700_after_init(self, tmp_path):
        import os
        import stat

        parent = tmp_path / "secrets"
        path = str(parent / "tsig.db")
        TSIGKeyStore(path).close()
        mode = stat.S_IMODE(os.stat(parent).st_mode)
        assert mode & 0o077 == 0, f"parent dir too permissive: 0o{mode:o}"

    def test_existing_loose_parent_is_healed_on_reopen(self, tmp_path):
        # Pre-#53 deployments have parent dirs with looser perms;
        # __init__ must heal them on reopen.
        import os
        import stat

        parent = tmp_path / "existing"
        parent.mkdir(mode=0o755)
        before = stat.S_IMODE(os.stat(parent).st_mode)
        assert before & 0o077 != 0
        path = str(parent / "tsig.db")
        TSIGKeyStore(path).close()
        after = stat.S_IMODE(os.stat(parent).st_mode)
        assert after & 0o077 == 0, f"loose parent dir not healed: 0o{after:o}"
