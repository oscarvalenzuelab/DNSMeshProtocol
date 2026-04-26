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
        assert _suffix_match(
            "extra.mb-abc.alice.test", "mb-*.alice.test"
        )
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
        a = store.mint(
            name="alice", allowed_suffixes=("alice.example.com",)
        )
        b = store.mint(
            name="bob", allowed_suffixes=("bob.example.com",)
        )
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
        assert authorize(
            dns.name.from_text("alice."), "add", "foo.alice.example.com"
        )

    def test_out_of_scope_owner_rejected(self, store):
        store.put(
            name="alice",
            secret=b"\x01" * 32,
            allowed_suffixes=("alice.example.com",),
        )
        authorize = store.build_authorizer()
        assert not authorize(
            dns.name.from_text("alice."), "add", "bob.example.com"
        )

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
        assert not authorize(
            dns.name.from_text("alice."), "add", "alice.example"
        )

    def test_unknown_key_rejected(self, store):
        authorize = store.build_authorizer()
        assert not authorize(
            dns.name.from_text("ghost."), "add", "anything.example"
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
