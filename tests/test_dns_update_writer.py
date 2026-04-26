"""Tests for the M9.2.4 client-side DNS UPDATE writer.

End-to-end against a real ``DMPDnsServer`` plus an in-memory record
store and an in-memory TSIG keystore. The writer contract matches the
generic ``DNSRecordWriter`` shape so the same fixtures we use for
``InMemoryDNSStore`` apply.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from dmp.network.dns_update_writer import _DnsUpdateWriter
from dmp.network.memory import InMemoryDNSStore
from dmp.server.dns_server import DMPDnsServer
from dmp.server.tsig_keystore import TSIGKeyStore


def _free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def keystore(tmp_path: Path) -> TSIGKeyStore:
    s = TSIGKeyStore(str(tmp_path / "tsig.db"))
    yield s
    s.close()


@pytest.fixture
def record_store() -> InMemoryDNSStore:
    return InMemoryDNSStore()


def _start_server(record_store: InMemoryDNSStore, keystore: TSIGKeyStore):
    """Boot a DNS server with the keystore live so newly-minted keys
    authorize on the very next packet."""
    port = _free_udp_port()
    server = DMPDnsServer(
        record_store,
        host="127.0.0.1",
        port=port,
        writer=record_store,
        tsig_keystore=keystore,
        allowed_zones=("example.com",),
    )
    server.start()
    return server, port


def _mint_key(keystore: TSIGKeyStore, name: str, allowed_suffixes):
    return keystore.mint(name=name, allowed_suffixes=allowed_suffixes)


class TestPublish:
    def test_publish_lands_in_record_store(self, record_store, keystore):
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("alice.example.com", "v=dmp1;t=identity")
        finally:
            server.stop()
        assert ok is True
        # The signed UPDATE landed in the same store the reader serves.
        assert record_store.query_txt_record("alice.example.com") == [
            "v=dmp1;t=identity"
        ]

    def test_publish_under_subtree(self, record_store, keystore):
        """Owner names beneath the user's scope are accepted — a key
        scoped to ``alice.example.com`` covers everything below it."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("prekey.alice.example.com", "v=dmp1;k=abc")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("prekey.alice.example.com") == [
            "v=dmp1;k=abc"
        ]

    def test_publish_with_special_chars_in_value(self, record_store, keystore):
        """TXT values containing ``;`` (the DNS comment delimiter) and
        ``"`` must round-trip cleanly. The DMP heartbeat wire is
        full of semicolons."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        wire = 'v=dmp1;t=heartbeat;data="quoted"'
        try:
            ok = writer.publish_txt_record("alice.example.com", wire)
        finally:
            server.stop()
        assert ok is True
        got = record_store.query_txt_record("alice.example.com")
        assert got == [wire]


class TestDelete:
    def test_delete_specific_value(self, record_store, keystore):
        record_store.publish_txt_record("alice.example.com", "keep")
        record_store.publish_txt_record("alice.example.com", "drop")
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.delete_txt_record("alice.example.com", value="drop")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("alice.example.com") == ["keep"]

    def test_delete_whole_rrset(self, record_store, keystore):
        record_store.publish_txt_record("alice.example.com", "a")
        record_store.publish_txt_record("alice.example.com", "b")
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.delete_txt_record("alice.example.com")
        finally:
            server.stop()
        assert ok is True
        assert record_store.query_txt_record("alice.example.com") is None


class TestRejection:
    def test_out_of_scope_owner_returns_false(self, record_store, keystore):
        """A write outside the key's scope bounces as REFUSED on the
        server side — the writer surfaces that as False so the caller
        can fall back. No exception."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            ok = writer.publish_txt_record("bob.example.com", "x")
        finally:
            server.stop()
        assert ok is False
        assert record_store.query_txt_record("bob.example.com") is None

    def test_owner_outside_zone_returns_false(self, record_store, keystore):
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            # Owner is in a different zone — the server returns NOTZONE,
            # which we surface as False.
            ok = writer.publish_txt_record("alice.other.com", "x")
        finally:
            server.stop()
        assert ok is False

    def test_revoked_key_returns_false(self, record_store, keystore):
        """Revoke between mint and write — the next UPDATE fails TSIG
        verification (key drops out of the live keyring) and the writer
        returns False without raising."""
        key = _mint_key(keystore, "alice", ("alice.example.com",))
        server, port = _start_server(record_store, keystore)
        writer = _DnsUpdateWriter(
            zone="example.com",
            server="127.0.0.1",
            port=port,
            tsig_key_name=key.name,
            tsig_secret=key.secret,
        )
        try:
            keystore.revoke(key.name)
            ok = writer.publish_txt_record("alice.example.com", "x")
        finally:
            server.stop()
        assert ok is False


class TestConstructorValidation:
    def test_empty_zone_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"\x01" * 32,
            )

    def test_empty_secret_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="example.com",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"",
            )

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(ValueError):
            _DnsUpdateWriter(
                zone="example.com",
                server="127.0.0.1",
                tsig_key_name="x.",
                tsig_secret=b"\x01" * 32,
                tsig_algorithm="not-a-real-algorithm",
            )
