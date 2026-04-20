"""Tests for the sqlite-backed persistent DNS record store."""

import os
import time

import pytest

from dmp.network.base import DNSRecordStore
from dmp.storage.sqlite_store import SqliteMailboxStore


@pytest.fixture
def store(tmp_path):
    db = tmp_path / "test.db"
    s = SqliteMailboxStore(str(db))
    yield s
    s.close()


class TestSqliteMailboxStore:
    def test_implements_store_abc(self, store):
        assert isinstance(store, DNSRecordStore)

    def test_publish_and_query(self, store):
        assert store.publish_txt_record("a.example.com", "value-1", ttl=60)
        assert store.query_txt_record("a.example.com") == ["value-1"]

    def test_missing_returns_none(self, store):
        assert store.query_txt_record("nope.example.com") is None

    def test_replace_on_republish(self, store):
        store.publish_txt_record("a.example.com", "first", ttl=60)
        store.publish_txt_record("a.example.com", "second", ttl=60)
        # RRset-style: re-publish replaces the prior value.
        assert store.query_txt_record("a.example.com") == ["second"]

    def test_delete_by_name(self, store):
        store.publish_txt_record("a.example.com", "v1", ttl=60)
        assert store.delete_txt_record("a.example.com")
        assert store.query_txt_record("a.example.com") is None

    def test_delete_missing_returns_false(self, store):
        assert not store.delete_txt_record("ghost.example.com")

    def test_expired_record_invisible_to_query(self, store):
        store.publish_txt_record("ephemeral.example.com", "v", ttl=0)
        # ttl=0 means expires_at == now; the query filter uses strict ">".
        assert store.query_txt_record("ephemeral.example.com") is None

    def test_cleanup_expired_removes_old_rows(self, store):
        store.publish_txt_record("ephemeral.example.com", "v", ttl=0)
        store.publish_txt_record("fresh.example.com", "v", ttl=600)
        # Records with ttl=0 are already expired.
        deleted = store.cleanup_expired()
        assert deleted == 1
        # Fresh one still counts.
        assert store.record_count() == 1

    def test_record_count_tracks_live_records(self, store):
        store.publish_txt_record("a.example.com", "v", ttl=600)
        store.publish_txt_record("b.example.com", "v", ttl=600)
        assert store.record_count() == 2

    def test_list_names_sorted(self, store):
        store.publish_txt_record("b.example.com", "v", ttl=60)
        store.publish_txt_record("a.example.com", "v", ttl=60)
        assert store.list_names() == ["a.example.com", "b.example.com"]

    def test_persistence_across_reopen(self, tmp_path):
        db = str(tmp_path / "persist.db")
        s1 = SqliteMailboxStore(db)
        s1.publish_txt_record("persisted.example.com", "hello", ttl=600)
        s1.close()

        s2 = SqliteMailboxStore(db)
        assert s2.query_txt_record("persisted.example.com") == ["hello"]
        s2.close()


class TestClientOverSqlite:
    """Exercise the full client send/receive flow over the sqlite store."""

    def test_roundtrip_over_sqlite(self, tmp_path):
        from dmp.client.client import DMPClient

        store = SqliteMailboxStore(str(tmp_path / "mesh.db"))
        try:
            alice = DMPClient("alice", "apass", domain="mesh.test", store=store)
            bob = DMPClient("bob", "bpass", domain="mesh.test", store=store)
            alice.add_contact("bob", bob.get_public_key_hex())
            bob.add_contact("alice", alice.get_public_key_hex())

            assert alice.send_message("bob", "hello from sqlite")
            inbox = bob.receive_messages()
            assert len(inbox) == 1
            assert inbox[0].plaintext == b"hello from sqlite"
        finally:
            store.close()

    def test_roundtrip_survives_restart(self, tmp_path):
        from dmp.client.client import DMPClient

        db = str(tmp_path / "persist.db")

        # Phase 1: alice sends while bob is "offline". Close the store.
        store1 = SqliteMailboxStore(db)
        alice = DMPClient("alice", "apass", domain="mesh.test", store=store1)
        bob_for_keys = DMPClient("bob", "bpass", domain="mesh.test", store=store1)
        alice.add_contact("bob", bob_for_keys.get_public_key_hex())
        assert alice.send_message("bob", "picked up after restart")
        store1.close()

        # Phase 2: new process, new store handle, new bob client reads.
        store2 = SqliteMailboxStore(db)
        try:
            bob = DMPClient("bob", "bpass", domain="mesh.test", store=store2)
            inbox = bob.receive_messages()
            assert len(inbox) == 1
            assert inbox[0].plaintext == b"picked up after restart"
        finally:
            store2.close()
