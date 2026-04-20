"""Tests for the `dmp` CLI.

Each test gets an isolated DMP_CONFIG_HOME so real user config isn't touched.
Network-dependent commands (send/recv) route through the in-memory store
exposed via a monkeypatched `_make_client`.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from dmp import cli
from dmp.client.client import DMPClient
from dmp.network.memory import InMemoryDNSStore


@pytest.fixture
def config_home(tmp_path, monkeypatch):
    home = tmp_path / "dmp-home"
    monkeypatch.setenv("DMP_CONFIG_HOME", str(home))
    return home


@pytest.fixture
def shared_store(monkeypatch):
    """Force _make_client to use a shared in-memory store across test clients.

    Preserves the real CLI's persistent-replay-cache path so tests exercise
    that wiring too (one replay cache per config home / identity). Also
    monkeypatches `_DnsReader` so the identity-fetch path (which bypasses
    _make_client) sees the same shared store.
    """
    store = InMemoryDNSStore()

    def fake_make_client(config, passphrase):
        from dmp.cli import _config_path
        replay_path = str(_config_path().parent / "replay_cache.json")
        client = DMPClient(
            config.username,
            passphrase,
            domain=config.domain,
            store=store,
            replay_cache_path=replay_path,
        )
        for name, pubkey in config.contacts.items():
            client.add_contact(name, pubkey, domain=config.domain)
        return client

    class _SharedStoreReader:
        def query_txt_record(self, name):
            return store.query_txt_record(name)

    def fake_dns_reader(host, port=5353):
        return _SharedStoreReader()

    monkeypatch.setattr(cli, "_make_client", fake_make_client)
    monkeypatch.setattr(cli, "_DnsReader", fake_dns_reader)
    return store


class TestInitAndIdentity:
    def test_init_writes_config(self, config_home, capsys):
        rc = cli.main(["init", "alice", "--domain", "mesh.test",
                       "--endpoint", "http://node:8053"])
        assert rc == 0
        cfg = yaml.safe_load((config_home / "config.yaml").read_text())
        assert cfg["username"] == "alice"
        assert cfg["domain"] == "mesh.test"
        assert cfg["endpoint"] == "http://node:8053"
        # Per-identity random salt: 32 bytes = 64 hex chars.
        assert len(cfg["kdf_salt"]) == 64

    def test_init_generates_unique_salts_per_identity(self, config_home, tmp_path, monkeypatch):
        """Two independent `dmp init` runs must produce distinct salts."""
        cli.main(["init", "alice", "--endpoint", "http://x"])
        first = yaml.safe_load((config_home / "config.yaml").read_text())["kdf_salt"]

        other_home = tmp_path / "dmp-other"
        monkeypatch.setenv("DMP_CONFIG_HOME", str(other_home))
        cli.main(["init", "alice", "--endpoint", "http://x"])
        second = yaml.safe_load((other_home / "config.yaml").read_text())["kdf_salt"]

        assert first != second

    def test_init_refuses_overwrite_without_force(self, config_home):
        cli.main(["init", "alice", "--endpoint", "http://a"])
        with pytest.raises(SystemExit) as exc:
            cli.main(["init", "bob", "--endpoint", "http://b"])
        assert exc.value.code == 1

    def test_init_force_overwrites(self, config_home):
        cli.main(["init", "alice", "--endpoint", "http://a"])
        rc = cli.main(["init", "bob", "--endpoint", "http://b", "--force"])
        assert rc == 0
        cfg = yaml.safe_load((config_home / "config.yaml").read_text())
        assert cfg["username"] == "bob"

    def test_identity_show_prints_keys(self, config_home, shared_store, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "pw")
        rc = cli.main(["identity", "show"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "username: alice" in out
        assert "public_key:" in out
        assert "signing_public_key:" in out

    def test_identity_show_json(self, config_home, shared_store, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()  # flush init output
        monkeypatch.setenv("DMP_PASSPHRASE", "pw")
        cli.main(["identity", "show", "--json"])
        out = capsys.readouterr().out
        import json
        parsed = json.loads(out)
        assert parsed["username"] == "alice"
        assert len(parsed["public_key"]) == 64  # 32 bytes hex


class TestIdentityPublishFetch:
    """`dmp identity publish` + `dmp identity fetch` + `--add`."""

    def test_publish_then_fetch_roundtrip(self, config_home, shared_store, monkeypatch, capsys):
        """alice publishes, a second invocation as bob can fetch and add her."""
        # Alice sets up + publishes.
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        cli.main(["identity", "publish"])
        assert "published identity" in capsys.readouterr().out

        # Bob's CLI (different config home; same shared in-memory store)
        # fetches alice's record and verifies it.
        bob_home = config_home.parent / "bob-home"
        monkeypatch.setenv("DMP_CONFIG_HOME", str(bob_home))
        cli.main(["init", "bob", "--endpoint", "http://x"])
        capsys.readouterr()
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        cli.main(["identity", "fetch", "alice", "--json"])
        import json
        parsed = json.loads(capsys.readouterr().out)
        assert parsed["username"] == "alice"
        assert len(parsed["public_key"]) == 64  # hex

    def test_fetch_add_stores_contact(self, config_home, shared_store, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        cli.main(["identity", "publish"])
        capsys.readouterr()

        bob_home = config_home.parent / "bob-home-2"
        monkeypatch.setenv("DMP_CONFIG_HOME", str(bob_home))
        cli.main(["init", "bob", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        capsys.readouterr()

        cli.main(["identity", "fetch", "alice", "--add"])
        out = capsys.readouterr().out
        assert "added contact alice" in out

        cli.main(["contacts", "list"])
        assert "alice" in capsys.readouterr().out

    def test_fetch_missing_identity_errors(self, config_home, shared_store, monkeypatch):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        with pytest.raises(SystemExit) as exc:
            cli.main(["identity", "fetch", "nobody"])
        assert exc.value.code == 2


class TestContacts:
    def test_add_and_list(self, config_home, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        pubkey = "a" * 64
        rc = cli.main(["contacts", "add", "bob", pubkey])
        assert rc == 0
        cli.main(["contacts", "list"])
        assert "bob" in capsys.readouterr().out

    def test_add_rejects_short_key(self, config_home):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        with pytest.raises(SystemExit) as exc:
            cli.main(["contacts", "add", "bob", "aabb"])
        assert exc.value.code == 1

    def test_list_empty(self, config_home, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        cli.main(["contacts", "list"])
        assert "no contacts" in capsys.readouterr().out


class TestSendRecv:
    def test_send_and_recv_roundtrip(self, config_home, shared_store, monkeypatch, capsys):
        # Set up alice's config.
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")

        # Discover bob's pubkey by spinning up a client in the same store.
        bob = DMPClient("bob", "bob-pass", domain="mesh.local", store=shared_store)
        cli.main(["contacts", "add", "bob", bob.get_public_key_hex()])

        rc = cli.main(["send", "bob", "hello from cli"])
        assert rc == 0
        assert "sent" in capsys.readouterr().out

        # Switch "identity" to bob and read.
        cli.main(["init", "bob", "--endpoint", "http://x", "--force"])
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        cli.main(["recv"])
        out = capsys.readouterr().out
        assert "hello from cli" in out

    def test_send_unknown_recipient_errors(self, config_home, shared_store, monkeypatch):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "pw")
        with pytest.raises(SystemExit) as exc:
            cli.main(["send", "ghost", "hi"])
        assert exc.value.code == 1

    def test_recv_empty_inbox(self, config_home, shared_store, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "pw")
        cli.main(["recv"])
        assert "no new messages" in capsys.readouterr().out

    def test_recv_twice_is_idempotent(self, config_home, shared_store, monkeypatch, capsys):
        """Persistent replay cache: second `dmp recv` in a fresh process
        doesn't re-deliver what was already delivered."""
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")

        bob = DMPClient("bob", "bob-pass", domain="mesh.local", store=shared_store)
        cli.main(["contacts", "add", "bob", bob.get_public_key_hex()])
        capsys.readouterr()

        # alice sends
        cli.main(["send", "bob", "only-once"])
        capsys.readouterr()

        # bob's CLI reads once
        cli.main(["init", "bob", "--endpoint", "http://x", "--force"])
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        capsys.readouterr()
        cli.main(["recv"])
        out1 = capsys.readouterr().out
        assert "only-once" in out1

        # bob's CLI reads again — replay cache persists across the simulated
        # second invocation, so no duplicate.
        cli.main(["recv"])
        out2 = capsys.readouterr().out
        assert "only-once" not in out2
        assert "no new messages" in out2


class TestLoadWithoutConfig:
    def test_identity_show_without_config_errors(self, config_home):
        # Don't init; config doesn't exist.
        with pytest.raises(FileNotFoundError):
            cli.main(["identity", "show"])
