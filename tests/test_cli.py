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
    """Force _make_client to use a shared in-memory store across test clients."""
    store = InMemoryDNSStore()

    def fake_make_client(config, passphrase):
        client = DMPClient(
            config.username,
            passphrase,
            domain=config.domain,
            store=store,
        )
        for name, pubkey in config.contacts.items():
            client.add_contact(name, pubkey, domain=config.domain)
        return client

    monkeypatch.setattr(cli, "_make_client", fake_make_client)
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


class TestLoadWithoutConfig:
    def test_identity_show_without_config_errors(self, config_home):
        # Don't init; config doesn't exist.
        with pytest.raises(FileNotFoundError):
            cli.main(["identity", "show"])
