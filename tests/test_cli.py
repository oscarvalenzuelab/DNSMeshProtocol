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
        for name, entry in config.contacts.items():
            client.add_contact(
                name,
                entry.get("pub", ""),
                domain=config.domain,
                signing_key_hex=entry.get("spk", ""),
            )
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
        rc = cli.main(
            ["init", "alice", "--domain", "mesh.test", "--endpoint", "http://node:8053"]
        )
        assert rc == 0
        cfg = yaml.safe_load((config_home / "config.yaml").read_text())
        assert cfg["username"] == "alice"
        assert cfg["domain"] == "mesh.test"
        assert cfg["endpoint"] == "http://node:8053"
        # Per-identity random salt: 32 bytes = 64 hex chars.
        assert len(cfg["kdf_salt"]) == 64

    def test_init_generates_unique_salts_per_identity(
        self, config_home, tmp_path, monkeypatch
    ):
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

    def test_identity_show_prints_keys(
        self, config_home, shared_store, monkeypatch, capsys
    ):
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

    def test_publish_then_fetch_roundtrip(
        self, config_home, shared_store, monkeypatch, capsys
    ):
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

    def test_fetch_add_stores_contact(
        self, config_home, shared_store, monkeypatch, capsys
    ):
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

    def test_fetch_missing_identity_errors(
        self, config_home, shared_store, monkeypatch
    ):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        with pytest.raises(SystemExit) as exc:
            cli.main(["identity", "fetch", "nobody"])
        assert exc.value.code == 2

    def test_zone_anchored_publish_and_fetch(
        self, config_home, shared_store, monkeypatch, capsys
    ):
        """Identity published under a user-controlled zone resolves via
        `user@host` addresses instead of the hash-based shared-mesh name."""
        # alice initializes with her own zone; publish goes to dmp.alice.example.com
        cli.main(
            [
                "init",
                "alice",
                "--endpoint",
                "http://x",
                "--identity-domain",
                "alice.example.com",
            ]
        )
        capsys.readouterr()
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        cli.main(["identity", "publish"])
        out = capsys.readouterr().out
        assert "published identity to dmp.alice.example.com" in out
        assert "alice@alice.example.com" in out

        # Bob fetches via the zone-anchored address.
        bob_home = config_home.parent / "bob-zone"
        monkeypatch.setenv("DMP_CONFIG_HOME", str(bob_home))
        cli.main(["init", "bob", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        capsys.readouterr()

        cli.main(["identity", "fetch", "alice@alice.example.com", "--add"])
        out = capsys.readouterr().out
        assert "added contact alice" in out

        cli.main(["contacts", "list"])
        assert "alice" in capsys.readouterr().out

    def test_zone_anchored_fetch_rejects_username_mismatch(
        self, config_home, shared_store, monkeypatch, capsys
    ):
        """An attacker who controls `alice.example.com` can't publish an
        identity record carrying username="bob" and have it stored as bob
        in a fetcher's contact list. The address's user part must match
        the record's username field."""
        from dmp.core.crypto import DMPCrypto
        from dmp.core.identity import (
            make_record,
            zone_anchored_identity_name,
        )

        # Skip normal publish — craft a record with mismatched username
        # directly and drop it in the shared store.
        attacker_crypto = DMPCrypto()
        record = make_record(attacker_crypto, "bob")  # record says "bob"
        wire = record.sign(attacker_crypto)
        shared_store.publish_txt_record(
            zone_anchored_identity_name("alice.example.com"),  # but at alice's zone
            wire,
        )

        # carol tries `dmp identity fetch alice@alice.example.com --add`.
        cli.main(["init", "carol", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "carol-pass")
        capsys.readouterr()

        with pytest.raises(SystemExit) as exc:
            cli.main(["identity", "fetch", "alice@alice.example.com", "--add"])
        assert exc.value.code == 2

    def test_fetch_refuses_ambiguous_without_fingerprint(
        self, config_home, shared_store, monkeypatch, capsys
    ):
        """Two valid identity records at the same name force manual choice.

        An attacker who squats `id-{hash(alice)}.{domain}` before the real
        alice publishes creates an RRset with two valid self-signed
        records. Auto-picking the first one hands the attacker a win;
        instead, fetch dumps fingerprints and requires --accept-fingerprint.
        """
        from dmp.core.crypto import DMPCrypto
        from dmp.core.identity import identity_domain, make_record

        # Real alice publishes her identity.
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        monkeypatch.setenv("DMP_PASSPHRASE", "alice-pass")
        cli.main(["identity", "publish"])
        capsys.readouterr()

        # An attacker with a different keypair publishes another valid
        # identity record for username "alice" at the same DNS name.
        attacker = DMPCrypto()
        squat = make_record(attacker, "alice").sign(attacker)
        name = identity_domain("alice", "mesh.local")
        shared_store.publish_txt_record(name, squat)

        # Bob tries to fetch alice. Two records; auto-pick refused.
        bob_home = config_home.parent / "bob-squat-home"
        monkeypatch.setenv("DMP_CONFIG_HOME", str(bob_home))
        cli.main(["init", "bob", "--endpoint", "http://x"])
        monkeypatch.setenv("DMP_PASSPHRASE", "bob-pass")
        capsys.readouterr()

        with pytest.raises(SystemExit) as exc:
            cli.main(["identity", "fetch", "alice", "--add"])
        assert exc.value.code == 2
        err = capsys.readouterr().err
        assert "ambiguous" in err
        assert "fingerprint=" in err
        assert "--accept-fingerprint" in err


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
    def test_send_and_recv_roundtrip(
        self, config_home, shared_store, monkeypatch, capsys
    ):
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

    def test_send_unknown_recipient_errors(
        self, config_home, shared_store, monkeypatch
    ):
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

    def test_recv_twice_is_idempotent(
        self, config_home, shared_store, monkeypatch, capsys
    ):
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


class TestResolversCommand:
    """`dmp resolvers discover` + `dmp resolvers list`.

    Network probes are mocked out via a stub ResolverPool that returns
    a fixed host list, so the tests run offline and deterministically.
    """

    def _stub_discover(self, monkeypatch, hosts):
        """Replace ResolverPool.discover with one that returns a stub pool."""
        from dmp.network.resolver_pool import ResolverPool

        class _StubPool:
            def snapshot(self):
                return [{"host": h} for h in hosts]

        def fake_discover(candidates, timeout=2.0):
            if not hosts:
                raise ValueError(
                    "ResolverPool.discover: no candidates answered "
                    f"within {timeout}s"
                )
            return _StubPool()

        # Patch the symbol the CLI imported, not just ResolverPool itself.
        monkeypatch.setattr(cli.ResolverPool, "discover", staticmethod(fake_discover))

    def test_discover_prints_working_list(self, config_home, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        self._stub_discover(monkeypatch, ["1.1.1.1", "9.9.9.9"])

        rc = cli.main(["resolvers", "discover"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "discovered 2 working resolver(s)" in out
        assert "1.1.1.1" in out
        assert "9.9.9.9" in out

    def test_discover_without_save_does_not_touch_config(
        self, config_home, monkeypatch, capsys
    ):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        cfg_path = config_home / "config.yaml"
        before = yaml.safe_load(cfg_path.read_text())
        assert before.get("dns_resolvers", []) == []

        self._stub_discover(monkeypatch, ["1.1.1.1", "9.9.9.9"])
        cli.main(["resolvers", "discover"])

        after = yaml.safe_load(cfg_path.read_text())
        assert after.get("dns_resolvers", []) == []

    def test_discover_with_save_writes_config(self, config_home, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        self._stub_discover(monkeypatch, ["1.1.1.1", "9.9.9.9", "8.8.8.8"])

        rc = cli.main(["resolvers", "discover", "--save"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "saved 3 resolvers" in out

        cfg = yaml.safe_load((config_home / "config.yaml").read_text())
        assert cfg["dns_resolvers"] == ["1.1.1.1", "9.9.9.9", "8.8.8.8"]

    def test_discover_save_then_list_shows_them(self, config_home, monkeypatch, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        self._stub_discover(monkeypatch, ["1.1.1.1", "9.9.9.9"])
        cli.main(["resolvers", "discover", "--save"])
        capsys.readouterr()

        cli.main(["resolvers", "list"])
        out = capsys.readouterr().out
        assert "1.1.1.1" in out
        assert "9.9.9.9" in out

    def test_list_without_saved_resolvers_prints_hint(self, config_home, capsys):
        cli.main(["init", "alice", "--endpoint", "http://x"])
        capsys.readouterr()
        cli.main(["resolvers", "list"])
        out = capsys.readouterr().out
        assert "no dns_resolvers configured" in out

    def test_discover_save_without_config_errors(
        self, config_home, monkeypatch, capsys
    ):
        """`--save` on a fresh machine (no `dmp init` yet) fails cleanly."""
        self._stub_discover(monkeypatch, ["1.1.1.1"])
        with pytest.raises(SystemExit) as exc:
            cli.main(["resolvers", "discover", "--save"])
        assert exc.value.code == 1

    def test_discover_all_failures_exits_with_network_error(
        self, config_home, monkeypatch
    ):
        """Every probe failed -> ResolverPool.discover raises ValueError,
        CLI surfaces it as exit code 2 (network/backend error)."""
        cli.main(["init", "alice", "--endpoint", "http://x"])
        self._stub_discover(monkeypatch, [])
        with pytest.raises(SystemExit) as exc:
            cli.main(["resolvers", "discover"])
        assert exc.value.code == 2
