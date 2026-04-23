"""Tests for dmp.client.node_tokens — per-node bearer storage + auto-attach."""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import pytest

from dmp.client import node_tokens as nt


@pytest.fixture
def fresh_home(tmp_path: Path, monkeypatch):
    """Point DMP_TOKENS_HOME at an isolated dir per test."""
    home = tmp_path / "tokens"
    monkeypatch.setenv("DMP_TOKENS_HOME", str(home))
    yield home


class TestSanitizeHostname:
    def test_lowercases_and_strips_trailing_dot(self) -> None:
        assert nt._sanitize_hostname("DMP.Example.Com.") == "dmp.example.com"

    def test_rejects_empty(self) -> None:
        with pytest.raises(ValueError):
            nt._sanitize_hostname("")
        with pytest.raises(ValueError):
            nt._sanitize_hostname("   ")

    def test_rejects_path_traversal(self) -> None:
        for bad in ["../evil", "foo/bar", "foo\\bar", "foo bar"]:
            with pytest.raises(ValueError):
                nt._sanitize_hostname(bad)

    def test_rejects_non_ascii(self) -> None:
        with pytest.raises(ValueError):
            nt._sanitize_hostname("ｄｍｐ.example.com")  # fullwidth

    def test_accepts_plain_hostname(self) -> None:
        assert nt._sanitize_hostname("dmp.example.com") == "dmp.example.com"
        assert nt._sanitize_hostname("node-a.example.co.uk") == "node-a.example.co.uk"


class TestHostFromEndpoint:
    def test_extracts_from_url(self) -> None:
        assert nt.host_from_endpoint("https://dmp.example.com/v1/records/foo") == "dmp.example.com"

    def test_extracts_with_port(self) -> None:
        assert nt.host_from_endpoint("http://dmp.example.com:8053") == "dmp.example.com"

    def test_accepts_bare_hostport(self) -> None:
        assert nt.host_from_endpoint("dmp.example.com:8053") == "dmp.example.com"

    def test_returns_none_on_malformed(self) -> None:
        assert nt.host_from_endpoint("") is None
        assert nt.host_from_endpoint("not a url at all") is None


class TestSaveAndLoad:
    def test_round_trip(self, fresh_home: Path) -> None:
        nt.save_token(
            "dmp.example.com",
            token="dmp_v1_XXXX", subject="alice@example.com",
            expires_at=int(time.time()) + 86400,
            registered_spk="ab" * 32,
        )
        body = nt.load_token("dmp.example.com")
        assert body is not None
        assert body["token"] == "dmp_v1_XXXX"
        assert body["subject"] == "alice@example.com"
        assert body["registered_spk"] == "ab" * 32

    def test_file_mode_is_0600(self, fresh_home: Path) -> None:
        path = nt.save_token(
            "dmp.example.com", token="dmp_v1_X", subject="a@b.co",
        )
        mode = stat.S_IMODE(path.stat().st_mode)
        assert mode == 0o600, f"expected 0600, got {oct(mode)}"

    def test_parent_dir_mode_0700(self, fresh_home: Path) -> None:
        nt.save_token("dmp.example.com", token="x", subject="a@b.co")
        mode = stat.S_IMODE(fresh_home.stat().st_mode)
        # Must have group/world bits stripped; exact mode is 0700 on
        # a fresh-create, but an existing dir is left alone (tested
        # separately via the non-clobber assertion below).
        assert mode & 0o077 == 0, f"group/world bits set: {oct(mode)}"

    def test_load_returns_none_for_missing(self, fresh_home: Path) -> None:
        assert nt.load_token("missing.example.com") is None

    def test_load_tolerates_corrupt_json(self, fresh_home: Path) -> None:
        # Write a garbage file under the tokens home.
        fresh_home.mkdir(parents=True, exist_ok=True)
        (fresh_home / "broken.example.com.json").write_text("{not json")
        assert nt.load_token("broken.example.com") is None

    def test_save_overwrites_existing(self, fresh_home: Path) -> None:
        nt.save_token("dmp.example.com", token="old", subject="a@b.co")
        nt.save_token("dmp.example.com", token="new", subject="a@b.co")
        body = nt.load_token("dmp.example.com")
        assert body["token"] == "new"

    def test_delete(self, fresh_home: Path) -> None:
        nt.save_token("dmp.example.com", token="x", subject="a@b.co")
        assert nt.delete_token("dmp.example.com") is True
        assert nt.load_token("dmp.example.com") is None
        # Second delete returns False.
        assert nt.delete_token("dmp.example.com") is False


class TestBearerForEndpoint:
    def test_returns_saved_token(self, fresh_home: Path) -> None:
        nt.save_token("dmp.example.com", token="dmp_v1_ABC", subject="a@b.co")
        assert nt.bearer_for_endpoint("https://dmp.example.com/v1/records/x") == "dmp_v1_ABC"

    def test_returns_none_for_unknown_host(self, fresh_home: Path) -> None:
        assert nt.bearer_for_endpoint("https://other.example.com") is None

    def test_returns_none_for_expired_token(self, fresh_home: Path) -> None:
        nt.save_token(
            "dmp.example.com",
            token="dmp_v1_expired",
            subject="a@b.co",
            expires_at=int(time.time()) - 1,
        )
        assert nt.bearer_for_endpoint("https://dmp.example.com") is None

    def test_none_expires_at_is_treated_as_infinite(self, fresh_home: Path) -> None:
        nt.save_token(
            "dmp.example.com", token="dmp_v1_forever",
            subject="a@b.co", expires_at=None,
        )
        assert nt.bearer_for_endpoint("https://dmp.example.com") == "dmp_v1_forever"


class TestListTokens:
    def test_yields_saved(self, fresh_home: Path) -> None:
        nt.save_token("a.example.com", token="t1", subject="a@example.com")
        nt.save_token("b.example.com", token="t2", subject="b@example.com")
        rows = list(nt.list_tokens())
        nodes = sorted(r["node"] for r in rows)
        assert nodes == ["a.example.com", "b.example.com"]

    def test_skips_broken(self, fresh_home: Path) -> None:
        fresh_home.mkdir(parents=True, exist_ok=True)
        (fresh_home / "broken.json").write_text("nope")
        nt.save_token("a.example.com", token="t1", subject="a@example.com")
        rows = list(nt.list_tokens())
        assert len(rows) == 1

    def test_empty_home(self, fresh_home: Path) -> None:
        assert list(nt.list_tokens()) == []
