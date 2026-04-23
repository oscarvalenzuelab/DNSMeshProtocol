"""Tests for dmp.server.admin helpers."""

from __future__ import annotations

import pytest

from dmp.server.admin import parse_duration


class TestParseDuration:
    def test_bare_seconds(self) -> None:
        assert parse_duration("60") == 60
        assert parse_duration("0") == 0

    def test_unit_suffixes(self) -> None:
        assert parse_duration("30s") == 30
        assert parse_duration("15m") == 15 * 60
        assert parse_duration("2h") == 2 * 3600
        assert parse_duration("7d") == 7 * 86400
        assert parse_duration("4w") == 4 * 7 * 86400

    def test_ascii_whitespace_stripped(self) -> None:
        assert parse_duration("  30s  ") == 30
        assert parse_duration("\t7d\n") == 7 * 86400

    def test_empty_rejected(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            parse_duration("")
        with pytest.raises(ValueError, match="empty"):
            parse_duration("   ")

    def test_unknown_unit_rejected(self) -> None:
        with pytest.raises(ValueError, match="duration"):
            parse_duration("5y")  # years not supported

    def test_malformed_rejected(self) -> None:
        with pytest.raises(ValueError, match="duration"):
            parse_duration("abc")
        with pytest.raises(ValueError, match="duration"):
            parse_duration("5s5")
        with pytest.raises(ValueError, match="duration"):
            parse_duration("5 s")  # internal space not allowed

    def test_rejects_arabic_indic_digits(self) -> None:
        """Regression: int('١٠s') previously yielded 10 via Python's
        Unicode-digit coercion, giving an operator a surprising
        valid-looking duration from a mixed-locale paste."""
        with pytest.raises(ValueError, match="duration"):
            parse_duration("١٠s")
        with pytest.raises(ValueError, match="duration"):
            parse_duration("۵d")

    def test_rejects_nbsp_inside_token(self) -> None:
        """Regression: '90 d' (NBSP between digits and unit) used
        to parse as 90 days; now rejected."""
        with pytest.raises(ValueError, match="duration"):
            parse_duration("90 d")
        with pytest.raises(ValueError, match="duration"):
            parse_duration("90 d")  # em-space

    def test_rejects_negative(self) -> None:
        # Negative numbers have a minus sign which isn't in the regex.
        with pytest.raises(ValueError, match="duration"):
            parse_duration("-5s")

    def test_rejects_uppercase_units(self) -> None:
        # Strict — 'H' not allowed to keep the accepted surface small
        # and discourage mixed-case invocations.
        with pytest.raises(ValueError, match="duration"):
            parse_duration("5H")
