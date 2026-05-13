"""Tests for the DMPv2 plaintext envelope."""

from __future__ import annotations

import json

import pytest

from dmp.core.envelope import (
    DMPV2_PREFIX,
    MAX_HEADER_BYTES,
    canonicalize_address,
    decode,
    encode,
)


class TestCanonicalizeAddress:
    def test_simple_address_passes_through(self):
        assert canonicalize_address("alice@example.com") == "alice@example.com"

    def test_lowercases(self):
        assert canonicalize_address("Alice@Example.COM") == "alice@example.com"

    def test_strips_surrounding_whitespace(self):
        assert canonicalize_address("  alice@example.com  ") == "alice@example.com"

    def test_strips_trailing_dot_on_host(self):
        assert canonicalize_address("alice@example.com.") == "alice@example.com"

    def test_allows_subdomain(self):
        assert canonicalize_address("bob@dmp.dnsmesh.io") == "bob@dmp.dnsmesh.io"

    def test_allows_digits_and_hyphens_in_host(self):
        assert canonicalize_address("u1@a-host.example.com") == "u1@a-host.example.com"

    def test_allows_localpart_punctuation(self):
        for addr in ("a.b@c.d", "a_b@c.d", "a-b@c.d", "a1b@c.d"):
            assert canonicalize_address(addr) == addr.lower()

    def test_rejects_non_ascii(self):
        assert canonicalize_address("álice@example.com") is None
        assert canonicalize_address("alice@éxample.com") is None
        # confusable: Cyrillic 'а' looks like Latin 'a'
        assert canonicalize_address("аlice@example.com") is None

    def test_rejects_missing_at(self):
        assert canonicalize_address("aliceexample.com") is None

    def test_rejects_multiple_at(self):
        assert canonicalize_address("alice@bob@example.com") is None

    def test_rejects_empty_local(self):
        assert canonicalize_address("@example.com") is None

    def test_rejects_empty_host(self):
        assert canonicalize_address("alice@") is None
        assert canonicalize_address("alice@.") is None

    def test_rejects_localpart_starting_with_punctuation(self):
        assert canonicalize_address(".alice@example.com") is None
        assert canonicalize_address("-alice@example.com") is None

    def test_rejects_localpart_ending_with_dot(self):
        assert canonicalize_address("alice.@example.com") is None

    def test_rejects_double_dot_in_localpart(self):
        assert canonicalize_address("a..b@example.com") is None

    def test_rejects_host_label_with_leading_hyphen(self):
        assert canonicalize_address("alice@-bad.example.com") is None

    def test_rejects_host_label_with_trailing_hyphen(self):
        assert canonicalize_address("alice@bad-.example.com") is None

    def test_rejects_oversize_localpart(self):
        # 65 chars: localpart cap is 64
        long_local = "a" * 65
        assert canonicalize_address(f"{long_local}@example.com") is None

    def test_accepts_localpart_at_cap(self):
        long_local = "a" * 64
        canonical = canonicalize_address(f"{long_local}@example.com")
        assert canonical == f"{long_local}@example.com"

    def test_rejects_oversize_host(self):
        # 254 chars: host cap is 253
        long_host = ("a" * 63 + ".") * 4 + "abc"  # > 253
        assert len(long_host) > 253
        assert canonicalize_address(f"a@{long_host}") is None

    def test_rejects_non_string_input(self):
        assert canonicalize_address(None) is None  # type: ignore[arg-type]
        assert canonicalize_address(b"alice@example.com") is None  # type: ignore[arg-type]
        assert canonicalize_address(123) is None  # type: ignore[arg-type]


class TestEncode:
    def test_none_sender_returns_body_unchanged(self):
        body = b"hello world"
        assert encode(body, sender_addr=None) == body

    def test_invalid_sender_returns_body_unchanged(self):
        body = b"hello world"
        # canonicalize_address would reject this, so encode skips wrapping
        assert encode(body, sender_addr="not-an-address") == body

    def test_valid_sender_produces_wrapper(self):
        wrapped = encode(b"hi", sender_addr="alice@example.com")
        assert wrapped.startswith(DMPV2_PREFIX)
        assert wrapped.endswith(b"hi")
        # header is canonical JSON
        header_part = wrapped[len(DMPV2_PREFIX) : -len(b"\nhi")]
        assert header_part == b'{"from":"alice@example.com"}'

    def test_canonicalizes_sender_before_wrapping(self):
        wrapped = encode(b"hi", sender_addr="ALICE@Example.COM.")
        # canonicalization lowercases and strips trailing dot
        assert b'"from":"alice@example.com"' in wrapped

    def test_empty_body_works(self):
        wrapped = encode(b"", sender_addr="alice@example.com")
        assert wrapped == DMPV2_PREFIX + b'{"from":"alice@example.com"}' + b"\n"

    def test_body_with_newlines_works(self):
        body = b"line1\nline2\nline3"
        wrapped = encode(body, sender_addr="alice@example.com")
        assert wrapped.endswith(b"\n" + body)


class TestDecode:
    def test_v1_plaintext_returns_unchanged(self):
        body, sender = decode(b"plain message no wrapper")
        assert body == b"plain message no wrapper"
        assert sender is None

    def test_empty_plaintext_returns_unchanged(self):
        body, sender = decode(b"")
        assert body == b""
        assert sender is None

    def test_v2_envelope_roundtrip(self):
        wrapped = encode(b"hello", sender_addr="alice@example.com")
        body, sender = decode(wrapped)
        assert body == b"hello"
        assert sender == "alice@example.com"

    def test_v2_envelope_with_empty_body(self):
        wrapped = encode(b"", sender_addr="alice@example.com")
        body, sender = decode(wrapped)
        assert body == b""
        assert sender == "alice@example.com"

    def test_v2_envelope_with_binary_body(self):
        binary = bytes(range(256))
        wrapped = encode(binary, sender_addr="alice@example.com")
        body, sender = decode(wrapped)
        assert body == binary
        assert sender == "alice@example.com"

    def test_canonicalizes_sender_on_decode(self):
        # Manually craft an envelope with a non-canonical from value to
        # confirm decode normalizes (mirrors what a malicious or buggy
        # sender might emit).
        raw_header = b'{"from":"Alice@Example.COM."}'
        wrapped = DMPV2_PREFIX + raw_header + b"\n" + b"body"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender == "alice@example.com"

    def test_prefix_no_newline_returns_full_plaintext(self):
        # No newline anywhere → treat as v1 (safety valve for the
        # implausible coincidence of a v1 body starting with DMPV2:).
        body, sender = decode(DMPV2_PREFIX + b"junk no newline")
        assert body == DMPV2_PREFIX + b"junk no newline"
        assert sender is None

    def test_prefix_newline_past_max_header_returns_full_plaintext(self):
        # Newline exists but past the size cap → still treat as v1.
        long_header = b"x" * (MAX_HEADER_BYTES + 5)
        body, sender = decode(DMPV2_PREFIX + long_header + b"\nrest")
        assert body == DMPV2_PREFIX + long_header + b"\nrest"
        assert sender is None

    def test_bad_json_falls_back_to_v1_plaintext(self):
        """A real v2 wrapper from this codebase always emits well-formed
        canonical JSON, so a header that fails to parse is far more
        likely a v1 message that happens to start with ``DMPV2:`` than
        a genuine envelope. Decode MUST fall back to the full
        plaintext so the legacy sender's body isn't truncated."""
        wrapped = DMPV2_PREFIX + b"{not json}" + b"\nbody"
        body, sender = decode(wrapped)
        assert body == wrapped
        assert sender is None

    def test_json_not_a_dict_falls_back_to_v1_plaintext(self):
        """A list-shaped header is not a real envelope — fall back to v1."""
        wrapped = DMPV2_PREFIX + b'["alice@example.com"]' + b"\nbody"
        body, sender = decode(wrapped)
        assert body == wrapped
        assert sender is None

    def test_missing_from_key_returns_body_with_none(self):
        wrapped = DMPV2_PREFIX + b'{"other":"x"}' + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender is None

    def test_from_not_a_string_returns_body_with_none(self):
        wrapped = DMPV2_PREFIX + b'{"from":42}' + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender is None

    def test_from_fails_canonicalization_returns_body_with_none(self):
        wrapped = DMPV2_PREFIX + b'{"from":"not-an-address"}' + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender is None

    def test_ignores_unknown_keys(self):
        # Forward-compat: a future sender adds a "reply_to" field; the
        # current decoder must still extract from.
        header = json.dumps(
            {"from": "alice@example.com", "reply_to": "bob@example.com"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        wrapped = DMPV2_PREFIX + header + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender == "alice@example.com"

    def test_oversize_header_at_exact_cap(self):
        # Exactly MAX_HEADER_BYTES of header content + newline → still
        # within the cap (cap is on header length, not header+newline).
        pad = "a" * (MAX_HEADER_BYTES - len('{"from":"a@b.c","x":""}'))
        header = json.dumps(
            {"from": "a@b.c", "x": pad}, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        assert len(header) <= MAX_HEADER_BYTES
        wrapped = DMPV2_PREFIX + header + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender == "a@b.c"

    def test_decode_strips_envelope_when_header_is_valid_dict_but_from_unverifiable(
        self,
    ):
        # A well-formed JSON dict header commits to the envelope. The
        # from claim may be junk (not a real address) — in that case
        # the body is returned cleanly without a label.
        wrapped = DMPV2_PREFIX + b'{"from":"bogus"}' + b"\nbody"
        body, sender = decode(wrapped)
        assert body == b"body"
        assert sender is None
        # Confirm no prefix leakage:
        assert DMPV2_PREFIX not in body

    def test_legacy_message_starting_with_prefix_and_newline_preserved(self):
        """A v1 message whose first few bytes happen to be ``DMPV2:``
        followed by some text and a newline within 256 bytes MUST be
        delivered intact, not truncated. The decoder requires
        well-formed JSON to commit."""
        legacy = DMPV2_PREFIX + b"actual first line\nrest of message"
        body, sender = decode(legacy)
        assert body == legacy  # full plaintext preserved
        assert sender is None


class TestEncodeDecodeRoundtrip:
    @pytest.mark.parametrize(
        "addr,body",
        [
            ("alice@example.com", b"hello"),
            ("bob.smith@mail.example.com", b""),
            ("a@b.c", b"\x00\x01\x02 binary payload"),
            ("u1@dmp.dnsmesh.io", b"x" * 4096),
        ],
    )
    def test_roundtrip(self, addr, body):
        wrapped = encode(body, sender_addr=addr)
        decoded_body, decoded_sender = decode(wrapped)
        assert decoded_body == body
        assert decoded_sender == addr

    def test_v1_body_is_idempotent_through_decode(self):
        # A v1 plaintext that does NOT use the prefix passes through
        # decode unchanged.
        body = b"unwrapped legacy message"
        decoded_body, decoded_sender = decode(body)
        assert decoded_body == body
        assert decoded_sender is None
