"""Fuzz harness for Prekey.parse_and_verify.

Property: for ANY bytes / string input and any ``expected_signer_spk``,
the parser must return either ``None`` or a ``Prekey``. It must never
raise.

Prekey records do not self-identify their signer — they're signed by
the user's identity key, which must be supplied externally by the
caller (via prior IdentityRecord lookup).
"""

from __future__ import annotations

import base64

from hypothesis import HealthCheck, given, settings, strategies as st

from dmp.core.prekeys import RECORD_PREFIX, Prekey

from tests.fuzz.conftest import FUZZ_MAX_EXAMPLES

SOME_SIGNER_SPK = bytes(range(32))


@given(wire=st.text(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_random_text(wire: str) -> None:
    result = Prekey.parse_and_verify(wire, SOME_SIGNER_SPK)
    assert result is None or isinstance(result, Prekey)


@given(blob=st.binary(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_base64_body(blob: bytes) -> None:
    wire = RECORD_PREFIX + base64.b64encode(blob).decode("ascii")
    result = Prekey.parse_and_verify(wire, SOME_SIGNER_SPK)
    assert result is None or isinstance(result, Prekey)


@given(trailing=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_truncated_prefix(trailing: bytes) -> None:
    result = Prekey.parse_and_verify(RECORD_PREFIX + trailing.hex(), SOME_SIGNER_SPK)
    assert result is None or isinstance(result, Prekey)


@given(spk=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_signer_spk(spk: bytes) -> None:
    result = Prekey.parse_and_verify(RECORD_PREFIX + "AAAA", spk)
    assert result is None or isinstance(result, Prekey)
