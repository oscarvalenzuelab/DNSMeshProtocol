"""Fuzz harness for RotationRecord.parse_and_verify.

Property: for ANY bytes/string input and any 32-byte expected_old_spk,
the parser must return either ``None`` or a ``RotationRecord``. It must
never raise.
"""

from __future__ import annotations

import base64

from hypothesis import HealthCheck, given, settings, strategies as st

from dmp.core.rotation import RECORD_PREFIX_ROTATION, RotationRecord

from tests.fuzz.conftest import FUZZ_MAX_EXAMPLES

SOME_SPK = bytes(range(32))


@given(wire=st.text(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_random_text(wire: str) -> None:
    result = RotationRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, RotationRecord)


@given(blob=st.binary(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_base64_body(blob: bytes) -> None:
    wire = RECORD_PREFIX_ROTATION + base64.b64encode(blob).decode("ascii")
    result = RotationRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, RotationRecord)


@given(trailing=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_truncated_prefix(trailing: bytes) -> None:
    result = RotationRecord.parse_and_verify(RECORD_PREFIX_ROTATION + trailing.hex())
    assert result is None or isinstance(result, RotationRecord)


@given(spk=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_expected_old_spk(spk: bytes) -> None:
    result = RotationRecord.parse_and_verify(
        RECORD_PREFIX_ROTATION + "AAAA", expected_old_spk=spk
    )
    assert result is None or isinstance(result, RotationRecord)


@given(subject=st.text(max_size=256))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_expected_subject(subject: str) -> None:
    result = RotationRecord.parse_and_verify(
        RECORD_PREFIX_ROTATION + "AAAA", expected_subject=subject
    )
    assert result is None or isinstance(result, RotationRecord)
