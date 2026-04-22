"""Fuzz harness for SlotManifest.parse_and_verify.

Property: for ANY bytes / string input, the parser must return either
``None`` or ``(SlotManifest, signature_bytes)``. It must never raise.

Like IdentityRecord, SlotManifest is self-signing (sender_spk is carried
in the body and verified against it), so ``parse_and_verify`` takes
only the wire argument.
"""

from __future__ import annotations

import base64

from hypothesis import HealthCheck, given, settings, strategies as st

from dmp.core.manifest import RECORD_PREFIX, SlotManifest

from tests.fuzz.conftest import FUZZ_MAX_EXAMPLES


def _valid_shape(result: object) -> bool:
    if result is None:
        return True
    if not isinstance(result, tuple) or len(result) != 2:
        return False
    rec, sig = result
    return isinstance(rec, SlotManifest) and isinstance(sig, (bytes, bytearray))


@given(wire=st.text(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_random_text(wire: str) -> None:
    result = SlotManifest.parse_and_verify(wire)
    assert _valid_shape(result)


@given(blob=st.binary(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_base64_body(blob: bytes) -> None:
    wire = RECORD_PREFIX + base64.b64encode(blob).decode("ascii")
    result = SlotManifest.parse_and_verify(wire)
    assert _valid_shape(result)


@given(trailing=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_truncated_prefix(trailing: bytes) -> None:
    result = SlotManifest.parse_and_verify(RECORD_PREFIX + trailing.hex())
    assert _valid_shape(result)
