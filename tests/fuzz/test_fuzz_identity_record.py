"""Fuzz harness for IdentityRecord.parse_and_verify.

Property: for ANY bytes / string input, ``parse_and_verify`` must return
either ``None`` or ``(IdentityRecord, signature_bytes)``. It must never
raise.

Identity records are self-signing — the signer's Ed25519 pubkey is
carried inside the body itself — so the parser takes only the wire
argument. No external ``operator_spk`` to fuzz.
"""

from __future__ import annotations

import base64

from hypothesis import HealthCheck, given, settings, strategies as st

from dmp.core.identity import RECORD_PREFIX, IdentityRecord

from tests.fuzz.conftest import FUZZ_MAX_EXAMPLES


def _valid_shape(result: object) -> bool:
    """True iff result is None or a 2-tuple ``(IdentityRecord, bytes)``."""
    if result is None:
        return True
    if not isinstance(result, tuple) or len(result) != 2:
        return False
    rec, sig = result
    return isinstance(rec, IdentityRecord) and isinstance(sig, (bytes, bytearray))


@given(wire=st.text(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_random_text(wire: str) -> None:
    result = IdentityRecord.parse_and_verify(wire)
    assert _valid_shape(result)


@given(blob=st.binary(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_base64_body(blob: bytes) -> None:
    wire = RECORD_PREFIX + base64.b64encode(blob).decode("ascii")
    result = IdentityRecord.parse_and_verify(wire)
    assert _valid_shape(result)


@given(trailing=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_truncated_prefix(trailing: bytes) -> None:
    result = IdentityRecord.parse_and_verify(RECORD_PREFIX + trailing.hex())
    assert _valid_shape(result)
