"""Fuzz harness for ClusterManifest.parse_and_verify.

Property: for ANY bytes / string input and any 32-byte operator_spk, the
parser must return either ``None`` or a ``ClusterManifest``. It must
never raise. An exception escaping here is a DoS vector — a cluster
node that decodes peer-gossiped manifest TXT values would crash the
anti-entropy worker.
"""

from __future__ import annotations

import base64

from hypothesis import HealthCheck, given, settings, strategies as st

from dmp.core.cluster import RECORD_PREFIX, ClusterManifest

from tests.fuzz.conftest import FUZZ_MAX_EXAMPLES

# A deterministic 32-byte "operator key". The actual bytes don't matter
# — we're probing parser robustness, not signature correctness; no input
# the harness generates will produce a valid signature under it.
SOME_OPERATOR_SPK = bytes(range(32))


@given(wire=st.text(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_random_text(wire: str) -> None:
    result = ClusterManifest.parse_and_verify(wire, SOME_OPERATOR_SPK)
    assert result is None or isinstance(result, ClusterManifest)


@given(blob=st.binary(max_size=2048))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_base64_body(blob: bytes) -> None:
    wire = RECORD_PREFIX + base64.b64encode(blob).decode("ascii")
    result = ClusterManifest.parse_and_verify(wire, SOME_OPERATOR_SPK)
    assert result is None or isinstance(result, ClusterManifest)


@given(trailing=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_truncated_prefix(trailing: bytes) -> None:
    result = ClusterManifest.parse_and_verify(
        RECORD_PREFIX + trailing.hex(), SOME_OPERATOR_SPK
    )
    assert result is None or isinstance(result, ClusterManifest)


@given(op_spk=st.binary(max_size=64))
@settings(
    max_examples=FUZZ_MAX_EXAMPLES,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)
def test_parse_never_raises_on_arbitrary_operator_spk(op_spk: bytes) -> None:
    # Defensive: a caller could pass a non-32-byte key. parse_and_verify
    # already guards this, but fuzz it explicitly.
    result = ClusterManifest.parse_and_verify(RECORD_PREFIX + "AAAA", op_spk)
    assert result is None or isinstance(result, ClusterManifest)
