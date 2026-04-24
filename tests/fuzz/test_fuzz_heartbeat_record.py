"""Hypothesis fuzz for HeartbeatRecord.parse_and_verify (M5.8).

parse_and_verify is the only trust entry for the record type; it
MUST never raise on any input — malformed bytes, truncated wire,
tampered base64, nothing. Every failure path returns None.

Run extended locally with
  HYPOTHESIS_PROFILE=ci pytest tests/fuzz/test_fuzz_heartbeat_record.py
"""

from __future__ import annotations

import base64
import os

import hypothesis
from hypothesis import given, strategies as st

from dmp.core.heartbeat import RECORD_PREFIX, HeartbeatRecord

hypothesis.settings.register_profile("ci", max_examples=5000, deadline=None)
hypothesis.settings.register_profile("default", max_examples=500, deadline=None)
hypothesis.settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


@given(st.text(max_size=2000))
def test_parse_never_raises_on_arbitrary_text(wire: str) -> None:
    # Worst-case inputs: any string up to 2KB. Must return a valid
    # HeartbeatRecord or None; no exceptions allowed.
    result = HeartbeatRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, HeartbeatRecord)


@given(st.binary(max_size=2000))
def test_parse_never_raises_on_random_body(blob: bytes) -> None:
    wire = RECORD_PREFIX + base64.b64encode(blob).decode("ascii")
    result = HeartbeatRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, HeartbeatRecord)


@given(st.binary(max_size=500))
def test_parse_never_raises_on_random_bytes_after_prefix(body: bytes) -> None:
    # The b64 layer itself rejects non-b64 inputs — this test covers
    # the "valid b64, garbage body" case.
    wire = RECORD_PREFIX + body.hex()  # hex is a subset of b64 alphabet
    result = HeartbeatRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, HeartbeatRecord)


@given(
    prefix=st.sampled_from(
        [
            RECORD_PREFIX,
            "v=dmp1;t=heartbeat",  # missing trailing semicolon
            "v=dmp1;t=rotation;",  # wrong type
            "",
            "v=dmp2;t=heartbeat;",  # future version
        ]
    ),
    body=st.binary(max_size=200),
)
def test_prefix_variants_never_raise(prefix: str, body: bytes) -> None:
    wire = prefix + base64.b64encode(body).decode("ascii")
    result = HeartbeatRecord.parse_and_verify(wire)
    assert result is None or isinstance(result, HeartbeatRecord)
