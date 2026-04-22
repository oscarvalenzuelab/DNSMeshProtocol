"""Property-based fuzz tests for every wire parser.

The contract the parsers must uphold: ``parse_and_verify`` on arbitrary
bytes (prefixed or not, base64-valid or not, signature-valid or not)
MUST return ``None`` (or a valid parsed record) — it must never raise.
An exception escaping the parser is a denial-of-service vector: a node
decoding peer-supplied TXT values would crash the receive thread.

Each test file covers one record type. The properties are:

1. Any random text input → no exception.
2. A prefix-matching wire with a random base64 body → no exception.
3. A prefix-matching wire with a random trailing hex suffix (exercises
   the prefix / decoder split) → no exception.

See ``conftest.py`` for how ``max_examples`` scales between PR CI and
the weekly extended fuzz run (set via ``DMP_FUZZ_MAX_EXAMPLES``).
"""
