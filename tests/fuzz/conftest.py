"""Shared test config for the fuzz suite.

Exposes ``FUZZ_MAX_EXAMPLES`` used by each property test's ``@settings``
decorator. Default 500 is fine for PR CI (a few seconds per property);
the weekly scheduled cron in ``.github/workflows/security.yml`` sets
``DMP_FUZZ_MAX_EXAMPLES=5000`` for deeper coverage.
"""

from __future__ import annotations

import os

FUZZ_MAX_EXAMPLES: int = int(os.environ.get("DMP_FUZZ_MAX_EXAMPLES", "500"))
