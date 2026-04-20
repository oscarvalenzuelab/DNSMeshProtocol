# Contributing

Thanks for considering a patch. A few ground rules.

## Before you start

- This is alpha software. Protocol and API can change. Expect to revisit
  a PR if the thing you're changing is itself under active design.
- For anything larger than a bug fix or a small feature, open an issue
  first so we can agree on the shape before you sink time into code.
- Security-sensitive changes (anything touching `dmp/core/crypto.py`,
  `dmp/core/manifest.py`, or the AEAD AAD surface) warrant an extra
  round of review. Don't merge those on the same day they're opened.

## Local setup

```bash
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest -v
```

For the full docker integration tests:

```bash
docker build -t dmp-node:latest .
pytest tests/test_docker_integration.py -v
```

## Code style

- Black is the formatter. CI runs `black --check dmp tests`. Run
  `black dmp tests` before you push.
- Type hints on public APIs. `mypy dmp` should not grow net new errors.
- Don't add new top-level dependencies without a clear reason. The
  runtime deps today are `cryptography`, `dnspython`, `reedsolo`,
  `pyyaml`, `requests`, `boto3`. CLI + server rely on stdlib.
- Default to writing no comments. If removing a comment wouldn't confuse
  a future reader, don't write it. Reserve comments for *why* something
  non-obvious is the way it is — a subtle invariant, a workaround for a
  specific bug, a constraint that isn't visible in the code.
- Prefer focused edits over refactor-adjacent cleanup. A bug fix
  shouldn't also rename twelve unrelated files.

## Tests

Every PR that changes behavior needs a test. The bar is:

- Unit tests for pure logic (core, storage, manifest, crypto).
- Integration tests for anything that crosses the server/client boundary.
- Regression tests for anything codex or a reviewer flags as a bug.

Name tests after the behavior, not the function: `test_forged_manifest_rejected`,
not `test_parse_and_verify_2`. Future-you will thank you.

## Commit and PR hygiene

- One logical change per commit. A PR can have multiple commits; each
  should stand on its own.
- Commit subjects in imperative mood, under ~72 chars. Bodies wrap at
  ~80. Explain *why*, not *what* — the diff says what.
- `git log --oneline` should read like a coherent narrative of the
  branch, not `wip`, `more`, `fix tests` x 6.

## What we won't merge

- Backwards-compatibility shims for unreleased APIs. If it's not tagged,
  it can change.
- Feature flags "just in case." Make the decision; delete the flag.
- PRs that disable `--no-verify`, skip hooks, or bypass the test suite
  to land something.
- Protocol changes without a corresponding update to `DMP_SPEC.md` /
  `PROTOCOL.md` / `CHANGELOG.md`.

## Questions

Open an issue. Or email the author (oscar.valenzuela.b@gmail.com) if
the question is security-sensitive.
