<!--
PR title format: `[<TASK-ID>] <one-line summary>`
Read AGENTS.md before opening this PR.
-->

## Task

**Task ID:** `<M1.1 | M1.2 | ...>` (from `TASKS.md`)
**Role:** Implementer
**Worktree:** `<branch name>`

## What changed

<!--
30-second summary. Why did this change happen, and what does the
reader need to know to review it? Link ROADMAP.md / TASKS.md items.
-->

## Tests

<!--
List new or modified tests. For each, say what behavior it pins.
Delete tests only with explicit justification.
-->

- [ ] New tests cover the new behavior
- [ ] Existing tests still pass locally: `pytest -v`
- [ ] `black --check dmp tests` passes
- [ ] `mypy --ignore-missing-imports dmp` produces no new errors
- [ ] Docker integration tests pass (if server/ or client/ touched)

## Security implications

<!--
Mandatory section. Pick one and expand:

- [ ] None — this PR does not touch security-sensitive code
- [ ] Wire format — specify the before/after and backward compatibility
- [ ] AEAD AAD surface — specify exactly what bytes changed and why
- [ ] Key management — specify key lifecycle impact
- [ ] Network surface — specify new endpoints / listening ports
- [ ] Other: ___________
-->

## Breaking changes

<!--
Anything that would make a client built against the previous tag stop
working? If yes, enumerate and add to CHANGELOG.md under BREAKING.
-->

- [ ] No breaking changes
- [ ] Wire format changed (protocol bump documented in CHANGELOG)
- [ ] CLI surface changed (docs updated)
- [ ] Library API changed (docs updated)

## Review gates

<!-- Fill these in as review progresses. -->

- [ ] CI green (Validator)
- [ ] Codex review requested
- [ ] Codex review clean (no open P1)
- [ ] Human maintainer approved

## Definition of done

- [ ] `CHANGELOG.md` updated under the right section
- [ ] `docs/` updated for any user-facing change
- [ ] `TASKS.md` will move to `done` with this commit SHA
