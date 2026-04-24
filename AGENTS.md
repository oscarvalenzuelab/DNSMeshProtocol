# Agent workflow

This repo is developed by multiple AI agents with a human maintainer
(Oscar). Every agent — whether spawned by Claude Code, Codex, or anything
else — reads this file first before touching code.

**Read this in full. Do not skim.**

## Roles

Each role has a narrow, non-overlapping responsibility. An agent picks
**one** role per turn; roles do not share authority.

### Planner

- **Can:** read the repo, read `ROADMAP.md`, write to `TASKS.md`,
  decompose roadmap milestones into atomic tasks, set task priorities,
  resolve "which task next" conflicts.
- **Cannot:** write application code, write tests, modify files other
  than `TASKS.md`, merge PRs, approve reviews.
- **Work unit:** one roadmap milestone → ≥1 atomic task entries in
  `TASKS.md`.

### Implementer

- **Can:** claim a task in `TASKS.md` (status `pending` → `in-progress`,
  set `owner` field to their session ID), work in an **isolated git
  worktree**, write application code and tests, self-validate locally,
  push a branch, open a PR.
- **Cannot:** touch `TASKS.md` after claiming (except to release on
  abandonment), claim a task that is blocked by another in-progress
  task, merge their own PR.
- **Work unit:** one atomic task → one branch → one PR.

### Validator

- **Can:** pull a PR branch, run the full test/lint/type/docker matrix,
  comment results on the PR.
- **Cannot:** modify code, approve the PR for merge, touch `TASKS.md`.
- **Work unit:** one PR → one pass/fail validation comment.
- **Automation:** the `.github/workflows/ci.yml` workflow acts as the
  Validator for every PR automatically. An agent plays this role only
  when a human needs an independent re-run of the matrix before merge.

### Reviewer

- **Can:** invoke Codex review (`codex review --base <target-branch>`)
  against a PR diff, read code, comment findings on the PR with
  `[P1]`/`[P2]`/`[P3]` severity.
- **Cannot:** modify code, approve the PR for merge, run tests.
- **Work unit:** one PR → one Codex review comment.

### Integrator

- **Can:** merge a PR into main after all gates pass (Validator ✓,
  Reviewer ✓ with no P1 open, human ✓), update `TASKS.md` status to
  `done`, add the commit SHA to the task.
- **Cannot:** write code, write tests, skip review, merge with open
  P1 findings.
- **Work unit:** one PR → one merged commit.

## Task lifecycle

```
pending ──▶ in-progress ──▶ in-review ──▶ done
   ▲             │              │
   └─── abandon ─┘       ┌── blocked (P1 findings)
                         ▼
                      in-progress
```

| From → To | Who | Trigger |
|---|---|---|
| `pending → in-progress` | Implementer | Claim task, set `owner`, start worktree |
| `in-progress → in-review` | Implementer | Open PR, referencing task ID |
| `in-review → blocked` | Reviewer | Codex finds P1, or Validator matrix fails |
| `blocked → in-progress` | Implementer | Address findings |
| `in-review → done` | Integrator | All gates pass, PR merged |
| `in-progress → pending` | Implementer | Abandon (session ended without PR) |

## Parallelism rules

Multiple Implementers can work at once. Correctness + speed depend on:

1. **Always work in a git worktree, never on `main` directly.**
   `git worktree add ../dmp-<task-id> -b feature/<task-id>` before any
   edits. The Agent tool's `isolation: "worktree"` parameter does this
   automatically.
2. **Do not claim a task whose `blocks` field names another
   `in-progress` task.** That's what `TASKS.md` dependencies exist for.
3. **Do not edit `TASKS.md` while it's being edited by another agent.**
   Planner owns write access; everyone else reads it and only mutates
   their own `owner` / `status` fields via PR comments or CLI
   invocations with a lock file if needed. For solo-maintainer speed,
   this usually means: the human Integrator is the arbiter of
   `TASKS.md`.
4. **Touch zones.** A task should declare which files it will modify.
   Two in-progress tasks that name overlapping files block each other.
   The Planner tries to avoid scheduling those in parallel.

## Definition of done

A task is `done` only when **all** of these are true:

- [ ] Code change lives in a merged commit on `main`.
- [ ] Every new behavior has at least one passing test.
- [ ] `pytest` passes locally and in CI (all three Python versions).
- [ ] `black --check dmp tests` passes.
- [ ] `mypy --ignore-missing-imports dmp` produces no *new* errors.
- [ ] Docker integration tests pass (or the task is explicitly
      non-container).
- [ ] Codex review returned no `[P1]` findings, or all P1s are resolved
      with follow-up commits on the same PR.
- [ ] `CHANGELOG.md` has an entry under the right section.
- [ ] Affected docs under `docs/` are updated in the same PR.

## Guardrails — things no agent does, ever

- **Never force-push to `main`.**
- **Never bypass `--no-verify` on hooks** unless the human explicitly
  asks.
- **Never skip Codex review** for changes under
  `dmp/core/{crypto,manifest,identity,prekeys,chunking,erasure}.py` or
  for anything touching AEAD AAD construction. These are security-
  sensitive regions.
- **Never widen the dependency surface** (new package in
  `requirements.txt` or `setup.py`) without a justification in the PR
  description.
- **Never commit secrets.** Explicitly: passphrases, bearer tokens,
  private keys, test fixtures with real key material. When in doubt
  `git diff --cached | grep -Ei "BEGIN|PRIVATE|token|secret|passphrase"`
  before committing.
- **Never silence a test** to make it pass. Fix the underlying issue or
  `xfail` with a referenced issue number.

## PR requirements

- Title format: `[<TASK-ID>] <one-line summary>`
- PR body uses the template at
  `.github/PULL_REQUEST_TEMPLATE.md`.
- PR description always includes:
  - The task ID from `TASKS.md`
  - What changed and why (the 30-second summary)
  - New / changed tests and what they cover
  - Any security implications
  - Whether the protocol wire format changed
- Link the commit SHAs in the final `TASKS.md` update.

## Local validation before opening a PR

Every Implementer must run this *before* pushing:

```bash
# From inside your worktree:
pip install -e ".[dev]"
pytest --ignore=tests/test_docker_integration.py -v
black --check dmp tests
mypy --ignore-missing-imports dmp || true    # permissive for now

# Docker integration (only if you touched server/ or client/ code):
docker build -t dnsmesh-node:latest .
pytest tests/test_docker_integration.py -v
```

The Validator (CI) runs the same matrix, so if this passes locally, CI
is almost certainly green.

## How a session uses this file

A fresh agent session picks up work like this:

1. Read `ROADMAP.md` (long-horizon vision) and `TASKS.md` (current sprint).
2. If no task is in `pending`, go to role = Planner, decompose the next
   milestone from `ROADMAP.md`, write tasks to `TASKS.md`, stop.
3. If at least one task is in `pending` with no blocking deps, go to
   role = Implementer, claim the task, open a worktree, do the work.
4. When the PR is open, go to role = Reviewer, invoke Codex against the
   diff, comment findings.
5. When gates pass, go to role = Integrator, merge and mark `done` in
   `TASKS.md`.

A single session can fluidly move between roles as long as it doesn't
conflict with the guardrails (e.g., Implementer cannot self-Review or
self-Integrate their own work).
