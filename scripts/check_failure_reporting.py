#!/usr/bin/env python3
"""Fail when a scheduled workflow has no way to report its own failure.

Except for the workflows in EXEMPT below, each of which carries its reason and
is printed on every successful run. That is a real hole in this check and it is
named rather than hidden: an exempted workflow can fail with nothing filed.

`lockfile refresh` runs weekly. It failed on every run from 7 Sep 2026 to
5 Oct 2026 — six consecutive runs — because it was not permitted to open the
pull request that carries its result. Nothing reported that. A scheduled run
has no pull request to turn red and nobody watching the Actions tab, so its
failure looks exactly like its success from anywhere a person actually reads.
It was found four weeks later by sweeping failed runs across every repository
by hand, and by then the lockfiles it could not deliver had gone stale enough
to make two `security` jobs red as well.

`.github/actions/report-ci-failure` fixes the symptom: it turns an unattended
run's outcome into a single open issue, and closes that issue when the workflow
goes green again. This script protects the mechanism, because the mechanism has
two ways to go quietly blind and both of them look healthy:

1. **A new scheduled workflow with no reporter at all.** Its failures are
   invisible again, and nothing about the file looks wrong.
2. **A new job added to a workflow that already has a reporter, without adding
   it to the reporter's `needs:` list.** The reporter still runs, still passes,
   and simply never sees that job's result. This is the worse of the two: the
   run is red, the reporter is green, and no issue is filed.

Both are the same fault as a guard whose failure mode is silence. A comment
asking the next person to keep two lists in sync is not a mechanism; this is.
Run from CI on every pull request.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import yaml

WORKFLOWS = Path(".github/workflows")
ACTION = "./.github/actions/report-ci-failure"

# Scheduled workflows that deliberately have no reporter, each with the reason.
# These are printed on every successful run rather than skipped quietly: an
# exemption nobody is reminded of is how a list of things that need doing turns
# into a list nobody reads. Adding an entry here has to happen in a diff, with
# a sentence, and it is never the quiet option.
EXEMPT = {
    "pages.yml": (
        "runs every 30 minutes, so a reporter that comments once per failing "
        "run would post dozens of comments a day and train everyone to ignore "
        "the label. Needs a rate-limited shape before it gets one — see #179."
    ),
}

# PyYAML resolves the bare key `on:` to the boolean True (YAML 1.1 treats it as
# a truthy keyword), so a workflow's trigger block is not under the string
# "on". Look under both rather than relying on which loader ran.
ON_KEYS = (True, "on")


def triggers(doc: dict[str, Any]) -> dict[str, Any]:
    for key in ON_KEYS:
        if key in doc:
            value = doc[key]
            if isinstance(value, dict):
                return value
            # `on: push` or `on: [push, schedule]` — normalise to a dict so
            # callers can ask the same question either way.
            if isinstance(value, str):
                return {value: None}
            if isinstance(value, list):
                return {item: None for item in value}
    return {}


def reporter_jobs(doc: dict[str, Any]) -> list[str]:
    found = []
    for name, job in (doc.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if step.get("uses") == ACTION:
                found.append(name)
                break
    return found


def permission_leaks(path: Path, doc: dict[str, Any]) -> list[str]:
    """Refuse any grant of `issues: write` outside a reporter job.

    The repository-wide default is `read` and the point of the reporter's own
    `permissions:` block is that it is the only thing holding write. A
    workflow-level grant, a `write-all`, or the same scope on an ordinary job
    hands it to everything in the file, which is the widening this change exists
    to avoid — and it is invisible, because the reporter still works.
    """
    problems: list[str] = []
    reporters = set(reporter_jobs(doc))

    def names_issue_write(perms: Any) -> str | None:
        if perms == "write-all":
            return "write-all"
        if isinstance(perms, dict) and perms.get("issues") == "write":
            return "issues: write"
        return None

    leak = names_issue_write(doc.get("permissions"))
    if leak:
        problems.append(
            f"{path}: workflow-level `permissions:` grants `{leak}`, so every job "
            f"in the file can open issues. Only the reporter job needs it; move it "
            f"there and leave the workflow default alone."
        )

    for name, job in (doc.get("jobs") or {}).items():
        if name in reporters:
            continue
        leak = names_issue_write(job.get("permissions"))
        if leak:
            problems.append(
                f"{path}: job `{name}` grants `{leak}` and is not a reporter job. "
                f"Only the reporter needs to open issues."
            )
    return problems


def check(path: Path) -> list[str]:
    """Return a list of problems with one workflow file. Empty means it is fine."""
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict):
        return [f"{path}: not a YAML mapping, so nothing could be checked."]

    problems: list[str] = []
    jobs = doc.get("jobs") or {}

    problems += permission_leaks(path, doc)

    reporters = reporter_jobs(doc)
    scheduled = "schedule" in triggers(doc)

    if not reporters:
        if not scheduled:
            # Not unattended, so a failure already lands on the pull request or
            # push that caused it. Nothing to require here.
            return problems
        if path.name in EXEMPT:
            # Deliberate, argued and printed on every run. It is a real hole.
            return problems
        problems.append(
            f"{path}: has a `schedule:` trigger and no job using {ACTION}. "
            f"A weekly run that fails with nothing watching it is invisible; "
            f"add a reporter job (see lockfile-refresh.yml) or drop the schedule."
        )
        return problems

    # From here on there IS a reporter, so it gets checked in full whether or
    # not the workflow is scheduled and whether or not it is exempt. A
    # half-wired reporter is worse than none: it looks like coverage.
    if len(reporters) > 1:
        problems.append(
            f"{path}: {len(reporters)} jobs use {ACTION} ({', '.join(sorted(reporters))}). "
            f"They would race to open and close the same issue; use one job that "
            f"`needs:` the others."
        )
        return problems

    name = reporters[0]
    job = jobs[name]

    declared = job.get("needs") or []
    if isinstance(declared, str):
        declared = [declared]
    expected = {j for j in jobs if j != name}
    missing = sorted(expected - set(declared))
    if missing:
        problems.append(
            f"{path}: job `{name}` reports failures but does not `needs:` "
            f"{', '.join('`' + m + '`' for m in missing)}. A job outside that list "
            f"can fail while the reporter passes and files nothing — which is the "
            f"silent failure this mechanism exists to prevent."
        )

    unknown = sorted(set(declared) - expected)
    if unknown:
        problems.append(
            f"{path}: job `{name}` lists {', '.join('`' + u + '`' for u in unknown)} "
            f"in `needs:`, which is not a job in this workflow."
        )

    # Whitespace-insensitive, because `always()&&false` and `always() && false`
    # are the same wiring error and only one of them contains "&& false".
    guard = str(job.get("if") or "")
    tight = "".join(guard.split())

    if "always()" not in tight:
        problems.append(
            f"{path}: job `{name}` is missing `always()` in its `if:`. Without it "
            f"the reporter is skipped exactly when an upstream job failed — and a "
            f"failure is what it has most to say about."
        )
    for cancels in ("!always()", "false&&", "&&false"):
        if cancels in tight:
            problems.append(
                f"{path}: job `{name}` has `{cancels.replace('&&', ' && ')}` in its "
                f"`if:`, which stops the reporter running while leaving the wiring "
                f"looking correct."
            )
    # Require an equality against the schedule event, not merely the word.
    # `github.event_name != 'schedule'` contains `'schedule'` and is the exact
    # opposite of what is wanted; `== 'push'` never runs on the cron at all.
    if scheduled and not ("=='schedule'" in tight or '=="schedule"' in tight):
        problems.append(
            f"{path}: job `{name}` has a `schedule:` trigger but its `if:` does not "
            f"test `github.event_name == 'schedule'`, so the reporter cannot be "
            f"relied on to run on the cron. Guard it on the unattended events "
            f"explicitly."
        )

    if job.get("continue-on-error"):
        # The job would go green whatever the reporter did, so a failure to file
        # would not even show up as a red reporter.
        problems.append(
            f"{path}: job `{name}` sets `continue-on-error`, so a reporter that "
            f"fails to file reports success. Remove it."
        )

    # And the same key on any job the reporter WATCHES is worse: GitHub reports
    # `needs.<job>.result` as `success` for a failed job that sets it, so the
    # reporter sees green and files nothing for a run that really failed.
    for other, other_job in jobs.items():
        if other == name or not isinstance(other_job, dict):
            continue
        if other_job.get("continue-on-error"):
            problems.append(
                f"{path}: job `{other}` sets `continue-on-error`, so "
                f"`needs.{other}.result` reports `success` even when it fails. The "
                f"reporter would see a green run and file nothing. Let the job fail, "
                f"or take it out of the reporter's `needs:` deliberately and say why."
            )

    if "concurrency" in job:
        # Deliberate: see the note beside the reporter jobs. GitHub keeps one
        # PENDING member per group, so serialising can cancel a queued reporter
        # and a cancelled reporter files nothing. The duplicate it would prevent
        # is reconciled by the green path instead.
        problems.append(
            f"{path}: job `{name}` declares `concurrency:`. A queued reporter can "
            f"be superseded — GitHub keeps one pending member per group — and a "
            f"cancelled reporter files nothing, which is worse than the duplicate "
            f"it prevents. The green path closes every match, so the duplicate "
            f"reconciles itself. See the note beside the job."
        )

    # The honest limit: these are substring tests over an expression language.
    # They catch the careless cases above. An `if:` written to look wired while
    # never running — `always() && inputs.enabled` with the input unset — would
    # still pass, and no amount of substring matching fixes that.
    #
    # A second limit, in a different direction: a STEP that swallows its own
    # failure (`run: ... || true`, or a `|| true` buried in a multi-line script)
    # makes its job report success, and nothing in a YAML read can tell that
    # apart from a step that genuinely succeeded. Job-level `continue-on-error`
    # is refused above because it is declarative and therefore checkable; the
    # step-level trick is not.

    perms = job.get("permissions") or {}
    if not isinstance(perms, dict):
        perms = {}
    if perms.get("issues") != "write":
        problems.append(
            f"{path}: job `{name}` needs `permissions: issues: write` of its own. "
            f"The repository-wide default is `read` and must stay that way."
        )
    if perms.get("contents") != "read":
        problems.append(
            f"{path}: job `{name}` needs `permissions: contents: read` as well. "
            f"Naming a `permissions` block sets every scope not listed to `none`, "
            f"so without it `actions/checkout` loses its token and the reporter "
            f"never runs — which is the silent failure, not a fix for it."
        )

    for step in job.get("steps") or []:
        if step.get("uses") != ACTION:
            continue
        with_ = step.get("with") or {}
        # Exact literal, not "contains toJSON(needs)". `results=${{ toJSON(needs)
        # }}` contains it and reaches the action as a string that is not JSON,
        # so the action refuses and files nothing for a real failure. The
        # documented substring limitation is about guard EXPRESSIONS; an input
        # has one correct spelling and gets checked against it.
        passed = "".join(str(with_.get("needs") or "").split())
        if passed != "${{toJSON(needs)}}":
            problems.append(
                f"{path}: job `{name}` must pass `needs: ${{{{ toJSON(needs) }}}}` "
                f"to {ACTION}, exactly. Got `{with_.get('needs')!r}`. Anything else "
                f"reaches the action as a value it cannot read, so it refuses and "
                f"files nothing."
            )
        if "".join(str(with_.get("default-branch") or "").split()) != (
            "${{github.event.repository.default_branch}}"
        ):
            problems.append(
                f"{path}: job `{name}` must pass "
                f"`default-branch: ${{{{ github.event.repository.default_branch }}}}` "
                f"to {ACTION}, exactly. Got `{with_.get('default-branch')!r}`. "
                f"Without it a green run from any branch can close a report that "
                f"belongs to the default branch, where the cron actually runs."
            )
        if "".join(str(with_.get("workflow-ref") or "").split()) != (
            "${{github.workflow_ref}}"
        ):
            problems.append(
                f"{path}: job `{name}` must pass "
                f"`workflow-ref: ${{{{ github.workflow_ref }}}}` to {ACTION}, "
                f"exactly. Got `{with_.get('workflow-ref')!r}`. The workflow file "
                f"path is the issue's identity; the display name is mutable, so "
                f"without it a rename orphans an open issue."
            )
        token = "".join(str(with_.get("token") or "").split())
        # The exact literal, not "something non-empty". A composite action's
        # `required: true` is not enforced by the runner, so an omitted token
        # reaches `gh` as an empty string; and a misspelled secret name such as
        # `secrets.GITHUB_T0KEN` also expands to empty, which is indistinguishable
        # from a correct one by any looser test.
        if token != "${{secrets.GITHUB_TOKEN}}":
            problems.append(
                f"{path}: job `{name}` must pass "
                f"`token: ${{{{ secrets.GITHUB_TOKEN }}}}` to {ACTION}, exactly. "
                f"Got `{with_.get('token')!r}`. An absent or misspelled secret "
                f"expands to an empty string, `gh` is then unauthenticated, and "
                f"nothing is filed."
            )
        if "if" in step:
            # There is no legitimate reason to gate the reporter step itself; the
            # job's own `if:` does that, and a step-level one is a way to stop it
            # running while leaving the wiring looking correct.
            problems.append(
                f"{path}: the {ACTION} step in job `{name}` has its own `if:` "
                f"({step['if']!r}). Gate the job, not the step — a step-level "
                f"condition can stop the reporter while the wiring still reads as "
                f"correct."
            )
        if step.get("continue-on-error"):
            problems.append(
                f"{path}: the {ACTION} step in job `{name}` sets "
                f"`continue-on-error`, so a failure to file would not even show as "
                f"a red reporter."
            )

    steps = job.get("steps") or []
    uses = [str(step.get("uses") or "") for step in steps]
    checkout_at = next(
        (i for i, u in enumerate(uses) if u.startswith("actions/checkout")), None
    )
    action_at = next((i for i, u in enumerate(uses) if u == ACTION), None)
    if checkout_at is None:
        # The action lives in this repository, so the runner can only find it
        # after a checkout. Without one the step fails to resolve and no issue
        # is filed.
        problems.append(
            f"{path}: job `{name}` uses the local action {ACTION} but never runs "
            f"`actions/checkout`, so the action is not on disk and the step cannot "
            f"resolve. Nothing would be filed."
        )
    elif action_at is not None and checkout_at > action_at:
        # Order matters and a listing that only asks "is checkout present?"
        # cannot see this.
        problems.append(
            f"{path}: job `{name}` runs `actions/checkout` at step {checkout_at + 1}, "
            f"after {ACTION} at step {action_at + 1}. The local action is not on "
            f"disk yet when it is reached."
        )

    if action_at is not None:
        # Every step carries an implicit `success()`, so ANY earlier step that
        # fails skips the reporter and the scheduled failure goes unfiled — and
        # a skipped reporter is not a red one, so nothing says so. A reporter
        # job needs a checkout and the action and nothing else, which makes the
        # rule simple enough to enforce: nothing may come first but checkout.
        for i, step in enumerate(steps[:action_at]):
            if not str(step.get("uses") or "").startswith("actions/checkout"):
                label = step.get("name") or step.get("uses") or step.get("run") or "?"
                problems.append(
                    f"{path}: job `{name}` runs `{str(label)[:60]}` at step {i + 1}, "
                    f"before {ACTION}. Any step that fails before the reporter skips "
                    f"it under the implicit `success()`, and a skipped reporter files "
                    f"nothing while showing as neither red nor missing. The reporter "
                    f"job should hold a checkout and the action, nothing else."
                )

    return problems


def main() -> int:
    if not WORKFLOWS.is_dir():
        # An absent directory is a statement about where this ran, not about
        # the repository. Refuse rather than passing on an empty sweep.
        print(f"{WORKFLOWS} not found — run this from the repository root.")
        return 1

    paths = sorted(p for p in WORKFLOWS.iterdir() if p.suffix in (".yml", ".yaml"))
    if not paths:
        print(f"no workflow files under {WORKFLOWS} — nothing was checked, which")
        print("is not the same as everything passing.")
        return 1

    problems = [problem for path in paths for problem in check(path)]

    if problems:
        print("Scheduled workflows that cannot report their own failure:\n")
        for problem in problems:
            print(f"  {problem}\n")
        print(
            "See .github/actions/report-ci-failure for what a reporter job looks like."
        )
        return 1

    scheduled = [
        p.name for p in paths if "schedule" in triggers(yaml.safe_load(p.read_text()))
    ]
    reporting = [name for name in scheduled if name not in EXEMPT]
    print(
        f"checked {len(paths)} workflow(s); {len(scheduled)} scheduled. "
        f"Reporting their own failures: {', '.join(reporting) or 'none'}."
    )
    stale = sorted(set(EXEMPT) - set(scheduled))
    for name in sorted(EXEMPT):
        if name not in scheduled:
            continue
        doc = yaml.safe_load((WORKFLOWS / name).read_text())
        if reporter_jobs(doc):
            # It has one now, so the exemption is spent. Printing the old reason
            # would describe a hole that has been filled.
            print(f"  {name} is in EXEMPT but now HAS a reporter. Remove the entry.")
            stale.append(name)
        else:
            print(f"  exempt: {name} — {EXEMPT[name]}")
    if stale:
        # An exemption for a workflow that is no longer scheduled (or no longer
        # exists) is a sentence nobody will reread. Make it fail, not rot.
        print()
        for name in stale:
            print(
                f"  {name} is in EXEMPT but has no `schedule:` trigger. Remove the entry."
            )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
