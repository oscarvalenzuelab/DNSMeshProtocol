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


def check(path: Path) -> list[str]:
    """Return a list of problems with one workflow file. Empty means it is fine."""
    doc = yaml.safe_load(path.read_text())
    if not isinstance(doc, dict):
        return [f"{path}: not a YAML mapping, so nothing could be checked."]

    problems: list[str] = []
    jobs = doc.get("jobs") or {}

    if "schedule" not in triggers(doc):
        # Not unattended, so a failure already lands somewhere a person looks.
        # Still refuse a half-wired reporter if somebody added one anyway.
        if len(reporter_jobs(doc)) > 1:
            problems.append(
                f"{path}: more than one job uses {ACTION}. One run must produce "
                f"one verdict, or the jobs race to open and close the same issue."
            )
        return problems

    reporters = reporter_jobs(doc)
    if path.name in EXEMPT:
        # An exemption is about not having a reporter. If somebody adds one
        # anyway, check it properly rather than waving the file through.
        if not reporters:
            return problems

    if not reporters:
        problems.append(
            f"{path}: has a `schedule:` trigger and no job using {ACTION}. "
            f"A weekly run that fails with nothing watching it is invisible; "
            f"add a reporter job (see lockfile-refresh.yml) or drop the schedule."
        )
        return problems

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

    # A substring test, and it is honest about being one: it catches the
    # accidental case (somebody forgets `always()`), and the two spellings that
    # cancel it out. It cannot catch an `if:` written to look wired while never
    # running — `${{ always() && inputs.enabled }}` with the input unset would
    # pass here. That is a hostile case, not a careless one.
    guard = str(job.get("if") or "")
    if "always()" not in guard:
        problems.append(
            f"{path}: job `{name}` is missing `always()` in its `if:`. Without it "
            f"the reporter is skipped exactly when an upstream job failed — and a "
            f"failure is what it has most to say about."
        )
    for cancels in ("!always()", "false &&", "&& false"):
        if cancels in guard.replace(" ", " "):
            problems.append(
                f"{path}: job `{name}` has `{cancels}` in its `if:`, which stops the "
                f"reporter running while leaving the wiring looking correct."
            )

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
        passed = str(with_.get("needs") or "")
        if "toJSON(needs)" not in passed:
            problems.append(
                f"{path}: job `{name}` must pass `needs: ${{{{ toJSON(needs) }}}}` "
                f"to {ACTION}. Anything else leaves the action unable to see the "
                f"results it is reporting on."
            )
        if "github.workflow_ref" not in str(with_.get("workflow-ref") or ""):
            problems.append(
                f"{path}: job `{name}` must pass "
                f"`workflow-ref: ${{{{ github.workflow_ref }}}}` to {ACTION}. The "
                f"workflow file path is the issue's identity; the display name is "
                f"mutable, so without it a rename orphans an open issue."
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
        if name in scheduled:
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
