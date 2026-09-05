# Assurance baselines

A drill says whether an inverse works now. A baseline is what turns a sequence of
those into the only sentence that matters operationally: *this was working and it
stopped.*

Two baselines, one per validated surface:

| Baseline | Target | What drift it watches |
|---|---|---|
| `github-baseline.json` | `github:OWNER/NAME` | The GitHub API changing under specs written from its documentation |
| `workstation-baseline.json` | `workstation-local` | This runner changing — a git release that alters what `reset --hard` or `stash pop` does |

One job per surface, because a run is comparable only against a baseline for the
same target: `validation-report` refuses a cross-target comparison on the grounds
that the difference would be the targets rather than the controls.

The workstation drills already run in CI on every push, which tests the *code*.
This is a different question. CI asks whether the change in front of it is
correct; the assurance loop asks whether a control that worked last month still
works, and answers with a date.

## Baselines are promoted by a person, never by CI

The workflow does not update this file. That is deliberate, and it is the same
reasoning `conformance/fixtures` rests on: a baseline that rewrites itself
whenever behaviour changes is not a baseline, it is a record of whatever the
system currently does, and a regression would quietly become the new normal.

To promote one, run the drill, read the diff, and commit it because you agree
with it:

```bash
python scripts/drill_github.py --repo OWNER/NAME --run-out assurance/github-baseline.json
git diff assurance/github-baseline.json     # this is the thing to review
```

## What a failure means

| Outcome | What happened | Where to look |
|---|---|---|
| `REGRESSED` | The inverse worked against the baseline and does not now | The spec, or the API it targets |
| `DISAPPEARED` | A control in the baseline was not drilled at all | The runner, not the spec |
| `STILL_FAILING` | Failing then and now | Known issue; not a new incident, and does not fail the job |

## Why the drills run against this repository

The runner needs write access to create and destroy canary refs. Pointing it at
another repository would mean a personal access token in CI; pointing it here
means the workflow's own `GITHUB_TOKEN` is enough, and there is no long-lived
credential to leak.

Every canary lives under `revoco-canary/<run>/` and the executor refuses any ref
outside that namespace, so the blast radius is a branch nobody uses. Teardown
runs regardless of outcome and reports anything it could not remove.

One operational note: GitHub disables scheduled workflows on a repository with
no commits for 60 days. A quiet month is enough to silently stop the assurance
loop, which is precisely the "stopped being tested" failure this is built to
catch — happening to the thing that catches it.
