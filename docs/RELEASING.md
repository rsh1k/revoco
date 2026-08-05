# Releasing

Push source to `main` and a new version lands on PyPI. There is nothing else to remember.

```
commit to main  →  tests run  →  version bumped  →  tagged  →  published to PyPI
```

## One-time setup you have to do yourself

Two steps I cannot do for you, both on pypi.org.

### 1. Configure Trusted Publishing

This is what lets the workflow publish with **no API token stored anywhere** — GitHub mints a short-lived OIDC token per run and PyPI verifies it came from this exact repo and workflow. A leaked repo secret cannot be used to publish, because there is no secret.

Before the first release, add a **pending publisher** at
<https://pypi.org/manage/account/publishing/>:

| Field | Value |
|---|---|
| PyPI project name | `revoco` |
| Owner | `rsh1k` |
| Repository name | `revoco` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

The environment name matters — the workflow declares `environment: pypi`, and PyPI will reject the publish if they don't match.

### 2. Create the `pypi` environment on GitHub

Settings → Environments → New environment → name it `pypi`.

Worth adding a **required reviewer** on that environment. It turns every release into a one-click approval instead of a silent publish, which is cheap insurance while the release path is new. Remove it later if the ceremony stops earning its keep.

## Day-to-day

**Patch release** — the default. Just commit:

```bash
git commit -m "Fix the SAP reversal-reason default"
git push
```

**Minor or major** — say so in the commit message:

```bash
git commit -m "[minor] Add ServiceNow adapter"
git commit -m "[major] Rename GateEvaluator to accept a context object"
```

**Skip a release** for a change that shouldn't ship:

```bash
git commit -m "Tidy up internal comments [skip release]"
```

**Release by hand** — Actions tab → `release` → *Run workflow* → pick the level. Useful for cutting a release after a docs-only change, since docs alone don't trigger one.

## What stops this from going wrong

| Guard | Why |
|---|---|
| Publish needs the test job to pass | Lint, mypy, the full suite, the containment benchmark and the demo all run first. A red build never publishes. |
| `paths` filter | Only `src/`, `tests/`, `examples/` and `pyproject.toml` trigger a release. Fixing a typo in the README doesn't burn a version number. |
| `[skip release]` | Escape hatch for source changes that shouldn't ship on their own. |
| Markers read from the **subject line only** | The first version of this workflow scanned the whole commit message, so the very commit that documented `[skip release]` skipped its own release. A commit that merely *mentions* a marker must not trigger it. |
| `concurrency: release` | Releases are serialized. Two concurrent runs would race on the version number and one would try to publish a version the other already took. |
| Version-exists check | PyPI versions are immutable and cannot be reused. If the target version is already published the job warns and skips instead of failing, so a re-run is a no-op. |
| `GITHUB_TOKEN` pushes don't trigger workflows | This is what stops the bump commit from triggering another release. The `[skip release]` marker on that commit is a second belt. |

## The version number

`pyproject.toml` is the single source of truth. `revoco.__version__` reads it back from installed package metadata via `importlib.metadata`, so a released wheel and the runtime value can never disagree.

It resolves through `packages_distributions()` rather than a hardcoded distribution name. The two match today (`pip install revoco` → `import revoco`), and this keeps working if they ever stop matching — a hardcoded name would silently return the fallback rather than raising, which is the worst way to be wrong about a version number.

From a source checkout with nothing installed, `__version__` reports `0.0.0+local`. That is deliberate: it should be obvious you are not looking at a released build.

## Testing the release path without publishing

```bash
uv build                       # sdist + wheel
uvx twine check dist/*         # metadata validation

# The check that actually matters — a wheel that imports in the repo root but not
# from a clean install is the classic packaging failure, and it stays invisible
# until someone pip-installs it.
uv venv /tmp/fresh
uv pip install --python /tmp/fresh/bin/python dist/*.whl
/tmp/fresh/bin/revoco surfaces
/tmp/fresh/bin/python -c "import revoco; print(revoco.__version__)"
```

CI runs exactly that on every push, so the failure surfaces on a pull request rather than after publication.

## A note on auto-publishing

Publishing on every source push is what you asked for and it is genuinely convenient, but be aware of the trade-off: version numbers advance quickly, and **a published version can never be reused or deleted** — only yanked. If you find that noisy, switch the trigger to tags only:

```yaml
on:
  push:
    tags: ["v*"]
```

and cut releases with `git tag v0.2.0 && git push --tags`. Everything else in the workflow works unchanged.

---

## Scheduling recovery drills

Releases keep the code fresh; drills keep the *rollback claims* fresh. A spec that was correct when written silently becomes a confident wrong rollback after an ERP upgrade, and nothing but a drill detects that.

Drills touch real systems of record, so this cannot be a repo workflow — it needs your credentials and your canary resources. Run it wherever you run scheduled jobs against those systems:

```python
from revoco.adapters import registry_for
from revoco.drills import Canary, DrillRunner, RecoverabilityRegister, render_report

register = RecoverabilityRegister(stale_after=24 * 3600)   # load from your own store
runner = DrillRunner(
    registry_for("sap", "cloud"),
    executor=my_client.execute,          # the same executor production undos use
    state_reader=my_client.read_state,
    gate_evaluator=my_gate_evaluator,
)

canaries = [
    Canary(
        tool="sap.supplier.bank.update",
        args={"BusinessPartner": "V-CANARY", "BankIdentification": "0001",
              "BankAccount": "GB00-DRILL-0000-0000"},
        verify=lambda: my_client.read_supplier_bank("V-CANARY"),
        compare_fields=("BankAccount", "IBAN"),
    ),
]

results = runner.drill_due(register, canaries, max_batch=10)
print(render_report(register))
```

Then persist `register` and alert on `register.report()["alarming"]`.

**The canary is the safety boundary and it is yours to get right.** Point one at production data and the drill becomes the incident. Use a dedicated supplier record, a dedicated bucket key, a scratch namespace.

Two settings worth thinking about rather than accepting:

- `stale_after` — how long a proof stays good. Tighten it for surfaces that change often; an ERP on a quarterly upgrade cycle and a Kubernetes cluster deploying hourly do not deserve the same window.
- `max_batch` — drills perform real writes and real undos. Ninety tools at once is ninety of each. The throttle matters more than completeness, and `due()` orders the work so the throttle drops the least urgent.
