"""
revoco.bench.external
=====================
Load benign scenarios from external benchmark data, without vendoring it.

The problem this solves
-----------------------
The hand-authored benign corpus has a structural blind spot: it contains the false
positives I thought to look for. Traffic that real models actually produced does
not, which makes it worth strictly more per scenario — and it is the one thing
authorship cannot manufacture.

The temptation is to generate benign scenarios with an LLM instead. That is a trap
the literature is clear about: systems score 84–89% on synthetic benchmarks and
25–34% on real-world tasks, so generated traffic would improve the *ratio* while
reducing what the corpus actually establishes. A number that looks better and means
less is the specific failure this package keeps refusing.

Why nothing is vendored
-----------------------
`RAS-Eval <https://github.com/lanzer-tree/RAS-Eval>`_ declares **no license**, so its
tasks and logs are all-rights-reserved by default and cannot ship inside an
Apache-2.0 package. This module reads them from a clone you obtain yourself and
returns an empty list when it is absent, so nothing here depends on data this
repository does not have the right to distribute.

    git clone https://github.com/lanzer-tree/RAS-Eval /path/to/RAS-Eval
    RAS_EVAL_PATH=/path/to/RAS-Eval revoco bench

What gets imported, and what deliberately does not
--------------------------------------------------
**80 unique tasks.** Not the 640 traces. RAS-Eval ships eight models' runs of the
same 80 tasks, so importing all of them would multiply the benign count eightfold
with near-duplicates — padding dressed as coverage. The *arguments* differ per
model, which is the interesting part, so the loader takes the union of distinct
(tool, argument-shape) calls across models while keeping one scenario per task.

This broadens the benign distribution rather than deepening it. RAS-Eval's domains
are alarms, calendars, disk stats, weather and arXiv lookups — no ERP posting, no
payroll, no IAM. It tests whether ordinary tool use gets blocked, which the
hand-built corpus does not cover; it says nothing about the enterprise write
surfaces where the money is. Both halves are needed and neither substitutes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..adapters.ras_eval import classified_tools, ras_eval_registry
from .scenario import GrantSpec, Intent, Scenario, Step
from .world import VERB_CREATE, VERB_NOOP, VERB_UPDATE, ToolBinding, World

ENV_VAR = "RAS_EVAL_PATH"

# Agent persona -> the risk band a task from it gets. RAS-Eval does not label risk,
# and inventing a single value for everything would make the corpus useless for
# testing risk-banded policy. These are graded by what the persona can touch.
_PERSONA_RISK = {
    "AcademicAgent": 10,
    "WebSearchAgent": 15,
    "GeneralAgent": 20,
    "StockAgent": 20,
    "ScheduleAgent": 35,
    "DatabaseAgent": 45,
    "SystemAgent": 45,
}
_DEFAULT_RISK = 30


def data_root(path: str | os.PathLike[str] | None = None) -> Path | None:
    """Locate a RAS-Eval clone, or return None.

    Checked in order: the argument, ``$RAS_EVAL_PATH``, then a sibling directory
    next to this repository. Returning None rather than raising is deliberate — the
    corpus has to work without this data, or CI would depend on an unlicensed
    third-party checkout.
    """
    def has_data(p: Path) -> bool:
        return (p / "data" / "tasks" / "tasks.json").is_file()

    # An explicit path is used exclusively. Falling through to the environment when
    # the caller named a directory would mean a typo silently loads *different* data
    # and reports on it as though it were what you asked for.
    if path:
        p = Path(path)
        return p if has_data(p) else None

    candidates = []
    if os.environ.get(ENV_VAR):
        candidates.append(Path(os.environ[ENV_VAR]))
    candidates.append(Path(__file__).resolve().parents[4] / "RAS-Eval")
    for c in candidates:
        if has_data(c):
            return c
    return None


def available(path: str | os.PathLike[str] | None = None) -> bool:
    return data_root(path) is not None


def _load_tasks(root: Path) -> list[dict[str, Any]]:
    with (root / "data" / "tasks" / "tasks.json").open() as f:
        tasks = json.load(f)
    return tasks if isinstance(tasks, list) else []


def _load_observed_args(root: Path) -> dict[int, list[dict[str, Any]]]:
    """Per task index, the tool calls models actually made, with real arguments.

    Merged across every model log present. Arguments are what make these traces
    worth more than the task definitions: a model's idea of a plausible ``path`` or
    ``query`` is exactly the input a hand-written scenario would sanitise without
    noticing.
    """
    out: dict[int, list[dict[str, Any]]] = {}
    logs = root / "data" / "logs"
    if not logs.is_dir():
        return out
    seen: set[tuple[int, str, str]] = set()
    for log in sorted(logs.glob("*.jsonl")):
        # guard_response.jsonl is a detector's output, not an execution trace.
        if "guard" in log.name:
            continue
        try:
            text = log.read_text()
        except OSError:
            continue
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            idx = rec.get("index")
            if idx is None:
                continue
            for msg in rec.get("response") or []:
                for call in msg.get("tool_calls") or []:
                    name, cargs = call.get("name"), call.get("args") or {}
                    if not name:
                        continue
                    # Deduplicate by argument *shape*, not value: two models passing
                    # different arXiv ids exercise the same path, and keeping both
                    # would be the same padding this loader exists to avoid.
                    key = (idx, name, ",".join(sorted(cargs)))
                    if key in seen:
                        continue
                    seen.add(key)
                    out.setdefault(idx, []).append({"tool": name, "args": cargs})
    return out


def _world_factory(calls: tuple[dict[str, Any], ...]) -> Any:
    def build() -> World:
        return _build_world(list(calls))

    return build


def _needs_args(tool: str) -> bool:
    """Whether this tool's inverse resolves anything from the forward arguments."""
    spec = ras_eval_registry().get(tool)
    if spec is None:
        return False
    return any(
        expr.startswith("args.")
        for step in spec.effective_steps
        for _name, expr in step.arg_map
    )


def _build_world(calls: list[dict[str, Any]]) -> World:
    """A world that can execute whatever this task touched.

    Bound generically by verb rather than modelled per tool. These scenarios measure
    whether legitimate traffic is *allowed*, so the fidelity that matters is the
    control plane's view of the call, not the tool's internal behaviour.
    """
    w = World()
    reg = ras_eval_registry()
    bound: set[str] = set()

    def bind(tool: str) -> None:
        if tool in bound:
            return
        bound.add(tool)
        spec = reg.get(tool)
        kind = "ras"
        if spec is None:
            w.bind(ToolBinding(tool, VERB_NOOP, kind=kind, id_arg="_"))
            return
        if spec.effective_steps and spec.effective_steps[0].tool == "ras.noop":
            w.bind(ToolBinding(tool, VERB_NOOP, kind=kind, id_arg="_"))
            return
        w.bind(ToolBinding(tool, VERB_UPDATE, kind=kind, id_arg="_",
                           generates_id=True, returns=(("row_id", "{seq}"),
                                                       ("event_id", "{seq}"),
                                                       ("alarm_id", "{seq}"),
                                                       ("timer_id", "{seq}"),
                                                       ("output_path", "{id}"))))

    for c in calls:
        bind(c["tool"])
        spec = reg.get(c["tool"])
        for step in (spec.effective_steps if spec else ()):
            if step.tool != "ras.noop":
                w.bind(ToolBinding(step.tool, VERB_CREATE, kind="ras", id_arg="_",
                                   generates_id=True))
    w.bind(ToolBinding("ras.noop", VERB_NOOP, kind="ras", id_arg="_"))
    w.seed("ras", "_", placeholder=True)
    return w


def ras_eval_scenarios(
    path: str | os.PathLike[str] | None = None, *, limit: int | None = None
) -> list[Scenario]:
    """Benign scenarios derived from RAS-Eval's 80 tasks. Empty if the data is absent.

    One scenario per task, carrying the tool calls models actually made. Tasks whose
    tools this package has no classification for are skipped rather than imported as
    ``UNKNOWN`` — importing them would manufacture false positives out of missing
    metadata and make the corpus look worse for a reason that has nothing to do with
    the control plane.
    """
    root = data_root(path)
    if root is None:
        return []

    tasks = _load_tasks(root)
    observed = _load_observed_args(root)
    known = classified_tools()
    scenarios: list[Scenario] = []

    for task in tasks:
        raw_idx = task.get("index")
        if raw_idx is None:
            continue
        idx = int(raw_idx)
        persona = task.get("agent", "GeneralAgent")
        workflow = list(task.get("workflow") or [])
        calls = observed.get(idx) or [{"tool": t, "args": {}} for t in workflow]
        calls = [c for c in calls if c["tool"] in known]
        # Drop calls with no observed arguments where the spec needs some. A scenario
        # built from an argument-less call cannot resolve any inverse, so it raises a
        # phantom rollback and scores as a false positive — one manufactured out of
        # missing trace data rather than out of anything the control plane did. Same
        # discipline as skipping unclassified tools: absent metadata must not become
        # a finding.
        calls = [c for c in calls if c["args"] or not _needs_args(c["tool"])]
        if not calls:
            continue

        risk = _PERSONA_RISK.get(persona, _DEFAULT_RISK)
        tools = frozenset(c["tool"] for c in calls)
        prompt = (task.get("prompt") or "").strip()

        scenarios.append(
            Scenario(
                id=f"RAS-{idx:03d}-{persona.replace('Agent', '').lower()}",
                title=prompt[:90] or f"{persona} task {idx}",
                intent=Intent.BENIGN,
                technique="EXT",
                narrative=(
                    f"RAS-Eval task {idx} ({persona}). Imported benign traffic: the "
                    "tool calls and arguments here were produced by real models "
                    "executing the task, not written to look plausible."
                ),
                # Bind the call list per iteration; a closure over the loop variable
                # would give every scenario the last task's tools.
                build_world=_world_factory(tuple(calls)),
                grant=GrantSpec(
                    tools=tools,
                    actions=frozenset({"read", "write"}),
                    max_risk=max(risk + 15, 50),
                    purpose=prompt[:120] or f"{persona} assigned work",
                ),
                steps=tuple(
                    Step(
                        tool=c["tool"],
                        args=dict(c["args"]),
                        action="read" if risk <= 20 else "write",
                        risk=risk,
                        description=(prompt[:70] or c["tool"]),
                    )
                    for c in calls
                ),
                registry=ras_eval_registry(),
            )
        )
        if limit and len(scenarios) >= limit:
            break
    return scenarios


def provenance(path: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """Where the external scenarios came from, for a report to state honestly."""
    root = data_root(path)
    if root is None:
        return {"source": "RAS-Eval", "available": False,
                "note": f"set {ENV_VAR} to a clone to include these scenarios"}
    scen = ras_eval_scenarios(path)
    return {
        "source": "RAS-Eval",
        "available": True,
        "citation": "arXiv:2506.15253",
        "url": "https://github.com/lanzer-tree/RAS-Eval",
        "license": "none declared — read from a local clone, never vendored",
        "path": str(root),
        "scenarios": len(scen),
        "note": (
            "80 unique tasks, not the 640 traces: eight models ran the same tasks, so "
            "importing every run would multiply the count with near-duplicates. "
            "Domains are alarms, calendars, disk stats, weather and arXiv lookups — "
            "this broadens the benign distribution, it does not reach enterprise "
            "write surfaces."
        ),
    }


__all__ = ["ras_eval_scenarios", "available", "data_root", "provenance", "ENV_VAR"]
