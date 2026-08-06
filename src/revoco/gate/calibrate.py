"""
revoco.gate.calibrate
=====================
Measure the threat scanner instead of asserting things about it.

The problem with the previous approach
-------------------------------------
The scanner's quality was established by hand-written probes: I wrote a pattern, I
wrote an example that trips it, the test passed. That establishes the regex compiles.
It does not establish that the *score* separates attacks from ordinary traffic, that
the default threshold sits anywhere sensible, or that any individual pattern carries
signal rather than noise.

This module answers those, following the protocol from *MCPShield*
(`arXiv 2605.11053 <https://arxiv.org/abs/2605.11053>`_), which studied exactly this
question for tool-call traffic and found two things worth stealing.

**Rank, don't threshold.** Their primary metrics are AUROC and AUPRC, not F1 at some
fixed cut. A single-threshold number cannot distinguish a detector that ranks well
and is badly calibrated from one that does not rank at all — and those need opposite
fixes.

**Split by task, not at random.** Random splits inflated their results by **up to
25.8 percentage points**, because a model learns tool-specific signatures and then
gets tested on the same tools. Anything tuned that way is measuring memorisation.
:func:`compare_splits` reproduces that experiment on this corpus, which matters here
for a specific reason: this scanner reads *arguments only* and never sees a tool
name, so it should be structurally immune. That is a claim worth measuring rather
than assuming, and the number is reported either way.

What this is not
----------------
Not a trainer. MCPShield's best configuration is Sentence-BERT embeddings under a
tree ensemble at 0.975 AUROC, and their sharpest architectural finding is that
feature quality beats model sophistication. Both are true and neither is adopted
here: this scanner is deliberately a transparent set of weighted regexes whose hits
are explainable in an incident review, feeding ``require_approval`` rather than
silent denial. A 768-dimensional embedding cannot tell an approver *why* it objected.

So the goal is a well-measured heuristic, not a better classifier. If the numbers
below turn out weak, that is information about where a heuristic stops being enough —
which is more useful than a good number nobody can interpret.
"""

from __future__ import annotations

import json
import math
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .threats import _PATTERNS, ScanResult, ThreatScanner


@dataclass(frozen=True)
class Sample:
    """One piece of argument content, labelled.

    ``task`` is the grouping key for task-disjoint splits — the scenario or task the
    content came from. Two samples sharing a task must never land on opposite sides
    of a split, or the evaluation measures memorisation.
    """

    text: str
    malicious: bool
    task: str
    source: str = "corpus"

    @property
    def label(self) -> int:
        return 1 if self.malicious else 0


@dataclass(frozen=True)
class ThresholdPoint:
    threshold: int
    tp: int
    fp: int
    tn: int
    fn: int

    @property
    def recall(self) -> float:
        d = self.tp + self.fn
        return self.tp / d if d else 0.0

    @property
    def precision(self) -> float:
        d = self.tp + self.fp
        return self.tp / d if d else 0.0

    @property
    def fpr(self) -> float:
        d = self.fp + self.tn
        return self.fp / d if d else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "threshold": self.threshold,
            "tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
            "recall": round(self.recall, 4),
            "precision": round(self.precision, 4),
            "fpr": round(self.fpr, 4),
            "f1": round(self.f1, 4),
        }


@dataclass(frozen=True)
class PatternStat:
    """How one pattern behaves on real content.

    ``lift`` is the ratio of its hit rate on malicious content to its hit rate on
    benign. Below 1.0 the pattern fires more often on ordinary traffic than on
    attacks, which means it is subtracting signal — a weighted vote for the wrong
    answer, not merely a weak one.
    """

    label: str
    category: str
    weight: int
    hits_malicious: int
    hits_benign: int
    n_malicious: int
    n_benign: int

    @property
    def rate_malicious(self) -> float:
        return self.hits_malicious / self.n_malicious if self.n_malicious else 0.0

    @property
    def rate_benign(self) -> float:
        return self.hits_benign / self.n_benign if self.n_benign else 0.0

    @property
    def lift(self) -> float | None:
        if not self.rate_benign:
            return None if not self.rate_malicious else math.inf
        return self.rate_malicious / self.rate_benign

    @property
    def verdict(self) -> str:
        if not self.hits_malicious and not self.hits_benign:
            return "dead"        # never fires on this corpus: unmeasured, not proven
        if self.weight == 0:
            # Already demoted. It still fires, and the hit is still surfaced to an
            # analyst, but it contributes nothing to the score — so it cannot be a
            # vote for the wrong answer, and reporting it as one would be crying wolf
            # about something the last round already fixed.
            return "observation"
        if not self.hits_benign:
            return "clean"       # only fires on attacks
        lift = self.lift or 0.0
        if lift < 1.0:
            return "noisy"       # fires more on benign: actively harmful as a vote
        if lift < 2.0:
            return "weak"
        return "useful"

    def to_dict(self) -> dict[str, Any]:
        lift = self.lift
        return {
            "label": self.label,
            "category": self.category,
            "weight": self.weight,
            "hits_malicious": self.hits_malicious,
            "hits_benign": self.hits_benign,
            "rate_malicious": round(self.rate_malicious, 4),
            "rate_benign": round(self.rate_benign, 4),
            "lift": (None if lift is None else ("inf" if lift == math.inf else round(lift, 2))),
            "verdict": self.verdict,
        }


@dataclass
class Calibration:
    """The measured behaviour of one scanner over one labelled set."""

    n_malicious: int
    n_benign: int
    auroc: float
    auprc: float
    points: list[ThresholdPoint] = field(default_factory=list)
    patterns: list[PatternStat] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def best_f1(self) -> ThresholdPoint | None:
        return max(self.points, key=lambda p: p.f1) if self.points else None

    @property
    def strictest_clean(self) -> ThresholdPoint | None:
        """Lowest threshold that still produces no false positives.

        The operating point that matters for a control plane feeding
        ``require_approval``: catch as much as possible without spending human
        attention on legitimate work, because an approver who learns the alerts are
        usually wrong stops reading them.
        """
        clean = [p for p in self.points if p.fp == 0 and p.tp > 0]
        return min(clean, key=lambda p: p.threshold) if clean else None

    @property
    def dead(self) -> list[str]:
        return [p.label for p in self.patterns if p.verdict == "dead"]

    @property
    def noisy(self) -> list[str]:
        """Patterns whose weight moves the score in the wrong direction.

        Excludes weight-0 patterns by construction — see :attr:`PatternStat.verdict`.
        """
        return [p.label for p in self.patterns if p.verdict == "noisy"]

    @property
    def demoted(self) -> list[str]:
        """Patterns kept as observations after calibration removed their weight."""
        return [p.label for p in self.patterns if p.verdict == "observation"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": {"malicious": self.n_malicious, "benign": self.n_benign},
            "auroc": round(self.auroc, 4),
            "auprc": round(self.auprc, 4),
            "best_f1": self.best_f1.to_dict() if self.best_f1 else None,
            "strictest_clean": (
                self.strictest_clean.to_dict() if self.strictest_clean else None
            ),
            "thresholds": [p.to_dict() for p in self.points],
            "patterns": [p.to_dict() for p in self.patterns],
            "dead_patterns": self.dead,
            "noisy_patterns": self.noisy,
            "demoted_patterns": self.demoted,
            "notes": list(self.notes),
        }


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def _auroc(scored: Sequence[tuple[float, int]]) -> float:
    """AUROC via the rank-sum identity, with ties averaged.

    Ties matter here more than in most settings: a weighted-regex scanner produces a
    coarse, heavily-tied score distribution, so a tie-breaking implementation would
    silently report a different number depending on input order.
    """
    pos = sum(1 for _s, y in scored if y == 1)
    neg = len(scored) - pos
    if not pos or not neg:
        return 0.0
    ordered = sorted(scored, key=lambda sy: sy[0])
    ranks: list[float] = [0.0] * len(ordered)
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1][0] == ordered[i][0]:
            j += 1
        avg = (i + j) / 2.0 + 1.0
        for k in range(i, j + 1):
            ranks[k] = avg
        i = j + 1
    rank_sum = sum(r for r, (_s, y) in zip(ranks, ordered, strict=True) if y == 1)
    return (rank_sum - pos * (pos + 1) / 2.0) / (pos * neg)


def _auprc(scored: Sequence[tuple[float, int]]) -> float:
    """Average precision. The metric to read when positives are rare."""
    pos = sum(1 for _s, y in scored if y == 1)
    if not pos:
        return 0.0
    ordered = sorted(scored, key=lambda sy: -sy[0])
    tp = 0
    total = 0.0
    for n, (_s, y) in enumerate(ordered, start=1):
        if y == 1:
            tp += 1
            total += tp / n
    return total / pos


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


def _flatten(value: Any) -> str:
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def score_sample(scanner: ThreatScanner, sample: Sample) -> ScanResult:
    return scanner.scan({"content": sample.text})


def evaluate(
    samples: Sequence[Sample], *, scanner: ThreatScanner | None = None
) -> Calibration:
    """Measure ranking quality, the threshold curve, and per-pattern contribution."""
    sc = scanner or ThreatScanner()
    scored: list[tuple[float, int]] = []
    per_pattern_mal: dict[str, int] = {}
    per_pattern_ben: dict[str, int] = {}
    n_mal = n_ben = 0

    for s in samples:
        result = score_sample(sc, s)
        scored.append((float(result.score), s.label))
        if s.malicious:
            n_mal += 1
        else:
            n_ben += 1
        for hit in result.hits:
            bucket = per_pattern_mal if s.malicious else per_pattern_ben
            bucket[hit.label] = bucket.get(hit.label, 0) + 1

    max_score = int(max((s for s, _ in scored), default=0))
    points = []
    for t in range(0, max_score + 2):
        tp = sum(1 for s, y in scored if y == 1 and s >= t)
        fp = sum(1 for s, y in scored if y == 0 and s >= t)
        fn = sum(1 for s, y in scored if y == 1 and s < t)
        tn = sum(1 for s, y in scored if y == 0 and s < t)
        points.append(ThresholdPoint(threshold=t, tp=tp, fp=fp, tn=tn, fn=fn))

    stats = [
        PatternStat(
            label=label, category=cat.value, weight=weight,
            hits_malicious=per_pattern_mal.get(label, 0),
            hits_benign=per_pattern_ben.get(label, 0),
            n_malicious=n_mal, n_benign=n_ben,
        )
        for _rx, cat, label, weight in _PATTERNS
    ]

    cal = Calibration(
        n_malicious=n_mal, n_benign=n_ben,
        auroc=_auroc(scored), auprc=_auprc(scored),
        points=points, patterns=sorted(stats, key=lambda p: -p.hits_malicious),
    )
    if n_mal < 10:
        cal.notes.append(
            f"ONLY {n_mal} ATTACK SAMPLE(S). Every number above is a description of "
            "those samples, not a calibration. A perfect AUROC here means the corpus is "
            "too small to disagree with, and the fix is more content-attack tasks — not "
            "a threshold change."
        )
    elif n_mal < 30 or n_ben < 30:
        cal.notes.append(
            f"Small sample ({n_mal} malicious, {n_ben} benign). These numbers indicate "
            "direction, not a calibrated operating point — a single scenario moves them."
        )
    if cal.dead:
        cal.notes.append(
            f"{len(cal.dead)} pattern(s) never fired: {', '.join(cal.dead[:6])}. "
            "Unmeasured rather than useless — but a pattern with no evidence behind it "
            "is carrying a weight nobody has justified."
        )
    if cal.noisy:
        cal.notes.append(
            f"{len(cal.noisy)} pattern(s) fire MORE on benign traffic than on attacks: "
            f"{', '.join(cal.noisy)}. Those are weighted votes for the wrong answer."
        )
    if cal.demoted:
        cal.notes.append(
            f"{len(cal.demoted)} pattern(s) carry weight 0 after calibration: "
            f"{', '.join(cal.demoted)}. They still fire and are still shown to an "
            "analyst; they no longer move a score that gates approval."
        )
    return cal


# ---------------------------------------------------------------------------
# Splits — the part that keeps the numbers honest
# ---------------------------------------------------------------------------


def task_disjoint_split(
    samples: Sequence[Sample], *, holdout: float = 0.3, seed: int = 0
) -> tuple[list[Sample], list[Sample]]:
    """Split so no task appears on both sides.

    The protocol MCPShield recommends, for the reason they measured: a random split
    lets the same task's content appear in both halves, and performance then reflects
    memorisation. Tasks are assigned by a stable hash so the split is reproducible
    without carrying a seed file around.
    """
    tasks = sorted({s.task for s in samples})
    if not tasks:
        return [], []
    ordered = sorted(tasks, key=lambda t: (hash((seed, t)) & 0xFFFFFFFF))
    n_hold = max(1, int(round(len(ordered) * holdout)))
    held = set(ordered[:n_hold])
    return (
        [s for s in samples if s.task not in held],
        [s for s in samples if s.task in held],
    )


def random_split(
    samples: Sequence[Sample], *, holdout: float = 0.3, seed: int = 0
) -> tuple[list[Sample], list[Sample]]:
    """Deliberately-leaky split, kept only to measure how much it inflates.

    Keyed on position as well as text. Hashing the text alone made identical texts
    sort together — the opposite of random — so a set where every attack shared one
    payload put all of them in the same fold and the comparison it feeds became
    meaningless. Unique texts hid this, which is how it would have stayed hidden.
    """
    ordered = sorted(
        enumerate(samples), key=lambda pair: (hash((seed, pair[0], pair[1].text)) & 0xFFFFFFFF)
    )
    n_hold = max(1, int(round(len(ordered) * holdout)))
    return [s for _i, s in ordered[n_hold:]], [s for _i, s in ordered[:n_hold]]


def compare_splits(
    samples: Sequence[Sample], *, scanner: ThreatScanner | None = None, seed: int = 0
) -> dict[str, Any]:
    """Reproduce MCPShield's leakage experiment on this corpus.

    They found random splits inflating AUROC by up to 25.8 points. This scanner reads
    arguments only and never sees a tool name, so it should be near-immune — and the
    difference is reported either way, because "should be" is not a measurement.
    """
    sc = scanner or ThreatScanner()
    _tr_t, te_t = task_disjoint_split(samples, seed=seed)
    _tr_r, te_r = random_split(samples, seed=seed)

    # A fold with no positives (or none negative) has no defined AUROC. Reporting the
    # 0.0 that falls out of the arithmetic as though it were a measurement produced a
    # "+100 point inflation" here on a corpus with three attack samples — a number
    # more misleading than silence, because it looks like the leak the experiment is
    # meant to detect.
    def measurable(subset: Sequence[Sample]) -> bool:
        pos = sum(1 for x in subset if x.malicious)
        return pos > 0 and pos < len(subset)

    if not (measurable(te_t) and measurable(te_r)):
        return {
            "measurable": False,
            "held_out_tasks": len({s.task for s in te_t}),
            "interpretation": (
                "Not measurable. A held-out fold contained no attack samples, so AUROC "
                "is undefined on it. This needs more content-attack tasks, not a "
                "different split."
            ),
        }

    disjoint = evaluate(te_t, scanner=sc)
    leaky = evaluate(te_r, scanner=sc)
    delta = (leaky.auroc - disjoint.auroc) * 100.0
    return {
        "measurable": True,
        "task_disjoint_auroc": round(disjoint.auroc, 4),
        "random_split_auroc": round(leaky.auroc, 4),
        "inflation_points": round(delta, 2),
        "held_out_tasks": len({s.task for s in te_t}),
        "interpretation": (
            "Near zero, as expected: this scanner reads argument content only and "
            "never sees a tool name, so there is no tool signature to memorise."
            if abs(delta) < 5.0
            else "Material inflation — the score is picking up something task-specific, "
                 "and any threshold tuned on a random split is overstated."
        ),
    }


# ---------------------------------------------------------------------------
# Sample construction
# ---------------------------------------------------------------------------


# The techniques whose attack actually lives in argument *content*. Everything else
# in the corpus is a semantic attack: repointing a supplier's bank account is
# malicious because of what it means, not because "LT77-MULE-0000-9999" looks wrong,
# and no content scanner can or should catch it. Those are the authority layer's, the
# spend cap's and the reversibility gate's job.
#
# This distinction is not a convenience. Scoring the scanner against semantic attacks
# produced AUROC 0.514 — indistinguishable from random — and the obvious reading was
# "the scanner is broken". The real fault was the measurement: 12 of 18 patterns
# never fired because the samples contained `V-100`, `48500` and `prod`. A metric
# that evaluates a control against attacks it was never the control for is worse than
# no metric, because it invites a fix to the wrong component.
CONTENT_ATTACK_TECHNIQUES = frozenset({
    "T07",   # indirect prompt injection carried in tool arguments
    "T16",   # credential exfiltration in tool arguments
    "T17",   # obfuscated instructions via invisible characters
})


def samples_from_scenarios(
    scenarios: Iterable[Any], *, content_only: bool = True
) -> list[Sample]:
    """Labelled samples from benchmark scenarios: one per argument value.

    Argument *values*, not whole calls, because that is exactly what the scanner
    sees. Feeding it anything richer would measure a detector that does not exist.

    With ``content_only`` (the default), harmful steps from semantic-attack scenarios
    are **excluded** rather than labelled either way. They are not attack content, and
    they are not benign content either — they are out of this control's scope, and
    counting them as negatives would flatter the scanner exactly as counting them as
    positives condemned it.
    """
    out: list[Sample] = []
    for sc in scenarios:
        malicious = getattr(sc.intent, "value", "") == "malicious"
        content_attack = getattr(sc, "technique", "") in CONTENT_ATTACK_TECHNIQUES

        for step in sc.steps:
            harmful = getattr(step, "harmful", False)
            if malicious and harmful and content_only and not content_attack:
                continue    # semantic attack: out of scope for a content scanner
            # Reconnaissance reads inside a malicious scenario are ordinary traffic;
            # labelling them as attacks would poison the negative class.
            label = malicious and harmful
            # One sample per CALL, not per argument value. The scanner is invoked once
            # with the whole argument dict, so the call is the unit it decides on.
            #
            # Measuring per value looked more granular and was simply wrong: an attack
            # call carries its payload in one argument and innocuous companions in the
            # rest — a path, a description, a recipient. Labelling those as attacks
            # scored six false misses per real payload and put recall at 33% when every
            # payload had in fact been caught. A metric has to share the unit of
            # decision with the thing it measures.
            parts = [_flatten(v) for v in (step.args or {}).values()]
            if step.description:
                parts.append(step.description)
            text = "\n".join(t for t in parts if t.strip())
            if text.strip():
                out.append(Sample(text=text, malicious=label, task=sc.id))
    return out


# ---------------------------------------------------------------------------
# ATBench: external attack content
# ---------------------------------------------------------------------------
#
# The bundled corpus has three content-attack samples, which is too few to calibrate
# anything — a perfect AUROC on three samples means the corpus cannot disagree with
# you. ATBench (Apache-2.0, on Hugging Face as ``AI45Research/ATBench``) supplies 500
# human-audited trajectories, balanced 250 safe / 250 unsafe.
#
# Its risk taxonomy splits exactly along the line this scanner cares about:
#
#   injection   indirect_prompt_injection, direct_prompt_injection,
#               tool_description_injection, malicious_user_instruction_or_jailbreak
#               -> text payloads a content scanner can see
#
#   semantic    corrupted_tool_feedback, unreliable_or_misinformation,
#               malicious_tool_execution, inherent_agent_failures
#               -> falsified values and bad behaviour, carrying no textual signal.
#               Excluded for the same reason vendor-bank fraud is: scoring a content
#               scanner against them measures the wrong control.
#
# Not vendored. Apache-2.0 would permit it, but five megabytes of third-party
# evaluation data does not belong inside a control plane, and the no-vendor
# discipline established for RAS-Eval should not get an exception for convenience.

ATBENCH_ENV_VAR = "ATBENCH_PATH"

INJECTION_RISK_SOURCES = frozenset({
    "indirect_prompt_injection",
    "direct_prompt_injection",
    "tool_description_injection",
    "malicious_user_instruction_or_jailbreak",
})


def atbench_path(path: str | None = None) -> Path | None:
    """Locate an ATBench ``test.json``, or return None.

    An explicit path is used exclusively — same rule as the RAS-Eval loader, and for
    the same reason: falling through to the environment on a typo would silently
    measure different data and report it as what you asked for.
    """
    if path:
        p = Path(path)
        return p if p.is_file() else None
    for cand in (os.environ.get(ATBENCH_ENV_VAR), "ATBench500/test.json", "atbench500.json"):
        if cand and Path(cand).is_file():
            return Path(cand)
    return None


def _untrusted_text(record: dict[str, Any]) -> str:
    """Everything in a trajectory that did not originate with the control plane.

    User instructions, tool responses and tool descriptions — the three places an
    injected payload arrives from. The agent's own reasoning is excluded: a scanner
    flagging the agent's summary of a payload would be reporting the symptom, and
    would fire just as readily when the agent correctly refused.
    """
    parts: list[str] = []
    for tool in record.get("tool_used") or []:
        if isinstance(tool, dict):
            parts.append(str(tool.get("description") or ""))
    blocks = record.get("content") or []
    turns = blocks[0] if (blocks and isinstance(blocks[0], list)) else blocks
    for turn in turns or []:
        if isinstance(turn, dict) and turn.get("role") in ("user", "environment"):
            parts.append(str(turn.get("content") or ""))
    return "\n".join(t for t in parts if t.strip())


def atbench_samples(path: str | None = None) -> list[Sample]:
    """Content-attack samples from an ATBench snapshot. Empty when absent.

    **One sample per trajectory**, not per turn. Per-turn labelling would inherit the
    trajectory's verdict on turns carrying no payload, and this module has already
    produced three wrong conclusions from exactly that kind of label noise. A coarser
    unit that is unambiguously labelled beats a finer one that is not — at the cost,
    stated here rather than buried, of being coarser than the single call the gate
    actually decides on.
    """
    src = atbench_path(path)
    if src is None:
        return []
    with src.open() as f:
        records = json.load(f)
    if not isinstance(records, list):
        return []

    out: list[Sample] = []
    for i, rec in enumerate(records):
        if not isinstance(rec, dict):
            continue
        risk = str(rec.get("risk_source") or "")

        # Labelled by RISK SOURCE, not by ATBench's `label`. Their label answers a
        # different question than this one: it records whether the *agent behaved
        # badly*, so a trajectory carrying an injection payload that the agent
        # correctly resisted is labelled safe. 84 of 127 indirect-injection
        # trajectories are labelled safe and still contain the payload — using their
        # label would have put 84 payload-carrying samples in the negative class and
        # made a correctly-firing scanner look catastrophically noisy.
        #
        # A borrowed dataset's label is only usable when it answers your question.
        # This is the fourth time in this module that assumption cost a wrong
        # conclusion, and it is the least obvious of the four.
        payload_present = risk in INJECTION_RISK_SOURCES

        text = _untrusted_text(rec)
        if not text.strip():
            continue
        out.append(Sample(
            text=text, malicious=payload_present,
            task=f"atbench-{rec.get('conv_id', i)}",
            source=f"atbench:{risk or 'unlabelled'}",
        ))
    return out


def corpus_samples(
    *,
    include_external: bool = True,
    content_only: bool = True,
    include_atbench: bool = True,
) -> list[Sample]:
    """Labelled samples from the bundled corpus, plus imported traffic if present."""
    from ..bench import all_scenarios
    from ..bench.external import ras_eval_scenarios

    scenarios = list(all_scenarios())
    if include_external:
        scenarios += ras_eval_scenarios()
    samples = samples_from_scenarios(scenarios, content_only=content_only)
    if include_atbench:
        samples += atbench_samples()
    return samples


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def render(cal: Calibration, *, splits: dict[str, Any] | None = None) -> str:
    lines = ["THREAT SCANNER CALIBRATION", "=" * 68]
    lines.append(f"samples          {cal.n_malicious} malicious, {cal.n_benign} benign")
    lines.append(f"AUROC            {cal.auroc:.3f}   does the score rank attacks above traffic")
    lines.append(f"AUPRC            {cal.auprc:.3f}   average precision, the one to read when "
                 "positives are rare")
    lines.append("")

    lines.append("OPERATING POINTS")
    lines.append(f"  {'thr':>4} {'recall':>7} {'prec':>7} {'FPR':>7} {'F1':>6}   tp/fp/fn")
    for p in cal.points:
        mark = ""
        if cal.best_f1 and p.threshold == cal.best_f1.threshold:
            mark = "  <- best F1"
        if cal.strictest_clean and p.threshold == cal.strictest_clean.threshold:
            mark += "  <- strictest with no false positives"
        lines.append(
            f"  {p.threshold:>4} {p.recall:>7.1%} {p.precision:>7.1%} {p.fpr:>7.1%} "
            f"{p.f1:>6.3f}   {p.tp}/{p.fp}/{p.fn}{mark}"
        )
    lines.append("")

    lines.append("PER-PATTERN CONTRIBUTION")
    lines.append(f"  {'verdict':>8} {'w':>2} {'mal':>4} {'ben':>4}  {'lift':>6}  pattern")
    for stat in cal.patterns:
        lift = stat.lift
        lift_s = "  —  " if lift is None else ("  inf" if lift == math.inf else f"{lift:6.1f}")
        lines.append(
            f"  {stat.verdict:>8} {stat.weight:>2} {stat.hits_malicious:>4} "
            f"{stat.hits_benign:>4} {lift_s}  {stat.label}"
        )
    lines.append("")

    if splits:
        lines.append("SPLIT LEAKAGE  (MCPShield's experiment, on this corpus)")
        if splits.get("measurable"):
            lines.append(f"  task-disjoint AUROC  {splits['task_disjoint_auroc']:.3f}")
            lines.append(f"  random-split  AUROC  {splits['random_split_auroc']:.3f}")
            lines.append(f"  inflation            {splits['inflation_points']:+.2f} points")
        lines.append(f"  {splits['interpretation']}")
        lines.append("")

    for n in cal.notes:
        lines.append(f"note: {n}")
    if cal.notes:
        lines.append("")
    lines.append(
        "A weighted-regex scanner is kept deliberately: its hits are explainable to "
        "whoever has to approve the call. The measurement exists to say where that "
        "stops being enough, not to replace it with a number nobody can interpret."
    )
    return "\n".join(lines)


__all__ = [
    "Sample",
    "ThresholdPoint",
    "PatternStat",
    "Calibration",
    "evaluate",
    "corpus_samples",
    "atbench_samples",
    "atbench_path",
    "INJECTION_RISK_SOURCES",
    "samples_from_scenarios",
    "task_disjoint_split",
    "random_split",
    "compare_splits",
    "render",
]
