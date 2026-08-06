"""
revoco.gate.threats
====================
Heuristic detection of injected instructions and dangerous arguments.

Design stance — read carefully
------------------------------
This is a HEURISTIC signal, not a classifier with a calibrated false-positive
rate. It is deliberately conservative and EXPLAINABLE: every hit names the
pattern and category that fired, so an analyst can see exactly why. Heuristics
produce false positives by nature, so the intended use is to feed a
REQUIRE_APPROVAL effect rather than a hard DENY — a false hit should cost a
review click, not a broken workflow. That is the honest way to use pattern
matching in a security control.

# HARDENING: pattern matching catches known shapes, not novel or obfuscated
# attacks. For stronger coverage, layer a dedicated injection classifier behind
# the same ThreatScanner interface and keep this heuristic as a cheap,
# deterministic first pass that needs no network call and cannot itself be
# prompt-injected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"      # OWASP ASI01 / ASI02
    COMMAND_INJECTION = "command_injection"    # OWASP ASI05
    SECRET_EXFIL = "secret_exfiltration"       # OWASP ASI02
    PATH_TRAVERSAL = "path_traversal"          # OWASP ASI02
    SUSPICIOUS_URL = "suspicious_url"          # data egress to attacker host
    OBFUSCATION = "obfuscation"                # hidden-character smuggling


# Each pattern is (compiled_regex, category, human_label, weight). Weights let
# policy set a threshold instead of firing on any single weak signal, which is
# the main lever for trading sensitivity against false positives.
_PATTERNS: list[tuple[re.Pattern[str], ThreatCategory, str, int]] = [
    # --- prompt injection / goal hijack -----------------------------------
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions", re.I),
     ThreatCategory.PROMPT_INJECTION, "ignore-previous-instructions", 4),
    (re.compile(r"disregard\s+(the\s+)?(system|above|prior)", re.I),
     ThreatCategory.PROMPT_INJECTION, "disregard-system", 3),
    (re.compile(r"\byou\s+are\s+now\b|\bnew\s+role\b|\bact\s+as\b", re.I),
     ThreatCategory.PROMPT_INJECTION, "role-reassignment", 2),
    # The verb must actually govern a credential. The first version wrote this as
    # `reveal|exfiltrate|leak|send.*(api_key|password|secret|token)`, where alternation
    # binds loosely: bare "reveal" matched, with no credential anywhere. Calibration
    # measured it firing on 37 benign samples against 19 attacks — a weight-3 vote for
    # the wrong answer, and invisible to a probe that only ever fed it true positives.
    (re.compile(
        r"\b(reveal|exfiltrate|leak|expose|send|post|upload)\b[^.\n]{0,60}?"
        r"\b(api[_\s-]?keys?|password|secret|token|credential)s?\b",
        re.I,
    ),
     # Weight 0, set by measurement rather than judgement. Even after the regex was
     # tightened this fires on 4 benign samples against 1 attack — as a weighted vote
     # it is worse than nothing. Weight 0 keeps the hit visible in `ScanResult.hits`
     # and in the audit obligations, so an analyst still sees that the text talked
     # about sending a secret, while it stops moving a score that gates approval.
     # Evidence is corpus-specific: an exfiltration instruction is a real signal, it
     # just is not a discriminating one in the data available here.
     ThreatCategory.PROMPT_INJECTION, "instruction-to-exfiltrate", 0),
    (re.compile(r"</?(system|assistant|tool)[>\]]", re.I),
     ThreatCategory.PROMPT_INJECTION, "fake-role-delimiter", 3),

    # --- command / code injection -----------------------------------------
    (re.compile(r";\s*(rm|del|format|shutdown|reboot)\b", re.I),
     ThreatCategory.COMMAND_INJECTION, "chained-destructive-command", 4),
    (re.compile(r"\$\(|\bsubprocess\b|\bos\.system\b|\beval\(|\bexec\(", re.I),
     ThreatCategory.COMMAND_INJECTION, "code-exec-primitive", 3),
    (re.compile(r"\|\s*(sh|bash|powershell|cmd)\b", re.I),
     ThreatCategory.COMMAND_INJECTION, "pipe-to-shell", 4),

    # --- secret exfiltration ----------------------------------------------
    (re.compile(r"AKIA[0-9A-Z]{16}"),
     ThreatCategory.SECRET_EXFIL, "aws-access-key-id", 4),
    (re.compile(r"-----BEGIN\s+(RSA|OPENSSH|EC|DSA|PGP)\s+PRIVATE\s+KEY-----"),
     ThreatCategory.SECRET_EXFIL, "private-key-block", 5),
    (re.compile(r"\b(sk|rk)-[A-Za-z0-9]{20,}\b"),
     ThreatCategory.SECRET_EXFIL, "api-secret-token", 3),

    # --- path traversal ----------------------------------------------------
    (re.compile(r"\.\./|\.\.\\"),
     ThreatCategory.PATH_TRAVERSAL, "dot-dot-slash", 3),
    (re.compile(r"/etc/(passwd|shadow|sudoers)\b"),
     ThreatCategory.PATH_TRAVERSAL, "sensitive-system-file", 4),

    # --- suspicious egress URLs -------------------------------------------
    (re.compile(r"https?://\d{1,3}(\.\d{1,3}){3}"),
     ThreatCategory.SUSPICIOUS_URL, "raw-ip-url", 2),
    # `.zip` and `.mov` are real gTLDs and, far more often, file extensions — a link
    # ending in `.zip` is usually a download. Calibration caught this firing on 4
    # benign samples against 1 attack. They are matched only as a bare authority, with
    # nothing following, which is the shape that actually indicates a hostile host.
    (re.compile(r"https?://[^\s\"'/]*\.(?:tk|top|xyz|click)\b", re.I),
     # Also demoted to 0 by calibration: 0 attacks, 3 benign. Same reasoning — the
     # observation survives, the vote does not.
     ThreatCategory.SUSPICIOUS_URL, "high-risk-tld", 0),
    (re.compile(r"https?://[^\s\"'/]*\.(?:zip|mov)(?:[/?#]|$)", re.I),
     ThreatCategory.SUSPICIOUS_URL, "filename-lookalike-tld", 2),

    # --- obfuscation -------------------------------------------------------
    # Zero-width and Unicode-tag characters carry payloads invisible in any
    # review UI, so a human approving the call cannot see what they approved.
    # Carried over from the memory-integrity work, where it was the one detector
    # that caught what content scanning missed.
    (re.compile(r"[​-‏⁠-⁤﻿]"),
     ThreatCategory.OBFUSCATION, "zero-width-characters", 3),
    (re.compile(r"[\U000e0000-\U000e007f]"),
     ThreatCategory.OBFUSCATION, "unicode-tag-characters", 4),
    (re.compile(r"[‪-‮⁦-⁩]"),
     ThreatCategory.OBFUSCATION, "bidi-override", 3),
]


@dataclass(frozen=True)
class ThreatHit:
    category: ThreatCategory
    label: str
    weight: int
    field_path: str
    excerpt: str


@dataclass(frozen=True)
class ScanResult:
    hits: tuple[ThreatHit, ...] = ()
    score: int = 0
    categories: frozenset[ThreatCategory] = field(default_factory=frozenset)

    @property
    def clean(self) -> bool:
        return not self.hits

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "categories": sorted(c.value for c in self.categories),
            "hits": [
                {
                    "category": h.category.value,
                    "label": h.label,
                    "weight": h.weight,
                    "field": h.field_path,
                }
                for h in self.hits
            ],
        }


def _walk_strings(obj: Any, prefix: str = "", depth: int = 0) -> list[tuple[str, str]]:
    """Yield ``(dotted_path, string_value)`` for every string in a structure."""
    if depth > 24:  # cheap guard against deeply nested hostile payloads
        return []
    out: list[tuple[str, str]] = []
    if isinstance(obj, str):
        out.append((prefix or "<root>", obj))
    elif isinstance(obj, dict):
        for k, v in obj.items():
            out.extend(_walk_strings(v, f"{prefix}.{k}" if prefix else str(k), depth + 1))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(_walk_strings(v, f"{prefix}[{i}]", depth + 1))
    return out


class ThreatScanner:
    """Scans tool-call arguments for known-dangerous content shapes."""

    def __init__(self, max_excerpt: int = 60) -> None:
        self.max_excerpt = max_excerpt

    def scan(self, arguments: dict[str, Any]) -> ScanResult:
        hits: list[ThreatHit] = []
        for path, value in _walk_strings(arguments or {}):
            for pattern, category, label, weight in _PATTERNS:
                m = pattern.search(value)
                if m:
                    start = max(0, m.start() - 10)
                    hits.append(
                        ThreatHit(
                            category=category,
                            label=label,
                            weight=weight,
                            field_path=path,
                            excerpt=value[start : start + self.max_excerpt],
                        )
                    )
        return ScanResult(
            hits=tuple(hits),
            score=sum(h.weight for h in hits),
            categories=frozenset(h.category for h in hits),
        )
