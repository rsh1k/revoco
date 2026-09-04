"""Hidden-character detection: the payload a regex scanner cannot see.

`threats.py` matches patterns against argument strings, which works exactly as
far as the attacker writes the instruction in characters a reviewer would
recognise. It does not have to. Unicode offers several ways to put text into a
string that a model reads and a human — and a regex written against readable
text — does not:

* **Tag characters** (U+E0000–U+E007F) encode a full ASCII payload invisibly.
  There is no legitimate use of them in ordinary text.
* **Bidirectional overrides** reorder how a string renders against how it parses,
  which is the Trojan Source class: the reviewer and the interpreter genuinely
  see different things.
* **Zero-width characters** wedged between letters break up a word so a pattern
  looking for `ignore previous instructions` matches nothing at all.

That last one is the reason this is not a nice-to-have. Every weighted pattern
in `threats.py` can be defeated by a character nobody can see, and adding more
patterns does not help.

Ported from mnemosyne, keeping the discrimination that makes it usable
-----------------------------------------------------------------------
A detector that flags every zero-width character is one that fires on emoji and
gets turned off. The distinctions preserved from the original are the whole
value:

* ZWJ (U+200D) is load-bearing in emoji sequences, so it is flagged **only**
  where it joins two ASCII word characters — never where it joins pictographs.
* Right-to-left script marks are how Arabic and Hebrew are written. The bidi
  *overrides* and *isolates* are flagged; the ordinary marks are not.
* A zero-width character standing alone in a string is not smuggling; one
  interleaved with word characters is.

Weights are measured, not chosen
--------------------------------
Everything in `threats.py` carries a weight justified against the corpus, and a
number invented here would be the one unjustified vote in the set. See
`revoco calibrate`; the figures behind these weights are in the module tests.
"""

from __future__ import annotations

import re
from typing import Any

from .threats import ThreatCategory, ThreatHit, _walk_strings

# Invisible, and capable of carrying a complete ASCII payload.
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F

# Overrides and isolates only. The plain marks (U+200E/200F) are how
# right-to-left scripts are written and are deliberately absent.
_BIDI_CONTROLS = frozenset({
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,   # LRE RLE PDF LRO RLO
    0x2066, 0x2067, 0x2068, 0x2069,           # LRI RLI FSI PDI
})

# ZWJ is excluded here on purpose and handled separately: it is what joins the
# parts of a single emoji, and blanket-flagging it makes the detector unusable.
_ZERO_WIDTH = frozenset({
    0x200B,   # zero width space
    0x200C,   # zero width non-joiner
    0xFEFF,   # zero width no-break space / BOM mid-string
    0x2060,   # word joiner
    0x00AD,   # soft hyphen
})
_ZWJ = 0x200D


def _ascii_word(ch: str) -> bool:
    return ch.isascii() and (ch.isalnum() or ch == "_")


def _interleaved_zero_width(text: str) -> int:
    """Zero-width characters sitting against ASCII word characters."""
    count = 0
    for i, ch in enumerate(text):
        cp = ord(ch)
        before = i > 0 and _ascii_word(text[i - 1])
        after = i + 1 < len(text) and _ascii_word(text[i + 1])
        if cp in _ZERO_WIDTH and (before or after):
            count += 1
        elif cp == _ZWJ and before and after:
            # Between two ASCII word characters this cannot be an emoji join.
            count += 1
    return count


def detect(arguments: dict[str, Any], *, max_excerpt: int = 60) -> list[ThreatHit]:
    """Hidden-character hits over every string in a tool call's arguments."""
    hits: list[ThreatHit] = []
    for path, value in _walk_strings(arguments or {}):
        tags = sum(1 for c in value if _TAG_LO <= ord(c) <= _TAG_HI)
        if tags:
            hits.append(ThreatHit(
                category=ThreatCategory.OBFUSCATION,
                label=f"unicode tag characters ({tags}) — invisible payload",
                weight=5,
                field_path=path,
                excerpt=_visible(value, max_excerpt),
            ))

        bidi = sum(1 for c in value if ord(c) in _BIDI_CONTROLS)
        if bidi:
            hits.append(ThreatHit(
                category=ThreatCategory.OBFUSCATION,
                label=f"bidirectional override/isolate ({bidi}) — renders "
                      "differently from how it parses",
                weight=4,
                field_path=path,
                excerpt=_visible(value, max_excerpt),
            ))

        zw = _interleaved_zero_width(value)
        if zw:
            hits.append(ThreatHit(
                category=ThreatCategory.OBFUSCATION,
                label=f"zero-width characters interleaved with text ({zw}) — "
                      "defeats pattern matching",
                weight=4 if zw >= 3 else 3,
                field_path=path,
                excerpt=_visible(value, max_excerpt),
            ))
    return hits


def _visible(text: str, limit: int) -> str:
    """An excerpt a person can read.

    Quoting the raw value in a finding would reproduce the invisible characters
    into the log, the console and the evidence pack — carrying the payload
    onward and rendering the excerpt as innocent there as it was in the
    argument. The excerpt shows what is left once they are removed.
    """
    return strip(text)[:limit]


def strip(text: str) -> str:
    """Remove smuggling characters, preserving legitimate ones.

    Tags, bidi controls and zero-width spacers go unconditionally. ZWJ goes only
    where it joins ASCII word characters, so emoji survive.
    """
    out: list[str] = []
    for i, ch in enumerate(text):
        cp = ord(ch)
        if _TAG_LO <= cp <= _TAG_HI or cp in _BIDI_CONTROLS or cp in _ZERO_WIDTH:
            continue
        if cp == _ZWJ:
            before = bool(out) and _ascii_word(out[-1])
            after = i + 1 < len(text) and _ascii_word(text[i + 1])
            if before and after:
                continue
        out.append(ch)
    return re.sub(r"[ \t]{2,}", " ", "".join(out))


__all__ = ["detect", "strip"]
