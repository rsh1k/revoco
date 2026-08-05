"""
praetor.core.ids
================
Identifier generation.

Ids are prefixed so a bare id in a log line tells you what kind of object it
refers to without a lookup — during an incident that saves real time. The
random part comes from :mod:`secrets`, not :mod:`random`, because ids appear in
signed payloads and a predictable id is a replay/collision aid.
"""

from __future__ import annotations

import secrets

_ID_BYTES = 12  # 96 bits of entropy — collision-free at any plausible scale


def new_id(prefix: str) -> str:
    """Return a new prefixed identifier, e.g. ``act_9f2c...``."""
    return f"{prefix}_{secrets.token_hex(_ID_BYTES)}"


# Canonical prefixes, kept in one place so they cannot drift between modules.
PRINCIPAL = "prn"
DELEGATION = "dlg"
ACTION = "act"
PLAN = "rvp"
JOURNAL = "rvj"
REVERSAL = "rev"
REVOCATION = "rvk"
