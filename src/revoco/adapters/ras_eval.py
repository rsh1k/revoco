"""
revoco.adapters.ras_eval
========================
Reversibility classifications for the 29 tools used by the RAS-Eval benchmark.

Why this exists
---------------
The containment corpus' benign half is hand-authored, and hand-authored benign
traffic has a specific blind spot: it contains the false positives I thought to
look for. RAS-Eval (`arXiv 2506.15253 <https://arxiv.org/abs/2506.15253>`_) has 80
benign tasks that real models actually executed, with real arguments. That is the
one thing authorship cannot produce.

Its tools are not this package's tools, so the traces are unusable until something
says what each of them does to the world. That is what this module is — **my
classifications of their tool surface**, written from the tool names and the
observed call arguments.

No data from RAS-Eval is vendored here. The repository declares no license, so its
tasks and logs are all-rights-reserved by default and cannot be redistributed in an
Apache-2.0 package. :mod:`revoco.bench.external` reads them from a clone you obtain
yourself, and returns nothing when it is absent.

Status: **unvalidated, and unvalidatable from here.** These are someone else's
tools; I cannot execute them, so no drill can confirm any inverse below. They are
classified for the purpose of measuring *whether ordinary tool use gets blocked* —
which only needs the reversal posture to be approximately right — and should not be
used to govern anything.

What this surface is good for, and what it is not
-------------------------------------------------
Good for: volume and variety of ordinary agent tool use. Thirty distinct tools
across seven agent personas, argument shapes produced by eight different models.
That is a false-positive dimension the hand-built corpus does not cover at all.

Not good for: enterprise write semantics. There is no ERP posting, no payroll, no
IAM here — the domains are alarms, calendars, disk stats, weather and arXiv
lookups. It broadens the benign distribution; it does not deepen it toward the
surfaces where the money is.
"""

from __future__ import annotations

from ..reversal.model import InverseSpec, Reversibility
from ..reversal.registry import InverseRegistry

# Reads. Trivially reversible because they change nothing — which is also why a
# corpus made only of these would prove very little. Most of RAS-Eval is here.
_READS = (
    "is_arxiv_identifier",
    "search_identifier",
    "get_disk_info",
    "get_memory_info",
    "get_current_time",
    "get_weather",
    "get_events_from_calendar",
    "search_event",
    "tavily_search",
    "location_encode",
    "get_stock_price",
    "get_cpu_info",
    "list_directory",
    "read_file",
    "get_alarms",
    "web_search",
)

# Paired create/cancel operations. The genuinely interesting part of this surface:
# each is an exact inverse of the other, which is the shape the reversal model
# handles best and the shape most real tool surfaces lack.
_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("add_event_to_calendar", "remove_event_from_calendar", "event_id"),
    ("remove_event_from_calendar", "add_event_to_calendar", "event_id"),
    ("set_alarm", "cancel_alarm", "alarm_id"),
    ("cancel_alarm", "set_alarm", "alarm_id"),
    ("timer", "cancel_timer", "timer_id"),
)


def _read_specs() -> list[InverseSpec]:
    return [
        InverseSpec(
            tool=t,
            kind=Reversibility.REVERSIBLE,
            inverse_tool="ras.noop",
            notes="Read-only: nothing to undo.",
        )
        for t in _READS
    ]


def _pair_specs() -> list[InverseSpec]:
    return [
        InverseSpec(
            tool=fwd,
            kind=Reversibility.REVERSIBLE,
            inverse_tool=inv,
            arg_map=((key, f"result.{key}"),),
            notes=(
                f"Exact inverse pair with {inv}. The identifier comes from the "
                "response, so the undo path only completes after the forward call "
                "returns — which is precisely the deferred-argument case the plan "
                "model exists to handle."
            ),
        )
        for fwd, inv, key in _PAIRS
    ]


RAS_EVAL_SPECS: list[InverseSpec] = [
    *_read_specs(),
    *_pair_specs(),
    # Writes with an approximate inverse.
    InverseSpec(
        tool="insert_data",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="delete_data",
        # `db_path` and `items`, not `table`. The first version of this spec invented
        # `table` from the tool's name, and the imported traces caught it: an argument
        # that is never passed cannot resolve, so every real insert raised a phantom
        # rollback. The same mistake in an enterprise adapter would look identical.
        arg_map=(("db_path", "args.db_path"), ("row_id", "result.row_id")),
        residue=(
            "Deleting the row removes the data, not its trace: auto-increment "
            "sequences have advanced, and anything that read the row while it existed "
            "acted on it."
        ),
    ),
    InverseSpec(
        tool="download_file",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="delete_file",
        arg_map=(("path", "args.path"),),
        residue=(
            "The file is removed but the transfer happened: bandwidth was consumed and "
            "the remote server logged the request."
        ),
    ),
    InverseSpec(
        tool="convert_file_to_markdown",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="delete_file",
        # The destination is `save_path` in the request, not `output_path` in the
        # response — also found by importing real calls rather than by reading.
        arg_map=(("path", "args.save_path"),),
        residue="The converted output is removed; the source is untouched.",
    ),
    InverseSpec(
        tool="write_file",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="write_file",
        arg_map=(("path", "args.path"), ("content", "snapshot.content")),
        snapshot_fields=("content",),
        residue=(
            "Prior content is restored where it was captured. If the file did not "
            "exist before, this leaves an empty file rather than no file."
        ),
    ),
    # Genuinely one-way, and worth registering so they escalate rather than
    # falling into UNKNOWN by accident.
    InverseSpec(
        tool="send_email",
        kind=Reversibility.IRREVERSIBLE,
        notes="Delivered mail cannot be recalled.",
    ),
    InverseSpec(
        tool="execute_shell_command",
        kind=Reversibility.UNKNOWN,
        notes=(
            "Same reasoning as revoco's own shell.exec: an arbitrary command's effects "
            "cannot be known in advance, so the honest classification is UNKNOWN and "
            "the honest outcome is escalation."
        ),
    ),
]


def ras_eval_registry() -> InverseRegistry:
    """Classifications for the RAS-Eval tool surface (unvalidated — see module docs)."""
    return InverseRegistry(list(RAS_EVAL_SPECS))


def classified_tools() -> set[str]:
    return {s.tool for s in RAS_EVAL_SPECS}


__all__ = ["RAS_EVAL_SPECS", "ras_eval_registry", "classified_tools"]
