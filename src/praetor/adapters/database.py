"""
praetor.adapters.database
=========================
Inverse-operation specs for relational database writes and schema migrations.

Status: **specification, not a validated integration.** See ``docs/ADAPTERS.md``.

The uncomfortable truth about this surface
-----------------------------------------
Most database writes an agent makes are **not recoverable by this control plane**,
and pretending otherwise would be the most dangerous thing in the whole package.

* A row update is reversible only if the prior row was captured, and only if no
  other transaction has since touched it. Blindly writing old values back over a
  row someone else has edited is data loss dressed as recovery.
* `DELETE` without a captured copy is gone.
* `DROP TABLE` is gone. So is `TRUNCATE`. Point-in-time recovery may exist at the
  infrastructure layer, but restoring a whole database to undo one statement is a
  decision for a DBA under an incident process, not an automated inverse.
* An `UPDATE` with no `WHERE` clause has already touched every row by the time
  anyone notices.

So the specs here lean hard on `IRREVERSIBLE`, and the useful control on this
surface is the *enforcement* layer, not the reversal layer: argument conditions
that require a `WHERE` clause, row-count caps, and denying DDL outright. The
reversal layer's honest contribution is to make that unrecoverability **visible at
authorize time** so policy escalates before the statement runs.

Migrations are the exception worth investing in
-----------------------------------------------
A migration framework's `down` step is a real, declared inverse — the only one on
this surface that is designed rather than improvised. It is also routinely
unwritten, untested, or destructive, which is why the spec gates on it rather than
assuming it works. A `down` migration that drops the column the `up` added is
technically an inverse and still loses every value in it.
"""

from __future__ import annotations

from ..reversal.model import (
    PHASE_AUTHORIZE,
    InverseSpec,
    ReversalGate,
    Reversibility,
)
from ..reversal.registry import InverseRegistry

# ---------------------------------------------------------------------------
# Gates
# ---------------------------------------------------------------------------

GATE_ROW_UNCHANGED = ReversalGate(
    name="db_row_unchanged_since_capture",
    description=(
        "The row must not have been modified by anyone else since the snapshot was "
        "taken. Writing captured values back over a concurrent edit destroys that "
        "edit."
    ),
    remediation=(
        "Compare the row's current version or updated_at against the snapshot. If it "
        "moved, a human has to merge — this is not a mechanical undo."
    ),
)

GATE_ROWS_BOUNDED = ReversalGate(
    name="db_affected_rows_captured",
    description=(
        "Every row the statement will change must have been captured beforehand. That "
        "is only feasible for a bounded, well-targeted statement."
    ),
    remediation=(
        "Require a WHERE clause and a row-count ceiling in policy. An unbounded UPDATE "
        "or DELETE should be denied, not snapshotted."
    ),
    check_at=PHASE_AUTHORIZE,
)

GATE_DOWN_MIGRATION_TESTED = ReversalGate(
    name="db_down_migration_exists_and_tested",
    description=(
        "The migration must have a down step that has actually been exercised. An "
        "unwritten or never-run down migration is not a rollback path."
    ),
    remediation=(
        "Require down migrations in review and run them in CI. Until then, treat "
        "migrations as irreversible and gate them behind a human."
    ),
    check_at=PHASE_AUTHORIZE,
)

DATABASE_GATES = (
    GATE_ROW_UNCHANGED,
    GATE_ROWS_BOUNDED,
    GATE_DOWN_MIGRATION_TESTED,
)


DATABASE_SPECS: list[InverseSpec] = [
    InverseSpec(
        tool="db.select",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="db.noop",
        notes="A read changes nothing, though it may still expose data it should not.",
    ),
    InverseSpec(
        tool="db.update_row",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="db.update_row",
        arg_map=(
            ("table", "args.table"),
            ("key", "args.key"),
            ("values", "snapshot.prior_values"),
        ),
        snapshot_fields=("prior_values", "row_version"),
        gates=(GATE_ROWS_BOUNDED, GATE_ROW_UNCHANGED),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Restoring prior values does not undo what read the row in between: "
            "triggers fired, change-data-capture streams published, downstream caches "
            "and search indexes ingested the bad value, and any decision made on it "
            "stands."
        ),
        notes=(
            "Capture row_version (or updated_at) alongside the values so the "
            "concurrency gate has something to compare. Without it the 'undo' is a "
            "blind overwrite, which is how a recovery becomes a second incident."
        ),
    ),
    InverseSpec(
        tool="db.delete_rows",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="db.insert_rows",
        arg_map=(("table", "args.table"), ("rows", "snapshot.deleted_rows")),
        snapshot_fields=("deleted_rows",),
        gates=(GATE_ROWS_BOUNDED,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "Re-inserting restores the data but not necessarily the identity: "
            "auto-increment keys may differ, sequences have advanced, and rows that "
                "referenced the deleted ones by foreign key may have cascaded away and "
            "not be covered by this capture."
        ),
        notes=(
            "Only meaningful for a bounded delete. The authorize gate is what stops an "
            "unbounded DELETE from being classified as recoverable."
        ),
    ),
    InverseSpec(
        tool="db.execute_sql",
        kind=Reversibility.UNKNOWN,
        notes=(
            "Arbitrary SQL cannot be classified, for the same reason arbitrary shell "
            "cannot. UNKNOWN escalates to a human under the starter policy, which is "
            "the right outcome — a statement that might be a SELECT and might be a DROP "
            "should not inherit either classification."
        ),
    ),
    InverseSpec(
        tool="db.drop_table",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Point-in-time recovery may exist at the infrastructure layer, but "
            "restoring an entire database to undo one statement is a DBA decision under "
            "an incident process, not an automated inverse. Deny this to agents."
        ),
    ),
    InverseSpec(
        tool="db.truncate_table",
        kind=Reversibility.IRREVERSIBLE,
        notes=(
            "Registered separately from delete_rows because it looks similar and behaves "
            "completely differently: no per-row capture is feasible and most engines do "
            "not even log it row by row."
        ),
    ),
    # -- migrations: the one designed inverse on this surface ---------------
    InverseSpec(
        tool="db.migrate_up",
        kind=Reversibility.COMPENSABLE,
        inverse_tool="db.migrate_down",
        arg_map=(("target", "snapshot.current_version"),),
        snapshot_fields=("current_version",),
        gates=(GATE_DOWN_MIGRATION_TESTED,),
        degraded_kind=Reversibility.IRREVERSIBLE,
        residue=(
            "A down migration reverses the schema, not the data. Dropping a column the "
            "up migration added discards every value written into it, and a down step "
            "that recreates a table cannot repopulate it. Rows written under the new "
            "schema may not fit the old one at all."
        ),
        notes=(
            "The only genuinely designed inverse here, and still gated — because down "
            "migrations are routinely unwritten, untested, or destructive. Requiring "
            "them in review and running them in CI is what makes this spec true; the "
            "spec cannot make it true on its own."
        ),
    ),
    InverseSpec(
        tool="db.create_index",
        kind=Reversibility.REVERSIBLE,
        inverse_tool="db.drop_index",
        arg_map=(("table", "args.table"), ("name", "args.name")),
        notes=(
            "One of the few cleanly reversible schema operations — though on a large "
            "table both directions can lock or consume enough I/O to be an incident in "
            "themselves."
        ),
    ),
]


def database_registry() -> InverseRegistry:
    """An :class:`InverseRegistry` preloaded with the database specs (unvalidated)."""
    return InverseRegistry(list(DATABASE_SPECS))


__all__ = ["DATABASE_SPECS", "DATABASE_GATES", "database_registry"]
