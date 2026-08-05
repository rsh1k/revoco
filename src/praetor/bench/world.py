"""
praetor.bench.world
===================
A simulated set of systems of record that benchmark scenarios act on.

Why a world, rather than mocks
------------------------------
A benchmark that asserts on a *receipt* only proves the control plane thinks it
undid something. The whole failure mode this package exists to catch — a rollback
capability the organization believes it has and does not — looks identical from
the receipt's point of view. So the harness needs somewhere real for actions to
land, and a way to ask afterwards whether the state actually came back.

That is this module. It holds typed resources, records every mutation, and can be
checkpointed and diffed. Recovery is then measured by comparing state, not by
trusting the reversal engine's own account of itself.

The verb vocabulary
-------------------
Rather than hand-writing an implementation for each of the ninety-odd adapter
tools, tools are *bound* to a small set of verbs against a resource kind. Adding a
scenario for a new tool is then a two-line binding rather than a new handler,
which is what keeps the corpus cheap to extend — and a corpus that is expensive to
extend does not get extended.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from ..core import crypto

# Verbs a bound tool can perform.
VERB_CREATE = "create"
VERB_UPDATE = "update"
VERB_DELETE = "delete"      # soft: moves to the graveyard so restore can work
VERB_RESTORE = "restore"
VERB_PURGE = "purge"        # hard: gone, nothing can bring it back
VERB_READ = "read"
VERB_NOOP = "noop"
VERB_APPEND = "append"      # for message/log-like surfaces

_VERBS = {
    VERB_CREATE, VERB_UPDATE, VERB_DELETE, VERB_RESTORE,
    VERB_PURGE, VERB_READ, VERB_NOOP, VERB_APPEND,
}

# Snapshot field names that mean "the whole record as it was", rather than one
# field of it. Real specs use several such names because the payload shape is the
# upstream API's choice; the world honours them so a spec does not have to be
# rewritten to be testable.
_WHOLE_RECORD_FIELDS = frozenset({"manifest", "prior_values", "tree", "protection",
                                  "PriorRecordSets", "targeting", "fields"})


class WorldError(Exception):
    """The simulated system rejected the call, as a real one would."""


@dataclass(frozen=True)
class ToolBinding:
    """Maps one tool name onto a mutation of the world.

    ``field_args`` are the argument names whose values get written onto the
    resource. ``returns`` describes the response body, because inverse specs
    routinely resolve arguments from ``result.*`` — a binding that returned
    nothing would make every result-bound inverse untestable, which is precisely
    the class of spec most likely to be wrong.

    Templates in ``returns``: ``{id}`` the resource id, ``{seq}`` a fresh
    monotonic token, ``{field:X}`` the current value of field X, anything else is
    a literal.
    """

    tool: str
    verb: str
    kind: str = ""
    id_arg: str = ""
    field_args: tuple[str, ...] = ()
    returns: tuple[tuple[str, str], ...] = ()
    # Some tools carry the resource id in the response rather than the request
    # (a create that assigns its own key).
    generates_id: bool = False
    # snapshot-field-name -> record-field-name. Real APIs routinely name the same
    # value differently on read and write (`tip_sha` in a snapshot, `sha` on the
    # ref you create), and a spec written against those names should be testable
    # without renaming the spec to suit the simulator.
    field_aliases: tuple[tuple[str, str], ...] = ()

    @property
    def alias_map(self) -> dict[str, str]:
        return dict(self.field_aliases)

    def __post_init__(self) -> None:
        if self.verb not in _VERBS:
            raise ValueError(f"{self.tool}: unknown verb {self.verb!r}; valid: {sorted(_VERBS)}")
        if self.verb in (VERB_NOOP,):
            return
        if not self.kind:
            raise ValueError(f"{self.tool}: verb {self.verb} needs a resource kind")
        if not self.id_arg and not self.generates_id:
            raise ValueError(f"{self.tool}: verb {self.verb} needs an id_arg or generates_id")


@dataclass
class Mutation:
    """One recorded change, for the harness's audit of what really happened."""

    tool: str
    verb: str
    kind: str
    resource_id: str
    before: dict[str, Any] | None
    after: dict[str, Any] | None

    @property
    def changed(self) -> bool:
        return self.before != self.after


@dataclass
class World:
    """A tiny multi-system state store.

    ``resources[kind][id]`` holds live resources; deleted ones move to
    ``graveyard`` so a restore verb has something to bring back. A ``purge``
    removes them from both, modelling the operations that genuinely have no undo —
    and the benchmark needs those to exist, otherwise every scenario would look
    recoverable.
    """

    resources: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    graveyard: dict[str, dict[str, dict[str, Any]]] = field(default_factory=dict)
    mutations: list[Mutation] = field(default_factory=list)
    bindings: dict[str, ToolBinding] = field(default_factory=dict)
    _seq: int = 0
    # Tools the world should refuse, to simulate a system rejecting a call.
    reject: set[str] = field(default_factory=set)

    # ---- setup ------------------------------------------------------------
    def bind(self, *bindings: ToolBinding) -> World:
        for b in bindings:
            self.bindings[b.tool] = b
        return self

    def seed(self, kind: str, resource_id: str, **fields: Any) -> World:
        self.resources.setdefault(kind, {})[resource_id] = dict(fields)
        return self

    def get(self, kind: str, resource_id: str) -> dict[str, Any] | None:
        return self.resources.get(kind, {}).get(resource_id)

    def exists(self, kind: str, resource_id: str) -> bool:
        return resource_id in self.resources.get(kind, {})

    # ---- the two callables the control plane needs -------------------------
    def state_reader(
        self, tool: str, args: dict[str, Any], fields: tuple[str, ...]
    ) -> dict[str, Any]:
        """Read prior state. Wired into ControlPlane(state_reader=...).

        Returns only the requested fields, and returns them partially rather than
        raising when absent — the same degradation a real reader should exhibit,
        so scenarios exercise the snapshot-gap path rather than a happy fiction.
        """
        binding = self.bindings.get(tool)
        if binding is None or not binding.kind:
            return {}
        rid = args.get(binding.id_arg, "")
        current = self.get(binding.kind, rid) or {}
        out: dict[str, Any] = {}
        aliases = binding.alias_map
        for f in fields:
            source = aliases.get(f, f)
            if source in current:
                out[f] = copy.deepcopy(current[source])
            elif f in _WHOLE_RECORD_FIELDS:
                # Some specs capture "the record as it was" under a single name
                # rather than field by field. Synthesising it here is what lets a
                # generic world serve specs written against real APIs, where the
                # payload shape is the API's choice and not ours.
                out[f] = (
                    {"kind": binding.kind, "id": rid, "spec": copy.deepcopy(current)}
                    if f == "manifest"
                    else copy.deepcopy(current)
                )
            elif f == "existed":
                out[f] = self.exists(binding.kind, rid)
        return out

    def executor(self, tool: str, args: dict[str, Any]) -> Any:
        """Execute a call. Wired in as both the forward and the inverse executor.

        Using one executor for both directions is deliberate: it means an inverse
        cannot succeed by touching some parallel universe the forward action never
        wrote to, which would make every recovery look perfect.
        """
        if tool in self.reject:
            raise WorldError(f"{tool} rejected by the simulated system")
        binding = self.bindings.get(tool)
        if binding is None:
            raise WorldError(f"no binding for tool {tool!r}; the scenario must bind it")

        if binding.verb in (VERB_NOOP, VERB_READ):
            rid = args.get(binding.id_arg, "") if binding.id_arg else ""
            current = self.get(binding.kind, rid) if binding.kind else None
            return copy.deepcopy(current) if current is not None else None

        self._seq += 1
        rid = self._resolve_id(binding, args)
        bucket = self.resources.setdefault(binding.kind, {})
        grave = self.graveyard.setdefault(binding.kind, {})
        before = copy.deepcopy(bucket.get(rid))

        if binding.verb in (VERB_CREATE, VERB_UPDATE, VERB_APPEND):
            record = dict(bucket.get(rid) or {})
            for name in binding.field_args:
                if name in args:
                    record[name] = copy.deepcopy(args[name])
            # A manifest-shaped restore carries the whole record inside it.
            if "manifest" in args and isinstance(args["manifest"], dict):
                record.update(copy.deepcopy(args["manifest"].get("spec", {})))
            bucket[rid] = record
        elif binding.verb == VERB_DELETE:
            if rid in bucket:
                grave[rid] = bucket.pop(rid)
        elif binding.verb == VERB_RESTORE:
            if rid in grave:
                bucket[rid] = grave.pop(rid)
            elif rid not in bucket:
                raise WorldError(f"{tool}: nothing to restore for {binding.kind}/{rid}")
        elif binding.verb == VERB_PURGE:
            bucket.pop(rid, None)
            grave.pop(rid, None)

        after = copy.deepcopy(bucket.get(rid))
        self.mutations.append(
            Mutation(tool=tool, verb=binding.verb, kind=binding.kind,
                     resource_id=rid, before=before, after=after)
        )
        return self._build_response(binding, rid, after)

    def _resolve_id(self, binding: ToolBinding, args: dict[str, Any]) -> str:
        if binding.id_arg and binding.id_arg in args:
            return str(args[binding.id_arg])
        if binding.generates_id:
            return f"{binding.kind}-{self._seq}"
        # A create whose id argument is missing still needs somewhere to land;
        # failing loudly here beats silently writing to an empty key.
        raise WorldError(
            f"{binding.tool}: argument {binding.id_arg!r} missing and no id generation"
        )

    def _build_response(
        self, binding: ToolBinding, rid: str, record: dict[str, Any] | None
    ) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, template in binding.returns:
            if template == "{id}":
                out[key] = rid
            elif template == "{seq}":
                out[key] = f"{key}-{self._seq:04d}"
            elif template.startswith("{field:") and template.endswith("}"):
                out[key] = (record or {}).get(template[len("{field:") : -1])
            else:
                out[key] = template
        return out

    # ---- comparison -------------------------------------------------------
    def snapshot(self) -> dict[str, Any]:
        """A deep copy of live state, for later comparison."""
        return copy.deepcopy(self.resources)

    def digest(self) -> str:
        return crypto.digest_of(self.resources)

    def diff(self, baseline: dict[str, Any]) -> dict[str, Any]:
        """Field-level differences between ``baseline`` and current live state.

        Reported as added / removed / changed so a partial recovery can be
        described precisely instead of as a boolean. "Restored the bank account
        but left the payment posted" is actionable; "not fully recovered" is not.
        """
        added: list[str] = []
        removed: list[str] = []
        changed: list[dict[str, Any]] = []

        kinds = set(baseline) | set(self.resources)
        for kind in sorted(kinds):
            base_k = baseline.get(kind, {})
            live_k = self.resources.get(kind, {})
            for rid in sorted(set(base_k) | set(live_k)):
                if rid not in base_k:
                    added.append(f"{kind}/{rid}")
                    continue
                if rid not in live_k:
                    removed.append(f"{kind}/{rid}")
                    continue
                b, live = base_k[rid], live_k[rid]
                for f in sorted(set(b) | set(live)):
                    if b.get(f) != live.get(f):
                        changed.append(
                            {"resource": f"{kind}/{rid}", "field": f,
                             "expected": b.get(f), "actual": live.get(f)}
                        )
        return {"added": added, "removed": removed, "changed": changed}

    def matches(self, baseline: dict[str, Any]) -> bool:
        d = self.diff(baseline)
        return not (d["added"] or d["removed"] or d["changed"])

    def check_state(self, expected: dict[str, dict[str, dict[str, Any]]]) -> list[str]:
        """Assert specific field values, returning a failure per mismatch.

        Used for the fields a scenario says *must* be back after recovery. A
        compensable undo is not expected to restore everything — an SAP reversal
        leaves two documents by design — so demanding a whole-world match would
        mark correct behaviour as failure. This checks what actually matters and
        reports the rest as residue.
        """
        failures: list[str] = []
        for kind, records in expected.items():
            for rid, fields in records.items():
                live = self.get(kind, rid)
                if live is None:
                    failures.append(f"{kind}/{rid} is absent")
                    continue
                for f, want in fields.items():
                    if live.get(f) != want:
                        failures.append(
                            f"{kind}/{rid}.{f} is {live.get(f)!r}, expected {want!r}"
                        )
        return failures


__all__ = [
    "World",
    "ToolBinding",
    "Mutation",
    "WorldError",
    "VERB_CREATE",
    "VERB_UPDATE",
    "VERB_DELETE",
    "VERB_RESTORE",
    "VERB_PURGE",
    "VERB_READ",
    "VERB_NOOP",
    "VERB_APPEND",
]
