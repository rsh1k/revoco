"""On-chain actions, where reversibility is a function of time rather than a label.

Everything else in recoup classifies an action as reversible or not. On a
blockchain that is the wrong shape, because the answer changes by the second.
A transaction is fully reversible while it is still a draft, cheaply cancellable
while it sits in the mempool, probabilistically settled after a confirmation or
two, and absolutely final after that. The same transaction occupies all four
states within about fifteen minutes.

That makes on-chain work the clearest possible demonstration of the idea this
product is built on, and the most dangerous place for an agent to operate. The
research is direct about it: agentic payment volume is real — x402 alone has
processed over 150 million transactions — and the recommendation is to insert a
layer between decision and finality, with the agent proposing and a
*deterministic* layer performing the checks and executing.

That layer is what recoup already is. This module gives it the vocabulary for
chains.

What this is not
----------------
Not chain analytics. Attributing addresses to real-world entities is a data
business built on exchange relationships and clustering heuristics accumulated
over years, and Chainalysis, TRM and Elliptic own it. Pretending a few hundred
lines here competes would be dishonest and useless.

What is defensible is the half nobody else sits in: the moment *before*
broadcast, when the transaction is still a proposal and stopping it costs
nothing. After broadcast this module's job is to record an anchor precise enough
that a real tracing tool has a verifiable place to start.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .bundle import Verdict


@dataclass(frozen=True)
class Chain:
    """How a chain settles, and how long that takes.

    `finality_confirmations` is where reorganisation stops being a practical
    concern, not where it becomes mathematically impossible. Bitcoin's six is a
    convention rather than a theorem; Ethereum's two-epoch finality genuinely is
    a protocol guarantee. The distinction is recorded in `absolute` because a
    control that treats a convention as a proof is making a claim it cannot
    support.
    """

    name: str
    block_seconds: float
    finality_confirmations: int
    absolute: bool          # protocol-guaranteed finality, or convention?
    replaceable: bool       # can a pending transaction be replaced or cancelled?
    note: str = ""


# Deliberately few, and only ones whose settlement behaviour is well documented.
# A wrong number here produces a confidently wrong holdback window, which is
# worse than refusing to guess.
CHAINS: dict[str, Chain] = {
    "bitcoin": Chain("bitcoin", 600.0, 6, False, True,
                     "six confirmations is convention; RBF allows replacement while pending"),
    "ethereum": Chain("ethereum", 12.0, 64, True, True,
                      "finality after two epochs is a protocol guarantee; "
                      "pending transactions are replaceable by nonce"),
    "solana": Chain("solana", 0.4, 32, True, False,
                    "carries most agentic payment volume; no replacement mechanism, "
                    "so the only cancellation point is before signing"),
    "base": Chain("base", 2.0, 64, False, True,
                  "an L2: soft-confirmed quickly, but inherits L1 finality, "
                  "and a forced withdrawal window applies"),
    "polygon": Chain("polygon", 2.0, 128, False, True, ""),
}

# The four states an on-chain action passes through, most recoverable first.
DRAFT = "draft"            # not signed or broadcast: stopping costs nothing
PENDING = "pending"        # in the mempool: replaceable on some chains
CONFIRMING = "confirming"  # in a block, below finality depth: probabilistic
FINAL = "final"            # settled; no mechanism exists to take it back


@dataclass
class OnChainAction:
    chain: str
    confirmations: int = -1     # -1 means not broadcast
    signed: bool = False
    value: float = 0.0
    asset: str = ""
    to_address: str = ""
    tx_hash: str = ""

    @property
    def state(self) -> str:
        if self.confirmations < 0:
            return DRAFT if not self.signed else PENDING
        if self.confirmations == 0:
            return PENDING
        chain = CHAINS.get(self.chain)
        depth = chain.finality_confirmations if chain else 64
        return CONFIRMING if self.confirmations < depth else FINAL


def reversibility(action: OnChainAction) -> str:
    """Map an on-chain state onto recoup's four postures.

    The mapping is deliberately pessimistic in one place. A pending transaction
    on a chain with no replacement mechanism is reported `irreversible`, not
    `compensable`, because there is genuinely nothing to be done once it is
    broadcast — and Solana, which has no replacement mechanism, carries most of
    the agentic payment volume. Reporting it as compensable would name a remedy
    that does not exist, which is the phantom rollback failure in a new costume.
    """
    chain = CHAINS.get(action.chain)
    state = action.state
    if state == DRAFT:
        return "reversible"
    if state == PENDING:
        return "compensable" if (chain and chain.replaceable) else "irreversible"
    if state == CONFIRMING:
        # A reorg could still drop it, but nobody can *cause* that, so it is not
        # a remedy. Compensation here means a return transaction, which needs
        # the counterparty's cooperation.
        return "compensable"
    return "irreversible"


def time_to_irreversibility(action: OnChainAction) -> float | None:
    """Seconds until nothing can be done about this, or None if that has passed.

    This is MTTI made literal. Elsewhere it is an estimate; here it is the
    protocol's own schedule, which makes on-chain work the best demonstration of
    the measure and the strongest argument for a holdback window.
    """
    chain = CHAINS.get(action.chain)
    if chain is None:
        return None
    state = action.state
    if state == FINAL:
        return None
    if state in (DRAFT, PENDING):
        return chain.block_seconds * chain.finality_confirmations
    remaining = chain.finality_confirmations - action.confirmations
    return max(0.0, chain.block_seconds * remaining)


@dataclass
class Holdback:
    """A decision to delay broadcast so a human still has somewhere to stand.

    The research recommendation is a holdback window on payments above a
    threshold, and a challenge period during which a second party can veto. It
    only works before broadcast: once a transaction is in the mempool on a chain
    without replacement, a holdback is theatre.
    """

    hold: bool
    seconds: float
    reason: str
    can_still_stop: bool


def holdback_for(action: OnChainAction, *, threshold: float,
                 window_seconds: float = 300.0) -> Holdback:
    """Decide whether to hold a transaction back before it is broadcast."""
    state = action.state
    if state != DRAFT:
        return Holdback(
            hold=False, seconds=0.0,
            reason=f"already {state}; a holdback after broadcast changes nothing",
            can_still_stop=reversibility(action) != "irreversible")

    if action.value < threshold:
        return Holdback(False, 0.0,
                        f"{action.value:,.2f} {action.asset} is below the "
                        f"{threshold:,.2f} threshold", True)

    return Holdback(
        hold=True, seconds=window_seconds,
        reason=(f"{action.value:,.2f} {action.asset} is at or above the "
                f"{threshold:,.2f} threshold, and after broadcast on "
                f"{action.chain} there is no mechanism to recall it"),
        can_still_stop=True)


def anchor(action: OnChainAction, verdict: Verdict | None = None) -> dict[str, Any]:
    """The record a forensic trace can start from.

    Deliberately narrow. It captures what recoup uniquely knows — that this
    specific agent, under this specific policy, was authorised to move this
    value to this address at this moment — and stops there. Attribution of the
    destination is somebody else's job and this hands off to them cleanly rather
    than guessing.

    The value of the anchor is that it is in the Merkle log, so the starting
    point of the trace is provable rather than asserted.
    """
    out: dict[str, Any] = {
        "kind": "onchain",
        "chain": action.chain,
        "state": action.state,
        "reversibility": reversibility(action),
        "seconds_to_final": time_to_irreversibility(action),
        "asset": action.asset,
        "value": action.value,
        "to_address": action.to_address,
        "tx_hash": action.tx_hash,
    }
    if verdict is not None:
        out["rule_id"] = verdict.rule_id
        out["effect"] = verdict.effect
        out["allowed"] = verdict.allowed
    chain = CHAINS.get(action.chain)
    if chain is not None and not chain.absolute:
        out["finality_note"] = (
            f"{chain.finality_confirmations} confirmations on {chain.name} is "
            f"convention rather than a protocol guarantee")
    return out


def describe(action: OnChainAction) -> str:
    """One line a person can act on."""
    rev = reversibility(action)
    ttl = time_to_irreversibility(action)
    when = "already final" if ttl is None else f"{ttl:,.0f}s to final"
    return (f"{action.chain} {action.state}: {rev}, {when}"
            f"{f' — {action.value:,.2f} {action.asset}' if action.value else ''}")
