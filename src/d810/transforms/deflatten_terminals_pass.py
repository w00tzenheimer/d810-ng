"""DeflattenTerminalsPass — the first LiSA/LLVM-shaped de-flatten transform.

Composes the two de-flatten primitives (:func:`plan_tail_duplicate`,
:func:`plan_dead_store_eliminate`) into one plan that turns a flattened terminal region
(N terminals fanning into one shared guard, with dead ``state = K`` staging writes) into the
``ref_cascade`` shape Hex-Rays preserves as distinct returns.

It also makes the LLVM pass *contract* explicit, which is the part our current pass API
(``passes/unflatten/state_machine.py``) cannot express:

* ``requires`` — the analyses consumed (``BlockOwnership`` provides the convergence /
  ``shared_suffix_blocks``; ``StateTransitions`` provides the terminals + staging sites).
* ``invalidates`` vs ``preserves`` — tail-dup rewrites the CFG, so block-keyed analyses are
  invalidated, **but the state-value lattice is unchanged** and preserved. Today
  ``PreservedAnalyses.all()/none()`` is all/none; this field is the missing granularity.
* ``run_before_structuring`` — the lab proved Hex-Rays pre-structures the flattened shape by
  GLBOPT1 (``map_rows=0``), so this pass MUST run at LOCOPT. The current pass API has no
  maturity-timing contract; this field surfaces it.

Pure ``facts -> plan`` (no IDA). Deriving :class:`DeflattenTerminalsFacts` from the live
analysis results — in particular the staging-site ``insn_ea`` (which the portable
``StateWriteAnchor`` fact does not yet carry) — is the next rung.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Callable, Iterable, Mapping

from d810.transforms.deflatten_primitives import (
    plan_dead_store_eliminate,
    plan_tail_duplicate,
)

__all__ = [
    "DeflattenTerminalsFacts",
    "DeflattenPlan",
    "plan_deflatten_terminals",
    "deflatten_facts_from_analyses",
]

_Succ = Callable[[int], Iterable[int]]


@dataclass(frozen=True, slots=True)
class DeflattenTerminalsFacts:
    """The facts the pass consumes, derived from BlockOwnership + StateTransitions.

    Attributes:
        terminals: Blocks routing into the shared convergence; each gets a private return.
        convergence_block: The shared guard / fan-in block to tail-duplicate.
        return_target: The STOP/return block the per-terminal clones wire to.
        staging_sites: ``(block_serial, insn_ea)`` of each dead state-variable store.
    """

    terminals: tuple[int, ...]
    convergence_block: int
    return_target: int
    staging_sites: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class DeflattenPlan:
    """A de-flatten plan plus its explicit LLVM pass contract."""

    modifications: tuple[object, ...]
    requires: frozenset[str] = field(default_factory=frozenset)
    invalidates: frozenset[str] = field(default_factory=frozenset)
    preserves: frozenset[str] = field(default_factory=frozenset)
    run_before_structuring: bool = True


def plan_deflatten_terminals(facts: DeflattenTerminalsFacts) -> DeflattenPlan:
    """Compose tail-duplication (de-converge) + dead-store-elimination (de-stage).

    One :class:`DuplicateBlock` per terminal gives each its own guard->return path (breaking
    the fan-in Hex-Rays turns into a loop nest); one per-block NOP op strips the staging
    writes Hex-Rays otherwise reads as loop induction.
    """
    modifications: list[object] = list(
        plan_tail_duplicate(
            convergence_block=facts.convergence_block,
            predecessors=facts.terminals,
            return_target=facts.return_target,
        )
    )
    modifications.extend(plan_dead_store_eliminate(facts.staging_sites))
    return DeflattenPlan(
        modifications=tuple(modifications),
        requires=frozenset({"BlockOwnership", "StateTransitions"}),
        # Tail-dup rewrites the CFG -> block-keyed analyses die; the value lattice survives.
        invalidates=frozenset({"BlockOwnership", "StateTransitions", "DispatcherMap"}),
        preserves=frozenset({"StateValueDomain"}),
        run_before_structuring=True,
    )


def deflatten_facts_from_analyses(
    *,
    owners: Mapping[int, frozenset[int]],
    successors_of: _Succ,
    predecessors_of: _Succ,
    return_block: int,
    staging_sites: Iterable[tuple[int, int]] = (),
) -> "DeflattenTerminalsFacts | None":
    """Derive the de-flatten facts by composing BlockOwnership + flow-graph topology.

    The convergence is a *shared* block (``len(owners[b]) > 1`` -- the owner-set's
    ``shared_suffix``, owned by more than one handler region) that is a direct predecessor of
    the return; the terminals are that block's predecessors (each gets a private guard->return
    clone). ``owners`` is ``block_owners(owner_result)`` from
    :mod:`d810.analyses.control_flow.block_ownership_domain`.

    Returns ``None`` when no shared fan-in precedes the return (nothing to de-converge).

    **Deficiency #5 (analysis-API gap):** the staging-site ``insn_ea`` is *not* derivable from
    the portable owner-set / transition facts -- ``StateWriteAnchor`` carries the block and the
    written constant but not the instruction EA -- so it is injected here by the live caller.
    Closing this means enriching the state-write fact with its ``insn_ea``.
    """
    return_block = int(return_block)
    shared = {int(b) for b, owner_set in owners.items() if len(owner_set) > 1}
    candidates = sorted(
        b for b in shared if return_block in {int(s) for s in successors_of(b)}
    )
    if not candidates:
        return None
    convergence_block = candidates[0]
    terminals = tuple(sorted(int(p) for p in predecessors_of(convergence_block)))
    return DeflattenTerminalsFacts(
        terminals=terminals,
        convergence_block=convergence_block,
        return_target=return_block,
        staging_sites=tuple((int(b), int(ea)) for b, ea in staging_sites),
    )
