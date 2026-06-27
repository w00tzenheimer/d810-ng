"""Exit-transition discovery helpers for late handler/condition-chain recovery.

d81-qlal -- canonical port.  This portable analysis no longer reads
backend-shaped operand slots and is typed against portable models / Protocols:

* the state-variable operand it inspects is the portable
  :class:`~d810.ir.flowgraph.MopSnapshot`; its ``stkoff`` is read off the
  canonical :class:`~d810.ir.varnode.Varnode` storage view (with the portable
  ``MopSnapshot.stkoff`` field and the condition-chain provider as exact
  behaviour-identity fallbacks);
* the condition-chain target-resolution evidence is the portable
  :class:`~d810.analyses.control_flow.condition_chain_model.ConditionChainAnalysisResult`;
* the live-backend bundle (``snapshot.mba`` / ``snapshot.detector``) is
  *genuinely* polymorphic -- those are live IDA / detector handles with no
  portable type -- so the :class:`_ExitTransitionSnapshot` Protocol declares
  them ``object | None``; the state-machine view (:class:`_StateMachineLike`)
  and the backend valrange resolver (a ``Callable``) are typed against their
  real portable shapes.

Block topology stays direct on the typed
:class:`~d810.ir.flowgraph.FlowGraph` / :class:`~d810.ir.flowgraph.BlockSnapshot`.
"""

from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.condition_chain_model import (
    ConditionChainAnalysisResult,
    resolve_target_via_condition_chain,
)
from d810.analyses.control_flow.state_machine_analysis import evaluate_handler_paths
from d810.analyses.control_flow.transition_builder import _get_state_var_stkoff
from d810.capabilities.providers import get_condition_chain_walkers
from d810.core.typing import Callable, Mapping, Protocol, Sequence
from d810.ir.flowgraph import FlowGraph, MopSnapshot
from d810.ir.varnode import Space, Varnode, varnode_from_mop_snapshot


class _TransitionLike(Protocol):
    """Portable view of a recovered state transition (see ``StateTransition``)."""

    from_state: int | None
    to_state: int
    from_block: int


class _StateHandlerLike(Protocol):
    """Portable view of a state handler (see ``StateHandler``)."""

    transitions: Sequence[_TransitionLike]


class _StateMachineLike(Protocol):
    """Portable view of the recovered dispatcher state machine.

    ``state_var`` is the portable operand snapshot the analysis inspects;
    ``handlers`` maps a state value to its handler.  These are Protocol fields,
    not operand slots, so reading them is allowed under the migrated-module
    guard.
    """

    state_var: MopSnapshot | None
    handlers: Mapping[int, _StateHandlerLike]


class _ExitTransitionSnapshot(Protocol):
    """Producer-supplied bundle for condition-chain-default discovery.

    ``mba`` and ``detector`` are live IDA / detector handles with no portable
    type -- they stay ``object | None`` (a live handle is genuinely
    polymorphic, not a typing gap).
    """

    mba: object | None
    detector: object | None


@dataclass(frozen=True, slots=True)
class ExitTransitionCandidate:
    """One discovered redirect candidate from an exit-state family."""

    state_value: int
    from_block: int
    target_entry: int
    exit_state_value: int | None
    discovery_kind: str


@dataclass(frozen=True, slots=True)
class ConditionChainDefaultTransitionCandidate:
    """One discovered redirect candidate from condition-chain-default path evaluation."""

    handler_state: int
    handler_entry: int
    from_block: int
    target_entry: int
    final_state: int


@dataclass(frozen=True, slots=True)
class ValrangeExitTransitionCandidate:
    """One unresolved exit recovered via evaluator valranges."""

    from_state: int
    to_state: int
    from_block: int
    target_entry: int
    resolved_state_value: int


@dataclass(frozen=True, slots=True)
class ValrangeExitTransitionDiscovery:
    """Batch result for valrange-based unresolved exit recovery."""

    total_unresolved: int = 0
    candidates: tuple[ValrangeExitTransitionCandidate, ...] = ()


def resolve_state_var_stkoff(
    *,
    detector: object | None,
    state_var: MopSnapshot | None,
) -> int | None:
    """Resolve the state-variable stack offset from detector or state var.

    ``detector`` is a live backend detector handle (genuinely polymorphic, kept
    ``object | None``); ``state_var`` is the portable operand snapshot whose
    stack offset is read via :func:`_stack_offset`.
    """
    stkoff: int | None = None
    if detector is not None:
        try:
            stkoff = _get_state_var_stkoff(detector)
        except Exception:
            pass
    if stkoff is None and state_var is not None:
        try:
            stkoff = _stack_offset(state_var)
        except Exception:
            pass
    return stkoff


def _varnode(mop: MopSnapshot | None) -> Varnode | None:
    if mop is None:
        return None
    try:
        return varnode_from_mop_snapshot(mop)
    except (AttributeError, TypeError, ValueError):
        return None


def _stack_offset(mop: MopSnapshot | None) -> int | None:
    """Stack offset a portable operand snapshot names, else ``None``.

    Reads the canonical :class:`~d810.ir.varnode.Varnode` storage view first; a
    stack operand projects to ``Varnode(Space.STACK, offset, size)``.  Falls
    back to the portable ``MopSnapshot.stkoff`` field and then the
    condition-chain provider, preserving the original triple-fallback exactly.
    """
    varnode = _varnode(mop)
    if varnode is not None and varnode.space is Space.STACK:
        return int(varnode.offset)
    # Read ``stkoff`` directly only when ``mop`` is a portable ``MopSnapshot``;
    # backend/rich operand shapes (which carry no portable ``stkoff`` field) fall
    # through to the condition-chain provider below, which resolves them via
    # ``s.off`` -- exactly as the prior defensive ``getattr`` fallback did.
    stkoff = mop.stkoff if isinstance(mop, MopSnapshot) else None
    if stkoff is not None:
        return int(stkoff)
    try:
        operand_stack_offset = get_condition_chain_walkers().operand_stack_offset
    except LookupError:
        operand_stack_offset = None
    if operand_stack_offset is None or mop is None:
        return None
    try:
        provider_stkoff = operand_stack_offset(mop)
    except Exception:
        provider_stkoff = None
    return int(provider_stkoff) if provider_stkoff is not None else None


def collect_condition_chain_default_transition_candidates(
    snapshot: _ExitTransitionSnapshot,
    *,
    sm: _StateMachineLike,
    range_evidence: ConditionChainAnalysisResult,
    handler_state_map: dict[int, int],
    condition_chain_blocks: set[int],
) -> tuple[ConditionChainDefaultTransitionCandidate, ...]:
    """Collect raw condition-chain-default transition candidates via handler-path eval."""
    mba = snapshot.mba
    if mba is None:
        return ()

    stkoff = resolve_state_var_stkoff(
        detector=snapshot.detector,
        state_var=sm.state_var,
    )
    if stkoff is None:
        return ()

    handler_entry_blocks: set[int] = set(handler_state_map.values())
    candidates: list[ConditionChainDefaultTransitionCandidate] = []
    for handler_state, handler_entry in handler_state_map.items():
        paths = evaluate_handler_paths(
            mba=mba,
            entry_serial=handler_entry,
            incoming_state=handler_state,
            condition_chain_blocks=condition_chain_blocks,
            state_var_stkoff=stkoff,
            handler_entry_blocks=handler_entry_blocks,
        )

        for path_result in paths:
            if path_result.final_state is None:
                continue

            final_state = path_result.final_state & 0xFFFFFFFF
            from_block = path_result.exit_block
            target_entry = resolve_target_via_condition_chain(range_evidence, final_state)
            if target_entry is None or from_block == target_entry:
                continue
            candidates.append(
                ConditionChainDefaultTransitionCandidate(
                    handler_state=handler_state,
                    handler_entry=handler_entry,
                    from_block=from_block,
                    target_entry=int(target_entry),
                    final_state=final_state,
                )
            )

    return tuple(candidates)


def collect_valrange_exit_transition_candidates(
    flow_graph: FlowGraph,
    *,
    sm: _StateMachineLike,
    range_evidence: ConditionChainAnalysisResult,
    resolve_state_via_valranges: Callable[[int, MopSnapshot | None], int | None] | None,
    resolved_transitions: object = (),
) -> ValrangeExitTransitionDiscovery:
    """Collect unresolved handler exits that valranges resolves to one target.

    Block identity/topology comes from the portable ``flow_graph``: this layer
    only confirms the exit block exists and is non-empty.  The actual IDA
    value-range query is performed by the injected ``resolve_state_via_valranges``
    callable, which the backend wires to the live ``mba`` so it can re-resolve
    the live block/tail from the (portable) block serial (ticket llr-f1cs F5b).

    Args:
        flow_graph: Portable CFG snapshot for exit-block identity.
        sm: State-machine model (handlers + state_var).
        range_evidence: Condition-chain target-resolution evidence.
        resolve_state_via_valranges: Backend callable
            ``(exit_serial: int, state_var) -> int | None`` that performs the
            live IDA valrange query for the state variable at the exit block.
        resolved_transitions: Already-resolved ``(from_state, to_state)`` pairs
            to skip (sourced from the snapshot by the caller).
    """
    if flow_graph is None or not callable(resolve_state_via_valranges):
        return ValrangeExitTransitionDiscovery()

    state_var = sm.state_var
    handlers = dict(sm.handlers or {})
    if state_var is None or not handlers:
        return ValrangeExitTransitionDiscovery()

    already_resolved = set(resolved_transitions or ())
    candidates: list[ValrangeExitTransitionCandidate] = []
    total_unresolved = 0

    for handler in handlers.values():
        for transition in tuple(handler.transitions):
            key = (int(transition.from_state), int(transition.to_state))
            if key in already_resolved:
                continue

            total_unresolved += 1
            exit_serial = int(transition.from_block)
            exit_blk = flow_graph.get_block(exit_serial)
            if exit_blk is None:
                continue

            # Non-empty gate: the live backend resolver anchors its valrange
            # query at the block tail, so an empty block cannot be resolved.
            if exit_blk.tail is None:
                continue

            resolved_value = resolve_state_via_valranges(exit_serial, state_var)
            if resolved_value is None:
                continue

            target_entry = resolve_target_via_condition_chain(range_evidence, resolved_value)
            if target_entry is None:
                continue

            candidates.append(
                ValrangeExitTransitionCandidate(
                    from_state=int(transition.from_state),
                    to_state=int(transition.to_state),
                    from_block=exit_serial,
                    target_entry=int(target_entry),
                    resolved_state_value=int(resolved_value),
                )
            )

    return ValrangeExitTransitionDiscovery(
        total_unresolved=total_unresolved,
        candidates=tuple(candidates),
    )


__all__ = [
    "ConditionChainDefaultTransitionCandidate",
    "ExitTransitionCandidate",
    "ValrangeExitTransitionCandidate",
    "ValrangeExitTransitionDiscovery",
    "collect_condition_chain_default_transition_candidates",
    "collect_valrange_exit_transition_candidates",
    "resolve_state_var_stkoff",
]
