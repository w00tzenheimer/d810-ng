"""Sound forward value-set fixpoint over the dispatcher state variable.

This module realizes the north-star ``#2 RecoverStateTransitions`` as a genuine
LiSA-shaped abstract domain (CENTRAL §11.3-11.4, ticket ``llr-mmfq``), replacing
the ad-hoc ``_walk_handler_chain`` recursion in
``backends/hexrays/evidence/bst_analysis.py``.

The walk is structural: at any ``nsucc > 1`` handler block it sub-walks each arm
and declares a ``conditional_states`` set whenever the arms reach the dispatcher
back-edge with different state writes.  That over-generates -- it counts branches
on non-state conditions, double-counts shared multi-predecessor blocks, and
cannot prune paths infeasible for the incoming state value (the diag DAG's 82 vs
oracle-66 ``CONDITIONAL_TRANSITION`` inflation, which makes the §1a bridge
over-claim the return anchors and pins ``returns`` at 1).

A sound forward value-set fixpoint over the state variable ``s`` eliminates the
unsoundness: a handler yields a *conditional* transition only when its feasible
exit value-set genuinely holds more than one constant.

The lattice (:class:`StateValue`) is the literal LiSA ``NonRedundantPowerset`` /
``ConstantValue`` spec -- a finite powerset of state constants with an explicit
``⊤`` (unknown / MBA-obfuscated write) and ``⊥`` (unreachable).  The fixpoint
runs on the portable :func:`d810.analyses.data_flow.run_fixpoint` engine, so the
domain stays portable-core (no IDA import): per-block state-write evidence and
topology cross the boundary as plain data, exactly like the
``ReachingDefinitionsDomain`` worked example in ``test_worklist_solver.py``.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.core.typing import Callable, ClassVar, Iterable, Mapping

from d810.analyses.control_flow.transition_builder import (
    StateHandler,
    StateTransition,
    TransitionResult,
)
from d810.analyses.data_flow import (
    FixpointConfiguration,
    FixpointResult,
    run_fixpoint,
)
from d810.analyses.data_flow.abstract_value import TOP, AbstractValue, Const, OneOf
from d810.analyses.data_flow.concolic import (
    ConcolicTransitionDomain,
    LocationRef,
    PartitionedState,
)
from d810.analyses.data_flow.domain import NodeId

__all__ = [
    "StateValue",
    "StateTransitionDomain",
    "build_state_writes_with_dispatch_assume",
    "recover_transition_result",
    "analyze_state_transitions",
    "analyze_state_transitions_concolic",
    "state_value_fixpoint_result",
]

_Succ = Callable[[NodeId], Iterable[NodeId]]

_U64_MASK = 0xFFFFFFFFFFFFFFFF


@dataclass(frozen=True, slots=True)
class StateValue:
    """Abstract value of the state variable: a powerset of constants, plus ⊤/⊥.

    The forward "may" value-set the dispatcher state variable can hold at a
    program point.  Three shapes:

    * ``⊥`` (bottom) -- ``constants`` empty, ``is_top`` False: the point is
      unreachable / carries no information yet (the fixpoint's initial state).
    * ``{k1, k2, ...}`` -- a non-empty finite set of state constants the
      variable may equal.
    * ``⊤`` (top) -- ``is_top`` True: the variable's value is unknown (an
      MBA-obfuscated / unresolved write, or the set grew past
      :attr:`MAX_CONSTS`).  ``⊤`` is *where leaked constants come from*, made
      explicit rather than silently dropped.

    Frozen + hashable so it can key the fixpoint's in/out state maps.  Equality
    is structural (two singletons of the same constant compare equal).
    """

    constants: frozenset[int] = field(default_factory=frozenset)
    is_top: bool = False

    #: Safety valve: a value-set this large is treated as genuine unboundedness
    #: (``⊤``), keeping the lattice finite-height.  Set comfortably above any
    #: realistic handler count (sub_7FFD has ~45-66 states).
    MAX_CONSTS: ClassVar[int] = 256

    @classmethod
    def bottom(cls) -> "StateValue":
        """The least element ``⊥`` -- unreachable / no information."""
        return cls(frozenset(), False)

    @classmethod
    def top(cls) -> "StateValue":
        """The greatest element ``⊤`` -- the value is unknown."""
        return cls(frozenset(), True)

    @classmethod
    def of(cls, value: int) -> "StateValue":
        """A singleton value-set ``{value}`` (a resolved state constant)."""
        return cls(frozenset({int(value) & _U64_MASK}), False)

    @classmethod
    def of_many(cls, values: Iterable[int]) -> "StateValue":
        """A value-set from an iterable of constants (``⊥`` when empty)."""
        consts = frozenset(int(v) & _U64_MASK for v in values)
        if len(consts) > cls.MAX_CONSTS:
            return cls.top()
        return cls(consts, False)

    @property
    def is_bottom(self) -> bool:
        """True when this is ``⊥`` (no constants and not ``⊤``)."""
        return not self.is_top and not self.constants

    def single(self) -> int | None:
        """The sole constant when this is a singleton set, else ``None``."""
        if self.is_top or len(self.constants) != 1:
            return None
        return next(iter(self.constants))

    #: Byte size stamped on the :class:`Const` ``project`` yields.  State
    #: constants are masked to u64, so 8 is the sound width (callers that know a
    #: narrower width can re-stamp; the router only reads ``.value``).
    _PROJECT_CONST_SIZE: ClassVar[int] = 8

    def project(self) -> AbstractValue:
        """Project this powerset into the router value-side :class:`AbstractValue`.

        Unifies with :meth:`d810.analyses.data_flow.abstract_value.OneOf.from_state_value`
        (the inverse lift).  ``⊤`` → :data:`TOP`; a singleton → :class:`Const`
        (size :data:`_PROJECT_CONST_SIZE`); a finite set → :class:`OneOf`; ``⊥``
        (empty, not ⊤) → an empty :class:`OneOf`.
        """
        if self.is_top:
            return TOP
        only = self.single()
        if only is not None:
            return Const(only, self._PROJECT_CONST_SIZE)
        return OneOf(frozenset(self.constants))

    def join(self, other: "StateValue") -> "StateValue":
        """Least upper bound -- set union, saturating to ``⊤``.

        ``⊤`` is absorbing and ``⊥`` is the identity.  A union exceeding
        :attr:`MAX_CONSTS` saturates to ``⊤`` (the finite-height safety valve).
        """
        if self.is_top or other.is_top:
            return StateValue.top()
        merged = self.constants | other.constants
        if len(merged) > self.MAX_CONSTS:
            return StateValue.top()
        return StateValue(merged, False)

    def leq(self, other: "StateValue") -> bool:
        """The lattice order ``⊑``: ``⊥`` below all, all below ``⊤``, else ``⊆``."""
        if self.is_bottom:
            return True
        if other.is_top:
            return True
        if self.is_top:
            return False
        return self.constants <= other.constants

    def meet(self, other: "StateValue") -> "StateValue":
        """Greatest lower bound ⊓ -- set intersection (the lattice glb).

        ``⊤`` is the identity (``⊤ ⊓ x = x``) and ``⊥`` is absorbing.  Two
        concrete sets meet to their intersection; *disjoint* sets meet to ``⊥``
        (no value satisfies both).  Distinct from :meth:`meet_const` (``assume
        s == k`` against one constant) and from
        :meth:`StateTransitionDomain.confluence` (the lattice *join*, not glb).
        """
        if self.is_top:
            return other
        if other.is_top:
            return self
        return StateValue(self.constants & other.constants, False)

    def widen(self, other: "StateValue") -> "StateValue":
        # finite height (powerset capped at MAX_CONSTS, then ⊤) -> join suffices
        # (no infinite ascending chains); mirrors KnownBits.widen.
        return self.join(other)

    def meet_const(self, value: int) -> "StateValue":
        """``assume (s == value)`` -- refine to ``self ⊓ {value}``.

        The proof carried by a state-comparison's equality arm: ``⊤ ⊓ {v} = {v}``
        (the comparison resolves the unknown to one constant); ``{...} ⊓ {v}`` is
        ``{v}`` when ``v`` is possible here, else ``⊥`` (the arm is infeasible for
        the incoming value-set -- a dead dispatcher edge, surfaced not guessed).
        """
        v = int(value) & _U64_MASK
        if self.is_top:
            return StateValue.of(v)
        return StateValue.of(v) if v in self.constants else StateValue.bottom()

    def exclude(self, value: int) -> "StateValue":
        """``assume (s != value)`` -- refine to ``self ∖ {value}``.

        The not-equal arm of a comparison.  ``⊤ ∖ {v}`` stays ``⊤`` (an
        "everything except v" set is not representable in a finite powerset; the
        sound over-approximation keeps ``⊤``).  A concrete set drops ``v``.
        """
        v = int(value) & _U64_MASK
        if self.is_top:
            return self
        return StateValue(self.constants - {v}, False)


class StateTransitionDomain:
    """Forward "may" value-set :class:`FlowDomain` over the state variable.

    Implements the abstract-domain Protocol the portable
    :func:`d810.analyses.data_flow.run_fixpoint` engine drives
    (``bottom``/``confluence``/``transfer``/``equals``/``widen``), parameterised
    by a per-block view of how each block writes the state variable.

    ``state_writes`` maps a block serial to the :class:`StateValue` the block
    *strong-updates* the variable to: ``StateValue.of(k)`` for a resolved
    constant write, ``StateValue.top()`` for an unresolved / MBA-obfuscated
    write (the value becomes unknown).  A block absent from the map performs no
    state write and passes the incoming value through unchanged.

    The lattice is finite-height (a powerset of constants capped at
    :attr:`StateValue.MAX_CONSTS`, plus ``⊤``), so ``widen`` need not accelerate
    -- it delegates to :meth:`StateValue.widen` (the finite-height join),
    mirroring the ``ReachingDefinitionsDomain`` worked example.  ``confluence``
    is the lattice join (set union), the sound merge for a forward may-analysis:
    an as-yet-unreached predecessor contributes ``⊥`` and so adds nothing.  Note
    it is a *join* (lub), NOT the element-level :meth:`StateValue.meet` (glb) --
    hence ``confluence`` rather than ``meet``.
    """

    def __init__(self, state_writes: Mapping[NodeId, StateValue]) -> None:
        self._writes: dict[NodeId, StateValue] = dict(state_writes)

    def bottom(self) -> StateValue:
        return StateValue.bottom()

    def confluence(self, left: StateValue, right: StateValue) -> StateValue:
        return left.join(right)

    def transfer(self, node: NodeId, in_state: StateValue) -> StateValue:
        """Strong-update to the block's written value, else pass the value through.

        An unreachable node (``⊥`` in-state) stays unreachable: its write never
        fires, so a block on a dead path cannot pollute the dispatcher's
        value-set.
        """
        if in_state.is_bottom:
            return StateValue.bottom()
        write = self._writes.get(node)
        return in_state if write is None else write

    def equals(self, left: StateValue, right: StateValue) -> bool:
        return left == right

    def widen(self, previous: StateValue, current: StateValue) -> StateValue:
        return previous.widen(current)


def build_state_writes_with_dispatch_assume(
    state_writes: Mapping[NodeId, StateValue],
    handler_entry_by_state: Mapping[int, NodeId],
) -> dict[NodeId, StateValue]:
    """Fold the dispatcher routing into the per-block state-write view as an ``assume``.

    A handler entry block is reached *only* on the dispatcher edge that proved
    ``s == routing_const``, so on entry the state variable is known to be that
    single constant.  Modelling that as a strong-update to ``{E}`` is the LiSA
    ``assume`` for this domain (the value the routed edge establishes), and it
    is what restricts each handler's region to start from its own value rather
    than the dispatcher's broadcast union -- making per-handler transition
    attribution sound.

    An explicit write already present for a block overrides the assume: the
    write happens *after* the routed entry, so the block's exit value is what it
    writes, not the routing constant.
    """
    merged: dict[NodeId, StateValue] = {
        int(entry_block): StateValue.of(int(state_const))
        for state_const, entry_block in handler_entry_by_state.items()
    }
    merged.update({int(node): value for node, value in state_writes.items()})
    return merged


def _handler_region(
    entry: NodeId, dispatcher_entry: NodeId, successors_of: _Succ
) -> set[NodeId]:
    """Blocks reachable from a handler entry without re-entering the dispatcher.

    The dispatcher is the region boundary: a block whose successor is the
    dispatcher is included (it is a back-edge predecessor), but the dispatcher
    itself is not, so the walk never crosses into another handler.
    """
    seen: set[NodeId] = set()
    stack = [int(entry)]
    while stack:
        node = stack.pop()
        if node in seen or node == dispatcher_entry:
            continue
        seen.add(node)
        stack.extend(int(s) for s in successors_of(node))
    return seen


def recover_transition_result(
    *,
    result: FixpointResult,
    dispatcher_entry: NodeId,
    handler_entry_by_state: Mapping[int, NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    strategy_name: str = "state_transition_domain",
) -> TransitionResult:
    """Extract a :class:`TransitionResult` from a converged state-value fixpoint.

    For each handler ``from_state E -> entry block H``, the next states are the
    state-variable values flowing back into the dispatcher from the handler's
    own region (the dispatcher's predecessors reachable from ``H`` without
    re-entering the dispatcher).  ``len(to_states) > 1`` is a genuine conditional
    transition; a single value is unconditional; an unresolved (``⊤``) or
    unreachable (``⊥``) back-edge value yields no clean transition (the
    leaked-constant case, surfaced rather than guessed).
    """
    dispatcher_entry = int(dispatcher_entry)
    back_edge_preds = {int(p) for p in predecessors_of(dispatcher_entry)}
    handlers: dict[int, StateHandler] = {}
    transitions: list[StateTransition] = []

    for from_state, entry_block in sorted(handler_entry_by_state.items()):
        from_state, entry_block = int(from_state), int(entry_block)
        handler = StateHandler(
            state_value=from_state,
            check_block=entry_block,
            handler_blocks=[entry_block],
            transitions=[],
        )
        handlers[from_state] = handler

        region = _handler_region(entry_block, dispatcher_entry, successors_of)
        to_states: set[int] = set()
        for exit_block in back_edge_preds & region:
            value = result.out_states.get(exit_block)
            if value is None or value.is_top or value.is_bottom:
                continue  # unresolved / dead -> no clean transition (explicit)
            to_states.update(value.constants)

        is_conditional = len(to_states) > 1
        for to_state in sorted(to_states):
            transition = StateTransition(
                from_state=from_state,
                to_state=int(to_state),
                from_block=entry_block,
                condition_block=entry_block if is_conditional else None,
                is_conditional=is_conditional,
            )
            transitions.append(transition)
            handler.transitions.append(transition)

    return TransitionResult(
        transitions=transitions,
        handlers=handlers,
        strategy_name=strategy_name,
        resolved_count=len(transitions),
    )


def analyze_state_transitions(
    *,
    nodes: Iterable[NodeId],
    entry_nodes: Iterable[NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    state_writes: Mapping[NodeId, StateValue],
    dispatcher_entry: NodeId,
    handler_entry_by_state: Mapping[int, NodeId],
    entry_state: StateValue | None = None,
    config: FixpointConfiguration | None = None,
    strategy_name: str = "state_transition_domain",
) -> TransitionResult:
    """Run the sound state-value fixpoint and extract its :class:`TransitionResult`.

    The one-call north-star ``#2 RecoverStateTransitions`` entry point: fold the
    dispatcher routing into the per-block writes as ``assume``s, solve the
    forward fixpoint on the portable engine, and attribute transitions per
    handler.  Topology and the per-block state-write view are supplied as plain
    data, so the whole analysis is portable-core (no IDA).
    """
    writes = build_state_writes_with_dispatch_assume(
        state_writes, handler_entry_by_state
    )
    domain = StateTransitionDomain(writes)
    result = run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes=entry_nodes,
        entry_state=StateValue.top() if entry_state is None else entry_state,
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        config=FixpointConfiguration() if config is None else config,
        raise_on_nonconvergence=True,
    )
    return recover_transition_result(
        result=result,
        dispatcher_entry=dispatcher_entry,
        handler_entry_by_state=handler_entry_by_state,
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        strategy_name=strategy_name,
    )


# ---------------------------------------------------------------------------
# Concolic re-realization of the same analysis (S4 increment A, ticket llr-1szn)
# ---------------------------------------------------------------------------

#: The single synthetic state-variable cell the concolic fixpoint tracks. The
#: state variable is modelled as one ``LocationRef`` so the
#: :class:`ConcolicTransitionDomain`'s ``LocationRef -> V`` store degenerates to
#: the single-cell case that exactly reproduces :class:`StateTransitionDomain`.
#: ``width`` is the u64 mask width state constants already carry (see
#: :attr:`StateValue._PROJECT_CONST_SIZE`); it never affects the powerset value.
_STATE_VAR_CELL: "LocationRef" = LocationRef.stack(0, StateValue._PROJECT_CONST_SIZE)


class _StateValueOps:
    """``ValueLatticeOps[StateValue]`` adapter: the powerset cell algebra.

    Injects :class:`StateValue`'s lattice ops into the parametric
    :class:`ConcolicTransitionDomain` so the SAME fixpoint plumbing carries the
    powerset cell. ``widen`` mirrors :class:`StateTransitionDomain.widen`
    (``previous.widen(current)`` -- the finite-height join).
    """

    def bottom(self) -> StateValue:
        return StateValue.bottom()

    def join(self, a: StateValue, b: StateValue) -> StateValue:
        return a.join(b)

    def widen(self, previous: StateValue, current: StateValue) -> StateValue:
        return previous.widen(current)

    def is_bottom(self, value: StateValue) -> bool:
        return value.is_bottom


def _project_partitioned_result(
    result: FixpointResult,
) -> FixpointResult:
    """Project a ``PartitionedState`` fixpoint result back to a ``StateValue`` one.

    Reads the single state-variable cell out of each in/out
    :class:`PartitionedState` so the downstream :func:`recover_transition_result`
    (which reads ``out_states[block]`` as a :class:`StateValue`) consumes it
    unchanged. A cell unset in a store concretizes to ``⊥`` (the engine seeds
    every node's state to ``domain.bottom()``, a full ⊥ store).
    """

    def _cell(state: PartitionedState) -> StateValue:
        return state.store().get(_STATE_VAR_CELL, StateValue.bottom())

    return FixpointResult(
        in_states={n: _cell(s) for n, s in result.in_states.items()},
        out_states={n: _cell(s) for n, s in result.out_states.items()},
        iterations=result.iterations,
        converged=result.converged,
    )


def state_value_fixpoint_result(
    *,
    nodes: Iterable[NodeId],
    entry_nodes: Iterable[NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    state_writes: Mapping[NodeId, StateValue],
    handler_entry_by_state: Mapping[int, NodeId],
    entry_state: StateValue | None = None,
    config: FixpointConfiguration | None = None,
) -> FixpointResult:
    """Run the sound #2 ``StateValue`` fixpoint on the concolic domain, projected.

    Builds the dispatch-assume per-block write view, runs
    :class:`~d810.analyses.data_flow.concolic.ConcolicTransitionDomain` with
    ``V = StateValue`` (single cell / single partition), and projects the
    :class:`PartitionedState` result back to a per-block :class:`StateValue`
    :class:`FixpointResult`.  Shared by :func:`analyze_state_transitions_concolic`
    (which attributes a ``TransitionResult``) and the C1 shadow-diff (which emits
    ``StateWriteTransition`` tuples from these ``out_states``).  Ticket llr-1szn.
    """
    writes = build_state_writes_with_dispatch_assume(
        state_writes, handler_entry_by_state
    )
    cell = _STATE_VAR_CELL
    domain = ConcolicTransitionDomain(
        writes={int(node): {cell: value} for node, value in writes.items()},
        vops=_StateValueOps(),
        cells=frozenset({cell}),
    )
    boundary = StateValue.top() if entry_state is None else entry_state
    result = run_fixpoint(
        domain,
        nodes=nodes,
        entry_nodes=entry_nodes,
        entry_state=PartitionedState.single({cell: boundary}),
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        config=FixpointConfiguration() if config is None else config,
        raise_on_nonconvergence=True,
    )
    return _project_partitioned_result(result)


def analyze_state_transitions_concolic(
    *,
    nodes: Iterable[NodeId],
    entry_nodes: Iterable[NodeId],
    successors_of: _Succ,
    predecessors_of: _Succ,
    state_writes: Mapping[NodeId, StateValue],
    dispatcher_entry: NodeId,
    handler_entry_by_state: Mapping[int, NodeId],
    entry_state: StateValue | None = None,
    config: FixpointConfiguration | None = None,
    strategy_name: str = "state_transition_domain",
) -> TransitionResult:
    """Same analysis as :func:`analyze_state_transitions`, via the concolic domain.

    Increment A of S4 (ticket ``llr-1szn``): re-realize the sound #2
    ``RecoverStateTransitions`` fixpoint on the parametric
    :class:`~d810.analyses.data_flow.concolic.ConcolicTransitionDomain` with
    ``V = StateValue`` (the single-cell, single-partition degenerate case),
    projecting the :class:`PartitionedState` result back to a per-block
    :class:`StateValue` and reusing the existing
    :func:`recover_transition_result` attribution. The returned
    :class:`TransitionResult` is **byte-identical** to
    :func:`analyze_state_transitions` -- the concolic domain reproduces
    :class:`StateTransitionDomain` exactly when carrying the powerset value.

    This is the wiring seam for the later concrete refinement (increment B): the
    same store can carry a richer per-cell value, but the abstract-only transfer
    here is identical to the legacy path.
    """
    return recover_transition_result(
        result=state_value_fixpoint_result(
            nodes=nodes,
            entry_nodes=entry_nodes,
            successors_of=successors_of,
            predecessors_of=predecessors_of,
            state_writes=state_writes,
            handler_entry_by_state=handler_entry_by_state,
            entry_state=entry_state,
            config=config,
        ),
        dispatcher_entry=dispatcher_entry,
        handler_entry_by_state=handler_entry_by_state,
        successors_of=successors_of,
        predecessors_of=predecessors_of,
        strategy_name=strategy_name,
    )
