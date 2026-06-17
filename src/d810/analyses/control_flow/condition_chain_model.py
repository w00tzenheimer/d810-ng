from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from dataclasses import field
from d810.core.typing import Dict
from d810.core.typing import Iterator
from d810.core.typing import Optional
from d810.core.typing import Set
from d810.core.typing import Tuple
from d810.analyses.control_flow.interval_map import IntervalDispatcher
from d810.analyses.control_flow.route_predicate import DecisionDag
from d810.ir.flowgraph import FlowGraph


@dataclass(frozen=True)
class ConditionChainNodeEntry:
    """Provenance for a single block visited during condition-chain analysis."""

    serial: int
    value_range: Tuple[Optional[int], Optional[int]]  # (lo, hi) state range reaching this block
    parent_serial: Optional[int]  # condition-chain comparison node that routes here
    comparison_const: Optional[int]  # constant compared at parent node
    branch: str  # "taken" or "fallthrough"
    depth: int  # depth in condition-chain tree (0 = root)
    opcode: Optional[int]  # tail opcode of this block (m_jnz, m_jbe, etc.)
    is_equality_branch: bool  # True when this is the equality path (m_jnz fall-through or m_jz taken)
    is_handler_entry: bool = False  # True for handler entry blocks (provenance-only, excluded from set-like interface)


class ConditionChainNodeMap:
    """Queryable condition-chain node registry -- drop-in replacement for Set[int].

    Stores per-node routing provenance built during condition-chain analysis walk.
    Supports ``__contains__``, ``__iter__``, ``__len__``,
    ``add(int)``, ``|`` (union with sets), and ``==`` comparison with sets.
    """

    def __init__(self) -> None:
        self._entries: Dict[int, ConditionChainNodeEntry] = {}

    # --- set-like behavior ---
    # Handler entries are provenance-only: excluded from set-like interface
    # so that routing-block membership checks don't match handler blocks.
    def __contains__(self, serial: object) -> bool:
        entry = self._entries.get(serial)
        return entry is not None and not entry.is_handler_entry

    def __iter__(self) -> Iterator[int]:
        return (s for s, e in self._entries.items() if not e.is_handler_entry)

    def __len__(self) -> int:
        return sum(1 for e in self._entries.values() if not e.is_handler_entry)

    def __bool__(self) -> bool:
        return any(not e.is_handler_entry for e in self._entries.values())

    def _condition_chain_keys(self) -> set[int]:
        """Return the set of serials excluding handler entries."""
        return {s for s, e in self._entries.items() if not e.is_handler_entry}

    def __eq__(self, other: object) -> bool:
        """Allow comparison with plain sets for tests."""
        if isinstance(other, set):
            return self._condition_chain_keys() == other
        if isinstance(other, ConditionChainNodeMap):
            return self._condition_chain_keys() == other._condition_chain_keys()
        return NotImplemented

    def __hash__(self) -> int:  # type: ignore[override]
        # Mutable -- not safely hashable, but needed for dataclass default
        return id(self)

    def __or__(self, other: set[int] | ConditionChainNodeMap) -> set[int]:
        """Union with a plain set -- returns a plain set."""
        keys = self._condition_chain_keys()
        if isinstance(other, ConditionChainNodeMap):
            return keys | other._condition_chain_keys()
        return keys | other

    def __ror__(self, other: set[int]) -> set[int]:
        """Reverse union (set | ConditionChainNodeMap)."""
        return other | self._condition_chain_keys()

    def __repr__(self) -> str:
        return f"ConditionChainNodeMap({self._condition_chain_keys()})"

    # --- registration ---
    def add(self, serial: int, *,
            value_range: Tuple[Optional[int], Optional[int]] = (None, None),
            parent_serial: Optional[int] = None,
            comparison_const: Optional[int] = None,
            branch: str = "",
            depth: int = 0,
            opcode: Optional[int] = None,
            is_equality_branch: bool = False,
            is_handler_entry: bool = False) -> None:
        """Register a condition-chain node with its routing provenance.

        When *is_handler_entry* is True the entry is stored for provenance
        queries (``get_entry``, ``resolve_state``) but is **excluded** from
        set-like iteration (``__contains__``, ``__iter__``, ``__len__``,
        ``__or__``) so that routing-block membership checks do not
        match handler blocks.
        """
        self._entries[serial] = ConditionChainNodeEntry(
            serial=serial,
            value_range=value_range,
            parent_serial=parent_serial,
            comparison_const=comparison_const,
            branch=branch,
            depth=depth,
            opcode=opcode,
            is_equality_branch=is_equality_branch,
            is_handler_entry=is_handler_entry,
        )

    # --- queries ---
    def get_entry(self, serial: int) -> Optional[ConditionChainNodeEntry]:
        """Get full provenance for a condition-chain node."""
        return self._entries.get(serial)

    def get_range(self, serial: int) -> Optional[Tuple[Optional[int], Optional[int]]]:
        """Get the state value range reaching a condition-chain node."""
        entry = self._entries.get(serial)
        return entry.value_range if entry else None

    def resolve_state(self, serial: int,
                      handler_state_map: Dict[int, int]) -> Optional[int]:
        """Given a condition-chain block, resolve the handler state that routes to it.

        Strategy:
        1. Direct lookup: if serial is itself a registered handler entry, return its state.
        2. Parent provenance: if this block's ``is_equality_branch`` is True and
           ``comparison_const`` is set, the comparison_const IS the state.
        3. Range intersection: find handler states within this block's value_range.
           If exactly one candidate, return it.
        """
        # Case 1: direct handler lookup (serial is a handler entry)
        for handler_serial, state_val in handler_state_map.items():
            if handler_serial == serial:
                return state_val

        entry = self._entries.get(serial)
        if entry is None:
            return None

        # Case 2: equality branch -> comparison_const IS the state
        if entry.is_equality_branch and entry.comparison_const is not None:
            return entry.comparison_const

        # Case 3: range intersection
        lo, hi = entry.value_range
        if lo is None and hi is None:
            return None
        candidates = []
        for _serial, state_val in handler_state_map.items():
            if (lo is None or state_val >= lo) and (hi is None or state_val <= hi):
                candidates.append(state_val)
        if len(candidates) == 1:
            return candidates[0]

        return None

    def resolve_state_for_block(self, block_serial: int,
                                handler_state_map: Dict[int, int],
                                pred_serials: Optional[list[int]] = None) -> Optional[int]:
        """Resolve handler state for a block, trying the block itself then its predecessors."""
        # Try direct lookup
        result = self.resolve_state(block_serial, handler_state_map)
        if result is not None:
            return result

        # Try predecessors for blocks not directly in the condition chain but adjacent.
        if pred_serials:
            for pred in pred_serials:
                result = self.resolve_state(pred, handler_state_map)
                if result is not None:
                    return result

        return None


@dataclass
class ConditionChainAnalysisResult:
    """Semantic model for condition-chain dispatcher analysis results."""

    handler_state_map: Dict[int, int] = field(default_factory=dict)
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = field(
        default_factory=dict
    )
    transitions: Dict[int, Optional[int]] = field(default_factory=dict)
    conditional_transitions: Dict[int, Set[int]] = field(default_factory=dict)
    exits: Set[int] = field(default_factory=set)
    pre_header_serial: Optional[int] = None
    initial_state: Optional[int] = None
    condition_chain_blocks: ConditionChainNodeMap = field(default_factory=ConditionChainNodeMap)
    default_block_serial: Optional[int] = None
    dispatcher: IntervalDispatcher | None = None
    # Path B: the decision-DAG route oracle for this dispatcher (built by
    # the backend extractor). When present, resolve_target_via_condition_chain routes through
    # it; verified to agree with the legacy interval/exact/range logic on every
    # sub_7FFD state (0 divergence), so this is golden-neutral consolidation.
    decision_dag: Optional[DecisionDag] = None


def resolve_target_via_condition_chain(
    condition_chain_result: ConditionChainAnalysisResult,
    state_value: int,
) -> Optional[int]:
    """Resolve a concrete state value to a handler block serial."""
    # Path B: the decision-DAG is the authoritative router -- it walks the real
    # condition-chain comparison tree, so it subsumes the legacy interval/exact/range logic.
    # Route through it when present (verified 0 divergence vs legacy on sub_7FFD);
    # fall back to the legacy path when no decision-DAG was built.
    dag = getattr(condition_chain_result, "decision_dag", None)
    if dag is not None and dag.nodes:
        return dag.route(int(state_value))
    # Legacy fast path: interval dispatcher (O(log n) bisect)
    if condition_chain_result.dispatcher is not None:
        result = condition_chain_result.dispatcher.lookup(state_value)
        if result is not None:
            return result

    for handler_serial, state_const in condition_chain_result.handler_state_map.items():
        if state_const == state_value:
            return handler_serial

    exact_handler_serials = set(condition_chain_result.handler_state_map.keys())
    for handler_serial, (low, high) in condition_chain_result.handler_range_map.items():
        if handler_serial in exact_handler_serials:
            continue
        if (
            low is not None
            and high is not None
            and (high - low) >= 0xFFFF0000
        ):
            continue
        if low is not None and state_value < low:
            continue
        if high is not None and state_value > high:
            continue
        return handler_serial

    default_serial = getattr(condition_chain_result, 'default_block_serial', None)
    if default_serial is not None:
        return default_serial

    return None


@dataclass(frozen=True)
class ConditionChainTargetResolution:
    """Result of resolving a state value through the condition chain."""

    serial: int
    kind: str  # "handler", "exit", "default", "range", "unknown"
    state_value: int


def resolve_redirectable_handler_target(
    condition_chain_result: ConditionChainAnalysisResult,
    state_value: int,
    augmented_exits: Set[int] | None = None,
    flow_graph: FlowGraph | None = None,
    dispatcher_serial: int = -1,
) -> Optional[int]:
    """Resolve a state value to a redirectable handler target.

    Unlike resolve_target_via_condition_chain() which is a raw condition-chain lookup,
    this function checks whether the resolved target represents
    a handler entry (safe to redirect to) vs an exit/return path
    (unsafe to redirect to).

    When *flow_graph* and *dispatcher_serial* are provided, a forward BFS
    terminal proof is applied: if the resolved target handler
    inevitably reaches return/epilogue without re-entering the
    dispatcher or condition chain, the state is classified as an exit and
    ``None`` is returned.

    Args:
        condition_chain_result: condition-chain analysis result with exits set
        state_value: concrete state value to resolve
        augmented_exits: additional exit states discovered by
            fallback strategies (e.g., backward-pred, valrange)
        flow_graph: portable FlowGraph for the forward terminal proof
            (optional; skipped when ``None``)
        dispatcher_serial: serial of the dispatcher block
            (required when *flow_graph* is provided, ignored otherwise)

    Returns:
        Handler serial if safe to redirect, None if exit/default/unknown
    """
    # Check primary exits
    if state_value in condition_chain_result.exits:
        return None

    # Check augmented exits
    if augmented_exits is not None and state_value in augmented_exits:
        return None

    # Raw condition-chain lookup
    target = resolve_target_via_condition_chain(condition_chain_result, state_value)
    if target is None:
        return None

    # Forward terminal proof: if the resolved target handler
    # inevitably reaches return/epilogue, it's an exit — don't redirect
    if flow_graph is not None and dispatcher_serial >= 0:
        condition_chain_blocks = (
            set(condition_chain_result.condition_chain_blocks)
            if condition_chain_result.condition_chain_blocks
            else set()
        )
        if is_terminal_handler(flow_graph, target, dispatcher_serial, condition_chain_blocks):
            # Augment exits with this discovery for future lookups
            if augmented_exits is not None:
                augmented_exits.add(state_value)
            return None

    return target


def is_terminal_handler(
    flow_graph: FlowGraph,
    entry_serial: int,
    dispatcher_serial: int,
    condition_chain_blocks: set[int],
    max_depth: int = 50,
) -> bool:
    """Forward BFS proof that a handler inevitably reaches return/epilogue.

    Returns True if ALL paths from entry_serial lead to no-successor
    blocks without going through the dispatcher or condition chain.
    """
    queue: deque[int] = deque([entry_serial])
    visited: set[int] = {entry_serial}
    depth = 0
    qty = (max(flow_graph.blocks) + 1) if flow_graph.blocks else 0

    while queue and depth < max_depth:
        depth += 1
        s = queue.popleft()
        if s >= qty:
            continue
        blk = flow_graph.blocks.get(s)
        if blk is None:
            continue
        if blk.nsucc == 0:
            continue  # terminal leaf — OK
        for succ in blk.succs:
            if succ == dispatcher_serial or succ in condition_chain_blocks:
                return False  # reaches dispatcher/condition chain -- NOT terminal
            if succ not in visited:
                visited.add(succ)
                queue.append(succ)

    return True  # all paths end at BLT_STOP/no-succ


__all__ = [
    "ConditionChainNodeEntry",
    "ConditionChainNodeMap",
    "ConditionChainAnalysisResult",
    "ConditionChainTargetResolution",
    "resolve_target_via_condition_chain",
    "resolve_redirectable_handler_target",
    "is_terminal_handler",
]
