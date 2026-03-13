from __future__ import annotations

from dataclasses import dataclass
from dataclasses import field
from d810.core.typing import Dict
from d810.core.typing import Iterator
from d810.core.typing import Optional
from d810.core.typing import Set
from d810.core.typing import Tuple


@dataclass(frozen=True)
class BSTNodeEntry:
    """Provenance for a single block visited during BST analysis."""

    serial: int
    value_range: Tuple[Optional[int], Optional[int]]  # (lo, hi) state range reaching this block
    parent_serial: Optional[int]  # BST comparison node that routes here
    comparison_const: Optional[int]  # constant compared at parent node
    branch: str  # "taken" or "fallthrough"
    depth: int  # depth in BST tree (0 = root)
    opcode: Optional[int]  # tail opcode of this block (m_jnz, m_jbe, etc.)
    is_equality_branch: bool  # True when this is the equality path (m_jnz fall-through or m_jz taken)
    is_handler_entry: bool = False  # True for handler entry blocks (provenance-only, excluded from set-like interface)


class BSTNodeMap:
    """Queryable BST node registry -- drop-in replacement for Set[int].

    Stores per-node routing provenance built during BST analysis walk.
    Backward-compatible: supports ``__contains__``, ``__iter__``, ``__len__``,
    ``add(int)``, ``|`` (union with sets), and ``==`` comparison with sets.
    """

    def __init__(self) -> None:
        self._entries: Dict[int, BSTNodeEntry] = {}

    # --- backward compat with Set[int] ---
    # Handler entries are provenance-only: excluded from set-like interface
    # so that ``serial in bst_node_blocks`` checks don't match handler blocks.
    def __contains__(self, serial: object) -> bool:
        entry = self._entries.get(serial)
        return entry is not None and not entry.is_handler_entry

    def __iter__(self) -> Iterator[int]:
        return (s for s, e in self._entries.items() if not e.is_handler_entry)

    def __len__(self) -> int:
        return sum(1 for e in self._entries.values() if not e.is_handler_entry)

    def __bool__(self) -> bool:
        return any(not e.is_handler_entry for e in self._entries.values())

    def _bst_keys(self) -> set[int]:
        """Return the set of serials excluding handler entries."""
        return {s for s, e in self._entries.items() if not e.is_handler_entry}

    def __eq__(self, other: object) -> bool:
        """Allow comparison with plain sets for backward compat / tests."""
        if isinstance(other, set):
            return self._bst_keys() == other
        if isinstance(other, BSTNodeMap):
            return self._bst_keys() == other._bst_keys()
        return NotImplemented

    def __hash__(self) -> int:  # type: ignore[override]
        # Mutable -- not safely hashable, but needed for dataclass default
        return id(self)

    def __or__(self, other: set[int] | BSTNodeMap) -> set[int]:
        """Union with a plain set -- returns a plain set (used by find_bst_default_block)."""
        keys = self._bst_keys()
        if isinstance(other, BSTNodeMap):
            return keys | other._bst_keys()
        return keys | other

    def __ror__(self, other: set[int]) -> set[int]:
        """Reverse union (set | BSTNodeMap)."""
        return other | self._bst_keys()

    def __repr__(self) -> str:
        return f"BSTNodeMap({self._bst_keys()})"

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
        """Register a BST node with its routing provenance.

        When *is_handler_entry* is True the entry is stored for provenance
        queries (``get_entry``, ``resolve_state``) but is **excluded** from
        set-like iteration (``__contains__``, ``__iter__``, ``__len__``,
        ``__or__``) so that ``serial in bst_node_blocks`` checks do not
        match handler blocks.
        """
        self._entries[serial] = BSTNodeEntry(
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
    def get_entry(self, serial: int) -> Optional[BSTNodeEntry]:
        """Get full provenance for a BST node."""
        return self._entries.get(serial)

    def get_range(self, serial: int) -> Optional[Tuple[Optional[int], Optional[int]]]:
        """Get the state value range reaching a BST node."""
        entry = self._entries.get(serial)
        return entry.value_range if entry else None

    def resolve_state(self, serial: int,
                      handler_state_map: Dict[int, int]) -> Optional[int]:
        """Given a BST-embedded block, resolve the handler state that routes to it.

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

        # Try predecessors (for blocks not directly in BST but adjacent)
        if pred_serials:
            for pred in pred_serials:
                result = self.resolve_state(pred, handler_state_map)
                if result is not None:
                    return result

        return None


@dataclass
class BSTAnalysisResult:
    """Semantic model for BST dispatcher analysis results."""

    handler_state_map: Dict[int, int] = field(default_factory=dict)
    handler_range_map: Dict[int, Tuple[Optional[int], Optional[int]]] = field(
        default_factory=dict
    )
    transitions: Dict[int, Optional[int]] = field(default_factory=dict)
    conditional_transitions: Dict[int, Set[int]] = field(default_factory=dict)
    exits: Set[int] = field(default_factory=set)
    pre_header_serial: Optional[int] = None
    initial_state: Optional[int] = None
    bst_node_blocks: BSTNodeMap = field(default_factory=BSTNodeMap)
    default_block_serial: Optional[int] = None


def resolve_target_via_bst(
    bst_result: BSTAnalysisResult,
    state_value: int,
) -> Optional[int]:
    """Resolve a concrete state value to a handler block serial."""
    for handler_serial, state_const in bst_result.handler_state_map.items():
        if state_const == state_value:
            return handler_serial

    exact_handler_serials = set(bst_result.handler_state_map.keys())
    for handler_serial, (low, high) in bst_result.handler_range_map.items():
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

    default_serial = getattr(bst_result, 'default_block_serial', None)
    if default_serial is not None:
        return default_serial

    return None


__all__ = [
    "BSTNodeEntry",
    "BSTNodeMap",
    "BSTAnalysisResult",
    "resolve_target_via_bst",
]
