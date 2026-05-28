"""State-machine path analysis helpers shared across recon and Hodur."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from types import SimpleNamespace

from d810.cfg.flowgraph import (
    BlockKind,
    BranchPredicate,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
    OperandKind,
)
from d810.core import logging
from d810.core.typing import Optional
from d810.ir.results import ConstantFixpointResult
from d810.recon.flow.bst_analysis import _forward_eval_insn

logger = logging.getLogger(__name__)

_BST_BRANCH_PREDICATES = frozenset(
    {
        BranchPredicate.NOT_EQUAL,
        BranchPredicate.EQUAL,
        BranchPredicate.UNSIGNED_LE,
        BranchPredicate.UNSIGNED_GT,
        BranchPredicate.UNSIGNED_LT,
        BranchPredicate.UNSIGNED_GE,
    }
)
_LEGACY_BLT_STOP = 1
_LEGACY_BST_STACK_OPERAND = 3
_LEGACY_INSN_KIND_OPCODES = {
    InsnKind.NOP: frozenset({0x00}),
    InsnKind.STORE: frozenset({0x01}),
    InsnKind.MOV: frozenset({0x04}),
    InsnKind.GOTO: frozenset({0x37}),
    InsnKind.CALL: frozenset({0x38, 0x39}),
    InsnKind.RET: frozenset({0x3A}),
}
_LEGACY_BRANCH_PREDICATE_OPCODES = {
    0x2B: BranchPredicate.NOT_EQUAL,
    0x2C: BranchPredicate.EQUAL,
    0x2D: BranchPredicate.UNSIGNED_GE,
    0x2E: BranchPredicate.UNSIGNED_LT,
    0x2F: BranchPredicate.UNSIGNED_GT,
    0x30: BranchPredicate.UNSIGNED_LE,
}


def _semantic_value(value: object) -> object:
    return getattr(value, "value", value)


def _kind_matches(value: object, expected: object, *legacy_names: str) -> bool:
    actual = _semantic_value(value)
    target = _semantic_value(expected)
    if actual == target or value is expected:
        return True
    if isinstance(actual, str) and actual in legacy_names:
        return True
    return False


def _operand_kind_matches(
    operand: object | None,
    expected: OperandKind,
    *legacy_names: str,
) -> bool:
    if operand is None:
        return False
    if _kind_matches(getattr(operand, "kind", None), expected, *legacy_names):
        return True
    operand_type = getattr(operand, "t", None)
    if isinstance(operand_type, str) and operand_type in legacy_names:
        return True
    if expected is OperandKind.STACK:
        return (
            getattr(operand, "stkoff", None) is not None
            or getattr(operand, "s", None) is not None
        )
    if expected is OperandKind.REGISTER:
        return (
            getattr(operand, "reg", None) is not None
            or getattr(operand, "r", None) is not None
        )
    if expected is OperandKind.NUMBER:
        return (
            getattr(operand, "value", None) is not None
            or getattr(operand, "nnn_value", None) is not None
        )
    if expected is OperandKind.LVAR:
        return (
            getattr(operand, "l", None) is not None
            or getattr(operand, "lvar_off", None) is not None
            or getattr(operand, "lvar_idx", None) is not None
        )
    return False


def _is_stack_operand(operand: object | None) -> bool:
    return _operand_kind_matches(operand, OperandKind.STACK, "mop_S")


def _is_lvar_operand(operand: object | None) -> bool:
    return _operand_kind_matches(operand, OperandKind.LVAR, "mop_l")


def _is_register_operand(operand: object | None) -> bool:
    return _operand_kind_matches(operand, OperandKind.REGISTER, "mop_r")


def _is_number_operand(operand: object | None) -> bool:
    return _operand_kind_matches(operand, OperandKind.NUMBER, "mop_n")


def _insn_kind_matches(
    insn: object | None,
    expected: InsnKind,
    *legacy_names: str,
) -> bool:
    if insn is None:
        return False
    if _kind_matches(getattr(insn, "kind", None), expected, *legacy_names):
        return True
    opcode_name = getattr(insn, "opcode_name", None)
    if isinstance(opcode_name, str) and opcode_name in legacy_names:
        return True
    opcode = getattr(insn, "opcode", None)
    if isinstance(opcode, str) and opcode in legacy_names:
        return True
    try:
        return int(opcode) in _LEGACY_INSN_KIND_OPCODES.get(expected, frozenset())
    except (TypeError, ValueError):
        return False


def _is_call_insn(insn: object | None) -> bool:
    return bool(getattr(insn, "is_call", False)) or _insn_kind_matches(
        insn,
        InsnKind.CALL,
        "m_call",
        "m_icall",
    )


def _is_store_insn(insn: object | None) -> bool:
    return _insn_kind_matches(insn, InsnKind.STORE, "m_stx")


def _is_goto_insn(insn: object | None) -> bool:
    return bool(getattr(insn, "is_unconditional_jump", False)) or _insn_kind_matches(
        insn,
        InsnKind.GOTO,
        "m_goto",
    )


def _is_nop_insn(insn: object | None) -> bool:
    return _insn_kind_matches(insn, InsnKind.NOP, "m_nop")


def _is_ret_insn(insn: object | None) -> bool:
    return _insn_kind_matches(insn, InsnKind.RET, "m_ret")


def _block_has_ret_tail(block: object | None) -> bool:
    if block is None:
        return False
    if _is_ret_insn(_tail_insn(block)):
        return True
    if _kind_matches(getattr(block, "tail_kind", None), InsnKind.RET, "m_ret"):
        return True
    tail_opcode = getattr(block, "tail_opcode", None)
    return _insn_kind_matches(SimpleNamespace(opcode=tail_opcode), InsnKind.RET, "m_ret")


def _is_stop_block(block: object | None) -> bool:
    if block is None:
        return False
    if _kind_matches(getattr(block, "kind", None), BlockKind.STOP, "BLT_STOP"):
        return True
    block_type = getattr(block, "block_type", None)
    if isinstance(block_type, str):
        return block_type == "BLT_STOP"
    try:
        return int(block_type) == _LEGACY_BLT_STOP
    except (TypeError, ValueError):
        return False


def _tail_insn(block: object | None) -> object | None:
    if block is None:
        return None
    tail = getattr(block, "tail", None)
    if tail is not None:
        return tail
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    return insns[-1] if insns else None


def _branch_predicate_for_tail(tail: object | None) -> BranchPredicate | object | None:
    if tail is None:
        return None
    predicate = getattr(tail, "branch_predicate", None)
    if predicate is not None:
        return predicate
    opcode_name = getattr(tail, "opcode_name", None)
    if not isinstance(opcode_name, str):
        opcode = getattr(tail, "opcode", None)
        opcode_name = opcode if isinstance(opcode, str) else None
        try:
            return _LEGACY_BRANCH_PREDICATE_OPCODES.get(int(opcode))
        except (TypeError, ValueError):
            return None
    return {
        "m_jnz": BranchPredicate.NOT_EQUAL,
        "m_jz": BranchPredicate.EQUAL,
        "m_jbe": BranchPredicate.UNSIGNED_LE,
        "m_ja": BranchPredicate.UNSIGNED_GT,
        "m_jb": BranchPredicate.UNSIGNED_LT,
        "m_jae": BranchPredicate.UNSIGNED_GE,
    }.get(opcode_name)


def _bst_condition_key_for_tail(tail: object | None) -> object | None:
    if tail is None:
        return None
    raw_opcode = getattr(tail, "opcode", None)
    if raw_opcode in _BST_CMP_OPCODES:
        return raw_opcode
    return _branch_predicate_for_tail(tail)


def _constant_operand_value(operand: object | None) -> int | None:
    if operand is None:
        return None
    value = getattr(operand, "nnn_value", None)
    if value is None:
        value = getattr(operand, "value", None)
    if value is None:
        return None
    return int(value)


def _stack_offset(operand: object | None) -> int | None:
    if operand is None:
        return None
    stkoff = getattr(operand, "stkoff", None)
    if stkoff is None:
        stack_ref = getattr(operand, "s", None)
        stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
    return int(stkoff) if stkoff is not None else None


def _register_id(operand: object | None) -> int | None:
    if operand is None:
        return None
    reg = getattr(operand, "r", None)
    if reg is None:
        reg = getattr(operand, "reg", None)
    return int(reg) if reg is not None else None


def _state_var_ref(operand: object) -> tuple[object, int | None]:
    raw_type = getattr(operand, "t", None)
    if raw_type is not None:
        return (raw_type, getattr(operand, "size", None))
    kind = getattr(operand, "kind", None)
    return (_semantic_value(kind), getattr(operand, "size", None))


def _tracks_bst_stack_offset(operand: object | None) -> bool:
    raw_type = getattr(operand, "t", None)
    if raw_type is None:
        return _is_stack_operand(operand)
    if raw_type == "mop_S":
        return True
    try:
        return int(raw_type) == _LEGACY_BST_STACK_OPERAND
    except (TypeError, ValueError):
        return False

__all__ = [
    "CarrierResolutionResult",
    "ConditionalTransition",
    "ExitStateKind",
    "HandlerPathResult",
    "ResolutionMethod",
    "classify_exit_state",
    "SnapshotConstantFixpointResult",
    "StateWriteSite",
    "build_mba_view_from_flow_graph",
    "can_reach_return_snapshot",
    "detect_conditional_transitions",
    "eval_bst_condition",
    "evaluate_handler_paths",
    "find_last_state_write_site_snapshot",
    "find_last_state_write_site_on_path_snapshot",
    "find_state_write_sites_snapshot",
    "find_terminal_exit_target_snapshot",
    "init_bst_cmp_opcodes",
    "resolve_exit_via_bst_default_snapshot",
    "run_snapshot_constant_fixpoint",
]


class _InsnView:
    __slots__ = (
        "opcode",
        "ea",
        "l",
        "r",
        "d",
        "kind",
        "branch_predicate",
        "is_call",
        "is_unconditional_jump",
        "next",
    )

    def __init__(self, insn: InsnSnapshot):
        self.opcode = insn.opcode
        self.ea = insn.ea
        self.l = insn.l
        self.r = insn.r
        self.d = insn.d
        self.kind = insn.kind
        self.branch_predicate = insn.branch_predicate
        self.is_call = insn.is_call
        self.is_unconditional_jump = insn.is_unconditional_jump
        self.next: _InsnView | None = None


class _BlockView:
    __slots__ = ("serial", "_succs", "head")

    def __init__(self, serial: int, succs: tuple[int, ...], head: _InsnView | None):
        self.serial = serial
        self._succs = succs
        self.head = head

    def nsucc(self) -> int:
        return len(self._succs)

    def succ(self, index: int) -> int:
        return self._succs[index]


class _FlowGraphMBAView:
    __slots__ = ("qty", "_blocks")

    def __init__(self, blocks: dict[int, _BlockView]):
        self.qty = (max(blocks) + 1) if blocks else 0
        self._blocks = blocks

    def get_mblock(self, serial: int) -> _BlockView | None:
        return self._blocks.get(serial)


def build_mba_view_from_flow_graph(flow_graph: FlowGraph) -> object:
    """Adapt a ``FlowGraph`` snapshot into the minimal MBA API used by path eval."""

    block_views: dict[int, _BlockView] = {}
    for serial, block in flow_graph.blocks.items():
        insn_views = [_InsnView(insn) for insn in block.insn_snapshots]
        for current, nxt in zip(insn_views, insn_views[1:]):
            current.next = nxt
        head = insn_views[0] if insn_views else None
        block_views[serial] = _BlockView(serial, tuple(block.succs), head)
    return _FlowGraphMBAView(block_views)


class ResolutionMethod(enum.Enum):
    """How a carrier constant was resolved."""

    SNAPSHOT = "snapshot"
    MBA_DEF_SEARCH = "mba_def_search"
    VALRANGES = "valranges"
    UNRESOLVED = "unresolved"


class ExitStateKind(enum.Enum):
    """Classification of an exit state recorded by ``evaluate_handler_paths``.

    Used to decide whether a state should be promoted to a supplemental row
    (STABLE_HANDOFF) or filtered out (TRANSIENT_CORRIDOR, SELF_LOOP).
    """

    STABLE_HANDOFF = "stable_handoff"
    """Real inter-handler transition. Dispatcher confirms the target."""

    TRANSIENT_CORRIDOR = "transient_corridor"
    """Internal value overwritten before reaching the next stable boundary.
    The DFS terminated early at a handler-entry boundary."""

    TERMINAL = "terminal"
    """Path ends at return/exit (final_state is None)."""

    BST_REENTRY = "bst_reentry"
    """Path returns to the dispatcher BST (exit_block succ in bst_node_blocks)."""

    SELF_LOOP = "self_loop"
    """Exit state equals incoming state (handler writes its own state back)."""

    UNCLASSIFIED = "unclassified"
    """Classification could not be determined."""


def classify_exit_state(
    mba: object,
    final_state: int | None,
    incoming_state: int | None,
    successor_serial: int,
    state_var_stkoff: int,
    bst_node_blocks: set[int],
    max_blocks: int = 6,
) -> ExitStateKind:
    """Classify an exit state via path-local lookahead through the successor.

    Walks forward from *successor_serial* through straight-line blocks in the
    MBA.  If the state variable is overwritten before any unsafe side effect
    (``m_call``/``m_icall``/``m_stx``), branch (nsucc > 1), merge (npred > 1),
    BST re-entry, or terminal (nsucc == 0), the exit state is transient — it
    gets consumed internally and never reaches the dispatcher.

    Args:
        mba: backend MBA-like object for instruction walking.
        final_state: The state value at handler exit (None for terminal paths).
        incoming_state: The state value at handler entry.
        successor_serial: The handler-entry block that caused DFS termination.
        state_var_stkoff: Stack offset of the state variable.
        bst_node_blocks: BST comparison node serials.
        max_blocks: Maximum corridor depth to walk.
    """
    if final_state is None:
        return ExitStateKind.TERMINAL

    masked = final_state & 0xFFFFFFFF

    # Self-loop: handler wrote its own incoming state back.
    if incoming_state is not None and masked == (incoming_state & 0xFFFFFFFF):
        return ExitStateKind.SELF_LOOP

    serial = successor_serial
    visited: set[int] = set()
    try:
        mba_qty = mba.qty
    except AttributeError:
        return ExitStateKind.UNCLASSIFIED
    for _ in range(max_blocks):
        if serial in visited or serial >= mba_qty:
            break
        visited.add(serial)
        blk = mba.get_mblock(serial)

        # Note: no merge-point guard here.  OLLVM handler entries have
        # npred > 1 from BST routing + shared suffix flows.  The
        # instruction-level checks (side effects, state writes, non-state
        # stack writes) are sufficient to classify corridor vs handler body.

        insn = blk.head
        while insn is not None:
            # Side effect before state overwrite → stable handoff.
            if _is_call_insn(insn) or _is_store_insn(insn):
                return ExitStateKind.STABLE_HANDOFF

            # Check if this instruction writes to the state variable.
            dest = getattr(insn, "d", None)
            if dest is not None:
                wrote_state = False
                if _is_stack_operand(dest):
                    off = _stack_offset(dest)
                    if off is not None and int(off) == int(state_var_stkoff):
                        wrote_state = True
                elif _is_lvar_operand(dest):
                    lvar_ref = getattr(dest, "l", None)
                    idx = getattr(lvar_ref, "idx", None) if lvar_ref else None
                    if idx is not None:
                        try:
                            lvar = mba.vars[idx]
                            off = lvar.location.stkoff()
                            if int(off) == int(state_var_stkoff):
                                wrote_state = True
                        except Exception:
                            pass
                if wrote_state:
                    # State variable overwritten before any side effect →
                    # the exit state is transient corridor glue.
                    return ExitStateKind.TRANSIENT_CORRIDOR

                # Non-state stack write: real computation, not corridor.
                if _is_stack_operand(dest):
                    off = _stack_offset(dest)
                    if off is not None and int(off) != int(state_var_stkoff):
                        return ExitStateKind.STABLE_HANDOFF

            insn = insn.next

        # Check successor structure.
        nsucc = blk.nsucc()
        if nsucc == 0:
            # Terminal block.
            return ExitStateKind.TERMINAL
        if nsucc > 1:
            # Branch → real handler body with conditionals.
            return ExitStateKind.STABLE_HANDOFF

        next_serial = blk.succ(0)
        if next_serial in bst_node_blocks:
            # Re-enters dispatcher → stable handoff (state will be consumed by BST).
            return ExitStateKind.BST_REENTRY
        serial = next_serial

    return ExitStateKind.UNCLASSIFIED


def _resolved_bst_exit_kind(
    mba: object,
    flow_graph: FlowGraph,
    *,
    bst_root_serial: int,
    state_value: int,
    incoming_state: int | None,
    state_var_stkoff: int,
    bst_node_blocks: set[int],
    state_machine_blocks: set[int],
) -> tuple[int | None, ExitStateKind | None, bool]:
    """Resolve ``state_value`` through the BST and classify the resolved body.

    A block outside the known state-machine set is not automatically terminal.
    OLLVM residual phases commonly route an intermediate state through the BST
    to a small pre-header/body block that writes the next dispatcher state and
    re-enters the BST.  A reachability-only terminal check misclassifies that
    shape because the pre-header can eventually reach a return through the
    rest of the function.  Local lookahead distinguishes those live state
    handoffs from true return-frontier exits.
    """

    resolved = resolve_exit_via_bst_default_snapshot(
        flow_graph,
        int(bst_root_serial),
        int(state_value) & 0xFFFFFFFF,
    )
    if resolved is None or resolved in state_machine_blocks:
        return resolved, None, False
    if not can_reach_return_snapshot(flow_graph, resolved):
        return resolved, None, False

    resolved_kind = classify_exit_state(
        mba=mba,
        final_state=int(state_value) & 0xFFFFFFFF,
        incoming_state=incoming_state,
        successor_serial=int(resolved),
        state_var_stkoff=int(state_var_stkoff),
        bst_node_blocks=bst_node_blocks,
    )
    is_terminal = resolved_kind in (
        ExitStateKind.TERMINAL,
        ExitStateKind.UNCLASSIFIED,
    )
    return resolved, resolved_kind, is_terminal


@dataclass(frozen=True, slots=True)
class CarrierResolutionResult:
    """Centralized result from backward constant resolution provenance."""

    kind: str
    """CarrierSourceKind value (str enum)."""

    const_value: int | None = None
    """Resolved numeric constant, or None if unresolved."""

    method: ResolutionMethod = ResolutionMethod.UNRESOLVED
    """How the constant was resolved."""

    def_blk_serial: int | None = None
    """Block serial containing the defining instruction."""

    def_insn_ea: int | None = None
    """Instruction EA of the defining instruction."""

    source_mop_type: int | None = None
    """mop_t.t of the source operand in the defining instruction."""

    source_stkoff: int | None = None
    """Stack offset if source is mop_S."""

    source_mreg: int | None = None
    """Register id if source is mop_r."""


@dataclass
class HandlerPathResult:
    """Result of evaluating one exit path from a handler."""

    exit_block: int
    final_state: Optional[int]
    state_writes: list
    ordered_path: list = field(default_factory=list)


@dataclass
class ConditionalTransition:
    """An intra-handler conditional branch where one arm is a state transition."""

    handler_entry: int
    branch_block: int
    target_state: int
    target_handler: int | None
    state_write_block: int | None
    state_write_ea: int | None
    branch_arm: int | None
    is_terminal_no_write: bool = False


@dataclass(frozen=True, slots=True)
class StateWriteSite:
    """A resolved write to the dispatcher state variable in one snapshot block."""

    block_serial: int
    state_value: int
    insn_ea: int
    insn_index: int
    truncation_insn_eas: tuple[int, ...] = ()
    trailing_insn_eas: tuple[int, ...] = ()
    trailing_opcodes: tuple[int, ...] = ()
    unsafe_trailing_insn_eas: tuple[int, ...] = ()
    unsafe_trailing_reasons: tuple[str, ...] = ()


# Back-compat alias preserving the legacy name at its original
# location.  The canonical definition lives at
# ``d810.ir.results.ConstantFixpointResult`` (slice 9, see
# docs/plans/recon-and-cfg-restructuring-phase0-inventory.md); the
# alias keeps the 5 prod + 1 test consumer files
# (``round_discovery_context.py``, ``path_horizon.py``,
# ``reconstruction_discovery.py``, ``reconstruction_candidate_builder.py``,
# this module, ``tests/unit/recon/flow/test_reconstruction_candidate_builder.py``)
# working without migration.  New code should import
# ``ConstantFixpointResult`` from ``d810.ir.results`` directly.
SnapshotConstantFixpointResult = ConstantFixpointResult


def _kill_constant_dest_snapshot(
    dest: object | None,
    stk_map: dict[int, int],
    reg_map: dict[int, int],
) -> None:
    """Forget a written destination when its new value is not provably constant."""

    if dest is None:
        return

    if _is_stack_operand(dest):
        stkoff = _stack_offset(dest)
        if stkoff is not None:
            stk_map.pop(int(stkoff), None)
        return

    if _is_register_operand(dest):
        reg = _register_id(dest)
        if reg is not None:
            reg_map.pop(int(reg), None)


def _constant_dest_locator_snapshot(dest: object | None) -> tuple[str, int] | None:
    """Return a stable locator for stack/register destinations in snapshots."""

    if dest is None:
        return None
    if _is_stack_operand(dest):
        stkoff = _stack_offset(dest)
        if stkoff is not None:
            return ("stk", int(stkoff))
        return None

    if _is_register_operand(dest):
        reg = _register_id(dest)
        if reg is not None:
            return ("reg", int(reg))
    return None


def _eval_insn_view_snapshot(insn: InsnSnapshot) -> object:
    """Build an evaluator view that prefers rich operand-slot snapshots.

    ``InsnSnapshot.l/r/d`` intentionally use lightweight cfg operands that omit
    nested expression structure. ``operand_slots`` retains the richer
    ``hexrays.ir.mop_snapshot.MopSnapshot`` objects, which can expose ``mop_d``
    trees through their owned-mop fallback. The forward evaluator needs those
    rich operands to fold live formula state writes.
    """

    if not insn.operand_slots:
        return insn

    slot_map = {name: operand for name, operand in insn.operand_slots}
    if not slot_map:
        return insn

    return SimpleNamespace(
        opcode=insn.opcode,
        ea=insn.ea,
        l=slot_map.get("l", insn.l),
        r=slot_map.get("r", insn.r),
        d=slot_map.get("d", insn.d),
    )


def _classify_truncation_side_effect_snapshot(
    insn: InsnSnapshot,
    *,
    state_var_stkoff: int,
) -> str | None:
    """Classify why truncating *insn* after a state write would be unsafe."""

    if _is_goto_insn(insn) or _is_nop_insn(insn):
        return None

    if _is_call_insn(insn):
        return "call"

    eval_insn = _eval_insn_view_snapshot(insn)
    dest = getattr(eval_insn, "d", None)
    if dest is None:
        return "control_flow"

    if _is_stack_operand(dest):
        stkoff = _stack_offset(dest)
        if stkoff is not None and int(stkoff) == int(state_var_stkoff):
            return "state_var_write"
        return "memory_write"

    if _is_register_operand(dest):
        return "register_write"

    return "unknown_side_effect"


def _meet_constant_maps(pred_maps: tuple[dict[int, int], ...]) -> dict[int, int]:
    """Keep only keys that are present with the same exact value in every pred."""

    if not pred_maps:
        return {}

    shared_keys = set(pred_maps[0])
    for mapping in pred_maps[1:]:
        shared_keys &= set(mapping)

    result: dict[int, int] = {}
    for key in shared_keys:
        value = pred_maps[0][key]
        if all(mapping.get(key) == value for mapping in pred_maps[1:]):
            result[int(key)] = int(value) & 0xFFFFFFFF
    return result


def _transfer_snapshot_constant_block(
    block,
    in_stk_map: dict[int, int],
    in_reg_map: dict[int, int],
    state_var_stkoff: int,
) -> tuple[dict[int, int], dict[int, int]]:
    """Propagate exact stack/register constants through one snapshot block."""

    stk_map = dict(in_stk_map)
    reg_map = dict(in_reg_map)
    for insn in block.insn_snapshots:
        eval_insn = _eval_insn_view_snapshot(insn)
        dest = getattr(eval_insn, "d", None)
        dest_locator = _constant_dest_locator_snapshot(dest)
        old_dest_value = None
        if dest_locator is not None:
            kind, ident = dest_locator
            old_dest_value = (
                stk_map.get(ident) if kind == "stk" else reg_map.get(ident)
            )
        resolved = _forward_eval_insn(
            eval_insn,
            stk_map,
            reg_map,
            state_var_stkoff,
            mba=None,
            state_var_lvar_idx=None,
        )
        if resolved is None:
            if dest_locator is None:
                continue
            kind, ident = dest_locator
            new_dest_value = stk_map.get(ident) if kind == "stk" else reg_map.get(ident)
            if new_dest_value != old_dest_value or new_dest_value is not None:
                continue
            _kill_constant_dest_snapshot(dest, stk_map, reg_map)
    return stk_map, reg_map


def run_snapshot_constant_fixpoint(
    flow_graph: FlowGraph,
    state_var_stkoff: int,
    *,
    max_iterations: int = 1000,
) -> SnapshotConstantFixpointResult:
    """Compute conservative exact constants at each snapshot block boundary.

    The domain is two exact-constant maps keyed by stack offset and register id.
    Meet semantics are intersection-on-equality: a fact survives only when every
    predecessor proves the same constant.
    """

    block_serials = tuple(sorted(flow_graph.blocks))
    in_stk_maps: dict[int, dict[int, int]] = {serial: {} for serial in block_serials}
    in_reg_maps: dict[int, dict[int, int]] = {serial: {} for serial in block_serials}
    out_stk_maps: dict[int, dict[int, int]] = {serial: {} for serial in block_serials}
    out_reg_maps: dict[int, dict[int, int]] = {serial: {} for serial in block_serials}

    worklist = list(block_serials)
    iterations = 0

    while worklist and iterations < max_iterations:
        serial = worklist.pop()
        iterations += 1

        block = flow_graph.get_block(serial)
        if block is None:
            continue

        if block.preds:
            pred_stk_maps = tuple(out_stk_maps.get(pred, {}) for pred in block.preds)
            pred_reg_maps = tuple(out_reg_maps.get(pred, {}) for pred in block.preds)
            in_stk = _meet_constant_maps(pred_stk_maps)
            in_reg = _meet_constant_maps(pred_reg_maps)
        else:
            in_stk = in_stk_maps.get(serial, {})
            in_reg = in_reg_maps.get(serial, {})

        in_changed = (
            in_stk != in_stk_maps.get(serial, {})
            or in_reg != in_reg_maps.get(serial, {})
        )
        if in_changed:
            in_stk_maps[serial] = in_stk
            in_reg_maps[serial] = in_reg

        out_stk, out_reg = _transfer_snapshot_constant_block(
            block,
            in_stk,
            in_reg,
            state_var_stkoff,
        )

        if (
            out_stk != out_stk_maps.get(serial, {})
            or out_reg != out_reg_maps.get(serial, {})
        ):
            out_stk_maps[serial] = out_stk
            out_reg_maps[serial] = out_reg
            for succ in block.succs:
                if succ not in worklist:
                    worklist.append(succ)

    return SnapshotConstantFixpointResult(
        in_stk_maps=in_stk_maps,
        in_reg_maps=in_reg_maps,
        out_stk_maps=out_stk_maps,
        out_reg_maps=out_reg_maps,
        iterations=iterations,
    )


def can_reach_return_snapshot(
    flow_graph: FlowGraph,
    start_serial: int,
) -> bool:
    """BFS to check if *start_serial* can reach a return/stop block via snapshots."""

    visited: set[int] = set()
    to_visit = [start_serial]
    while to_visit:
        blk_serial = to_visit.pop(0)
        if blk_serial in visited:
            continue
        visited.add(blk_serial)
        blk = flow_graph.get_block(blk_serial)
        if blk is None:
            continue
        if _is_stop_block(blk):
            return True
        if _block_has_ret_tail(blk):
            return True
        for succ in blk.succs:
            if succ not in visited:
                to_visit.append(succ)
    return False


def find_state_write_sites_snapshot(
    flow_graph: FlowGraph,
    block_serial: int,
    state_var_stkoff: int,
    *,
    initial_stk_map: dict[int, int] | None = None,
    initial_reg_map: dict[int, int] | None = None,
) -> tuple[StateWriteSite, ...]:
    """Return all resolved state-variable write sites in one snapshot block.

    The walk uses the same forward evaluator as the live BST analysis, so it
    can recover simple formula-derived constants within a block rather than
    matching only literal ``m_mov #const, state_var`` writes.
    """

    block = flow_graph.get_block(block_serial)
    if block is None:
        return ()

    stk_map: dict[int, int] = dict(initial_stk_map or {})
    reg_map: dict[int, int] = dict(initial_reg_map or {})
    sites: list[StateWriteSite] = []
    instructions = tuple(block.insn_snapshots)

    for index, insn in enumerate(instructions):
        eval_insn = _eval_insn_view_snapshot(insn)
        dest = getattr(eval_insn, "d", None)
        dest_locator = _constant_dest_locator_snapshot(dest)
        old_dest_value = None
        if dest_locator is not None:
            kind, ident = dest_locator
            old_dest_value = (
                stk_map.get(ident) if kind == "stk" else reg_map.get(ident)
            )
        resolved_state = _forward_eval_insn(
            eval_insn,
            stk_map,
            reg_map,
            state_var_stkoff,
            mba=None,
            state_var_lvar_idx=None,
        )
        if resolved_state is None:
            if dest_locator is None:
                continue
            kind, ident = dest_locator
            new_dest_value = stk_map.get(ident) if kind == "stk" else reg_map.get(ident)
            if new_dest_value != old_dest_value or new_dest_value is not None:
                continue
            _kill_constant_dest_snapshot(dest, stk_map, reg_map)
            continue
        trailing = instructions[index + 1 :]
        unsafe_trailing_eas: list[int] = []
        unsafe_trailing_reasons: list[str] = []
        for trailing_insn in trailing:
            reason = _classify_truncation_side_effect_snapshot(
                trailing_insn,
                state_var_stkoff=state_var_stkoff,
            )
            if reason is None:
                continue
            unsafe_trailing_eas.append(int(trailing_insn.ea))
            unsafe_trailing_reasons.append(reason)
        sites.append(
            StateWriteSite(
                block_serial=block_serial,
                state_value=resolved_state & 0xFFFFFFFF,
                insn_ea=int(insn.ea),
                insn_index=index,
                truncation_insn_eas=tuple(
                    [int(insn.ea), *(int(tail.ea) for tail in trailing)]
                ),
                trailing_insn_eas=tuple(int(tail.ea) for tail in trailing),
                trailing_opcodes=tuple(int(tail.opcode) for tail in trailing),
                unsafe_trailing_insn_eas=tuple(unsafe_trailing_eas),
                unsafe_trailing_reasons=tuple(unsafe_trailing_reasons),
            )
        )

    return tuple(sites)


def find_last_state_write_site_snapshot(
    flow_graph: FlowGraph,
    block_serial: int,
    state_var_stkoff: int,
    *,
    initial_stk_map: dict[int, int] | None = None,
    initial_reg_map: dict[int, int] | None = None,
) -> StateWriteSite | None:
    """Return the last resolved state write in one snapshot block, if any."""

    sites = find_state_write_sites_snapshot(
        flow_graph,
        block_serial,
        state_var_stkoff,
        initial_stk_map=initial_stk_map,
        initial_reg_map=initial_reg_map,
    )
    return sites[-1] if sites else None


def find_last_state_write_site_on_path_snapshot(
    flow_graph: FlowGraph,
    ordered_path: tuple[int, ...] | list[int],
    state_var_stkoff: int,
    *,
    in_stk_maps: dict[int, dict[int, int]] | None = None,
    in_reg_maps: dict[int, dict[int, int]] | None = None,
) -> tuple[int, StateWriteSite] | None:
    """Return the deepest resolved state write while walking one concrete path.

    Unlike :func:`find_last_state_write_site_snapshot`, this helper carries the
    path-local constant environment forward block by block. That preserves
    predecessor-specific constants across merge points, which is required when
    a semantic corridor converges before the state write.
    """

    path = tuple(int(serial) for serial in ordered_path)
    if not path:
        return None

    entry_serial = path[0]
    stk_map = dict((in_stk_maps or {}).get(entry_serial, {}))
    reg_map = dict((in_reg_maps or {}).get(entry_serial, {}))
    last_site: tuple[int, StateWriteSite] | None = None

    for block_serial in path:
        block = flow_graph.get_block(block_serial)
        if block is None:
            return last_site

        site = find_last_state_write_site_snapshot(
            flow_graph,
            block_serial,
            state_var_stkoff,
            initial_stk_map=stk_map,
            initial_reg_map=reg_map,
        )
        if site is not None:
            last_site = (int(block_serial), site)

        stk_map, reg_map = _transfer_snapshot_constant_block(
            block,
            stk_map,
            reg_map,
            state_var_stkoff,
        )

    return last_site


def find_terminal_exit_target_snapshot(
    flow_graph: FlowGraph,
    first_check_block: int,
    state_machine_blocks: set[int],
) -> int | None:
    """Find the first block outside the state machine that can reach a return."""

    first_check = flow_graph.get_block(first_check_block)
    if first_check is None:
        return None

    outside_successors = [
        succ for succ in first_check.succs if succ not in state_machine_blocks
    ]
    for succ in outside_successors:
        if can_reach_return_snapshot(flow_graph, succ):
            return succ

    for serial, blk in flow_graph.blocks.items():
        if _block_has_ret_tail(blk) and (
            blk.npred > 0 or can_reach_return_snapshot(flow_graph, blk.serial)
        ):
            return blk.serial

    max_serial = max(flow_graph.blocks.keys()) if flow_graph.blocks else None
    if max_serial is not None:
        stop_blk = flow_graph.get_block(max_serial)
        if stop_blk is not None and stop_blk.nsucc == 0:
            return stop_blk.serial

    return None


def init_bst_cmp_opcodes() -> frozenset:
    """Build the set of comparison opcodes for BST walking.

    The legacy name is kept for compatibility with tests and callers that
    monkeypatch ``_BST_CMP_OPCODES`` with synthetic opcode integers. The
    default remains the legacy numeric opcode set; portable
    ``BranchPredicate`` values are accepted in the walkers as an additive
    snapshot path.
    """

    return frozenset(_LEGACY_BRANCH_PREDICATE_OPCODES)


def eval_bst_condition(opcode: object, state: int, cmp_val: int) -> bool:
    """Evaluate a BST comparison: does the condition cause a jump?"""

    if not isinstance(opcode, str):
        try:
            opcode = _LEGACY_BRANCH_PREDICATE_OPCODES.get(int(opcode), opcode)
        except (TypeError, ValueError):
            pass

    if _kind_matches(opcode, BranchPredicate.NOT_EQUAL, "m_jnz"):
        return state != cmp_val
    if _kind_matches(opcode, BranchPredicate.EQUAL, "m_jz"):
        return state == cmp_val
    if _kind_matches(opcode, BranchPredicate.UNSIGNED_LE, "m_jbe"):
        return state <= cmp_val
    if _kind_matches(opcode, BranchPredicate.UNSIGNED_GT, "m_ja"):
        return state > cmp_val
    if _kind_matches(opcode, BranchPredicate.UNSIGNED_LT, "m_jb"):
        return state < cmp_val
    if _kind_matches(opcode, BranchPredicate.UNSIGNED_GE, "m_jae"):
        return state >= cmp_val
    return False


_BST_CMP_OPCODES: frozenset = frozenset()


def _is_bst_comparison_snapshot(
    block: object | None,
    *,
    state_var_ref: tuple[object, int | None] | None = None,
    state_var_stkoff: int | None = None,
) -> bool:
    """Return whether *block* continues the current BST comparison walk."""

    if block is None or getattr(block, "nsucc", 0) != 2:
        return False
    tail = _tail_insn(block)
    condition_key = _bst_condition_key_for_tail(tail)
    if condition_key is None:
        condition_key = getattr(tail, "opcode", getattr(block, "tail_opcode", None))
    if (
        condition_key not in _BST_CMP_OPCODES
        and condition_key not in _BST_BRANCH_PREDICATES
    ):
        return False
    l_mop = getattr(tail, "l", None)
    r_mop = getattr(tail, "r", None)
    if l_mop is None or r_mop is None:
        return False
    if not _is_number_operand(r_mop):
        return False
    if state_var_ref is not None:
        if _state_var_ref(l_mop) != state_var_ref:
            return False
        if (
            _tracks_bst_stack_offset(l_mop)
            and state_var_stkoff is not None
            and _stack_offset(l_mop) != state_var_stkoff
        ):
            return False
    return True


def _is_trivial_bst_connector_snapshot(
    block: object,
    flow_graph: FlowGraph,
    *,
    state_var_ref: tuple[object, int | None] | None = None,
    state_var_stkoff: int | None = None,
) -> bool:
    """Return whether *block* is only connector glue inside a dispatcher walk."""

    if getattr(block, "nsucc", 0) != 1:
        return False
    insns = tuple(getattr(block, "insn_snapshots", ()) or ())
    if not insns:
        pass
    elif len(insns) == 1:
        tail = _tail_insn(block)
        if not _is_goto_insn(tail):
            return False
    else:
        return False
    succs = tuple(getattr(block, "succs", ()) or ())
    if len(succs) != 1:
        return False
    return _is_bst_comparison_snapshot(
        flow_graph.get_block(int(succs[0])),
        state_var_ref=state_var_ref,
        state_var_stkoff=state_var_stkoff,
    )


def resolve_exit_via_bst_default_snapshot(
    flow_graph: FlowGraph,
    bst_default_serial: int,
    exit_state: int,
) -> int | None:
    """Resolve an exit state by walking BST comparison blocks via snapshots."""

    global _BST_CMP_OPCODES
    if not _BST_CMP_OPCODES:
        _BST_CMP_OPCODES = init_bst_cmp_opcodes()

    current_serial = bst_default_serial
    visited: set[int] = set()
    state_var_ref: tuple[object, int | None] | None = None
    state_var_stkoff_local: int | None = None

    while current_serial not in visited:
        visited.add(current_serial)

        blk_snap = flow_graph.get_block(current_serial)
        if (
            blk_snap is not None
            and current_serial != bst_default_serial
            and _is_trivial_bst_connector_snapshot(
                blk_snap,
                flow_graph,
                state_var_ref=state_var_ref,
                state_var_stkoff=state_var_stkoff_local,
            )
        ):
            current_serial = int(blk_snap.succs[0])
            continue
        if blk_snap is None or blk_snap.nsucc != 2:
            return current_serial if current_serial != bst_default_serial else None

        tail = _tail_insn(blk_snap)
        condition_key = _bst_condition_key_for_tail(tail)
        if condition_key is None:
            condition_key = getattr(tail, "opcode", None)
        if tail is None or (
            condition_key not in _BST_CMP_OPCODES
            and condition_key not in _BST_BRANCH_PREDICATES
        ):
            return current_serial if current_serial != bst_default_serial else None

        r_mop = tail.r
        if r_mop is None or not _is_number_operand(r_mop):
            return current_serial if current_serial != bst_default_serial else None

        l_mop = tail.l
        if l_mop is None:
            return current_serial if current_serial != bst_default_serial else None

        if state_var_ref is None:
            state_var_ref = _state_var_ref(l_mop)
            if _tracks_bst_stack_offset(l_mop):
                state_var_stkoff_local = _stack_offset(l_mop)
        else:
            if _state_var_ref(l_mop) != state_var_ref:
                logger.info(
                    "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                    exit_state,
                    current_serial,
                    l_mop.t,
                )
                return current_serial if current_serial != bst_default_serial else None
            if (
                _tracks_bst_stack_offset(l_mop)
                and state_var_stkoff_local != _stack_offset(l_mop)
            ):
                logger.info(
                    "  exit %#x: blk[%d] compares different stkoff=%s, stopping",
                    exit_state,
                    current_serial,
                    getattr(l_mop, "stkoff", None),
                )
                return current_serial if current_serial != bst_default_serial else None

        cmp_val = _constant_operand_value(r_mop)
        if cmp_val is None:
            return current_serial if current_serial != bst_default_serial else None
        cond_taken = eval_bst_condition(condition_key, exit_state, cmp_val)

        if cond_taken:
            next_serial = blk_snap.succs[1]
        else:
            next_serial = blk_snap.succs[0]

        if next_serial == current_serial:
            return current_serial if current_serial != bst_default_serial else None

        current_serial = next_serial

    return None


def detect_terminal_state_families_snapshot(
    flow_graph: FlowGraph,
    dispatcher_blocks: set[int],
    side_effect_blocks: set[int] | None = None,
) -> set[int]:
    """Identify the **terminal cone** — dispatcher blocks whose resolution
    would collapse branches feeding the terminal cleanup/return path.

    1. Find **boundary blocks**: dispatcher blocks with a non-dispatcher arm
       that reaches ``BLT_STOP`` via restricted BFS **and** the path
       passes through at least one block with side effects (calls, stores).
       This distinguishes cleanup regions (printf, CloseHandle) from simple
       BST-to-exit fallthroughs.
    2. Expand to the **reverse predecessor cone**: walk backwards through
       dispatcher-block predecessors of the boundary.

    FixPredCondJump should skip patches for blocks in this cone.
    """
    _se = side_effect_blocks or set()

    # --- Step 1: find direct boundary blocks ---
    terminal_boundary: set[int] = set()

    for serial in dispatcher_blocks:
        blk_snap = flow_graph.get_block(serial)
        if blk_snap is None or blk_snap.nsucc != 2:
            continue

        for arm in blk_snap.succs:
            if arm in dispatcher_blocks:
                continue
            if _restricted_reach_stop_with_side_effects(
                flow_graph, arm, dispatcher_blocks, _se,
            ):
                terminal_boundary.add(serial)
                logger.info(
                    "[TERMINAL-FAMILY] blk[%d] arm→blk[%d] reaches "
                    "BLT_STOP via side-effecting cleanup — terminal boundary",
                    serial, arm,
                )
                break

    if not terminal_boundary:
        return terminal_boundary

    # --- Step 2: reverse predecessor cone ---
    # Walk backwards from boundary blocks through dispatcher predecessors.
    # --- Step 2: reverse predecessor cone ---
    cone = set(terminal_boundary)
    queue = list(terminal_boundary)
    while queue:
        serial = queue.pop(0)
        blk_snap = flow_graph.get_block(serial)
        if blk_snap is None:
            continue
        for pred in blk_snap.preds:
            if pred in cone:
                continue
            if pred not in dispatcher_blocks:
                continue
            cone.add(pred)
            queue.append(pred)

    # If the cone reached a dispatcher root, the terminal chain is the
    # primary spine of that root's component.  Expand the cone to cover
    # ALL dispatcher blocks reachable from that root (forward BFS within
    # dispatchers) to avoid INTERR 50858 from partially resolving
    # interleaved control-flow blocks (e.g. m_jge loops).
    # Only the triggering root's component is protected — unrelated
    # dispatcher components are left alone.
    dispatcher_roots = {
        blk_id for blk_id in dispatcher_blocks
        if all(
            pred not in dispatcher_blocks
            for pred in (flow_graph.get_block(blk_id).preds
                         if flow_graph.get_block(blk_id) is not None else ())
        )
    }
    reached_roots = dispatcher_roots & cone
    if reached_roots:
        # Forward BFS from each reached root through ALL edges, but only
        # collect dispatcher blocks.  This captures interleaved non-BST
        # dispatcher blocks (e.g. for-loop conditions between BST nodes)
        # that are reachable via handler body intermediates.
        component: set[int] = set()
        visited_comp: set[int] = set()
        comp_queue = list(reached_roots)
        while comp_queue:
            s = comp_queue.pop(0)
            if s in visited_comp:
                continue
            visited_comp.add(s)
            if s in dispatcher_blocks:
                component.add(s)
            blk_s = flow_graph.get_block(s)
            if blk_s is None:
                continue
            for succ in blk_s.succs:
                if succ not in visited_comp:
                    comp_queue.append(succ)
        cone = component
        logger.info(
            "[TERMINAL-CONE] cone reached root(s) %s, guarding "
            "component of %d dispatcher blocks (total dispatchers=%d)",
            sorted(reached_roots), len(cone), len(dispatcher_blocks),
        )

    logger.info(
        "[TERMINAL-CONE] boundary=%s cone=%s (%d blocks)",
        sorted(terminal_boundary),
        sorted(cone),
        len(cone),
    )
    return cone


def _restricted_reach_stop_with_side_effects(
    flow_graph: FlowGraph,
    start: int,
    forbidden: set[int],
    side_effect_blocks: set[int],
    max_depth: int = 80,
) -> bool:
    """BFS from *start* to BLT_STOP, requiring side effects on the path.

    Returns True only if a path to BLT_STOP exists AND at least one block
    on the path has side effects (calls, stores).  This distinguishes
    cleanup regions (hodur_func: printf, CloseHandle) from simple
    BST-to-exit fallthroughs (direct return, no side effects).
    """
    visited: set[int] = set()
    queue = [start]
    found_stop = False
    found_side_effect = False
    while queue and len(visited) < max_depth:
        serial = queue.pop(0)
        if serial in visited or serial in forbidden:
            continue
        visited.add(serial)
        blk = flow_graph.get_block(serial)
        if blk is None:
            continue
        if serial in side_effect_blocks:
            found_side_effect = True
        if _is_stop_block(blk):
            found_stop = True
            break
        for succ in blk.succs:
            if succ not in visited and succ not in forbidden:
                queue.append(succ)
    return found_stop and found_side_effect


def _restricted_reach_stop(
    flow_graph: FlowGraph,
    start: int,
    forbidden: set[int],
    max_depth: int = 80,
) -> bool:
    """BFS from *start* to BLT_STOP, not re-entering *forbidden* blocks."""
    visited: set[int] = set()
    queue = [start]
    while queue and len(visited) < max_depth:
        serial = queue.pop(0)
        if serial in visited or serial in forbidden:
            continue
        visited.add(serial)
        blk = flow_graph.get_block(serial)
        if blk is None:
            continue
        if _is_stop_block(blk):
            return True
        for s in blk.succs:
            if s not in visited and s not in forbidden:
                queue.append(s)
    return False


def detect_conditional_transitions(
    handler_entry: int,
    paths: list[HandlerPathResult],
    state_constants: set[int],
    flow_graph: FlowGraph,
    incoming_state: int | None = None,
) -> list[ConditionalTransition]:
    """Detect intra-handler conditional branches where one arm is a state transition."""

    if len(paths) < 2:
        return []

    all_ordered_paths = [p.ordered_path for p in paths]
    results: list[ConditionalTransition] = []

    for path in paths:
        if path.final_state is None:
            continue
        if (path.final_state & 0xFFFFFFFF) not in state_constants:
            continue
        if not path.state_writes:
            continue
        if len(path.ordered_path) < 2:
            continue

        if incoming_state is not None and (path.final_state & 0xFFFFFFFF) == (
            incoming_state & 0xFFFFFFFF
        ):
            logger.info(
                "detect_conditional_transitions: skipping self-loop path "
                "handler=blk[%d] final_state=0x%X == incoming_state=0x%X",
                handler_entry,
                path.final_state,
                incoming_state,
            )
            continue

        other_paths = [op for op in all_ordered_paths if op is not path.ordered_path]
        if not other_paths:
            continue

        this_op = path.ordered_path
        max_prefix_len = 0
        for other_op in other_paths:
            prefix_len = 0
            for i in range(min(len(this_op), len(other_op))):
                if this_op[i] == other_op[i]:
                    prefix_len += 1
                else:
                    break
            if prefix_len > max_prefix_len:
                max_prefix_len = prefix_len

        if max_prefix_len < 1:
            continue

        divergence_block = None
        branch_arm = None

        for candidate_len in range(max_prefix_len, 0, -1):
            if candidate_len >= len(this_op):
                continue

            cand_block = this_op[candidate_len - 1]
            cand_next = this_op[candidate_len]
            cand_snap = flow_graph.get_block(cand_block)
            if cand_snap is None or len(cand_snap.succs) != 2:
                continue

            if cand_next == cand_snap.succs[0]:
                arm = 0
            elif cand_next == cand_snap.succs[1]:
                arm = 1
            else:
                continue

            has_diverging_sibling = False
            for other_op in other_paths:
                if (
                    candidate_len - 1 < len(other_op)
                    and other_op[candidate_len - 1] == cand_block
                ):
                    if candidate_len < len(other_op) and other_op[candidate_len] != cand_next:
                        has_diverging_sibling = True
                        break
                elif candidate_len - 1 >= len(other_op):
                    has_diverging_sibling = True
                    break

            if has_diverging_sibling:
                divergence_block = cand_block
                branch_arm = arm
                break

        if divergence_block is None or branch_arm is None:
            continue

        write_blk, write_ea = path.state_writes[0]
        results.append(
            ConditionalTransition(
                handler_entry=handler_entry,
                branch_block=divergence_block,
                target_state=path.final_state & 0xFFFFFFFF,
                target_handler=None,
                state_write_block=write_blk,
                state_write_ea=write_ea,
                branch_arm=branch_arm,
            )
        )

    return results


def evaluate_handler_paths(
    mba: object,
    entry_serial: int,
    incoming_state: int,
    bst_node_blocks: set[int],
    state_var_stkoff: int,
    handler_entry_blocks: set[int] | None = None,
    *,
    flow_graph: "FlowGraph | None" = None,
    known_handler_states: "set[int] | None" = None,
    bst_root_serial: "int | None" = None,
    state_machine_blocks: "set[int] | None" = None,
    use_snapshot_state_writes: bool = True,
    classify_bst_exits: bool = True,
) -> list[HandlerPathResult]:
    """DFS forward eval of a handler, forking state at conditional branches.

    When *flow_graph*, *known_handler_states*, *bst_root_serial*, and
    *state_machine_blocks* are provided, exits whose resolved BST target
    lands outside the state machine and can reach a return are emitted as
    **terminal** paths (``final_state=None``) rather than state handoffs.
    """

    results: list[HandlerPathResult] = []
    queue: list[tuple[int, dict, dict, frozenset, list, list]] = [
        (
            entry_serial,
            {},
            {state_var_stkoff: incoming_state},
            frozenset(),
            [],
            [entry_serial],
        ),
    ]

    while queue:
        curr_serial, reg_map, stk_map, path_visited, state_writes, ordered_path = (
            queue.pop()
        )

        if curr_serial in path_visited:
            continue
        path_visited = path_visited | {curr_serial}

        if curr_serial >= mba.qty:
            break

        blk = mba.get_mblock(curr_serial)

        cur_writes = list(state_writes)
        insn = blk.head
        while insn is not None:
            old_val = stk_map.get(state_var_stkoff)
            _forward_eval_insn(
                insn,
                stk_map,
                reg_map,
                state_var_stkoff,
                mba=mba,
            )
            new_val = stk_map.get(state_var_stkoff)
            if new_val != old_val:
                cur_writes.append((curr_serial, insn.ea))
            insn = insn.next

        succs = [blk.succ(i) for i in range(blk.nsucc())]

        snapshot_state_resolved = False
        snapshot_final_state: int | None = None
        snapshot_state_writes: list | None = None

        def _resolved_final_state_and_writes() -> tuple[int | None, list]:
            """Return the best path-local state value known at this exit.

            Live Hex-Rays evaluation is still the primary source. OLLVM/HCC
            handlers can, however, choose the next dispatcher state through a
            branch-local temporary and only copy that temporary into the state
            variable at a shared suffix block. At that point live lvar identity
            may not line up with the stack-offset map, so the live walk can miss
            the actual state write or leave the incoming state in place. The CFG
            snapshot keeps richer operand-slot data and can replay the concrete
            ordered path, preserving the branch-local temporary until the shared
            state assignment. When the snapshot proves such a write on this same
            path, prefer it over a stale/missing live value.
            """

            live_val = stk_map.get(state_var_stkoff)
            nonlocal snapshot_state_resolved
            nonlocal snapshot_final_state
            nonlocal snapshot_state_writes

            if not snapshot_state_resolved:
                snapshot_state_resolved = True
                snapshot_state_writes = list(cur_writes)
                if use_snapshot_state_writes and flow_graph is not None:
                    resolved = find_last_state_write_site_on_path_snapshot(
                        flow_graph,
                        ordered_path,
                        state_var_stkoff,
                    )
                    if resolved is not None:
                        write_blk, site = resolved
                        snapshot_final_state = int(site.state_value) & 0xFFFFFFFF
                        write_sig = (int(write_blk), int(site.insn_ea))
                        existing_writes = {
                            (int(block), int(ea)) for block, ea in snapshot_state_writes
                        }
                        if write_sig not in existing_writes:
                            snapshot_state_writes.append(write_sig)

            if snapshot_final_state is None:
                return live_val, list(cur_writes)

            if live_val is None:
                return snapshot_final_state, list(snapshot_state_writes or cur_writes)

            if (live_val & 0xFFFFFFFF) != snapshot_final_state:
                return snapshot_final_state, list(snapshot_state_writes or cur_writes)

            return live_val, list(cur_writes)

        if not succs:
            final_val, final_writes = _resolved_final_state_and_writes()
            if (
                final_val is not None
                and final_writes
                and known_handler_states is not None
                and (final_val & 0xFFFFFFFF)
                in {state & 0xFFFFFFFF for state in known_handler_states}
            ):
                results.append(
                    HandlerPathResult(
                        exit_block=curr_serial,
                        final_state=final_val & 0xFFFFFFFF,
                        state_writes=list(final_writes),
                        ordered_path=list(ordered_path),
                    )
                )
                continue
            results.append(
                HandlerPathResult(
                    exit_block=curr_serial,
                    final_state=None,
                    state_writes=list(cur_writes),
                    ordered_path=list(ordered_path),
                )
            )
            continue

        for succ_serial in succs:
            if (
                handler_entry_blocks
                and succ_serial in handler_entry_blocks
                and succ_serial != entry_serial
            ):
                final_val, final_writes = _resolved_final_state_and_writes()
                if final_val is not None:
                    # If the current state equals incoming (self-loop default
                    # write), the shared suffix may overwrite it.  Continue
                    # into the successor instead of terminating early.
                    if (
                        incoming_state is not None
                        and (final_val & 0xFFFFFFFF) == (incoming_state & 0xFFFFFFFF)
                        and succ_serial not in path_visited
                        and succ_serial not in bst_node_blocks
                    ):
                        # Self-loop default write — shared suffix may
                        # overwrite with the real exit state.
                        new_ordered = ordered_path + [succ_serial]
                        queue.append(
                            (
                                succ_serial,
                                dict(reg_map),
                                dict(stk_map),
                                path_visited,
                                list(cur_writes),
                                new_ordered,
                            )
                        )
                    elif (
                        succ_serial not in path_visited
                        and succ_serial not in bst_node_blocks
                        and classify_exit_state(
                            mba, final_val, incoming_state,
                            succ_serial, state_var_stkoff,
                            bst_node_blocks,
                        ) == ExitStateKind.TRANSIENT_CORRIDOR
                    ):
                        # Transient corridor: successor overwrites state
                        # before any side effect.  Continue DFS.
                        new_ordered = ordered_path + [succ_serial]
                        queue.append(
                            (
                                succ_serial,
                                dict(reg_map),
                                dict(stk_map),
                                path_visited,
                                list(cur_writes),
                                new_ordered,
                            )
                        )
                    else:
                        results.append(
                            HandlerPathResult(
                                exit_block=curr_serial,
                                final_state=final_val & 0xFFFFFFFF,
                                state_writes=list(final_writes),
                                ordered_path=list(ordered_path),
                            )
                        )
            elif succ_serial in bst_node_blocks:
                final_val, final_writes = _resolved_final_state_and_writes()
                if final_val is not None:
                    masked = final_val & 0xFFFFFFFF
                    # --- Terminal classification ---
                    # If the exit state is NOT a known handler and we
                    # have enough context, resolve through the BST to
                    # check whether it reaches cleanup/return.
                    _is_terminal = False
                    if (
                        classify_bst_exits
                        and
                        known_handler_states is not None
                        and masked not in known_handler_states
                        and flow_graph is not None
                        and bst_root_serial is not None
                    ):
                        _sm_blks = state_machine_blocks or bst_node_blocks
                        _resolved, _resolved_kind, _is_terminal = (
                            _resolved_bst_exit_kind(
                                mba,
                                flow_graph,
                                bst_root_serial=bst_root_serial,
                                state_value=masked,
                                incoming_state=incoming_state,
                                state_var_stkoff=state_var_stkoff,
                                bst_node_blocks=bst_node_blocks,
                                state_machine_blocks=set(_sm_blks),
                            )
                        )
                        if _resolved is not None and _resolved not in _sm_blks:
                            if _is_terminal:
                                logger.info(
                                    "  [BST-TERMINAL] entry=%d curr=%d "
                                    "state=0x%08X resolved=blk[%d] kind=%s "
                                    "→ terminal",
                                    entry_serial, curr_serial, masked,
                                    _resolved,
                                    (
                                        _resolved_kind.value
                                        if _resolved_kind is not None
                                        else "unclassified"
                                    ),
                                )
                            else:
                                logger.info(
                                    "  [BST-HANDOFF] entry=%d curr=%d "
                                    "state=0x%08X resolved=blk[%d] kind=%s "
                                    "→ keep state handoff",
                                    entry_serial, curr_serial, masked,
                                    _resolved,
                                    (
                                        _resolved_kind.value
                                        if _resolved_kind is not None
                                        else "unclassified"
                                    ),
                                )

                    if _is_terminal:
                        results.append(
                            HandlerPathResult(
                                exit_block=curr_serial,
                                final_state=None,
                                state_writes=list(final_writes),
                                ordered_path=list(ordered_path),
                            )
                        )
                    else:
                        results.append(
                            HandlerPathResult(
                                exit_block=curr_serial,
                                final_state=masked,
                                state_writes=list(final_writes),
                                ordered_path=list(ordered_path),
                            )
                        )
            else:
                new_ordered = ordered_path + [succ_serial]
                queue.append(
                    (
                        succ_serial,
                        dict(reg_map),
                        dict(stk_map),
                        path_visited,
                        list(cur_writes),
                        new_ordered,
                    )
                )

    return results
