"""State-machine path analysis helpers shared across recon and Hodur."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from types import SimpleNamespace

import ida_hexrays

from d810.cfg.flowgraph import FlowGraph, InsnSnapshot
from d810.core import logging
from d810.core.typing import Optional
from d810.recon.flow.bst_analysis import _forward_eval_insn

logger = logging.getLogger(__name__)

__all__ = [
    "CarrierResolutionResult",
    "ConditionalTransition",
    "HandlerPathResult",
    "ResolutionMethod",
    "SnapshotConstantFixpointResult",
    "StateWriteSite",
    "build_mba_view_from_flow_graph",
    "can_reach_return_snapshot",
    "detect_conditional_transitions",
    "eval_bst_condition",
    "evaluate_handler_paths",
    "find_last_state_write_site_snapshot",
    "find_state_write_sites_snapshot",
    "find_terminal_exit_target_snapshot",
    "init_bst_cmp_opcodes",
    "resolve_exit_via_bst_default_snapshot",
    "run_snapshot_constant_fixpoint",
]


class _InsnView:
    __slots__ = ("opcode", "ea", "l", "r", "d", "next")

    def __init__(self, insn: InsnSnapshot):
        self.opcode = insn.opcode
        self.ea = insn.ea
        self.l = insn.l
        self.r = insn.r
        self.d = insn.d
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
    branch_arm: int
    is_terminal_no_write: bool = False


@dataclass(frozen=True, slots=True)
class StateWriteSite:
    """A resolved write to the dispatcher state variable in one snapshot block."""

    block_serial: int
    state_value: int
    insn_ea: int
    insn_index: int
    trailing_insn_eas: tuple[int, ...] = ()
    trailing_opcodes: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class SnapshotConstantFixpointResult:
    """Conservative exact-constant facts at block boundaries for snapshots."""

    in_stk_maps: dict[int, dict[int, int]]
    in_reg_maps: dict[int, dict[int, int]]
    out_stk_maps: dict[int, dict[int, int]]
    out_reg_maps: dict[int, dict[int, int]]
    iterations: int


def _kill_constant_dest_snapshot(
    dest: object | None,
    stk_map: dict[int, int],
    reg_map: dict[int, int],
) -> None:
    """Forget a written destination when its new value is not provably constant."""

    if dest is None:
        return

    mop_type = getattr(dest, "t", None)
    if mop_type == getattr(ida_hexrays, "mop_S", None):
        stkoff = getattr(dest, "stkoff", None)
        if stkoff is None:
            stack_ref = getattr(dest, "s", None)
            stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
        if stkoff is not None:
            stk_map.pop(int(stkoff), None)
        return

    if mop_type == getattr(ida_hexrays, "mop_r", None):
        reg = getattr(dest, "r", None)
        if reg is None:
            reg = getattr(dest, "reg", None)
        if reg is not None:
            reg_map.pop(int(reg), None)


def _constant_dest_locator_snapshot(dest: object | None) -> tuple[str, int] | None:
    """Return a stable locator for stack/register destinations in snapshots."""

    if dest is None:
        return None
    mop_type = getattr(dest, "t", None)
    if mop_type == getattr(ida_hexrays, "mop_S", None):
        stkoff = getattr(dest, "stkoff", None)
        if stkoff is None:
            stack_ref = getattr(dest, "s", None)
            stkoff = getattr(stack_ref, "off", None) if stack_ref is not None else None
        if stkoff is not None:
            return ("stk", int(stkoff))
        return None

    if mop_type == getattr(ida_hexrays, "mop_r", None):
        reg = getattr(dest, "r", None)
        if reg is None:
            reg = getattr(dest, "reg", None)
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
    """BFS to check if *start_serial* can reach an m_ret block via snapshots."""

    m_ret = ida_hexrays.m_ret
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
        if blk.tail_opcode is not None and blk.tail_opcode == m_ret:
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
        sites.append(
            StateWriteSite(
                block_serial=block_serial,
                state_value=resolved_state & 0xFFFFFFFF,
                insn_ea=int(insn.ea),
                insn_index=index,
                trailing_insn_eas=tuple(int(tail.ea) for tail in trailing),
                trailing_opcodes=tuple(int(tail.opcode) for tail in trailing),
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


def find_terminal_exit_target_snapshot(
    flow_graph: FlowGraph,
    first_check_block: int,
    state_machine_blocks: set[int],
) -> int | None:
    """Find the first block outside the state machine that can reach a return."""

    m_ret = ida_hexrays.m_ret

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
        if blk.tail_opcode is None:
            continue
        if blk.tail_opcode == m_ret and (
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
    """Build the set of comparison opcodes for BST walking."""

    return frozenset(
        {
            ida_hexrays.m_jnz,
            ida_hexrays.m_jz,
            ida_hexrays.m_jbe,
            ida_hexrays.m_ja,
            ida_hexrays.m_jb,
            ida_hexrays.m_jae,
        }
    )


def eval_bst_condition(opcode: int, state: int, cmp_val: int) -> bool:
    """Evaluate a BST comparison: does the condition cause a jump?"""

    if opcode == ida_hexrays.m_jnz:
        return state != cmp_val
    if opcode == ida_hexrays.m_jz:
        return state == cmp_val
    if opcode == ida_hexrays.m_jbe:
        return state <= cmp_val
    if opcode == ida_hexrays.m_ja:
        return state > cmp_val
    if opcode == ida_hexrays.m_jb:
        return state < cmp_val
    if opcode == ida_hexrays.m_jae:
        return state >= cmp_val
    return False


_BST_CMP_OPCODES: frozenset = frozenset()


def resolve_exit_via_bst_default_snapshot(
    flow_graph: FlowGraph,
    bst_default_serial: int,
    exit_state: int,
) -> int | None:
    """Resolve an exit state by walking BST comparison blocks via snapshots."""

    global _BST_CMP_OPCODES
    if not _BST_CMP_OPCODES:
        _BST_CMP_OPCODES = init_bst_cmp_opcodes()

    MOP_N = 2
    MOP_S = 3

    current_serial = bst_default_serial
    visited: set[int] = set()
    state_var_ref: tuple[int, int] | None = None
    state_var_stkoff_local: int | None = None

    while current_serial not in visited:
        visited.add(current_serial)

        blk_snap = flow_graph.get_block(current_serial)
        if blk_snap is None or blk_snap.nsucc != 2:
            return current_serial if current_serial != bst_default_serial else None

        tail = blk_snap.tail
        if tail is None or tail.opcode not in _BST_CMP_OPCODES:
            return current_serial if current_serial != bst_default_serial else None

        r_mop = tail.r
        if r_mop is None or r_mop.t != MOP_N:
            return current_serial if current_serial != bst_default_serial else None

        l_mop = tail.l
        if l_mop is None:
            return current_serial if current_serial != bst_default_serial else None

        if state_var_ref is None:
            state_var_ref = (l_mop.t, l_mop.size)
            if l_mop.t == MOP_S:
                state_var_stkoff_local = l_mop.stkoff
        else:
            if (l_mop.t, l_mop.size) != state_var_ref:
                logger.info(
                    "  exit %#x: blk[%d] compares non-state-var (mop_t=%d), stopping",
                    exit_state,
                    current_serial,
                    l_mop.t,
                )
                return current_serial if current_serial != bst_default_serial else None
            if l_mop.t == MOP_S and state_var_stkoff_local != l_mop.stkoff:
                logger.info(
                    "  exit %#x: blk[%d] compares different stkoff=%s, stopping",
                    exit_state,
                    current_serial,
                    getattr(l_mop, "stkoff", None),
                )
                return current_serial if current_serial != bst_default_serial else None

        cmp_val = r_mop.nnn_value
        cond_taken = eval_bst_condition(tail.opcode, exit_state, cmp_val)

        if cond_taken:
            next_serial = blk_snap.succs[1]
        else:
            next_serial = blk_snap.succs[0]

        if next_serial == current_serial:
            return current_serial if current_serial != bst_default_serial else None

        current_serial = next_serial

    return None


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
) -> list[HandlerPathResult]:
    """DFS forward eval of a handler, forking state at conditional branches."""

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

        if not succs:
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
                final_val = stk_map.get(state_var_stkoff)
                if final_val is not None:
                    results.append(
                        HandlerPathResult(
                            exit_block=curr_serial,
                            final_state=final_val & 0xFFFFFFFF,
                            state_writes=cur_writes,
                            ordered_path=list(ordered_path),
                        )
                    )
            elif succ_serial in bst_node_blocks:
                final_val = stk_map.get(state_var_stkoff)
                if final_val is not None:
                    results.append(
                        HandlerPathResult(
                            exit_block=curr_serial,
                            final_state=final_val & 0xFFFFFFFF,
                            state_writes=cur_writes,
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
