"""State-machine path analysis helpers shared across recon and Hodur."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

import ida_hexrays

from d810.core import logging
from d810.core.typing import TYPE_CHECKING, Optional
from d810.recon.flow.bst_analysis import _forward_eval_insn

if TYPE_CHECKING:
    from d810.cfg.flowgraph import FlowGraph

logger = logging.getLogger(__name__)

__all__ = [
    "CarrierResolutionResult",
    "ConditionalTransition",
    "HandlerPathResult",
    "ResolutionMethod",
    "can_reach_return_snapshot",
    "detect_conditional_transitions",
    "eval_bst_condition",
    "evaluate_handler_paths",
    "find_terminal_exit_target_snapshot",
    "init_bst_cmp_opcodes",
    "resolve_exit_via_bst_default_snapshot",
]


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
