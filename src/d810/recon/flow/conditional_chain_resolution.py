"""Enriched conditional-chain resolution with deep emulation fallback."""

from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.algorithm_metadata import algorithm_metadata
from d810.evaluator.hexrays_microcode.def_search import resolve_mop_via_predecessors
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.evaluator.hexrays_microcode.tracker import (
    InstructionDefUseCollector,
    remove_segment_registers,
)
from d810.hexrays.utils.hexrays_helpers import (
    append_mop_if_not_in_list,
    equal_mops_ignore_size,
    get_mop_index,
)
from d810.recon.flow.conditional_chain_discovery import (
    extract_check_constant_from_snapshot,
    find_conditional_predecessor,
    get_successor_into_dispatcher,
    resolve_conditional_chain_target,
)


@dataclass(frozen=True, slots=True)
class ConditionalForkResolutionCandidate:
    """One resolved conditional fork with concrete arm targets."""

    from_block: int
    cond_block: int
    taken_target: int
    fallthrough_target: int
    states: tuple[int, int]
    owned_transitions: tuple[tuple[int, int], ...] = ()


def _collect_ladder_use_before_def(
    mba: object,
    dispatcher_set: set[int],
    entry_serial: int,
    flow_graph: object,
) -> list:
    """Collect unresolved mops used-before-defined inside the dispatcher ladder."""
    use_list: list = []
    def_list: list = []
    use_before_def: list = []

    reachable: set[int] = set()
    queue = [int(entry_serial)]
    while queue:
        curr = queue.pop(0)
        if curr in reachable or curr not in dispatcher_set:
            continue
        reachable.add(curr)
        blk_snap = flow_graph.get_block(curr)
        if blk_snap is not None:
            for succ in getattr(blk_snap, "succs", ()):
                queue.append(int(succ))

    for serial in sorted(reachable):
        blk = mba.get_mblock(serial)
        if blk is None:
            continue
        cur_ins = blk.head
        while cur_ins is not None:
            collector = InstructionDefUseCollector()
            cur_ins.for_all_ops(collector)
            cleaned = remove_segment_registers(collector.unresolved_ins_mops)
            for mop_used in cleaned + list(collector.memory_unresolved_ins_mops):
                append_mop_if_not_in_list(mop_used, use_list)
                if get_mop_index(mop_used, def_list) == -1:
                    append_mop_if_not_in_list(mop_used, use_before_def)
            for mop_def in collector.target_mops:
                append_mop_if_not_in_list(mop_def, def_list)
            cur_ins = cur_ins.next

    return [
        mop for mop in use_before_def if mop.t in (ida_hexrays.mop_r, ida_hexrays.mop_S)
    ]


def _emulate_chain_exit(
    mba: object,
    entry_block_serial: int,
    state_value: int,
    state_var: object,
    dispatcher_set: set[int],
    use_before_def: list,
    from_block_serial: int,
    *,
    max_instructions: int = 5000,
) -> int | None:
    """Emulate one state through the dispatcher ladder until it exits."""
    cur_blk = mba.get_mblock(int(entry_block_serial))
    if cur_blk is None:
        return None

    interpreter = MicroCodeInterpreter(symbolic_mode=False)
    env = MicroCodeEnvironment()
    try:
        env.define(state_var, int(state_value))
    except Exception:
        return None

    from_blk = mba.get_mblock(int(from_block_serial))
    if from_blk is None:
        return None

    for mop in use_before_def:
        if state_var is not None and equal_mops_ignore_size(mop, state_var):
            continue
        ast = resolve_mop_via_predecessors(mop, from_blk, from_blk.tail)
        if ast is None or not hasattr(ast, "value") or ast.value is None:
            return None
        try:
            env.define(mop, int(ast.value))
        except Exception:
            return None

    cur_ins = cur_blk.head
    visited: set[int] = set()
    nb_emulated = 0

    while cur_blk is not None:
        if cur_ins is None:
            cur_ins = cur_blk.head
        if cur_ins is None:
            return None
        if cur_blk.serial in visited:
            return None
        visited.add(cur_blk.serial)

        is_ok = interpreter.eval_instruction(
            cur_blk,
            cur_ins,
            env,
            raise_exception=False,
        )
        if not is_ok:
            return None
        nb_emulated += 1
        if nb_emulated >= max_instructions:
            return None

        next_blk = env.next_blk
        next_ins = env.next_ins
        if next_blk is None:
            return None
        if next_blk.serial not in dispatcher_set:
            return int(next_blk.serial)
        cur_blk = next_blk
        cur_ins = next_ins

    return None


@algorithm_metadata(
    algorithm_id="recon.collect_conditional_fork_resolution_candidates",
    family="conditional_fork_resolution",
    summary="Resolves both arms of conditional state forks from chain walk or emulation.",
    use_cases=(
        "Recover concrete taken/fallthrough targets when one handler writes two successor states.",
        "Bridge dispatcher-ladder gaps with emulation when static chain walking cannot resolve a fork arm.",
    ),
    examples=(
        "Turn a conditional state fork into a candidate with concrete taken and fallthrough handler targets.",
        "Emulate a dispatcher ladder entry when one arm exits the ladder without a directly readable constant.",
    ),
    tags=("conditional", "fork", "emulation", "dispatcher", "reconstruction"),
    related_paths=(
        "src/d810/recon/flow/conditional_chain_resolution.py",
        "src/d810/optimizers/microcode/flow/flattening/hodur/strategies/conditional_fork_fallback.py",
    ),
)
def collect_conditional_fork_resolution_candidates(
    snapshot: object,
    *,
    conditional_opcodes: tuple[int, ...] | list[int],
    normalize_reversed_jump_opcode: object,
    is_jump_taken_for_state: object,
) -> tuple[ConditionalForkResolutionCandidate, ...]:
    """Resolve conditional fork arm targets from static chain walk or emulation."""
    if not callable(is_jump_taken_for_state):
        return ()

    mba = getattr(snapshot, "mba", None)
    fg = getattr(snapshot, "flow_graph", None)
    sm = getattr(snapshot, "state_machine", None)
    if mba is None or fg is None or sm is None:
        return ()

    transitions = tuple(getattr(sm, "transitions", ()) or ())
    dispatcher_set = {
        int(check_block)
        for handler in (getattr(sm, "handlers", None) or {}).values()
        if (check_block := getattr(handler, "check_block", None)) is not None
    }
    state_var = getattr(sm, "state_var", None)

    conditional_groups: dict[int, list] = {}
    for transition in transitions:
        if not getattr(transition, "is_conditional", False):
            continue
        from_block = getattr(transition, "from_block", None)
        if from_block is None:
            continue
        conditional_groups.setdefault(int(from_block), []).append(transition)

    candidates: list[ConditionalForkResolutionCandidate] = []
    for from_blk_serial, group_transitions in conditional_groups.items():
        unique_states = sorted(
            {
                int(to_state)
                for transition in group_transitions
                if (to_state := getattr(transition, "to_state", None)) is not None
            }
        )
        if len(unique_states) != 2:
            continue

        cond_block = find_conditional_predecessor(
            from_blk_serial,
            fg,
            conditional_opcodes=conditional_opcodes,
        )
        if cond_block is None:
            continue

        state_a, state_b = unique_states
        target_a = resolve_conditional_chain_target(
            cond_block,
            state_a,
            fg,
            conditional_opcodes=conditional_opcodes,
            normalize_reversed_jump_opcode=normalize_reversed_jump_opcode,
            is_jump_taken_for_state=is_jump_taken_for_state,
        )
        target_b = resolve_conditional_chain_target(
            cond_block,
            state_b,
            fg,
            conditional_opcodes=conditional_opcodes,
            normalize_reversed_jump_opcode=normalize_reversed_jump_opcode,
            is_jump_taken_for_state=is_jump_taken_for_state,
        )

        if target_a is None or target_b is None:
            if dispatcher_set and state_var is not None:
                use_before_def = _collect_ladder_use_before_def(
                    mba,
                    dispatcher_set,
                    cond_block,
                    fg,
                )
                ladder_entry = get_successor_into_dispatcher(
                    dispatcher_set,
                    fg,
                    from_blk_serial,
                )
                if ladder_entry is not None:
                    try:
                        if target_a is None:
                            target_a = _emulate_chain_exit(
                                mba,
                                ladder_entry,
                                state_a,
                                state_var,
                                dispatcher_set,
                                use_before_def,
                                from_blk_serial,
                            )
                        if target_b is None:
                            target_b = _emulate_chain_exit(
                                mba,
                                ladder_entry,
                                state_b,
                                state_var,
                                dispatcher_set,
                                use_before_def,
                                from_blk_serial,
                            )
                    except Exception:
                        pass
            if target_a is None or target_b is None:
                continue

        cond_snap = fg.get_block(int(cond_block))
        if (
            cond_snap is None
            or getattr(cond_snap, "tail_opcode", None) is None
            or cond_snap.tail_opcode not in conditional_opcodes
        ):
            continue

        cond_tail = getattr(cond_snap, "tail", None)
        if cond_tail is None:
            continue
        check_info = extract_check_constant_from_snapshot(
            cond_tail,
            normalize_reversed_jump_opcode=normalize_reversed_jump_opcode,
        )
        if check_info is None:
            continue
        check_opcode, check_const, check_size = check_info

        jt_a = is_jump_taken_for_state(
            check_opcode,
            int(state_a),
            check_const,
            check_size,
        )
        if jt_a is None:
            continue

        transition_pairs = tuple(
            sorted(
                (
                    (int(from_state), int(to_state))
                    for transition in group_transitions
                    if (from_state := getattr(transition, "from_state", None)) is not None
                    and (to_state := getattr(transition, "to_state", None)) is not None
                )
            )
        )
        candidates.append(
            ConditionalForkResolutionCandidate(
                from_block=int(from_blk_serial),
                cond_block=int(cond_block),
                taken_target=int(target_a if jt_a else target_b),
                fallthrough_target=int(target_b if jt_a else target_a),
                states=(int(state_a), int(state_b)),
                owned_transitions=transition_pairs,
            )
        )

    return tuple(candidates)


__all__ = [
    "ConditionalForkResolutionCandidate",
    "collect_conditional_fork_resolution_candidates",
]
