"""Read-only discovery for local guarded constant-state machines."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, OperandKind


GUARDED_STATE_MACHINE_FIXES_METADATA_KEY = "guarded_state_machine_fixes"


@dataclass(frozen=True)
class GuardedStateMachineFix:
    """Validated redirects around a local range-guard state-machine shell."""

    outer_guard_block: int
    outer_guard_old_target: int
    inner_guard_block: int
    inner_guard_old_target: int
    inner_override_block: int
    inner_override_old_target: int
    invalid_target: int
    success_target: int


def _operand(insn: object | None, slot: str) -> object | None:
    if insn is None:
        return None
    for slot_name, operand in getattr(insn, "operand_slots", ()) or ():
        if slot_name == slot:
            return operand
    return getattr(insn, slot, None)


def _const_value(mop: object | None) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "value", None)
    if value is None:
        nnn = getattr(mop, "nnn", None)
        value = getattr(nnn, "value", None)
    if value is None:
        return None
    try:
        return int(value) & 0xFFFFFFFF
    except (TypeError, ValueError):
        return None


def _var_key(mop: object | None) -> tuple[str, int, int] | None:
    if mop is None:
        return None
    size = int(getattr(mop, "size", 0) or 0)
    kind = getattr(mop, "kind", None)
    reg = getattr(mop, "reg", None)
    if reg is not None or kind is OperandKind.REGISTER:
        try:
            return ("reg", int(reg), size)
        except (TypeError, ValueError):
            return None
    stkoff = getattr(mop, "stkoff", None)
    if stkoff is not None or kind is OperandKind.STACK:
        try:
            return ("stack", int(stkoff), size)
        except (TypeError, ValueError):
            return None
    lvar_idx = getattr(mop, "lvar_idx", None)
    if lvar_idx is not None:
        try:
            return ("lvar", int(lvar_idx), size)
        except (TypeError, ValueError):
            return None
    return None


def _is_mov(insn: object | None) -> bool:
    if insn is None:
        return False
    if getattr(insn, "kind", None) is InsnKind.MOV:
        return True
    return str(getattr(insn, "kind", "")) == "InsnKind.MOV"


def _is_conditional(insn: object | None) -> bool:
    if insn is None:
        return False
    kind = getattr(insn, "kind", None)
    if kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}:
        return True
    return str(kind) in {
        "InsnKind.COND_JUMP",
        "InsnKind.EQUALITY_JUMP",
        "cond_jump",
        "equality_jump",
    }


def _iter_movs(block: BlockSnapshot) -> tuple[object, ...]:
    return tuple(insn for insn in block.insn_snapshots if _is_mov(insn))


def _last_insn(block: BlockSnapshot) -> object | None:
    if not block.insn_snapshots:
        return None
    return block.insn_snapshots[-1]


def _const_assignment(
    block: BlockSnapshot,
    dest_key: tuple[str, int, int] | None = None,
) -> tuple[tuple[str, int, int], int] | None:
    result: tuple[tuple[str, int, int], int] | None = None
    for insn in _iter_movs(block):
        dst = _var_key(_operand(insn, "d"))
        value = _const_value(_operand(insn, "l"))
        if dst is None or value is None:
            continue
        if dest_key is not None and dst != dest_key:
            continue
        result = (dst, int(value))
    return result


def _var_assignment(
    block: BlockSnapshot,
    *,
    dest_key: tuple[str, int, int] | None = None,
) -> tuple[tuple[str, int, int], tuple[str, int, int]] | None:
    result: tuple[tuple[str, int, int], tuple[str, int, int]] | None = None
    for insn in _iter_movs(block):
        dst = _var_key(_operand(insn, "d"))
        src = _var_key(_operand(insn, "l"))
        if dst is None or src is None:
            continue
        if dest_key is not None and dst != dest_key:
            continue
        result = (dst, src)
    return result


def _compare_const(
    block: BlockSnapshot,
    *,
    var_key: tuple[str, int, int] | None = None,
) -> int | None:
    tail = _last_insn(block)
    if not _is_conditional(tail):
        return None
    left = _operand(tail, "l")
    right = _operand(tail, "r")
    left_var = _var_key(left)
    right_var = _var_key(right)
    left_const = _const_value(left)
    right_const = _const_value(right)
    if right_const is not None and left_var is not None:
        if var_key is None or left_var == var_key:
            return int(right_const)
    if left_const is not None and right_var is not None:
        if var_key is None or right_var == var_key:
            return int(left_const)
    return None


def _one_way_const_assign_to(
    cfg: FlowGraph,
    serial: int,
    *,
    dest_key: tuple[str, int, int],
    target: int,
) -> int | None:
    block = cfg.get_block(serial)
    if block is None or block.nsucc != 1 or int(block.succs[0]) != int(target):
        return None
    assignment = _const_assignment(block, dest_key)
    if assignment is None:
        return None
    return int(assignment[1])


def _state_assign_successors(
    cfg: FlowGraph,
    block: BlockSnapshot,
    *,
    state_key: tuple[str, int, int],
    header: int,
) -> tuple[tuple[int, int], ...]:
    assignments: list[tuple[int, int]] = []
    for succ in block.succs:
        value = _one_way_const_assign_to(
            cfg,
            int(succ),
            dest_key=state_key,
            target=int(header),
        )
        if value is not None:
            assignments.append((int(succ), int(value)))
    return tuple(assignments)


def _find_low_dispatch(
    cfg: FlowGraph,
    header: BlockSnapshot,
    *,
    state_key: tuple[str, int, int],
) -> tuple[BlockSnapshot, BlockSnapshot, tuple[str, int, int]] | None:
    for succ in header.succs:
        block = cfg.get_block(int(succ))
        if block is None or block.nsucc != 2 or int(header.serial) not in block.succs:
            continue
        assignment = _var_assignment(block, dest_key=state_key)
        if assignment is None:
            continue
        _dst, choice_key = assignment
        other_succs = tuple(int(s) for s in block.succs if int(s) != int(header.serial))
        if len(other_succs) != 1:
            continue
        next_block = cfg.get_block(other_succs[0])
        if next_block is None:
            continue
        high_succs = tuple(int(s) for s in header.succs if int(s) != int(block.serial))
        if len(high_succs) != 1:
            continue
        high_block = cfg.get_block(high_succs[0])
        if high_block is None:
            continue
        return block, high_block, choice_key
    return None


def _find_low_tail(
    cfg: FlowGraph,
    *,
    header: int,
    low_block: BlockSnapshot,
    state_key: tuple[str, int, int],
) -> tuple[tuple[str, int, int], int, int] | None:
    expected_prev_const = _compare_const(low_block)
    if expected_prev_const is None:
        return None
    next_serials = tuple(int(s) for s in low_block.succs if int(s) != int(header))
    if len(next_serials) != 1:
        return None
    copy_block = cfg.get_block(next_serials[0])
    if copy_block is None or copy_block.nsucc != 2 or int(header) not in copy_block.succs:
        return None
    copy_assignment = _var_assignment(copy_block, dest_key=state_key)
    if copy_assignment is None:
        return None
    copied_from = copy_assignment[1]
    assign_serials = tuple(int(s) for s in copy_block.succs if int(s) != int(header))
    if len(assign_serials) != 1:
        return None
    choice_block = cfg.get_block(assign_serials[0])
    if choice_block is None or choice_block.nsucc != 1 or int(choice_block.succs[0]) != int(header):
        return None
    choice_assignment = _var_assignment(choice_block, dest_key=state_key)
    if choice_assignment is None:
        return None
    return choice_assignment[1], int(expected_prev_const), int(copy_block.serial)


def _invalid_and_success_targets(
    cfg: FlowGraph,
    final_check: BlockSnapshot,
) -> tuple[int, int] | None:
    zero_way = tuple(
        int(succ)
        for succ in final_check.succs
        if (cfg.get_block(int(succ)) is not None and cfg.get_block(int(succ)).nsucc == 0)
    )
    non_zero = tuple(
        int(succ)
        for succ in final_check.succs
        if (cfg.get_block(int(succ)) is not None and cfg.get_block(int(succ)).nsucc != 0)
    )
    if len(zero_way) != 1 or len(non_zero) != 1:
        return None
    return zero_way[0], non_zero[0]


def _find_high_exit(
    cfg: FlowGraph,
    *,
    header: int,
    high_block: BlockSnapshot,
    state_key: tuple[str, int, int],
    choice_one_success: int,
) -> tuple[int, int] | None:
    eq_ok_consts: set[int] = set()
    exit_candidates: list[tuple[int, int]] = []
    for succ in high_block.succs:
        block = cfg.get_block(int(succ))
        if block is None or block.nsucc != 2:
            continue
        compare_const = _compare_const(block, var_key=state_key)
        if compare_const is None:
            continue
        assignments = _state_assign_successors(
            cfg,
            block,
            state_key=state_key,
            header=int(header),
        )
        if int(compare_const) == int(choice_one_success):
            eq_ok_consts.update(value for _serial, value in assignments)
            continue
        for assign_serial, success_const in assignments:
            final_serials = tuple(int(s) for s in block.succs if int(s) != int(assign_serial))
            if len(final_serials) != 1:
                continue
            final_check = cfg.get_block(final_serials[0])
            if final_check is None or final_check.nsucc != 2:
                continue
            if _compare_const(final_check, var_key=state_key) != int(success_const):
                continue
            targets = _invalid_and_success_targets(cfg, final_check)
            if targets is not None:
                exit_candidates.append(targets)
                eq_ok_consts.add(int(compare_const))
    if not eq_ok_consts or not exit_candidates:
        return None
    return exit_candidates[0]


def _find_pre_guard(
    cfg: FlowGraph,
    *,
    init_block: BlockSnapshot,
    choice_one_key: tuple[str, int, int],
    choice_two_key: tuple[str, int, int],
    choice_one_success: int,
    choice_two_success: int,
    invalid_target: int,
    success_target: int,
) -> GuardedStateMachineFix | None:
    init_preds = tuple(int(pred) for pred in init_block.preds)
    if len(init_preds) != 2:
        return None
    inner_guard: BlockSnapshot | None = None
    inner_override: BlockSnapshot | None = None
    for pred in init_preds:
        block = cfg.get_block(pred)
        if block is None:
            return None
        assignment = _const_assignment(block, choice_two_key)
        if assignment is None:
            return None
        _dst, value = assignment
        if block.nsucc == 2 and int(init_block.serial) in block.succs:
            if int(value) == int(choice_two_success):
                return None
            inner_guard = block
        elif block.nsucc == 1 and int(block.succs[0]) == int(init_block.serial):
            if int(value) != int(choice_two_success):
                return None
            inner_override = block
    if inner_guard is None or inner_override is None:
        return None
    if int(inner_override.serial) not in inner_guard.succs:
        return None

    inner_guard_preds = tuple(int(pred) for pred in inner_guard.preds)
    if len(inner_guard_preds) != 2:
        return None
    outer_guard: BlockSnapshot | None = None
    outer_guard_value: int | None = None
    outer_arm: BlockSnapshot | None = None
    outer_arm_value: int | None = None
    for pred in inner_guard_preds:
        block = cfg.get_block(pred)
        if block is None:
            return None
        assignment = _const_assignment(block, choice_one_key)
        if assignment is None:
            return None
        _dst, value = assignment
        if block.nsucc == 2 and int(inner_guard.serial) in block.succs:
            outer_guard = block
            outer_guard_value = int(value)
        elif block.nsucc == 1 and int(block.succs[0]) == int(inner_guard.serial):
            outer_arm = block
            outer_arm_value = int(value)
    if (
        outer_guard is None
        or outer_guard_value is None
        or outer_arm is None
        or outer_arm_value is None
    ):
        return None
    if int(outer_arm.serial) not in outer_guard.succs:
        return None

    if (
        int(outer_guard_value) != int(choice_one_success)
        and int(outer_arm_value) == int(choice_one_success)
    ):
        outer_guard_old_target = int(inner_guard.serial)
    elif (
        int(outer_guard_value) == int(choice_one_success)
        and int(outer_arm_value) != int(choice_one_success)
    ):
        outer_guard_old_target = int(outer_arm.serial)
    else:
        return None

    return GuardedStateMachineFix(
        outer_guard_block=int(outer_guard.serial),
        outer_guard_old_target=int(outer_guard_old_target),
        inner_guard_block=int(inner_guard.serial),
        inner_guard_old_target=int(init_block.serial),
        inner_override_block=int(inner_override.serial),
        inner_override_old_target=int(init_block.serial),
        invalid_target=int(invalid_target),
        success_target=int(success_target),
    )


def collect_guarded_state_machine_fixes(
    cfg: FlowGraph | None,
) -> tuple[GuardedStateMachineFix, ...]:
    """Collect local state-machine guard collapses from a lifted CFG."""
    if cfg is None:
        return ()
    fixes: dict[tuple[int, int, int], GuardedStateMachineFix] = {}
    for init_block in cfg.blocks.values():
        if init_block.nsucc != 1:
            continue
        init_assignment = _const_assignment(init_block)
        if init_assignment is None:
            continue
        state_key, init_const = init_assignment
        header = cfg.get_block(int(init_block.succs[0]))
        if header is None or header.nsucc != 2:
            continue
        low_info = _find_low_dispatch(cfg, header, state_key=state_key)
        if low_info is None:
            continue
        low_block, high_block, choice_one_key = low_info
        low_tail = _find_low_tail(
            cfg,
            header=int(header.serial),
            low_block=low_block,
            state_key=state_key,
        )
        if low_tail is None:
            continue
        choice_two_key, choice_two_success, copy_block_serial = low_tail
        copy_block = cfg.get_block(copy_block_serial)
        if copy_block is None or _compare_const(copy_block) != int(init_const):
            continue
        choice_one_success = None
        for succ in high_block.succs:
            candidate = cfg.get_block(int(succ))
            if candidate is None:
                continue
            compare_const = _compare_const(candidate, var_key=state_key)
            if compare_const is None:
                continue
            assignments = _state_assign_successors(
                cfg,
                candidate,
                state_key=state_key,
                header=int(header.serial),
            )
            if len(assignments) >= 2:
                choice_one_success = int(compare_const)
                break
        if choice_one_success is None:
            continue
        exit_targets = _find_high_exit(
            cfg,
            header=int(header.serial),
            high_block=high_block,
            state_key=state_key,
            choice_one_success=int(choice_one_success),
        )
        if exit_targets is None:
            continue
        invalid_target, success_target = exit_targets
        fix = _find_pre_guard(
            cfg,
            init_block=init_block,
            choice_one_key=choice_one_key,
            choice_two_key=choice_two_key,
            choice_one_success=int(choice_one_success),
            choice_two_success=int(choice_two_success),
            invalid_target=int(invalid_target),
            success_target=int(success_target),
        )
        if fix is not None:
            key = (
                int(fix.outer_guard_block),
                int(fix.inner_guard_block),
                int(fix.inner_override_block),
            )
            fixes[key] = fix
    return tuple(fixes[key] for key in sorted(fixes))


def _coerce_fixes(raw: object) -> tuple[GuardedStateMachineFix, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    fixes: list[GuardedStateMachineFix] = []
    for item in raw:
        if isinstance(item, GuardedStateMachineFix):
            fixes.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        try:
            fixes.append(
                GuardedStateMachineFix(
                    outer_guard_block=int(item["outer_guard_block"]),
                    outer_guard_old_target=int(item["outer_guard_old_target"]),
                    inner_guard_block=int(item["inner_guard_block"]),
                    inner_guard_old_target=int(item["inner_guard_old_target"]),
                    inner_override_block=int(item["inner_override_block"]),
                    inner_override_old_target=int(item["inner_override_old_target"]),
                    invalid_target=int(item["invalid_target"]),
                    success_target=int(item["success_target"]),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(fixes)


def serialize_guarded_state_machine_fixes(
    fixes: Sequence[GuardedStateMachineFix],
) -> tuple[dict[str, int], ...]:
    """Serialize guard-collapse fixes into FlowGraph metadata."""
    return tuple(
        {
            "outer_guard_block": int(fix.outer_guard_block),
            "outer_guard_old_target": int(fix.outer_guard_old_target),
            "inner_guard_block": int(fix.inner_guard_block),
            "inner_guard_old_target": int(fix.inner_guard_old_target),
            "inner_override_block": int(fix.inner_override_block),
            "inner_override_old_target": int(fix.inner_override_old_target),
            "invalid_target": int(fix.invalid_target),
            "success_target": int(fix.success_target),
        }
        for fix in sorted(
            fixes,
            key=lambda item: (
                int(item.outer_guard_block),
                int(item.inner_guard_block),
                int(item.inner_override_block),
            ),
        )
    )


def _is_valid_fix(cfg: FlowGraph, fix: GuardedStateMachineFix) -> bool:
    outer_guard = cfg.get_block(fix.outer_guard_block)
    inner_guard = cfg.get_block(fix.inner_guard_block)
    inner_override = cfg.get_block(fix.inner_override_block)
    if (
        outer_guard is None
        or inner_guard is None
        or inner_override is None
        or cfg.get_block(fix.invalid_target) is None
        or cfg.get_block(fix.success_target) is None
    ):
        return False
    if outer_guard.nsucc != 2 or fix.outer_guard_old_target not in outer_guard.succs:
        return False
    if inner_guard.nsucc != 2 or fix.inner_guard_old_target not in inner_guard.succs:
        return False
    if (
        inner_override.nsucc != 1
        or int(inner_override.succs[0]) != int(fix.inner_override_old_target)
    ):
        return False
    return fix in collect_guarded_state_machine_fixes(cfg)


def extract_guarded_state_machine_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[GuardedStateMachineFix, ...]:
    """Read validated guarded state-machine fixes from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return tuple(
        fix
        for fix in _coerce_fixes(
            flow_graph.metadata.get(GUARDED_STATE_MACHINE_FIXES_METADATA_KEY)
        )
        if _is_valid_fix(flow_graph, fix)
    )


__all__ = [
    "GUARDED_STATE_MACHINE_FIXES_METADATA_KEY",
    "GuardedStateMachineFix",
    "collect_guarded_state_machine_fixes",
    "extract_guarded_state_machine_fixes",
    "serialize_guarded_state_machine_fixes",
]
