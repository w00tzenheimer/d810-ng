"""Cleanup strategy for local constant-select loop shells."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, OperandKind
from d810.cfg.graph_modification import (
    ConvertToGoto,
    GraphModification,
    RedirectBranch,
    RedirectGoto,
)
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )


LOCAL_SELECT_LOOP_FIXES_METADATA_KEY = "local_select_loop_fixes"


VarId = tuple[str, int]
VarUseId = tuple[str, int, int]


@dataclass(frozen=True)
class LocalSelectLoopFix:
    """Validated redirects that bypass a one-iteration local select loop."""

    init_block: int
    init_old_target: int
    test_block: int
    test_old_target: int
    assignment_block: int
    assignment_old_target: int
    exit_target: int
    selector_assignment_block: int | None = None
    selector_assignment_old_target: int | None = None


@dataclass(frozen=True)
class LocalSelectConvergenceLoopFix:
    """Validated collapse of a dispatch-only local convergence loop."""

    init_block: int
    header_block: int
    loop_entry_target: int
    exit_target: int


@dataclass(frozen=True)
class LocalSelectTerminalLoopFix:
    """Validated collapse of a closed dispatch-only terminal loop."""

    init_block: int
    init_old_target: int
    sink_block: int
    sink_old_target: int
    exit_target: int | None = None


@dataclass(frozen=True)
class LocalSelectDirectExitLoopFix:
    """Validated collapse of a dispatch-only loop with a proven real exit."""

    init_block: int
    init_old_target: int
    header_block: int
    loop_entry_target: int
    exit_target: int


LocalSelectLoopCandidate = (
    LocalSelectLoopFix
    | LocalSelectConvergenceLoopFix
    | LocalSelectTerminalLoopFix
    | LocalSelectDirectExitLoopFix
)


@dataclass(frozen=True)
class _HeaderStep:
    state_id: VarId
    selector_id: VarId
    previous_id: VarId
    previous_use_id: VarUseId
    init_const: int


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


def _var_id(mop: object | None) -> VarId | None:
    if mop is None:
        return None
    kind = getattr(mop, "kind", None)
    reg = getattr(mop, "reg", None)
    if reg is not None or kind is OperandKind.REGISTER:
        try:
            return ("reg", int(reg))
        except (TypeError, ValueError):
            return None
    stkoff = getattr(mop, "stkoff", None)
    if stkoff is not None or kind is OperandKind.STACK:
        try:
            return ("stack", int(stkoff))
        except (TypeError, ValueError):
            return None
    lvar_idx = getattr(mop, "lvar_idx", None)
    if lvar_idx is not None:
        try:
            return ("lvar", int(lvar_idx))
        except (TypeError, ValueError):
            return None
    return None


def _var_use_id(mop: object | None) -> VarUseId | None:
    var_id = _var_id(mop)
    if var_id is None:
        return None
    try:
        size = int(getattr(mop, "size", 0) or 0)
    except (TypeError, ValueError):
        size = 0
    return (var_id[0], var_id[1], size)


def _kind_name(insn: object | None) -> str:
    if insn is None:
        return ""
    kind = getattr(insn, "kind", None)
    if isinstance(kind, InsnKind):
        return kind.value
    return str(kind)


def _is_mov(insn: object | None) -> bool:
    return getattr(insn, "kind", None) is InsnKind.MOV or _kind_name(insn) in {
        "InsnKind.MOV",
        "mov",
    }


def _is_xdu(insn: object | None) -> bool:
    return getattr(insn, "kind", None) is InsnKind.XDU or _kind_name(insn) in {
        "InsnKind.XDU",
        "xdu",
    }


def _is_forward_assign(insn: object | None) -> bool:
    return _is_mov(insn) or _is_xdu(insn)


def _is_conditional(insn: object | None) -> bool:
    kind = getattr(insn, "kind", None)
    if kind in {InsnKind.COND_JUMP, InsnKind.EQUALITY_JUMP}:
        return True
    return _kind_name(insn) in {
        "InsnKind.COND_JUMP",
        "InsnKind.EQUALITY_JUMP",
        "cond_jump",
        "equality_jump",
    }


def _is_goto(insn: object | None) -> bool:
    kind = getattr(insn, "kind", None)
    if kind is InsnKind.GOTO:
        return True
    return _kind_name(insn) in {"InsnKind.GOTO", "goto"}


def _is_call(insn: object | None) -> bool:
    try:
        opcode = int(getattr(insn, "raw_opcode", getattr(insn, "opcode", -1)))
    except (TypeError, ValueError):
        opcode = -1
    return opcode in {56, 57}


def _last_insn(block: BlockSnapshot) -> object | None:
    if not block.insn_snapshots:
        return None
    return block.insn_snapshots[-1]


def _iter_assignments(block: BlockSnapshot) -> tuple[object, ...]:
    return tuple(insn for insn in block.insn_snapshots if _is_forward_assign(insn))


def _var_assignment(insn: object | None) -> tuple[VarId, VarId] | None:
    if not _is_forward_assign(insn):
        return None
    dst = _var_id(_operand(insn, "d"))
    src = _var_id(_operand(insn, "l"))
    if dst is None or src is None:
        return None
    return dst, src


def _const_assignment(
    block: BlockSnapshot,
    dest_id: VarId | None = None,
) -> tuple[VarId, int] | None:
    result: tuple[VarId, int] | None = None
    for insn in block.insn_snapshots:
        if not _is_mov(insn):
            continue
        dst = _var_id(_operand(insn, "d"))
        value = _const_value(_operand(insn, "l"))
        if dst is None or value is None:
            continue
        if dest_id is not None and dst != dest_id:
            continue
        result = (dst, int(value))
    return result


def _compare_var_const_operand(
    block: BlockSnapshot,
) -> tuple[VarId, int, object] | None:
    tail = _last_insn(block)
    if not _is_conditional(tail):
        return None
    left = _operand(tail, "l")
    right = _operand(tail, "r")
    left_var = _var_id(left)
    right_var = _var_id(right)
    left_const = _const_value(left)
    right_const = _const_value(right)
    if left_var is not None and right_const is not None:
        return left_var, int(right_const), left
    if right_var is not None and left_const is not None:
        return right_var, int(left_const), right
    return None


def _compare_var_const(block: BlockSnapshot) -> tuple[VarId, int] | None:
    result = _compare_var_const_operand(block)
    if result is None:
        return None
    var_id, const_value, _operand = result
    return var_id, const_value


def _compare_var_const_use(block: BlockSnapshot) -> tuple[VarId, int, VarUseId] | None:
    result = _compare_var_const_operand(block)
    if result is None:
        return None
    var_id, const_value, operand = result
    use_id = _var_use_id(operand)
    if use_id is None:
        return None
    return var_id, const_value, use_id


def _parse_header_step(header: BlockSnapshot) -> _HeaderStep | None:
    compare = _compare_var_const_use(header)
    if compare is None:
        return None
    previous_id, init_const, previous_use_id = compare
    state_id: VarId | None = None
    selector_id: VarId | None = None
    for insn in header.insn_snapshots[:-1]:
        assignment = _var_assignment(insn)
        if assignment is None:
            continue
        dst, src = assignment
        if dst == previous_id and state_id is None:
            state_id = src
            continue
        if state_id is not None and dst == state_id:
            selector_id = src
    if state_id is None or selector_id is None:
        return None
    if selector_id == previous_id or selector_id == state_id:
        return None
    return _HeaderStep(
        state_id=state_id,
        selector_id=selector_id,
        previous_id=previous_id,
        previous_use_id=previous_use_id,
        init_const=int(init_const),
    )


def _parse_copy_compare_header(
    header: BlockSnapshot,
) -> tuple[VarId, VarId, int] | None:
    compare = _compare_var_const(header)
    if compare is None:
        return None
    state_id, compare_const = compare
    previous_id: VarId | None = None
    for insn in header.insn_snapshots[:-1]:
        assignment = _var_assignment(insn)
        if assignment is None:
            continue
        dst, src = assignment
        if src == state_id:
            previous_id = dst
    if previous_id is None or previous_id == state_id:
        return None
    return state_id, previous_id, int(compare_const)

def _has_payload_var_assignment(
    block: BlockSnapshot,
    *,
    state_id: VarId,
    selector_id: VarId,
    previous_id: VarId,
) -> bool:
    dispatch_ids = {state_id, selector_id, previous_id}
    for insn in _iter_assignments(block):
        assignment = _var_assignment(insn)
        if assignment is None:
            continue
        dst, src = assignment
        if dst not in dispatch_ids and src not in dispatch_ids:
            return True
    return False


def _find_init_block(
    cfg: FlowGraph,
    header: BlockSnapshot,
    *,
    step: _HeaderStep,
    test_block: int,
    assignment_block: int,
) -> BlockSnapshot | None:
    candidates: list[BlockSnapshot] = []
    for pred_serial in header.preds:
        serial = int(pred_serial)
        if serial in {int(test_block), int(assignment_block)}:
            continue
        pred = cfg.get_block(serial)
        if pred is None:
            continue
        if pred.nsucc != 1 or int(pred.succs[0]) != int(header.serial):
            continue
        const_assignment = _const_assignment(pred, step.state_id)
        if const_assignment is None:
            continue
        if int(const_assignment[1]) != int(step.init_const):
            continue
        candidates.append(pred)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _find_selector_assignment_pred(
    cfg: FlowGraph,
    init_block: BlockSnapshot,
    *,
    selector_id: VarId,
    selector_const: int,
) -> BlockSnapshot | None:
    candidates: list[BlockSnapshot] = []
    for pred_serial in init_block.preds:
        pred = cfg.get_block(int(pred_serial))
        if pred is None or pred.nsucc != 1:
            continue
        if int(pred.succs[0]) != int(init_block.serial):
            continue
        const_assignment = _const_assignment(pred, selector_id)
        if const_assignment is None:
            continue
        if int(const_assignment[1]) != int(selector_const):
            continue
        candidates.append(pred)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _find_select_loop_for_header(
    cfg: FlowGraph,
    header: BlockSnapshot,
) -> LocalSelectLoopFix | None:
    if header.nsucc != 2 or header.npred != 3:
        return None
    step = _parse_header_step(header)
    if step is None:
        return None

    for test_serial in header.succs:
        test_block = cfg.get_block(int(test_serial))
        if (
            test_block is None
            or test_block.nsucc != 2
            or int(header.serial) not in test_block.succs
        ):
            continue
        compare = _compare_var_const(test_block)
        if compare is None or compare[0] != step.selector_id:
            continue
        selector_const = int(compare[1])
        assignment_serials = tuple(
            int(succ) for succ in test_block.succs if int(succ) != int(header.serial)
        )
        if len(assignment_serials) != 1:
            continue
        assignment = cfg.get_block(assignment_serials[0])
        if (
            assignment is None
            or assignment.nsucc != 1
            or int(assignment.succs[0]) != int(header.serial)
        ):
            continue
        done_assignment = _const_assignment(assignment, step.state_id)
        if done_assignment is None or int(done_assignment[1]) == int(step.init_const):
            continue
        if not _has_payload_var_assignment(
            assignment,
            state_id=step.state_id,
            selector_id=step.selector_id,
            previous_id=step.previous_id,
        ):
            continue

        exit_targets = tuple(
            int(succ) for succ in header.succs if int(succ) != int(test_block.serial)
        )
        if len(exit_targets) != 1 or cfg.get_block(exit_targets[0]) is None:
            continue
        init_block = _find_init_block(
            cfg,
            header,
            step=step,
            test_block=int(test_block.serial),
            assignment_block=int(assignment.serial),
        )
        if init_block is None:
            continue
        selector_assignment_block = _find_selector_assignment_pred(
            cfg,
            init_block,
            selector_id=step.selector_id,
            selector_const=selector_const,
        )
        return LocalSelectLoopFix(
            init_block=int(init_block.serial),
            init_old_target=int(header.serial),
            test_block=int(test_block.serial),
            test_old_target=int(header.serial),
            assignment_block=int(assignment.serial),
            assignment_old_target=int(header.serial),
            exit_target=int(exit_targets[0]),
            selector_assignment_block=(
                int(selector_assignment_block.serial)
                if selector_assignment_block is not None
                else None
            ),
            selector_assignment_old_target=(
                int(init_block.serial)
                if selector_assignment_block is not None
                else None
            ),
        )
    return None


def _can_reach_block(
    cfg: FlowGraph,
    start: int,
    target: int,
    *,
    max_depth: int = 16,
) -> bool:
    """Return whether ``start`` reaches ``target`` within a small local search."""
    stack: list[tuple[int, int]] = [(int(start), 0)]
    seen: set[int] = set()
    while stack:
        serial, depth = stack.pop()
        if serial == int(target):
            return True
        if serial in seen or depth >= max_depth:
            continue
        seen.add(serial)
        block = cfg.get_block(serial)
        if block is None:
            continue
        for succ in block.succs:
            stack.append((int(succ), depth + 1))
    return False


def _collect_loop_region_to_header(
    cfg: FlowGraph,
    *,
    start: int,
    header: int,
    max_nodes: int = 8,
) -> frozenset[int] | None:
    """Collect the closed local region reached before returning to ``header``."""
    region: set[int] = set()
    stack: list[int] = [int(start)]
    while stack:
        serial = stack.pop()
        if serial == int(header):
            continue
        if serial in region:
            continue
        if len(region) >= max_nodes:
            return None
        block = cfg.get_block(serial)
        if block is None:
            return None
        region.add(serial)
        for succ in block.succs:
            succ_int = int(succ)
            if succ_int == int(header):
                continue
            if cfg.get_block(succ_int) is None:
                return None
            stack.append(succ_int)

    if not region:
        return None
    for serial in region:
        block = cfg.get_block(serial)
        if block is None:
            return None
        if not any(
            int(succ) == int(header) or int(succ) in region
            for succ in block.succs
        ):
            return None
    return frozenset(region)


def _instruction_var_use_ids(insn: object | None) -> frozenset[VarUseId]:
    result: set[VarUseId] = set()
    for _slot_name, operand in getattr(insn, "operand_slots", ()) or ():
        var_id = _var_use_id(operand)
        if var_id is not None:
            result.add(var_id)
    return frozenset(result)


def _is_dispatch_only_loop_block(
    block: BlockSnapshot,
    *,
    step: _HeaderStep,
) -> bool:
    allowed_ids = {step.state_id, step.selector_id, step.previous_id}
    tail = _last_insn(block)
    for insn in block.insn_snapshots:
        if insn is tail and (_is_conditional(insn) or _is_goto(insn)):
            compare = _compare_var_const(block)
            if _is_conditional(insn) and compare is not None:
                return compare[0] in allowed_ids
            return _is_goto(insn)
        if not _is_forward_assign(insn):
            return False
        dst = _var_id(_operand(insn, "d"))
        if dst not in allowed_ids:
            return False
        src_var = _var_id(_operand(insn, "l"))
        src_const = _const_value(_operand(insn, "l"))
        if src_var is None and src_const is None:
            return False
        if src_var is not None and src_var not in allowed_ids:
            return False
    return True


def _find_convergence_init_block(
    cfg: FlowGraph,
    header: BlockSnapshot,
    *,
    step: _HeaderStep,
    loop_region: frozenset[int],
) -> BlockSnapshot | None:
    candidates: list[BlockSnapshot] = []
    for pred_serial in header.preds:
        serial = int(pred_serial)
        if serial in loop_region:
            continue
        pred = cfg.get_block(serial)
        if pred is None:
            continue
        if pred.nsucc != 1 or int(pred.succs[0]) != int(header.serial):
            continue
        const_assignment = _const_assignment(pred, step.state_id)
        if const_assignment is None:
            continue
        if int(const_assignment[1]) != int(step.init_const):
            continue
        candidates.append(pred)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _var_referenced_after_exit(
    cfg: FlowGraph,
    *,
    exit_target: int,
    var_id: VarUseId,
    forbidden: frozenset[int],
    max_nodes: int = 128,
) -> bool:
    if var_id[0] == "reg":
        return False
    stack: list[int] = [int(exit_target)]
    seen: set[int] = set()
    while stack:
        serial = stack.pop()
        if serial in seen or serial in forbidden:
            continue
        if len(seen) >= max_nodes:
            return True
        seen.add(serial)
        block = cfg.get_block(serial)
        if block is None:
            continue
        for insn in block.insn_snapshots:
            if var_id in _instruction_var_use_ids(insn):
                return True
        for succ in block.succs:
            stack.append(int(succ))
    return False


def _find_convergence_loop_for_header(
    cfg: FlowGraph,
    header: BlockSnapshot,
) -> LocalSelectConvergenceLoopFix | None:
    if header.nsucc != 2:
        return None
    step = _parse_header_step(header)
    if step is None:
        return None

    loop_targets = tuple(
        int(succ)
        for succ in header.succs
        if _can_reach_block(cfg, int(succ), int(header.serial))
    )
    exit_targets = tuple(
        int(succ) for succ in header.succs if int(succ) not in loop_targets
    )
    if len(loop_targets) != 1 or len(exit_targets) != 1:
        return None

    loop_region = _collect_loop_region_to_header(
        cfg,
        start=loop_targets[0],
        header=int(header.serial),
    )
    if loop_region is None:
        return None
    for serial in loop_region:
        block = cfg.get_block(serial)
        if block is None or not _is_dispatch_only_loop_block(block, step=step):
            return None

    init_block = _find_convergence_init_block(
        cfg,
        header,
        step=step,
        loop_region=loop_region,
    )
    if init_block is None:
        return None

    forbidden = frozenset({int(header.serial), *loop_region})
    if _var_referenced_after_exit(
        cfg,
        exit_target=exit_targets[0],
        var_id=step.previous_use_id,
        forbidden=forbidden,
    ):
        return None

    return LocalSelectConvergenceLoopFix(
        init_block=int(init_block.serial),
        header_block=int(header.serial),
        loop_entry_target=int(loop_targets[0]),
        exit_target=int(exit_targets[0]),
    )


def _closed_region_from_header(
    cfg: FlowGraph,
    *,
    header: int,
    max_nodes: int = 8,
) -> frozenset[int] | None:
    region: set[int] = set()
    stack: list[int] = []
    header_block = cfg.get_block(int(header))
    if header_block is None or header_block.nsucc != 2:
        return None
    stack.extend(int(succ) for succ in header_block.succs)
    while stack:
        serial = stack.pop()
        if serial == int(header):
            continue
        if serial in region:
            continue
        if len(region) >= max_nodes:
            return None
        block = cfg.get_block(serial)
        if block is None:
            return None
        region.add(serial)
        for succ in block.succs:
            succ_int = int(succ)
            if succ_int == int(header):
                continue
            if cfg.get_block(succ_int) is None:
                return None
            stack.append(succ_int)

    if not region:
        return None
    for serial in region:
        block = cfg.get_block(serial)
        if block is None:
            return None
        if not all(
            int(succ) == int(header) or int(succ) in region
            for succ in block.succs
        ):
            return None
    return frozenset(region)


def _is_terminal_dispatch_loop_block(
    block: BlockSnapshot,
    *,
    allowed_ids: frozenset[VarId],
) -> bool:
    tail = _last_insn(block)
    for insn in block.insn_snapshots:
        if insn is tail and (_is_conditional(insn) or _is_goto(insn)):
            if _is_goto(insn):
                return True
            compare = _compare_var_const(block)
            return compare is not None and compare[0] in allowed_ids
        if not _is_forward_assign(insn):
            return False
        dst = _var_id(_operand(insn, "d"))
        if dst not in allowed_ids:
            return False
        src_var = _var_id(_operand(insn, "l"))
        src_const = _const_value(_operand(insn, "l"))
        if src_var is None and src_const is None:
            return False
        if src_var is not None and src_var not in allowed_ids:
            return False
    return True


def _terminal_loop_allowed_ids(
    cfg: FlowGraph,
    *,
    region: frozenset[int],
    state_id: VarId,
    previous_id: VarId,
) -> frozenset[VarId] | None:
    allowed: set[VarId] = {state_id, previous_id}
    changed = True
    while changed:
        changed = False
        for serial in region:
            block = cfg.get_block(serial)
            if block is None:
                return None
            for insn in _iter_assignments(block):
                assignment = _var_assignment(insn)
                if assignment is None:
                    continue
                dst, src = assignment
                if dst in allowed and src not in allowed:
                    src_const = _const_value(_operand(insn, "l"))
                    if src_const is not None:
                        continue
                    if src[0] != "reg":
                        return None
                    allowed.add(src)
                    changed = True
    return frozenset(allowed)


def _find_terminal_loop_init_block(
    cfg: FlowGraph,
    header: BlockSnapshot,
    *,
    state_id: VarId,
    region: frozenset[int],
) -> BlockSnapshot | None:
    candidates: list[BlockSnapshot] = []
    for pred_serial in header.preds:
        serial = int(pred_serial)
        if serial in region:
            continue
        pred = cfg.get_block(serial)
        if pred is None:
            continue
        if pred.nsucc != 1 or int(pred.succs[0]) != int(header.serial):
            continue
        const_assignment = _const_assignment(pred, state_id)
        if const_assignment is None:
            continue
        candidates.append(pred)
    if len(candidates) != 1:
        return None
    return candidates[0]


def _find_terminal_sink_block(
    cfg: FlowGraph,
    *,
    header: int,
    region: frozenset[int],
) -> BlockSnapshot | None:
    candidates: list[BlockSnapshot] = []
    for serial in sorted(region):
        block = cfg.get_block(serial)
        if block is None:
            return None
        if block.nsucc == 1 and int(block.succs[0]) == int(header):
            candidates.append(block)
    if not candidates:
        return None
    return candidates[-1]


def _find_closed_loop_external_exit(
    cfg: FlowGraph,
    *,
    init_block: BlockSnapshot,
    header: int,
    region: frozenset[int],
    max_depth: int = 8,
) -> int | None:
    """Find a nearby pre-loop guard arm that skips the closed selector shell."""
    forbidden = {int(header), int(init_block.serial), *region}
    queue: list[tuple[int, int]] = [
        (int(pred), 0)
        for pred in init_block.preds
        if int(pred) not in forbidden
    ]
    seen: set[int] = set()
    candidates: list[tuple[int, int]] = []
    while queue:
        serial, depth = queue.pop(0)
        if serial in seen or depth > max_depth:
            continue
        seen.add(serial)
        block = cfg.get_block(serial)
        if block is None:
            continue
        if block.nsucc == 2:
            header_reaching: list[int] = []
            exits: list[int] = []
            for succ in block.succs:
                succ_int = int(succ)
                if _can_reach_block(cfg, succ_int, int(header)):
                    header_reaching.append(succ_int)
                elif succ_int not in forbidden and (
                    exit_block := cfg.get_block(succ_int)
                ) is not None and exit_block.nsucc == 0:
                    exits.append(succ_int)
            if len(header_reaching) == 1 and len(exits) == 1:
                candidates.append((depth, exits[0]))
        if depth >= max_depth:
            continue
        for pred in block.preds:
            pred_int = int(pred)
            if pred_int not in forbidden:
                queue.append((pred_int, depth + 1))
    if not candidates:
        return None
    min_depth = min(depth for depth, _exit in candidates)
    nearest = [exit_target for depth, exit_target in candidates if depth == min_depth]
    if len(nearest) != 1:
        return None
    return int(nearest[0])


def _is_noreturn_call_terminal(block: BlockSnapshot) -> bool:
    """Return whether a no-successor block is represented by one call."""
    return (
        block.nsucc == 0
        and len(block.insn_snapshots) == 1
        and _is_call(block.insn_snapshots[0])
    )


def _find_nearest_noreturn_call_terminal(
    cfg: FlowGraph,
    *,
    init_block: BlockSnapshot,
    header: int,
    region: frozenset[int],
    max_serial_distance: int = 96,
) -> int | None:
    """Find a nearby terminal call usable for a proven closed selector arm."""
    forbidden = {int(header), int(init_block.serial), *region}
    candidates: list[tuple[int, int, int]] = []
    for serial, block in cfg.blocks.items():
        serial_int = int(serial)
        if serial_int in forbidden:
            continue
        if not _is_noreturn_call_terminal(block):
            continue
        distance = abs(serial_int - int(init_block.serial))
        if distance > max_serial_distance:
            continue
        is_backward = 1 if serial_int < int(init_block.serial) else 0
        candidates.append((distance, is_backward, serial_int))
    if not candidates:
        return None
    candidates.sort()
    return int(candidates[0][2])


def _find_terminal_loop_for_header(
    cfg: FlowGraph,
    header: BlockSnapshot,
) -> LocalSelectTerminalLoopFix | None:
    parsed = _parse_copy_compare_header(header)
    if parsed is None:
        return None
    state_id, previous_id, _compare_const = parsed
    if state_id[0] != "reg" or previous_id[0] != "reg":
        return None

    region = _closed_region_from_header(cfg, header=int(header.serial))
    if region is None:
        return None
    init_block = _find_terminal_loop_init_block(
        cfg,
        header,
        state_id=state_id,
        region=region,
    )
    if init_block is None:
        return None
    allowed_ids = _terminal_loop_allowed_ids(
        cfg,
        region=region,
        state_id=state_id,
        previous_id=previous_id,
    )
    if allowed_ids is None:
        return None
    for serial in region:
        block = cfg.get_block(serial)
        if block is None or not _is_terminal_dispatch_loop_block(
            block,
            allowed_ids=allowed_ids,
        ):
            return None
    sink = _find_terminal_sink_block(
        cfg,
        header=int(header.serial),
        region=region,
    )
    if sink is None:
        return None
    external_exit = _find_closed_loop_external_exit(
        cfg,
        init_block=init_block,
        header=int(header.serial),
        region=region,
    )
    if external_exit is None:
        external_exit = _find_nearest_noreturn_call_terminal(
            cfg,
            init_block=init_block,
            header=int(header.serial),
            region=region,
        )
    return LocalSelectTerminalLoopFix(
        init_block=int(init_block.serial),
        init_old_target=int(header.serial),
        sink_block=int(sink.serial),
        sink_old_target=int(header.serial),
        exit_target=external_exit,
    )


def _find_terminal_exit_loop_for_header(
    cfg: FlowGraph,
    header: BlockSnapshot,
) -> LocalSelectTerminalLoopFix | None:
    parsed = _parse_copy_compare_header(header)
    if parsed is None:
        return None
    state_id, previous_id, _compare_const = parsed
    if state_id[0] != "reg" or previous_id[0] != "reg":
        return None
    terminal_targets = tuple(
        int(succ)
        for succ in header.succs
        if (target := cfg.get_block(int(succ))) is not None and target.nsucc == 0
    )
    loop_targets = tuple(
        int(succ)
        for succ in header.succs
        if (target := cfg.get_block(int(succ))) is not None and target.nsucc != 0
    )
    if len(terminal_targets) != 1 or len(loop_targets) != 1:
        return None
    loop_region = _collect_loop_region_to_header(
        cfg,
        start=loop_targets[0],
        header=int(header.serial),
    )
    if loop_region is None:
        return None
    init_block = _find_terminal_loop_init_block(
        cfg,
        header,
        state_id=state_id,
        region=loop_region,
    )
    if init_block is None:
        return None
    allowed_ids = _terminal_loop_allowed_ids(
        cfg,
        region=loop_region,
        state_id=state_id,
        previous_id=previous_id,
    )
    if allowed_ids is None:
        return None
    for serial in loop_region:
        block = cfg.get_block(serial)
        if block is None or not _is_terminal_dispatch_loop_block(
            block,
            allowed_ids=allowed_ids,
        ):
            return None
    sink = _find_terminal_sink_block(
        cfg,
        header=int(header.serial),
        region=loop_region,
    )
    if sink is None:
        return None
    return LocalSelectTerminalLoopFix(
        init_block=int(init_block.serial),
        init_old_target=int(header.serial),
        sink_block=int(sink.serial),
        sink_old_target=int(header.serial),
        exit_target=int(terminal_targets[0]),
    )


def _const_state_assignment_to_header(
    cfg: FlowGraph,
    *,
    serial: int,
    state_id: VarId,
    header: int,
) -> int | None:
    block = cfg.get_block(int(serial))
    if block is None or block.nsucc != 1 or int(block.succs[0]) != int(header):
        return None
    assignment = _const_assignment(block, state_id)
    if assignment is None:
        return None
    return int(assignment[1])


def _state_check_success_exit(
    cfg: FlowGraph,
    *,
    block: BlockSnapshot,
    state_id: VarId,
    header: int,
) -> tuple[int, frozenset[int]] | None:
    if block.nsucc != 2:
        return None
    compare = _compare_var_const(block)
    if compare is None or compare[0] != state_id:
        return None
    if len(block.insn_snapshots) != 1 or not _is_conditional(_last_insn(block)):
        return None
    assignment_successors: list[int] = []
    exit_successors: list[int] = []
    for succ in block.succs:
        succ_int = int(succ)
        if (
            _const_state_assignment_to_header(
                cfg,
                serial=succ_int,
                state_id=state_id,
                header=int(header),
            )
            is not None
        ):
            assignment_successors.append(succ_int)
            continue
        if not _can_reach_block(cfg, succ_int, int(header)):
            exit_successors.append(succ_int)
    if len(assignment_successors) != 1 or len(exit_successors) != 1:
        return None
    return int(exit_successors[0]), frozenset(int(s) for s in assignment_successors)


def _find_direct_exit_loop_for_header(
    cfg: FlowGraph,
    header: BlockSnapshot,
) -> LocalSelectDirectExitLoopFix | None:
    parsed = _parse_copy_compare_header(header)
    if parsed is None:
        return None
    state_id, previous_id, _compare_const = parsed
    if state_id[0] != "reg" or previous_id[0] != "reg":
        return None
    if header.nsucc != 2:
        return None

    candidates: list[tuple[int, int, frozenset[int]]] = []
    for first_serial, second_serial in (
        (int(header.succs[0]), int(header.succs[1])),
        (int(header.succs[1]), int(header.succs[0])),
    ):
        first = cfg.get_block(first_serial)
        second = cfg.get_block(second_serial)
        if first is None or second is None:
            continue

        if not _can_reach_block(cfg, first_serial, int(header.serial)):
            candidates.append((second_serial, first_serial, frozenset()))
            continue

        success_exit = _state_check_success_exit(
            cfg,
            block=first,
            state_id=state_id,
            header=int(header.serial),
        )
        if success_exit is not None:
            exit_target, extra_loop_region = success_exit
            candidates.append((second_serial, exit_target, extra_loop_region))

    for loop_entry, exit_target, extra_loop_region in candidates:
        if loop_entry == exit_target:
            continue
        loop_region = _collect_loop_region_to_header(
            cfg,
            start=int(loop_entry),
            header=int(header.serial),
        )
        if loop_region is None:
            continue
        loop_region = frozenset({*loop_region, *extra_loop_region})
        if int(exit_target) in loop_region:
            continue
        init_block = _find_terminal_loop_init_block(
            cfg,
            header,
            state_id=state_id,
            region=loop_region,
        )
        if init_block is None:
            continue
        allowed_ids = _terminal_loop_allowed_ids(
            cfg,
            region=loop_region,
            state_id=state_id,
            previous_id=previous_id,
        )
        if allowed_ids is None:
            continue
        if any(
            (block := cfg.get_block(serial)) is None
            or not _is_terminal_dispatch_loop_block(
                block,
                allowed_ids=allowed_ids,
            )
            for serial in loop_region
        ):
            continue
        return LocalSelectDirectExitLoopFix(
            init_block=int(init_block.serial),
            init_old_target=int(header.serial),
            header_block=int(header.serial),
            loop_entry_target=int(loop_entry),
            exit_target=int(exit_target),
        )
    return None


def collect_local_select_loop_fixes(
    cfg: FlowGraph | None,
) -> tuple[LocalSelectLoopCandidate, ...]:
    """Collect one-iteration local select loops from a lifted CFG."""
    if cfg is None:
        return ()
    fixes: dict[tuple[str, int, int, int], LocalSelectLoopCandidate] = {}
    for block in cfg.blocks.values():
        fix = _find_select_loop_for_header(cfg, block)
        if fix is not None:
            key = (
                "select",
                int(fix.init_block),
                int(fix.test_block),
                int(fix.assignment_block),
            )
            fixes[key] = fix
            continue
        convergence_fix = _find_convergence_loop_for_header(cfg, block)
        if convergence_fix is not None:
            key = (
                "convergence",
                int(convergence_fix.init_block),
                int(convergence_fix.header_block),
                int(convergence_fix.loop_entry_target),
            )
            fixes[key] = convergence_fix
            continue
        terminal_exit_fix = _find_terminal_exit_loop_for_header(cfg, block)
        if terminal_exit_fix is not None:
            key = (
                "terminal_exit",
                int(terminal_exit_fix.init_block),
                int(terminal_exit_fix.sink_block),
                int(terminal_exit_fix.exit_target or -1),
            )
            fixes[key] = terminal_exit_fix
            continue
        direct_exit_fix = _find_direct_exit_loop_for_header(cfg, block)
        if direct_exit_fix is not None:
            key = (
                "direct_exit",
                int(direct_exit_fix.init_block),
                int(direct_exit_fix.header_block),
                int(direct_exit_fix.exit_target),
            )
            fixes[key] = direct_exit_fix
            continue
        terminal_fix = _find_terminal_loop_for_header(cfg, block)
        if terminal_fix is not None:
            key = (
                "terminal",
                int(terminal_fix.init_block),
                int(terminal_fix.sink_block),
                int(terminal_fix.sink_old_target),
            )
            fixes[key] = terminal_fix
    return tuple(fixes[key] for key in sorted(fixes))


def _coerce_fixes(raw: object) -> tuple[LocalSelectLoopCandidate, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    fixes: list[LocalSelectLoopCandidate] = []
    for item in raw:
        if isinstance(
            item,
            (
                LocalSelectLoopFix,
                LocalSelectConvergenceLoopFix,
                LocalSelectDirectExitLoopFix,
            ),
        ):
            fixes.append(item)
            continue
        if isinstance(item, LocalSelectTerminalLoopFix):
            fixes.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        if item.get("kind") == "terminal_loop":
            try:
                fixes.append(
                    LocalSelectTerminalLoopFix(
                        init_block=int(item["init_block"]),
                        init_old_target=int(item["init_old_target"]),
                        sink_block=int(item["sink_block"]),
                        sink_old_target=int(item["sink_old_target"]),
                        exit_target=(
                            int(item["exit_target"])
                            if item.get("exit_target") is not None
                            else None
                        ),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
            continue
        if item.get("kind") == "direct_exit_loop":
            try:
                fixes.append(
                    LocalSelectDirectExitLoopFix(
                        init_block=int(item["init_block"]),
                        init_old_target=int(item["init_old_target"]),
                        header_block=int(item["header_block"]),
                        loop_entry_target=int(item["loop_entry_target"]),
                        exit_target=int(item["exit_target"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
            continue
        if "header_block" in item:
            try:
                fixes.append(
                    LocalSelectConvergenceLoopFix(
                        init_block=int(item["init_block"]),
                        header_block=int(item["header_block"]),
                        loop_entry_target=int(item["loop_entry_target"]),
                        exit_target=int(item["exit_target"]),
                    )
                )
            except (KeyError, TypeError, ValueError):
                continue
            continue
        try:
            fixes.append(
                LocalSelectLoopFix(
                    init_block=int(item["init_block"]),
                    init_old_target=int(item["init_old_target"]),
                    test_block=int(item["test_block"]),
                    test_old_target=int(item["test_old_target"]),
                    assignment_block=int(item["assignment_block"]),
                    assignment_old_target=int(item["assignment_old_target"]),
                    exit_target=int(item["exit_target"]),
                    selector_assignment_block=(
                        int(item["selector_assignment_block"])
                        if item.get("selector_assignment_block") is not None
                        else None
                    ),
                    selector_assignment_old_target=(
                        int(item["selector_assignment_old_target"])
                        if item.get("selector_assignment_old_target") is not None
                        else None
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(fixes)


def serialize_local_select_loop_fixes(
    fixes: Sequence[LocalSelectLoopCandidate],
) -> tuple[dict[str, int | str], ...]:
    """Serialize select-loop fixes into FlowGraph metadata."""
    serialized: list[dict[str, int | str]] = []
    for fix in sorted(
        fixes,
        key=lambda item: (
            item.__class__.__name__,
            int(item.init_block),
            int(getattr(item, "test_block", getattr(item, "header_block", -1))),
            int(
                getattr(
                    item,
                    "assignment_block",
                    getattr(item, "loop_entry_target", getattr(item, "sink_block", -1)),
                )
            ),
        ),
    ):
        if isinstance(fix, LocalSelectLoopFix):
            serialized.append(
                {
                    "kind": "select_loop",
                    "init_block": int(fix.init_block),
                    "init_old_target": int(fix.init_old_target),
                    "test_block": int(fix.test_block),
                    "test_old_target": int(fix.test_old_target),
                    "assignment_block": int(fix.assignment_block),
                    "assignment_old_target": int(fix.assignment_old_target),
                    "exit_target": int(fix.exit_target),
                    "selector_assignment_block": (
                        int(fix.selector_assignment_block)
                        if fix.selector_assignment_block is not None
                        else None
                    ),
                    "selector_assignment_old_target": (
                        int(fix.selector_assignment_old_target)
                        if fix.selector_assignment_old_target is not None
                        else None
                    ),
                }
            )
            continue
        if isinstance(fix, LocalSelectTerminalLoopFix):
            serialized.append(
                {
                    "kind": "terminal_loop",
                    "init_block": int(fix.init_block),
                    "init_old_target": int(fix.init_old_target),
                    "sink_block": int(fix.sink_block),
                    "sink_old_target": int(fix.sink_old_target),
                    "exit_target": (
                        int(fix.exit_target) if fix.exit_target is not None else None
                    ),
                }
            )
            continue
        if isinstance(fix, LocalSelectDirectExitLoopFix):
            serialized.append(
                {
                    "kind": "direct_exit_loop",
                    "init_block": int(fix.init_block),
                    "init_old_target": int(fix.init_old_target),
                    "header_block": int(fix.header_block),
                    "loop_entry_target": int(fix.loop_entry_target),
                    "exit_target": int(fix.exit_target),
                }
            )
            continue
        serialized.append(
            {
                "kind": "convergence_loop",
                "init_block": int(fix.init_block),
                "header_block": int(fix.header_block),
                "loop_entry_target": int(fix.loop_entry_target),
                "exit_target": int(fix.exit_target),
            }
        )
    return tuple(serialized)


def _is_valid_select_fix(cfg: FlowGraph, fix: LocalSelectLoopFix) -> bool:
    init_block = cfg.get_block(fix.init_block)
    test_block = cfg.get_block(fix.test_block)
    assignment_block = cfg.get_block(fix.assignment_block)
    exit_target = cfg.get_block(fix.exit_target)
    if (
        init_block is None
        or test_block is None
        or assignment_block is None
        or exit_target is None
    ):
        return False
    if init_block.nsucc != 1 or int(init_block.succs[0]) != int(fix.init_old_target):
        return False
    if test_block.nsucc != 2 or int(fix.test_old_target) not in test_block.succs:
        return False
    if (
        assignment_block.nsucc != 1
        or int(assignment_block.succs[0]) != int(fix.assignment_old_target)
    ):
        return False
    header = cfg.get_block(fix.init_old_target)
    if header is None or int(fix.exit_target) not in header.succs:
        return False
    if fix.selector_assignment_block is None:
        return fix.selector_assignment_old_target is None
    selector_assignment = cfg.get_block(fix.selector_assignment_block)
    if selector_assignment is None or fix.selector_assignment_old_target is None:
        return False
    return (
        selector_assignment.nsucc == 1
        and int(selector_assignment.succs[0])
        == int(fix.selector_assignment_old_target)
        and int(fix.selector_assignment_old_target) == int(fix.init_block)
    )


def _is_valid_convergence_fix(
    cfg: FlowGraph,
    fix: LocalSelectConvergenceLoopFix,
) -> bool:
    init_block = cfg.get_block(fix.init_block)
    header = cfg.get_block(fix.header_block)
    loop_entry = cfg.get_block(fix.loop_entry_target)
    exit_target = cfg.get_block(fix.exit_target)
    if (
        init_block is None
        or header is None
        or loop_entry is None
        or exit_target is None
    ):
        return False
    if init_block.nsucc != 1 or int(init_block.succs[0]) != int(header.serial):
        return False
    if header.nsucc != 2:
        return False
    if int(fix.loop_entry_target) not in header.succs:
        return False
    if int(fix.exit_target) not in header.succs:
        return False
    if int(fix.loop_entry_target) == int(fix.exit_target):
        return False
    return _find_convergence_loop_for_header(cfg, header) == fix


def _is_valid_terminal_fix(
    cfg: FlowGraph,
    fix: LocalSelectTerminalLoopFix,
) -> bool:
    init_block = cfg.get_block(fix.init_block)
    header = cfg.get_block(fix.init_old_target)
    sink = cfg.get_block(fix.sink_block)
    if init_block is None or header is None or sink is None:
        return False
    if init_block.nsucc != 1 or int(init_block.succs[0]) != int(fix.init_old_target):
        return False
    if sink.nsucc != 1 or int(sink.succs[0]) != int(fix.sink_old_target):
        return False
    if int(fix.sink_old_target) != int(fix.init_old_target):
        return False
    if fix.exit_target is not None:
        if cfg.get_block(fix.exit_target) is None:
            return False
        return (
            _find_terminal_exit_loop_for_header(cfg, header) == fix
            or _find_terminal_loop_for_header(cfg, header) == fix
        )
    return _find_terminal_loop_for_header(cfg, header) == fix


def _is_valid_direct_exit_fix(
    cfg: FlowGraph,
    fix: LocalSelectDirectExitLoopFix,
) -> bool:
    init_block = cfg.get_block(fix.init_block)
    header = cfg.get_block(fix.header_block)
    loop_entry = cfg.get_block(fix.loop_entry_target)
    exit_target = cfg.get_block(fix.exit_target)
    if (
        init_block is None
        or header is None
        or loop_entry is None
        or exit_target is None
    ):
        return False
    if init_block.nsucc != 1 or int(init_block.succs[0]) != int(fix.init_old_target):
        return False
    if int(fix.init_old_target) != int(fix.header_block):
        return False
    return _find_direct_exit_loop_for_header(cfg, header) == fix


def _is_valid_fix(cfg: FlowGraph, fix: LocalSelectLoopCandidate) -> bool:
    if isinstance(fix, LocalSelectLoopFix):
        return _is_valid_select_fix(cfg, fix)
    if isinstance(fix, LocalSelectTerminalLoopFix):
        return _is_valid_terminal_fix(cfg, fix)
    if isinstance(fix, LocalSelectDirectExitLoopFix):
        return _is_valid_direct_exit_fix(cfg, fix)
    return _is_valid_convergence_fix(cfg, fix)


def extract_local_select_loop_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[LocalSelectLoopCandidate, ...]:
    """Read validated local select-loop fixes from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    return tuple(
        fix
        for fix in _coerce_fixes(
            flow_graph.metadata.get(LOCAL_SELECT_LOOP_FIXES_METADATA_KEY)
        )
        if _is_valid_fix(flow_graph, fix)
    )


def build_local_select_loop_modifications(
    fixes: Sequence[LocalSelectLoopCandidate],
) -> list[GraphModification]:
    """Translate local select-loop evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
        if isinstance(fix, LocalSelectConvergenceLoopFix):
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.header_block),
                    goto_target=int(fix.exit_target),
                )
            )
            continue
        if isinstance(fix, LocalSelectTerminalLoopFix):
            if fix.exit_target is not None:
                modifications.append(
                    RedirectGoto(
                        from_serial=int(fix.init_block),
                        old_target=int(fix.init_old_target),
                        new_target=int(fix.exit_target),
                    )
                )
                continue
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.init_block),
                    old_target=int(fix.init_old_target),
                    new_target=int(fix.sink_block),
                )
            )
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.sink_block),
                    old_target=int(fix.sink_old_target),
                    new_target=int(fix.sink_block),
                )
            )
            continue
        if isinstance(fix, LocalSelectDirectExitLoopFix):
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.init_block),
                    old_target=int(fix.init_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            continue
        if (
            fix.selector_assignment_block is not None
            and fix.selector_assignment_old_target is not None
        ):
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.selector_assignment_block),
                    old_target=int(fix.selector_assignment_old_target),
                    new_target=int(fix.assignment_block),
                )
            )
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.init_block),
                    old_target=int(fix.init_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            modifications.append(
                RedirectGoto(
                    from_serial=int(fix.assignment_block),
                    old_target=int(fix.assignment_old_target),
                    new_target=int(fix.exit_target),
                )
            )
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.init_old_target),
                    goto_target=int(fix.exit_target),
                )
            )
            modifications.append(
                ConvertToGoto(
                    block_serial=int(fix.test_block),
                    goto_target=int(fix.exit_target),
                )
            )
            continue
        modifications.append(
            RedirectBranch(
                from_serial=int(fix.test_block),
                old_target=int(fix.test_old_target),
                new_target=int(fix.exit_target),
            )
        )
        modifications.append(
            RedirectGoto(
                from_serial=int(fix.assignment_block),
                old_target=int(fix.assignment_old_target),
                new_target=int(fix.exit_target),
            )
        )
        modifications.append(
            RedirectGoto(
                from_serial=int(fix.init_block),
                old_target=int(fix.init_old_target),
                new_target=int(fix.test_block),
            )
        )
        modifications.append(
            ConvertToGoto(
                block_serial=int(fix.init_old_target),
                goto_target=int(fix.exit_target),
            )
        )
    return modifications


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()
    for mod in modifications:
        if isinstance(mod, (RedirectBranch, RedirectGoto)):
            blocks.add(int(mod.from_serial))
            edges.add((int(mod.from_serial), int(mod.old_target)))
        elif isinstance(mod, ConvertToGoto):
            blocks.add(int(mod.block_serial))
    return OwnershipScope(
        blocks=frozenset(blocks),
        edges=frozenset(edges),
        transitions=frozenset(),
    )


class LocalSelectLoopStrategy:
    """Engine strategy for one-iteration local constant-select loops."""

    name = "local_select_loop"
    family = FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        return bool(extract_local_select_loop_fixes(snapshot.flow_graph))

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        fixes = extract_local_select_loop_fixes(snapshot.flow_graph)
        if not fixes:
            return None
        modifications = build_local_select_loop_modifications(fixes)
        if not modifications:
            return None
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            ownership=_build_ownership(modifications),
            prerequisites=[],
            expected_benefit=BenefitMetrics(
                handlers_resolved=0,
                transitions_resolved=0,
                blocks_freed=len(modifications),
                conflict_density=0.0,
            ),
            risk_score=0.2,
            metadata={
                LOCAL_SELECT_LOOP_FIXES_METADATA_KEY: (
                    serialize_local_select_loop_fixes(fixes)
                ),
                "safeguard_min_required": 1,
            },
            modifications=list(modifications),
        )


__all__ = [
    "LOCAL_SELECT_LOOP_FIXES_METADATA_KEY",
    "LocalSelectConvergenceLoopFix",
    "LocalSelectDirectExitLoopFix",
    "LocalSelectLoopCandidate",
    "LocalSelectLoopFix",
    "LocalSelectTerminalLoopFix",
    "LocalSelectLoopStrategy",
    "build_local_select_loop_modifications",
    "collect_local_select_loop_fixes",
    "extract_local_select_loop_fixes",
    "serialize_local_select_loop_fixes",
]
