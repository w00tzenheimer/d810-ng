"""Cleanup strategy for local constant-select loop shells."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, OperandKind
from d810.cfg.graph_modification import GraphModification, RedirectBranch, RedirectGoto
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


@dataclass(frozen=True)
class _HeaderStep:
    state_id: VarId
    selector_id: VarId
    previous_id: VarId
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


def _compare_var_const(block: BlockSnapshot) -> tuple[VarId, int] | None:
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
        return left_var, int(right_const)
    if right_var is not None and left_const is not None:
        return right_var, int(left_const)
    return None


def _parse_header_step(header: BlockSnapshot) -> _HeaderStep | None:
    compare = _compare_var_const(header)
    if compare is None:
        return None
    previous_id, init_const = compare
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
        init_const=int(init_const),
    )


def _has_payload_var_assignment(block: BlockSnapshot, *, state_id: VarId) -> bool:
    for insn in _iter_assignments(block):
        assignment = _var_assignment(insn)
        if assignment is None:
            continue
        dst, src = assignment
        if dst != state_id and src != state_id:
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
        if not _has_payload_var_assignment(assignment, state_id=step.state_id):
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
        return LocalSelectLoopFix(
            init_block=int(init_block.serial),
            init_old_target=int(header.serial),
            test_block=int(test_block.serial),
            test_old_target=int(header.serial),
            assignment_block=int(assignment.serial),
            assignment_old_target=int(header.serial),
            exit_target=int(exit_targets[0]),
        )
    return None


def collect_local_select_loop_fixes(
    cfg: FlowGraph | None,
) -> tuple[LocalSelectLoopFix, ...]:
    """Collect one-iteration local select loops from a lifted CFG."""
    if cfg is None:
        return ()
    fixes: dict[tuple[int, int, int], LocalSelectLoopFix] = {}
    for block in cfg.blocks.values():
        fix = _find_select_loop_for_header(cfg, block)
        if fix is None:
            continue
        key = (
            int(fix.init_block),
            int(fix.test_block),
            int(fix.assignment_block),
        )
        fixes[key] = fix
    return tuple(fixes[key] for key in sorted(fixes))


def _coerce_fixes(raw: object) -> tuple[LocalSelectLoopFix, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    fixes: list[LocalSelectLoopFix] = []
    for item in raw:
        if isinstance(item, LocalSelectLoopFix):
            fixes.append(item)
            continue
        if not isinstance(item, Mapping):
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
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(fixes)


def serialize_local_select_loop_fixes(
    fixes: Sequence[LocalSelectLoopFix],
) -> tuple[dict[str, int], ...]:
    """Serialize select-loop fixes into FlowGraph metadata."""
    return tuple(
        {
            "init_block": int(fix.init_block),
            "init_old_target": int(fix.init_old_target),
            "test_block": int(fix.test_block),
            "test_old_target": int(fix.test_old_target),
            "assignment_block": int(fix.assignment_block),
            "assignment_old_target": int(fix.assignment_old_target),
            "exit_target": int(fix.exit_target),
        }
        for fix in sorted(
            fixes,
            key=lambda item: (
                int(item.init_block),
                int(item.test_block),
                int(item.assignment_block),
            ),
        )
    )


def _is_valid_fix(cfg: FlowGraph, fix: LocalSelectLoopFix) -> bool:
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
    return header is not None and int(fix.exit_target) in header.succs


def extract_local_select_loop_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[LocalSelectLoopFix, ...]:
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
    fixes: Sequence[LocalSelectLoopFix],
) -> list[GraphModification]:
    """Translate local select-loop evidence into graph edits."""
    modifications: list[GraphModification] = []
    for fix in fixes:
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
    return modifications


def _build_ownership(modifications: Sequence[GraphModification]) -> OwnershipScope:
    blocks: set[int] = set()
    edges: set[tuple[int, int]] = set()
    for mod in modifications:
        if isinstance(mod, (RedirectBranch, RedirectGoto)):
            blocks.add(int(mod.from_serial))
            edges.add((int(mod.from_serial), int(mod.old_target)))
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
    "LocalSelectLoopFix",
    "LocalSelectLoopStrategy",
    "build_local_select_loop_modifications",
    "collect_local_select_loop_fixes",
    "extract_local_select_loop_fixes",
    "serialize_local_select_loop_fixes",
]
