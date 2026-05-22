"""Read-only discovery for predecessor-armed side-effect state loops."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnKind, OperandKind
from d810.core import logging
from d810.recon.flow.instruction_semantics import (
    branch_predicate,
    evaluate_branch_predicate,
    is_branch,
    is_goto,
    is_kind as _is_kind,
)


SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY = "side_effect_select_loop_fixes"
logger = logging.getLogger("D810.recon.flow.side_effect_select_loop")

VarId = tuple[str, int]
Env = dict[VarId, int]


@dataclass(frozen=True)
class SideEffectSelectLoopFix:
    """Validated rewrites for a side-effectful local state selector loop."""

    init_block: int
    header_block: int
    per_pred_targets: tuple[tuple[int, int], ...]
    terminal_redirects: tuple[tuple[int, int, int], ...]


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
        return int(value) & 0xFFFFFFFFFFFFFFFF
    except (TypeError, ValueError):
        return None


def _block_ref(mop: object | None) -> int | None:
    if mop is None:
        return None
    value = getattr(mop, "block_ref", None)
    if value is None:
        value = getattr(mop, "block_num", None)
    if value is None:
        return None
    try:
        return int(value)
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


def _is_simple_assign(insn: object | None) -> bool:
    if not (
        _is_kind(insn, InsnKind.MOV, "mov") or _is_kind(insn, InsnKind.XDU, "xdu")
    ):
        return False
    if _var_id(_operand(insn, "d")) is None:
        return False
    src = _operand(insn, "l")
    return _const_value(src) is not None or _var_id(src) is not None


def _is_branch(insn: object | None) -> bool:
    return is_branch(insn)


def _is_goto(insn: object | None) -> bool:
    return is_goto(insn)


def _last_insn(block: BlockSnapshot) -> object | None:
    return block.insn_snapshots[-1] if block.insn_snapshots else None


def _is_pure_dispatch_block(block: BlockSnapshot) -> bool:
    for insn in block.insn_snapshots:
        if _is_simple_assign(insn) or _is_branch(insn) or _is_goto(insn):
            continue
        return False
    return True


def _exec_simple_assignments(block: BlockSnapshot, env: Env) -> Env:
    result = dict(env)
    for insn in block.insn_snapshots:
        if not _is_simple_assign(insn):
            continue
        dst = _var_id(_operand(insn, "d"))
        if dst is None:
            continue
        src = _operand(insn, "l")
        value = _const_value(src)
        if value is None:
            src_id = _var_id(src)
            value = result.get(src_id) if src_id is not None else None
        if value is None:
            result.pop(dst, None)
        else:
            result[dst] = int(value)
    return result


def _eval_branch(block: BlockSnapshot, env: Env) -> bool | None:
    tail = _last_insn(block)
    if tail is None or not _is_branch(tail):
        return None
    left = _operand(tail, "l")
    right = _operand(tail, "r")
    left_value = _const_value(left)
    if left_value is None:
        left_id = _var_id(left)
        left_value = env.get(left_id) if left_id is not None else None
    right_value = _const_value(right)
    if right_value is None:
        right_id = _var_id(right)
        right_value = env.get(right_id) if right_id is not None else None
    return evaluate_branch_predicate(
        branch_predicate(tail),
        left_value,
        right_value,
    )


def _branch_targets(block: BlockSnapshot) -> tuple[int, int] | None:
    tail = _last_insn(block)
    taken = _block_ref(_operand(tail, "d"))
    if taken is None or taken not in block.succs:
        return None
    fallthrough = tuple(int(succ) for succ in block.succs if int(succ) != int(taken))
    if len(fallthrough) != 1:
        return None
    return int(taken), fallthrough[0]


def _next_successors(block: BlockSnapshot, env: Env) -> tuple[int, ...] | None:
    if block.nsucc == 0:
        return ()
    if block.nsucc == 1:
        return (int(block.succs[0]),)
    if block.nsucc != 2:
        return None
    targets = _branch_targets(block)
    if targets is None:
        return None
    taken, fallthrough = targets
    decision = _eval_branch(block, env)
    if decision is None:
        return None
    return (taken if decision else fallthrough,)


def _simulate_to_payload(
    cfg: FlowGraph,
    start: int,
    env: Env,
    *,
    max_steps: int = 24,
) -> tuple[int, Env] | None:
    current = int(start)
    current_env = dict(env)
    seen: set[tuple[int, tuple[tuple[VarId, int], ...]]] = set()
    for _ in range(max_steps):
        block = cfg.get_block(current)
        if block is None:
            return None
        state_key = (current, tuple(sorted(current_env.items())))
        if state_key in seen:
            return None
        seen.add(state_key)
        if not _is_pure_dispatch_block(block):
            return current, current_env
        current_env = _exec_simple_assignments(block, current_env)
        successors = _next_successors(block, current_env)
        if successors is None or len(successors) != 1:
            return None
        current = successors[0]
    return None


def _explore_payload_terminals(
    cfg: FlowGraph,
    start: int,
    header: int,
    env: Env,
    *,
    max_depth: int = 12,
) -> dict[int, Env]:
    terminals: dict[int, Env] = {}
    stack: list[tuple[int, Env, int]] = [(int(start), dict(env), 0)]
    seen: set[tuple[int, tuple[tuple[VarId, int], ...]]] = set()
    while stack:
        serial, current_env, depth = stack.pop()
        if depth > max_depth:
            continue
        block = cfg.get_block(serial)
        if block is None or int(serial) == int(header):
            continue
        state_key = (serial, tuple(sorted(current_env.items())))
        if state_key in seen:
            continue
        seen.add(state_key)
        next_env = _exec_simple_assignments(block, current_env)
        if block.nsucc == 1 and int(block.succs[0]) == int(header):
            if not _is_pure_dispatch_block(block):
                terminals[int(serial)] = next_env
            continue
        if block.nsucc == 0:
            continue
        successors: tuple[int, ...]
        resolved = _next_successors(block, next_env)
        if resolved is None:
            successors = tuple(int(succ) for succ in block.succs)
        else:
            successors = resolved
        for succ in successors:
            stack.append((int(succ), dict(next_env), depth + 1))
    return terminals


def _can_reach_block(
    cfg: FlowGraph,
    start: int,
    target: int,
    *,
    max_depth: int = 16,
) -> bool:
    stack: list[tuple[int, int]] = [(int(start), 0)]
    seen: set[int] = set()
    while stack:
        serial, depth = stack.pop()
        if depth > max_depth:
            continue
        if int(serial) == int(target):
            return True
        if serial in seen:
            continue
        seen.add(serial)
        block = cfg.get_block(serial)
        if block is None:
            continue
        for succ in block.succs:
            stack.append((int(succ), depth + 1))
    return False


def _find_side_effect_select_loop(
    cfg: FlowGraph,
    init_block: BlockSnapshot,
) -> SideEffectSelectLoopFix | None:
    if init_block.nsucc != 1 or init_block.npred != 2:
        return None

    def reject(reason: str) -> None:
        if logger.debug_on:
            logger.debug(
                "Rejected side-effect selector loop init blk[%d]: %s",
                int(init_block.serial),
                reason,
            )

    header = cfg.get_block(int(init_block.succs[0]))
    if header is None or header.nsucc != 2:
        reject("missing_or_non_2way_header")
        return None

    per_pred_targets: list[tuple[int, int]] = []
    terminal_redirects: dict[int, tuple[int, int, int]] = {}
    exit_target: int | None = None
    for pred_serial in init_block.preds:
        pred = cfg.get_block(int(pred_serial))
        if pred is None:
            reject(f"missing_pred:{int(pred_serial)}")
            return None
        env = _exec_simple_assignments(pred, {})
        env = _exec_simple_assignments(init_block, env)
        target = _simulate_to_payload(cfg, int(header.serial), env)
        if target is None:
            reject(f"unresolved_pred_target:{int(pred_serial)}")
            return None
        target_serial, target_env = target
        terminals = _explore_payload_terminals(
            cfg,
            target_serial,
            int(header.serial),
            target_env,
        )
        if not terminals and _can_reach_block(
            cfg,
            int(target_serial),
            int(header.serial),
        ):
            reject(f"no_payload_terminal:{int(target_serial)}")
            return None
        per_pred_targets.append((int(pred_serial), int(target_serial)))
        for terminal, terminal_env in terminals.items():
            exit_result = _simulate_to_payload(
                cfg,
                int(header.serial),
                terminal_env,
            )
            if exit_result is None:
                reject(f"unresolved_terminal_exit:{int(terminal)}")
                return None
            terminal_exit, _exit_env = exit_result
            if terminal_exit in {int(header.serial), int(target_serial)}:
                reject(f"terminal_exit_not_progress:{int(terminal)}")
                return None
            if exit_target is None:
                exit_target = int(terminal_exit)
            elif int(exit_target) != int(terminal_exit):
                reject(f"non_common_exit:{int(terminal)}->{int(terminal_exit)}")
                return None
            terminal_redirects[int(terminal)] = (
                int(terminal),
                int(header.serial),
                int(terminal_exit),
            )

    if len({target for _pred, target in per_pred_targets}) != len(per_pred_targets):
        reject("duplicate_pred_targets")
        return None
    if not per_pred_targets:
        reject("missing_pred_targets")
        return None
    return SideEffectSelectLoopFix(
        init_block=int(init_block.serial),
        header_block=int(header.serial),
        per_pred_targets=tuple(per_pred_targets),
        terminal_redirects=tuple(
            terminal_redirects[key] for key in sorted(terminal_redirects)
        ),
    )


def collect_side_effect_select_loop_fixes(
    cfg: FlowGraph | None,
) -> tuple[SideEffectSelectLoopFix, ...]:
    """Collect side-effectful selector state loops from a lifted CFG."""
    if cfg is None:
        return ()
    fixes: dict[int, SideEffectSelectLoopFix] = {}
    for block in cfg.blocks.values():
        fix = _find_side_effect_select_loop(cfg, block)
        if fix is not None:
            fixes[int(fix.init_block)] = fix
    return tuple(fixes[key] for key in sorted(fixes))


def _coerce_fixes(raw: object) -> tuple[SideEffectSelectLoopFix, ...]:
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        return ()
    fixes: list[SideEffectSelectLoopFix] = []
    for item in raw:
        if isinstance(item, SideEffectSelectLoopFix):
            fixes.append(item)
            continue
        if not isinstance(item, Mapping):
            continue
        try:
            fixes.append(
                SideEffectSelectLoopFix(
                    init_block=int(item["init_block"]),
                    header_block=int(item["header_block"]),
                    per_pred_targets=tuple(
                        (int(pred), int(target))
                        for pred, target in item["per_pred_targets"]
                    ),
                    terminal_redirects=tuple(
                        (int(src), int(old), int(new))
                        for src, old, new in item["terminal_redirects"]
                    ),
                )
            )
        except (KeyError, TypeError, ValueError):
            continue
    return tuple(fixes)


def serialize_side_effect_select_loop_fixes(
    fixes: Sequence[SideEffectSelectLoopFix],
) -> tuple[dict[str, object], ...]:
    """Serialize side-effect selector-loop fixes into FlowGraph metadata."""
    return tuple(
        {
            "init_block": int(fix.init_block),
            "header_block": int(fix.header_block),
            "per_pred_targets": tuple(
                (int(pred), int(target)) for pred, target in fix.per_pred_targets
            ),
            "terminal_redirects": tuple(
                (int(src), int(old), int(new))
                for src, old, new in fix.terminal_redirects
            ),
        }
        for fix in sorted(fixes, key=lambda item: int(item.init_block))
    )


def _canonical_fix(fix: SideEffectSelectLoopFix) -> SideEffectSelectLoopFix:
    return SideEffectSelectLoopFix(
        init_block=int(fix.init_block),
        header_block=int(fix.header_block),
        per_pred_targets=tuple(
            sorted((int(pred), int(target)) for pred, target in fix.per_pred_targets)
        ),
        terminal_redirects=tuple(
            sorted(
                (int(src), int(old), int(new))
                for src, old, new in fix.terminal_redirects
            )
        ),
    )


def _is_valid_fix(cfg: FlowGraph, fix: SideEffectSelectLoopFix) -> bool:
    init_block = cfg.get_block(fix.init_block)
    header_block = cfg.get_block(fix.header_block)
    if init_block is None or header_block is None:
        return False
    if init_block.nsucc != 1 or int(init_block.succs[0]) != int(fix.header_block):
        return False
    if len(fix.per_pred_targets) != 2:
        return False
    for pred, target in fix.per_pred_targets:
        if int(pred) not in init_block.preds:
            return False
        if cfg.get_block(int(target)) is None:
            return False
    for src, old, new in fix.terminal_redirects:
        block = cfg.get_block(int(src))
        if block is None or block.nsucc != 1 or int(block.succs[0]) != int(old):
            return False
        if int(old) != int(fix.header_block) or cfg.get_block(int(new)) is None:
            return False
    rediscovered = {
        _canonical_fix(candidate)
        for candidate in collect_side_effect_select_loop_fixes(cfg)
    }
    return _canonical_fix(fix) in rediscovered


def extract_side_effect_select_loop_fixes(
    flow_graph: FlowGraph | None,
) -> tuple[SideEffectSelectLoopFix, ...]:
    """Read validated side-effect selector-loop fixes from metadata."""
    if flow_graph is None:
        return ()
    return tuple(
        fix
        for fix in _coerce_fixes(
            flow_graph.metadata.get(SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY)
        )
        if _is_valid_fix(flow_graph, fix)
    )


__all__ = [
    "SIDE_EFFECT_SELECT_LOOP_FIXES_METADATA_KEY",
    "SideEffectSelectLoopFix",
    "collect_side_effect_select_loop_fixes",
    "extract_side_effect_select_loop_fixes",
    "serialize_side_effect_select_loop_fixes",
]
