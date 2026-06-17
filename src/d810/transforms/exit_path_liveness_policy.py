"""Exit-path liveness policy — decide whether shortcutting over witness blocks is legal.

Branch witnesses prove which dispatcher arm is feasible.  This module decides
whether bypassing the selected witness exit path would sever a live non-state
use-def chain.  The state variable itself is intentionally severed by the
unflattening and is ignored.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.control_flow.branch_witness import (
    BranchWitnessAbstain,
    BranchWitnessConflict,
)
from d810.core import logging
from d810.ir.block_identity import block_label
from d810.ir.flowgraph import InsnKind, PredicateKind

logger = logging.getLogger("D810.transforms.exit_path_liveness_policy")


@dataclass(frozen=True, slots=True)
class ExitPathShortcutDecision:
    """Decision for shortcutting over an exact branch-witness exit path."""

    allowed: bool
    reason: str
    exit_path_blocks: tuple[int, ...] = ()
    live_definitions: tuple[tuple[str, int], ...] = ()


def _int_or_none(value: object) -> int | None:
    try:
        return int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _format_block_label(flow_graph: object, serial: object | None) -> str:
    try:
        return block_label(flow_graph, None if serial is None else int(serial))  # type: ignore[arg-type]
    except Exception:
        return "blk[?]@?" if serial is None else f"blk[{serial}]@?"


def _variable_key(operand: object) -> tuple[str, int] | None:
    """Canonical identity for a directly named non-state operand."""
    if operand is None:
        return None
    stkoff = _int_or_none(getattr(operand, "stkoff", None))
    if stkoff is not None:
        return ("stk", int(stkoff))
    reg = _int_or_none(getattr(operand, "reg", None))
    if reg is not None:
        return ("reg", int(reg))
    refs = getattr(operand, "stack_refs", ()) or ()
    if refs:
        return ("stk", int(refs[0]))
    return None


def _variable_keys(operand: object) -> set[tuple[str, int]]:
    """All variable identities read by ``operand``, including nested sub-insns."""
    found: set[tuple[str, int]] = set()
    seen: set[int] = set()

    def _walk(cur: object) -> None:
        if cur is None:
            return
        ident = id(cur)
        if ident in seen:
            return
        seen.add(ident)
        key = _variable_key(cur)
        if key is not None:
            found.add(key)
        for stkoff in getattr(cur, "stack_refs", ()) or ():
            found.add(("stk", int(stkoff)))
        for attr in ("sub_l", "sub_r", "sub_operand"):
            _walk(getattr(cur, attr, None))
        sub_insn = getattr(cur, "sub_instruction", None)
        if sub_insn is not None:
            _walk(getattr(sub_insn, "l", None))
            _walk(getattr(sub_insn, "r", None))
            # Function-call argument lists can hide additional register/stack uses.
            dest = getattr(sub_insn, "d", None)
            for arg in getattr(dest, "args", ()) or ():
                _walk(arg)

    _walk(operand)
    return found


def _operand_literal_value(operand: object) -> int | None:
    return _int_or_none(getattr(operand, "value", None))


def _normal_predicate(predicate: object) -> str:
    return str(getattr(predicate, "value", predicate) or "")


def _constant_defs_for_key(
    block: object,
    key: tuple[str, int],
) -> tuple[set[int], bool]:
    """Return constant values assigned to ``key`` and whether all defs were constants."""
    values: set[int] = set()
    all_constant = True
    for insn in getattr(block, "insn_snapshots", ()) or ():
        if _variable_key(getattr(insn, "d", None)) != key:
            continue
        value = _operand_literal_value(getattr(insn, "l", None))
        if value is None or getattr(insn, "kind", None) is not InsnKind.MOV:
            all_constant = False
            continue
        values.add(int(value))
    return values, all_constant


def _edge_proves_constant(
    flow_graph: object,
    source_block: int,
    selected_successor: int,
    key: tuple[str, int],
    value: int,
) -> bool:
    """Return whether ``source_block -> selected_successor`` already proves ``key == value``.

    This keeps no-provider liveness from rejecting nested dispatcher exit paths
    whose selected incoming edge has already established the same outer-state
    constant that the skipped exit-path block redundantly writes.
    """
    block = flow_graph.get_block(int(source_block))
    if block is None or int(selected_successor) not in tuple(
        int(s) for s in getattr(block, "succs", ())
    ):
        return False

    # A one-way predecessor can prove the value if it assigns that exact constant
    # before entering the exit path.
    if int(getattr(block, "nsucc", len(getattr(block, "succs", ())) or 0)) == 1:
        values, all_constant = _constant_defs_for_key(block, key)
        return all_constant and values == {int(value)}

    tail = getattr(block, "tail", None)
    if tail is None:
        insns = tuple(getattr(block, "insn_snapshots", ()) or ())
        tail = insns[-1] if insns else None
    if tail is None or not bool(getattr(tail, "is_conditional_jump", False)):
        return False

    compare_value = _operand_literal_value(getattr(tail, "r", None))
    compare_key = _variable_key(getattr(tail, "l", None))
    if compare_key != key or compare_value is None or int(compare_value) != int(value):
        compare_value = _operand_literal_value(getattr(tail, "l", None))
        compare_key = _variable_key(getattr(tail, "r", None))
    if compare_key != key or compare_value is None or int(compare_value) != int(value):
        return False

    taken = _int_or_none(getattr(getattr(tail, "d", None), "block_ref", None))
    if taken is None:
        return False
    pred = _normal_predicate(getattr(tail, "branch_predicate", None))
    selected_is_taken = int(selected_successor) == int(taken)
    if pred == PredicateKind.EQ.value:
        return selected_is_taken
    if pred == PredicateKind.NE.value:
        return not selected_is_taken
    return False


def _value_preserving_live_definitions(
    flow_graph: object,
    exit_path_blocks: tuple[int, ...],
    unsafe: set[tuple[str, int]],
    *,
    source_blocks: tuple[int, ...],
    old_target: int | None,
) -> set[tuple[str, int]]:
    """Live exit-path definitions that are safe because skipped writes are redundant."""
    if old_target is None or not source_blocks:
        return set()
    preserving: set[tuple[str, int]] = set()
    for key in unsafe:
        values: set[int] = set()
        all_constant = True
        saw_definition = False
        for serial in exit_path_blocks:
            block = flow_graph.get_block(int(serial))
            if block is None:
                continue
            block_values, block_all_constant = _constant_defs_for_key(block, key)
            if block_values or not block_all_constant:
                saw_definition = True
            values |= block_values
            all_constant = all_constant and block_all_constant
        if not saw_definition or not all_constant or len(values) != 1:
            continue
        value = next(iter(values))
        if all(
            _edge_proves_constant(flow_graph, source, int(old_target), key, value)
            for source in source_blocks
        ):
            preserving.add(key)
    return preserving


def _block_gen_kill(block: object, state_var_stkoff: int | None):
    """Return (gen, kill) variable sets for one block.

    A stack/register location is killed by a definition (``d`` operand) and
    generated by a use (``l`` or ``r`` operand).  The state variable is excluded
    from both sets.
    """
    gen: set[tuple[str, int]] = set()
    kill: set[tuple[str, int]] = set()
    state_key: tuple[str, int] | None = None
    if state_var_stkoff is not None:
        state_key = ("stk", int(state_var_stkoff))

    for insn in getattr(block, "insn_snapshots", ()) or ():
        # Uses first (a use in the same instruction is not killed by its own def).
        for operand in (getattr(insn, "l", None), getattr(insn, "r", None)):
            for key in _variable_keys(operand):
                if key != state_key:
                    gen.add(key)
        dest = getattr(insn, "d", None)
        key = _variable_key(dest)
        if key is not None and key != state_key:
            kill.add(key)
    return gen, kill


def _compute_liveness(
    flow_graph: object,
    state_var_stkoff: int | None,
) -> dict[int, set[tuple[str, int]]]:
    """Backward dataflow: live-in variables per block."""
    blocks: dict[int, object] = {}
    for serial in getattr(flow_graph, "blocks", ()):
        block = flow_graph.get_block(serial)
        if block is not None:
            blocks[int(serial)] = block

    gen: dict[int, set[tuple[str, int]]] = {}
    kill: dict[int, set[tuple[str, int]]] = {}
    for serial, block in blocks.items():
        g, k = _block_gen_kill(block, state_var_stkoff)
        gen[serial] = g
        kill[serial] = k

    live_in: dict[int, set[tuple[str, int]]] = {serial: set() for serial in blocks}
    live_out: dict[int, set[tuple[str, int]]] = {serial: set() for serial in blocks}

    changed = True
    while changed:
        changed = False
        for serial in blocks:
            new_out: set[tuple[str, int]] = set()
            for succ in getattr(blocks[serial], "succs", ()):
                succ_i = int(succ)
                if succ_i in live_in:
                    new_out |= live_in[succ_i]
            if new_out != live_out[serial]:
                live_out[serial] = new_out
                changed = True
            new_in = (new_out - kill[serial]) | gen[serial]
            if new_in != live_in[serial]:
                live_in[serial] = new_in
                changed = True

    return live_in


def block_defined_variables(
    block: object,
    state_var_stkoff: int | None,
) -> set[tuple[str, int]]:
    """Return non-state variables directly defined by ``block``."""
    _gen, kill = _block_gen_kill(block, state_var_stkoff)
    return set(kill)


def live_in_variables(
    flow_graph: object,
    state_var_stkoff: int | None,
) -> dict[int, set[tuple[str, int]]]:
    """Return live-in variables per block."""
    return _compute_liveness(flow_graph, state_var_stkoff)


def exit_path_shortcut_live_violations(
    flow_graph: object,
    witness_path: tuple[object, ...],
    shortcut_target: int,
    state_var_stkoff: int | None,
) -> set[tuple[str, int]]:
    """Return live non-state definitions bypassed by shortcutting an exit path.

    A non-state variable defined in the witness exit path is unsafe to bypass if
    it is live at the entry of ``shortcut_target``.  The state variable is the
    unflattening target and is never counted.
    """
    live_in = _compute_liveness(flow_graph, state_var_stkoff)
    target_live = live_in.get(int(shortcut_target), set())
    if not target_live:
        return set()

    exit_path_defs: set[tuple[str, int]] = set()
    for witness in witness_path:
        compare_serial = _int_or_none(getattr(witness, "compare_block", None))
        if compare_serial is None:
            continue
        block = flow_graph.get_block(compare_serial)
        if block is None:
            continue
        _gen, kill = _block_gen_kill(block, state_var_stkoff)
        exit_path_defs |= kill

    unsafe = exit_path_defs & target_live
    if unsafe and logger.debug_on:
        logger.debug(
            "exit-path liveness rejects shortcut to %s: live variables %s "
            "defined in exit path %s",
            _format_block_label(flow_graph, shortcut_target),
            sorted(unsafe),
            [
                _format_block_label(flow_graph, getattr(w, "compare_block", None))
                for w in witness_path
            ],
        )
    return set(unsafe)


def exit_path_blocks_live_violations(
    flow_graph: object,
    exit_path_blocks: tuple[int, ...],
    shortcut_target: int,
    state_var_stkoff: int | None,
    *,
    source_blocks: tuple[int, ...] = (),
    old_target: int | None = None,
) -> set[tuple[str, int]]:
    """Return live non-state definitions bypassed by shortcutting blocks.

    This is the no-provider fallback for profiles that can identify the
    dispatcher exit path but cannot yet prove an exact selected/rejected branch
    witness.  It does not prove feasibility; it only decides whether the legacy
    endpoint shortcut would skip a live stack/register definition.
    """
    live_in = _compute_liveness(flow_graph, state_var_stkoff)
    target_live = live_in.get(int(shortcut_target), set())
    if not target_live:
        return set()

    exit_path_defs: set[tuple[str, int]] = set()
    for serial in exit_path_blocks:
        block = flow_graph.get_block(int(serial))
        if block is None:
            continue
        _gen, kill = _block_gen_kill(block, state_var_stkoff)
        exit_path_defs |= kill
    unsafe = exit_path_defs & target_live
    unsafe -= _value_preserving_live_definitions(
        flow_graph,
        tuple(int(block) for block in exit_path_blocks),
        unsafe,
        source_blocks=tuple(int(block) for block in source_blocks),
        old_target=old_target,
    )
    if unsafe and logger.debug_on:
        logger.debug(
            "exit-path liveness rejects no-provider shortcut to %s: "
            "live variables %s defined in exit path %s",
            _format_block_label(flow_graph, shortcut_target),
            sorted(unsafe),
            [_format_block_label(flow_graph, b) for b in exit_path_blocks],
        )
    return set(unsafe)


def exit_path_shortcut_is_live_safe(
    flow_graph: object,
    witness_path: tuple[object, ...],
    shortcut_target: int,
    state_var_stkoff: int | None,
) -> bool:
    """Return ``True`` if bypassing ``witness_path`` blocks is use-def safe."""

    return not exit_path_shortcut_live_violations(
        flow_graph, witness_path, shortcut_target, state_var_stkoff
    )


def evaluate_exit_path_shortcut(
    flow_graph: object,
    witness_result: object,
    shortcut_target: int,
    state_var_stkoff: int | None,
) -> ExitPathShortcutDecision:
    """Apply shortcut legality after branch feasibility has been proven.

    Branch-witness resolution is the feasibility policy.  This function consumes
    its exact/abstain/conflict result and then applies the liveness policy as a
    second, independent gate.
    """
    if isinstance(witness_result, BranchWitnessAbstain):
        return ExitPathShortcutDecision(
            allowed=False,
            reason=f"witness_abstain:{witness_result.reason}",
        )
    if isinstance(witness_result, BranchWitnessConflict):
        return ExitPathShortcutDecision(
            allowed=False,
            reason="witness_conflict",
        )

    witness_path = tuple(witness_result) if witness_result is not None else ()
    exit_path_blocks = tuple(
        int(compare_block)
        for witness in witness_path
        for compare_block in (_int_or_none(getattr(witness, "compare_block", None)),)
        if compare_block is not None
    )
    if not witness_path:
        return ExitPathShortcutDecision(
            allowed=False,
            reason="empty_witness_path",
            exit_path_blocks=exit_path_blocks,
        )
    unsafe = exit_path_shortcut_live_violations(
        flow_graph, witness_path, int(shortcut_target), state_var_stkoff
    )
    if unsafe:
        return ExitPathShortcutDecision(
            allowed=False,
            reason="exit_path_liveness_unsafe",
            exit_path_blocks=exit_path_blocks,
            live_definitions=tuple(sorted(unsafe)),
        )
    return ExitPathShortcutDecision(
        allowed=True,
        reason="exact_witness_live_safe",
        exit_path_blocks=exit_path_blocks,
    )


__all__ = [
    "ExitPathShortcutDecision",
    "block_defined_variables",
    "exit_path_blocks_live_violations",
    "exit_path_shortcut_live_violations",
    "exit_path_shortcut_is_live_safe",
    "evaluate_exit_path_shortcut",
    "live_in_variables",
]
