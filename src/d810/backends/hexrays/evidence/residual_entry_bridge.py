"""Recognize a proven two-state entry predicate in live microcode.

The recognizer is intentionally evidence-only.  It identifies the compact
``default; jcc; one-arm overwrite; merged stack store`` form emitted from an
x86 conditional move, but does not resolve targets or mutate the database.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.control_flow.residual_entry_bridge import (
    EntryBridgeEvidence as ResidualEntryBridgeEvidence,
    StateRoutingNode,
)
from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from d810.core.typing import Mapping


@dataclass(frozen=True, slots=True)
class ConditionalHandlerBridgeEvidence:
    """One CALLS-maturity live handler fork with exact state-routed arms."""

    source_block_ea: int
    predicate_ea: int
    predicate_register: int | None
    predicate_size: int
    predicate_compare_register: int | None
    predicate_compare_constant: int | None
    predicate_predecessor_ea: int | None
    true_state: int
    false_state: int
    true_target_ea: int
    false_target_ea: int
    true_is_taken: bool


def _opcode(name: str) -> int | None:
    value = getattr(ida_hexrays, name, None)
    return int(value) if value is not None else None


def _instructions(block: object) -> tuple[object, ...]:
    current = block.head
    tail = block.tail
    result: list[object] = []
    while current is not None:
        result.append(current)
        if current is tail or current == tail:
            break
        current = current.next
    return tuple(result)


def _successors(block: object) -> tuple[int, ...]:
    try:
        return tuple(int(block.succ(index)) for index in range(int(block.nsucc())))
    except Exception:
        return ()


def _register(mop: object) -> int | None:
    if mop.t != _opcode("mop_r"):
        return None
    return int(mop.r)


def _immediate(mop: object) -> int | None:
    if mop.t != _opcode("mop_n"):
        return None
    return int(mop.nnn.value)


def _stack_identity(mop: object) -> tuple[int, int] | None:
    if mop.t != _opcode("mop_S"):
        return None
    return int(mop.s.off), int(mop.size)


def _block_native_entry_ea(block: object) -> int | None:
    native_eas = {
        int(insn.ea)
        for insn in _instructions(block)
        if int(insn.ea) > 0
    }
    return min(native_eas) if native_eas else None


def _condition_code(opcode: int) -> int | None:
    for name, code in (("m_jz", 4), ("m_jnz", 5)):
        if opcode == _opcode(name):
            return code
    return None


def _state_condition_code(opcode: int) -> int | None:
    for name, code in (
        ("m_jc", 2),
        ("m_jb", 2),
        ("m_jnc", 3),
        ("m_jae", 3),
        ("m_jz", 4),
        ("m_jnz", 5),
        ("m_jbe", 6),
        ("m_ja", 7),
        ("m_jl", 12),
        ("m_jge", 13),
        ("m_jle", 14),
        ("m_jg", 15),
    ):
        if opcode == _opcode(name):
            return code
    return None


def _apply_moves(instructions: tuple[object, ...], values: dict[int, int]) -> None:
    for insn in instructions:
        if int(insn.opcode) != _opcode("m_mov"):
            continue
        destination = _register(insn.d)
        if destination is None:
            continue
        immediate = _immediate(insn.l)
        source = _register(insn.l)
        if immediate is not None:
            values[destination] = immediate
        elif source is not None and source in values:
            values[destination] = values[source]
        else:
            values.pop(destination, None)


def _state_store(
    mba: object,
    start_serial: int,
    defaults: dict[int, int],
) -> tuple[tuple[int, int], int, int] | None:
    """Follow one bounded arm to its state-cell store, or abstain."""
    values = dict(defaults)
    serial = int(start_serial)
    seen: set[int] = set()
    for _hop in range(3):
        if serial in seen:
            return None
        seen.add(serial)
        try:
            block = mba.get_mblock(serial)
        except Exception:
            return None
        if block is None:
            return None
        instructions = _instructions(block)
        for insn in instructions:
            if int(insn.opcode) == _opcode("m_mov"):
                source = _register(insn.l)
                destination = _stack_identity(insn.d)
                if source is not None and destination is not None and source in values:
                    return destination, values[source], int(insn.ea)
        _apply_moves(instructions, values)
        successors = _successors(block)
        if len(successors) != 1:
            return None
        serial = successors[0]
    return None


def recognize_residual_entry_bridge(mba: object) -> ResidualEntryBridgeEvidence | None:
    """Recognize one direct stack predicate with two proven initial states.

    The condition must compare a direct frame operand with zero.  The selected
    values must both reach the same direct stack store through at most two
    one-way arm blocks.  Any ambiguity abstains.
    """
    try:
        blocks = tuple(mba.get_mblock(index) for index in range(int(mba.qty)))
    except Exception:
        return None
    for block in blocks:
        if block is None:
            continue
        instructions = _instructions(block)
        branch = instructions[-1] if instructions else None
        if branch is None:
            continue
        code = _condition_code(int(branch.opcode))
        if code is None:
            continue
        predicate = _stack_identity(branch.l)
        compared = _immediate(branch.r)
        taken = branch.d.b
        successors = _successors(block)
        if predicate is None or compared != 0:
            continue
        taken = int(taken)
        if len(successors) != 2 or taken not in successors:
            continue
        fallthrough = next((serial for serial in successors if serial != taken), None)
        if fallthrough is None:
            continue
        defaults: dict[int, int] = {}
        _apply_moves(instructions[:-1], defaults)
        taken_store = _state_store(mba, taken, defaults)
        fallthrough_store = _state_store(mba, fallthrough, defaults)
        if taken_store is None or fallthrough_store is None:
            continue
        taken_cell, taken_value, taken_store_ea = taken_store
        fallthrough_cell, fallthrough_value, fallthrough_store_ea = fallthrough_store
        if taken_cell != fallthrough_cell or taken_store_ea != fallthrough_store_ea:
            continue
        if taken_value == fallthrough_value:
            continue
        try:
            canonical_predicate_stack_identity = (
                int(mba.stkoff_vd2ida(int(predicate[0]))),
                int(predicate[1]),
            )
        except (AttributeError, TypeError, ValueError):
            canonical_predicate_stack_identity = None
        return ResidualEntryBridgeEvidence(
            predicate_ea=int(branch.ea),
            condition_code=code,
            predicate_stack_identity=predicate,
            stack_cell_identity=taken_cell,
            taken_state_constant=taken_value,
            fallthrough_state_constant=fallthrough_value,
            source_store_ea=taken_store_ea,
            conditional_tail_ea=int(branch.ea),
            canonical_predicate_stack_identity=(
                canonical_predicate_stack_identity
            ),
        )
    return None


def recognize_preoptimized_residual_entry_bridge(
    mba: object,
) -> ResidualEntryBridgeEvidence | None:
    """Recognize the pre-CFG conditional-move lowering, or abstain.

    At ``hxe_preoptimized`` Hex-Rays has emitted basic blocks but has not yet
    populated their successor sets.  An x86 conditional move therefore still
    appears as ``setz predicate, 0, flag; jcnd [lnot] flag`` followed by one
    fall-through overwrite and a shared stack store.  Resolve only that exact
    linearized shape; any missing or conflicting identity abstains.
    """
    mop_d_type = _opcode("mop_d")
    m_jcnd = _opcode("m_jcnd")
    m_lnot = _opcode("m_lnot")
    m_setz = _opcode("m_setz")
    m_goto = _opcode("m_goto")
    terminal_opcodes = {
        opcode
        for opcode in (
            _opcode("m_jcnd"),
            _opcode("m_ret"),
            _opcode("m_ijmp"),
            _opcode("m_jtbl"),
        )
        if opcode is not None
    }

    def _target_serial(target: object) -> int | None:
        if int(target.t) == _opcode("mop_b"):
            return int(target.b) if target.b is not None else None
        if int(target.t) != _opcode("mop_v"):
            return None
        target_ea = int(target.g)
        matches: list[int] = []
        for candidate_serial in range(int(mba.qty)):
            candidate = mba.get_mblock(candidate_serial)
            if candidate is None:
                continue
            if int(candidate.start) == target_ea:
                matches.append(candidate_serial)
        unique = tuple(dict.fromkeys(matches))
        return unique[0] if len(unique) == 1 else None

    def _linear_state_store(
        start_serial: int,
        defaults: dict[int, int],
    ) -> tuple[tuple[int, int], int, int] | None:
        values = dict(defaults)
        serial = int(start_serial)
        seen: set[int] = set()
        for _hop in range(3):
            if serial in seen or not 0 <= serial < int(mba.qty):
                return None
            seen.add(serial)
            block = mba.get_mblock(serial)
            if block is None:
                return None
            instructions = _instructions(block)
            for insn in instructions:
                opcode = int(insn.opcode)
                if opcode == _opcode("m_mov"):
                    source = _register(insn.l)
                    destination = _stack_identity(insn.d)
                    if (
                        source is not None
                        and destination is not None
                        and source in values
                    ):
                        return destination, values[source], int(insn.ea)
                    _apply_moves((insn,), values)
                    continue
                destination_register = _register(insn.d)
                if destination_register is not None:
                    values.pop(destination_register, None)
            tail = instructions[-1] if instructions else None
            if tail is not None and int(tail.opcode) == m_goto:
                target_serial = _target_serial(tail.d)
                if target_serial is None:
                    return None
                serial = target_serial
                continue
            if tail is not None and int(tail.opcode) in terminal_opcodes:
                return None
            serial += 1
        return None

    try:
        blocks = tuple(mba.get_mblock(index) for index in range(int(mba.qty)))
    except Exception:
        return None
    for serial, block in enumerate(blocks):
        if block is None:
            continue
        instructions = _instructions(block)
        branch = instructions[-1] if instructions else None
        if branch is None or int(branch.opcode) != m_jcnd:
            continue
        flag_register = _register(branch.l)
        inverted = False
        if flag_register is None and int(branch.l.t) == mop_d_type:
            nested = branch.l.d
            if int(nested.opcode) != m_lnot:
                continue
            flag_register = _register(nested.l)
            inverted = True
        if flag_register is None:
            continue
        predicate: tuple[int, int] | None = None
        predicate_ea: int | None = None
        for insn in reversed(instructions[:-1]):
            if _register(insn.d) != flag_register:
                continue
            if int(insn.opcode) != m_setz or _immediate(insn.r) != 0:
                break
            predicate = _stack_identity(insn.l)
            if predicate is not None:
                predicate_ea = int(insn.ea)
            break
        if predicate is None or predicate_ea is None:
            continue
        defaults: dict[int, int] = {}
        _apply_moves(instructions[:-1], defaults)
        taken_serial = _target_serial(branch.d)
        if taken_serial is None:
            continue
        fallthrough_serial = int(serial) + 1
        if taken_serial == fallthrough_serial:
            continue
        taken_store = _linear_state_store(taken_serial, defaults)
        fallthrough_store = _linear_state_store(fallthrough_serial, defaults)
        if taken_store is None or fallthrough_store is None:
            continue
        taken_cell, taken_value, taken_store_ea = taken_store
        fallthrough_cell, fallthrough_value, fallthrough_store_ea = (
            fallthrough_store
        )
        if (
            taken_cell != fallthrough_cell
            or taken_store_ea != fallthrough_store_ea
            or taken_value == fallthrough_value
        ):
            continue
        source_entry_ea = _block_native_entry_ea(block)
        taken_entry_ea = _block_native_entry_ea(blocks[taken_serial])
        fallthrough_entry_ea = _block_native_entry_ea(
            blocks[fallthrough_serial]
        )
        try:
            canonical_stack_cell_identity = (
                int(mba.stkoff_vd2ida(int(taken_cell[0]))),
                int(taken_cell[1]),
            )
        except (AttributeError, TypeError, ValueError):
            canonical_stack_cell_identity = None
        try:
            canonical_predicate_stack_identity = (
                int(mba.stkoff_vd2ida(int(predicate[0]))),
                int(predicate[1]),
            )
        except (AttributeError, TypeError, ValueError):
            canonical_predicate_stack_identity = None
        return ResidualEntryBridgeEvidence(
            predicate_ea=predicate_ea,
            condition_code=5 if inverted else 4,
            predicate_stack_identity=predicate,
            stack_cell_identity=taken_cell,
            taken_state_constant=taken_value,
            fallthrough_state_constant=fallthrough_value,
            source_store_ea=taken_store_ea,
            canonical_stack_cell_identity=canonical_stack_cell_identity,
            predicate_block_ea=source_entry_ea,
            taken_arm_entry_ea=taken_entry_ea,
            fallthrough_arm_entry_ea=fallthrough_entry_ea,
            conditional_tail_ea=int(branch.ea),
            canonical_predicate_stack_identity=(
                canonical_predicate_stack_identity
            ),
        )
    return None


def recover_initial_state_write(
    mba: object,
    *,
    state_register: int,
    after_ea: int,
    before_ea: int,
) -> int | None:
    """Return one uniquely proven immediate state write in the entry corridor."""
    values: set[int] = set()
    for serial in range(int(mba.qty)):
        block = mba.get_mblock(serial)
        insn = block.head
        while insn is not None:
            if (
                int(after_ea) < int(insn.ea) < int(before_ea)
                and int(insn.opcode) == _opcode("m_mov")
                and _register(insn.d) == int(state_register)
            ):
                value = _immediate(insn.l)
                if value is None:
                    return None
                values.add(value)
            if insn is block.tail:
                break
            insn = insn.next
    return next(iter(values)) if len(values) == 1 else None


def recover_state_routing_nodes(
    mba: object,
    *,
    state_register: int,
    after_ea: int,
    before_ea: int,
    transfers: tuple[MaterializedIndirectTransfer, ...],
) -> tuple[StateRoutingNode, ...]:
    """Lift resolver-materialized entry comparisons into portable routing nodes."""
    nodes: list[StateRoutingNode] = []
    for transfer in transfers:
        if (
            transfer.resolver_kind != "static_fixpoint"
            or transfer.condition_code is None
            or transfer.true_target_ea is None
            or transfer.false_target_ea is None
            or len(transfer.materialized_anchor_eas) < 2
        ):
            continue
        source = int(transfer.source_block_ea)
        anchors = tuple(int(ea) for ea in transfer.materialized_anchor_eas)
        window_end = (
            int(transfer.materialized_region_end_ea)
            if transfer.materialized_region_end_ea is not None
            else max(anchors)
        )
        if (
            not int(after_ea) < source < int(before_ea)
            or source >= min(anchors)
            or source + 11 > window_end
        ):
            continue
        matched: tuple[int, int] | None = None
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            insn = block.head
            while insn is not None:
                if source <= int(insn.ea) <= window_end:
                    code = _state_condition_code(int(insn.opcode))
                    compared = _immediate(insn.r)
                    if code is not None and _register(insn.l) == int(state_register) and compared is not None:
                        if code != int(transfer.condition_code):
                            return ()
                        matched = (code, compared)
                        break
                if insn is block.tail:
                    break
                insn = insn.next
            if matched is not None:
                break
        if matched is None:
            continue
        code, compared = matched
        nodes.append(
            StateRoutingNode(
                source_block_ea=source,
                patch_window_end_ea=window_end,
                condition_code=code,
                compared_state_constant=compared,
                true_target_ea=int(transfer.true_target_ea),
                false_target_ea=int(transfer.false_target_ea),
            )
        )
    return tuple(nodes)


def _last_immediate_state_write(
    instructions: tuple[object, ...], state_register: int
) -> int | None:
    result: int | None = None
    for insn in instructions:
        if int(insn.opcode) != _opcode("m_mov"):
            continue
        if _register(insn.d) != int(state_register):
            continue
        value = _immediate(insn.l)
        if value is None:
            return None
        result = int(value)
    return result


def predicate_arm_reaches_ea(
    mba: object,
    *,
    predicate_ea: int,
    route_ea: int,
    max_hops: int = 4,
) -> bool:
    """Prove that one live predicate arm reaches a route EA.

    The path is bounded and may contain only one-way blocks after the initial
    two-way predicate.  This preserves detached native layout while keeping
    the proof entirely in the current microcode CFG.
    """
    predicate_blocks: list[tuple[int, object]] = []
    route_blocks: list[tuple[int, object]] = []
    try:
        for serial in range(int(mba.qty)):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            instruction_eas = {
                int(instruction.ea) for instruction in _instructions(block)
            }
            if int(predicate_ea) in instruction_eas:
                predicate_blocks.append((int(serial), block))
            if int(route_ea) in instruction_eas:
                route_blocks.append((int(serial), block))
    except Exception:
        return False
    if len(predicate_blocks) != 1 or len(route_blocks) != 1:
        return False
    _, source = predicate_blocks[0]
    target_serial, _ = route_blocks[0]
    source_successors = _successors(source)
    if len(source_successors) != 2:
        return False

    frontier = [(int(successor), 0) for successor in source_successors]
    seen: set[int] = set()
    while frontier:
        serial, depth = frontier.pop()
        if serial in seen or depth > int(max_hops):
            continue
        seen.add(serial)
        if serial == target_serial:
            return True
        try:
            block = mba.get_mblock(serial)
        except Exception:
            return False
        if block is None:
            return False
        successors = _successors(block)
        if len(successors) == 1:
            frontier.append((int(successors[0]), depth + 1))
    return False


def recognize_conditional_handler_bridges(
    mba: object,
    *,
    state_register: int,
    state_targets: Mapping[int, int],
    inherited_states_by_predicate_ea: Mapping[int, int] | None = None,
    arm_states_by_predicate_ea: Mapping[int, tuple[int, int]] | None = None,
) -> tuple[ConditionalHandlerBridgeEvidence, ...]:
    """Capture handler predicates before residual routing folds their arms.

    The accepted shape is deliberately narrow and portable: a live ``jz`` or
    ``jnz`` has a concrete non-empty left operand and a scalar register or
    immediate right operand, the branch block has one concrete inherited
    state, and each immediate successor either preserves that state or writes
    one concrete replacement state.  Both states must map uniquely to distinct
    condition-chain handler EAs.  A register identity is retained when present
    but is not required because a still-live branch can be retargeted without
    reconstructing its predicate.
    """
    try:
        blocks = tuple(mba.get_mblock(index) for index in range(int(mba.qty)))
    except Exception:
        return ()
    inherited_states = inherited_states_by_predicate_ea or {}
    pre_dce_arm_states = arm_states_by_predicate_ea or {}
    results: list[ConditionalHandlerBridgeEvidence] = []
    for block in blocks:
        if block is None:
            continue
        instructions = _instructions(block)
        branch = instructions[-1] if instructions else None
        if branch is None or int(branch.opcode) not in {
            _opcode("m_jz"),
            _opcode("m_jnz"),
        }:
            continue
        predicate_register = _register(branch.l)
        compared = _immediate(branch.r)
        compare_register = _register(branch.r)
        predicate_size = int(branch.l.size)
        successors = _successors(block)
        taken = int(branch.d.b)
        proven_arm_states = pre_dce_arm_states.get(int(branch.ea))
        if (
            int(branch.l.t) == _opcode("mop_z")
            or (
                proven_arm_states is None
                and
                compared is None
                and (
                    compare_register is None
                    or int(branch.r.size) != predicate_size
                )
            )
            or predicate_size <= 0
            or len(successors) != 2
            or taken not in successors
        ):
            continue
        predicate_predecessor_ea = (
            int(instructions[-2].ea)
            if len(instructions) >= 2 and int(instructions[-2].ea) > 0
            else None
        )
        if predicate_predecessor_ea is None and proven_arm_states is None:
            continue
        fallthrough = next(
            (serial for serial in successors if int(serial) != taken), None
        )
        if fallthrough is None:
            continue
        if proven_arm_states is not None:
            taken_state = int(proven_arm_states[0])
            fallthrough_state = int(proven_arm_states[1])
        else:
            # The caller supplies only exact predicate-EA route evidence whose
            # source is the replayed handler itself and whose exit was proven.
            # It therefore outranks a maturity-merged local write that may
            # belong to a different predecessor path.  Exact pre-DCE arm
            # states above do not require this inherited-state fallback: the
            # earlier maturity has already proved both selected values.
            inherited_state = inherited_states.get(int(branch.ea))
            if inherited_state is None:
                inherited_state = _last_immediate_state_write(
                    instructions[:-1], int(state_register)
                )
            if inherited_state is None:
                continue
            arm_states: dict[int, int] = {}
            valid = True
            for successor in (taken, int(fallthrough)):
                try:
                    successor_block = mba.get_mblock(int(successor))
                except Exception:
                    valid = False
                    break
                if successor_block is None:
                    valid = False
                    break
                replacement = _last_immediate_state_write(
                    _instructions(successor_block), int(state_register)
                )
                arm_states[int(successor)] = (
                    int(inherited_state)
                    if replacement is None
                    else int(replacement)
                )
            if not valid:
                continue
            taken_state = arm_states[taken]
            fallthrough_state = arm_states[int(fallthrough)]
        taken_target = state_targets.get(int(taken_state) & 0xFFFFFFFF)
        fallthrough_target = state_targets.get(
            int(fallthrough_state) & 0xFFFFFFFF
        )
        if (
            taken_target is None
            or fallthrough_target is None
            or int(taken_target) == int(fallthrough_target)
        ):
            continue
        # The lowering primitive always branches on ``register != 0``.  Swap
        # the original jz arms so true/false retain that normalized meaning.
        if int(branch.opcode) == _opcode("m_jnz"):
            true_state, true_target = taken_state, int(taken_target)
            false_state, false_target = fallthrough_state, int(fallthrough_target)
        else:
            true_state, true_target = fallthrough_state, int(fallthrough_target)
            false_state, false_target = taken_state, int(taken_target)
        source_block_ea = int(block.start)
        if source_block_ea <= 0:
            source_block_ea = min(
                int(insn.ea) for insn in instructions if int(insn.ea) > 0
            )
        results.append(
            ConditionalHandlerBridgeEvidence(
                source_block_ea=source_block_ea,
                predicate_ea=int(branch.ea),
                predicate_register=(
                    int(predicate_register)
                    if predicate_register is not None
                    else None
                ),
                predicate_size=predicate_size,
                predicate_compare_register=(
                    int(compare_register)
                    if compare_register is not None
                    else None
                ),
                predicate_compare_constant=(
                    int(compared)
                    if compared is not None and int(compared) != 0
                    else None
                ),
                predicate_predecessor_ea=predicate_predecessor_ea,
                true_state=int(true_state) & 0xFFFFFFFF,
                false_state=int(false_state) & 0xFFFFFFFF,
                true_target_ea=true_target,
                false_target_ea=false_target,
                true_is_taken=int(branch.opcode) == _opcode("m_jnz"),
            )
        )
    return tuple(results)


__all__ = [
    "ConditionalHandlerBridgeEvidence",
    "ResidualEntryBridgeEvidence",
    "recognize_residual_entry_bridge",
    "recognize_preoptimized_residual_entry_bridge",
    "recover_initial_state_write",
    "recover_state_routing_nodes",
    "predicate_arm_reaches_ea",
    "recognize_conditional_handler_bridges",
]
