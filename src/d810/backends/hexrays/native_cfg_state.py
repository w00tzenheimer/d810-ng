"""Read-only, fail-closed machine-state proofs for native CFG relinking."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass

from d810.ir.edge_state_contract import (
    EdgeStateContract,
    MachineStateLocation,
    MachineStateLocationKind,
)
from d810.ir.flowgraph import FlowGraph, InsnKind, ValueOpKind

__all__ = [
    "HexRaysNativeEdgeStateProof",
    "NativeFlagAccessStep",
    "prove_target_flag_independence",
]


def _default_stack_delta(mba: object, ea: int) -> int | None:
    try:
        import ida_frame
        import ida_funcs

        function = ida_funcs.get_func(int(getattr(mba, "entry_ea")))
        if function is None:
            return None
        return int(ida_frame.get_spd(function, int(ea)))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None


@dataclass(frozen=True, slots=True)
class NativeFlagAccessStep:
    next_ea: int
    reads_flags: bool
    writes_flags: bool
    stops: bool = False


def prove_target_flag_independence(
    target_ea: int,
    *,
    inspect: Callable[[int], NativeFlagAccessStep | None],
    max_instructions: int = 64,
) -> bool:
    """Prove inherited flags die before any target-prefix read."""
    current_ea = int(target_ea)
    visited: set[int] = set()
    for _index in range(int(max_instructions)):
        if current_ea in visited:
            return False
        visited.add(current_ea)
        step = inspect(current_ea)
        if step is None or step.next_ea == current_ea or step.next_ea < 0:
            return False
        if step.reads_flags:
            return False
        if step.writes_flags:
            return True
        if step.stops:
            return False
        current_ea = step.next_ea
    return False


_FLAG_READ_PREFIXES = ("cmov", "set", "loop")
_FLAG_READ_MNEMONICS = frozenset(
    {"adc", "sbb", "rcl", "rcr", "lahf", "pushf", "pushfd", "pushfq"}
)
_FLAG_KILL_MNEMONICS = frozenset({"add", "sub", "cmp", "test", "and", "or", "xor"})
_FLAG_PRESERVE_MNEMONICS = frozenset(
    {"mov", "movzx", "movsx", "movsxd", "lea", "nop", "push", "pop"}
)
_FLAG_REGISTER_NAMES = frozenset({"flags", "efl", "eflags", "rflags"})


def _inspect_native_flag_access(ea: int) -> NativeFlagAccessStep | None:
    try:
        import ida_idp
        import ida_ua
        import idaapi

        instruction = ida_ua.insn_t()
        size = int(ida_ua.decode_insn(instruction, int(ea)))
        if size <= 0:
            return None
        mnemonic = str(ida_ua.print_insn_mnem(int(ea)) or "").lower()
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None
    if not mnemonic:
        return None

    reads_flags = (
        (mnemonic.startswith("j") and mnemonic not in {"jmp", "jmpq"})
        or mnemonic.startswith(_FLAG_READ_PREFIXES)
        or mnemonic in _FLAG_READ_MNEMONICS
    )
    writes_flags = mnemonic in _FLAG_KILL_MNEMONICS
    accesses = ida_idp.reg_accesses_t()
    if ida_idp.ph_get_reg_accesses(accesses, instruction, 0) < 0:
        return None
    register_names = ida_idp.ph_get_regnames()
    for access in accesses:
        name = str(register_names[int(access.regnum)]).lower()
        if name not in _FLAG_REGISTER_NAMES:
            continue
        access_type = int(access.access_type)
        reads_flags = reads_flags or bool(access_type & int(ida_idp.READ_ACCESS))
        writes_flags = writes_flags or bool(access_type & int(ida_idp.WRITE_ACCESS))

    known = (
        reads_flags
        or writes_flags
        or mnemonic in _FLAG_PRESERVE_MNEMONICS
        or mnemonic in {"jmp", "jmpq", "ret", "retn", "retf"}
    )
    if not known:
        return None
    is_direct_unconditional_jump = bool(
        mnemonic in {"jmp", "jmpq"}
        and int(instruction.ops[0].type) in {int(idaapi.o_near), int(idaapi.o_far)}
    )
    next_ea = (
        int(instruction.ops[0].addr) if is_direct_unconditional_jump else int(ea) + size
    )
    stops = bool(
        ida_idp.is_call_insn(instruction)
        or ida_idp.is_ret_insn(instruction, 0)
        or (
            ida_idp.is_basic_block_end(instruction, False)
            and not is_direct_unconditional_jump
        )
    )
    return NativeFlagAccessStep(
        next_ea=next_ea,
        reads_flags=reads_flags,
        writes_flags=writes_flags,
        stops=stops,
    )


def _default_target_flags_are_independent(ea: int) -> bool:
    return prove_target_flag_independence(
        int(ea),
        inspect=_inspect_native_flag_access,
    )


def _native_terminator_ea(graph: FlowGraph, serial: int) -> int | None:
    block = graph.get_block(serial)
    if block is None:
        return None
    if block.tail is not None and block.tail.native_ea is not None:
        return int(block.tail.native_ea)
    if block.native_start_ea is not None:
        return int(block.native_start_ea)
    return None


def _native_block_ea(graph: FlowGraph, serial: int) -> int | None:
    block = graph.get_block(serial)
    if block is None or block.native_start_ea is None:
        return None
    return int(block.native_start_ea)


def _bypassed_corridor(
    graph: FlowGraph,
    inherited_successors: tuple[int, ...],
    final_successors: tuple[int, ...],
) -> tuple[int, ...] | None:
    added_targets = tuple(
        target for target in final_successors if target not in inherited_successors
    )
    if not added_targets:
        return ()
    removed_roots = tuple(
        target for target in inherited_successors if target not in final_successors
    )
    if not removed_roots:
        return None
    corridor: set[int] = set()
    for target in added_targets:
        routes: list[tuple[int, ...]] = []
        for root in removed_roots:
            pending: list[tuple[int, tuple[int, ...], frozenset[int]]] = [
                (root, (root,), frozenset((root,)))
            ]
            while pending:
                current, route, seen = pending.pop()
                if current == target:
                    routes.append(route[:-1])
                    if len(routes) > 1:
                        return None
                    continue
                for successor in reversed(graph.blocks[current].succs):
                    if successor not in graph.blocks or successor in seen:
                        continue
                    pending.append((successor, (*route, successor), seen | {successor}))
        if len(routes) != 1:
            return None
        corridor.update(routes[0])
    return tuple(sorted(corridor))


def _list_summary(value: object) -> str | None:
    try:
        rendered = str(value.dstr())
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None
    return rendered


def _list_empty(value: object) -> bool | None:
    try:
        return bool(value.empty())
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None


def _has_common(left: object, right: object) -> bool | None:
    try:
        return bool(left.has_common(right))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None


def _location(label: str, summary: str) -> MachineStateLocation:
    digest = hashlib.sha256(summary.encode("utf-8")).hexdigest()
    return MachineStateLocation(
        kind=MachineStateLocationKind.MEMORY,
        identity=f"hexrays-mlist:{label}:{digest}",
        bit_offset=0,
        bit_width=1,
    )


class HexRaysNativeEdgeStateProof:
    """Use mature Hex-Rays liveness plus native stack facts without retaining them."""

    def __init__(
        self,
        mba: object,
        *,
        stack_delta_for_ea: Callable[[int], int | None] | None = None,
        target_reads_flags: Callable[[int], bool] | None = None,
        target_flags_are_independent: Callable[[int], bool] | None = None,
    ) -> None:
        self._mba = mba
        self._stack_delta_for_ea = (
            stack_delta_for_ea
            if stack_delta_for_ea is not None
            else lambda ea: _default_stack_delta(mba, ea)
        )
        if target_reads_flags is not None and target_flags_are_independent is not None:
            raise ValueError("provide only one target flag proof callback")
        self._target_flags_are_independent = (
            target_flags_are_independent
            if target_flags_are_independent is not None
            else (
                lambda ea: (
                    not target_reads_flags(ea)
                    if target_reads_flags is not None
                    else _default_target_flags_are_independent(ea)
                )
            )
        )

    def prove_edge_transition(
        self,
        *,
        graph: FlowGraph,
        source_block: int,
        inherited_successors: tuple[int, ...],
        final_successors: tuple[int, ...],
        semantic_proof_ids: tuple[str, ...],
    ) -> EdgeStateContract | None:
        if (
            not semantic_proof_ids
            or int(getattr(self._mba, "entry_ea", -1)) != graph.func_ea
        ):
            return None
        source = graph.get_block(source_block)
        if source is None or tuple(source.succs) != inherited_successors:
            return None
        if not final_successors or any(
            target not in graph.blocks for target in final_successors
        ):
            return None
        corridor = _bypassed_corridor(
            graph,
            inherited_successors,
            final_successors,
        )
        if corridor is None:
            return None

        source_ea = _native_terminator_ea(graph, source_block)
        if source_ea is None:
            return None
        try:
            source_stack_delta = self._stack_delta_for_ea(source_ea)
        except (RuntimeError, TypeError, ValueError):
            return None
        if source_stack_delta is None:
            return None

        target_use_lists: list[tuple[int, object, str]] = []
        for target in sorted(set(final_successors)):
            target_ea = _native_block_ea(graph, target)
            if target_ea is None:
                return None
            try:
                target_stack_delta = self._stack_delta_for_ea(target_ea)
                target_flags_are_independent = self._target_flags_are_independent(
                    target_ea
                )
            except (RuntimeError, TypeError, ValueError):
                return None
            if (
                target_stack_delta != source_stack_delta
                or not target_flags_are_independent
            ):
                return None
            live_target = self._mba.get_mblock(target)
            if live_target is None:
                return None
            try:
                live_target.make_lists_ready()
                may_use = live_target.maybuse
            except (AttributeError, RuntimeError):
                return None
            summary = _list_summary(may_use)
            if summary is None or _list_empty(may_use) is None:
                return None
            target_use_lists.append((target, may_use, summary))

        dead_effect_locations: list[MachineStateLocation] = []
        for serial in corridor:
            portable_block = graph.get_block(serial)
            live_block = self._mba.get_mblock(serial)
            if portable_block is None or live_block is None:
                return None
            if any(
                instruction.kind in {InsnKind.CALL, InsnKind.STORE, InsnKind.UNKNOWN}
                or instruction.is_call
                or instruction.value_op_kind is ValueOpKind.STORE
                for instruction in portable_block.insn_snapshots
            ):
                return None
            try:
                live_block.make_lists_ready()
                may_def = live_block.maybdef
            except (AttributeError, RuntimeError):
                return None
            definition_summary = _list_summary(may_def)
            definition_empty = _list_empty(may_def)
            if definition_summary is None or definition_empty is None:
                return None
            for _target, may_use, _summary in target_use_lists:
                overlap = _has_common(may_def, may_use)
                if overlap is None or overlap:
                    return None
            if not definition_empty:
                dead_effect_locations.append(
                    _location(f"dead-def-block-{serial}", definition_summary)
                )

        input_locations = tuple(
            _location(f"target-{target}-live-in", summary)
            for target, may_use, summary in target_use_lists
            if _list_empty(may_use) is False
        )
        proof_payload = "|".join(
            (
                str(graph.func_ea),
                str(source_block),
                ",".join(map(str, inherited_successors)),
                ",".join(map(str, final_successors)),
                str(source_stack_delta),
                *(location.identity for location in input_locations),
                *(location.identity for location in dead_effect_locations),
            )
        )
        state_proof_id = (
            "hexrays-edge-state:"
            + hashlib.sha256(proof_payload.encode("utf-8")).hexdigest()
        )
        return EdgeStateContract(
            required_target_inputs=input_locations,
            proven_equivalent_inputs=input_locations,
            unpersisted_body_effects=tuple(dead_effect_locations),
            proven_dead_body_effects=tuple(dead_effect_locations),
            source_stack_delta=int(source_stack_delta),
            target_stack_delta=int(source_stack_delta),
            proof_ids=(*semantic_proof_ids, state_proof_id),
        )
