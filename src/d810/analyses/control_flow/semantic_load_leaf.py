"""Bounded fresh-definition check for a reused physical route carrier.

This check does not prove that the loaded memory value is independent of the
selector. The load and its branch remain executable. A caller must separately
prove that bypassing the dispatcher preserves the leaf's other live-ins.
Missing definitions, partial writes, and unsupported operations abstain.
"""

from __future__ import annotations

from collections.abc import Callable

from d810.ir.flowgraph import InsnKind
from d810.ir.expressions import ValueOpKind
from d810.ir.instructions import (
    Instruction,
    InstructionMemoryAccessKind,
)
from d810.ir.storage_identity import (
    StorageIdentity,
    StorageIdentityKind,
    storage_identity_from_varnode,
)
from d810.ir.varnode import Space, Varnode


_PURE_VALUE_OPS = frozenset(
    {
        ValueOpKind.MOVE,
        ValueOpKind.ADD,
        ValueOpKind.SUB,
        ValueOpKind.MUL,
        ValueOpKind.AND,
        ValueOpKind.OR,
        ValueOpKind.XOR,
        ValueOpKind.SHL,
        ValueOpKind.SHR,
        ValueOpKind.SAR,
        ValueOpKind.ROL,
        ValueOpKind.ROR,
    }
)


def _supported_load(instruction: Instruction) -> bool:
    if instruction.operation is not ValueOpKind.LOAD:
        return True
    if instruction.result is None or len(instruction.inputs) < 2:
        return False
    memory = instruction.memory
    if memory is not None:
        return bool(
            memory.kind in {
                InstructionMemoryAccessKind.DIRECT_CELL,
                InstructionMemoryAccessKind.INDIRECT,
            }
            and memory.target is not None
            and memory.width == instruction.result.size
        )
    return bool(
        instruction.result.space is Space.TEMP
        and instruction.attrs.get("nested_sub_kind") == InsnKind.LOAD.value
        and instruction.attrs.get("nested_load_width") == instruction.result.size
    )


def _overlaps(value: Varnode, identity: StorageIdentity, width: int) -> bool:
    actual = storage_identity_from_varnode(value)
    return bool(
        actual is not None
        and actual.kind is identity.kind
        and actual.offset < identity.offset + width
        and (
            value.size <= 0
            or identity.offset < actual.offset + value.size
        )
    )


def prove_fresh_full_width_load_leaf(
    *,
    block_serial: int,
    entry_serial: int,
    projected_block: Callable[[int], tuple[Instruction, ...]],
    predecessors_of: Callable[[int], tuple[int, ...]],
    expected_state_identities: frozenset[StorageIdentity],
    expected_state_width: int,
    selector_source_identities: frozenset[StorageIdentity],
) -> bool:
    """Prove a branch uses a full-width load, not the incoming carrier value.

    Reaching writes are collected over every predecessor path, including loop
    backedges. Only exact-width pure copies and load-address computations can
    establish provenance. An external register at the graph entry is admitted;
    an external stack/global value is not. This is deliberately narrower than
    generic taint tracking, and never treats an unknown write as a kill. This
    is not a memory-alias proof and does not itself authorize a CFG shortcut.
    """

    if expected_state_width <= 0 or not expected_state_identities:
        return False
    try:
        leaf = projected_block(int(block_serial))
    except (KeyError, IndexError):
        return False
    forbidden = expected_state_identities | selector_source_identities
    external = object()
    read_memo: dict[tuple[Varnode, int, int, object], bool] = {}
    active_reads: set[tuple[Varnode, int, int, object]] = set()
    fresh_load: Varnode | None = None
    fresh_load_index: int | None = None

    def is_forbidden(value: Varnode) -> bool:
        return any(
            _overlaps(value, identity, expected_state_width)
            for identity in forbidden
        )

    def reaches(
        value: Varnode, serial: int, before: int,
    ) -> set[tuple[int, int] | object] | None:
        """All finite-path last writes; ``None`` means an unproved boundary."""
        pending = [(serial, before)]
        visited: set[tuple[int, int]] = set()
        writers: set[tuple[int, int] | object] = set()
        while pending:
            current, limit = pending.pop()
            if (current, limit) in visited:
                continue
            visited.add((current, limit))
            try:
                instructions = projected_block(current)
            except (KeyError, IndexError):
                return None
            if limit < 0 or limit > len(instructions):
                return None
            found = False
            for index in range(limit - 1, -1, -1):
                instruction = instructions[index]
                if instruction.attrs.get("unprojected_write"):
                    return None
                result = instruction.result
                if result is not None and (
                    result == value
                    or (
                        value.space is not Space.TEMP
                        and storage_identity_from_varnode(result) is not None
                        and _overlaps(result, storage_identity_from_varnode(value), value.size)
                    )
                ):
                    writers.add((current, index))
                    found = True
                    break
                if any(
                    effect.target is not None
                    and storage_identity_from_varnode(effect.target) is not None
                    and storage_identity_from_varnode(value) is not None
                    and _overlaps(
                        effect.target, storage_identity_from_varnode(value), value.size
                    )
                    for effect in instruction.effects
                ):
                    return None
            if found:
                continue
            if value.space is Space.TEMP:
                return None  # instruction-local temporaries cannot cross blocks
            if current == int(entry_serial):
                writers.add(external)
            try:
                predecessors = predecessors_of(current)
            except (KeyError, IndexError):
                return None
            if not predecessors and current != int(entry_serial):
                return None
            try:
                pending.extend(
                    (int(predecessor), len(projected_block(int(predecessor))))
                    for predecessor in predecessors
                )
            except (KeyError, IndexError):
                return None
        return writers or None

    def prove_read(
        value: Varnode, serial: int, before: int, consumer_ea: object,
    ) -> bool:
        if value.space is Space.CONST:
            return True
        if (
            fresh_load is not None
            and fresh_load_index is not None
            and serial == int(block_serial)
            and before > fresh_load_index
            and value == fresh_load
        ):
            return True
        if value.size <= 0 or is_forbidden(value):
            return False
        if value.space not in {Space.REGISTER, Space.STACK, Space.TEMP}:
            return False
        key = (value, serial, before, consumer_ea)
        if key in read_memo:
            return read_memo[key]
        if key in active_reads:
            return False
        active_reads.add(key)
        writers = reaches(value, serial, before)
        accepted = bool(writers)
        if writers:
            for site in writers:
                if site is external:
                    accepted = value.space is Space.REGISTER
                    if not accepted:
                        break
                    continue
                writer_serial, index = site
                writer = projected_block(writer_serial)[index]
                result = writer.result
                if (
                    result != value
                    or writer.attrs.get("unprojected_source")
                    or writer.attrs.get("unprojected_write")
                    or writer.effects
                    or writer.control is not None
                    or writer.operation not in _PURE_VALUE_OPS | {ValueOpKind.LOAD}
                    or not writer.inputs
                    or not _supported_load(writer)
                    or (
                        writer.operation is ValueOpKind.MOVE
                        and (
                            len(writer.inputs) != 1
                            or writer.inputs[0].size != result.size
                        )
                    )
                    or (
                        value.space is Space.TEMP
                        and (
                            type(consumer_ea) is not int
                            or type(writer.attrs.get("ea")) is not int
                            or writer.attrs["ea"] != consumer_ea
                        )
                    )
                ):
                    accepted = False
                    break
                writer_ea = writer.attrs.get("ea")
                if not all(
                    prove_read(source, writer_serial, index, writer_ea)
                    for source in writer.inputs
                ):
                    accepted = False
                    break
        active_reads.remove(key)
        read_memo[key] = accepted
        return accepted

    for index, instruction in enumerate(leaf):
        if instruction.attrs.get("unprojected_source") or instruction.attrs.get(
            "unprojected_write"
        ):
            return False
        result = instruction.result
        result_is_carrier = bool(
            result is not None
            and any(
                _overlaps(result, identity, expected_state_width)
                for identity in expected_state_identities
            )
        )
        if instruction.control is not None:
            if instruction.control.predicate is None or fresh_load is None:
                return False
            carrier_inputs = tuple(
                value for value in instruction.inputs
                if any(
                    _overlaps(value, identity, expected_state_width)
                    for identity in expected_state_identities
                )
            )
            return bool(
                carrier_inputs
                and all(value == fresh_load for value in carrier_inputs)
                and all(
                    value == fresh_load
                    or prove_read(
                        value, block_serial, index, instruction.attrs.get("ea")
                    )
                    for value in instruction.inputs
                )
            )
        if instruction.effects or instruction.operation not in _PURE_VALUE_OPS | {
            ValueOpKind.LOAD
        }:
            return False
        if not _supported_load(instruction):
            return False
        if result_is_carrier:
            if (
                fresh_load is not None
                or result is None
                or instruction.operation is not ValueOpKind.LOAD
                or result.size != expected_state_width
                or storage_identity_from_varnode(result)
                not in expected_state_identities
            ):
                return False
        if not all(
            (fresh_load is not None and value == fresh_load)
            or prove_read(value, block_serial, index, instruction.attrs.get("ea"))
            for value in instruction.inputs
        ):
            return False
        if result_is_carrier:
            fresh_load = result
            fresh_load_index = index
    return False
