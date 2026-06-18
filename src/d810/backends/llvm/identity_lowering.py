"""Portable identity-lower parity scaffold for LLVM M1 lifts.

This module does not parse LLVM IR and does not lower back to Hex-Rays
microcode.  It records the portable instruction signature accepted by the
LLVM emitter and checks that the emitted manifest can reconstruct the original
portable ``FlowGraph`` shape for the currently supported M1 subset.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from d810.ir.flowgraph import FlowGraph
from d810.ir.insn_projection import project_instruction_sequence
from d810.ir.instructions import (
    Instruction,
    InstructionControl,
    InstructionEffect,
    InstructionMemoryAccess,
    InstructionSwitchCase,
)
from d810.ir.semantics import OperationKind
from d810.ir.varnode import Space, Varnode

__all__ = [
    "LlvmIdentityManifest",
    "LlvmIdentityManifestBlock",
    "LlvmIdentityManifestControl",
    "LlvmIdentityManifestEffect",
    "LlvmIdentityManifestInstruction",
    "LlvmIdentityManifestMemory",
    "LlvmIdentityManifestSwitchCase",
    "LlvmIdentityManifestVarnode",
    "LlvmIdentityMismatch",
    "LlvmIdentityParityResult",
    "LlvmIdentityParityStatus",
    "build_identity_manifest",
    "check_identity_manifest",
    "check_identity_roundtrip",
    "sanitize_llvm_function_name",
]


class LlvmIdentityParityStatus(str, Enum):
    """Stable status values for portable LLVM identity parity."""

    PASSED = "passed"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestVarnode:
    """Stable manifest identity for a portable varnode."""

    space: str
    offset: int
    size: int


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestSwitchCase:
    """Stable manifest identity for a portable switch case row."""

    values: tuple[int, ...]
    target: int


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestControl:
    """Stable manifest identity for typed instruction control payload."""

    transfer: str | None = None
    predicate: str | None = None
    target: int | None = None
    fallthrough: int | None = None
    switch_cases: tuple[LlvmIdentityManifestSwitchCase, ...] = ()
    indirect_target: LlvmIdentityManifestVarnode | None = None
    call_kind: str | None = None
    call_target: LlvmIdentityManifestVarnode | None = None
    return_value: LlvmIdentityManifestVarnode | None = None


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestEffect:
    """Stable manifest identity for typed instruction effects."""

    kind: str
    target: LlvmIdentityManifestVarnode | None = None
    segment: LlvmIdentityManifestVarnode | None = None
    value: LlvmIdentityManifestVarnode | None = None


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestMemory:
    """Stable manifest identity for portable memory access contracts."""

    kind: str
    target: LlvmIdentityManifestVarnode | None = None
    segment: LlvmIdentityManifestVarnode | None = None
    value: LlvmIdentityManifestVarnode | None = None
    width: int | None = None


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestInstruction:
    """Stable manifest identity for an emitted source instruction."""

    block_serial: int
    instruction_index: int
    ea: int | None
    operation: str
    inputs: tuple[LlvmIdentityManifestVarnode, ...]
    result: LlvmIdentityManifestVarnode | None
    effects: tuple[LlvmIdentityManifestEffect, ...]
    control: LlvmIdentityManifestControl | None
    memory: LlvmIdentityManifestMemory | None


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifestBlock:
    """Stable manifest identity for an emitted basic block."""

    source_serial: int
    label: str
    succs: tuple[int, ...]
    instructions: tuple[LlvmIdentityManifestInstruction, ...]


@dataclass(frozen=True, slots=True)
class LlvmIdentityManifest:
    """Emitter-produced identity manifest for a supported LLVM lift."""

    function_name: str
    entry_serial: int
    block_count: int
    instruction_count: int
    blocks: tuple[LlvmIdentityManifestBlock, ...]
    allocas: tuple[LlvmIdentityManifestVarnode, ...]


@dataclass(frozen=True, slots=True)
class LlvmIdentityMismatch:
    """One portable identity mismatch between source and emitted manifest."""

    kind: str
    path: str
    expected: str
    actual: str


@dataclass(frozen=True, slots=True)
class LlvmIdentityParityResult:
    """Result of checking LLVM M1 portable identity parity."""

    status: LlvmIdentityParityStatus
    mismatches: tuple[LlvmIdentityMismatch, ...] = ()
    reason: str | None = None
    function_name: str = ""
    block_count: int = 0
    instruction_count: int = 0

    @property
    def passed(self) -> bool:
        return self.status is LlvmIdentityParityStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status is LlvmIdentityParityStatus.FAILED

    @property
    def unsupported(self) -> bool:
        return self.status is LlvmIdentityParityStatus.UNSUPPORTED


def build_identity_manifest(
    flow_graph: FlowGraph,
    instructions: dict[int, tuple[Instruction, ...]],
    allocas: tuple[Varnode, ...],
    *,
    function_name: str,
) -> LlvmIdentityManifest:
    """Build an identity manifest from the emitter's accepted instruction map."""

    blocks: list[LlvmIdentityManifestBlock] = []
    instruction_count = 0
    for serial in _ordered_block_serials(flow_graph):
        block = flow_graph.blocks[serial]
        block_instructions = tuple(
            _manifest_instruction(serial, index, instruction)
            for index, instruction in enumerate(instructions.get(serial, ()))
        )
        instruction_count += len(block_instructions)
        blocks.append(
            LlvmIdentityManifestBlock(
                source_serial=int(serial),
                label=f"bb{serial}",
                succs=tuple(int(succ) for succ in block.succs),
                instructions=block_instructions,
            )
        )
    return LlvmIdentityManifest(
        function_name=function_name,
        entry_serial=int(flow_graph.entry_serial),
        block_count=len(flow_graph.blocks),
        instruction_count=instruction_count,
        blocks=tuple(blocks),
        allocas=tuple(_manifest_varnode(vn) for vn in allocas),
    )


def check_identity_manifest(
    flow_graph: FlowGraph,
    manifest: LlvmIdentityManifest | None,
    *,
    function_name: str = "d810_fn",
) -> LlvmIdentityParityResult:
    """Compare a portable ``FlowGraph`` signature with an emitted manifest."""

    if manifest is None:
        return LlvmIdentityParityResult(
            status=LlvmIdentityParityStatus.UNSUPPORTED,
            reason="supported lift did not include an identity manifest",
            function_name=function_name,
        )
    source_instructions = {
        int(serial): tuple(
            instruction
            for insn in block.insn_snapshots
            for instruction in project_instruction_sequence(insn)
        )
        for serial, block in flow_graph.blocks.items()
    }
    source_manifest = build_identity_manifest(
        flow_graph,
        source_instructions,
        _collect_source_allocas(source_instructions),
        function_name=sanitize_llvm_function_name(function_name),
    )
    mismatches = tuple(_compare_manifest(source_manifest, manifest))
    if mismatches:
        return LlvmIdentityParityResult(
            status=LlvmIdentityParityStatus.FAILED,
            mismatches=mismatches,
            reason=f"{len(mismatches)} identity mismatches",
            function_name=manifest.function_name,
            block_count=manifest.block_count,
            instruction_count=manifest.instruction_count,
        )
    return LlvmIdentityParityResult(
        status=LlvmIdentityParityStatus.PASSED,
        function_name=manifest.function_name,
        block_count=manifest.block_count,
        instruction_count=manifest.instruction_count,
    )


def check_identity_roundtrip(
    flow_graph: FlowGraph,
    *,
    function_name: str = "d810_fn",
    lift_result: object | None = None,
) -> LlvmIdentityParityResult:
    """Check manifest identity parity for a supported LLVM lift result.

    ``lift_result`` is intentionally structural to avoid a module import cycle.
    Callers should pass the result from ``emit_flowgraph_to_llvm`` so this
    checker stays independent of the emitter implementation.
    """

    result = lift_result
    if result is None:
        return LlvmIdentityParityResult(
            status=LlvmIdentityParityStatus.UNSUPPORTED,
            reason="LLVM lift result is required for identity parity",
            function_name=function_name,
            block_count=len(flow_graph.blocks),
            instruction_count=0,
        )
    if not bool(getattr(result, "supported", False)):
        return LlvmIdentityParityResult(
            status=LlvmIdentityParityStatus.UNSUPPORTED,
            reason="LLVM lift is unsupported; identity parity is not meaningful",
            function_name=function_name,
            block_count=len(flow_graph.blocks),
            instruction_count=0,
        )
    manifest = getattr(result, "identity_manifest", None)
    return check_identity_manifest(flow_graph, manifest, function_name=function_name)


def sanitize_llvm_function_name(name: str) -> str:
    """Return the LLVM-safe function symbol spelling used in manifests."""

    sanitized = re.sub(r"[^A-Za-z0-9_$.-]", "_", name)
    if not sanitized:
        return "d810_fn"
    if sanitized[0].isdigit():
        return f"d810_{sanitized}"
    return sanitized


def _ordered_block_serials(flow_graph: FlowGraph) -> tuple[int, ...]:
    entry = int(flow_graph.entry_serial)
    rest = tuple(serial for serial in sorted(flow_graph.blocks) if serial != entry)
    return (entry, *rest)


def _manifest_instruction(
    block_serial: int,
    index: int,
    instruction: Instruction,
) -> LlvmIdentityManifestInstruction:
    raw_ea = instruction.attrs.get("ea")
    return LlvmIdentityManifestInstruction(
        block_serial=int(block_serial),
        instruction_index=int(index),
        ea=int(raw_ea) if isinstance(raw_ea, int) else None,
        operation=_operation_name(instruction.operation),
        inputs=tuple(_manifest_varnode(vn) for vn in instruction.inputs),
        result=_manifest_varnode(instruction.result),
        effects=tuple(_manifest_effect(effect) for effect in instruction.effects),
        control=_manifest_control(instruction.control),
        memory=_manifest_memory(instruction.memory),
    )


def _manifest_control(
    control: InstructionControl | None,
) -> LlvmIdentityManifestControl | None:
    if control is None:
        return None
    return LlvmIdentityManifestControl(
        transfer=_operation_name(control.transfer),
        predicate=_operation_name(control.predicate),
        target=control.target,
        fallthrough=control.fallthrough,
        switch_cases=tuple(_manifest_switch_case(case) for case in control.switch_cases),
        indirect_target=_manifest_varnode(control.indirect_target),
        call_kind=_operation_name(control.call_kind),
        call_target=_manifest_varnode(control.call_target),
        return_value=_manifest_varnode(control.return_value),
    )


def _manifest_switch_case(
    case: InstructionSwitchCase,
) -> LlvmIdentityManifestSwitchCase:
    return LlvmIdentityManifestSwitchCase(
        values=tuple(int(value) for value in case.values),
        target=int(case.target),
    )


def _manifest_effect(effect: InstructionEffect) -> LlvmIdentityManifestEffect:
    return LlvmIdentityManifestEffect(
        kind=effect.kind.value,
        target=_manifest_varnode(effect.target),
        segment=_manifest_varnode(effect.segment),
        value=_manifest_varnode(effect.value),
    )


def _manifest_memory(
    memory: InstructionMemoryAccess | None,
) -> LlvmIdentityManifestMemory | None:
    if memory is None:
        return None
    return LlvmIdentityManifestMemory(
        kind=memory.kind.value,
        target=_manifest_varnode(memory.target),
        segment=_manifest_varnode(memory.segment),
        value=_manifest_varnode(memory.value),
        width=int(memory.width) if memory.width is not None else None,
    )


def _manifest_varnode(vn: Varnode | None) -> LlvmIdentityManifestVarnode | None:
    if vn is None:
        return None
    return LlvmIdentityManifestVarnode(
        space=vn.space.value,
        offset=int(vn.offset),
        size=int(vn.size),
    )


def _operation_name(operation: OperationKind | None) -> str | None:
    if operation is None:
        return None
    return getattr(operation, "value", str(operation))


def _collect_source_allocas(
    instructions: dict[int, tuple[Instruction, ...]],
) -> tuple[Varnode, ...]:
    found: set[Varnode] = set()
    ordered: list[Varnode] = []
    for serial in sorted(instructions):
        for instruction in instructions[serial]:
            for vn in (*instruction.inputs, instruction.result):
                _append_alloca(ordered, found, vn)
            if instruction.control is not None:
                for vn in (
                    instruction.control.call_target,
                    instruction.control.indirect_target,
                    instruction.control.return_value,
                ):
                    _append_alloca(ordered, found, vn)
            if instruction.memory is not None:
                for vn in (
                    instruction.memory.target,
                    instruction.memory.segment,
                    instruction.memory.value,
                ):
                    _append_alloca(ordered, found, vn)
    return tuple(sorted(ordered, key=lambda vn: (vn.space.value, vn.offset, vn.size)))


def _append_alloca(
    ordered: list[Varnode],
    found: set[Varnode],
    vn: Varnode | None,
) -> None:
    if vn is None or vn.space is Space.CONST or vn in found:
        return
    found.add(vn)
    ordered.append(vn)


def _compare_manifest(
    expected: LlvmIdentityManifest,
    actual: LlvmIdentityManifest,
) -> list[LlvmIdentityMismatch]:
    mismatches: list[LlvmIdentityMismatch] = []
    _compare_value(mismatches, "function_name", "function_name", expected.function_name, actual.function_name)
    _compare_value(mismatches, "entry", "entry_serial", expected.entry_serial, actual.entry_serial)
    _compare_value(mismatches, "block_count", "block_count", expected.block_count, actual.block_count)
    _compare_value(
        mismatches,
        "instruction_count",
        "instruction_count",
        expected.instruction_count,
        actual.instruction_count,
    )
    _compare_value(mismatches, "allocas", "allocas", expected.allocas, actual.allocas)
    if len(expected.blocks) != len(actual.blocks):
        _compare_value(mismatches, "blocks", "blocks", len(expected.blocks), len(actual.blocks))
        return mismatches
    for block_index, (expected_block, actual_block) in enumerate(zip(expected.blocks, actual.blocks)):
        path = f"blocks[{block_index}]"
        _compare_value(
            mismatches,
            "block",
            f"{path}.source_serial",
            expected_block.source_serial,
            actual_block.source_serial,
        )
        _compare_value(
            mismatches,
            "block",
            f"{path}.label",
            expected_block.label,
            actual_block.label,
        )
        _compare_value(
            mismatches,
            "successors",
            f"{path}.succs",
            expected_block.succs,
            actual_block.succs,
        )
        if len(expected_block.instructions) != len(actual_block.instructions):
            _compare_value(
                mismatches,
                "instruction_count",
                f"{path}.instructions",
                len(expected_block.instructions),
                len(actual_block.instructions),
            )
            continue
        for instruction_index, (expected_insn, actual_insn) in enumerate(
            zip(expected_block.instructions, actual_block.instructions)
        ):
            _compare_instruction(
                mismatches,
                f"{path}.instructions[{instruction_index}]",
                expected_insn,
                actual_insn,
            )
    return mismatches


def _compare_instruction(
    mismatches: list[LlvmIdentityMismatch],
    path: str,
    expected: LlvmIdentityManifestInstruction,
    actual: LlvmIdentityManifestInstruction,
) -> None:
    _compare_value(mismatches, "operation", f"{path}.operation", expected.operation, actual.operation)
    _compare_value(mismatches, "inputs", f"{path}.inputs", expected.inputs, actual.inputs)
    _compare_value(mismatches, "result", f"{path}.result", expected.result, actual.result)
    _compare_value(mismatches, "effects", f"{path}.effects", expected.effects, actual.effects)
    _compare_value(mismatches, "control", f"{path}.control", expected.control, actual.control)
    _compare_value(mismatches, "memory", f"{path}.memory", expected.memory, actual.memory)


def _compare_value(
    mismatches: list[LlvmIdentityMismatch],
    kind: str,
    path: str,
    expected: object,
    actual: object,
) -> None:
    if expected == actual:
        return
    mismatches.append(
        LlvmIdentityMismatch(
            kind=kind,
            path=path,
            expected=repr(expected),
            actual=repr(actual),
        )
    )
