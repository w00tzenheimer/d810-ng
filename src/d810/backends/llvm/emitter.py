"""Textual LLVM IR emitter for the M1a portable-IR supported subset."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import FlowGraph
from d810.ir.insn_projection import project_instruction
from d810.ir.instructions import Instruction
from d810.ir.semantics import CallKind, ControlTransferKind, OperationKind, PredicateKind
from d810.ir.varnode import Space, Varnode

__all__ = [
    "LlvmLiftResult",
    "UnsupportedLiftKind",
    "UnsupportedLiftReason",
    "emit_flowgraph_to_llvm",
]


_SCALAR_WIDTHS = {1: "i8", 2: "i16", 4: "i32", 8: "i64"}
_BINARY_VALUE_OPS = {
    ValueOpKind.ADD,
    ValueOpKind.SUB,
    ValueOpKind.MUL,
    ValueOpKind.OR,
    ValueOpKind.AND,
    ValueOpKind.XOR,
}
_VALUE_OPS = {ValueOpKind.MOVE, *_BINARY_VALUE_OPS}
_PREDICATES = {
    PredicateKind.EQ: "eq",
    PredicateKind.NE: "ne",
    PredicateKind.UGE: "uge",
    PredicateKind.UGT: "ugt",
    PredicateKind.ULE: "ule",
    PredicateKind.ULT: "ult",
    PredicateKind.SGE: "sge",
    PredicateKind.SGT: "sgt",
    PredicateKind.SLE: "sle",
    PredicateKind.SLT: "slt",
}


class UnsupportedLiftKind(str, Enum):
    """Stable front-lift diagnostic taxonomy for unsupported LLVM M1 input."""

    VARNODE_WIDTH = "varnode_width"
    VARNODE_SPACE = "varnode_space"
    CALL_UNSUPPORTED = "call_unsupported"
    EFFECT_UNSUPPORTED = "effect_unsupported"
    CONTROL_TRANSFER_UNSUPPORTED = "control_transfer_unsupported"
    VALUE_OP_UNSUPPORTED = "value_op_unsupported"
    VALUE_RESULT_MISSING = "value_result_missing"
    VALUE_RESULT_CONST = "value_result_const"
    VALUE_ARITY = "value_arity"
    VALUE_WIDTH_MISMATCH = "value_width_mismatch"
    PREDICATE_UNSUPPORTED = "predicate_unsupported"
    PREDICATE_RESULT_MISSING = "predicate_result_missing"
    PREDICATE_RESULT_CONST = "predicate_result_const"
    PREDICATE_ARITY = "predicate_arity"
    PREDICATE_WIDTH_MISMATCH = "predicate_width_mismatch"
    BRANCH_SUCCESSOR_ARITY = "branch_successor_arity"
    BRANCH_PREDICATE_UNSUPPORTED = "branch_predicate_unsupported"
    BRANCH_ARITY = "branch_arity"
    MALFORMED_TERMINATOR = "malformed_terminator"
    RETURN_SUCCESSOR = "return_successor"
    RETURN_TYPE_UNSUPPORTED = "return_type_unsupported"
    GOTO_SUCCESSOR_ARITY = "goto_successor_arity"
    BLOCK_TERMINATOR_MISSING = "block_terminator_missing"


@dataclass(frozen=True, slots=True)
class UnsupportedLiftReason:
    """Why a portable instruction or block cannot be lifted in M1a."""

    block_serial: int
    instruction_index: int | None
    ea: int | None
    operation: str
    kind: UnsupportedLiftKind
    reason: str


@dataclass(frozen=True, slots=True)
class LlvmLiftResult:
    """Result of a whole-function LLVM lift attempt."""

    ir_text: str
    unsupported: tuple[UnsupportedLiftReason, ...] = ()

    @property
    def supported(self) -> bool:
        return not self.unsupported


def emit_flowgraph_to_llvm(
    flow_graph: FlowGraph,
    *,
    function_name: str = "d810_fn",
) -> LlvmLiftResult:
    """Emit LLVM IR for the M1a supported subset.

    The whole graph is classified before emission.  If anything is unsupported,
    ``ir_text`` is empty and every reason is returned.
    """
    classifier = _Classifier(flow_graph)
    unsupported = classifier.classify()
    if unsupported:
        return LlvmLiftResult(ir_text="", unsupported=tuple(unsupported))
    emitter = _Emitter(flow_graph, _sanitize_function_name(function_name))
    return LlvmLiftResult(ir_text=emitter.emit())


def _sanitize_function_name(name: str) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_$.-]", "_", name)
    if not sanitized:
        return "d810_fn"
    if sanitized[0].isdigit():
        return f"d810_{sanitized}"
    return sanitized


def _operation_name(operation: OperationKind | None) -> str:
    if operation is None:
        return "<none>"
    return getattr(operation, "value", str(operation))


def _llvm_type(vn: Varnode) -> str | None:
    return _SCALAR_WIDTHS.get(int(vn.size))


def _is_non_const(vn: Varnode) -> bool:
    return vn.space is not Space.CONST


def _varnode_name(vn: Varnode) -> str:
    return f"{vn.space.value}{vn.offset}_{int(vn.size)}".replace("-", "n")


def _const_literal(vn: Varnode) -> str:
    ty = _llvm_type(vn)
    assert ty is not None
    bits = int(vn.size) * 8
    mask = (1 << bits) - 1
    return str(int(vn.offset) & mask)


def _collect_instructions(flow_graph: FlowGraph) -> dict[int, tuple[Instruction, ...]]:
    projected: dict[int, tuple[Instruction, ...]] = {}
    for serial, block in flow_graph.blocks.items():
        projected[int(serial)] = tuple(
            project_instruction(insn) for insn in block.insn_snapshots
        )
    return projected


class _Classifier:
    def __init__(self, flow_graph: FlowGraph) -> None:
        self.flow_graph = flow_graph
        self.instructions = _collect_instructions(flow_graph)
        self.unsupported: list[UnsupportedLiftReason] = []

    def classify(self) -> list[UnsupportedLiftReason]:
        for serial in sorted(self.flow_graph.blocks):
            block = self.flow_graph.blocks[serial]
            instructions = self.instructions[serial]
            for index, instruction in enumerate(instructions):
                self._check_instruction(serial, index, instruction)
            self._check_terminator(serial, instructions)
        return self.unsupported

    def _add(
        self,
        block_serial: int,
        instruction_index: int | None,
        instruction: Instruction | None,
        kind: UnsupportedLiftKind,
        reason: str,
    ) -> None:
        ea = None
        operation = "<block>"
        if instruction is not None:
            raw_ea = instruction.attrs.get("ea")
            ea = int(raw_ea) if isinstance(raw_ea, int) else None
            operation = _operation_name(instruction.operation)
        self.unsupported.append(
            UnsupportedLiftReason(
                block_serial=int(block_serial),
                instruction_index=instruction_index,
                ea=ea,
                operation=operation,
                kind=kind,
                reason=reason,
            )
        )

    def _check_varnode(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
        vn: Varnode | None,
    ) -> None:
        if vn is None:
            return
        if _llvm_type(vn) is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VARNODE_WIDTH,
                f"unsupported varnode width {vn.size}; expected 1/2/4/8 bytes",
            )
        if vn.space is Space.UNKNOWN:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VARNODE_SPACE,
                "unknown varnode space",
            )

    def _check_instruction(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        for vn in (*instruction.inputs, instruction.result):
            self._check_varnode(block_serial, instruction_index, instruction, vn)
        if isinstance(instruction.operation, CallKind):
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.CALL_UNSUPPORTED,
                "calls are unsupported in M1a",
            )
            return
        if instruction.effects:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.EFFECT_UNSUPPORTED,
                "effects are unsupported in M1a",
            )
        if isinstance(instruction.operation, ControlTransferKind):
            if instruction.operation not in {
                ControlTransferKind.CONDITIONAL_BRANCH,
                ControlTransferKind.RETURN,
                ControlTransferKind.GOTO,
            }:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.CONTROL_TRANSFER_UNSUPPORTED,
                    f"control transfer {instruction.operation.value} is unsupported in M1a",
                )
            return
        if isinstance(instruction.operation, PredicateKind):
            self._check_predicate_materialization(block_serial, instruction_index, instruction)
            return
        if instruction.operation not in _VALUE_OPS:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_OP_UNSUPPORTED,
                f"value operation {_operation_name(instruction.operation)} is unsupported in M1a",
            )
            return
        if instruction.result is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_RESULT_MISSING,
                "value op has no result varnode",
            )
        elif instruction.result.space is Space.CONST:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_RESULT_CONST,
                "value op result cannot be const",
            )
        if instruction.operation is ValueOpKind.MOVE and len(instruction.inputs) != 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_ARITY,
                "MOVE requires one input",
            )
        if instruction.operation in _BINARY_VALUE_OPS:
            if len(instruction.inputs) != 2:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_ARITY,
                    f"{instruction.operation.value.upper()} requires two inputs",
                )
            self._check_matching_widths(block_serial, instruction_index, instruction)

    def _check_matching_widths(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        widths = {vn.size for vn in instruction.inputs}
        if instruction.result is not None:
            widths.add(instruction.result.size)
        if len(widths) > 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
                "M1a requires value operands and result to have matching widths",
            )

    def _check_predicate_materialization(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        if instruction.operation not in _PREDICATES:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.PREDICATE_UNSUPPORTED,
                f"predicate {_operation_name(instruction.operation)} is unsupported for materialization in M1c",
            )
        if instruction.result is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.PREDICATE_RESULT_MISSING,
                "predicate materialization has no result varnode",
            )
        elif instruction.result.space is Space.CONST:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.PREDICATE_RESULT_CONST,
                "predicate materialization result cannot be const",
            )
        if len(instruction.inputs) != 2:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.PREDICATE_ARITY,
                "predicate materialization requires two compared inputs",
            )
            return
        widths = {vn.size for vn in instruction.inputs}
        if len(widths) > 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.PREDICATE_WIDTH_MISMATCH,
                "M1c requires predicate inputs to have matching widths",
            )

    def _check_terminator(
        self,
        block_serial: int,
        instructions: tuple[Instruction, ...],
    ) -> None:
        block = self.flow_graph.blocks[block_serial]
        control_indexes = [
            index
            for index, instruction in enumerate(instructions)
            if isinstance(instruction.operation, ControlTransferKind)
        ]
        if len(control_indexes) > 1:
            for index in control_indexes[1:]:
                self._add(
                    block_serial,
                    index,
                    instructions[index],
                    UnsupportedLiftKind.MALFORMED_TERMINATOR,
                    "block has multiple control-transfer instructions",
                )
        for index in control_indexes:
            if index != len(instructions) - 1:
                self._add(
                    block_serial,
                    index,
                    instructions[index],
                    UnsupportedLiftKind.MALFORMED_TERMINATOR,
                    "control-transfer instruction must be block tail",
                )
        tail = instructions[-1] if instructions else None
        if tail is not None and tail.operation is ControlTransferKind.CONDITIONAL_BRANCH:
            if len(block.succs) != 2:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.BRANCH_SUCCESSOR_ARITY,
                    "conditional block needs two succs",
                )
            if tail.control is None or tail.control.predicate not in _PREDICATES:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.BRANCH_PREDICATE_UNSUPPORTED,
                    "unsupported branch predicate",
                )
            if len(tail.inputs) != 2:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.BRANCH_ARITY,
                    "conditional branch requires two compared inputs",
                )
            else:
                self._check_matching_widths(block_serial, len(instructions) - 1, tail)
            return
        if tail is not None and tail.operation is ControlTransferKind.RETURN:
            if block.succs:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.RETURN_SUCCESSOR,
                    "return block must have zero succs",
                )
            if tail.control is not None and tail.control.return_value is not None:
                ret_vn = tail.control.return_value
                if _llvm_type(ret_vn) != "i32":
                    self._add(
                        block_serial,
                        len(instructions) - 1,
                        tail,
                        UnsupportedLiftKind.RETURN_TYPE_UNSUPPORTED,
                        "M1a function signature supports only i32 return values",
                    )
            return
        if tail is not None and tail.operation is ControlTransferKind.GOTO:
            if len(block.succs) != 1:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.GOTO_SUCCESSOR_ARITY,
                    "goto block needs one succ",
                )
            return
        if len(block.succs) > 1:
            self._add(
                block_serial,
                None,
                None,
                UnsupportedLiftKind.BLOCK_TERMINATOR_MISSING,
                "multi-successor block needs conditional terminator",
            )


class _Emitter:
    def __init__(self, flow_graph: FlowGraph, function_name: str) -> None:
        self.flow_graph = flow_graph
        self.function_name = function_name
        self.instructions = _collect_instructions(flow_graph)
        self.varnodes = self._collect_varnodes()
        self._next_tmp = 0

    def emit(self) -> str:
        lines: list[str] = [
            f"; ModuleID = 'd810.{self.function_name}'",
            'source_filename = "d810-portable-ir"',
            "",
            f"define i32 @{self.function_name}() {{",
            "entry:",
        ]
        for vn in self.varnodes:
            lines.append(f"  %{_varnode_name(vn)} = alloca {_llvm_type(vn)}, align {vn.size}")
        lines.append(f"  br label %bb{self.flow_graph.entry_serial}")
        for serial in self._ordered_blocks():
            lines.extend(self._emit_block(serial))
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _ordered_blocks(self) -> tuple[int, ...]:
        entry = int(self.flow_graph.entry_serial)
        rest = tuple(serial for serial in sorted(self.flow_graph.blocks) if serial != entry)
        return (entry, *rest)

    def _collect_varnodes(self) -> tuple[Varnode, ...]:
        found: set[Varnode] = set()
        ordered: list[Varnode] = []
        for serial in sorted(self.flow_graph.blocks):
            for instruction in self.instructions[serial]:
                for vn in (*instruction.inputs, instruction.result):
                    if vn is None or not _is_non_const(vn) or vn in found:
                        continue
                    found.add(vn)
                    ordered.append(vn)
                if instruction.control is not None:
                    for vn in (
                        instruction.control.call_target,
                        instruction.control.indirect_target,
                        instruction.control.return_value,
                    ):
                        if vn is None or not _is_non_const(vn) or vn in found:
                            continue
                        found.add(vn)
                        ordered.append(vn)
        return tuple(sorted(ordered, key=lambda vn: (vn.space.value, vn.offset, vn.size)))

    def _emit_block(self, serial: int) -> list[str]:
        block = self.flow_graph.blocks[serial]
        instructions = self.instructions[serial]
        lines = [f"bb{serial}:"]
        body = instructions
        if body and isinstance(body[-1].operation, ControlTransferKind):
            body = body[:-1]
        for instruction in body:
            lines.extend(self._emit_value_instruction(instruction))
        lines.extend(self._emit_terminator(serial, instructions))
        return lines

    def _tmp(self) -> str:
        name = f"%t{self._next_tmp}"
        self._next_tmp += 1
        return name

    def _value(self, vn: Varnode) -> tuple[str, str]:
        ty = _llvm_type(vn)
        assert ty is not None
        if vn.space is Space.CONST:
            return ty, _const_literal(vn)
        tmp = self._tmp()
        return ty, f"{tmp} = load {ty}, ptr %{_varnode_name(vn)}, align {vn.size}"

    def _emit_value(self, vn: Varnode, lines: list[str]) -> tuple[str, str]:
        ty, value = self._value(vn)
        if value.startswith("%t") and " = load " in value:
            lines.append(f"  {value}")
            return ty, value.split(" = ", 1)[0]
        return ty, value

    def _emit_value_instruction(self, instruction: Instruction) -> list[str]:
        assert instruction.result is not None
        lines: list[str] = []
        result_ty = _llvm_type(instruction.result)
        assert result_ty is not None
        if isinstance(instruction.operation, PredicateKind):
            lhs_ty, lhs = self._emit_value(instruction.inputs[0], lines)
            _rhs_ty, rhs = self._emit_value(instruction.inputs[1], lines)
            cmp_tmp = self._tmp()
            zext_tmp = self._tmp()
            lines.append(
                f"  {cmp_tmp} = icmp {_PREDICATES[instruction.operation]} {lhs_ty} {lhs}, {rhs}"
            )
            lines.append(f"  {zext_tmp} = zext i1 {cmp_tmp} to {result_ty}")
            computed = zext_tmp
        elif instruction.operation is ValueOpKind.MOVE:
            _ty, value = self._emit_value(instruction.inputs[0], lines)
            computed = value
        else:
            _left_ty, left = self._emit_value(instruction.inputs[0], lines)
            _right_ty, right = self._emit_value(instruction.inputs[1], lines)
            tmp = self._tmp()
            opcode = {
                ValueOpKind.ADD: "add",
                ValueOpKind.SUB: "sub",
                ValueOpKind.MUL: "mul",
                ValueOpKind.OR: "or",
                ValueOpKind.AND: "and",
                ValueOpKind.XOR: "xor",
            }[instruction.operation]
            lines.append(f"  {tmp} = {opcode} {result_ty} {left}, {right}")
            computed = tmp
        lines.append(
            f"  store {result_ty} {computed}, ptr %{_varnode_name(instruction.result)}, "
            f"align {instruction.result.size}"
        )
        return lines

    def _emit_terminator(self, serial: int, instructions: tuple[Instruction, ...]) -> list[str]:
        block = self.flow_graph.blocks[serial]
        tail = instructions[-1] if instructions else None
        if tail is not None and tail.operation is ControlTransferKind.CONDITIONAL_BRANCH:
            return self._emit_conditional_branch(block.succs, tail)
        if tail is not None and tail.operation is ControlTransferKind.RETURN:
            return self._emit_return(tail)
        if block.succs:
            return [f"  br label %bb{block.succs[0]}"]
        return ["  ret i32 0"]

    def _emit_conditional_branch(
        self,
        succs: tuple[int, ...],
        instruction: Instruction,
    ) -> list[str]:
        lines: list[str] = []
        lhs_ty, lhs = self._emit_value(instruction.inputs[0], lines)
        _rhs_ty, rhs = self._emit_value(instruction.inputs[1], lines)
        pred = instruction.control.predicate if instruction.control is not None else None
        icmp = self._tmp()
        lines.append(f"  {icmp} = icmp {_PREDICATES[pred]} {lhs_ty} {lhs}, {rhs}")
        lines.append(f"  br i1 {icmp}, label %bb{succs[0]}, label %bb{succs[1]}")
        return lines

    def _emit_return(self, instruction: Instruction) -> list[str]:
        if instruction.control is None or instruction.control.return_value is None:
            return ["  ret i32 0"]
        lines: list[str] = []
        _ty, value = self._emit_value(instruction.control.return_value, lines)
        lines.append(f"  ret i32 {value}")
        return lines
