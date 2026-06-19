"""Textual LLVM IR emitter for the M1a portable-IR supported subset."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import FlowGraph
from d810.ir.insn_projection import project_instruction_sequence
from d810.ir.instructions import (
    Instruction,
    InstructionEffectKind,
    InstructionMemoryAccessKind,
)
from d810.ir.semantics import CallKind, ControlTransferKind, OperationKind, PredicateKind
from d810.ir.varnode import Space, Varnode
from d810.backends.llvm.identity_lowering import (
    LlvmIdentityManifest,
    build_identity_manifest,
    sanitize_llvm_function_name,
)

__all__ = [
    "LlvmIdentityManifest",
    "LlvmLiftBoundary",
    "LlvmLiftBoundaryInput",
    "LlvmLiftBoundaryObservable",
    "LlvmLiftBoundaryReturnPolicy",
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
_UNARY_VALUE_OPS = {
    ValueOpKind.NEG,
    ValueOpKind.SIGN_BIT,
    ValueOpKind.ZEXT,
}
_OVERFLOW_VALUE_OPS = {
    ValueOpKind.OVERFLOW_ADD,
    ValueOpKind.OVERFLOW_FLAG,
}
_VALUE_OPS = {
    ValueOpKind.MOVE,
    *_BINARY_VALUE_OPS,
    *_UNARY_VALUE_OPS,
    *_OVERFLOW_VALUE_OPS,
}
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
    CALL_PAYLOAD_UNSUPPORTED = "call_payload_unsupported"
    CALL_RESULT_UNSUPPORTED = "call_result_unsupported"
    EFFECT_UNSUPPORTED = "effect_unsupported"
    MEMORY_PAYLOAD_UNSUPPORTED = "memory_payload_unsupported"
    MEMORY_TARGET_UNSUPPORTED = "memory_target_unsupported"
    MEMORY_WIDTH_MISMATCH = "memory_width_mismatch"
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
    BRANCH_TARGET_UNSUPPORTED = "branch_target_unsupported"
    TABLE_ARITY = "table_arity"
    TABLE_CASES_MISSING = "table_cases_missing"
    TABLE_DEFAULT_MISSING = "table_default_missing"
    TABLE_CASE_DUPLICATE = "table_case_duplicate"
    TABLE_TARGET_UNSUPPORTED = "table_target_unsupported"
    MALFORMED_TERMINATOR = "malformed_terminator"
    RETURN_SUCCESSOR = "return_successor"
    RETURN_TYPE_UNSUPPORTED = "return_type_unsupported"
    BOUNDARY_SYMBOL_CONFLICT = "boundary_symbol_conflict"
    GOTO_SUCCESSOR_ARITY = "goto_successor_arity"
    BLOCK_TERMINATOR_MISSING = "block_terminator_missing"
    NESTED_EXPRESSION_UNSUPPORTED = "nested_expression_unsupported"


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
    identity_manifest: LlvmIdentityManifest | None = None

    @property
    def supported(self) -> bool:
        return not self.unsupported


@dataclass(frozen=True, slots=True)
class LlvmLiftBoundaryInput:
    """Opt-in function parameter mapped to one or more portable cells."""

    name: str
    cell: Varnode
    aliases: tuple[Varnode, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "aliases", tuple(self.aliases))


@dataclass(frozen=True, slots=True)
class LlvmLiftBoundaryObservable:
    """Opt-in observable cell mirrored to an external LLVM global."""

    name: str
    cell: Varnode
    volatile: bool = True


class LlvmLiftBoundaryReturnPolicy(str, Enum):
    """How an explicit boundary return cell participates in return emission."""

    FALLBACK = "fallback"
    OVERRIDE = "override"


@dataclass(frozen=True, slots=True)
class LlvmLiftBoundary:
    """Explicit function-boundary policy for diagnostic/prototype lifts.

    The default lift deliberately remains local and zero-argument.  Boundary
    policies are opt-in so lab-specific ABI assumptions stay visible at the call
    site instead of being inferred from generic portable cells.
    """

    inputs: tuple[LlvmLiftBoundaryInput, ...] = ()
    observables: tuple[LlvmLiftBoundaryObservable, ...] = ()
    return_cell: Varnode | None = None
    return_policy: LlvmLiftBoundaryReturnPolicy = LlvmLiftBoundaryReturnPolicy.FALLBACK

    def __post_init__(self) -> None:
        object.__setattr__(self, "inputs", tuple(self.inputs))
        object.__setattr__(self, "observables", tuple(self.observables))


def emit_flowgraph_to_llvm(
    flow_graph: FlowGraph,
    *,
    function_name: str = "d810_fn",
    boundary: LlvmLiftBoundary | None = None,
) -> LlvmLiftResult:
    """Emit LLVM IR for the M1a supported subset.

    The whole graph is classified before emission.  If anything is unsupported,
    ``ir_text`` is empty and every reason is returned.
    """
    boundary = boundary or LlvmLiftBoundary()
    classifier = _Classifier(flow_graph, boundary)
    unsupported = classifier.classify()
    if unsupported:
        return LlvmLiftResult(ir_text="", unsupported=tuple(unsupported))
    emitter = _Emitter(
        flow_graph,
        sanitize_llvm_function_name(function_name),
        boundary,
    )
    return LlvmLiftResult(ir_text=emitter.emit(), identity_manifest=emitter.identity_manifest())


def _sanitize_function_name(name: str) -> str:
    return sanitize_llvm_function_name(name)


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


def _symbol_name(name: str) -> str:
    return sanitize_llvm_function_name(name)


def _boundary_arg_name(name: str) -> str:
    return f"arg_{_symbol_name(name)}"


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
            instruction
            for insn in block.insn_snapshots
            for instruction in project_instruction_sequence(insn)
        )
    return projected


class _Classifier:
    def __init__(self, flow_graph: FlowGraph, boundary: LlvmLiftBoundary) -> None:
        self.flow_graph = flow_graph
        self.boundary = boundary
        self.instructions = _collect_instructions(flow_graph)
        self.unsupported: list[UnsupportedLiftReason] = []

    def classify(self) -> list[UnsupportedLiftReason]:
        self._check_boundary()
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

    def _check_boundary(self) -> None:
        self._check_boundary_input_names()
        self._check_boundary_observable_names()
        for boundary_input in self.boundary.inputs:
            self._check_boundary_cell(
                boundary_input.cell,
                f"boundary input {boundary_input.name!r}",
            )
            for alias in boundary_input.aliases:
                self._check_boundary_cell(
                    alias,
                    f"boundary input alias for {boundary_input.name!r}",
                )
        for observable in self.boundary.observables:
            self._check_boundary_cell(
                observable.cell,
                f"boundary observable {observable.name!r}",
            )
        if self.boundary.return_cell is None:
            if self.boundary.return_policy is LlvmLiftBoundaryReturnPolicy.OVERRIDE:
                self._add(
                    int(self.flow_graph.entry_serial),
                    None,
                    None,
                    UnsupportedLiftKind.RETURN_TYPE_UNSUPPORTED,
                    "M2n boundary return override requires return_cell",
                )
            return
        self._check_boundary_cell(self.boundary.return_cell, "boundary return cell")
        if _llvm_type(self.boundary.return_cell) != "i32":
            self._add(
                int(self.flow_graph.entry_serial),
                None,
                None,
                UnsupportedLiftKind.RETURN_TYPE_UNSUPPORTED,
                "M2l boundary return_cell supports only i32 values",
            )

    def _check_boundary_input_names(self) -> None:
        seen: dict[str, str] = {}
        for boundary_input in self.boundary.inputs:
            symbol = _boundary_arg_name(boundary_input.name)
            previous = seen.get(symbol)
            if previous is not None:
                self._add(
                    int(self.flow_graph.entry_serial),
                    None,
                    None,
                    UnsupportedLiftKind.BOUNDARY_SYMBOL_CONFLICT,
                    (
                        f"boundary input names {previous!r} and {boundary_input.name!r} "
                        f"both sanitize to %{symbol}"
                    ),
                )
                continue
            seen[symbol] = boundary_input.name

    def _check_boundary_observable_names(self) -> None:
        seen: dict[str, LlvmLiftBoundaryObservable] = {}
        for observable in self.boundary.observables:
            symbol = _symbol_name(observable.name)
            previous = seen.get(symbol)
            if previous is not None and previous.cell != observable.cell:
                self._add(
                    int(self.flow_graph.entry_serial),
                    None,
                    None,
                    UnsupportedLiftKind.BOUNDARY_SYMBOL_CONFLICT,
                    (
                        f"boundary observables {previous.name!r} and {observable.name!r} "
                        f"both sanitize to @{symbol} for different cells"
                    ),
                )
                continue
            seen[symbol] = observable

    def _check_boundary_cell(self, vn: Varnode, description: str) -> None:
        if _llvm_type(vn) is None:
            self._add(
                int(self.flow_graph.entry_serial),
                None,
                None,
                UnsupportedLiftKind.VARNODE_WIDTH,
                f"{description} has unsupported width {vn.size}; expected 1/2/4/8 bytes",
            )
        if vn.space in {Space.CONST, Space.UNKNOWN}:
            self._add(
                int(self.flow_graph.entry_serial),
                None,
                None,
                UnsupportedLiftKind.VARNODE_SPACE,
                f"{description} must be a concrete non-const cell",
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
            self._check_call(block_serial, instruction_index, instruction)
            return
        if instruction.operation in {ValueOpKind.LOAD, ValueOpKind.STORE}:
            self._check_memory_access(block_serial, instruction_index, instruction)
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
            if instruction.operation is ControlTransferKind.TABLE_BRANCH:
                return
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
        if "unsupported_nested_sub_kind" in instruction.attrs:
            nested_kind = instruction.attrs.get("unsupported_nested_sub_kind")
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.NESTED_EXPRESSION_UNSUPPORTED,
                f"nested expression {nested_kind} is unsupported in M1f",
            )
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
        if instruction.operation is ValueOpKind.NEG:
            if len(instruction.inputs) != 1:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_ARITY,
                    "NEG requires one input",
                )
            self._check_matching_widths(block_serial, instruction_index, instruction)
        if instruction.operation is ValueOpKind.SIGN_BIT:
            if len(instruction.inputs) != 1:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_ARITY,
                    "SIGN_BIT requires one input",
                )
        if instruction.operation is ValueOpKind.ZEXT:
            if len(instruction.inputs) != 1:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_ARITY,
                    "ZEXT requires one input",
                )
            elif instruction.result is not None and (
                int(instruction.inputs[0].size) >= int(instruction.result.size)
            ):
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
                    "ZEXT requires input width to be narrower than result width",
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
        if instruction.operation in _OVERFLOW_VALUE_OPS:
            if len(instruction.inputs) != 2:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_ARITY,
                    f"{instruction.operation.value.upper()} requires two inputs",
                )
            self._check_input_widths_match(block_serial, instruction_index, instruction)

    def _check_memory_access(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        memory = instruction.memory
        if memory is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_PAYLOAD_UNSUPPORTED,
                "memory operation requires an explicit portable memory access contract",
            )
            return
        if memory.kind is not InstructionMemoryAccessKind.DIRECT_CELL:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_TARGET_UNSUPPORTED,
                "M1l supports only direct-cell memory accesses",
            )
            return
        if memory.segment is not None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_TARGET_UNSUPPORTED,
                "direct-cell memory access cannot carry a segment or pointer component",
            )
        if memory.target is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_PAYLOAD_UNSUPPORTED,
                "direct-cell memory access requires a target cell",
            )
            return
        self._check_varnode(block_serial, instruction_index, instruction, memory.target)
        if memory.target.space in {Space.CONST, Space.REGISTER, Space.UNKNOWN}:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_TARGET_UNSUPPORTED,
                "direct-cell memory target must be a concrete non-register storage cell",
            )
        if instruction.operation is ValueOpKind.LOAD:
            if instruction.result is None:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_RESULT_MISSING,
                    "LOAD requires a result varnode",
                )
                return
            if instruction.result.space is Space.CONST:
                self._add(
                    block_serial,
                    instruction_index,
                    instruction,
                    UnsupportedLiftKind.VALUE_RESULT_CONST,
                    "LOAD result cannot be const",
                )
            self._check_varnode(block_serial, instruction_index, instruction, instruction.result)
            self._check_memory_width(
                block_serial,
                instruction_index,
                instruction,
                memory.target,
                instruction.result,
                memory.width,
            )
            return
        if (
            len(instruction.effects) != 1
            or instruction.effects[0].kind is not InstructionEffectKind.STORE
        ):
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_PAYLOAD_UNSUPPORTED,
                "STORE requires exactly one canonical store effect",
            )
            return
        store_effect = instruction.effects[0]
        if (
            store_effect.target != memory.target
            or store_effect.segment != memory.segment
            or store_effect.value != memory.value
        ):
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_PAYLOAD_UNSUPPORTED,
                "STORE effect payload must match memory access contract",
            )
        if memory.value is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_PAYLOAD_UNSUPPORTED,
                "STORE requires a value varnode",
            )
            return
        self._check_varnode(block_serial, instruction_index, instruction, memory.value)
        self._check_memory_width(
            block_serial,
            instruction_index,
            instruction,
            memory.target,
            memory.value,
            memory.width,
        )

    def _check_memory_width(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
        target: Varnode,
        value: Varnode,
        access_width: int | None,
    ) -> None:
        widths = {int(target.size), int(value.size)}
        if access_width is not None:
            widths.add(int(access_width))
        if len(widths) > 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.MEMORY_WIDTH_MISMATCH,
                "direct-cell memory access requires target/value/access widths to match",
            )

    def _check_call(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        if (
            len(instruction.effects) != 1
            or instruction.effects[0].kind is not InstructionEffectKind.CALL
        ):
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.CALL_PAYLOAD_UNSUPPORTED,
                "call requires exactly one canonical call effect",
            )
        call_target = instruction.control.call_target if instruction.control is not None else None
        if call_target is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.CALL_PAYLOAD_UNSUPPORTED,
                "call requires a portable call target",
            )
        else:
            self._check_varnode(block_serial, instruction_index, instruction, call_target)
        if instruction.result is not None and instruction.result.space is Space.CONST:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.CALL_RESULT_UNSUPPORTED,
                "call result cannot be const",
            )

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

    def _check_input_widths_match(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        widths = {vn.size for vn in instruction.inputs}
        if len(widths) > 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.VALUE_WIDTH_MISMATCH,
                "M1k requires flag inputs to have matching widths",
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
            self._check_conditional_branch_targets(block_serial, len(instructions) - 1, tail)
            return
        if tail is not None and tail.operation is ControlTransferKind.TABLE_BRANCH:
            if len(tail.inputs) != 1:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.TABLE_ARITY,
                    "table branch requires one selector input",
                )
            cases = tail.control.switch_cases if tail.control is not None else ()
            if not cases:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.TABLE_CASES_MISSING,
                    "table branch requires switch cases",
                )
                return
            default_cases = [case for case in cases if not case.values]
            if len(default_cases) != 1:
                self._add(
                    block_serial,
                    len(instructions) - 1,
                    tail,
                    UnsupportedLiftKind.TABLE_DEFAULT_MISSING,
                    "table branch requires exactly one default case",
                )
            if len(tail.inputs) == 1 and _llvm_type(tail.inputs[0]) is not None:
                bits = int(tail.inputs[0].size) * 8
                mask = (1 << bits) - 1
                seen_values: set[int] = set()
                for case in cases:
                    for value in case.values:
                        masked = int(value) & mask
                        if masked in seen_values:
                            self._add(
                                block_serial,
                                len(instructions) - 1,
                                tail,
                                UnsupportedLiftKind.TABLE_CASE_DUPLICATE,
                                "table branch case values must be unique after selector-width canonicalization",
                            )
                            break
                        seen_values.add(masked)
                    else:
                        continue
                    break
            succs = {int(succ) for succ in block.succs}
            for case in cases:
                if int(case.target) not in succs:
                    self._add(
                        block_serial,
                        len(instructions) - 1,
                        tail,
                        UnsupportedLiftKind.TABLE_TARGET_UNSUPPORTED,
                        "table branch case target is not a block successor",
                    )
                    break
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
            boundary_return_overrides = (
                self.boundary.return_policy is LlvmLiftBoundaryReturnPolicy.OVERRIDE
                and self.boundary.return_cell is not None
            )
            if (
                tail.control is not None
                and tail.control.return_value is not None
                and not boundary_return_overrides
            ):
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

    def _check_conditional_branch_targets(
        self,
        block_serial: int,
        instruction_index: int,
        instruction: Instruction,
    ) -> None:
        block = self.flow_graph.blocks[block_serial]
        control = instruction.control
        succs = tuple(int(succ) for succ in block.succs)
        if len(succs) != 2 or control is None:
            return
        if control.target is None:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.BRANCH_TARGET_UNSUPPORTED,
                "conditional branch requires portable taken target",
            )
            return
        target = int(control.target)
        if target not in succs:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.BRANCH_TARGET_UNSUPPORTED,
                "conditional branch target is not a block successor",
            )
            return
        false_candidates = tuple(succ for succ in succs if succ != target)
        if len(false_candidates) != 1:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.BRANCH_TARGET_UNSUPPORTED,
                "conditional branch target must identify one taken edge",
            )
            return
        if control.fallthrough is None:
            return
        fallthrough = int(control.fallthrough)
        if fallthrough not in succs:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.BRANCH_TARGET_UNSUPPORTED,
                "conditional branch fallthrough is not a block successor",
            )
            return
        if fallthrough == target or fallthrough != false_candidates[0]:
            self._add(
                block_serial,
                instruction_index,
                instruction,
                UnsupportedLiftKind.BRANCH_TARGET_UNSUPPORTED,
                "conditional branch fallthrough conflicts with target/successors",
            )


class _Emitter:
    def __init__(
        self,
        flow_graph: FlowGraph,
        function_name: str,
        boundary: LlvmLiftBoundary,
    ) -> None:
        self.flow_graph = flow_graph
        self.function_name = function_name
        self.boundary = boundary
        self.instructions = _collect_instructions(flow_graph)
        self.varnodes = self._collect_varnodes()
        self.declarations: dict[str, str] = {}
        self._next_tmp = 0

    def emit(self) -> str:
        args = ", ".join(
            f"{_llvm_type(boundary_input.cell)} %{_boundary_arg_name(boundary_input.name)}"
            for boundary_input in self.boundary.inputs
        )
        body_lines: list[str] = [
            f"; ModuleID = 'd810.{self.function_name}'",
            'source_filename = "d810-portable-ir"',
            "",
            f"define i32 @{self.function_name}({args}) {{",
            "entry:",
        ]
        for vn in self.varnodes:
            body_lines.append(f"  %{_varnode_name(vn)} = alloca {_llvm_type(vn)}, align {vn.size}")
        for boundary_input in self.boundary.inputs:
            body_lines.extend(self._emit_boundary_input(boundary_input))
        body_lines.append(f"  br label %bb{self.flow_graph.entry_serial}")
        for serial in self._ordered_blocks():
            body_lines.extend(self._emit_block(serial))
        body_lines.append("}")
        lines = body_lines[:3]
        for observable in self.boundary.observables:
            ty = _llvm_type(observable.cell)
            assert ty is not None
            name = _symbol_name(observable.name)
            self.declarations.setdefault(name, f"@{name} = external global {ty}")
        for name in sorted(self.declarations):
            lines.append(self.declarations[name])
        if self.declarations:
            lines.append("")
        lines.extend(body_lines[3:])
        return "\n".join(lines) + "\n"

    def identity_manifest(self) -> LlvmIdentityManifest:
        """Return the portable identity manifest for the accepted lift."""

        return build_identity_manifest(
            self.flow_graph,
            self.instructions,
            self.varnodes,
            function_name=self.function_name,
        )

    def _ordered_blocks(self) -> tuple[int, ...]:
        entry = int(self.flow_graph.entry_serial)
        rest = tuple(serial for serial in sorted(self.flow_graph.blocks) if serial != entry)
        return (entry, *rest)

    def _collect_varnodes(self) -> tuple[Varnode, ...]:
        found: set[Varnode] = set()
        ordered: list[Varnode] = []
        for boundary_input in self.boundary.inputs:
            for vn in (boundary_input.cell, *boundary_input.aliases):
                if not _is_non_const(vn) or vn in found:
                    continue
                found.add(vn)
                ordered.append(vn)
        for observable in self.boundary.observables:
            if not _is_non_const(observable.cell) or observable.cell in found:
                continue
            found.add(observable.cell)
            ordered.append(observable.cell)
        if (
            self.boundary.return_cell is not None
            and _is_non_const(self.boundary.return_cell)
            and self.boundary.return_cell not in found
        ):
            found.add(self.boundary.return_cell)
            ordered.append(self.boundary.return_cell)
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
                if instruction.memory is not None:
                    for vn in (
                        instruction.memory.target,
                        instruction.memory.segment,
                        instruction.memory.value,
                    ):
                        if vn is None or not _is_non_const(vn) or vn in found:
                            continue
                        found.add(vn)
                        ordered.append(vn)
        return tuple(sorted(ordered, key=lambda vn: (vn.space.value, vn.offset, vn.size)))

    def _emit_boundary_input(self, boundary_input: LlvmLiftBoundaryInput) -> list[str]:
        lines: list[str] = []
        source_ty = _llvm_type(boundary_input.cell)
        assert source_ty is not None
        source = f"%{_boundary_arg_name(boundary_input.name)}"
        for target in (boundary_input.cell, *boundary_input.aliases):
            target_ty = _llvm_type(target)
            assert target_ty is not None
            value = source
            if target_ty != source_ty:
                value = self._tmp()
                op = "trunc" if int(target.size) < int(boundary_input.cell.size) else "zext"
                lines.append(f"  {value} = {op} {source_ty} {source} to {target_ty}")
            lines.append(
                f"  store {target_ty} {value}, ptr %{_varnode_name(target)}, "
                f"align {target.size}"
            )
        return lines

    def _emit_block(self, serial: int) -> list[str]:
        block = self.flow_graph.blocks[serial]
        instructions = self.instructions[serial]
        lines = [f"bb{serial}:"]
        body = instructions
        if body and isinstance(body[-1].operation, ControlTransferKind):
            body = body[:-1]
        for instruction in body:
            lines.extend(self._emit_body_instruction(instruction))
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

    def _emit_body_instruction(self, instruction: Instruction) -> list[str]:
        if isinstance(instruction.operation, CallKind):
            return self._emit_call_instruction(instruction)
        if instruction.operation in {ValueOpKind.LOAD, ValueOpKind.STORE}:
            return self._emit_memory_instruction(instruction)
        return self._emit_value_instruction(instruction)

    def _call_arguments(self, instruction: Instruction) -> tuple[Varnode, ...]:
        target = instruction.control.call_target if instruction.control is not None else None
        if target is None:
            return instruction.inputs
        if instruction.inputs and instruction.inputs[0] == target:
            return instruction.inputs
        return (target, *instruction.inputs)

    def _call_declaration_name(self, ret_ty: str, arg_tys: tuple[str, ...]) -> str:
        sig = "_".join((ret_ty, *arg_tys)).replace("*", "ptr").replace(" ", "_")
        name = f"__d810_opaque_call_{sig}"
        self.declarations.setdefault(name, f"declare {ret_ty} @{name}({', '.join(arg_tys)})")
        return name

    def _overflow_intrinsic_name(self, operation: ValueOpKind, ty: str) -> str:
        suffix = "sadd" if operation is ValueOpKind.OVERFLOW_ADD else "ssub"
        name = f"llvm.{suffix}.with.overflow.{ty}"
        self.declarations.setdefault(name, f"declare {{ {ty}, i1 }} @{name}({ty}, {ty})")
        return name

    def _emit_call_instruction(self, instruction: Instruction) -> list[str]:
        lines: list[str] = []
        args: list[str] = []
        arg_tys: list[str] = []
        for vn in self._call_arguments(instruction):
            ty, value = self._emit_value(vn, lines)
            arg_tys.append(ty)
            args.append(f"{ty} {value}")
        ret_ty = _llvm_type(instruction.result) if instruction.result is not None else "void"
        assert ret_ty is not None
        callee = self._call_declaration_name(ret_ty, tuple(arg_tys))
        if instruction.result is None:
            lines.append(f"  call void @{callee}({', '.join(args)})")
            return lines
        tmp = self._tmp()
        lines.append(f"  {tmp} = call {ret_ty} @{callee}({', '.join(args)})")
        lines.append(
            f"  store {ret_ty} {tmp}, ptr %{_varnode_name(instruction.result)}, "
            f"align {instruction.result.size}"
        )
        return lines

    def _emit_memory_instruction(self, instruction: Instruction) -> list[str]:
        assert instruction.memory is not None
        assert instruction.memory.target is not None
        target = instruction.memory.target
        target_ty = _llvm_type(target)
        assert target_ty is not None
        lines: list[str] = []
        if instruction.operation is ValueOpKind.LOAD:
            assert instruction.result is not None
            result_ty = _llvm_type(instruction.result)
            assert result_ty is not None
            loaded = self._tmp()
            lines.append(
                f"  {loaded} = load {target_ty}, ptr %{_varnode_name(target)}, align {target.size}"
            )
            lines.append(
                f"  store {result_ty} {loaded}, ptr %{_varnode_name(instruction.result)}, "
                f"align {instruction.result.size}"
            )
            return lines
        assert instruction.memory.value is not None
        value_ty, value = self._emit_value(instruction.memory.value, lines)
        assert value_ty == target_ty
        lines.append(
            f"  store {target_ty} {value}, ptr %{_varnode_name(target)}, align {target.size}"
        )
        lines.extend(self._emit_observable_store(target, value))
        return lines

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
        elif instruction.operation is ValueOpKind.NEG:
            _ty, value = self._emit_value(instruction.inputs[0], lines)
            tmp = self._tmp()
            lines.append(f"  {tmp} = sub {result_ty} 0, {value}")
            computed = tmp
        elif instruction.operation is ValueOpKind.SIGN_BIT:
            input_ty, value = self._emit_value(instruction.inputs[0], lines)
            cmp_tmp = self._tmp()
            zext_tmp = self._tmp()
            lines.append(f"  {cmp_tmp} = icmp slt {input_ty} {value}, 0")
            lines.append(f"  {zext_tmp} = zext i1 {cmp_tmp} to {result_ty}")
            computed = zext_tmp
        elif instruction.operation is ValueOpKind.ZEXT:
            input_ty, value = self._emit_value(instruction.inputs[0], lines)
            tmp = self._tmp()
            lines.append(f"  {tmp} = zext {input_ty} {value} to {result_ty}")
            computed = tmp
        elif instruction.operation in _OVERFLOW_VALUE_OPS:
            input_ty, left = self._emit_value(instruction.inputs[0], lines)
            _right_ty, right = self._emit_value(instruction.inputs[1], lines)
            intrinsic = self._overflow_intrinsic_name(instruction.operation, input_ty)
            pair_tmp = self._tmp()
            overflow_tmp = self._tmp()
            zext_tmp = self._tmp()
            pair_ty = f"{{ {input_ty}, i1 }}"
            lines.append(
                f"  {pair_tmp} = call {pair_ty} @{intrinsic}({input_ty} {left}, {input_ty} {right})"
            )
            lines.append(f"  {overflow_tmp} = extractvalue {pair_ty} {pair_tmp}, 1")
            lines.append(f"  {zext_tmp} = zext i1 {overflow_tmp} to {result_ty}")
            computed = zext_tmp
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
        lines.extend(self._emit_observable_store(instruction.result, computed))
        return lines

    def _emit_observable_store(self, cell: Varnode, value: str) -> list[str]:
        lines: list[str] = []
        for observable in self.boundary.observables:
            if observable.cell != cell:
                continue
            ty = _llvm_type(cell)
            assert ty is not None
            volatile = " volatile" if observable.volatile else ""
            lines.append(
                f"  store{volatile} {ty} {value}, ptr @{_symbol_name(observable.name)}, "
                f"align {cell.size}"
            )
        return lines

    def _emit_terminator(self, serial: int, instructions: tuple[Instruction, ...]) -> list[str]:
        block = self.flow_graph.blocks[serial]
        tail = instructions[-1] if instructions else None
        if tail is not None and tail.operation is ControlTransferKind.CONDITIONAL_BRANCH:
            return self._emit_conditional_branch(block.succs, tail)
        if tail is not None and tail.operation is ControlTransferKind.TABLE_BRANCH:
            return self._emit_table_branch(tail)
        if tail is not None and tail.operation is ControlTransferKind.RETURN:
            return self._emit_return(tail)
        if block.succs:
            return [f"  br label %bb{block.succs[0]}"]
        if self.boundary.return_cell is not None:
            return self._emit_return_value(self.boundary.return_cell)
        return ["  ret i32 0"]

    def _emit_conditional_branch(
        self,
        succs: tuple[int, ...],
        instruction: Instruction,
    ) -> list[str]:
        lines: list[str] = []
        lhs_ty, lhs = self._emit_value(instruction.inputs[0], lines)
        _rhs_ty, rhs = self._emit_value(instruction.inputs[1], lines)
        assert instruction.control is not None
        pred = instruction.control.predicate
        true_target = int(instruction.control.target)
        false_target = (
            int(instruction.control.fallthrough)
            if instruction.control.fallthrough is not None
            else next(succ for succ in succs if int(succ) != true_target)
        )
        icmp = self._tmp()
        lines.append(f"  {icmp} = icmp {_PREDICATES[pred]} {lhs_ty} {lhs}, {rhs}")
        lines.append(f"  br i1 {icmp}, label %bb{true_target}, label %bb{false_target}")
        return lines

    def _emit_table_branch(self, instruction: Instruction) -> list[str]:
        lines: list[str] = []
        selector_ty, selector = self._emit_value(instruction.inputs[0], lines)
        cases = instruction.control.switch_cases if instruction.control is not None else ()
        default_target = next(case.target for case in cases if not case.values)
        lines.append(f"  switch {selector_ty} {selector}, label %bb{default_target} [")
        for case in cases:
            if not case.values:
                continue
            for value in case.values:
                bits = int(instruction.inputs[0].size) * 8
                masked = int(value) & ((1 << bits) - 1)
                lines.append(f"    {selector_ty} {masked}, label %bb{case.target}")
        lines.append("  ]")
        return lines

    def _emit_return(self, instruction: Instruction) -> list[str]:
        if (
            instruction.control is None or instruction.control.return_value is None
        ) and self.boundary.return_cell is None:
            return ["  ret i32 0"]
        lines: list[str] = []
        if (
            self.boundary.return_policy is LlvmLiftBoundaryReturnPolicy.OVERRIDE
            and self.boundary.return_cell is not None
        ):
            return_value = self.boundary.return_cell
        else:
            return_value = (
                instruction.control.return_value
                if instruction.control is not None and instruction.control.return_value is not None
                else self.boundary.return_cell
            )
        assert return_value is not None
        return self._emit_return_value(return_value)

    def _emit_return_value(self, return_value: Varnode) -> list[str]:
        lines: list[str] = []
        _ty, value = self._emit_value(return_value, lines)
        lines.append(f"  ret i32 {value}")
        return lines
