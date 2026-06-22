"""Constrained optimized-LLVM ingestion for M3 lower-back readiness.

This module is IDA-free and intentionally not a general LLVM parser.  It
accepts the small textual subset currently emitted and optimized by the local
M1/M2 path, converts it into the M3 lower-back contract DTOs, and delegates the
actual support decision to ``plan_lower_back``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .lower_back_contract import (
    LlvmLowerBackBlock,
    LlvmLowerBackFunction,
    LlvmLowerBackInstruction,
    LlvmLowerBackResult,
    LlvmLowerBackStatus,
    LlvmLowerBackTerminator,
    LlvmLowerBackTerminatorKind,
    LlvmPhiIncoming,
    LlvmPhiNode,
    LlvmValueRef,
    plan_lower_back,
)


class LlvmLowerBackParseStatus(str, Enum):
    PARSED = "parsed"
    FAILED = "failed"


class LlvmLowerBackReadinessStatus(str, Enum):
    PLANNED = "planned"
    UNSUPPORTED = "unsupported"
    PARSE_FAILED = "parse_failed"


class LlvmLowerBackParseDiagnosticKind(str, Enum):
    FUNCTION_UNSUPPORTED = "function_unsupported"
    INSTRUCTION_AFTER_TERMINATOR = "instruction_after_terminator"
    MALFORMED_BRANCH = "malformed_branch"
    MALFORMED_DEFINE = "malformed_define"
    MALFORMED_INSTRUCTION = "malformed_instruction"
    MALFORMED_PHI = "malformed_phi"
    MALFORMED_RETURN = "malformed_return"
    MISSING_TERMINATOR = "missing_terminator"
    MULTIPLE_TERMINATORS = "multiple_terminators"
    MULTIPLE_FUNCTIONS = "multiple_functions"
    UNKNOWN_TERMINATOR = "unknown_terminator"


@dataclass(frozen=True, slots=True)
class LlvmLowerBackParseDiagnostic:
    kind: LlvmLowerBackParseDiagnosticKind
    line_number: int
    reason: str
    text: str = ""


@dataclass(frozen=True, slots=True)
class LlvmLowerBackParseResult:
    status: LlvmLowerBackParseStatus
    function: LlvmLowerBackFunction | None = None
    diagnostics: tuple[LlvmLowerBackParseDiagnostic, ...] = ()

    @property
    def parsed(self) -> bool:
        return self.status is LlvmLowerBackParseStatus.PARSED


@dataclass(frozen=True, slots=True)
class LlvmLowerBackReadinessResult:
    status: LlvmLowerBackReadinessStatus
    parse_result: LlvmLowerBackParseResult
    plan_result: LlvmLowerBackResult | None = None

    @property
    def planned(self) -> bool:
        return self.status is LlvmLowerBackReadinessStatus.PLANNED


_DEFINE_RE = re.compile(r"^define\b.*@(?P<name>[A-Za-z0-9_.$-]+)\([^)]*\)\s*\{\s*$")
_ONE_LINE_DEFINE_RE = re.compile(
    r"^define\b.*@(?P<name>[A-Za-z0-9_.$-]+)\([^)]*\)\s*\{\s*(?P<body>.+?)\s*\}\s*$"
)
_LABEL_RE = re.compile(r"^(?P<label>[A-Za-z$._-][A-Za-z0-9$._-]*):\s*(?:;.*)?$")
_BR_RE = re.compile(r"^br\s+label\s+%(?P<target>[A-Za-z0-9$._-]+)$")
_COND_BR_RE = re.compile(
    r"^br\s+i1\s+[^,]+,\s+label\s+%(?P<true>[A-Za-z0-9$._-]+),\s+label\s+%(?P<false>[A-Za-z0-9$._-]+)$"
)
_RET_RE = re.compile(
    r"^ret\s+(?P<type>i(?:1|8|16|32|64))\s+(?P<value>%?[A-Za-z0-9$._-]+|-?\d+|true|false)$"
)
_PHI_RE = re.compile(r"^(?P<result>%[A-Za-z0-9$._-]+)\s*=\s*phi\s+(?P<type>\S+)\s+(?P<body>.+)$")
_PHI_INCOMING_RE = re.compile(
    r"\[\s*(?P<value>%?[A-Za-z0-9$._-]+|-?\d+|true|false)\s*,\s*%(?P<pred>[A-Za-z0-9$._-]+)\s*\]"
)
_ASSIGN_RE = re.compile(r"^(?P<result>%[A-Za-z0-9$._-]+)\s*=\s*(?P<opcode>[A-Za-z][A-Za-z0-9.]*)\b(?P<rest>.*)$")
_TYPE_RE = re.compile(r"(?P<type><[^>]+>|i(?:1|8|16|32|64)\b|ptr\b|void\b|float\b|double\b)")
_VALUE_RE = re.compile(r"(?P<value>%[A-Za-z0-9$._-]+|-?\d+|true|false)")
_BINARY_SCALAR_OPCODES = {"add", "and", "mul", "or", "sub", "xor"}
_SUPPORTED_SCALAR_OPCODES = _BINARY_SCALAR_OPCODES | {"icmp", "zext"}


def parse_lower_back_function(ir_text: str) -> LlvmLowerBackParseResult:
    """Parse one constrained LLVM function into the M3 lower-back DTO."""
    diagnostics: list[LlvmLowerBackParseDiagnostic] = []
    lines = _semantic_lines(ir_text)
    define_indexes = [
        index for index, (_line_no, line) in enumerate(lines) if line.startswith("define ")
    ]
    if len(define_indexes) != 1:
        return _parse_failure(
            diagnostics,
            LlvmLowerBackParseDiagnosticKind.MULTIPLE_FUNCTIONS,
            0,
            "expected exactly one define block",
            "",
        )

    line_no, define_line = lines[define_indexes[0]]
    one_line = _ONE_LINE_DEFINE_RE.match(define_line)
    if one_line is not None:
        body_line = one_line.group("body").strip()
        terminator = _parse_terminator(body_line, line_no, diagnostics)
        if terminator is None or diagnostics:
            return LlvmLowerBackParseResult(
                status=LlvmLowerBackParseStatus.FAILED,
                diagnostics=tuple(diagnostics),
            )
        return LlvmLowerBackParseResult(
            status=LlvmLowerBackParseStatus.PARSED,
            function=LlvmLowerBackFunction(
                name=one_line.group("name"),
                entry="entry",
                blocks=(
                    LlvmLowerBackBlock(
                        label="entry",
                        predecessors=(),
                        terminator=terminator,
                    ),
                ),
            ),
        )

    match = _DEFINE_RE.match(define_line)
    if match is None:
        return _parse_failure(
            diagnostics,
            LlvmLowerBackParseDiagnosticKind.MALFORMED_DEFINE,
            line_no,
            "unsupported define syntax",
            define_line,
        )
    function_name = match.group("name")
    body_lines = lines[define_indexes[0] + 1 :]
    if not body_lines or body_lines[-1][1] != "}":
        return _parse_failure(
            diagnostics,
            LlvmLowerBackParseDiagnosticKind.MALFORMED_DEFINE,
            line_no,
            "define block is not closed by '}'",
            define_line,
        )
    body_lines = body_lines[:-1]
    blocks = _parse_blocks(function_name, body_lines, diagnostics)
    if diagnostics:
        return LlvmLowerBackParseResult(
            status=LlvmLowerBackParseStatus.FAILED,
            diagnostics=tuple(diagnostics),
        )
    return LlvmLowerBackParseResult(
        status=LlvmLowerBackParseStatus.PARSED,
        function=LlvmLowerBackFunction(
            name=function_name,
            entry=blocks[0].label,
            blocks=tuple(blocks),
        ),
    )


def assess_lower_back_readiness(ir_text: str) -> LlvmLowerBackReadinessResult:
    """Parse optimized LLVM and classify M3 lower-back readiness."""
    parse_result = parse_lower_back_function(ir_text)
    if not parse_result.parsed or parse_result.function is None:
        return LlvmLowerBackReadinessResult(
            status=LlvmLowerBackReadinessStatus.PARSE_FAILED,
            parse_result=parse_result,
        )
    plan_result = plan_lower_back(parse_result.function)
    status = (
        LlvmLowerBackReadinessStatus.PLANNED
        if plan_result.status is LlvmLowerBackStatus.PLANNED
        else LlvmLowerBackReadinessStatus.UNSUPPORTED
    )
    return LlvmLowerBackReadinessResult(
        status=status,
        parse_result=parse_result,
        plan_result=plan_result,
    )


def _semantic_lines(ir_text: str) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    for line_no, raw_line in enumerate(ir_text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        if stripped.startswith(";"):
            continue
        if stripped.startswith(("source_filename", "target ")):
            continue
        lines.append((line_no, stripped))
    return lines


def _parse_blocks(
    function_name: str,
    body_lines: list[tuple[int, str]],
    diagnostics: list[LlvmLowerBackParseDiagnostic],
) -> list[LlvmLowerBackBlock]:
    grouped: list[tuple[str, list[tuple[int, str]]]] = []
    current_label: str | None = None
    current_lines: list[tuple[int, str]] = []
    for line_no, line in body_lines:
        label = _LABEL_RE.match(line)
        if label is not None:
            if current_label is not None:
                grouped.append((current_label, current_lines))
            current_label = label.group("label")
            current_lines = []
            continue
        if current_label is None:
            current_label = "entry"
        current_lines.append((line_no, line))
    if current_label is not None:
        grouped.append((current_label, current_lines))
    if not grouped:
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.FUNCTION_UNSUPPORTED,
                line_number=0,
                reason=f"function {function_name!r} has no blocks",
            )
        )
        return []

    raw_blocks: list[
        tuple[
            str,
            tuple[LlvmLowerBackInstruction, ...],
            tuple[LlvmPhiNode, ...],
            LlvmLowerBackTerminator,
        ]
    ] = []
    incoming: dict[str, list[str]] = {label: [] for label, _lines in grouped}
    for label, lines in grouped:
        instructions: list[LlvmLowerBackInstruction] = []
        phis: list[LlvmPhiNode] = []
        terminator: LlvmLowerBackTerminator | None = None
        for line_no, line in lines:
            if terminator is not None:
                kind = (
                    LlvmLowerBackParseDiagnosticKind.MULTIPLE_TERMINATORS
                    if _is_terminator(line)
                    else LlvmLowerBackParseDiagnosticKind.INSTRUCTION_AFTER_TERMINATOR
                )
                diagnostics.append(
                    LlvmLowerBackParseDiagnostic(
                        kind=kind,
                        line_number=line_no,
                        reason=f"block {label!r} has text after its terminator",
                        text=line,
                    )
                )
                continue
            if _is_terminator(line):
                terminator = _parse_terminator(line, line_no, diagnostics)
                continue
            phi = _parse_phi(line, line_no, diagnostics)
            if phi is not None:
                phis.append(phi)
                continue
            instruction = _parse_instruction(line, line_no, diagnostics)
            if instruction is not None:
                instructions.append(instruction)
        if terminator is None:
            diagnostics.append(
                LlvmLowerBackParseDiagnostic(
                    kind=LlvmLowerBackParseDiagnosticKind.MISSING_TERMINATOR,
                    line_number=lines[-1][0] if lines else 0,
                    reason=f"block {label!r} has no terminator",
                    text=label,
                )
            )
            terminator = LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.RETURN)
        raw_blocks.append((label, tuple(instructions), tuple(phis), terminator))
        for target in terminator.targets:
            incoming.setdefault(target, []).append(label)

    return [
        LlvmLowerBackBlock(
            label=label,
            predecessors=tuple(incoming.get(label, ())),
            instructions=instructions,
            phis=phis,
            terminator=terminator,
        )
        for label, instructions, phis, terminator in raw_blocks
    ]


def _is_terminator(line: str) -> bool:
    return line.startswith(
        (
            "br ",
            "indirectbr ",
            "invoke ",
            "landingpad",
            "ret",
            "switch ",
            "unreachable",
        )
    )


def _parse_terminator(
    line: str,
    line_no: int,
    diagnostics: list[LlvmLowerBackParseDiagnostic],
) -> LlvmLowerBackTerminator | None:
    if line == "ret void":
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.RETURN)
    if line.startswith("ret "):
        if _RET_RE.match(line) is not None:
            return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.RETURN)
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.MALFORMED_RETURN,
                line_number=line_no,
                reason="return must be void or a scalar integer value",
                text=line,
            )
        )
        return None
    if line == "ret":
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.MALFORMED_RETURN,
                line_number=line_no,
                reason="return must be void or a scalar integer value",
                text=line,
            )
        )
        return None
    branch = _BR_RE.match(line)
    if branch is not None:
        return LlvmLowerBackTerminator(
            LlvmLowerBackTerminatorKind.BRANCH,
            targets=(branch.group("target"),),
        )
    cond = _COND_BR_RE.match(line)
    if cond is not None:
        return LlvmLowerBackTerminator(
            LlvmLowerBackTerminatorKind.COND_BRANCH,
            targets=(cond.group("true"), cond.group("false")),
        )
    if line.startswith("switch "):
        targets = tuple(dict.fromkeys(re.findall(r"label\s+%([A-Za-z0-9$._-]+)", line)))
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.SWITCH, targets=targets)
    if line.startswith("indirectbr "):
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.INDIRECTBR)
    if line.startswith("invoke "):
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.INVOKE)
    if line.startswith("landingpad"):
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.LANDINGPAD)
    if line == "unreachable":
        return LlvmLowerBackTerminator(LlvmLowerBackTerminatorKind.UNREACHABLE)
    diagnostics.append(
        LlvmLowerBackParseDiagnostic(
            kind=LlvmLowerBackParseDiagnosticKind.UNKNOWN_TERMINATOR,
            line_number=line_no,
            reason="unsupported terminator syntax",
            text=line,
        )
    )
    return None


def _parse_phi(
    line: str,
    line_no: int,
    diagnostics: list[LlvmLowerBackParseDiagnostic],
) -> LlvmPhiNode | None:
    match = _PHI_RE.match(line)
    if match is None:
        return None
    type_name = match.group("type")
    incoming = _parse_phi_incoming_list(match.group("body"), type_name)
    if incoming is None or not incoming:
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.MALFORMED_PHI,
                line_number=line_no,
                reason="PHI incoming list is malformed",
                text=line,
            )
        )
        return None
    return LlvmPhiNode(
        result=LlvmValueRef(name=_value_name(match.group("result")), type=type_name),
        incoming=incoming,
    )


def _parse_phi_incoming_list(
    body: str,
    type_name: str,
) -> tuple[LlvmPhiIncoming, ...] | None:
    incoming: list[LlvmPhiIncoming] = []
    pos = 0
    while pos < len(body):
        while pos < len(body) and body[pos].isspace():
            pos += 1
        item = _PHI_INCOMING_RE.match(body, pos)
        if item is None:
            return None
        incoming.append(
            LlvmPhiIncoming(
                predecessor=item.group("pred"),
                value=LlvmValueRef(name=_value_name(item.group("value")), type=type_name),
            )
        )
        pos = item.end()
        while pos < len(body) and body[pos].isspace():
            pos += 1
        if pos == len(body):
            return tuple(incoming)
        if body[pos] != ",":
            return None
        pos += 1
    return tuple(incoming)


def _parse_instruction(
    line: str,
    line_no: int,
    diagnostics: list[LlvmLowerBackParseDiagnostic],
) -> LlvmLowerBackInstruction | None:
    if line.startswith("store "):
        return LlvmLowerBackInstruction(opcode="store")
    if line.startswith("call "):
        return LlvmLowerBackInstruction(opcode="call")
    match = _ASSIGN_RE.match(line)
    if match is None:
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.MALFORMED_INSTRUCTION,
                line_number=line_no,
                reason="unsupported instruction syntax",
                text=line,
            )
        )
        return None
    result_name = _value_name(match.group("result"))
    opcode = match.group("opcode")
    rest = match.group("rest").strip()
    result_type = _result_type_for_instruction(opcode, rest)
    operands = tuple(_operands_for_instruction(opcode, rest))
    instruction = LlvmLowerBackInstruction(
        opcode=opcode,
        result=LlvmValueRef(name=result_name, type=result_type),
        operands=operands,
    )
    if opcode in _SUPPORTED_SCALAR_OPCODES and not _has_supported_instruction_shape(
        instruction
    ):
        diagnostics.append(
            LlvmLowerBackParseDiagnostic(
                kind=LlvmLowerBackParseDiagnosticKind.MALFORMED_INSTRUCTION,
                line_number=line_no,
                reason=f"malformed {opcode!r} instruction for M3c readiness subset",
                text=line,
            )
        )
        return None
    return instruction


def _result_type_for_instruction(opcode: str, rest: str) -> str:
    if opcode == "icmp":
        return "i1"
    if opcode == "zext" and " to " in rest:
        return rest.rsplit(" to ", 1)[1].split()[0]
    type_match = _TYPE_RE.search(rest)
    if type_match is not None:
        return type_match.group("type")
    return "unknown"


def _operands_for_instruction(opcode: str, rest: str) -> tuple[LlvmValueRef, ...]:
    if opcode == "icmp":
        parts = rest.split(None, 2)
        if len(parts) < 3:
            return ()
        type_name = parts[1]
        return tuple(
            LlvmValueRef(name=_value_name(item.group("value")), type=type_name)
            for item in _VALUE_RE.finditer(parts[2])
        )
    if opcode == "zext" and " to " in rest:
        before_to = rest.split(" to ", 1)[0]
        type_match = _TYPE_RE.search(before_to)
        type_name = type_match.group("type") if type_match is not None else "unknown"
        return tuple(
            LlvmValueRef(name=_value_name(item.group("value")), type=type_name)
            for item in _VALUE_RE.finditer(before_to)
        )
    type_match = _TYPE_RE.search(rest)
    type_name = type_match.group("type") if type_match is not None else "unknown"
    if type_match is None:
        return ()
    return tuple(
        LlvmValueRef(name=_value_name(item.group("value")), type=type_name)
        for item in _VALUE_RE.finditer(rest[type_match.end() :])
    )


def _value_name(value: str) -> str:
    return value[1:] if value.startswith("%") else value


def _has_supported_instruction_shape(instruction: LlvmLowerBackInstruction) -> bool:
    result = instruction.result
    if result is None:
        return False
    operands = instruction.operands
    opcode = instruction.opcode
    if opcode in _BINARY_SCALAR_OPCODES:
        if len(operands) != 2:
            return False
        return (
            _is_supported_scalar(result.type)
            and operands[0].type == result.type
            and operands[1].type == result.type
        )
    if opcode == "icmp":
        if result.type != "i1" or len(operands) != 2:
            return False
        return (
            _is_supported_scalar(operands[0].type)
            and operands[0].type == operands[1].type
        )
    if opcode == "zext":
        if len(operands) != 1:
            return False
        input_width = _scalar_width(operands[0].type)
        result_width = _scalar_width(result.type)
        return input_width is not None and result_width is not None and result_width > input_width
    return False


def _is_supported_scalar(type_name: str) -> bool:
    return bool(re.fullmatch(r"i(?:1|8|16|32|64)", type_name.strip()))


def _scalar_width(type_name: str) -> int | None:
    if not _is_supported_scalar(type_name):
        return None
    return int(type_name.strip()[1:])


def _parse_failure(
    diagnostics: list[LlvmLowerBackParseDiagnostic],
    kind: LlvmLowerBackParseDiagnosticKind,
    line_number: int,
    reason: str,
    text: str,
) -> LlvmLowerBackParseResult:
    diagnostics.append(
        LlvmLowerBackParseDiagnostic(
            kind=kind,
            line_number=line_number,
            reason=reason,
            text=text,
        )
    )
    return LlvmLowerBackParseResult(
        status=LlvmLowerBackParseStatus.FAILED,
        diagnostics=tuple(diagnostics),
    )
