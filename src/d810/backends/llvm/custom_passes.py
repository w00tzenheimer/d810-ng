"""IDA-free d810 MBA/Z3 custom pass socket for LLVM text.

This module is deliberately narrow: it does not parse arbitrary LLVM IR and it
does not implement a compiled LLVM plugin.  It provides the first M2b socket for
running d810-verified MBA rewrites around the stock ``opt`` runner.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from enum import Enum

from d810.backends.mba.z3 import prove_equivalence
from d810.mba.dsl import Var


class LlvmCustomPassStatus(str, Enum):
    PASSED = "passed"
    NO_CHANGE = "no_change"
    FAILED = "failed"
    SKIPPED = "skipped"


class LlvmCustomPassDiagnosticKind(str, Enum):
    UNSUPPORTED_SHAPE = "unsupported_shape"
    UNSUPPORTED_TYPE = "unsupported_type"
    WIDTH_MISMATCH = "width_mismatch"
    PROOF_UNAVAILABLE = "proof_unavailable"
    PROOF_FAILED = "proof_failed"


@dataclass(frozen=True, slots=True)
class LlvmCustomPass:
    pass_id: str
    name: str


@dataclass(frozen=True, slots=True)
class LlvmCustomPassDiagnostic:
    pass_id: str
    kind: LlvmCustomPassDiagnosticKind
    reason: str
    line_number: int | None = None


@dataclass(frozen=True, slots=True)
class LlvmCustomRewriteProof:
    rule_name: str
    engine: str
    bit_width: int
    verified: bool


@dataclass(frozen=True, slots=True)
class LlvmCustomProofResult:
    verified: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class LlvmCustomRewrite:
    pass_id: str
    rule_name: str
    result_name: str
    original_line: str
    rewritten_line: str
    removed_lines: tuple[str, ...]
    proof: LlvmCustomRewriteProof


@dataclass(frozen=True, slots=True)
class LlvmCustomPassResult:
    pass_id: str
    status: LlvmCustomPassStatus
    before_ir: str
    after_ir: str
    rewrites: tuple[LlvmCustomRewrite, ...]
    diagnostics: tuple[LlvmCustomPassDiagnostic, ...]

    @property
    def changed(self) -> bool:
        return bool(self.rewrites)

    @property
    def passed(self) -> bool:
        return self.status is LlvmCustomPassStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status is LlvmCustomPassStatus.FAILED


@dataclass(frozen=True, slots=True)
class LlvmCustomPassRunResult:
    status: LlvmCustomPassStatus
    before_ir: str
    after_ir: str
    pass_results: tuple[LlvmCustomPassResult, ...]

    @property
    def changed(self) -> bool:
        return any(result.changed for result in self.pass_results)

    @property
    def failed(self) -> bool:
        return self.status is LlvmCustomPassStatus.FAILED


D810_MBA_XOR_OR_SUB_AND_PASS = LlvmCustomPass(
    pass_id="d810_mba_xor_or_sub_and",
    name="d810 MBA/Z3 XOR from OR-sub-AND",
)

_SUPPORTED_WIDTHS = frozenset({8, 16, 32, 64})
_SSA_NAME = r"%[A-Za-z$._-][A-Za-z0-9$._-]*"
_RAW_ASSIGN_RE = re.compile(
    rf"^(?P<prefix>\s*)(?P<result>{_SSA_NAME})\s*=\s*"
    rf"(?P<op>or|and|sub)\s+(?P<body>.+?)(?P<tail>\s*(?:;.*)?)$"
)
_SCALAR_BINARY_RE = re.compile(
    rf"^(?P<ty>i(?P<bits>\d+))\s+"
    rf"(?P<lhs>{_SSA_NAME}),\s*(?P<rhs>{_SSA_NAME})$"
)
_TOKEN_RE_TEMPLATE = r"(?<![A-Za-z0-9$._-]){}(?![A-Za-z0-9$._-])"


@dataclass(frozen=True, slots=True)
class _RawInstruction:
    line_index: int
    line: str
    prefix: str
    result: str
    op: str
    body: str
    tail: str


@dataclass(frozen=True, slots=True)
class _ParsedInstruction:
    raw: _RawInstruction
    ty: str
    bits: int
    lhs: str
    rhs: str


ProofChecker = Callable[[int], LlvmCustomProofResult]


def run_d810_custom_passes(
    ir_text: str,
    *,
    passes: Iterable[LlvmCustomPass] = (D810_MBA_XOR_OR_SUB_AND_PASS,),
    proof_checker: ProofChecker | None = None,
) -> LlvmCustomPassRunResult:
    """Run opt-in d810 custom passes over LLVM text.

    The API returns structured results and never throws for unsupported IR
    shapes.  The default pass set contains only the M2b XOR MBA rewrite socket.
    """
    current = ir_text
    pass_results: list[LlvmCustomPassResult] = []
    status = LlvmCustomPassStatus.NO_CHANGE
    for custom_pass in passes:
        if custom_pass.pass_id != D810_MBA_XOR_OR_SUB_AND_PASS.pass_id:
            result = LlvmCustomPassResult(
                pass_id=custom_pass.pass_id,
                status=LlvmCustomPassStatus.SKIPPED,
                before_ir=current,
                after_ir=current,
                rewrites=(),
                diagnostics=(
                    LlvmCustomPassDiagnostic(
                        pass_id=custom_pass.pass_id,
                        kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_SHAPE,
                        reason=f"unsupported custom pass id: {custom_pass.pass_id}",
                    ),
                ),
            )
        else:
            result = _run_xor_or_sub_and_pass(current, proof_checker=proof_checker)
        pass_results.append(result)
        if result.failed:
            status = LlvmCustomPassStatus.FAILED
            break
        current = result.after_ir
        if result.changed:
            status = LlvmCustomPassStatus.PASSED

    return LlvmCustomPassRunResult(
        status=status,
        before_ir=ir_text,
        after_ir=current,
        pass_results=tuple(pass_results),
    )


def _run_xor_or_sub_and_pass(
    ir_text: str,
    *,
    proof_checker: ProofChecker | None,
) -> LlvmCustomPassResult:
    pass_id = D810_MBA_XOR_OR_SUB_AND_PASS.pass_id
    lines = ir_text.splitlines()
    scopes = _function_scopes(lines)
    line_scopes = {line_index: scope for scope in scopes for line_index in scope}
    diagnostics: list[LlvmCustomPassDiagnostic] = []
    candidates: list[tuple[_ParsedInstruction, _ParsedInstruction, _ParsedInstruction]] = []
    for scope in scopes:
        scope_candidates, scope_diagnostics = _find_xor_or_sub_and_candidates(
            lines,
            scope,
            pass_id=pass_id,
        )
        candidates.extend(scope_candidates)
        diagnostics.extend(scope_diagnostics)

    if diagnostics:
        return LlvmCustomPassResult(
            pass_id=pass_id,
            status=LlvmCustomPassStatus.FAILED,
            before_ir=ir_text,
            after_ir=ir_text,
            rewrites=(),
            diagnostics=tuple(diagnostics),
        )
    if not candidates:
        return LlvmCustomPassResult(
            pass_id=pass_id,
            status=LlvmCustomPassStatus.NO_CHANGE,
            before_ir=ir_text,
            after_ir=ir_text,
            rewrites=(),
            diagnostics=(),
        )

    proof_cache: dict[int, LlvmCustomProofResult] = {}
    rewritten_lines = list(lines)
    removed_indexes: set[int] = set()
    rewrites: list[LlvmCustomRewrite] = []
    for sub, or_insn, and_insn in candidates:
        proof = proof_cache.get(sub.bits)
        if proof is None:
            checker = proof_checker or _prove_xor_or_sub_and
            proof = checker(sub.bits)
            proof_cache[sub.bits] = proof
        if not proof.verified:
            return _failed_result(
                pass_id,
                ir_text,
                LlvmCustomPassDiagnostic(
                    pass_id=pass_id,
                    kind=(
                        LlvmCustomPassDiagnosticKind.PROOF_FAILED
                        if proof.reason
                        else LlvmCustomPassDiagnosticKind.PROOF_UNAVAILABLE
                    ),
                    reason=proof.reason or "MBA/Z3 proof unavailable",
                    line_number=sub.raw.line_index + 1,
                ),
            )

        replacement = (
            f"{sub.raw.prefix}{sub.raw.result} = xor "
            f"{sub.ty} {or_insn.lhs}, {or_insn.rhs}{sub.raw.tail}"
        )
        rewritten_lines[sub.raw.line_index] = replacement
        removed: list[str] = []
        for producer in (or_insn, and_insn):
            scope = line_scopes.get(producer.raw.line_index, range(0, len(lines)))
            if _use_count(lines, producer.raw.result, scope) == 1:
                removed_indexes.add(producer.raw.line_index)
                removed.append(producer.raw.line)
        rewrites.append(
            LlvmCustomRewrite(
                pass_id=pass_id,
                rule_name="Xor_HackersDelightRule_1",
                result_name=sub.raw.result,
                original_line=sub.raw.line,
                rewritten_line=replacement,
                removed_lines=tuple(removed),
                proof=LlvmCustomRewriteProof(
                    rule_name="Xor_HackersDelightRule_1",
                    engine="d810.backends.mba.z3",
                    bit_width=sub.bits,
                    verified=True,
                ),
            )
        )

    after = "\n".join(
        line for index, line in enumerate(rewritten_lines) if index not in removed_indexes
    )
    if ir_text.endswith("\n"):
        after += "\n"
    return LlvmCustomPassResult(
        pass_id=pass_id,
        status=LlvmCustomPassStatus.PASSED,
        before_ir=ir_text,
        after_ir=after,
        rewrites=tuple(rewrites),
        diagnostics=(),
    )


def _find_xor_or_sub_and_candidates(
    lines: list[str],
    scope: range,
    *,
    pass_id: str,
) -> tuple[
    list[tuple[_ParsedInstruction, _ParsedInstruction, _ParsedInstruction]],
    list[LlvmCustomPassDiagnostic],
]:
    raw_defs: dict[str, _RawInstruction] = {}
    parsed_defs: dict[str, _ParsedInstruction] = {}
    invalid_defs: dict[str, LlvmCustomPassDiagnostic] = {}
    diagnostics: list[LlvmCustomPassDiagnostic] = []
    candidates: list[tuple[_ParsedInstruction, _ParsedInstruction, _ParsedInstruction]] = []

    for index in scope:
        raw = _parse_raw_instruction(index, lines[index])
        if raw is None:
            continue
        if raw.result in raw_defs:
            diagnostics.append(
                LlvmCustomPassDiagnostic(
                    pass_id=pass_id,
                    kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_SHAPE,
                    reason=f"duplicate SSA definition for {raw.result}",
                    line_number=index + 1,
                )
            )
            continue
        raw_defs[raw.result] = raw
        parsed, diagnostic = _parse_scalar_binary(raw, pass_id=pass_id)
        if parsed is not None:
            parsed_defs[raw.result] = parsed
        elif diagnostic is not None:
            invalid_defs[raw.result] = diagnostic

    for parsed in parsed_defs.values():
        if parsed.raw.op != "sub":
            continue
        if parsed.lhs not in raw_defs or parsed.rhs not in raw_defs:
            continue
        if parsed.lhs in invalid_defs or parsed.rhs in invalid_defs:
            for name in (parsed.lhs, parsed.rhs):
                if name in invalid_defs:
                    diagnostics.append(invalid_defs[name])
            continue
        lhs = parsed_defs[parsed.lhs]
        rhs = parsed_defs[parsed.rhs]
        if not _looks_like_xor_or_sub_and_producers(lhs, rhs):
            continue
        if lhs.raw.op != "or" or rhs.raw.op != "and":
            diagnostics.append(
                LlvmCustomPassDiagnostic(
                    pass_id=pass_id,
                    kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_SHAPE,
                    reason="MBA XOR candidate must be (or lhs,rhs) - (and lhs,rhs)",
                    line_number=parsed.raw.line_index + 1,
                )
            )
            continue
        if len({parsed.ty, lhs.ty, rhs.ty}) != 1:
            diagnostics.append(
                LlvmCustomPassDiagnostic(
                    pass_id=pass_id,
                    kind=LlvmCustomPassDiagnosticKind.WIDTH_MISMATCH,
                    reason="MBA XOR candidate producer/result widths must match",
                    line_number=parsed.raw.line_index + 1,
                )
            )
            continue
        if (lhs.lhs, lhs.rhs) != (rhs.lhs, rhs.rhs):
            diagnostics.append(
                LlvmCustomPassDiagnostic(
                    pass_id=pass_id,
                    kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_SHAPE,
                    reason="MBA XOR candidate OR/AND operands must match in order",
                    line_number=parsed.raw.line_index + 1,
                )
            )
            continue
        candidates.append((parsed, lhs, rhs))

    for raw in raw_defs.values():
        if raw.op != "sub" or raw.result not in invalid_defs:
            continue
        operands = _extract_ssa_operands(raw.body)
        if len(operands) != 2 or operands[0] not in raw_defs or operands[1] not in raw_defs:
            continue
        lhs_raw = raw_defs[operands[0]]
        rhs_raw = raw_defs[operands[1]]
        if _looks_like_xor_or_sub_and_raw_producers(lhs_raw, rhs_raw):
            diagnostics.append(invalid_defs[raw.result])

    return candidates, diagnostics


def _looks_like_xor_or_sub_and_producers(
    lhs: _ParsedInstruction,
    rhs: _ParsedInstruction,
) -> bool:
    return {lhs.raw.op, rhs.raw.op} == {"or", "and"}


def _looks_like_xor_or_sub_and_raw_producers(
    lhs: _RawInstruction,
    rhs: _RawInstruction,
) -> bool:
    return {lhs.op, rhs.op} == {"or", "and"}


def _function_scopes(lines: list[str]) -> tuple[range, ...]:
    scopes: list[range] = []
    start: int | None = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if start is None and stripped.startswith("define ") and stripped.endswith("{"):
            start = index + 1
            continue
        if start is not None and stripped == "}":
            scopes.append(range(start, index))
            start = None
    if scopes:
        return tuple(scopes)
    return (range(0, len(lines)),)


def _parse_raw_instruction(line_index: int, line: str) -> _RawInstruction | None:
    match = _RAW_ASSIGN_RE.match(line)
    if match is None:
        return None
    return _RawInstruction(
        line_index=line_index,
        line=line,
        prefix=match.group("prefix"),
        result=match.group("result"),
        op=match.group("op"),
        body=match.group("body").strip(),
        tail=match.group("tail"),
    )


def _parse_scalar_binary(
    raw: _RawInstruction,
    *,
    pass_id: str,
) -> tuple[_ParsedInstruction | None, LlvmCustomPassDiagnostic | None]:
    match = _SCALAR_BINARY_RE.match(raw.body)
    if match is None:
        return None, LlvmCustomPassDiagnostic(
            pass_id=pass_id,
            kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE,
            reason=f"unsupported or non-SSA LLVM {raw.op} shape",
            line_number=raw.line_index + 1,
        )
    bits = int(match.group("bits"))
    if bits not in _SUPPORTED_WIDTHS:
        return None, LlvmCustomPassDiagnostic(
            pass_id=pass_id,
            kind=LlvmCustomPassDiagnosticKind.UNSUPPORTED_TYPE,
            reason=f"unsupported scalar integer width i{bits}",
            line_number=raw.line_index + 1,
        )
    return _ParsedInstruction(
        raw=raw,
        ty=match.group("ty"),
        bits=bits,
        lhs=match.group("lhs"),
        rhs=match.group("rhs"),
    ), None


def _failed_result(
    pass_id: str,
    ir_text: str,
    diagnostic: LlvmCustomPassDiagnostic,
) -> LlvmCustomPassResult:
    return LlvmCustomPassResult(
        pass_id=pass_id,
        status=LlvmCustomPassStatus.FAILED,
        before_ir=ir_text,
        after_ir=ir_text,
        rewrites=(),
        diagnostics=(diagnostic,),
    )


def _prove_xor_or_sub_and(bit_width: int) -> LlvmCustomProofResult:
    x, y = Var("x"), Var("y")
    try:
        verified, counterexample = prove_equivalence(
            (x | y) - (x & y),
            x ^ y,
            bit_width=bit_width,
        )
    except Exception as exc:  # pragma: no cover - exercised via injected checker.
        return LlvmCustomProofResult(
            verified=False,
            reason=f"MBA/Z3 proof unavailable: {exc}",
        )
    if not verified:
        return LlvmCustomProofResult(
            verified=False,
            reason=f"MBA/Z3 proof failed; counterexample={counterexample}",
        )
    return LlvmCustomProofResult(verified=True)


def _use_count(lines: list[str], token: str, scope: range) -> int:
    pattern = re.compile(_TOKEN_RE_TEMPLATE.format(re.escape(token)))
    count = 0
    for index in scope:
        line = lines[index]
        raw = _parse_raw_instruction(-1, line)
        if raw is not None and raw.result == token:
            line = line.replace(token, "", 1)
        count += len(pattern.findall(line))
    return count


def _extract_ssa_operands(text: str) -> tuple[str, ...]:
    return tuple(re.findall(_SSA_NAME, text))
