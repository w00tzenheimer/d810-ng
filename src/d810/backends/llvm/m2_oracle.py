"""IDA-free M2 oracle/drift DTOs and fixture-level checks."""
from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum

from .optimization import normalize_llvm_ir


class LlvmM2OracleStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class LlvmM2DriftCheckResult:
    status: LlvmM2OracleStatus
    oracle_id: str
    subject: str
    reason: str = ""
    expected_signature: tuple[str, ...] = ()
    actual_signature: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return self.status is LlvmM2OracleStatus.PASSED

    @property
    def failed(self) -> bool:
        return self.status is LlvmM2OracleStatus.FAILED

    @property
    def unavailable(self) -> bool:
        return self.status is LlvmM2OracleStatus.UNAVAILABLE

    @property
    def not_applicable(self) -> bool:
        return self.status is LlvmM2OracleStatus.NOT_APPLICABLE


_ALIGN_RE = re.compile(r",\s*align\s+\d+\b")


def llvm_m2_fixture_signature(ir_text: str) -> tuple[str, ...]:
    """Return a narrow optimized-function signature for checked-in M0 fixtures."""
    signature: list[str] = []
    in_function = False
    for raw_line in normalize_llvm_ir(ir_text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("define "):
            in_function = True
            continue
        if not in_function:
            continue
        if line == "}":
            break
        signature.append(_canonical_fixture_line(line))
    return tuple(signature)


def check_m2_fixture_oracle(
    *,
    subject: str,
    actual_ir: str,
    expected_ir: str,
    oracle_id: str,
) -> LlvmM2DriftCheckResult:
    """Compare optimized LLVM IR against a checked-in fixture signature.

    This is an M2 optimized-IR artifact check, not a Hex-Rays pseudocode or
    native execution oracle.
    """
    if not expected_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected optimized LLVM fixture unavailable",
        )
    if not actual_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="actual optimized LLVM IR unavailable",
        )

    expected_shape_error = _single_function_shape_error(
        expected_ir,
        description="expected optimized LLVM fixture",
    )
    if expected_shape_error:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason=expected_shape_error,
        )
    actual_shape_error = _single_function_shape_error(
        actual_ir,
        description="actual optimized LLVM IR",
    )
    if actual_shape_error:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason=actual_shape_error,
        )

    expected_signature = llvm_m2_fixture_signature(expected_ir)
    actual_signature = llvm_m2_fixture_signature(actual_ir)
    if not expected_signature:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected optimized LLVM fixture has no supported function body",
        )
    if not actual_signature:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason="actual optimized LLVM IR has no supported function body",
            expected_signature=expected_signature,
            actual_signature=actual_signature,
        )
    if actual_signature != expected_signature:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason="optimized LLVM fixture signature mismatch",
            expected_signature=expected_signature,
            actual_signature=actual_signature,
        )
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.PASSED,
        oracle_id=oracle_id,
        subject=subject,
        expected_signature=expected_signature,
        actual_signature=actual_signature,
    )


def llvm_m2_post_d810_branchless_signature(ir_text: str) -> tuple[str, ...]:
    """Return a semantic signature for the post-D810 branchless oracle target."""
    lines = _function_body_lines(ir_text)
    blocks = _function_blocks(lines)
    defs: dict[str, str] = {}
    value_blocks: dict[str, str] = {}
    low_bit_values: set[str] = set()
    base_values: set[str] = set()
    even_values: set[str] = set()
    odd_values: set[str] = set()
    low_bit_conditions: dict[str, str] = {}
    return_phi_values: set[str] = set()
    value_sink_values: set[str] = set()
    state_initial_count = 0
    state_terminal_count = 0
    unexpected_observable_stores: list[str] = []

    for block_label, block_lines in blocks.items():
        for line in block_lines:
            if match := _ASSIGN_RE.match(line):
                value = match.group("dst")
                defs[value] = match.group("expr")
                value_blocks[value] = block_label

    changed = True
    while changed:
        changed = False
        for value, expr in defs.items():
            if value not in base_values and _matches_add_token(expr, "17"):
                base_values.add(value)
                changed = True
            elif value not in low_bit_values and _matches_and_token(expr, "1"):
                low_bit_values.add(value)
                changed = True
            elif value not in even_values and _matches_add_token(expr, "-34"):
                even_values.add(value)
                changed = True
            elif value not in odd_values and _matches_xor_base(
                expr,
                base_values,
                "34",
            ):
                odd_values.add(value)
                changed = True

    for value, expr in defs.items():
        low_bit_predicate = _low_bit_condition_predicate(expr, low_bit_values)
        if low_bit_predicate:
            low_bit_conditions[value] = low_bit_predicate
        elif _matches_phi_with_labels(
            expr,
            odd_values,
            even_values,
            value_blocks,
        ):
            return_phi_values.add(value)

    branch_polarity_features = _branch_polarity_features(
        blocks,
        low_bit_conditions,
        even_labels={value_blocks[value] for value in even_values},
        odd_labels={value_blocks[value] for value in odd_values},
    )
    return_phi_found = any(_matches_return(line, return_phi_values) for line in lines)
    return_constant_zero_found = any(line == "ret i32 0" for line in lines)

    for line in lines:
        store = _STORE_I32_RE.match(line)
        if not store:
            continue
        value = store.group("value")
        target = store.group("target")
        is_volatile = bool(store.group("volatile"))
        if target == "state_sink":
            if not is_volatile:
                unexpected_observable_stores.append(f"state_sink:nonvolatile:{value}")
            elif value == "-966241705":
                state_initial_count += 1
            elif value == "439041101":
                state_terminal_count += 1
            else:
                unexpected_observable_stores.append(f"state_sink:{value}")
        elif target == "value_sink":
            if not is_volatile:
                unexpected_observable_stores.append(f"value_sink:nonvolatile:{value}")
            elif value in base_values or value in odd_values or value in even_values:
                value_sink_values.add(value)
            else:
                unexpected_observable_stores.append(f"value_sink:{value}")

    features: list[str] = []
    if base_values:
        features.append("value:base:add_token_17")
    features.extend(branch_polarity_features)
    if odd_values:
        features.append("value:odd:xor_base_34")
    if even_values:
        features.append("value:even:add_token_-34")
    if base_values & value_sink_values:
        features.append("observable:value_sink:base")
    if odd_values & value_sink_values:
        features.append("observable:value_sink:odd")
    if even_values & value_sink_values:
        features.append("observable:value_sink:even")
    if state_initial_count:
        features.append(f"observable:state_sink:initial_k0:count={state_initial_count}")
    if state_terminal_count:
        features.append(
            f"observable:state_sink:terminal:count={state_terminal_count}"
        )
    if return_phi_found:
        features.append("return:phi:odd_even")
    if return_constant_zero_found:
        features.append("return:constant_zero")
    for store in sorted(unexpected_observable_stores):
        features.append(f"unexpected_observable:{store}")
    return tuple(features)


def check_m2_post_d810_branchless_oracle(
    *,
    subject: str,
    actual_ir: str,
    expected_ir: str,
    oracle_id: str,
) -> LlvmM2DriftCheckResult:
    """Compare post-D810 structured branchless M2 output to its oracle target."""
    if not expected_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected post-D810 structured LLVM fixture unavailable",
        )
    if not actual_ir.strip():
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="actual post-D810 structured LLVM IR unavailable",
        )

    expected_shape_error = _single_function_shape_error(
        expected_ir,
        description="expected post-D810 structured LLVM fixture",
    )
    if expected_shape_error:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason=expected_shape_error,
        )
    actual_shape_error = _single_function_shape_error(
        actual_ir,
        description="actual post-D810 structured LLVM IR",
    )
    if actual_shape_error:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason=actual_shape_error,
        )

    expected_signature = llvm_m2_post_d810_branchless_signature(expected_ir)
    actual_signature = llvm_m2_post_d810_branchless_signature(actual_ir)
    if not expected_signature:
        return m2_oracle_unavailable(
            subject=subject,
            oracle_id=oracle_id,
            reason="expected post-D810 structured LLVM fixture has no supported signature",
        )
    if actual_signature != expected_signature:
        return LlvmM2DriftCheckResult(
            status=LlvmM2OracleStatus.FAILED,
            oracle_id=oracle_id,
            subject=subject,
            reason="post-D810 structured LLVM signature mismatch",
            expected_signature=expected_signature,
            actual_signature=actual_signature,
        )
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.PASSED,
        oracle_id=oracle_id,
        subject=subject,
        expected_signature=expected_signature,
        actual_signature=actual_signature,
    )


def m2_oracle_not_applicable(
    *,
    subject: str,
    reason: str,
    oracle_id: str = "",
) -> LlvmM2DriftCheckResult:
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.NOT_APPLICABLE,
        oracle_id=oracle_id,
        subject=subject,
        reason=reason,
    )


def m2_oracle_unavailable(
    *,
    subject: str,
    reason: str,
    oracle_id: str,
) -> LlvmM2DriftCheckResult:
    return LlvmM2DriftCheckResult(
        status=LlvmM2OracleStatus.UNAVAILABLE,
        oracle_id=oracle_id,
        subject=subject,
        reason=reason,
    )


def _canonical_fixture_line(line: str) -> str:
    return " ".join(_ALIGN_RE.sub("", line).split())


def _function_body_lines(ir_text: str) -> tuple[str, ...]:
    signature: list[str] = []
    in_function = False
    for raw_line in normalize_llvm_ir(ir_text).splitlines():
        line = raw_line.strip()
        if not line or line.startswith(";"):
            continue
        if line.startswith("define "):
            in_function = True
            continue
        if not in_function:
            continue
        if line == "}":
            break
        signature.append(_canonical_fixture_line(line))
    return tuple(signature)


def _function_blocks(lines: tuple[str, ...]) -> dict[str, tuple[str, ...]]:
    blocks: dict[str, list[str]] = {}
    current_label = ""
    for line in lines:
        label_match = _LABEL_RE.match(line)
        if label_match:
            current_label = label_match.group("label")
            blocks.setdefault(current_label, [])
            continue
        if not current_label:
            continue
        blocks.setdefault(current_label, []).append(line)
    return {label: tuple(block_lines) for label, block_lines in blocks.items()}


def _single_function_shape_error(ir_text: str, *, description: str) -> str:
    function_count = sum(
        1
        for raw_line in normalize_llvm_ir(ir_text).splitlines()
        if raw_line.strip().startswith("define ")
    )
    if function_count > 1:
        return (
            f"{description} must contain exactly one function definition; "
            f"found {function_count}"
        )
    return ""


_ASSIGN_RE = re.compile(r"^(?P<dst>%[-.\w]+) = (?P<expr>.+)$")
_LABEL_RE = re.compile(r"^(?P<label>[-.\w]+):(?:\s*;.*)?$")
_STORE_I32_RE = re.compile(
    r"^store(?P<volatile> volatile)? i32 (?P<value>%[-.\w]+|-?\d+), "
    r"ptr @(?P<target>[-.\w]+)$"
)


def _is_token_ref(value: str) -> bool:
    return value in {"%token", "%arg_token"}


def _matches_add_token(expr: str, amount: str) -> bool:
    match = re.match(r"^add(?: \w+)* i32 (?P<lhs>%[-.\w]+), (?P<rhs>-?\d+)$", expr)
    return bool(
        match
        and _is_token_ref(match.group("lhs"))
        and match.group("rhs") == amount
    )


def _matches_and_token(expr: str, amount: str) -> bool:
    match = re.match(r"^and i32 (?P<lhs>%[-.\w]+), (?P<rhs>-?\d+)$", expr)
    return bool(
        match
        and _is_token_ref(match.group("lhs"))
        and match.group("rhs") == amount
    )


def _matches_xor_base(expr: str, base_values: set[str], amount: str) -> bool:
    match = re.match(r"^xor i32 (?P<lhs>%[-.\w]+), (?P<rhs>-?\d+)$", expr)
    return bool(match and match.group("lhs") in base_values and match.group("rhs") == amount)


def _low_bit_condition_predicate(expr: str, low_bit_values: set[str]) -> str:
    match = re.match(
        r"^icmp (?P<pred>eq|ne) i32 (?P<lhs>%[-.\w]+), 0$",
        expr,
    )
    if match and match.group("lhs") in low_bit_values:
        return match.group("pred")
    return ""


def _branch_polarity_features(
    blocks: dict[str, tuple[str, ...]],
    low_bit_conditions: dict[str, str],
    *,
    even_labels: set[str],
    odd_labels: set[str],
) -> tuple[str, ...]:
    features: list[str] = []
    for block_lines in blocks.values():
        for line in block_lines:
            branch = _conditional_branch(line, low_bit_conditions)
            if branch is None:
                continue
            predicate, true_label, false_label = branch
            if (
                predicate == "eq"
                and true_label in even_labels
                and false_label in odd_labels
            ):
                features.append("cfg:branch:eq_zero:true_even:false_odd")
            elif (
                predicate == "ne"
                and true_label in odd_labels
                and false_label in even_labels
            ):
                features.append("cfg:branch:ne_zero:true_odd:false_even")
            else:
                features.append(
                    "cfg:branch:polarity_mismatch:"
                    f"{predicate}:true={true_label}:false={false_label}"
                )
    return tuple(features)


def _conditional_branch(
    line: str,
    low_bit_conditions: dict[str, str],
) -> tuple[str, str, str] | None:
    match = re.match(
        r"^br i1 (?P<cond>%[-.\w]+), label %(?P<true>[-.\w]+), "
        r"label %(?P<false>[-.\w]+)$",
        line,
    )
    if match is None:
        return None
    predicate = low_bit_conditions.get(match.group("cond"))
    if not predicate:
        return None
    return predicate, match.group("true"), match.group("false")


def _matches_phi_with_labels(
    expr: str,
    odd_values: set[str],
    even_values: set[str],
    value_blocks: dict[str, str],
) -> bool:
    incoming = tuple(
        (match.group("value"), match.group("label"))
        for match in re.finditer(
            r"\[ (?P<value>%[-.\w]+), %(?P<label>[-.\w]+) \]",
            expr,
        )
    )
    if not expr.startswith("phi i32 ") or len(incoming) != 2:
        return False
    odd_labels = {value_blocks[value] for value in odd_values}
    even_labels = {value_blocks[value] for value in even_values}
    return (
        any(value in odd_values and label in odd_labels for value, label in incoming)
        and any(
            value in even_values and label in even_labels for value, label in incoming
        )
    )


def _matches_return(line: str, return_values: set[str]) -> bool:
    match = re.match(r"^ret i32 (?P<value>%[-.\w]+)$", line)
    return bool(match and match.group("value") in return_values)
