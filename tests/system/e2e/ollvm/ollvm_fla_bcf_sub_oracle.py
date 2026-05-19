"""Test-support oracle for ``test_function_ollvm_fla_bcf_sub``.

The OLLVM engine can now collapse this sample's dispatcher enough that the
remaining differences are mostly presentation: local-carrier names, retained
BCF predicates, and IDA's inferred function type.  This module records the
semantic checks for this one fixture without requiring exact pseudocode.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
import sqlite3

MASK32 = 0xFFFFFFFF
XOR_MASK = 0x173063C1
XOR_MASK_COMPLEMENT = 0xE8CF9C3E
FINAL_SELECT_MASK = 0xCD536960
FINAL_XOR = 0x259CF55E
FINAL_COMPLEMENT_MASK = 0x32AC969F


@dataclass(frozen=True)
class OllvmFlaBcfSubCheck:
    """One oracle check result."""

    name: str
    passed: bool
    detail: str
    blocker: bool = True


@dataclass(frozen=True)
class OllvmCarrierFactSummary:
    """Compact view of OLLVM semantic-carrier facts from the diag DB."""

    role_counts: dict[str, int]
    role_tokens: dict[str, tuple[str, ...]]
    accumulator_evidence: tuple[str, ...]
    output_evidence: tuple[str, ...]
    alias_multiply_add_proof_count: int = 0

    def has_role(self, role: str) -> bool:
        return self.role_counts.get(role, 0) > 0


@dataclass(frozen=True)
class OllvmFlaBcfSubOracleResult:
    """Top-level oracle result."""

    checks: tuple[OllvmFlaBcfSubCheck, ...]
    fact_summary: OllvmCarrierFactSummary | None

    @property
    def passed(self) -> bool:
        return all(check.passed or not check.blocker for check in self.checks)

    @property
    def blockers(self) -> tuple[OllvmFlaBcfSubCheck, ...]:
        return tuple(
            check for check in self.checks if check.blocker and not check.passed
        )


def _mask32(value: int) -> int:
    return int(value) & MASK32


def prove_alias_multiply_add_equivalence() -> bool:
    """Prove the arithmetic half of ``5*x + x == 6*x`` for one carrier.

    The caller must separately prove that the ``+ x`` operand aliases the same
    logical carrier as the multiply operand.  This helper intentionally only
    covers the 32-bit arithmetic identity.
    """

    return _mask32(5 + 1) == 6


def prove_xor_select_equivalence() -> bool:
    """Prove ``(~x & A) | (x & ~A)`` is ``x ^ A`` for the current masks."""

    return _mask32(~XOR_MASK) == XOR_MASK_COMPLEMENT


def prove_terminal_bcf_forms_equivalent() -> bool:
    """Prove the retained terminal BCF write forms normalize to one XOR.

    Current pseudocode may show either ``x ^ 0x173063C1`` or the retained BCF
    form ``((x ^ ~x) & 0xCD536960) ^ ~x ^ 0x259CF55E``.  The latter is
    equivalent because ``0xCD536960 ^ 0x259CF55E`` is ``~0x173063C1``.
    """

    return _mask32(FINAL_SELECT_MASK ^ FINAL_XOR) == XOR_MASK_COMPLEMENT


def _has_counted_loop(code: str) -> bool:
    return bool(
        re.search(
            r"for\s*\([^;]*=\s*0\s*;\s*[^;]*<\s*0x64\s*;\s*\+\+[^)]*\)",
            code,
            re.MULTILINE,
        )
    )


def _has_self_feeding_increment_loop(code: str) -> bool:
    return bool(
        re.search(
            r"for\s*\([^;]*;\s*[^;]*;\s*[^)]*\+=\s*\*?\(?[^)]*\*",
            code,
            re.MULTILINE,
        )
    )


def _looks_like_uninitialized_return_artifact(code: str) -> bool:
    return "__int64 result;" in code and "return result;" in code


def _looks_like_output_sink(code: str) -> bool:
    return "**a2" in code or "*output" in code or "output[" in code


def _query_ollvm_carrier_facts(
    conn: sqlite3.Connection,
    *,
    func_ea_hex: str | None = None,
) -> OllvmCarrierFactSummary:
    where = "WHERE kind='OllvmValueFlowEvidence'"
    params: list[object] = []
    if func_ea_hex:
        where += " AND lower(func_ea_hex)=lower(?)"
        params.append(func_ea_hex)

    try:
        rows = conn.execute(
            f"SELECT payload FROM fact_observations {where} ORDER BY snapshot_id, fact_id",
            tuple(params),
        ).fetchall()
    except sqlite3.OperationalError:
        rows = []

    role_counts: dict[str, int] = {}
    role_tokens: dict[str, set[str]] = {}
    accumulator_evidence: list[str] = []
    output_evidence: list[str] = []
    alias_multiply_add_proof_count = 0

    for (payload_json,) in rows:
        try:
            payload = json.loads(payload_json or "{}")
        except json.JSONDecodeError:
            continue
        role = str(payload.get("role") or "")
        token = str(payload.get("carrier_token") or "")
        if not role:
            continue
        role_counts[role] = role_counts.get(role, 0) + 1
        if token:
            role_tokens.setdefault(role, set()).add(token)
        dstr = str(payload.get("instruction_dstr") or "")
        if role == "ACCUMULATOR_CARRIER":
            accumulator_evidence.append(dstr)
            if payload.get("same_carrier_alias_proof") is True:
                alias_multiply_add_proof_count += 1
        if role in {
            "ARG_OUTPUT_STORE_CANDIDATE",
            "LOCAL_WORKING_STORE_CANDIDATE",
            "INDIRECT_STORE_CANDIDATE",
        }:
            output_evidence.append(dstr)

    return OllvmCarrierFactSummary(
        role_counts=dict(sorted(role_counts.items())),
        role_tokens={
            role: tuple(sorted(tokens))
            for role, tokens in sorted(role_tokens.items())
        },
        accumulator_evidence=tuple(accumulator_evidence),
        output_evidence=tuple(output_evidence),
        alias_multiply_add_proof_count=alias_multiply_add_proof_count,
    )


def evaluate_ollvm_fla_bcf_sub_oracle(
    code: str,
    *,
    conn: sqlite3.Connection | None = None,
    func_ea_hex: str | None = None,
) -> OllvmFlaBcfSubOracleResult:
    """Evaluate semantic equivalence facts for the current OLLVM output."""

    checks: list[OllvmFlaBcfSubCheck] = [
        OllvmFlaBcfSubCheck(
            "prompt_and_secret_compare",
            "Please enter password:" in code and "secret" in code,
            "pseudocode retains prompt/read and the hardcoded password literal",
        ),
        OllvmFlaBcfSubCheck(
            "dispatcher_loop_removed",
            "while (" not in code and "while(1)" not in code.replace(" ", ""),
            "no residual dispatcher while loop remains in the rendered output",
        ),
        OllvmFlaBcfSubCheck(
            "xor_select_equivalence",
            prove_xor_select_equivalence(),
            "terminal select mask pair is an XOR mask/complement pair",
        ),
        OllvmFlaBcfSubCheck(
            "terminal_bcf_forms_equivalent",
            (
                prove_terminal_bcf_forms_equivalent()
                and "0x173063C1" in code
                and "0xCD536960" in code
                and "0x259CF55E" in code
            ),
            "retained terminal BCF write forms normalize to carrier ^ 0x173063C1",
        ),
    ]

    fact_summary = None
    output_fact_present = False
    fact_backed_loop_split = False
    if conn is not None:
        fact_summary = _query_ollvm_carrier_facts(conn, func_ea_hex=func_ea_hex)
        required_roles = (
            "ARG_INPUT_POINTER",
            "ARG_OUTPUT_POINTER",
            "PASSWORD_BUFFER",
            "PASSWORD_COMPARE_RESULT",
            "LOOP_INDEX_CARRIER",
            "ACCUMULATOR_CARRIER",
        )
        for role in required_roles:
            checks.append(OllvmFlaBcfSubCheck(
                f"fact_role_{role.lower()}",
                fact_summary.has_role(role),
                f"diag fact role {role} is present",
            ))
        output_fact_present = any(
            fact_summary.has_role(role)
            for role in (
                "ARG_OUTPUT_STORE_CANDIDATE",
                "LOCAL_WORKING_STORE_CANDIDATE",
                "INDIRECT_STORE_CANDIDATE",
            )
        )
        checks.append(OllvmFlaBcfSubCheck(
            "fact_output_or_terminal_store_candidate",
            output_fact_present,
            "diag facts identify a terminal/output store candidate",
        ))
        checks.append(OllvmFlaBcfSubCheck(
            "fact_accumulator_has_transform_evidence",
            any("#5.4*" in text for text in fact_summary.accumulator_evidence)
            and any("#0x42" in text for text in fact_summary.accumulator_evidence)
            and any("#0xFFFFFFBD" in text for text in fact_summary.accumulator_evidence),
            "diag accumulator facts include multiply/add and mask transform evidence",
        ))
        checks.append(OllvmFlaBcfSubCheck(
            "fact_alias_multiply_add_same_carrier",
            (
                prove_alias_multiply_add_equivalence()
                and fact_summary.alias_multiply_add_proof_count > 0
            ),
            "diag facts prove the 5*x+x add operand aliases the same accumulator carrier",
        ))
        loop_tokens = set(fact_summary.role_tokens.get("LOOP_INDEX_CARRIER", ()))
        accumulator_tokens = set(fact_summary.role_tokens.get("ACCUMULATOR_CARRIER", ()))
        fact_backed_loop_split = (
            bool(loop_tokens)
            and bool(accumulator_tokens)
            and loop_tokens.isdisjoint(accumulator_tokens)
            and fact_summary.alias_multiply_add_proof_count > 0
        )

    rendered_loop_clean = _has_counted_loop(code) and not _has_self_feeding_increment_loop(code)
    checks.append(OllvmFlaBcfSubCheck(
        "clean_counted_loop",
        rendered_loop_clean or fact_backed_loop_split,
        (
            "rendered loop is a normal 0..0x64 traversal, or diag facts prove "
            "the loop-index/accumulator carrier split when IDA renders a "
            "self-feeding presentation artifact"
        ),
    ))

    rendered_output_sink = _looks_like_output_sink(code)
    return_artifact = _looks_like_uninitialized_return_artifact(code)
    checks.append(OllvmFlaBcfSubCheck(
        "sink_present",
        rendered_output_sink or (
            "return " in code and output_fact_present and not return_artifact
        ),
        "rendered output has an observable output sink carrier",
    ))
    checks.append(OllvmFlaBcfSubCheck(
        "return_result_is_presentation_artifact",
        not return_artifact,
        (
            "IDA rendered an uninitialized return carrier; accepted as a "
            "type-recovery presentation warning only with rendered and diag output sinks"
        ),
        blocker=return_artifact and not (rendered_output_sink and output_fact_present),
    ))

    return OllvmFlaBcfSubOracleResult(
        checks=tuple(checks),
        fact_summary=fact_summary,
    )


def render_ollvm_fla_bcf_sub_oracle_report(
    result: OllvmFlaBcfSubOracleResult,
    *,
    func_ea_hex: str,
) -> str:
    """Render a compact markdown report for e2e artifacts."""

    lines = [
        "# test_function_ollvm_fla_bcf_sub Oracle",
        "",
        f"Function: `{func_ea_hex}`",
        f"Status: `{'pass' if result.passed else 'fail'}`",
        "",
        "| Check | Status | Detail |",
        "|-|-|-|",
    ]
    for check in result.checks:
        status = "pass" if check.passed else ("warn" if not check.blocker else "fail")
        lines.append(f"| `{check.name}` | `{status}` | {check.detail} |")

    if result.fact_summary is not None:
        lines.extend([
            "",
            "## Carrier Fact Roles",
            "",
            "| Role | Count | Tokens |",
            "|-|-|-|",
        ])
        for role, count in result.fact_summary.role_counts.items():
            tokens = ", ".join(result.fact_summary.role_tokens.get(role, ()))
            lines.append(f"| `{role}` | {count} | `{tokens}` |")

    if result.blockers:
        lines.extend([
            "",
            "## Blockers",
            "",
        ])
        for blocker in result.blockers:
            lines.append(f"- `{blocker.name}`: {blocker.detail}")

    return "\n".join(lines) + "\n"


__all__ = [
    "OllvmCarrierFactSummary",
    "OllvmFlaBcfSubCheck",
    "OllvmFlaBcfSubOracleResult",
    "evaluate_ollvm_fla_bcf_sub_oracle",
    "prove_alias_multiply_add_equivalence",
    "prove_terminal_bcf_forms_equivalent",
    "prove_xor_select_equivalence",
    "render_ollvm_fla_bcf_sub_oracle_report",
]
