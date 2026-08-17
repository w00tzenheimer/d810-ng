"""Integrity checks for the exact MASM exports used by the safety regressions."""

from __future__ import annotations

from pathlib import Path
import re

import pytest

import tests.system.e2e.unflattening_effect_safety_oracle as safety_oracle
from tests.system.e2e.unflattening_effect_safety_oracle import (
    reachable_call_eas,
    session_scoped_rows,
)

WORKTREE = Path(__file__).parents[2]
MASM_DIR = WORKTREE / "samples" / "src" / "masm"


def _fixture(name: str) -> str:
    return (MASM_DIR / f"{name}.asm").read_text()


def _parse_callsite_markers(source: str) -> dict[str, tuple[str, str]]:
    """Resolve CONST marker pointers to the following in-function instruction.

    The committed MASM exporter represents exact native callsites as a public
    qword in ``CONST`` that points at a private code label immediately before
    the instruction.  Parse the section metadata rather than treating marker
    names or imported API spellings as sufficient fixture evidence.
    """
    lines = source.splitlines()
    const_start = next(
        index for index, line in enumerate(lines) if line.strip() == "CONST SEGMENT"
    )
    const_end = next(
        index
        for index, line in enumerate(lines[const_start + 1 :], const_start + 1)
        if line.strip() == "CONST ENDS"
    )
    text_start = next(
        index
        for index, line in enumerate(lines)
        if re.match(r"^_TEXT SEGMENT\b", line.strip())
    )
    text_end = next(
        index
        for index, line in enumerate(lines[text_start + 1 :], text_start + 1)
        if line.strip() == "_TEXT ENDS"
    )
    const_lines = lines[const_start + 1 : const_end]
    text_lines = lines[text_start + 1 : text_end]
    marker_names = {
        match.group(1)
        for line in const_lines
        if (match := re.match(
            r"^\s*PUBLIC\s+(d810_callsite_[A-Za-z0-9_]+)\s*$", line
        ))
    }
    bindings: dict[str, tuple[str, str]] = {}
    for marker in marker_names:
        definition = next(
            (
                line
                for line in const_lines
                if re.match(
                    rf"^\s*{re.escape(marker)}\s+dq\s+([A-Za-z0-9_]+)\s*$",
                    line,
                )
            ),
            None,
        )
        assert definition is not None, f"marker {marker} has no CONST qword"
        target = re.fullmatch(
            rf"\s*{re.escape(marker)}\s+dq\s+([A-Za-z0-9_]+)\s*",
            definition,
        )
        assert target is not None, definition
        target_label = target.group(1)
        label_index = next(
            (
                index
                for index, line in enumerate(text_lines)
                if line.strip() == f"{target_label}:"
            ),
            None,
        )
        assert label_index is not None, (
            f"marker {marker} points at missing code label {target_label}"
        )
        instruction = next(
            (
                line.strip()
                for line in text_lines[label_index + 1 :]
                if line.strip() and not line.lstrip().startswith(";")
            ),
            None,
        )
        assert instruction is not None, f"marker {marker} has no instruction"
        bindings[marker] = (target_label, instruction)
    return bindings


def test_exact_target_a_fixture_preserves_materialized_effectful_corridor():
    source = _fixture("sub_7FF8569F0540")

    assert "; Function: sub_7FF8569F0540  @ 0x7ff8569f0540" in source
    assert "PUBLIC sub_7FF8569F0540" in source
    assert "EXTERN memcpy:PROC" in source
    assert source.count("call memcpy") >= 8
    assert "PUBLIC d810_callsite_sub_7FF8569F0540_memcpy" in source
    assert "CONST SEGMENT" in source
    assert "jmp loc_7FF8569F0600" in source
    marker_bindings = _parse_callsite_markers(source)
    assert marker_bindings[
        "d810_callsite_sub_7FF8569F0540_memcpy"
    ][1].lower().startswith("call ")


def test_exact_target_b_fixture_preserves_dispatcher_trap_and_lock_effect():
    source = _fixture("sub_7FF8568132D0")

    assert "; Function: sub_7FF8568132D0  @ 0x7ff8568132d0" in source
    assert "PUBLIC sub_7FF8568132D0" in source
    assert "EXTERN __imp_RtlAcquireSRWLockExclusive:PROC" in source
    assert "call qword ptr [__imp_RtlAcquireSRWLockExclusive]" in source
    assert "EXTERN Eid_UpdateSharedStateIfSentinelMatches:PROC" in source
    assert source.count("call Eid_UpdateSharedStateIfSentinelMatches") >= 4
    assert "PUBLIC d810_callsite_sub_7FF8568132D0_srw_lock" in source
    assert "int 3" in source
    assert "CONST SEGMENT" in source
    marker_bindings = _parse_callsite_markers(source)
    assert marker_bindings[
        "d810_callsite_sub_7FF8568132D0_srw_lock"
    ][1].lower().startswith("call ")


def test_exact_target_c_fixture_preserves_termination_effects_and_markers():
    source_path = MASM_DIR / "sub_7FF855576B50.asm"
    assert source_path.is_file(), f"missing committed MASM fixture: {source_path}"
    source = source_path.read_text()

    assert "; Function: sub_7FF855576B50  @ 0x7ff855576b50" in source
    assert "PUBLIC sub_7FF855576B50" in source
    assert "EXTERN MessageBoxA:PROC" in source
    assert "EXTERN GetCurrentProcess:PROC" in source
    assert "EXTERN TerminateProcess:PROC" in source
    assert "CONST SEGMENT" in source

    expected = {
        "d810_callsite_sub_7FF855576B50_message_box",
        "d810_callsite_sub_7FF855576B50_get_current_process",
        "d810_callsite_sub_7FF855576B50_terminate_process",
    }
    marker_bindings = _parse_callsite_markers(source)
    assert set(marker_bindings) == expected
    function_start = source.index("sub_7FF855576B50:")
    function_end = source.index("_TEXT ENDS")
    for marker, (target_label, instruction) in marker_bindings.items():
        target_offset = source.index(f"{target_label}:")
        assert function_start < target_offset < function_end, marker
        assert instruction.lower().startswith(("call ", "jmp ")), (
            marker,
            instruction,
        )


def test_masm_build_exports_only_explicit_d810_callsite_markers() -> None:
    sources = {
        "a": _fixture("sub_7FF8569F0540"),
        "b": _fixture("sub_7FF8568132D0"),
        "c": _fixture("sub_7FF855576B50"),
    }
    markers = {
        marker
        for source in sources.values()
        for marker in re.findall(
            r"(?m)^\s*PUBLIC\s+(d810_callsite_[A-Za-z0-9_]+)\s*$",
            source,
        )
    }
    assert markers == {
        "d810_callsite_sub_7FF8569F0540_memcpy",
        "d810_callsite_sub_7FF8568132D0_srw_lock",
        "d810_callsite_sub_7FF855576B50_message_box",
        "d810_callsite_sub_7FF855576B50_get_current_process",
        "d810_callsite_sub_7FF855576B50_terminate_process",
    }


def test_exact_call_reachability_requires_the_bound_native_ea() -> None:
    graph = {
        0: (1, 2),
        1: (3,),
        2: (),
        3: (),
    }
    call_blocks = {3: (0x18001234,)}
    assert reachable_call_eas(graph, call_blocks) == frozenset({0x18001234})


def test_exact_call_reachability_rejects_an_unreachable_native_ea() -> None:
    graph = {0: (1,), 1: ()}
    call_blocks = {2: (0x18001234,)}
    assert reachable_call_eas(graph, call_blocks) == frozenset()


def test_exact_call_reachability_fails_closed_on_unknown_successor() -> None:
    with pytest.raises(ValueError, match="unknown successor"):
        reachable_call_eas({0: (99,)}, {0: (0x18001234,)})


def test_diagnostic_oracle_excludes_receipts_and_attempts_from_other_sessions() -> None:
    receipt_rows = (
        ("batch-current", "committed", "session-current"),
        ("batch-stale", "committed", "session-stale"),
    )
    attempt_rows = (
        ("committed", 1, 0, "session-current"),
        ("committed", 1, 0, "session-stale"),
    )
    assert session_scoped_rows(receipt_rows, "session-current") == (
        ("batch-current", "committed", "session-current"),
    )
    assert session_scoped_rows(attempt_rows, "session-current") == (
        ("committed", 1, 0, "session-current"),
    )


def test_dispatcher_removal_proof_requires_the_committed_attempt_and_batch() -> None:
    matcher = getattr(
        safety_oracle,
        "transaction_bound_dispatcher_removal_proofs",
        None,
    )
    assert callable(matcher), "transaction-bound proof matcher is missing"

    proofs = (
        {
            "application_status": "applied",
            "proof_status": "accepted",
            "plan_id": "stale-plan",
            "attempt_id": "stale-attempt",
        },
        {
            "application_status": "applied",
            "proof_status": "rejected",
            "plan_id": "current-plan",
            "attempt_id": "current-attempt",
        },
    )
    assert matcher(
        proofs,
        committed_attempts={("current-plan", "current-attempt")},
        committed_batches={"current-attempt"},
    ) == (proofs[1],)
    batch_mismatch = {
        **proofs[1],
        "proof_status": "accepted",
    }
    assert matcher(
        (batch_mismatch,),
        committed_attempts={("current-plan", "current-attempt")},
        committed_batches={"different-batch"},
    ) == ()


def test_exact_call_oracle_rejects_duplicate_native_marker_eas() -> None:
    validator = getattr(safety_oracle, "require_distinct_native_eas", None)
    assert callable(validator), "native-EA uniqueness validator is missing"

    assert validator((0x180044A5A, 0x180044A60, 0x180044AF7), expected_count=3) == (
        0x180044A5A,
        0x180044A60,
        0x180044AF7,
    )
    with pytest.raises(ValueError, match="distinct"):
        validator((0x180044A5A, 0x180044A5A, 0x180044AF7), expected_count=3)
