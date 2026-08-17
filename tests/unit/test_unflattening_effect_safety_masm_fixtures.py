"""Integrity checks for the exact MASM exports used by the safety regressions."""

from __future__ import annotations

from pathlib import Path

WORKTREE = Path(__file__).parents[2]
MASM_DIR = WORKTREE / "samples" / "src" / "masm"


def _fixture(name: str) -> str:
    return (MASM_DIR / f"{name}.asm").read_text()


def test_exact_target_a_fixture_preserves_materialized_effectful_corridor():
    source = _fixture("sub_7FF8569F0540")

    assert "; Function: sub_7FF8569F0540  @ 0x7ff8569f0540" in source
    assert "PUBLIC sub_7FF8569F0540" in source
    assert "EXTERN memcpy:PROC" in source
    assert source.count("call memcpy") >= 8
    assert "CONST SEGMENT" in source
    assert "jmp loc_7FF8569F0600" in source


def test_exact_target_b_fixture_preserves_dispatcher_trap_and_lock_effect():
    source = _fixture("sub_7FF8568132D0")

    assert "; Function: sub_7FF8568132D0  @ 0x7ff8568132d0" in source
    assert "PUBLIC sub_7FF8568132D0" in source
    assert "EXTERN __imp_RtlAcquireSRWLockExclusive:PROC" in source
    assert "call qword ptr [__imp_RtlAcquireSRWLockExclusive]" in source
    assert "EXTERN Eidolon_UpdateSharedStateIfSentinelMatches:PROC" in source
    assert source.count("call Eidolon_UpdateSharedStateIfSentinelMatches") >= 4
    assert "int 3" in source
    assert "CONST SEGMENT" in source
