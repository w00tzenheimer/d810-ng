"""Integrity checks for the exact MASM exports used by the safety regressions."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.system.e2e.unflattening_effect_safety_oracle import reachable_call_eas

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
