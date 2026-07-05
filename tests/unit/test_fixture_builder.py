"""Unit tests for the pure-Python fixture-builder logic (ticket d81-rtfh).

No IDA imports — everything here is testable without an IDA runtime. The
IDA-bound extract/resolve worker is covered by
``tests/system/e2e/test_fixture_idb_worker.py``.
"""
from pathlib import Path

from d810.samples.fixture_builder import CallSiteFold, detect_indirect_call_folds

REPO = Path(__file__).resolve().parents[2]
SUB = (REPO / "samples/src/masm/sub_1815C8C30.asm").read_text()


def test_detects_slot_const_and_reg_from_committed_asm():
    folds = detect_indirect_call_folds(SUB)
    assert CallSiteFold(
        slot_symbol="off_18210A360",
        const=0x64E2C558D421136,
        call_reg="rax",
        materialized=None,  # committed slot is a reloc expr, not a raw dq
    ) in folds


def test_reads_materialized_value_on_fresh_extract():
    fresh = (
        "CONST SEGMENT\n"
        "off_ABC dq 0DEADBEEFCAFE0000h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "f:\n"
        "    mov rax, qword ptr [off_ABC]\n"
        "    mov rcx, 10h\n"
        "    add rax, rcx\n"
        "    call rax\n"
        "_TEXT ENDS\nEND\n"
    )
    (fold,) = detect_indirect_call_folds(fresh)
    assert fold.slot_symbol == "off_ABC"
    assert fold.const == 0x10
    assert fold.materialized == 0xDEADBEEFCAFE0000


# --------------------------------------------------------------------------- #
# Task 2: retarget planner + rewriter + stub renderer
# --------------------------------------------------------------------------- #
from d810.samples.fixture_builder import (  # noqa: E402
    ResolvedTarget, RetargetAction, RetargetPlan,
    plan_retargets, apply_retargets, render_stub,
)


def test_plan_retargets_keeps_leaf_import_skips_sub():
    folds = [
        CallSiteFold("off_A", 0x10, "rax", materialized=0x100),  # -> va 0x110
        CallSiteFold("off_B", 0x20, "rcx", materialized=0x200),  # -> va 0x220
    ]
    resolved = {
        0x110: ResolvedTarget(0x110, "rand", is_import=True, retargetable=True),
        0x220: ResolvedTarget(0x220, "sub_1815DF1C0", is_import=False, retargetable=False),
    }
    plan = plan_retargets(folds, resolved, image_symbols=set())
    assert plan.actions == (RetargetAction("off_A", 0x10, "rand"),)
    assert any("sub_1815DF1C0" in s for s in plan.skipped)


def test_apply_retargets_rewrites_slot_and_adds_extern():
    asm = (
        "; header\n"
        "CONST SEGMENT\n"
        "off_A dq 0100h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "PUBLIC f\nf:\n    call rax\n_TEXT ENDS\nEND\n"
    )
    plan = RetargetPlan(actions=(RetargetAction("off_A", 0x10, "rand"),), skipped=())
    out = apply_retargets(asm, plan)
    assert "off_A dq rand - 10h" in out
    assert "EXTERN rand:PROC" in out
    assert "dq 0100h" not in out


def test_render_stub_is_dependency_free_leaf():
    stub = render_stub("rand")
    assert "PUBLIC rand" in stub
    assert "xor eax, eax" in stub
    assert "ret" in stub
    assert "OPTION PROLOGUE:NONE" in stub
