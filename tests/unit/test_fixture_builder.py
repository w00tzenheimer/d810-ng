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


# --------------------------------------------------------------------------- #
# Task 3: DSL case emitter + idempotent upsert
# --------------------------------------------------------------------------- #
from d810.samples.fixture_builder import (  # noqa: E402
    emit_fixture_case, upsert_case_in_list,
)


def test_emit_case_is_minimal_no_auto_semantics():
    src = emit_fixture_case("sub_ABC", "default_unflattening_ollvm.json")
    assert 'function="sub_ABC"' in src
    assert 'project="default_unflattening_ollvm.json"' in src
    assert "must_change=True" in src
    assert "skip_if_function_absent=True" in src
    assert "TODO(human)" in src
    # MINIMAL policy: no auto semantic assertions
    assert "deobfuscated_contains" not in src
    assert "deobfuscated_not_contains" not in src
    assert "expected_rules" not in src


def test_upsert_appends_new_case():
    lst = "DAC_MASM_CASES = [\n    DeobfuscationCase(\n        function=\"old\",\n    ),\n]\n"
    out = upsert_case_in_list(lst, "sub_NEW", emit_fixture_case("sub_NEW", "p.json"))
    assert 'function="old"' in out
    assert 'function="sub_NEW"' in out
    assert out.count("DeobfuscationCase(") == 2


def test_upsert_replaces_existing_case_no_duplicate():
    base = upsert_case_in_list(
        "DAC_MASM_CASES = [\n]\n", "sub_X", emit_fixture_case("sub_X", "p.json"))
    again = upsert_case_in_list(base, "sub_X", emit_fixture_case("sub_X", "q.json"))
    assert again.count('function="sub_X"') == 1
    assert 'project="q.json"' in again


# --------------------------------------------------------------------------- #
# Task 5: build + verify subprocess orchestration
# --------------------------------------------------------------------------- #
import subprocess as _sp  # noqa: E402

from d810.samples.fixture_builder import (  # noqa: E402
    build_fixture_dll, verify_fixture_case,
)


def test_build_fixture_dll_invokes_build_masm_sh(tmp_path):
    calls = {}

    def fake_run(cmd, **kw):
        calls["cmd"] = cmd
        calls["env"] = kw.get("env", {})
        (tmp_path / "samples/bins").mkdir(parents=True, exist_ok=True)
        (tmp_path / "samples/bins/tmpfx.dll").write_bytes(b"MZ")
        return _sp.CompletedProcess(cmd, 0, "linked", "")

    out = build_fixture_dll(tmp_path, "tmpfx", runner=fake_run)
    assert out == tmp_path / "samples/bins/tmpfx.dll"
    assert "build_masm.sh" in " ".join(str(c) for c in calls["cmd"])
    assert calls["env"].get("BINARY_NAME") == "tmpfx"


def test_verify_sets_test_binary_env(tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env", {})
        return _sp.CompletedProcess(cmd, 0, "1 passed", "")

    ok = verify_fixture_case(tmp_path, "sub_X", "tmpfx", runner=fake_run)
    assert ok is True
    assert seen["env"].get("D810_TEST_BINARY") == "tmpfx.dll"
