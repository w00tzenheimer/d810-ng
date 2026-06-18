from __future__ import annotations

import shutil

import pytest

from tools.llvm_m0_roundtrip import run_opt


def _opt_or_skip():
    opt = run_opt.find_opt()
    if opt is None:
        pytest.skip(
            "LLVM opt not found; set LLVM_OPT or install opt in PATH/"
            "/opt/homebrew/opt/llvm/bin/opt"
        )
    return opt


def test_before_fixture_contains_branchless_mask_select_shape():
    text = run_opt.default_before().read_text(encoding="utf-8")

    assert "%low = and i32 %token, 1" in text
    assert "%mask = sub i32 0, %low" in text
    assert "%not_mask = xor i32 %mask, -1" in text
    assert "%state_true = and i32 -1188804898, %mask" in text
    assert "%state_false = and i32 1015636137, %not_mask" in text
    assert "%state = or i32 %state_true, %state_false" in text


def test_after_fixture_pins_partial_llvm_middle_simplification():
    before = run_opt.default_before().read_text(encoding="utf-8")
    after = run_opt.default_after().read_text(encoding="utf-8")

    assert "%not_mask = xor i32 %mask, -1" in before
    assert "%false_value = add i32 %base, -51" in before
    assert "%not_mask = add nsw i32 %low, -1" in after
    assert "%false_value = add i32 %token, -34" in after
    assert "%not_mask = xor i32 %mask, -1" not in after
    assert "%false_value = add i32 %base, -51" not in after
    assert "select " not in after
    assert "%value = or i32 %true_part, %false_part" in after


def test_runner_normalized_output_matches_checked_in_after_fixture():
    opt = _opt_or_skip()

    result = run_opt.run_opt(opt=opt)

    assert result.opt == opt
    assert result.optimized == run_opt.normalize_ir(
        run_opt.default_after().read_text(encoding="utf-8")
    )


def test_find_opt_honors_path_or_homebrew_install():
    opt = run_opt.find_opt()
    if opt is None:
        assert shutil.which("opt") is None
    else:
        assert opt.exists()
        assert opt.name == "opt"
