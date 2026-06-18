from __future__ import annotations

import json
import shutil

import pytest

from tools.llvm_m0_roundtrip import run_opt


LOWER_BACK = run_opt.repo_root() / "tools/llvm_m0_roundtrip/lab_flat_branchless.lower_back.json"


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


def test_lower_back_artifact_matches_optimized_fixture():
    after = run_opt.default_after().read_text(encoding="utf-8")
    artifact = json.loads(LOWER_BACK.read_text(encoding="utf-8"))

    assert artifact["schema"] == "d810.llvm_m0.lower_back.v1"
    assert artifact["ticket"] == "llr-6q39"
    assert artifact["case"] == "lab_flat_branchless"
    assert artifact["source_fixture"] == "fixtures/lab_flat_branchless.after.ll"
    assert artifact["optimized_llvm"]["low_predicate"] in after
    assert artifact["optimized_llvm"]["state_mask_form"] in after
    assert artifact["optimized_llvm"]["value_mask_form"] in after
    assert "%not_mask = add nsw i32 %low, -1" in after
    assert "%false_value = add i32 %token, -34" in after


def test_lower_back_artifact_pins_hand_lowering_and_oracle_path():
    artifact = json.loads(LOWER_BACK.read_text(encoding="utf-8"))

    assert artifact["arms"]["true_odd"]["state"] == "0xB92456DE"
    assert artifact["arms"]["true_odd"]["value"] == "(token + 0x11) ^ 0x22"
    assert artifact["arms"]["false_even"]["state"] == "0x3C8960A9"
    assert artifact["arms"]["false_even"]["value"] == "token - 0x22"
    assert artifact["hand_lowered_control"] == {
        "shape": "if_else",
        "predicate": "(token & 1) != 0",
        "true_arm": "true_odd",
        "false_arm": "false_even",
    }
    assert artifact["d810_lower_back"]["primitive"] == "ConditionalSynthesize"
    assert artifact["d810_lower_back"]["recover"] == "recover_branchless"
    assert artifact["d810_lower_back"]["lower"] == "lower_conditional_synthesize"
    assert artifact["d810_lower_back"]["flat_function"] == "lab_flat_branchless"
    assert artifact["d810_lower_back"]["oracle_function"] == "lab_ref_cond"


def test_lower_back_artifact_classifies_collapse_responsibility():
    artifact = json.loads(LOWER_BACK.read_text(encoding="utf-8"))
    classes = artifact["collapse_classes"]

    assert "LLVM-free" in classes
    assert any("~mask canonicalization" in item for item in classes["LLVM-free"])
    assert any("false-arm fold" in item for item in classes["LLVM-free"])
    assert classes["needs d810 predicate recovery"] == [
        "mask/or state select -> recovered (token & 1) predicate -> synthesized if/else"
    ]
    assert classes["needs MBA/Z3"] == []


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
