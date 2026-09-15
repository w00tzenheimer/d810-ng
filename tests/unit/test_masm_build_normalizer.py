from __future__ import annotations

import importlib.util
import json
import re
from pathlib import Path

import pytest


REPO = Path(__file__).resolve().parents[2]
NORMALIZER_PATH = REPO / "samples" / "scripts" / "normalize_masm_for_build.py"


def _load_normalizer():
    spec = importlib.util.spec_from_file_location("normalize_masm_for_build", NORMALIZER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _structural_export(body: str) -> str:
    return (
        "; Auto-generated x64 MASM (d810 structural export) -- assemble with ml64\n"
        + body
    )


def test_normalizer_folds_ida_frame_variable_terms():
    normalizer = _load_normalizer()
    source = _structural_export(
        "    lea r13, [rsp+rax+508h+var_508]\n"
        "    movzx eax, byte ptr [rsp+r8+648h+var_88]\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "lea r13, [rsp+rax]" in result.text
    assert "movzx eax, byte ptr [rsp+r8+5C0h]" in result.text
    assert result.stats.frame_terms == 2


def test_normalizer_emits_x64_unwind_metadata_without_changing_prologue_bytes():
    normalizer = _load_normalizer()
    source = _structural_export(
        "OPTION PROLOGUE:NONE\n"
        "OPTION EPILOGUE:NONE\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "PUBLIC sub_fixture\n"
        "sub_fixture:\n"
        "    push r15\n"
        "    push rbx\n"
        "    sub rsp, 238h\n"
        "    mov rax, rcx\n"
        "    add rsp, 238h\n"
        "    pop rbx\n"
        "    pop r15\n"
        "    ret\n"
        "_TEXT ENDS\n"
        "END\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "sub_fixture PROC FRAME" in result.text
    assert "    push r15\n    .pushreg r15" in result.text
    assert "    push rbx\n    .pushreg rbx" in result.text
    assert "    sub rsp, 238h\n    .allocstack 238h\n    .endprolog" in result.text
    assert "sub_fixture ENDP\n_TEXT ENDS" in result.text
    assert result.stats.unwind_frames == 1


def test_normalizer_rebases_relative_jump_table_and_rewrites_its_entries():
    normalizer = _load_normalizer()
    source = _structural_export(
        "CONST SEGMENT\n"
        "jpt_A dd 0FFFFFFF0h\n"
        "dd 20h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "    lea rdx, jpt_A\n"
        "    movsxd rcx, dword ptr (jpt_A - 180001000h)[rdx+rcx*4]\n"
        "    add rcx, rdx\n"
        "    jmp rcx\n"
        "loc_180000FF0:\n"
        "    ret\n"
        "loc_180001020:\n"
        "    ret\n"
        "_TEXT ENDS\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "movsxd rcx, dword ptr [rdx+rcx*4]" in result.text
    assert "OPTION NOSCOPED" in result.text
    assert "jpt_A dd loc_180000FF0 - jpt_A" in result.text
    assert "dd loc_180001020 - jpt_A" in result.text
    assert result.text.index("_TEXT SEGMENT") < result.text.index("jpt_A dd")
    assert "jpt_A dd 0FFFFFFF0h" not in result.text
    assert result.stats.rebased_indexed_symbols == 1
    assert result.stats.relative_jump_tables == 1
    assert result.stats.relative_jump_entries == 2


def test_normalizer_unscopes_pre_materialized_relative_table_targets():
    normalizer = _load_normalizer()
    source = _structural_export(
        "OPTION PROLOGUE:NONE\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "jpt_A dd loc_180001020 - jpt_A\n"
        "PUBLIC sub_fixture\n"
        "sub_fixture:\n"
        "    push rbx\n"
        "    sub rsp, 20h\n"
        "loc_180001020:\n"
        "    add rsp, 20h\n"
        "    pop rbx\n"
        "    ret\n"
        "_TEXT ENDS\n"
        "END\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "OPTION NOSCOPED" in result.text
    assert result.text.index("OPTION NOSCOPED") < result.text.index("jpt_A dd")


def test_normalizer_rejects_unproven_indexed_symbol_rebase():
    normalizer = _load_normalizer()
    source = _structural_export(
        "jpt_A dd 0\n"
        "    movsxd rcx, dword ptr (jpt_A - 180001000h)[rdx+rcx*4]\n"
    )

    with pytest.raises(normalizer.MasmNormalizationError, match="matching LEA"):
        normalizer.normalize_masm_text(source)


def test_normalizer_rejects_relative_entry_without_a_native_target_label():
    normalizer = _load_normalizer()
    source = _structural_export(
        "CONST SEGMENT\n"
        "jpt_A dd 0FFFFFFF0h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "    lea rdx, jpt_A\n"
        "    movsxd rcx, dword ptr (jpt_A - 180001000h)[rdx+rcx*4]\n"
        "    add rcx, rdx\n"
        "    jmp rcx\n"
        "_TEXT ENDS\n"
    )

    with pytest.raises(normalizer.MasmNormalizationError, match="target label"):
        normalizer.normalize_masm_text(source)


def test_normalizer_uses_attested_supplement_for_incomplete_dword_table():
    normalizer = _load_normalizer()
    source = _structural_export(
        "CONST SEGMENT\n"
        "unk_A db 0F0h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "    lea rdx, unk_A\n"
        "    movsxd rcx, dword ptr (unk_A - 180001000h)[rdx+rcx*4]\n"
        "    add rcx, rdx\n"
        "    jmp rcx\n"
        "loc_180000FF0:\n"
        "    ret\n"
        "loc_180001020:\n"
        "    ret\n"
        "_TEXT ENDS\n"
    )

    result = normalizer.normalize_masm_text(
        source,
        supplemental_tables={"unk_A": (0xFFFFFFF0, 0x20)},
    )

    assert "unk_A dd loc_180000FF0 - unk_A" in result.text
    assert "dd loc_180001020 - unk_A" in result.text
    assert "unk_A db" not in result.text


def test_normalizer_rejects_supplement_that_disagrees_with_materialized_prefix():
    normalizer = _load_normalizer()
    source = _structural_export(
        "CONST SEGMENT\n"
        "unk_A db 0F1h\n"
        "CONST ENDS\n"
        "_TEXT SEGMENT ALIGN(16) 'CODE'\n"
        "    lea rdx, unk_A\n"
        "    movsxd rcx, dword ptr (unk_A - 180001000h)[rdx+rcx*4]\n"
        "    add rcx, rdx\n"
        "    jmp rcx\n"
        "loc_180000FF0:\n"
        "    ret\n"
        "_TEXT ENDS\n"
    )

    with pytest.raises(normalizer.MasmNormalizationError, match="prefix"):
        normalizer.normalize_masm_text(
            source,
            supplemental_tables={"unk_A": (0xFFFFFFF0,)},
        )


def test_e1_relative_jump_table_targets_the_four_native_cfg_successors():
    normalizer = _load_normalizer()
    source = (
        REPO / "samples" / "src" / "masm" / "sub_7FFB0E1E69E0.asm"
    ).read_text()

    result = normalizer.normalize_masm_text(source)

    assert "jpt_7FFB0E1E6A88 dd def_7FFB0E1E6A88 - jpt_7FFB0E1E6A88" in result.text
    for target in (
        "loc_7FFB0E1E6A40",
        "loc_7FFB0E1E6AEF",
        "loc_7FFB0E1E6A8B",
    ):
        assert f"dd {target} - jpt_7FFB0E1E6A88" in result.text


def test_normalizer_preserves_invalid_lock_prefix_as_raw_byte():
    normalizer = _load_normalizer()
    source = _structural_export(
        "    lock seto byte ptr [rax+24048990h]\n"
        "    lock xadd dword ptr [rax], r8d\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "    db 0F0h\n    seto byte ptr [rax+24048990h]" in result.text
    assert "    lock xadd dword ptr [rax], r8d" in result.text
    assert result.stats.raw_lock_prefixes == 1


def test_normalizer_leaves_non_structural_masm_unchanged():
    normalizer = _load_normalizer()
    source = "PUBLIC f\nf:\n    lea rax, [rsp+100h+var_20]\n"

    result = normalizer.normalize_masm_text(source)

    assert result.text == source
    assert result.stats.total == 0


def test_all_hash_bound_sources_normalize_without_portability_residue(tmp_path: Path):
    normalizer = _load_normalizer()
    manifest = json.loads(
        (REPO / "samples" / "src" / "masm" / "hash_bound_seven_manifest.json").read_text()
    )

    total_changes = 0
    for record in manifest["fixtures"]:
        source = REPO / "samples" / "src" / "masm" / record["masm"]
        output = tmp_path / record["masm"]
        stats = normalizer.normalize_file(source, output)
        normalized = output.read_text()
        total_changes += stats.total
        assert not re.search(r"\+[0-9A-Fa-f]+h\+var_[0-9A-Fa-f]+\b", normalized)
        assert not re.search(
            r"\([A-Za-z_][A-Za-z0-9_]* - [0-9A-Fa-f]+h\)\[", normalized
        )
        assert "lock seto" not in normalized.lower()

    assert total_changes > 0
