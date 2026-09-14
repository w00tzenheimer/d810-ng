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


def test_normalizer_rebases_indexed_symbol_only_with_matching_base_load():
    normalizer = _load_normalizer()
    source = _structural_export(
        "jpt_A dd 0\n"
        "    lea rdx, jpt_A\n"
        "    movsxd rcx, dword ptr (jpt_A - 180001000h)[rdx+rcx*4]\n"
    )

    result = normalizer.normalize_masm_text(source)

    assert "movsxd rcx, dword ptr [rdx+rcx*4]" in result.text
    assert result.stats.rebased_indexed_symbols == 1


def test_normalizer_rejects_unproven_indexed_symbol_rebase():
    normalizer = _load_normalizer()
    source = _structural_export(
        "jpt_A dd 0\n"
        "    movsxd rcx, dword ptr (jpt_A - 180001000h)[rdx+rcx*4]\n"
    )

    with pytest.raises(normalizer.MasmNormalizationError, match="matching LEA"):
        normalizer.normalize_masm_text(source)


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


def test_all_hash_bound_sources_normalize_without_portability_residue():
    normalizer = _load_normalizer()
    manifest = json.loads(
        (REPO / "samples" / "src" / "masm" / "hash_bound_seven_manifest.json").read_text()
    )

    total_changes = 0
    for record in manifest["fixtures"]:
        source = (REPO / "samples" / "src" / "masm" / record["masm"]).read_text()
        result = normalizer.normalize_masm_text(source)
        total_changes += result.stats.total
        assert not re.search(r"\+[0-9A-Fa-f]+h\+var_[0-9A-Fa-f]+\b", result.text)
        assert not re.search(
            r"\([A-Za-z_][A-Za-z0-9_]* - [0-9A-Fa-f]+h\)\[", result.text
        )
        assert "lock seto" not in result.text.lower()

    assert total_changes > 0
