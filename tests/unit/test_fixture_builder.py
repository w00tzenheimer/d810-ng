"""Unit tests for the pure-Python fixture-builder logic (ticket d81-rtfh).

No IDA imports — everything here is testable without an IDA runtime. The
IDA-bound extract/resolve worker is covered by
``tests/system/e2e/test_fixture_idb_worker.py``.
"""

import os
import re
import struct
from pathlib import Path

import pytest

from d810.testing.fixture_builder import CallSiteFold, detect_indirect_call_folds

REPO = Path(__file__).resolve().parents[2]
SUB = (REPO / "samples/src/masm/sub_1815C8C30.asm").read_text()


def test_committed_windows_fixture_contains_every_masm_export():
    """Do not let a stale DLL turn tracked MASM regressions into skips."""
    fixture = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    required_exports = tuple(
        sorted(source.stem for source in (REPO / "samples/src/masm").glob("*.asm"))
    )
    missing = [
        name for name in required_exports if name.encode("ascii") + b"\0" not in fixture
    ]
    assert missing == []


def _pe_sections(blob: bytes) -> tuple[tuple[str, int], ...]:
    pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    assert blob[pe_offset : pe_offset + 4] == b"PE\0\0"
    section_count = struct.unpack_from("<H", blob, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", blob, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    return tuple(
        (
            blob[offset : offset + 8].rstrip(b"\0").decode("ascii"),
            struct.unpack_from("<I", blob, offset + 36)[0],
        )
        for offset in (table + 40 * index for index in range(section_count))
    )


def test_committed_hodur_constants_are_read_only_without_reclassifying_all_data():
    """HODCONST is read-only while ordinary data sections retain write access."""
    sections = _pe_sections((REPO / "samples/bins/libobfuscated.dll").read_bytes())
    write_flag = 0x80000000
    hodconst = [chars for name, chars in sections if name == "HODCONST"]
    assert len(hodconst) == 1
    assert hodconst[0] & write_flag == 0

    ordinary_data = {
        name: chars for name, chars in sections if name in {".data", "_DATA"}
    }
    assert ".data" in ordinary_data
    assert all(chars & write_flag for chars in ordinary_data.values())


def test_committed_windows_fixture_exports_required_system_cases():
    """Required named cases must remain discoverable in a fresh IDA DB."""
    fixture = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    required_exports = (
        "_hodur_func",
        "abc_f6_add_dispatch",
        "approov_real_pattern",
        "high_fan_in_pattern",
        "resolve_api",
    )
    missing = [
        name for name in required_exports if name.encode("ascii") + b"\0" not in fixture
    ]
    assert missing == []


def test_committed_hodur_egglog_probe_is_isolated_from_comprehensive_fixture():
    """The focused native proof probe must not perturb shared fixture layout."""
    comprehensive = (REPO / "samples/bins/libobfuscated.dll").read_bytes()
    probe = (REPO / "samples/bins/hodur_egglog_probe.dll").read_bytes()
    export = b"Hodur_ComplementMaskResidual\0"

    assert export not in comprehensive
    assert export in probe


def test_masm_builder_supports_masm_only_probe_source_directory():
    """A dedicated probe build links only its explicitly scoped MASM corpus."""
    build_script = (REPO / "samples/scripts/build_masm.sh").read_text()
    makefile = (REPO / "samples/Makefile").read_text()

    assert "MASM_SOURCE_DIR" in build_script
    assert "MASM_INCLUDE_C" in build_script
    assert "hodur-egglog-probe:" in makefile
    assert "MASM_SOURCE_DIR=src/masm_probes" in makefile
    assert "MASM_INCLUDE_C=0" in makefile
    assert "-DD810_FREESTANDING_FIXTURE=1" in build_script


def test_masm_builder_exports_public_c_text_symbols():
    build_script = (REPO / "samples/scripts/build_masm.sh").read_text()
    assert "llvm-nm" in build_script
    assert "--defined-only --extern-only" in build_script
    assert 'export_flags+=("/EXPORT:$symbol")' in build_script


def _extract_hodur_crt_branches(source: str) -> tuple[str, str]:
    """Extract the two branches of Hodur's outer CRT preprocessor guard."""

    lines = source.splitlines(keepends=True)
    directive_re = re.compile(
        r"^\s*#\s*(if|ifdef|ifndef|elif|else|endif)\b(.*)$"
    )
    target_re = re.compile(
        r"^\s*defined\s*\(\s*D810_FREESTANDING_FIXTURE\s*\)\s*$"
    )
    stack: list[dict[str, int | bool | None]] = []
    target: dict[str, int | bool | None] | None = None
    target_occurrences = 0

    for index, line in enumerate(lines):
        match = directive_re.match(line)
        if match is None:
            continue
        kind, expression = match.groups()
        expression = expression.strip()
        if kind in {"if", "ifdef", "ifndef"}:
            is_target = kind == "if" and target_re.fullmatch(expression) is not None
            if is_target:
                target_occurrences += 1
                if target_occurrences > 1 or stack:
                    raise ValueError("target guard must occur exactly once at top level")
                target = {
                    "start": index,
                    "else": None,
                    "end": None,
                    "has_else": False,
                }
            stack.append(
                {
                    "seen_else": False,
                    "target": is_target,
                }
            )
            continue

        if not stack:
            raise ValueError(f"unmatched #{kind}")
        frame = stack[-1]
        if kind == "elif":
            if bool(frame["seen_else"]):
                raise ValueError("#elif after #else")
            if bool(frame["target"]):
                raise ValueError("target guard must not use #elif")
            if target_re.fullmatch(expression) is not None:
                target_occurrences += 1
            continue
        if kind == "else":
            if bool(frame["seen_else"]):
                raise ValueError("duplicate #else")
            frame["seen_else"] = True
            if bool(frame["target"]):
                assert target is not None
                target["else"] = index
                target["has_else"] = True
            continue

        stack.pop()
        if bool(frame["target"]):
            assert target is not None
            target["end"] = index

    if stack:
        raise ValueError("unterminated preprocessor directive")
    if target_occurrences != 1 or target is None:
        raise ValueError("missing target guard")
    if not bool(target["has_else"]):
        # ``has_else`` is populated below from the captured delimiter.
        if target["else"] is None:
            raise ValueError("target guard is missing #else")
    if target["else"] is None or target["end"] is None:
        raise ValueError("target guard is incomplete")
    start = int(target["start"])
    else_index = int(target["else"])
    end = int(target["end"])
    return "".join(lines[start + 1 : else_index]), "".join(lines[else_index + 1 : end])


def test_hodur_crt_shim_is_only_enabled_for_local_freestanding_build():
    """The source guard keeps freestanding and authoritative CRT contracts separate."""

    source = (REPO / "samples/src/c/hodur_c2_flattened.c").read_text()
    freestanding, authoritative = _extract_hodur_crt_branches(source)

    assert "extern int printf(const char *format, ...);" in freestanding
    assert "#define memcpy(destination, source, count)" in freestanding
    assert "__builtin_memcpy((destination), (source), (count))" in freestanding
    assert "#include <stdio.h>" not in freestanding
    assert "#include <string.h>" not in freestanding
    assert "#include <stdio.h>" in authoritative
    assert "#include <string.h>" in authoritative
    assert "extern int printf" not in authoritative
    assert "__builtin_memcpy" not in authoritative


@pytest.mark.parametrize(
    "source",
    [
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "#if INNER\n"
        "nested\n"
        "#else\n"
        "nested else\n"
        "#else\n"
        "duplicate nested else\n"
        "#endif\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#else\n"
        "authoritative\n"
        "#elif(0)\n"
        "duplicate target branch\n"
        "#endif\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#if(INNER)\n"
        "nested\n"
        "#endif\n"
        "#else\n"
        "authoritative\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#elif(0)\n"
        "authoritative\n"
        "#endif\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#else\n"
        "authoritative\n"
        "#endif\n"
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "duplicate target\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#else\n"
        "authoritative\n"
        "#endif\n"
        "#endif\n",
        "#if defined(D810_FREESTANDING_FIXTURE)\n"
        "freestanding\n"
        "#else\n"
        "authoritative\n"
        "#else\n"
        "#endif\n",
    ],
)
def test_hodur_crt_branch_extractor_rejects_malformed_nesting(source: str) -> None:
    with pytest.raises(ValueError):
        _extract_hodur_crt_branches(source)


def test_hodur_crt_branch_extractor_accepts_flexible_directive_spacing() -> None:
    source = (
        "\t# if\tdefined ( D810_FREESTANDING_FIXTURE )\n"
        "freestanding\n\t# else\nauthoritative\n\t# endif\n"
    )
    assert _extract_hodur_crt_branches(source) == (
        "freestanding\n",
        "authoritative\n",
    )


def test_detects_slot_const_and_reg_from_committed_asm():
    folds = detect_indirect_call_folds(SUB)
    assert (
        CallSiteFold(
            slot_symbol="off_18210A360",
            const=0x64E2C558D421136,
            call_reg="rax",
            materialized=None,  # committed slot is a reloc expr, not a raw dq
        )
        in folds
    )


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
from d810.testing.fixture_builder import (  # noqa: E402
    ResolvedTarget,
    RetargetAction,
    RetargetPlan,
    plan_retargets,
    apply_retargets,
    render_stub,
)


def test_plan_retargets_keeps_leaf_import_skips_sub():
    folds = [
        CallSiteFold("off_A", 0x10, "rax", materialized=0x100),  # -> va 0x110
        CallSiteFold("off_B", 0x20, "rcx", materialized=0x200),  # -> va 0x220
    ]
    resolved = {
        0x110: ResolvedTarget(0x110, "rand", is_import=True, retargetable=True),
        0x220: ResolvedTarget(
            0x220, "sub_1815DF1C0", is_import=False, retargetable=False
        ),
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
from d810.testing.fixture_builder import (  # noqa: E402
    emit_fixture_case,
    upsert_case_in_list,
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
    lst = 'DAC_MASM_CASES = [\n    DeobfuscationCase(\n        function="old",\n    ),\n]\n'
    out = upsert_case_in_list(lst, "sub_NEW", emit_fixture_case("sub_NEW", "p.json"))
    assert 'function="old"' in out
    assert 'function="sub_NEW"' in out
    assert out.count("DeobfuscationCase(") == 2


def test_upsert_replaces_existing_case_no_duplicate():
    base = upsert_case_in_list(
        "DAC_MASM_CASES = [\n]\n", "sub_X", emit_fixture_case("sub_X", "p.json")
    )
    again = upsert_case_in_list(base, "sub_X", emit_fixture_case("sub_X", "q.json"))
    assert again.count('function="sub_X"') == 1
    assert 'project="q.json"' in again


# --------------------------------------------------------------------------- #
# Task 5: build + verify subprocess orchestration
# --------------------------------------------------------------------------- #
import subprocess as _sp  # noqa: E402

from d810.testing.fixture_builder import (  # noqa: E402
    build_fixture_dll,
    verify_fixture_case,
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


def test_masm_builder_verifies_scoped_d810_exports_behaviorally(tmp_path):
    """The real post-link verifier accepts present exports and rejects missing ones."""

    script = REPO / "samples/scripts/build_masm.sh"
    asm_source = tmp_path / "fixture.asm"
    asm_source.write_text(
        "PUBLIC fixture_basename\n"
        "PUBLIC unrelated_public_symbol\n"
        "; D810_EXPORT explicit_fixture_anchor\n"
    )
    export_dump = tmp_path / "exports.txt"
    export_dump.write_text(
        "Import Table:\n"
        "  missing_explicit_anchor\n"
        "Export Table:\n"
        "  1 0x1000 fixture_basename\n"
        "  2 0x1010 explicit_fixture_anchor\n"
        "Debug Table:\n"
        "  missing_explicit_anchor\n"
    )

    present = _sp.run(
        [
            "bash",
            str(script),
            "--verify-source-exports",
            str(export_dump),
            "fixture_basename",
            str(asm_source),
        ],
        capture_output=True,
        text=True,
    )
    assert present.returncode == 0, present.stderr

    missing_dump = tmp_path / "missing-exports.txt"
    missing_dump.write_text(
        "Export Table:\n"
        "  1 0x1000 fixture_basename\n"
        "Debug Table:\n"
        "  explicit_fixture_anchor\n"
        "  unrelated_public_symbol\n"
    )
    missing = _sp.run(
        [
            "bash",
            str(script),
            "--verify-source-exports",
            str(missing_dump),
            "fixture_basename",
            str(asm_source),
        ],
        capture_output=True,
        text=True,
    )
    assert missing.returncode != 0
    assert "MISSING required MASM export: explicit_fixture_anchor" in missing.stderr
    assert "unrelated_public_symbol" not in missing.stderr


def test_masm_builder_rejects_required_symbol_present_only_in_import_table(tmp_path):
    script = REPO / "samples/scripts/build_masm.sh"
    asm_source = tmp_path / "fixture.asm"
    asm_source.write_text("; D810_EXPORT explicit_fixture_anchor\n")
    import_only_dump = tmp_path / "import-only.txt"
    import_only_dump.write_text(
        "Import Table:\n"
        "  7 0x2000 explicit_fixture_anchor\n"
        "Export Table:\n"
        "  1 0x1000 fixture_basename\n"
        "Debug Table:\n"
    )

    rejected = _sp.run(
        [
            "bash",
            str(script),
            "--verify-source-exports",
            str(import_only_dump),
            "fixture_basename",
            str(asm_source),
        ],
        capture_output=True,
        text=True,
    )

    assert rejected.returncode != 0
    assert "MISSING required MASM export: explicit_fixture_anchor" in rejected.stderr


def test_masm_builder_failed_link_cannot_reuse_stale_outputs(tmp_path):
    """A failed link must remove stale DLL, PDB, and export evidence first."""

    script = REPO / "samples/scripts/build_masm.sh"
    output_dir = tmp_path / "bins"
    output_dir.mkdir()
    dll = output_dir / "stale_fixture.dll"
    pdb = output_dir / "stale_fixture.pdb"
    export_dump = output_dir / "stale_fixture.exports.txt"
    linklog = tmp_path / "link.log"
    for artifact in (dll, pdb, export_dump):
        artifact.write_bytes(b"stale artifact")
    linklog.write_text("lld-link: fatal test failure\n")

    failed = _sp.run(
        [
            "bash",
            str(script),
            "--test-failed-link-contract",
            str(output_dir),
            "stale_fixture",
            str(export_dump),
            str(linklog),
        ],
        capture_output=True,
        text=True,
    )

    assert failed.returncode != 0
    assert "link failed" in failed.stderr
    assert not dll.exists()
    assert not pdb.exists()
    assert not export_dump.exists()


def test_masm_builder_exports_only_explicit_d810_directives():
    """Additional MASM exports are opt-in, never every PUBLIC symbol."""

    script = (REPO / "samples/scripts/build_masm.sh").read_text()
    assert "D810_EXPORT" in script
    assert 'public_names="$(explicit_d810_exports "$src")"' in script
    assert 'export_flags+=("/EXPORT:$public_name")' in script
    assert 'export_flags+=("/EXPORT:$marker")' in script
    assert "PUBLIC[[:space:]]+([A-Za-z0-9_]+)" not in script


def test_windows_builder_preserves_explicit_masm_export_contract() -> None:
    """The authoritative reversepc build must expose MASM oracle anchors."""

    makefile = (REPO / "samples/Makefile").read_text()
    exporter = (REPO / "samples/scripts/generate_auto_exports.ps1").read_text()

    assert "$(AUTO_EXPORTS_RSP): $(OBJS) $(MASM_ASM)" in makefile
    assert '-MasmSources "$(MASM_ASM)"' in makefile
    assert "D810_EXPORT" in exporter
    assert "d810_callsite_" in exporter
    assert "$MasmSources" in exporter
    assert 'throw "MASM source' in exporter


def test_authoritative_windows_builder_marks_hodconst_read_only() -> None:
    """The Microsoft-link release path must retain immutable Hodur constants."""

    dry_run = _sp.run(
        [
            "make",
            "-n",
            "-B",
            "TARGET_OS=windows",
            "BINARY_NAME=fixture_dry_run",
            "USING_CLANG_CL=1",
            "CC_BASE=clang-cl.exe",
        ],
        cwd=REPO / "samples",
        capture_output=True,
        text=True,
    )
    assert dry_run.returncode == 0, dry_run.stderr
    assert "D810_FREESTANDING_FIXTURE" not in dry_run.stdout
    link_lines = [line for line in dry_run.stdout.splitlines() if "link.exe" in line]
    assert len(link_lines) == 1
    assert "/SECTION:HODCONST,R" in link_lines[0].split()


def test_masm_builder_pins_layout_sensitive_object_at_link_tail(tmp_path) -> None:
    """The portable MASM build must preserve the complete append-only layout."""

    samples = tmp_path / "samples"
    scripts = samples / "scripts"
    scripts.mkdir(parents=True)
    builder = scripts / "build_masm.sh"
    source_builder = REPO / "samples/scripts/build_masm.sh"
    builder.write_text(source_builder.read_text())
    builder.chmod(source_builder.stat().st_mode)

    tools = tmp_path / "tools"
    tools.mkdir()

    def executable(name: str, source: str) -> Path:
        path = tools / name
        path.write_text("#!/usr/bin/env bash\nset -euo pipefail\n" + source)
        path.chmod(0o755)
        return path

    assembler = executable(
        "ml64",
        'for arg in "$@"; do\n'
        '  case "$arg" in /Fo*) touch "${arg#/Fo}" ;; esac\n'
        "done\n",
    )
    link_args = tmp_path / "link-args.txt"
    linker = executable(
        "linker",
        'printf \'%s\\n\' "$@" > "$D810_TEST_LINK_ARGS"\n'
        'for arg in "$@"; do\n'
        '  case "$arg" in\n'
        '    /OUT:*) printf MZ > "${arg#/OUT:}" ;;\n'
        '    /PDB:*) printf \'Microsoft C/C++ MSF 7.00\' > "${arg#/PDB:}" ;;\n'
        "  esac\n"
        "done\n",
    )
    objdump = executable(
        "objdump",
        "echo 'Export Table:'\n"
        "ordinal=1\n"
        'while IFS= read -r arg; do\n'
        '  case "$arg" in\n'
        '    /EXPORT:*) printf \'%s 0x1000 %s\\n\' "$ordinal" "${arg#/EXPORT:}"; ordinal=$((ordinal + 1)) ;;\n'
        "  esac\n"
        'done < "$D810_TEST_LINK_ARGS"\n'
        "echo 'Debug Table:'\n",
    )
    noop = executable("noop", "exit 0\n")

    masm_sources = REPO / "samples/src/masm"
    env = {
        **os.environ,
        "BINARY_NAME": "fixture_link_order",
        "CC": str(noop),
        "ML64": str(assembler),
        "LINKER": str(linker),
        "NM": str(noop),
        "LLVM_OBJDUMP": str(objdump),
        "MASM_SOURCE_DIR": str(masm_sources),
        "MASM_INCLUDE_C": "0",
        "MASM_FUNCS": "",
        "D810_TEST_LINK_ARGS": str(link_args),
    }
    built = _sp.run(
        ["bash", str(builder)],
        cwd=samples,
        env=env,
        capture_output=True,
        text=True,
    )
    assert built.returncode == 0, built.stderr

    args = link_args.read_text().splitlines()
    linked_masm = [Path(arg).stem for arg in args if arg.endswith(".obj")]
    source_names = {source.stem for source in masm_sources.glob("*.asm")}
    assert set(linked_masm) == source_names
    assert len(linked_masm) == len(source_names)
    assert linked_masm[-1] == "sub_7FF855576B50"
    assert "/SECTION:HODCONST,R" in args


def test_windows_builder_uses_native_masm_relative_jump_table() -> None:
    """The authoritative ml64 build needs no post-link table repair."""

    makefile = (REPO / "samples/Makefile").read_text()
    fixture = (REPO / "samples/src/masm/sub_7FF856533A20.asm").read_text()

    assert "patch_relative_jump_table" not in makefile
    assert "; D810_EXPORT d810_relative_jpt_sub_7FF856533A20" in fixture
    assert "d810_relative_jpt_sub_7FF856533A20:" in fixture
    assert "jpt_7FF856535804:" in fixture
    assert "dd loc_7FF856535806 - jpt_7FF856535804" in fixture
    table_targets = re.findall(
        r"^\s*dd\s+(loc_[0-9A-F]+)\s+-\s+jpt_7FF856535804$",
        fixture,
        re.MULTILINE,
    )
    assert len(table_targets) == 45
    table_start = fixture.index("jpt_7FF856535804:")
    assert fixture.index("OPTION NOSCOPED") < table_start
    assert not re.search(r"^PUBLIC loc_[0-9A-F]+$", fixture, re.MULTILINE)
    assert "jmp near ptr loc_7FF856533AF0" in fixture
    assert "imagerel" not in fixture
    assert "LABEL DWORD" not in fixture
    assert "::" not in fixture


def test_layered_masm_fixture_keeps_runtime_globals_writable() -> None:
    """Readonly placement lets Hex-Rays erase the captured outer dispatcher."""

    fixture = (REPO / "samples/src/masm/sub_7FF856533A20.asm").read_text()

    data_start = fixture.index("_DATA SEGMENT")
    data_end = fixture.index("_DATA ENDS")
    table_start = fixture.index("_TEXT SEGMENT", data_end)
    first_seed = fixture.index("dword_7FF85722E310 dd 33FFA28Fh")
    jump_table = fixture.index("jpt_7FF856535804:")

    assert data_start < first_seed < data_end < table_start < jump_table


def test_verify_sets_test_binary_env(tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["env"] = kw.get("env", {})
        return _sp.CompletedProcess(cmd, 0, "1 passed", "")

    ok = verify_fixture_case(tmp_path, "sub_X", "tmpfx", runner=fake_run)
    assert ok is True
    assert seen["env"].get("D810_TEST_BINARY") == "tmpfx.dll"
