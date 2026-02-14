"""Integration tests for exported C compilation.

These tests validate end-to-end export formatting behavior by writing generated
C source to disk and invoking a real C compiler in syntax-check mode.
"""
from __future__ import annotations

import shutil
import subprocess

import pytest

from d810.ui.actions.export_to_c_logic import (
    format_c_output,
    format_sample_compatible_c,
)
from tests.conftest import PROJECT_ROOT


def _compile_syntax_only(source_path: str, include_dirs: list[str] | None = None) -> None:
    """Compile a C file in syntax-only mode."""
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("No C compiler found in PATH (expected `cc`)")

    cmd = [compiler, "-std=c11", "-fsyntax-only"]
    for include_dir in include_dirs or []:
        cmd.extend(["-I", include_dir])
    cmd.append(source_path)

    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode == 0, (
        f"Failed to compile generated C source:\n"
        f"  command: {' '.join(cmd)}\n"
        f"  stdout:\n{result.stdout}\n"
        f"  stderr:\n{result.stderr}"
    )


@pytest.mark.integration
class TestExportToCCompileIntegration:
    """Validate exported C output is compilable in realistic workflows."""

    def test_normal_export_writes_and_compiles(self, tmp_path):
        """Normal export mode should produce syntax-valid standalone C."""
        pseudocode = [
            "_BOOL8 __fastcall plain_export(__int64 x)",
            "{",
            "  return x > 0;",
            "}",
        ]
        generated = format_c_output(
            func_name="plain_export",
            func_ea=0x401000,
            pseudocode_lines=pseudocode,
            metadata=None,
        )

        output_path = tmp_path / "plain_export.c"
        output_path.write_text(generated, encoding="utf-8")

        _compile_syntax_only(str(output_path))

    def test_sample_compatible_export_writes_and_compiles(self, tmp_path):
        """Sample-compatible export should compile with sample include shims."""
        pseudocode = [
            "int __fastcall sample_export(int a)",
            "{",
            "  SIZE_T n = (SIZE_T)a;",
            "  if (a == 0)",
            "    JUMPOUT(0x401000);",
            "  return helper_call((int)(dword_4010ABCD + n));",
            "}",
        ]
        generated = format_sample_compatible_c(
            func_name="sample_export",
            func_ea=0x401000,
            pseudocode_lines=pseudocode,
            metadata=None,
            global_declarations=None,  # exercise auto-inference path
        )

        output_path = tmp_path / "sample_export.c"
        output_path.write_text(generated, encoding="utf-8")

        sample_include = str(PROJECT_ROOT / "samples" / "include")
        _compile_syntax_only(str(output_path), include_dirs=[sample_include])

    def test_sample_compatible_collapsed_locals_compile(self, tmp_path):
        """Collapsed IDA local declarations should still yield compilable output."""
        pseudocode = [
            "__int64 __fastcall collapsed_case(__int64 a1, __int64 a2)",
            "{",
            "  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD \"+\" TO EXPAND]",
            "",
            "  v3 = a1 ^ a2;",
            "  return v3 + 1;",
            "}",
        ]
        generated = format_sample_compatible_c(
            func_name="collapsed_case",
            func_ea=0x402000,
            pseudocode_lines=pseudocode,
        )

        output_path = tmp_path / "collapsed_case.c"
        output_path.write_text(generated, encoding="utf-8")

        sample_include = str(PROJECT_ROOT / "samples" / "include")
        _compile_syntax_only(str(output_path), include_dirs=[sample_include])
