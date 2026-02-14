"""Unit tests for export to C logic layer.

These tests verify the pure Python logic without requiring IDA Pro.
"""
from __future__ import annotations

from d810.ui.actions.export_to_c_logic import (
    CExportSettings,
    build_metadata_comment,
    build_sample_header_comment,
    format_c_output,
    format_sample_compatible_c,
    sanitize_c_identifier,
    sanitize_filename,
    suggest_filename,
)


class TestSanitizeFilename:
    """Test filename sanitization."""

    def test_basic_name(self):
        """Test basic alphanumeric name passes through."""
        assert sanitize_filename("my_function") == "my_function"

    def test_removes_invalid_chars(self):
        """Test removal of invalid filename characters."""
        assert sanitize_filename("my::func<int>") == "my__func_int_"
        assert sanitize_filename("operator<<") == "operator__"
        assert sanitize_filename('bad/path\\chars') == "bad_path_chars"

    def test_replaces_spaces(self):
        """Test spaces are replaced with underscores."""
        assert sanitize_filename("my func name") == "my_func_name"

    def test_limits_length(self):
        """Test long names are truncated."""
        long_name = "a" * 200
        result = sanitize_filename(long_name)
        assert len(result) == 100
        assert result == "a" * 100

    def test_empty_string(self):
        """Test empty string handling."""
        assert sanitize_filename("") == ""


class TestSuggestFilename:
    """Test filename suggestion."""

    def test_adds_extension(self):
        """Test .c extension is added."""
        assert suggest_filename("my_function") == "my_function.c"

    def test_sanitizes_name(self):
        """Test name is sanitized before adding extension."""
        assert suggest_filename("my::func") == "my__func.c"
        assert suggest_filename("operator<<") == "operator__.c"


class TestSanitizeCIdentifier:
    """Test C identifier sanitization."""

    def test_basic_identifier(self):
        """Test basic identifier passes through."""
        assert sanitize_c_identifier("my_func") == "my_func"
        assert sanitize_c_identifier("MyFunc123") == "MyFunc123"

    def test_replaces_invalid_chars(self):
        """Test invalid C identifier characters are replaced."""
        assert sanitize_c_identifier("my::func") == "my__func"
        assert sanitize_c_identifier("operator<<") == "operator__"
        assert sanitize_c_identifier("my-func") == "my_func"

    def test_prepends_underscore_if_starts_with_digit(self):
        """Test identifiers starting with digits get underscore prefix."""
        assert sanitize_c_identifier("123start") == "_123start"
        assert sanitize_c_identifier("9var") == "_9var"

    def test_doesnt_modify_valid_with_digit(self):
        """Test valid identifiers with digits in middle/end unchanged."""
        assert sanitize_c_identifier("func123") == "func123"
        assert sanitize_c_identifier("my_func_2") == "my_func_2"


class TestBuildMetadataComment:
    """Test metadata comment generation."""

    def test_empty_stats(self):
        """Test empty or None stats returns empty string."""
        assert build_metadata_comment(None) == ""
        assert build_metadata_comment({}) == ""

    def test_optimizer_matches(self):
        """Test optimizer matches are included."""
        stats = {"optimizer_matches": {"OpaquePredicate": 5, "ConstantFolding": 3}}
        comment = build_metadata_comment(stats)
        assert "Optimizer matches:" in comment
        assert "OpaquePredicate: 5" in comment
        assert "ConstantFolding: 3" in comment

    def test_rule_matches(self):
        """Test rule matches are included."""
        stats = {"rule_matches": {"MBARule_Add": 3, "MBARule_Xor": 7}}
        comment = build_metadata_comment(stats)
        assert "Rule matches:" in comment
        assert "MBARule_Add: 3" in comment
        assert "MBARule_Xor: 7" in comment

    def test_cfg_patches(self):
        """Test CFG patches are included."""
        stats = {
            "cfg_patches": {
                "FlatteningRule": {"uses": 2, "total_patches": 15},
            }
        }
        comment = build_metadata_comment(stats)
        assert "CFG rule patches:" in comment
        assert "FlatteningRule: 2 uses, 15 patches" in comment

    def test_totals(self):
        """Test total counts are included."""
        stats = {"total_rule_firings": 42, "total_cycles_detected": 3}
        comment = build_metadata_comment(stats)
        assert "Total rule firings: 42" in comment
        assert "Cycles detected and broken: 3" in comment

    def test_complete_stats(self):
        """Test complete stats with all sections."""
        stats = {
            "optimizer_matches": {"OpaquePredicate": 5},
            "rule_matches": {"MBARule_Add": 3},
            "cfg_patches": {"FlatteningRule": {"uses": 2, "total_patches": 15}},
            "total_rule_firings": 8,
            "total_cycles_detected": 1,
        }
        comment = build_metadata_comment(stats)
        # Check structure
        assert comment.startswith("/*")
        assert comment.endswith("*/")
        assert "d810ng Deobfuscation Metadata" in comment
        # Check all sections present
        assert "Optimizer matches:" in comment
        assert "Rule matches:" in comment
        assert "CFG rule patches:" in comment
        assert "Total rule firings: 8" in comment

    def test_sorted_output(self):
        """Test that items are sorted alphabetically."""
        stats = {
            "optimizer_matches": {"ZRule": 1, "ARule": 2, "MRule": 3},
        }
        comment = build_metadata_comment(stats)
        lines = comment.splitlines()
        # Find the optimizer matches section
        rule_lines = [l for l in lines if "Rule:" in l]
        assert len(rule_lines) == 3
        # Check they're sorted
        assert "ARule" in rule_lines[0]
        assert "MRule" in rule_lines[1]
        assert "ZRule" in rule_lines[2]


class TestFormatCOutput:
    """Test C output formatting."""

    def test_basic_output(self):
        """Test basic C output structure."""
        output = format_c_output(
            func_name="my_func",
            func_ea=0x401000,
            pseudocode_lines=["int my_func(int x) {", "  return x + 1;", "}"],
        )
        # Check header comment
        assert "Function: my_func" in output
        assert "0x401000" in output
        assert "d810ng" in output
        # Check standard includes
        assert "#include <stdint.h>" in output
        assert "#include <stdbool.h>" in output
        # Check type aliases
        assert "typedef uint8_t _BYTE;" in output
        assert "typedef uint32_t _DWORD;" in output
        # Check function body
        assert "int my_func(int x) {" in output
        assert "  return x + 1;" in output

    def test_with_metadata(self):
        """Test output includes metadata when provided."""
        metadata = {
            "optimizer_matches": {"OpaquePredicate": 5},
            "total_rule_firings": 5,
        }
        output = format_c_output(
            func_name="test_func",
            func_ea=0x400000,
            pseudocode_lines=["void test_func() {}"],
            metadata=metadata,
        )
        # Check metadata comment
        assert "d810ng Deobfuscation Metadata" in output
        assert "OpaquePredicate: 5" in output
        assert "Total rule firings: 5" in output

    def test_with_local_types(self):
        """Test output includes local types when provided."""
        local_types = [
            "struct MyStruct {",
            "  int field1;",
            "  char field2;",
            "};",
        ]
        output = format_c_output(
            func_name="test_func",
            func_ea=0x400000,
            pseudocode_lines=["void test_func() {}"],
            local_types=local_types,
        )
        # Check local types section
        assert "Local type declarations" in output
        assert "struct MyStruct {" in output
        assert "  int field1;" in output

    def test_timestamp_present(self):
        """Test timestamp is included in header."""
        output = format_c_output(
            func_name="test_func",
            func_ea=0x400000,
            pseudocode_lines=["void test_func() {}"],
        )
        assert "Exported:" in output
        # Check it looks like a timestamp (basic sanity check)
        assert "20" in output  # Year should be in 2000s

    def test_all_ida_types_defined(self):
        """Test all common IDA types are defined."""
        output = format_c_output(
            func_name="test_func",
            func_ea=0x400000,
            pseudocode_lines=["void test_func() {}"],
        )
        # Check byte types
        assert "typedef uint8_t _BYTE;" in output
        assert "typedef uint16_t _WORD;" in output
        assert "typedef uint32_t _DWORD;" in output
        assert "typedef uint64_t _QWORD;" in output
        # Check signed types
        assert "typedef int8_t __int8;" in output
        assert "typedef int16_t __int16;" in output
        assert "typedef int32_t __int32;" in output
        assert "typedef int64_t __int64;" in output
        # Check bool types
        assert "typedef bool _BOOL1;" in output
        assert "typedef int32_t _BOOL4;" in output

    def test_multiline_pseudocode(self):
        """Test multiline pseudocode is preserved."""
        lines = [
            "int complex_func(int a, int b) {",
            "  int result = 0;",
            "  for (int i = 0; i < a; i++) {",
            "    result += b;",
            "  }",
            "  return result;",
            "}",
        ]
        output = format_c_output(
            func_name="complex_func", func_ea=0x401000, pseudocode_lines=lines
        )
        # Check all lines are present
        for line in lines:
            assert line in output

    def test_no_metadata_no_extra_comment(self):
        """Test that no metadata produces no extra comment block."""
        output = format_c_output(
            func_name="test_func",
            func_ea=0x400000,
            pseudocode_lines=["void test_func() {}"],
            metadata=None,
        )
        # Should not have metadata section
        assert "d810ng Deobfuscation Metadata" not in output
        # But should have main header comment
        assert "Function: test_func" in output

    def test_infers_collapsed_locals(self):
        """Collapsed local declarations should emit fallback local vars."""
        output = format_c_output(
            func_name="collapsed_locals",
            func_ea=0x401000,
            pseudocode_lines=[
                "__int64 __fastcall collapsed_locals(__int64 a1)",
                "{",
                "    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD \"+\" TO EXPAND]",
                "",
                "    v4 = a1 + 1;",
                "    return v4;",
                "}",
            ],
        )
        assert "__int64 v4;" in output


class TestCExportSettings:
    """Test CExportSettings dataclass."""

    def test_default_values(self):
        """Test default values are correct."""
        settings = CExportSettings()
        assert settings.sample_compatible is False
        assert settings.recursion_depth == 0
        assert settings.export_globals is False
        assert settings.output_path == ""

    def test_custom_values(self):
        """Test custom values can be set."""
        settings = CExportSettings(
            sample_compatible=True,
            recursion_depth=3,
            export_globals=True,
            output_path="/tmp/output.c",
        )
        assert settings.sample_compatible is True
        assert settings.recursion_depth == 3
        assert settings.export_globals is True
        assert settings.output_path == "/tmp/output.c"


class TestBuildSampleHeaderComment:
    """Test sample header comment generation."""

    def test_basic_header(self):
        """Test basic header without metadata."""
        comment = build_sample_header_comment("test_func", 0x401000)
        assert comment.startswith("/**")
        assert comment.endswith("*/")
        assert "test_func" in comment
        assert "0x401000" in comment
        assert "-O0 -g -fno-inline -fno-builtin" in comment

    def test_with_optimizer_metadata(self):
        """Test header includes optimizer metadata."""
        metadata = {"optimizer_matches": {"OpaquePredicate": 5, "ConstantFolding": 3}}
        comment = build_sample_header_comment("test_func", 0x401000, metadata)
        assert "d810ng Deobfuscation Applied:" in comment
        assert "OpaquePredicate: 5 matches" in comment
        assert "ConstantFolding: 3 matches" in comment

    def test_with_rule_metadata(self):
        """Test header includes rule match summary."""
        metadata = {"rule_matches": {"MBARule_Add": 3, "MBARule_Xor": 7}}
        comment = build_sample_header_comment("test_func", 0x401000, metadata)
        assert "MBA rules: 10 simplifications" in comment

    def test_compilation_flags_always_present(self):
        """Test compilation flags are always included."""
        comment = build_sample_header_comment("func", 0x400000)
        assert "Compilation flags (recommended):" in comment
        assert "-O0 -g -fno-inline -fno-builtin" in comment


class TestFormatSampleCompatibleC:
    """Test sample-compatible C output formatting."""

    def test_basic_structure(self):
        """Test basic sample-compatible output structure."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["int test_func(int x) {", "  return x + 1;", "}"],
        )
        # Check includes
        assert '#include "polyfill.h"' in output
        assert '#include "platform.h"' in output
        # Check sink variable
        assert "volatile int g_test_func_sink = 0;" in output
        # Check EXPORT and noinline
        assert "EXPORT __attribute__((noinline))" in output
        # Check function code
        assert "int test_func(int x) {" in output
        assert "  return x + 1;" in output

    def test_header_comment_present(self):
        """Test header comment is included."""
        output = format_sample_compatible_c(
            func_name="my_func",
            func_ea=0x400000,
            pseudocode_lines=["void my_func() {}"],
        )
        assert "/**" in output
        assert "my_func" in output
        assert "0x400000" in output
        assert "-O0 -g -fno-inline" in output

    def test_with_metadata(self):
        """Test metadata is included in header comment."""
        metadata = {
            "optimizer_matches": {"OpaquePredicate": 5},
            "rule_matches": {"MBARule_Add": 3},
        }
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func() {}"],
            metadata=metadata,
        )
        assert "d810ng Deobfuscation Applied:" in output
        assert "OpaquePredicate: 5 matches" in output
        assert "MBA rules: 3 simplifications" in output

    def test_with_local_types(self):
        """Test local types are included."""
        local_types = ["struct MyStruct {", "  int field1;", "};"]
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func() {}"],
            local_types=local_types,
        )
        assert "Local type declarations" in output
        assert "struct MyStruct {" in output
        assert "  int field1;" in output

    def test_with_global_declarations(self):
        """Test global declarations are included as volatile."""
        globals_decls = ["extern int global_var;", "int another_global;"]
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func() {}"],
            global_declarations=globals_decls,
        )
        assert "Referenced globals" in output
        # Globals should be made volatile
        assert "extern volatile int global_var;" in output
        assert "volatile int another_global;" in output

    def test_infers_globals_when_not_provided(self):
        """Test globals are inferred from pseudocode when not provided."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=[
                "int test_func(void) {",
                "  return dword_1234ABCD + 1;",
                "}",
            ],
        )
        assert "extern volatile unsigned __int32 dword_1234ABCD;" in output

    def test_infers_forward_declarations(self):
        """Test call targets are forward-declared for C99 compatibility."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=[
                "int test_func(void) {",
                "  return helper_call(7);",
                "}",
            ],
        )
        assert "extern int helper_call();" in output

    def test_global_already_volatile(self):
        """Test globals already volatile are not duplicated."""
        globals_decls = ["volatile int already_volatile;"]
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func() {}"],
            global_declarations=globals_decls,
        )
        # Should not add duplicate volatile
        assert "volatile int already_volatile;" in output
        assert "volatile volatile" not in output

    def test_sink_variable_naming(self):
        """Test sink variable uses sanitized function name."""
        output = format_sample_compatible_c(
            func_name="my::func<int>",
            func_ea=0x401000,
            pseudocode_lines=["void func() {}"],
        )
        # Function name should be sanitized for C identifier
        assert "volatile int g_my__func_int__sink = 0;" in output

    def test_export_macro_position(self):
        """Test EXPORT macro is placed before function signature."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=[
                "int test_func(int x) {",
                "  return x + 1;",
                "}",
            ],
        )
        # Check EXPORT is on same line as function signature
        lines = output.splitlines()
        export_line = [line for line in lines if "EXPORT __attribute__" in line]
        assert len(export_line) == 1
        assert "int test_func(int x)" in export_line[0]

    def test_multiline_function(self):
        """Test multiline function code is preserved."""
        pseudocode = [
            "int complex_func(int a, int b) {",
            "  int result = 0;",
            "  for (int i = 0; i < a; i++) {",
            "    result += b;",
            "  }",
            "  return result;",
            "}",
        ]
        output = format_sample_compatible_c(
            func_name="complex_func", func_ea=0x401000, pseudocode_lines=pseudocode
        )
        # All lines except first should be unchanged
        for line in pseudocode[1:]:
            assert line in output
        # First line should have EXPORT prepended
        assert "EXPORT __attribute__((noinline)) int complex_func(int a, int b) {" in output

    def test_complete_sample_format(self):
        """Test complete output matches expected sample format."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["int test_func(int x) {", "  return x + 1;", "}"],
            metadata={"optimizer_matches": {"OpaquePredicate": 2}},
        )

        # Verify order of sections
        lines = output.splitlines()
        sections = []
        for line in lines:
            if "/**" in line:
                sections.append("header_comment")
            elif '#include "polyfill.h"' in line:
                sections.append("polyfill_include")
            elif '#include "platform.h"' in line:
                sections.append("platform_include")
            elif "volatile int g_test_func_sink" in line:
                sections.append("sink_variable")
            elif "EXPORT __attribute__" in line:
                sections.append("function")

        # Check sections appear in correct order
        assert sections.index("header_comment") < sections.index("polyfill_include")
        assert sections.index("polyfill_include") < sections.index("platform_include")
        assert sections.index("platform_include") < sections.index("sink_variable")
        assert sections.index("sink_variable") < sections.index("function")

    def test_infers_collapsed_locals(self):
        """Collapsed local declarations should emit fallback local vars."""
        output = format_sample_compatible_c(
            func_name="collapsed_locals",
            func_ea=0x401000,
            pseudocode_lines=[
                "__int64 __fastcall collapsed_locals(__int64 a1, __int64 a2)",
                "{",
                "    // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD \"+\" TO EXPAND]",
                "",
                "    v2 = a1 + a2;",
                "    return v2;",
                "}",
            ],
        )
        assert "__int64 v2;" in output
