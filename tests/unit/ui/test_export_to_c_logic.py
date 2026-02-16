"""Unit tests for export to C logic layer.

These tests verify the pure Python logic without requiring IDA Pro.
"""
from __future__ import annotations

from d810.ui.actions.export_to_c_logic import (
    CExportSettings,
    apply_compile_safety_rewrites,
    build_metadata_comment,
    build_sample_header_comment,
    format_c_output,
    format_sample_compatible_c,
    replace_oword_assignments,
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
        assert "Deobfuscation applied:" in comment
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
        assert "// Compatibility shims for decompiler-emitted syntax" not in output
        # Check sink variable
        assert "volatile int g_test_func_sink = 0;" in output
        # Check EXPORT and D810_NOINLINE
        assert "EXPORT D810_NOINLINE" in output
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
        assert "Deobfuscation applied:" in output
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

    def test_handle_global_initializer_gets_cast(self):
        """HANDLE globals initialized from integers should be cast safely."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func(void) {}"],
            global_declarations=["volatile HANDLE qword_1234 = 0x2C0uLL;"],
        )
        assert "volatile HANDLE qword_1234 = (HANDLE)(ULONG_PTR)(0x2C0uLL);" in output

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

    def test_ignores_macro_like_and_polyfill_forward_decls(self):
        """Do not emit conflicting forward declarations for known helpers/macros."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=[
                "int test_func(__int64 a1) {",
                "  return LOBYTE(a1) + (int)(unsigned __int64)NtCurrentTeb();",
                "}",
            ],
        )
        assert "extern int LOBYTE();" not in output
        assert "extern int NtCurrentTeb();" not in output

    def test_infers_callback_symbol_forward_declaration(self):
        """Function symbols passed as callback args should be forward-declared."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=[
                "void test_func(void) {",
                "  CreateFiber(0, sub_7FFB207ADFE0, 0);",
                "}",
            ],
        )
        assert "extern int sub_7FFB207ADFE0();" in output

    def test_imported_declarations_are_normalized(self):
        """Known imported APIs should use canonical declaration spellings."""
        output = format_sample_compatible_c(
            func_name="test_func",
            func_ea=0x401000,
            pseudocode_lines=["void test_func(void) {}"],
            imported_function_declarations=[
                "intintintintextern (BOOL (int*)())(BOOL) (__stdcall int*IsThreadAFiber)();",
                "extern __int64 (__fastcall *RtlAcquireSRWLockExclusive)(int(long long (*)(_QWORD))(_QWORD));",
                "extern LPVOID (__stdcall *TlsGetValue)(int(LPVOID (*)(DWORD))(DWORD dwTlsIndex));",
            ],
        )
        assert "extern BOOL (__stdcall *IsThreadAFiber)(void);" in output
        assert "extern void (__stdcall *RtlAcquireSRWLockExclusive)(void *SRWLock);" in output
        assert "extern LPVOID (__stdcall *TlsGetValue)(DWORD dwTlsIndex);" in output

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
        export_line = [line for line in lines if "EXPORT D810_NOINLINE" in line]
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
        assert "EXPORT D810_NOINLINE int complex_func(int a, int b) {" in output

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
            elif "EXPORT D810_NOINLINE" in line:
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

    def test_oword_typedef_not_emitted_inline(self):
        """_OWORD should come from ida_types.h via polyfill.h, not inline shim."""
        output = format_sample_compatible_c(
            func_name="has_oword",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_oword(char *p) {",
                "  *(_OWORD *)p = 0;",
                "}",
            ],
        )
        assert '#include "polyfill.h"' in output
        assert "typedef unsigned __int128 _OWORD;" not in output

    def test_memory_macro_not_emitted_inline(self):
        """MEMORY should come from polyfill.h, not inline shim."""
        output = format_sample_compatible_c(
            func_name="has_memory",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_memory(void) {",
                "  MEMORY[0x123]();",
                "}",
            ],
        )
        assert '#include "polyfill.h"' in output
        assert "#define MEMORY" not in output

    def test_size_t_type_not_emitted_inline(self):
        """SIZE_T should come from polyfill.h, not inline shim."""
        output = format_sample_compatible_c(
            func_name="has_size_t",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_size_t(SIZE_T a1) {",
                "  (void)a1;",
                "}",
            ],
        )
        assert '#include "polyfill.h"' in output
        assert "typedef size_t SIZE_T;" not in output

    def test_oword_assignments_replaced_with_store_macro(self):
        """_OWORD assignments should be replaced with STORE_OWORD_N."""
        output = format_sample_compatible_c(
            func_name="has_oword_stores",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_oword_stores(char *Value) {",
                "  *(_OWORD *)Value = xmmword_7FFB2084A716;",
                "  *((_OWORD *)Value + 1) = xmmword_7FFB2084A726;",
                "}",
            ],
            global_declarations=[
                "static volatile const _OWORD xmmword_7FFB2084A716 = D810_XMMWORD(\"90708D8A9D04E7A19D273081BA1B2423\");",
                "static volatile const _OWORD xmmword_7FFB2084A726 = D810_XMMWORD(\"33E919F4343E7A0985500402EEC8F9F4\");",
            ],
        )
        assert "STORE_OWORD_N(Value, 0, &xmmword_7FFB2084A716);" in output
        assert "STORE_OWORD_N(Value, 1, &xmmword_7FFB2084A726);" in output
        assert "*(_OWORD *)Value =" not in output

    def test_oword_zero_store_uses_zero_constant(self):
        """_OWORD = 0 should use D810_ZERO_OWORD from ida_types.h."""
        output = format_sample_compatible_c(
            func_name="has_oword_zero",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_oword_zero(char *p) {",
                "  *((_OWORD *)p + 2) = 0;",
                "}",
            ],
        )
        assert "STORE_OWORD_N(p, 2, &D810_ZERO_OWORD);" in output
        assert '#include "polyfill.h"' in output  # ida_types.h defines D810_ZERO_OWORD

    def test_oword_offset_store_converted_to_index(self):
        """*(_OWORD *)(Base + offset) = xmmword should use offset/16 as index."""
        output = format_sample_compatible_c(
            func_name="has_oword_offset",
            func_ea=0x401000,
            pseudocode_lines=[
                "void has_oword_offset(char *Value) {",
                "  *(_OWORD *)(Value + 0x3C) = xmmword_7FFB2084A736;",
                "}",
            ],
            global_declarations=[
                "static volatile const _OWORD xmmword_7FFB2084A736 = D810_XMMWORD(\"9A5BC3C2D1CDC6822CCC81A6D1D635D1\");",
            ],
        )
        assert "STORE_OWORD_N(Value, 3, &xmmword_7FFB2084A736);" in output


class TestReplaceOwordAssignments:
    """Test replace_oword_assignments transformation."""

    def test_index_zero(self):
        """*(_OWORD *)Base = xmmword -> STORE_OWORD_N(Base, 0, &xmmword)."""
        lines = ["  *(_OWORD *)Value = xmmword_7FFB2084A716;"]
        out, needs_zero = replace_oword_assignments(lines)
        assert out[0] == "  STORE_OWORD_N(Value, 0, &xmmword_7FFB2084A716);"
        assert needs_zero is False

    def test_index_n(self):
        """*((_OWORD *)Base + N) = xmmword -> STORE_OWORD_N(Base, N, &xmmword)."""
        lines = ["  *((_OWORD *)Value + 1) = xmmword_7FFB2084A726;"]
        out, needs_zero = replace_oword_assignments(lines)
        assert out[0] == "  STORE_OWORD_N(Value, 1, &xmmword_7FFB2084A726);"
        assert needs_zero is False

    def test_offset_converted_to_index(self):
        """*(_OWORD *)(Base + 0x3C) = xmmword -> STORE_OWORD_N(Base, 3, &xmmword)."""
        lines = ["  *(_OWORD *)(Value + 0x3C) = xmmword_7FFB2084A736;"]
        out, needs_zero = replace_oword_assignments(lines)
        assert out[0] == "  STORE_OWORD_N(Value, 3, &xmmword_7FFB2084A736);"
        assert needs_zero is False

    def test_zero_rhs_uses_d810_zero_oword(self):
        """= 0 should use &D810_ZERO_OWORD and set needs_zero True."""
        lines = ["  *((_OWORD *)Value + 2) = 0;"]
        out, needs_zero = replace_oword_assignments(lines)
        assert out[0] == "  STORE_OWORD_N(Value, 2, &D810_ZERO_OWORD);"
        assert needs_zero is True

    def test_mixed_replacements(self):
        """Multiple patterns in one run."""
        lines = [
            "  *(_OWORD *)Value = xmmword_7FFB2084A716;",
            "  *((_OWORD *)Value + 1) = xmmword_7FFB2084A726;",
            "  *((_OWORD *)Value + 2) = 0;",
            "  *(_OWORD *)(Value + 0x3C) = xmmword_7FFB2084A736;",
        ]
        out, needs_zero = replace_oword_assignments(lines)
        assert out[0] == "  STORE_OWORD_N(Value, 0, &xmmword_7FFB2084A716);"
        assert out[1] == "  STORE_OWORD_N(Value, 1, &xmmword_7FFB2084A726);"
        assert out[2] == "  STORE_OWORD_N(Value, 2, &D810_ZERO_OWORD);"
        assert out[3] == "  STORE_OWORD_N(Value, 3, &xmmword_7FFB2084A736);"
        assert needs_zero is True

    def test_unchanged_lines_preserved(self):
        """Lines without _OWORD assignments are left unchanged."""
        lines = [
            "  int x = 1;",
            "  *(_OWORD *)p = xmmword_123;",
            "  return x;",
        ]
        out, _ = replace_oword_assignments(lines)
        assert out[0] == "  int x = 1;"
        assert out[1] == "  STORE_OWORD_N(p, 0, &xmmword_123);"
        assert out[2] == "  return x;"


class TestCompileSafetyRewrites:
    """Test static compile-safety rewrite pass."""

    def test_handle_integer_initializer_gets_cast(self):
        lines = ["volatile HANDLE h = 0x2C0uLL;"]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "volatile HANDLE h = (HANDLE)(ULONG_PTR)(0x2C0uLL);"

    def test_qword_store_from_pointer_gets_cast(self):
        lines = ["  *((_QWORD *)Value + 4) = CreateFiber(0, sub_foo, Value);"]
        out = apply_compile_safety_rewrites(lines)
        assert (
            out[0]
            == "  *((_QWORD *)Value + 4) = (_QWORD)(CreateFiber(0, sub_foo, Value));"
        )

    def test_multiline_qword_store_from_call_gets_cast(self):
        lines = [
            "  *((_QWORD *)Value + 4) = CreateFiber(",
            "      0,",
            "      sub_foo,",
            "      Value);",
        ]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "  *((_QWORD *)Value + 4) = (_QWORD)(CreateFiber("
        assert out[3] == "      Value));"

    def test_rtl_lock_address_not_rewritten(self):
        lines = ["  RtlAcquireSRWLockExclusive(&unk_7FFB208C0068);"]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "  RtlAcquireSRWLockExclusive(&unk_7FFB208C0068);"

    def test_subcall_first_arg_casted(self):
        lines = ["  v = sub_7FFB205841B0(a1, 0x2E, 0x52, 5);"]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "  v = sub_7FFB205841B0((_QWORD)(a1), 0x2E, 0x52, 5);"

    def test_subcall_pointer_args_get_casted(self):
        lines = [
            "  sub_7FFB20835490((_QWORD)(&Context), a1[1], 0x4D0);",
            "  sub_7FFB207233E0(0x23, 0x26, Value, 0xAA, 0xA);",
        ]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "  sub_7FFB20835490((_QWORD)(&Context), (_QWORD)(a1[1]), 0x4D0);"
        assert "(_QWORD)(Value)" in out[1]

    def test_multiline_subcall_third_arg_gets_casted(self):
        lines = [
            "  sub_7FFB207233E0(",
            "      0x23,",
            "      0x26,",
            "      Value,",
            "      0xAA,",
            "      0xA);",
        ]
        out = apply_compile_safety_rewrites(lines)
        assert out[3].strip() == "(_QWORD)(Value),"

    def test_setthreadcontext_hthread_and_security_cookie_rewritten(self):
        lines = [
            "  SetThreadContext(hThread, &Context);",
            "  if (x != _security_cookie) return 0;",
        ]
        out = apply_compile_safety_rewrites(lines)
        assert out[0] == "  SetThreadContext(qword_7FFB208C0058, &Context);"
        assert out[1] == "  if (x != __security_cookie) return 0;"
