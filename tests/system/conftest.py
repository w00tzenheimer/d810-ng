"""Pytest configuration for system tests.

System tests require IDA Pro and test actual decompilation functionality.

This module provides:
- IDA Pro initialization and module loading
- libclang initialization for AST-based code comparison
- Pytest fixtures for database management and code comparison

Fixtures defined here are automatically available to all tests - do NOT import
from this file. Pytest auto-injects fixtures by name.

AST-Based Code Comparison
=========================
The CodeComparator class provides structural/semantic code comparison using
libclang, which is more reliable than string comparison because it ignores:
- Formatting differences (indentation, spacing)
- Type name variations (`int` vs `_DWORD`)
- Comment differences (IDA annotations)

Key Fixtures:
- `clang_index`: Session-scoped clang Index (or None if unavailable)
- `code_comparator`: Session-scoped CodeComparator instance
- `require_clang`: Skips test if clang is not available
- `ida_database`: Class-scoped IDA database management
- `assert_code_equivalent`: AST-based equivalence assertion
- `assert_code_contains`: Pattern-based containment assertion
- `assert_code_not_contains`: Pattern-based exclusion assertion
"""

from __future__ import annotations

import contextlib
import logging
import os
import pathlib
import platform
import shutil
import sys
import tempfile
import time
import warnings
from typing import TYPE_CHECKING

import pytest

from tests.conftest import PROJECT_ROOT, EnvWrapper

logger = logging.getLogger(__name__)


# =============================================================================
# IDA Pro Initialization
# =============================================================================
def _is_ida():
    """Crude check to see if running inside IDA."""
    exec_name = pathlib.Path(sys.executable).name.lower()
    return exec_name.startswith("ida") or exec_name.startswith("idat")


# Try to import idapro first to initialize IDA Python environment
# This is CRITICAL for headless/idalib mode, but not needed if we
# are in the IDA Pro environment.
# See: https://docs.hex-rays.com/user-guide/idalib#using-the-ida-library-python-module

if not _is_ida():
    try:
        import idapro
        logger.info("idapro module initialized for idalib mode")
    except ImportError:
        pytest.skip(
            "Not running inside IDA Pro and idapro module not available. "
            "System tests require IDA Pro or idalib.",
            allow_module_level=True,
        )

    print("  idapro module initialized")


# Try to import IDA modules to check availability
with warnings.catch_warnings():
    warnings.filterwarnings("ignore")
    import idaapi
    import idc

print(f"  IDA Pro version: {idaapi.get_kernel_version()}")

# Load all d810 modules to populate registries using reload_package

if TYPE_CHECKING:
    from d810.manager import D810State

import d810
import d810._vendor.ida_reloader as reloadable

# Just scan/import modules to populate registries - no reload needed for tests
reloadable.Scanner.scan(d810.__path__, "d810.", skip_packages=False)
print("  d810 modules loaded")


# =============================================================================
# Clang / AST Comparison Initialization
# =============================================================================

# Try to import clang bindings - required for AST comparison in system tests
_CLANG_AVAILABLE = False
try:
    from d810._vendor.clang.cindex import Config, Cursor, CursorKind, Index, TranslationUnit
    _CLANG_AVAILABLE = True
except ImportError:
    logger.warning("Clang bindings not available - AST comparison tests will be skipped")
    Config = None
    Cursor = None
    CursorKind = None
    Index = None
    TranslationUnit = None


def _init_clang(env: EnvWrapper) -> "Index | None":
    """Initialize libclang with the library from IDA Pro installation."""
    if not _CLANG_AVAILABLE:
        return None

    system = platform.system()
    ida_install_dir = env.as_path("IDA_INSTALL_DIR")
    logger.info("Initializing libclang from %s", ida_install_dir)

    possible_lib_paths = []
    if ida_install_dir.exists():
        lib_names = {
            "Linux": "libclang.so",
            "Darwin": "libclang.dylib",
            "Windows": "libclang.dll",
        }
        if lib_name := lib_names.get(system):
            possible_lib_paths.append(ida_install_dir / lib_name)

    if system == "Linux":
        possible_lib_paths.append(ida_install_dir / "libclang.so")
    elif system == "Darwin":
        possible_lib_paths.append(ida_install_dir / "libclang.dylib")
    elif system == "Windows":
        possible_lib_paths.append(ida_install_dir / "libclang.dll")

    local_names = {
        "Linux": "libclang.so",
        "Darwin": "libclang.dylib",
        "Windows": "libclang.dll",
    }
    if local_lib_name := local_names.get(system):
        possible_lib_paths.append(PROJECT_ROOT / local_lib_name)

    lib_path = None
    for path in possible_lib_paths:
        if path.exists():
            lib_path = path
            break

    if not lib_path:
        logger.warning(
            "libclang library not found. Tried: %s",
            ", ".join(str(p) for p in possible_lib_paths),
        )
        return None

    Config.set_library_file(str(lib_path.resolve()))

    try:
        index = Index.create()
        logger.info("Clang loaded successfully from %s", lib_path)
        return index
    except Exception as e:
        logger.warning("Failed to load libclang: %s", e)
        return None


class CodeComparator:
    """Parses and compares C/C++ code snippets for structural equivalence using Clang ASTs."""

    def __init__(self, index: "Index"):
        self.index = index

    def _parse(self, code: str, filename: str = "dummy.cpp") -> "TranslationUnit":
        args = [
            "-target",
            "x86_64-pc-windows-msvc",
            "-fms-extensions",
            "-fms-compatibility",
            "-w",
            "-std=c++14",
        ]
        tu = self.index.parse(
            path=filename, args=args, unsaved_files=[(filename, code)], options=0
        )
        if tu.diagnostics:
            for diag in tu.diagnostics:
                logger.debug("Clang Parse Diagnostic: %s", diag)
        return tu

    def _get_function_cursor(self, tu: "TranslationUnit") -> "Cursor | None":
        if tu.cursor is None:
            return None
        for cursor in tu.cursor.get_children():
            if cursor.kind == CursorKind.FUNCTION_DECL:
                return cursor
        return None

    def _normalize_spelling(self, spelling: str) -> str:
        return spelling.strip()

    def _get_literal_value(self, cursor: "Cursor") -> str | None:
        """Extract the literal value from a cursor using its tokens."""
        literal_kinds = (
            CursorKind.INTEGER_LITERAL,
            CursorKind.FLOATING_LITERAL,
            CursorKind.CHARACTER_LITERAL,
            CursorKind.STRING_LITERAL,
        )
        if cursor.kind not in literal_kinds:
            return None
        try:
            tokens = list(cursor.get_tokens())
            if tokens:
                return tokens[0].spelling
        except Exception:
            pass
        return None

    def _cursors_equal(
        self, c1: "Cursor", c2: "Cursor", ignore_comments: bool = True
    ) -> bool:
        if ignore_comments and c1.kind in (
            CursorKind.UNEXPOSED_ATTR,
            CursorKind.DLLIMPORT_ATTR,
            CursorKind.DLLEXPORT_ATTR,
        ):
            return True

        if c1.kind != c2.kind:
            logger.debug("Kind mismatch: %s vs %s", c1.kind, c2.kind)
            return False

        lit1 = self._get_literal_value(c1)
        lit2 = self._get_literal_value(c2)
        if lit1 is not None or lit2 is not None:
            if lit1 != lit2:
                logger.debug("Literal value mismatch: '%s' vs '%s'", lit1, lit2)
                return False

        spell1 = self._normalize_spelling(c1.spelling)
        spell2 = self._normalize_spelling(c2.spelling)
        if spell1 != spell2:
            if spell1 or spell2:
                logger.debug("Spelling mismatch: '%s' vs '%s'", spell1, spell2)
                return False

        try:
            if c1.type.kind != c2.type.kind:
                logger.debug(
                    "Type mismatch for %s: %s vs %s",
                    c1.spelling,
                    c1.type.kind,
                    c2.type.kind,
                )
                return False
        except Exception:
            pass

        children1 = list(c1.get_children())
        children2 = list(c2.get_children())

        if ignore_comments:
            filter_kinds = (
                CursorKind.UNEXPOSED_ATTR,
                CursorKind.DLLIMPORT_ATTR,
                CursorKind.DLLEXPORT_ATTR,
            )
            children1 = [c for c in children1 if c.kind not in filter_kinds]
            children2 = [c for c in children2 if c.kind not in filter_kinds]

        if len(children1) != len(children2):
            logger.debug(
                "Child count mismatch for %s: %d vs %d",
                c1.kind,
                len(children1),
                len(children2),
            )
            return False

        for child1, child2 in zip(children1, children2):
            if not self._cursors_equal(child1, child2, ignore_comments):
                return False

        return True

    def check_equivalence(
        self, actual_code: str, expected_code: str, ignore_comments: bool = True
    ) -> None:
        tu_actual = self._parse(actual_code, "actual.cpp")
        tu_expected = self._parse(expected_code, "expected.cpp")

        cursor_actual = self._get_function_cursor(tu_actual)
        cursor_expected = self._get_function_cursor(tu_expected)

        if not cursor_actual or not cursor_expected:
            raise AssertionError(
                "Could not find function definition in one or both inputs."
            )

        if not self._cursors_equal(cursor_actual, cursor_expected, ignore_comments):
            raise AssertionError(
                f"Code semantic mismatch!\n\nActual:\n{actual_code}\n\nExpected:\n{expected_code}"
            )

    def are_equivalent(
        self, actual_code: str, expected_code: str, ignore_comments: bool = True
    ) -> bool:
        try:
            self.check_equivalence(actual_code, expected_code, ignore_comments)
            return True
        except AssertionError:
            return False


# =============================================================================
# Pytest Fixtures - Basic
# =============================================================================


@pytest.fixture
def ida_available():
    """Fixture that provides IDA availability status."""
    return True


@pytest.fixture
def skip_if_no_ida():
    """Fixture that skips test if IDA is not available."""
    pytest.skip("IDA Pro not available")


# =============================================================================
# Pytest Fixtures - IDA Database
# =============================================================================


@pytest.fixture(scope="class")
def ida_database(request):
    """Class-scoped fixture for IDA database management.

    Opens the database specified by the test class's `binary_name` attribute.
    """
    binary_name = getattr(request.cls, "binary_name", None)
    if binary_name is None:
        pytest.skip("Test class must set binary_name attribute")

    timing_data = {}

    # Check if the expected database is already open
    try:
        current_db = idaapi.get_root_filename()
        if current_db and (
            binary_name in current_db or current_db.endswith(binary_name)
        ):
            print(f"    Reusing existing database: {current_db}")
            yield {
                "min_ea": idaapi.inf_get_min_ea(),
                "max_ea": idaapi.inf_get_max_ea(),
                "binary_name": binary_name,
                "reused": True,
            }
            return
    except Exception:
        pass

    # Find the binary
    tests_dir = pathlib.Path(__file__).parent
    project_root = tests_dir.parent.parent

    possible_paths = [
        project_root / "samples" / "bins" / binary_name,
        project_root / "tests" / "_resources" / "bin" / binary_name,
        tests_dir / "bins" / binary_name,
    ]

    binary_path = None
    for path in possible_paths:
        if path.exists():
            binary_path = path
            break

    if binary_path is None:
        pytest.skip(f"Test binary '{binary_name}' not found")

    logger.info(f"Found binary at: {binary_path}")

    # Create temporary directory and copy binary
    tempdir = pathlib.Path(tempfile.mkdtemp())
    temp_binary_path = tempdir / binary_path.name
    shutil.copy(binary_path, temp_binary_path)

    logger.info(f"Copied binary to temp location: {temp_binary_path}")

    # Open database
    t_db_start = time.perf_counter()
    result = idapro.open_database(str(temp_binary_path), True)
    timing_data["db_open"] = time.perf_counter() - t_db_start
    print(f"    idapro.open_database() took {timing_data['db_open']:.2f}s")

    if result != 0:
        shutil.rmtree(tempdir)
        pytest.skip(f"Failed to open database. Result code: {result}")

    # Run auto analysis
    t_auto_start = time.perf_counter()
    idaapi.auto_wait()
    timing_data["auto_wait"] = time.perf_counter() - t_auto_start
    print(f"    idaapi.auto_wait() took {timing_data['auto_wait']:.2f}s")

    db_info = {
        "min_ea": idaapi.inf_get_min_ea(),
        "max_ea": idaapi.inf_get_max_ea(),
        "binary_name": binary_name,
        "binary_path": binary_path,
        "temp_path": temp_binary_path,
        "tempdir": tempdir,
        "timing": timing_data,
        "reused": False,
    }

    yield db_info

    # Cleanup
    if not db_info.get("reused", False):
        logger.debug("Closing database...")
        idapro.close_database()
        if tempdir.exists():
            logger.debug("Cleaning up temporary directory...")
            shutil.rmtree(tempdir)


# =============================================================================
# Pytest Fixtures - Hex-Rays Helpers
# =============================================================================


def _pseudocode_to_string(pseudo_code) -> str:
    """Convert IDA pseudocode to a plain string without formatting tags."""
    converted_obj = [idaapi.tag_remove(line_obj.line) for line_obj in pseudo_code]
    return os.linesep.join(converted_obj)


def _configure_hexrays():
    """Configure Hex-Rays decompiler settings for consistent test output."""
    idaapi.change_hexrays_config("RIGHT_MARGIN = 100")
    idaapi.change_hexrays_config("PSEUDOCODE_SYNCED = YES")
    idaapi.change_hexrays_config("PSEUDOCODE_DOCKPOS = DP_RIGHT")
    idaapi.change_hexrays_config("GENERATE_EMPTY_LINES = YES")
    idaapi.change_hexrays_config("BLOCK_INDENT = 4")
    idaapi.change_hexrays_config("MAX_FUNCSIZE = 2048")
    idaapi.change_hexrays_config("MAX_NCOMMAS = 1")
    idaapi.change_hexrays_config("COLLAPSE_LVARS = YES")
    idaapi.change_hexrays_config("GENERATE_EA_LABELS = YES")
    idaapi.change_hexrays_config("AUTO_UNHIDE = YES")
    idaapi.change_hexrays_config("DEFAULT_RADIX = 16")


def _setup_libobfuscated_function_names():
    """Set up function names for libobfuscated binaries.

    For .dll (Windows PE): Uses hardcoded address map.
    For .dylib/.so (macOS/Linux): Function names come from exports, just verify they exist.
    """
    # Check which binary type we have
    root_filename = idaapi.get_root_filename() or ""
    is_pe = root_filename.endswith(".dll")

    if is_pe:
        # Windows PE - use hardcoded addresses
        function_map = {
            "constant_folding_test1": 0x180001000,
            "constant_folding_test2": 0x1800015C0,
            "outlined_helper_1": 0x1800016A0,
            "outlined_helper_2": 0x1800016D0,
            "AntiDebug_ExceptionFilter": 0x180001710,
            "test_chained_add": 0x180006630,
            "test_cst_simplification": 0x180006680,
            "test_opaque_predicate": 0x180006780,
            "test_xor": 0x180006920,
            "test_mba_guessing": 0x1800069A0,
            "test_function_ollvm_fla_bcf_sub": 0x180006B40,
            "tigress_minmaxarray": 0x180009490,
            "unwrap_loops": 0x180009730,
            "unwrap_loops_2": 0x1800097E0,
            "unwrap_loops_3": 0x1800098C0,
            "while_switch_flattened": 0x1800099F0,
            "NtCurrentTeb": 0x180009B30,
        }
        for name, addr in function_map.items():
            idc.set_name(addr, name, idc.SN_NOWARN | idc.SN_NOCHECK)
            if not idc.get_func_attr(addr, idc.FUNCATTR_START):
                idc.create_insn(addr)
                idaapi.add_func(addr)
    else:
        # macOS dylib / Linux so - IDA auto-detects function names from exports
        # Just verify the expected functions exist
        expected_functions = [
            "test_chained_add",
            "test_cst_simplification",
            "test_opaque_predicate",
            "test_xor",
            "test_mba_guessing",
            "test_and",
            "test_or",
            "test_neg",
            "_hodur_func",
        ]
        for name in expected_functions:
            # Try with and without underscore prefix (macOS adds underscore)
            ea = idc.get_name_ea_simple(name)
            if ea == idaapi.BADADDR:
                ea = idc.get_name_ea_simple("_" + name)
            if ea != idaapi.BADADDR:
                logger.debug(f"Found function {name} at 0x{ea:x}")


@pytest.fixture
def pseudocode_to_string():
    """Fixture providing the pseudocode_to_string function."""
    return _pseudocode_to_string


@pytest.fixture(scope="class")
def configure_hexrays():
    """Fixture that configures Hex-Rays for consistent output."""
    _configure_hexrays()


@pytest.fixture(scope="class")
def setup_libobfuscated_funcs():
    """Fixture that sets up function names for libobfuscated.dll."""
    _setup_libobfuscated_function_names()


@pytest.fixture(scope="class")
def setup_libobfuscated_test_funcs():
    """Fixture that verifies function names exist for libobfuscated_test binary.

    For macOS dylib: Function names come from exports, just verify they exist.
    """
    expected_functions = [
        # ABC pattern functions
        "abc_xor_dispatch",
        "abc_or_dispatch",
        "abc_mixed_dispatch",
        # Nested dispatcher functions
        "nested_simple",
        "nested_deep",
        "nested_parallel",
        "nested_shared_blocks",
        # Exception path functions
        "unresolvable_external",
        "unresolvable_computed",
        "non_duplicable_side_effects",
        "deep_duplication_path",
        "loop_dependent_state",
        "indirect_state_pointer",
        "external_transform_state",
    ]
    for name in expected_functions:
        # Try with and without underscore prefix (macOS adds underscore)
        ea = idc.get_name_ea_simple(name)
        if ea == idaapi.BADADDR:
            ea = idc.get_name_ea_simple("_" + name)
        if ea != idaapi.BADADDR:
            logger.debug(f"Found function {name} at 0x{ea:x}")


# =============================================================================
# Pytest Fixtures - D810 State
# =============================================================================


@contextlib.contextmanager
def _d810_state_cm(*, all_rules=False):
    """Context manager for D810 state with statistics tracking."""
    from d810.manager import D810State

    state = D810State()  # singleton
    if not (was_loaded := state.is_loaded()):
        t_load_start = time.perf_counter()
        state.load(gui=False)
        t_load = time.perf_counter() - t_load_start
        print(f"    D810State.load() took {t_load:.2f}s")

    if all_rules:
        state.current_ins_rules = state.known_ins_rules
        state.current_blk_rules = state.known_blk_rules
        logger.debug(
            f"all_rules=True: Loaded {len(state.current_ins_rules)} instruction rules"
        )

    if not (was_started := state.manager.started):
        t_start = time.perf_counter()
        state.start_d810()
        t_start_elapsed = time.perf_counter() - t_start
        print(f"    D810State.start_d810() took {t_start_elapsed:.2f}s")

    state.stats.reset()

    try:
        yield state
    finally:
        if not was_started:
            state.stop_d810()
        if not was_loaded:
            state.unload(gui=False)


@pytest.fixture
def d810_state():
    """Fixture providing d810 state context manager.

    Usage:
        def test_something(self, d810_state):
            with d810_state() as state:
                state.stop_d810()
                # decompile without d810
                state.start_d810()
                # decompile with d810
    """
    return _d810_state_cm


@pytest.fixture
def d810_state_all_rules():
    """Fixture providing d810 state with all rules enabled.

    Usage:
        def test_something(self, d810_state_all_rules):
            with d810_state_all_rules() as state:
                # all rules are active
    """
    return lambda: _d810_state_cm(all_rules=True)


# =============================================================================
# Pytest Fixtures - Clang / AST Comparison
# =============================================================================


@pytest.fixture(scope="session")
def clang_index(env: EnvWrapper):
    """Session-scoped fixture providing the clang Index for AST parsing."""
    return _init_clang(env)


@pytest.fixture(scope="session")
def code_comparator(clang_index):
    """Session-scoped fixture providing a CodeComparator instance."""
    if clang_index is None:
        return None
    return CodeComparator(clang_index)


@pytest.fixture
def require_clang(clang_index):
    """Fixture that skips test if clang is not available."""
    if clang_index is None:
        pytest.skip("libclang not available")
    return clang_index


@pytest.fixture
def assert_code_equivalent(code_comparator):
    """Fixture providing code equivalence assertion."""

    def _assert(actual: str, expected: str, msg: str = ""):
        if code_comparator is None:
            if expected not in actual:
                fail_msg = (
                    f"Code mismatch.\n\nActual:\n{actual}\n\nExpected:\n{expected}"
                )
                if msg:
                    fail_msg = f"{msg}\n\n{fail_msg}"
                pytest.fail(fail_msg)
            return

        try:
            code_comparator.check_equivalence(actual, expected)
        except AssertionError as e:
            if msg:
                pytest.fail(f"{msg}\n\n{str(e)}")
            pytest.fail(str(e))

    return _assert


# =============================================================================
# Custom Assertion Fixtures
# =============================================================================


@pytest.fixture
def assert_code_contains():
    """Fixture providing code contains assertion."""

    def _assert(actual: str, *expected_patterns: str, msg: str = ""):
        missing = [p for p in expected_patterns if p not in actual]
        if missing:
            fail_msg = (
                f"Code missing expected patterns: {missing}\n\nActual code:\n{actual}"
            )
            if msg:
                fail_msg = f"{msg}\n\n{fail_msg}"
            pytest.fail(fail_msg)

    return _assert


@pytest.fixture
def assert_code_not_contains():
    """Fixture providing code not-contains assertion."""

    def _assert(actual: str, *forbidden_patterns: str, msg: str = ""):
        found = [p for p in forbidden_patterns if p in actual]
        if found:
            fail_msg = (
                f"Code contains forbidden patterns: {found}\n\nActual code:\n{actual}"
            )
            if msg:
                fail_msg = f"{msg}\n\n{fail_msg}"
            pytest.fail(fail_msg)

    return _assert


# =============================================================================
# Pytest Fixtures - Statistics Capture
# =============================================================================


@pytest.fixture
def capture_stats(request):
    """Fixture for capturing and optionally saving deobfuscation statistics.

    Supports binary-specific expectations:
    - Saves to: expectations/<test_name>.<binary_basename>.json
    - Example: test_ollvm.libobfuscated.json (for libobfuscated.dll or libobfuscated.dylib)

    Usage:
        def test_something(self, d810_state, capture_stats):
            with d810_state() as state:
                state.start_d810()
                decompiled = idaapi.decompile(func_ea)
                # Capture stats after decompilation
                stats = capture_stats(state.stats)
                # stats is now a dict you can assert on

    To generate expectation files, run pytest with --capture-stats:
        pytest tests/system/test_libdeobfuscated.py --capture-stats

    The captured stats will be saved to tests/system/expectations/<test_name>.<binary>.json
    """
    import json

    capture_mode = request.config.getoption("--capture-stats", default=False)
    test_name = request.node.name
    # Get binary name from class attribute if available
    binary_name = getattr(request.cls, "binary_name", None)
    binary_basename = pathlib.Path(binary_name).stem if binary_name else None

    def _capture(stats):
        """Capture statistics and optionally save to file."""
        stats_dict = stats.to_dict()

        if capture_mode:
            # Save to expectations file (binary-specific if binary_name is set)
            expectations_dir = pathlib.Path(__file__).parent / "expectations"
            expectations_dir.mkdir(exist_ok=True)

            if binary_basename:
                expectation_file = expectations_dir / f"{test_name}.{binary_basename}.json"
            else:
                expectation_file = expectations_dir / f"{test_name}.json"

            with open(expectation_file, "w") as f:
                json.dump(stats_dict, f, indent=2, sort_keys=True)

            logger.info(f"Saved expectations to {expectation_file}")

        return stats_dict

    return _capture


@pytest.fixture
def load_expected_stats(request):
    """Fixture for loading expected statistics from JSON files.

    Supports binary-specific expectations:
    - First tries: expectations/<test_name>.<binary_basename>.json
    - Falls back to: expectations/<test_name>.json

    Usage:
        def test_something(self, d810_state, load_expected_stats):
            expected = load_expected_stats()  # Loads from expectations/<test_name>.json
            with d810_state() as state:
                state.start_d810()
                decompiled = idaapi.decompile(func_ea)
                state.stats.assert_matches(expected)
    """
    import json

    test_name = request.node.name
    # Get binary name from class attribute if available
    binary_name = getattr(request.cls, "binary_name", None)
    binary_basename = pathlib.Path(binary_name).stem if binary_name else None

    def _load(filename: str = None):
        """Load expected statistics from JSON file.

        Tries binary-specific file first, then falls back to generic.
        """
        expectations_dir = pathlib.Path(__file__).parent / "expectations"

        if filename is None:
            # Try binary-specific expectations first
            if binary_basename:
                binary_specific = expectations_dir / f"{test_name}.{binary_basename}.json"
                if binary_specific.exists():
                    logger.debug(f"Loading binary-specific expectations: {binary_specific}")
                    with open(binary_specific) as f:
                        return json.load(f)

            # Fall back to generic expectations
            filename = f"{test_name}.json"

        expectation_file = expectations_dir / filename

        if not expectation_file.exists():
            return None

        with open(expectation_file) as f:
            return json.load(f)

    return _load


def pytest_addoption(parser):
    """Add custom pytest options."""
    parser.addoption(
        "--capture-stats",
        action="store_true",
        default=False,
        help="Capture deobfuscation statistics to expectation files",
    )
    parser.addoption(
        "--capture-to-db",
        action="store_true",
        default=False,
        help="Capture test results to SQLite database",
    )


def pytest_configure(config):
    """Configure pytest plugins."""
    # Register the test capture plugin if --capture-to-db is enabled
    if config.getoption("--capture-to-db"):
        from tests.system.test_capture import CapturePlugin
        config.pluginmanager.register(CapturePlugin(config), "capture_plugin")


# =============================================================================
# Pytest Fixture - Database Capture
# =============================================================================


@pytest.fixture
def db_capture(request):
    """Fixture for manually capturing test results in tests.

    Usage:
        def test_something(self, d810_state, db_capture):
            with d810_state() as state:
                # ... run test ...
                db_capture.record(
                    function_name="test_func",
                    code_before=before,
                    code_after=after,
                    stats=state.stats,
                    passed=True
                )
    """
    if not request.config.getoption("--capture-to-db", default=False):
        # Return a no-op object if capture is disabled
        class NoOpCapture:
            def record(self, **kwargs):
                pass
        return NoOpCapture()

    # Get test context
    test_suite = pathlib.Path(request.fspath).name
    test_name = request.node.name
    test_class = request.cls.__name__ if request.cls else None
    binary_name = getattr(request.cls, "binary_name", None)

    class CaptureHelper:
        """Helper for manual result capture."""

        def record(
            self,
            function_name: str,
            code_before: str,
            code_after: str,
            stats,
            passed: bool,
            function_address: str = None,
            error_message: str = None,
        ):
            """Record a test result."""
            # Store as user properties so pytest hooks can access
            request.node.user_properties.append(("function_name", function_name))
            request.node.user_properties.append(("code_before", code_before))
            request.node.user_properties.append(("code_after", code_after))
            request.node.user_properties.append(("stats_dict", stats.to_dict()))
            if binary_name:
                request.node.user_properties.append(("binary_name", binary_name))
            if function_address:
                request.node.user_properties.append(("function_address", function_address))

    return CaptureHelper()
