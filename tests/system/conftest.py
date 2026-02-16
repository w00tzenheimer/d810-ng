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
import shutil
import sys
import tempfile
import time
import warnings
from d810.core.typing import TYPE_CHECKING

import pytest

from d810.core.clang_loader import load_clang_index
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
from d810.expr.utils import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
# Also import from d810.core to ensure both cache locations are accessible
from d810.core import (
    MOP_CONSTANT_CACHE as CORE_MOP_CONSTANT_CACHE,
    MOP_TO_AST_CACHE as CORE_MOP_TO_AST_CACHE,
)

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

    ida_install_dir = env.as_path("IDA_INSTALL_DIR")
    logger.info("Initializing libclang from %s", ida_install_dir)

    index, lib_path, tried_paths = load_clang_index(
        ida_directory=ida_install_dir,
        project_root=PROJECT_ROOT,
    )

    if index is None:
        logger.warning(
            "libclang library not found. Tried: %s",
            ", ".join(str(p) for p in tried_paths),
        )
        return None

    try:
        logger.info("Clang loaded successfully from %s", lib_path)
        return index
    except Exception as e:
        logger.warning("Failed to load libclang: %s", e)
        return None


class CodeComparator:
    """Parses and compares C/C++ code snippets for structural equivalence using Clang ASTs.

    Supports type-agnostic comparison (enabled by default via ``ignore_types=True``)
    which handles cross-platform type differences such as:

    - IDA-specific typedefs (``_DWORD``, ``__int64``, etc.)
    - LP64 vs LLP64 divergence (``long`` is 64-bit on LP64, 32-bit on LLP64)
    - Signedness differences (``int`` vs ``unsigned int``)
    - Trivial integer casts (``(unsigned int)(expr)`` vs bare ``expr``)

    Three tiers of type tolerance:

    1. **IDA Typedef Preamble** -- prepended before parsing so libclang resolves
       IDA-specific names (``_DWORD``, ``__int64``, ...) to canonical C types.
    2. **TypeKind Equivalence Classes** -- maps integer TypeKinds to bit-width
       buckets, ignoring signedness and LP64/LLP64 differences.
    3. **Cast Stripping** -- unwraps trivial integer casts during child comparison
       so ``(unsigned int)(expr)`` matches bare ``expr``.
    """

    # Tier 1: IDA typedef preamble injected before every snippet so that
    # libclang can resolve IDA-specific type names to standard C types.
    IDA_TYPEDEF_PREAMBLE = """\
typedef unsigned int _DWORD;
typedef unsigned long long _QWORD;
typedef unsigned short _WORD;
typedef unsigned char _BYTE;
typedef int _BOOL;
typedef unsigned long long uint64_t;
typedef long long int64_t;
typedef unsigned int uint32_t;
typedef int int32_t;
"""
    # Note: __int64, __int32, __int16, __int8 are NOT included above because
    # they are built-in keywords when parsing with -fms-extensions.  Adding
    # them as typedefs causes "cannot combine with previous declaration
    # specifier" errors.

    # Tier 2: Map TypeKind values to bit-width buckets.  Types in the same
    # bucket are considered compatible when ``ignore_types=True``.
    # On the MSVC target we parse with, ``long`` is 32-bit (LLP64).  On LP64
    # targets ``long`` would be 64-bit.  We map both LONG/ULONG into the
    # 64-bit bucket so that cross-compiled comparisons work.
    _WIDTH_BUCKET: dict[int, int] = {}  # populated in __init_subclass__ or lazily

    def __init__(self, index: "Index", *, ignore_types: bool = True):
        self.index = index
        self.ignore_types = ignore_types
        # Build the width-bucket map once we know TypeKind is available.
        if not CodeComparator._WIDTH_BUCKET and _CLANG_AVAILABLE:
            CodeComparator._build_width_buckets()

    @classmethod
    def _build_width_buckets(cls) -> None:
        """Populate ``_WIDTH_BUCKET`` from TypeKind enum values."""
        from d810._vendor.clang.cindex import TypeKind as TK

        # 8-bit bucket
        for tk in (TK.CHAR_U, TK.UCHAR, TK.CHAR_S, TK.SCHAR):
            cls._WIDTH_BUCKET[tk.value] = 8
        # 16-bit bucket
        for tk in (TK.SHORT, TK.USHORT, TK.CHAR16, TK.WCHAR):
            cls._WIDTH_BUCKET[tk.value] = 16
        # 32-bit bucket
        for tk in (TK.INT, TK.UINT, TK.CHAR32):
            cls._WIDTH_BUCKET[tk.value] = 32
        # 64-bit bucket -- includes LONG/ULONG so LP64 <-> LLP64 comparisons work
        for tk in (TK.LONG, TK.ULONG, TK.LONGLONG, TK.ULONGLONG):
            cls._WIDTH_BUCKET[tk.value] = 64
        # 128-bit bucket
        for tk in (TK.INT128, TK.UINT128):
            cls._WIDTH_BUCKET[tk.value] = 128
        # Bool
        cls._WIDTH_BUCKET[TK.BOOL.value] = 1

    # ------------------------------------------------------------------
    # Tier 2 helper: type compatibility check
    # ------------------------------------------------------------------

    def _types_compatible(self, t1, t2) -> bool:
        """Return True if two clang Types are compatible under type-agnostic rules.

        Handles:
        - Integer types mapped to the same bit-width bucket
        - Pointer types (recursively compares pointee types)
        - TYPEDEF / ELABORATED types (resolves to canonical type first)
        - Identical TypeKinds (trivially compatible)
        """
        from d810._vendor.clang.cindex import TypeKind as TK

        k1, k2 = t1.kind, t2.kind

        # Fast path: identical kinds are always compatible.
        if k1 == k2:
            # For pointers, also check pointee compatibility.
            if k1 == TK.POINTER:
                return self._types_compatible(t1.get_pointee(), t2.get_pointee())
            return True

        # Resolve typedefs / elaborated types to their canonical form.
        if k1 in (TK.TYPEDEF, TK.ELABORATED) or k2 in (TK.TYPEDEF, TK.ELABORATED):
            return self._types_compatible(t1.get_canonical(), t2.get_canonical())

        # Integer width-bucket comparison.
        b1 = self._WIDTH_BUCKET.get(k1.value)
        b2 = self._WIDTH_BUCKET.get(k2.value)
        if b1 is not None and b2 is not None:
            return b1 == b2

        # POINTER vs POINTER already handled above; mixed pointer/non-pointer
        # is never compatible.
        return False

    # ------------------------------------------------------------------
    # Tier 3 helpers: trivial cast detection and stripping
    # ------------------------------------------------------------------

    @staticmethod
    def _is_trivial_cast(cursor: "Cursor") -> bool:
        """Return True if *cursor* is a C-style cast to an integer type.

        A "trivial" cast is one like ``(unsigned int)(expr)`` which does not
        change the structural meaning of the expression for our purposes.
        """
        if cursor.kind != CursorKind.CSTYLE_CAST_EXPR:
            return False
        from d810._vendor.clang.cindex import TypeKind as TK

        cast_target = cursor.type.get_canonical().kind
        return cast_target.value in CodeComparator._WIDTH_BUCKET

    @staticmethod
    def _unwrap_single_child(cursor: "Cursor") -> "Cursor":
        """Recursively unwrap single-child wrappers (PAREN_EXPR, UNEXPOSED_EXPR, trivial casts).

        After stripping a ``CSTYLE_CAST_EXPR``, the result may be wrapped
        in ``UNEXPOSED_EXPR`` (implicit conversion) and/or ``PAREN_EXPR``
        nodes.  Recursively unwrap these syntactic-only nodes to reach the
        semantic core.
        """
        while True:
            if cursor.kind == CursorKind.PAREN_EXPR:
                children = list(cursor.get_children())
                if len(children) == 1:
                    cursor = children[0]
                    continue
            if cursor.kind == CursorKind.UNEXPOSED_EXPR:
                children = list(cursor.get_children())
                if len(children) == 1:
                    cursor = children[0]
                    continue
            if CodeComparator._is_trivial_cast(cursor):
                children = list(cursor.get_children())
                if len(children) == 1:
                    cursor = children[0]
                    continue
            break
        return cursor

    @staticmethod
    def _strip_redundant_casts(children: list["Cursor"]) -> list["Cursor"]:
        """Unwrap trivial integer casts in a child list.

        If a child is a ``CSTYLE_CAST_EXPR`` to an integer type, replace it
        with its single operand so that ``(unsigned int)(expr)`` compares
        equal to bare ``expr``.  Also unwraps any resulting ``PAREN_EXPR``
        wrappers which are purely syntactic.
        """
        result = []
        for child in children:
            if CodeComparator._is_trivial_cast(child):
                inner = list(child.get_children())
                if len(inner) == 1:
                    result.append(CodeComparator._unwrap_single_child(inner[0]))
                    continue
            result.append(child)
        return result

    @staticmethod
    def _unwrap_implicit(cursor: "Cursor") -> "Cursor":
        """Unwrap an UNEXPOSED_EXPR implicit conversion wrapper.

        Clang inserts ``UNEXPOSED_EXPR`` around expressions when implicit
        type conversion is needed (e.g. ``int`` literal assigned to a
        ``_DWORD`` lvalue).  When the wrapper has exactly one child,
        return that child; otherwise return the cursor unchanged.
        """
        if cursor.kind == CursorKind.UNEXPOSED_EXPR:
            children = list(cursor.get_children())
            if len(children) == 1:
                return children[0]
        return cursor

    # ------------------------------------------------------------------
    # Parsing
    # ------------------------------------------------------------------

    def _parse(self, code: str, filename: str = "dummy.cpp") -> "TranslationUnit":
        args = [
            "-target",
            "x86_64-pc-windows-msvc",
            "-fms-extensions",
            "-fms-compatibility",
            "-w",
            "-std=c++14",
        ]
        # Tier 1: prepend the IDA typedef preamble so that _DWORD, __int64,
        # etc. are resolved by libclang to canonical C types.
        if self.ignore_types:
            code = self.IDA_TYPEDEF_PREAMBLE + code

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
        self,
        c1: "Cursor",
        c2: "Cursor",
        ignore_comments: bool = True,
        ignore_types: bool | None = None,
    ) -> bool:
        # Resolve the effective ignore_types flag (instance default or override).
        if ignore_types is None:
            ignore_types = self.ignore_types

        if ignore_comments and c1.kind in (
            CursorKind.UNEXPOSED_ATTR,
            CursorKind.DLLIMPORT_ATTR,
            CursorKind.DLLEXPORT_ATTR,
        ):
            return True

        # Normalize common wrapper nodes early when type-agnostic comparison is enabled.
        # This handles real-world shapes like:
        #   UNEXPOSED_EXPR -> CSTYLE_CAST_EXPR -> BINARY_OPERATOR
        # vs
        #   BINARY_OPERATOR
        if ignore_types:
            c1n = self._unwrap_single_child(c1)
            c2n = self._unwrap_single_child(c2)
            if c1n is not c1 or c2n is not c2:
                return self._cursors_equal(c1n, c2n, ignore_comments, ignore_types)

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

        # Tier 2: type comparison.
        #
        # When ignore_types is True we skip type-kind checks entirely.
        # Cross-platform decompilers routinely choose different C types for
        # the same logical value (e.g. macOS IDA emits ``__int64`` where
        # Windows IDA emits ``int``).  These differences propagate through
        # parameter declarations, variable declarations, AND expression
        # result types.  Skipping all type-kind comparison when
        # ignore_types is True lets us focus on structural equivalence
        # (cursor kind, spelling, literal values, children).
        #
        # When ignore_types is False we use strict TypeKind equality.
        try:
            if not ignore_types:
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

        # For PARM_DECL nodes with ignore_types, skip child comparison
        # entirely.  Typedef-based types (e.g. _DWORD*) generate TypeRef
        # children that built-in types (e.g. int*) do not, causing spurious
        # child-count mismatches.  The spelling check above already confirms
        # the parameter names match.  Parameters in function declarations
        # never have initializer expressions, so this is safe.
        if ignore_types and c1.kind == CursorKind.PARM_DECL:
            return True

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

        # When ignore_types is True, filter out TYPE_REF children which
        # appear under typedef-based declarations (e.g. _DWORD) but not
        # under built-in type declarations (e.g. int).  This prevents
        # spurious child-count mismatches for VAR_DECL and other nodes
        # while preserving initializer and expression children.
        if ignore_types:
            children1 = [c for c in children1 if c.kind != CursorKind.TYPE_REF]
            children2 = [c for c in children2 if c.kind != CursorKind.TYPE_REF]

        # Tier 3: strip trivial integer casts before child comparison so
        # that ``(unsigned int)(expr)`` matches bare ``expr``.
        if ignore_types:
            children1 = self._strip_redundant_casts(children1)
            children2 = self._strip_redundant_casts(children2)

        if len(children1) != len(children2):
            logger.debug(
                "Child count mismatch for %s: %d vs %d",
                c1.kind,
                len(children1),
                len(children2),
            )
            return False

        for child1, child2 in zip(children1, children2):
            if not self._cursors_equal(child1, child2, ignore_comments, ignore_types):
                return False

        return True

    def check_equivalence(
        self,
        actual_code: str,
        expected_code: str,
        ignore_comments: bool = True,
        ignore_types: bool | None = None,
    ) -> None:
        tu_actual = self._parse(actual_code, "actual.cpp")
        tu_expected = self._parse(expected_code, "expected.cpp")

        cursor_actual = self._get_function_cursor(tu_actual)
        cursor_expected = self._get_function_cursor(tu_expected)

        if not cursor_actual or not cursor_expected:
            raise AssertionError(
                "Could not find function definition in one or both inputs."
            )

        effective_ignore = ignore_types if ignore_types is not None else self.ignore_types
        if not self._cursors_equal(cursor_actual, cursor_expected, ignore_comments, effective_ignore):
            raise AssertionError(
                f"Code semantic mismatch!\n\nActual:\n{actual_code}\n\nExpected:\n{expected_code}"
            )

    def are_equivalent(
        self,
        actual_code: str,
        expected_code: str,
        ignore_comments: bool = True,
        ignore_types: bool | None = None,
    ) -> bool:
        try:
            self.check_equivalence(actual_code, expected_code, ignore_comments, ignore_types)
            return True
        except AssertionError:
            return False


# =============================================================================
# Pytest Fixtures - Basic
# =============================================================================


@pytest.fixture(scope="class", autouse=True)
def clear_all_caches():
    """Clear all global caches before each test class.

    This prevents stale microcode pointer issues and segfaults between tests
    by ensuring all caches that may hold references to IDA objects are cleared.
    """
    from d810.optimizers.microcode.flow.flattening.dispatcher_detection import DispatcherCache
    from d810.hexrays.tracker import MopTracker
    from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block

    # Clear all caches before test class
    MOP_CONSTANT_CACHE.clear()
    MOP_TO_AST_CACHE.clear()
    CORE_MOP_CONSTANT_CACHE.clear()
    CORE_MOP_TO_AST_CACHE.clear()
    DispatcherCache.clear_cache()
    MopTracker.reset()
    fix_pred_cond_jump_block.clear_cache()

    yield

    # Clear again after test class to prevent cross-class contamination
    MOP_CONSTANT_CACHE.clear()
    MOP_TO_AST_CACHE.clear()
    CORE_MOP_CONSTANT_CACHE.clear()
    CORE_MOP_TO_AST_CACHE.clear()
    DispatcherCache.clear_cache()
    MopTracker.reset()
    fix_pred_cond_jump_block.clear_cache()


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

    For .dll (Windows PE): Function names come from PE exports via --export-all-symbols.
        IDA auto-detects these, so we don't need hardcoded addresses. The hardcoded
        address map was stale (6+ new C source files added since it was created) and
        would create phantom functions at wrong addresses.
    For .dylib/.so (macOS/Linux): Function names come from exports, just verify they exist.
    """
    # Check which binary type we have
    root_filename = idaapi.get_root_filename() or ""
    is_pe = root_filename.endswith(".dll")

    if is_pe:
        # Windows PE - IDA auto-detects function names from PE exports
        # (MinGW build uses --export-all-symbols)
        # No hardcoded address map needed - trust IDA's auto-detection
        expected_functions = [
            "test_chained_add",
            "test_cst_simplification",
            "test_opaque_predicate",
            "test_xor",
            "test_mba_guessing",
            "test_and",
            "test_or",
            "test_neg",
        ]
        for name in expected_functions:
            ea = idc.get_name_ea_simple(name)
            if ea != idaapi.BADADDR:
                logger.debug(f"Found function {name} at 0x{ea:x}")
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

    # Clear caches to prevent stale microcode pointer issues between tests
    # Import and clear from both locations to ensure complete cleanup
    from d810.optimizers.microcode.flow.flattening.dispatcher_detection import DispatcherCache
    from d810.hexrays.tracker import MopTracker
    from d810.optimizers.microcode.flow.flattening import fix_pred_cond_jump_block

    MOP_CONSTANT_CACHE.clear()
    MOP_TO_AST_CACHE.clear()
    CORE_MOP_CONSTANT_CACHE.clear()
    CORE_MOP_TO_AST_CACHE.clear()
    DispatcherCache.clear_cache()
    MopTracker.reset()
    fix_pred_cond_jump_block.clear_cache()
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
    - Saves to: e2e/expectations/<test_name>.<binary_basename>.json
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

    The captured stats will be saved to tests/system/e2e/expectations/<test_name>.<binary>.json
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
            expectations_dir = pathlib.Path(__file__).parent / "e2e" / "expectations"
            expectations_dir.mkdir(exist_ok=True, parents=True)

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
    - First tries: e2e/expectations/<test_name>.<binary_basename>.json
    - Falls back to: e2e/expectations/<test_name>.json

    Usage:
        def test_something(self, d810_state, load_expected_stats):
            expected = load_expected_stats()  # Loads from e2e/expectations/<test_name>.json
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
        expectations_dir = pathlib.Path(__file__).parent / "e2e" / "expectations"

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
    parser.addoption(
        "--dump-function-pseudocode",
        action="store",
        default=None,
        help=(
            "Dump before/after pseudocode for one function name "
            "(or comma-separated function names)."
        ),
    )
    parser.addoption(
        "--dump-project",
        action="store",
        default="example_libobfuscated.json",
        help=(
            "Project configuration filename to load for pseudocode dump "
            "(default: example_libobfuscated.json)."
        ),
    )
    parser.addoption(
        "--dump-no-project",
        action="store_true",
        default=False,
        help="Do not load any project configuration when dumping pseudocode.",
    )
    parser.addoption(
        "--unskip-research",
        action="store_true",
        default=False,
        help=(
            "Run system test cases normally marked with case-level skip reasons. "
            "Dangerous hang/segfault cases remain skipped unless "
            "--unskip-dangerous is also set."
        ),
    )
    parser.addoption(
        "--unskip-dangerous",
        action="store_true",
        default=False,
        help=(
            "Also run dangerous known-hang/known-segfault cases. "
            "Use only for local investigation."
        ),
    )


def pytest_configure(config):
    """Configure pytest plugins."""
    if config.getoption("--unskip-research"):
        os.environ["D810_UNSKIP_CASES"] = "1"
    if config.getoption("--unskip-dangerous"):
        os.environ["D810_UNSKIP_DANGEROUS"] = "1"

    config.addinivalue_line(
        "markers",
        "pseudocode_dump: manual utility tests for before/after pseudocode dumping",
    )
    # Register the test capture plugin if --capture-to-db is enabled
    if config.getoption("--capture-to-db"):
        from tests.system.runtime.test_capture import CapturePlugin
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
