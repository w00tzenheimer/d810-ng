"""Pytest configuration for system tests.

System tests require external dependencies like libclang and IDA Pro.
This conftest provides fixtures for AST-based code comparison using Clang.
"""

import logging
import pathlib
import platform

import pytest

from tests.conftest import PROJECT_ROOT, EnvWrapper

logger = logging.getLogger(__name__)

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
# Pytest Fixtures - Clang / AST Comparison (System Tests Only)
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
