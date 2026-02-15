"""Semantic equivalence testing infrastructure for d810.

This module provides tools to verify that deobfuscated functions produce the
same outputs as original functions by compiling and executing C code directly.
This catches correctness bugs beyond what syntactic/AST comparison can detect.

Key Functions:
- compile_reference_function: Compile C source to shared library
- call_function: Call compiled function with arguments
- assert_semantic_equivalence: Assert function produces expected outputs
- generate_test_cases: Generate random test cases from reference implementation

Example:
    # Test that deobfuscated code produces same outputs as original
    test_cases = [
        ((10, 20), 39),  # mixed_dispatcher_pattern(10, 20) == 39
        ((50, 60), 49),  # mixed_dispatcher_pattern(50, 60) == 49
    ]
    assert_semantic_equivalence(
        "samples/src/c/dispatcher_patterns.c",
        "mixed_dispatcher_pattern",
        test_cases
    )
"""

from __future__ import annotations

import atexit
import ctypes
import logging
import pathlib
import platform
import random
import subprocess
import tempfile
from d810.core.typing import Any

logger = logging.getLogger(__name__)


# Track temporary files for cleanup
_TEMP_LIBS: list[pathlib.Path] = []


def _cleanup_temp_libs() -> None:
    """Clean up temporary shared libraries on exit."""
    for lib_path in _TEMP_LIBS:
        try:
            if lib_path.exists():
                lib_path.unlink()
                logger.debug(f"Cleaned up temporary library: {lib_path}")
        except Exception as e:
            logger.warning(f"Failed to clean up {lib_path}: {e}")


atexit.register(_cleanup_temp_libs)


def compile_reference_function(
    c_source_path: str,
    function_name: str,
    extra_cflags: list[str] | None = None,
) -> ctypes.CDLL:
    """Compile a C source file into a shared library and load it.

    Args:
        c_source_path: Path to C source file
        function_name: Name of function to compile (for validation)
        extra_cflags: Additional compiler flags (e.g., ["-DIDA_SDK=0"])

    Returns:
        ctypes.CDLL object with loaded library

    Raises:
        subprocess.CalledProcessError: If compilation fails
        FileNotFoundError: If source file doesn't exist

    Note:
        Uses -O0 to prevent compiler optimizations that might change behavior.
        Handles platform-specific library extensions (.so, .dylib, .dll).
    """
    src_path = pathlib.Path(c_source_path)
    if not src_path.exists():
        raise FileNotFoundError(f"Source file not found: {c_source_path}")

    # Determine library extension based on platform
    system = platform.system()
    if system == "Darwin":
        lib_ext = ".dylib"
    elif system == "Linux":
        lib_ext = ".so"
    elif system == "Windows":
        lib_ext = ".dll"
    else:
        raise RuntimeError(f"Unsupported platform: {system}")

    # Create temporary output file
    temp_dir = pathlib.Path(tempfile.gettempdir())
    lib_path = temp_dir / f"libsemantics_{function_name}{lib_ext}"
    _TEMP_LIBS.append(lib_path)

    # Determine include path for ida_types.h
    # Source is at: samples/src/c/dispatcher_patterns.c
    # Include is at: samples/include/ida_types.h
    # So we go up 2 levels from the .c file's parent dir
    include_dir = src_path.parent.parent.parent / "include"

    # Build compiler command
    # Use cc as default (symlinks to clang on macOS, gcc on Linux)
    compiler = "cc"
    cmd = [
        compiler,
        "-shared",
        "-fPIC",
        "-O0",  # No optimizations - preserve source semantics
        "-I", str(include_dir),  # Include directory for ida_types.h
        "-o", str(lib_path),
        str(src_path),
    ]

    # Add extra flags if provided
    if extra_cflags:
        cmd.extend(extra_cflags)

    # Compile
    logger.debug(f"Compiling {src_path} to {lib_path}")
    logger.debug(f"Command: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout:
            logger.debug(f"Compiler stdout: {result.stdout}")
        if result.stderr:
            logger.debug(f"Compiler stderr: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Compilation failed with exit code {e.returncode}")
        logger.error(f"Stdout: {e.stdout}")
        logger.error(f"Stderr: {e.stderr}")
        raise

    # Load and return library
    logger.debug(f"Loading library from {lib_path}")
    lib = ctypes.CDLL(str(lib_path))
    logger.debug(f"Successfully loaded library for {function_name}")

    return lib


def call_function(
    lib: ctypes.CDLL,
    function_name: str,
    args: tuple,
    restype: Any = ctypes.c_int32,
) -> int:
    """Call a function from a compiled library.

    Args:
        lib: Loaded ctypes.CDLL library
        function_name: Name of function to call
        args: Tuple of arguments to pass
        restype: Return type (default: ctypes.c_int32)

    Returns:
        Function return value

    Raises:
        AttributeError: If function not found in library

    Note:
        Uses ctypes.c_int32 for int parameters to match IDA's int type.
    """
    try:
        func = getattr(lib, function_name)
    except AttributeError:
        raise AttributeError(
            f"Function '{function_name}' not found in library. "
            f"Available symbols: {dir(lib)}"
        )

    # Set return type
    func.restype = restype

    # Set argument types (assume all int32 for now)
    func.argtypes = [ctypes.c_int32] * len(args)

    # Call and return
    result = func(*args)
    logger.debug(f"{function_name}{args} = {result}")

    return result


def assert_semantic_equivalence(
    c_source_path: str,
    function_name: str,
    test_cases: list[tuple[tuple, int]],
) -> None:
    """Assert that a function produces expected outputs for given inputs.

    Args:
        c_source_path: Path to C source file
        function_name: Name of function to test
        test_cases: List of (args, expected_output) tuples

    Raises:
        AssertionError: If any test case produces wrong output

    Example:
        test_cases = [
            ((10, 20), 39),
            ((50, 60), 49),
        ]
        assert_semantic_equivalence(
            "samples/src/c/dispatcher_patterns.c",
            "mixed_dispatcher_pattern",
            test_cases
        )
    """
    lib = compile_reference_function(c_source_path, function_name)

    failures = []
    for args, expected in test_cases:
        actual = call_function(lib, function_name, args)
        if actual != expected:
            failures.append(
                f"  {function_name}{args}: expected {expected}, got {actual}"
            )

    if failures:
        raise AssertionError(
            f"Semantic equivalence check failed for {function_name}:\n"
            + "\n".join(failures)
        )

    logger.info(
        f"Semantic equivalence verified for {function_name}: "
        f"{len(test_cases)} test cases passed"
    )


def generate_test_cases(
    c_source_path: str,
    function_name: str,
    arg_ranges: list[tuple[int, int]],
    num_cases: int = 20,
    seed: int = 42,
) -> list[tuple[tuple, int]]:
    """Generate random test cases by compiling and calling reference function.

    Args:
        c_source_path: Path to C source file
        function_name: Name of function to test
        arg_ranges: List of (min, max) ranges for each argument
        num_cases: Number of test cases to generate
        seed: Random seed for deterministic generation

    Returns:
        List of (args, expected_output) tuples

    Example:
        # Generate 20 test cases for function with 2 int arguments
        test_cases = generate_test_cases(
            "samples/src/c/dispatcher_patterns.c",
            "mixed_dispatcher_pattern",
            arg_ranges=[(-100, 100), (-100, 100)],
            num_cases=20,
            seed=42,
        )
        # Returns: [((10, 20), 39), ((50, 60), 49), ...]
    """
    lib = compile_reference_function(c_source_path, function_name)

    # Set random seed for deterministic generation
    rng = random.Random(seed)

    test_cases = []
    for _ in range(num_cases):
        # Generate random args within ranges
        args = tuple(rng.randint(min_val, max_val) for min_val, max_val in arg_ranges)

        # Call function to get expected output
        output = call_function(lib, function_name, args)

        test_cases.append((args, output))

    logger.info(f"Generated {num_cases} test cases for {function_name}")
    return test_cases
