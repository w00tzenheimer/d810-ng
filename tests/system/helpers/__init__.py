"""Test helpers for d810 system tests.

This package provides utilities for system testing:
- semantic_equivalence: Compile and execute C code to verify deobfuscation correctness
"""

from .semantic_equivalence import (
    assert_semantic_equivalence,
    call_function,
    compile_reference_function,
    generate_test_cases,
)

__all__ = [
    "assert_semantic_equivalence",
    "call_function",
    "compile_reference_function",
    "generate_test_cases",
]
