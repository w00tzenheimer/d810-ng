"""Benchmark tests comparing Cython vs Pure Python performance.

Run inside IDA to measure the speedup from Cython implementations.

Usage:
    pytest tests/system/test_cython_benchmark.py -v -s
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable

import pytest

import ida_hexrays

# Import both implementations directly for comparison
try:
    from d810.speedups.expr import c_ast as cython_ast
    CYTHON_AVAILABLE = True
except ImportError:
    CYTHON_AVAILABLE = False

from d810.expr import p_ast as python_ast


@dataclass
class BenchResult:
    name: str
    cython_time: float
    python_time: float
    iterations: int

    @property
    def speedup(self) -> float:
        if self.cython_time == 0:
            return float('inf')
        return self.python_time / self.cython_time

    def report(self) -> str:
        return (
            f"\n{self.name}:\n"
            f"  Cython:      {self.cython_time * 1000:.2f} ms ({self.iterations} iterations)\n"
            f"  Pure Python: {self.python_time * 1000:.2f} ms ({self.iterations} iterations)\n"
            f"  Speedup:     {self.speedup:.2f}x"
        )


def timed_run(func: Callable[[], None], iterations: int) -> float:
    """Run function multiple times and return total elapsed time."""
    # Warmup
    for _ in range(min(5, iterations // 10)):
        func()

    start = time.perf_counter()
    for _ in range(iterations):
        func()
    return time.perf_counter() - start


@pytest.mark.skipif(not CYTHON_AVAILABLE, reason="Cython extensions not built")
class TestCythonBenchmark:
    """Benchmark tests for Cython vs Pure Python performance."""

    def test_ast_node_creation(self):
        """Benchmark AST node creation."""
        iterations = 1000

        def create_cython():
            leaf1 = cython_ast.AstLeaf("x_0")
            leaf2 = cython_ast.AstLeaf("x_1")
            const = cython_ast.AstConstant("42", 42)
            add_node = cython_ast.AstNode(ida_hexrays.m_add, leaf1, leaf2)
            and_node = cython_ast.AstNode(ida_hexrays.m_and, leaf1, leaf2)
            sub_node = cython_ast.AstNode(ida_hexrays.m_sub, add_node, and_node)
            return sub_node

        def create_python():
            leaf1 = python_ast.AstLeaf("x_0")
            leaf2 = python_ast.AstLeaf("x_1")
            const = python_ast.AstConstant("42", 42)
            add_node = python_ast.AstNode(ida_hexrays.m_add, leaf1, leaf2)
            and_node = python_ast.AstNode(ida_hexrays.m_and, leaf1, leaf2)
            sub_node = python_ast.AstNode(ida_hexrays.m_sub, add_node, and_node)
            return sub_node

        cython_time = timed_run(create_cython, iterations)
        python_time = timed_run(create_python, iterations)

        result = BenchResult("AST Node Creation", cython_time, python_time, iterations)
        print(result.report())

        # Note: Benchmark is informative only - results vary by environment

    def test_ast_clone(self):
        """Benchmark AST cloning operations."""
        iterations = 500

        # Create trees with both implementations
        def make_cython_tree():
            x = cython_ast.AstLeaf("x_0")
            y = cython_ast.AstLeaf("x_1")
            z = cython_ast.AstLeaf("x_2")
            return cython_ast.AstNode(
                ida_hexrays.m_sub,
                cython_ast.AstNode(ida_hexrays.m_or, x, y),
                cython_ast.AstNode(
                    ida_hexrays.m_and,
                    cython_ast.AstNode(ida_hexrays.m_xor, x, z),
                    y,
                ),
            )

        def make_python_tree():
            x = python_ast.AstLeaf("x_0")
            y = python_ast.AstLeaf("x_1")
            z = python_ast.AstLeaf("x_2")
            return python_ast.AstNode(
                ida_hexrays.m_sub,
                python_ast.AstNode(ida_hexrays.m_or, x, y),
                python_ast.AstNode(
                    ida_hexrays.m_and,
                    python_ast.AstNode(ida_hexrays.m_xor, x, z),
                    y,
                ),
            )

        cython_tree = make_cython_tree()
        python_tree = make_python_tree()

        cython_time = timed_run(cython_tree.clone, iterations)
        python_time = timed_run(python_tree.clone, iterations)

        result = BenchResult("AST Clone", cython_time, python_time, iterations)
        print(result.report())

        # Note: Benchmark is informative only - results vary by environment

    def test_ast_get_pattern(self):
        """Benchmark AST pattern string generation."""
        iterations = 500

        # Create trees
        def make_cython_tree():
            x = cython_ast.AstLeaf("x_0")
            y = cython_ast.AstLeaf("x_1")
            return cython_ast.AstNode(
                ida_hexrays.m_sub,
                cython_ast.AstNode(ida_hexrays.m_or, x, y),
                cython_ast.AstNode(ida_hexrays.m_and, x, y),
            )

        def make_python_tree():
            x = python_ast.AstLeaf("x_0")
            y = python_ast.AstLeaf("x_1")
            return python_ast.AstNode(
                ida_hexrays.m_sub,
                python_ast.AstNode(ida_hexrays.m_or, x, y),
                python_ast.AstNode(ida_hexrays.m_and, x, y),
            )

        cython_tree = make_cython_tree()
        python_tree = make_python_tree()

        cython_time = timed_run(cython_tree.get_pattern, iterations)
        python_time = timed_run(python_tree.get_pattern, iterations)

        result = BenchResult("AST Get Pattern", cython_time, python_time, iterations)
        print(result.report())

        # Note: Benchmark is informative only - results vary by environment

    def test_ast_get_leaf_list(self):
        """Benchmark AST leaf list extraction."""
        iterations = 500

        # Create trees with multiple leaves
        def make_cython_tree():
            x = cython_ast.AstLeaf("x_0")
            y = cython_ast.AstLeaf("x_1")
            z = cython_ast.AstLeaf("x_2")
            w = cython_ast.AstLeaf("x_3")
            return cython_ast.AstNode(
                ida_hexrays.m_add,
                cython_ast.AstNode(ida_hexrays.m_sub, x, y),
                cython_ast.AstNode(ida_hexrays.m_mul, z, w),
            )

        def make_python_tree():
            x = python_ast.AstLeaf("x_0")
            y = python_ast.AstLeaf("x_1")
            z = python_ast.AstLeaf("x_2")
            w = python_ast.AstLeaf("x_3")
            return python_ast.AstNode(
                ida_hexrays.m_add,
                python_ast.AstNode(ida_hexrays.m_sub, x, y),
                python_ast.AstNode(ida_hexrays.m_mul, z, w),
            )

        cython_tree = make_cython_tree()
        python_tree = make_python_tree()

        cython_time = timed_run(cython_tree.get_leaf_list, iterations)
        python_time = timed_run(python_tree.get_leaf_list, iterations)

        result = BenchResult("AST Get Leaf List", cython_time, python_time, iterations)
        print(result.report())

        # Note: Some operations may not benefit from Cython due to Python object overhead
        # This test is informative, not a strict requirement


class TestCythonAvailability:
    """Tests to verify Cython extensions are properly loaded."""

    def test_cython_extensions_loaded(self):
        """Verify that Cython extensions are available."""
        try:
            from d810.speedups.expr import c_ast
            from d810.speedups.expr import c_ast_evaluate
            cython_available = True
        except ImportError as e:
            print(f"\nCython import error: {e}")
            cython_available = False

        print(f"\nCython extensions available: {cython_available}")

        # This test documents the state, doesn't assert
        if not cython_available:
            pytest.skip("Cython extensions not built - run: IDA_SDK=... python setup.py build_ext --inplace")

    def test_cython_mode_toggle(self):
        """Verify CythonMode can be toggled."""
        from d810.core import CythonMode

        mode = CythonMode()
        initial_state = mode.is_enabled()

        mode.disable()
        assert not mode.is_enabled(), "Should be disabled"

        mode.enable()
        assert mode.is_enabled(), "Should be enabled"

        # Restore original state
        if not initial_state:
            mode.disable()
