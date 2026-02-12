"""System regression test for AstProxy/AstNode compatibility in Z3 constant folding.

This test runs a real deobfuscation flow against the libobfuscated sample and
ensures Z3ConstantOptimization can fire without the SWIG director TypeError:
    expected AstNode, got AstProxy
"""

from __future__ import annotations

import os
import platform

import idaapi
import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


def _get_default_binary() -> str:
    """Get default binary name based on platform, with env var override."""
    override = os.environ.get("D810_TEST_BINARY")
    if override:
        return override
    return "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"


@pytest.fixture(scope="class")
def libobfuscated_setup(ida_database, configure_hexrays, setup_libobfuscated_funcs):
    """Setup fixture for libobfuscated tests - runs once per class."""
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    return ida_database


class TestZ3AstProxyRegression:
    """Regression coverage for AstProxy -> AstNode replacement path."""

    binary_name = _get_default_binary()

    def test_z3_constant_optimization_astproxy_path(
        self,
        libobfuscated_setup,
        d810_state,
        pseudocode_to_string,
        code_comparator,
        capture_stats,
        load_expected_stats,
        capsys,
    ):
        case = DeobfuscationCase(
            function="test_cst_simplification",
            description="Regression: Z3 replacement must handle AstProxy candidates",
            project="default_instruction_only.json",
            required_rules=["Z3ConstantOptimization"],
            must_change=True,
        )

        run_deobfuscation_test(
            case=case,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
            code_comparator=code_comparator,
            capture_stats=capture_stats,
            load_expected_stats=load_expected_stats,
        )

        captured = capsys.readouterr()
        output = f"{captured.out}\n{captured.err}"
        assert "SwigDirector_optinsn_t::func" not in output
        assert "expected d810.speedups.expr.c_ast.AstNode, got d810.speedups.expr.c_ast.AstProxy" not in output

