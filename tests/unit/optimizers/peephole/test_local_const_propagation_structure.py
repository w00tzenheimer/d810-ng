"""Structural tests for LocalizedConstantPropagationRule register tracking.

These are SOURCE-LEVEL tests only (no IDA import) because the module
uses ida_hexrays.m_* constants at module level.
"""
import pathlib

SRC = pathlib.Path(
    "src/d810/optimizers/microcode/instructions/peephole/local_const_propagation.py"
).read_text()


def test_register_operand_type_referenced():
    """Rule must reference mop_r (register operand type) for register tracking."""
    assert "mop_r" in SRC, "Rule must handle mop_r operand type for register propagation"


def test_ldc_opcode_referenced():
    """Rule must recognise m_ldc (load-constant instruction) to track register assignments."""
    assert "m_ldc" in SRC, "Rule must handle m_ldc opcode"


def test_register_constant_map_exists():
    """Rule must maintain a register->constant map (any name containing 'reg' is fine)."""
    assert any(
        name in SRC for name in (
            "_reg_constants", "_reg_map", "_known_regs",
            "_register_constants", "reg_const", "reg_values",
        )
    ), "Expect a register-constant mapping attribute (e.g. _reg_constants)"
