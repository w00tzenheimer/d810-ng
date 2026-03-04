"""Unit tests for IDAIRTranslator lift helpers.

Tests the lift() and lift_block() helper behavior when IDA is not available.
IDA-dependent tests (with actual mba_t objects) go in tests/system/runtime/.
"""
import pytest


def test_lift_raises_when_ida_not_available(monkeypatch):
    """Test that lift() raises RuntimeError when IDA is not available."""
    from d810.hexrays.mutation import ir_translator

    # Monkeypatch the IDA availability flag
    monkeypatch.setattr(ir_translator, "_IDA_AVAILABLE", False)

    # Attempt to call lift() should raise RuntimeError
    with pytest.raises(RuntimeError, match="lift requires IDA Hexrays"):
        ir_translator.lift(None)  # type: ignore


def test_lift_block_raises_when_ida_not_available(monkeypatch):
    """Test that lift_block() raises RuntimeError when IDA is not available."""
    from d810.hexrays.mutation import ir_translator

    # Monkeypatch the IDA availability flag
    monkeypatch.setattr(ir_translator, "_IDA_AVAILABLE", False)

    # Attempt to call lift_block() should raise RuntimeError
    with pytest.raises(RuntimeError, match="lift_block requires IDA Hexrays"):
        ir_translator.lift_block(None)  # type: ignore
