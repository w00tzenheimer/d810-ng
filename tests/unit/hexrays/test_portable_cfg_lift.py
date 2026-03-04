"""Unit tests for lift_portable_cfg lift functions.

Tests the lift() and lift_block() functions' behavior when IDA is not available.
IDA-dependent tests (with actual mba_t objects) go in tests/system/runtime/.
"""
import pytest


def test_lift_raises_when_ida_not_available(monkeypatch):
    """Test that lift() raises RuntimeError when IDA is not available."""
    # Import the module first
    from d810.hexrays.ir import lift_portable_cfg as portable_cfg

    # Monkeypatch the IDA availability flag
    monkeypatch.setattr(portable_cfg, "_IDA_AVAILABLE", False)

    # Attempt to call lift() should raise RuntimeError
    with pytest.raises(RuntimeError, match="lift requires IDA Hexrays"):
        portable_cfg.lift(None)  # type: ignore


def test_lift_block_raises_when_ida_not_available(monkeypatch):
    """Test that lift_block() raises RuntimeError when IDA is not available."""
    # Import the module first
    from d810.hexrays.ir import lift_portable_cfg as portable_cfg

    # Monkeypatch the IDA availability flag
    monkeypatch.setattr(portable_cfg, "_IDA_AVAILABLE", False)

    # Attempt to call lift_block() should raise RuntimeError
    with pytest.raises(RuntimeError, match="lift_block requires IDA Hexrays"):
        portable_cfg.lift_block(None)  # type: ignore
