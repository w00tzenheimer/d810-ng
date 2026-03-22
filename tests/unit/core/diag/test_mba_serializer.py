"""Tests for mba_serializer module (IDA-free unit tests).

Since ``mba_to_block_snapshots`` requires ``ida_hexrays`` at runtime,
unit tests focus on the import guard behavior and the module-level
contract.  Full integration tests that exercise the serializer with
a real MBA belong in ``tests/system/``.
"""
from __future__ import annotations

import importlib
import sys
from unittest import mock

import pytest


class TestMbaSerializerImportGuard:
    """Verify that the module handles missing ida_hexrays gracefully."""

    def test_module_importable_without_ida(self) -> None:
        """The module must be importable even when ida_hexrays is not available."""
        # Force ida_hexrays to be absent for the duration of this test
        saved = sys.modules.get("ida_hexrays")
        try:
            sys.modules["ida_hexrays"] = None  # type: ignore[assignment]
            # Remove cached module if it was already imported
            sys.modules.pop("d810.core.diag.mba_serializer", None)
            mod = importlib.import_module("d810.core.diag.mba_serializer")
            assert mod._ihr is None
        finally:
            if saved is not None:
                sys.modules["ida_hexrays"] = saved
            else:
                sys.modules.pop("ida_hexrays", None)
            # Restore cached module
            sys.modules.pop("d810.core.diag.mba_serializer", None)

    def test_mba_to_block_snapshots_raises_without_ida(self) -> None:
        """Calling mba_to_block_snapshots without IDA raises RuntimeError."""
        saved = sys.modules.get("ida_hexrays")
        try:
            sys.modules["ida_hexrays"] = None  # type: ignore[assignment]
            sys.modules.pop("d810.core.diag.mba_serializer", None)
            mod = importlib.import_module("d810.core.diag.mba_serializer")
            with pytest.raises(RuntimeError, match="requires ida_hexrays"):
                mod.mba_to_block_snapshots(mock.MagicMock())
        finally:
            if saved is not None:
                sys.modules["ida_hexrays"] = saved
            else:
                sys.modules.pop("ida_hexrays", None)
            sys.modules.pop("d810.core.diag.mba_serializer", None)


class TestMbaSerializerExports:
    """Verify public API surface of the module."""

    def test_public_function_exists(self) -> None:
        from d810.core.diag.mba_serializer import mba_to_block_snapshots

        assert callable(mba_to_block_snapshots)

    def test_snapshot_types_reexported(self) -> None:
        """BlockSnapshot and InstructionSnapshot should be accessible."""
        from d810.core.diag.mba_serializer import BlockSnapshot, InstructionSnapshot

        assert BlockSnapshot is not None
        assert InstructionSnapshot is not None
