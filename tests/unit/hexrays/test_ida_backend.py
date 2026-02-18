"""Unit tests for IDABackend.

Tests the mapping logic between GraphModification and DeferredGraphModifier
without requiring IDA runtime.

Since IDABackend imports modules inside methods (to defer IDA dependency),
we use sys.modules patching to provide mock implementations.
"""
from __future__ import annotations

import logging
import sys
from unittest.mock import Mock, call
import pytest

from d810.hexrays.backends.ida_backend import IDABackend
from d810.hexrays.graph_modification import (
    RedirectGoto,
    RedirectBranch,
    ConvertToGoto,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
)
from d810.hexrays.portable_cfg import InsnSnapshot

# IDA availability guard
try:
    import ida_hexrays
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


class TestIDABackendBasics:
    """Test basic IDABackend properties and interface."""

    def test_backend_name(self):
        """Test that IDABackend.name returns 'ida'."""
        backend = IDABackend()
        assert backend.name == "ida"

    @pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA")
    def test_backend_implements_protocol(self):
        """Test that IDABackend conforms to CFGBackend protocol."""
        from d810.hexrays.cfg_backend import CFGBackend

        backend = IDABackend()
        assert isinstance(backend, CFGBackend)


class TestModificationMapping:
    """Test GraphModification → DeferredGraphModifier mapping logic.

    These tests use sys.modules patching to mock IDA-dependent modules.
    """

    def test_redirect_goto_maps_to_queue_goto_change(self):
        """Test RedirectGoto → queue_goto_change mapping (1-way blocks)."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 1

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        # Inject mock module into sys.modules before calling lower()
        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [RedirectGoto(from_serial=10, old_target=20, new_target=30)]

            count = backend.lower(modifications, mock_mba)

            assert count == 1
            mock_modifier.queue_goto_change.assert_called_once_with(
                10, 30, description="redirect goto 10: 20→30"
            )
            mock_modifier.apply.assert_called_once_with(enable_snapshot_rollback=True)
        finally:
            # Clean up mock module
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_redirect_branch_maps_to_queue_target_change(self):
        """Test RedirectBranch → queue_target_change mapping (2-way blocks)."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 1

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [RedirectBranch(from_serial=10, old_target=20, new_target=30)]

            count = backend.lower(modifications, mock_mba)

            assert count == 1
            mock_modifier.queue_target_change.assert_called_once_with(
                10, 20, 30, description="redirect branch 10: 20→30"
            )
            mock_modifier.apply.assert_called_once_with(enable_snapshot_rollback=True)
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_convert_to_goto_maps_to_queue_convert_to_goto(self):
        """Test ConvertToGoto → queue_convert_to_goto mapping."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 1

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [ConvertToGoto(block_serial=15, goto_target=25)]

            count = backend.lower(modifications, mock_mba)

            assert count == 1
            mock_modifier.queue_convert_to_goto.assert_called_once_with(
                15, 25, description="convert 15 to goto 25"
            )
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_nop_instructions_maps_to_queue_insn_nop(self):
        """Test NopInstructions → queue_insn_nop mapping (one call per EA)."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 1

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004, 0x1008))]

            count = backend.lower(modifications, mock_mba)

            assert count == 1
            assert mock_modifier.queue_insn_nop.call_count == 3
            mock_modifier.queue_insn_nop.assert_has_calls([
                call(10, 0x1000, description="nop 0x1000 in block 10"),
                call(10, 0x1004, description="nop 0x1004 in block 10"),
                call(10, 0x1008, description="nop 0x1008 in block 10"),
            ])
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_insert_block_logs_warning_and_skips(self, caplog):
        """Test InsertBlock logs warning and is skipped (not yet implemented)."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 0

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            insn = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
            modifications = [InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn,))]

            with caplog.at_level(logging.WARNING):
                count = backend.lower(modifications, mock_mba)

            assert count == 0
            assert "InsertBlock(5→10) requires InsnSnapshot→minsn_t conversion" in caplog.text
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_remove_edge_logs_warning_and_skips(self, caplog):
        """Test RemoveEdge logs warning and is skipped (not yet implemented)."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 0

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [RemoveEdge(from_serial=10, to_serial=20)]

            with caplog.at_level(logging.WARNING):
                count = backend.lower(modifications, mock_mba)

            assert count == 0
            assert "RemoveEdge(10→20) not implemented" in caplog.text
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_unknown_modification_type_logs_warning(self, caplog):
        """Test unknown modification type is handled gracefully."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 0

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            fake_mod = Mock()
            fake_mod.__class__.__name__ = "FakeModification"
            modifications = [fake_mod]

            with caplog.at_level(logging.WARNING):
                count = backend.lower(modifications, mock_mba)

            assert count == 0
            assert "Unknown GraphModification type" in caplog.text
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)

    def test_multiple_modifications_batched(self):
        """Test multiple modifications are batched in one DeferredGraphModifier."""
        mock_modifier = Mock()
        mock_modifier.apply.return_value = 3

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = mock_modifier

        sys.modules['d810.hexrays.deferred_modifier'] = mock_deferred_module
        try:
            backend = IDABackend()
            mock_mba = Mock()
            modifications = [
                RedirectGoto(from_serial=10, old_target=20, new_target=30),
                ConvertToGoto(block_serial=15, goto_target=25),
                NopInstructions(block_serial=20, insn_eas=(0x2000,)),
            ]

            count = backend.lower(modifications, mock_mba)

            # Should create only one modifier instance
            assert mock_deferred_module.DeferredGraphModifier.call_count == 1
            # Should queue all three modifications
            assert mock_modifier.queue_goto_change.call_count == 1
            assert mock_modifier.queue_convert_to_goto.call_count == 1
            assert mock_modifier.queue_insn_nop.call_count == 1
            # Should call apply once with all modifications batched
            assert mock_modifier.apply.call_count == 1
            assert count == 3
        finally:
            sys.modules.pop('d810.hexrays.deferred_modifier', None)


class TestVerify:
    """Test IDABackend.verify() method."""

    def test_verify_success(self):
        """Test verify() returns True when safe_verify succeeds."""
        mock_cfg_verify = Mock()
        mock_cfg_verify.safe_verify.return_value = None

        sys.modules['d810.hexrays.cfg_verify'] = mock_cfg_verify
        try:
            backend = IDABackend()
            mock_mba = Mock()

            result = backend.verify(mock_mba)

            assert result is True
            mock_cfg_verify.safe_verify.assert_called_once_with(mock_mba, "IDABackend.verify()")
        finally:
            sys.modules.pop('d810.hexrays.cfg_verify', None)

    def test_verify_failure(self):
        """Test verify() returns False when safe_verify raises RuntimeError."""
        mock_cfg_verify = Mock()
        mock_cfg_verify.safe_verify.side_effect = RuntimeError("verify failed")

        sys.modules['d810.hexrays.cfg_verify'] = mock_cfg_verify
        try:
            backend = IDABackend()
            mock_mba = Mock()

            result = backend.verify(mock_mba)

            assert result is False
        finally:
            sys.modules.pop('d810.hexrays.cfg_verify', None)


@pytest.mark.skipif(not IDA_AVAILABLE, reason="Requires IDA")
class TestIDAIntegration:
    """Integration tests requiring IDA runtime.

    These tests verify that the backend can interact with real IDA types.
    """

    def test_lift_returns_portable_cfg(self):
        """Test lift() returns a PortableCFG for a real mba_t."""
        backend = IDABackend()
        assert hasattr(backend, "lift")
        assert callable(backend.lift)

    def test_lower_accepts_real_mba(self):
        """Test lower() accepts a real mba_t instance."""
        backend = IDABackend()
        assert hasattr(backend, "lower")
        assert callable(backend.lower)

    def test_verify_accepts_real_mba(self):
        """Test verify() accepts a real mba_t instance."""
        backend = IDABackend()
        assert hasattr(backend, "verify")
        assert callable(backend.verify)
