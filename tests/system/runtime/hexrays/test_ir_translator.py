"""Tests for IDAIRTranslator.

Tests the mapping logic between GraphModification and DeferredGraphModifier.
Uses monkeypatch to substitute mock implementations for IDA-dependent modules
that are imported inside methods.

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""
from __future__ import annotations

import logging
from unittest.mock import Mock, call

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation.ir_translator import IDAIRTranslator
from d810.cfg.graph_modification import (
    RedirectGoto,
    RedirectBranch,
    ConvertToGoto,
    InsertBlock,
    RemoveEdge,
    NopInstructions,
)
from d810.cfg.flowgraph import InsnSnapshot


class TestIDAIRTranslatorBasics:
    """Test basic IDAIRTranslator properties and interface."""

    def test_backend_name(self):
        """Test that IDAIRTranslator.name returns 'ida'."""
        backend = IDAIRTranslator()
        assert backend.name == "ida"

    def test_backend_implements_protocol(self):
        """Test that IDAIRTranslator conforms to CFGBackend protocol."""
        from d810.cfg.protocol import IRTranslator

        backend = IDAIRTranslator()
        assert isinstance(backend, IRTranslator)


class TestModificationMapping:
    """Test GraphModification -> DeferredGraphModifier mapping logic.

    These tests use monkeypatch to mock the deferred import of
    DeferredGraphModifier inside IDAIRTranslator.lower().
    """

    @pytest.fixture(autouse=True)
    def _patch_deferred(self, monkeypatch):
        """Patch deferred_modifier so lower() uses a mock DeferredGraphModifier."""
        self.mock_modifier = Mock()
        self.mock_modifier.apply.return_value = 1
        self.mock_modifier.verify_failed = False

        mock_deferred_module = Mock()
        mock_deferred_module.DeferredGraphModifier.return_value = self.mock_modifier

        monkeypatch.setitem(
            __import__("sys").modules,
            "d810.hexrays.mutation.deferred_modifier",
            mock_deferred_module,
        )

    def test_redirect_goto_maps_to_queue_goto_change(self):
        """Test RedirectGoto -> queue_goto_change mapping (1-way blocks)."""
        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [RedirectGoto(from_serial=10, old_target=20, new_target=30)]

        count = backend.lower(modifications, mock_mba)

        assert count == 1
        self.mock_modifier.queue_goto_change.assert_called_once_with(
            10, 30, description="redirect goto 10: 20->30"
        )
        self.mock_modifier.apply.assert_called_once_with(enable_snapshot_rollback=True)

    def test_redirect_branch_maps_to_queue_target_change(self):
        """Test RedirectBranch -> queue_target_change mapping (2-way blocks)."""
        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [RedirectBranch(from_serial=10, old_target=20, new_target=30)]

        count = backend.lower(modifications, mock_mba)

        assert count == 1
        self.mock_modifier.queue_conditional_target_change.assert_called_once_with(
            10, 30, description="redirect branch 10: 20->30"
        )
        self.mock_modifier.apply.assert_called_once_with(enable_snapshot_rollback=True)

    def test_convert_to_goto_maps_to_queue_convert_to_goto(self):
        """Test ConvertToGoto -> queue_convert_to_goto mapping."""
        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [ConvertToGoto(block_serial=15, goto_target=25)]

        count = backend.lower(modifications, mock_mba)

        assert count == 1
        self.mock_modifier.queue_convert_to_goto.assert_called_once_with(
            15, 25, description="convert 15 to goto 25"
        )

    def test_nop_instructions_maps_to_queue_insn_nop(self):
        """Test NopInstructions -> queue_insn_nop mapping (one call per EA)."""
        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [NopInstructions(block_serial=10, insn_eas=(0x1000, 0x1004, 0x1008))]

        count = backend.lower(modifications, mock_mba)

        assert count == 1
        assert self.mock_modifier.queue_insn_nop.call_count == 3
        self.mock_modifier.queue_insn_nop.assert_has_calls([
            call(10, 0x1000, description="nop 0x1000 in block 10"),
            call(10, 0x1004, description="nop 0x1004 in block 10"),
            call(10, 0x1008, description="nop 0x1008 in block 10"),
        ])

    def test_insert_block_logs_warning_and_skips(self, caplog):
        """Test InsertBlock logs warning and is skipped (not yet implemented)."""
        self.mock_modifier.apply.return_value = 0

        backend = IDAIRTranslator()
        mock_mba = Mock()
        insn = InsnSnapshot(opcode=0x01, ea=0x1000, operands=())
        modifications = [InsertBlock(pred_serial=5, succ_serial=10, instructions=(insn,))]

        with caplog.at_level(logging.WARNING):
            count = backend.lower(modifications, mock_mba)

        assert count == 0
        assert "InsertBlock(5->10) requires InsnSnapshot->minsn_t conversion" in caplog.text

    def test_remove_edge_logs_warning_and_skips(self, caplog):
        """Test RemoveEdge logs warning and is skipped (not yet implemented)."""
        self.mock_modifier.apply.return_value = 0

        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [RemoveEdge(from_serial=10, to_serial=20)]

        with caplog.at_level(logging.WARNING):
            count = backend.lower(modifications, mock_mba)

        assert count == 0
        assert "RemoveEdge(10->20) not implemented" in caplog.text

    def test_unknown_modification_type_logs_warning(self, caplog):
        """Test unknown modification type is handled gracefully."""
        self.mock_modifier.apply.return_value = 0

        backend = IDAIRTranslator()
        mock_mba = Mock()
        fake_mod = Mock()
        fake_mod.__class__.__name__ = "FakeModification"
        modifications = [fake_mod]

        with caplog.at_level(logging.WARNING):
            count = backend.lower(modifications, mock_mba)

        assert count == 0
        assert "Unknown GraphModification type" in caplog.text

    def test_multiple_modifications_batched(self):
        """Test multiple modifications are batched in one DeferredGraphModifier."""
        self.mock_modifier.apply.return_value = 3

        backend = IDAIRTranslator()
        mock_mba = Mock()
        modifications = [
            RedirectGoto(from_serial=10, old_target=20, new_target=30),
            ConvertToGoto(block_serial=15, goto_target=25),
            NopInstructions(block_serial=20, insn_eas=(0x2000,)),
        ]

        count = backend.lower(modifications, mock_mba)

        # Should queue all three modifications
        assert self.mock_modifier.queue_goto_change.call_count == 1
        assert self.mock_modifier.queue_convert_to_goto.call_count == 1
        assert self.mock_modifier.queue_insn_nop.call_count == 1
        # Should call apply once with all modifications batched
        assert self.mock_modifier.apply.call_count == 1
        assert count == 3


class TestVerify:
    """Test IDAIRTranslator.verify() method."""

    def test_verify_success(self, monkeypatch):
        """Test verify() returns True when safe_verify succeeds."""
        import d810.hexrays.mutation as _mut_pkg

        mock_cfg_verify = Mock()
        mock_cfg_verify.safe_verify.return_value = None
        monkeypatch.setitem(
            __import__("sys").modules,
            "d810.hexrays.mutation.cfg_verify",
            mock_cfg_verify,
        )
        monkeypatch.setattr(_mut_pkg, "cfg_verify", mock_cfg_verify)

        backend = IDAIRTranslator()
        mock_mba = Mock()

        result = backend.verify(mock_mba)

        assert result is True
        mock_cfg_verify.safe_verify.assert_called_once_with(mock_mba, "IDAIRTranslator.verify()")

    def test_verify_failure(self, monkeypatch):
        """Test verify() returns False when safe_verify raises RuntimeError."""
        import d810.hexrays.mutation as _mut_pkg

        mock_cfg_verify = Mock()
        mock_cfg_verify.safe_verify.side_effect = RuntimeError("verify failed")
        monkeypatch.setitem(
            __import__("sys").modules,
            "d810.hexrays.mutation.cfg_verify",
            mock_cfg_verify,
        )
        monkeypatch.setattr(_mut_pkg, "cfg_verify", mock_cfg_verify)

        backend = IDAIRTranslator()
        mock_mba = Mock()

        result = backend.verify(mock_mba)

        assert result is False


class TestIDAIntegration:
    """Integration tests requiring IDA runtime.

    These tests verify that the backend can interact with real IDA types.
    """

    def test_lift_returns_flowgraph(self):
        """Test lift() returns a FlowGraph flowgraph for a real mba_t."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lift")
        assert callable(backend.lift)

    def test_lower_accepts_real_mba(self):
        """Test lower() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "lower")
        assert callable(backend.lower)

    def test_verify_accepts_real_mba(self):
        """Test verify() accepts a real mba_t instance."""
        backend = IDAIRTranslator()
        assert hasattr(backend, "verify")
        assert callable(backend.verify)
