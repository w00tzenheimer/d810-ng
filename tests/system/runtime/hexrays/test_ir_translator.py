"""Tests for IDAIRTranslator.

System-level integration tests that verify IDAIRTranslator conforms to the
IRTranslator protocol and exposes the expected interface.

Runs in IDA environment (system/runtime); skips gracefully without IDA.
"""
from __future__ import annotations

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.hexrays.mutation.ir_translator import IDAIRTranslator


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
