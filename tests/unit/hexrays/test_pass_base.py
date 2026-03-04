"""Tests for FlowGraphTransform abstract base class and CFGBackend protocol.

This module tests:
- FlowGraphTransform subclassing and validation
- CFGBackend protocol conformance (runtime_checkable)
- InMemoryBackend implementation for testing
- Concrete pass examples (NoOpPass, CountBlocksPass)
"""
from __future__ import annotations

import pytest

from d810.cfg.protocol import IRTranslator
from d810.cfg.passes._base import FlowGraphTransform
from d810.cfg.graph_modification import ConvertToGoto, GraphModification
from d810.cfg.flowgraph import BlockSnapshot, InsnSnapshot, FlowGraph
from tests.unit.hexrays.conftest import InMemoryBackend


# ============================================================================
# Concrete FlowGraphTransform Examples for Testing
# ============================================================================


class NoOpPass(FlowGraphTransform):
    """Pass that does nothing (returns empty modification list)."""
    name = "noop"

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return empty list."""
        return []


class CountBlocksPass(FlowGraphTransform):
    """Pass that returns ConvertToGoto for each block with nsucc==0."""
    name = "count_blocks"
    tags = frozenset({"test", "example"})

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return ConvertToGoto for terminal blocks.

        Args:
            cfg: FlowGraph to analyze.

        Returns:
            List with ConvertToGoto for each block with nsucc==0.
            Targets serial 0 (entry) as dummy target.
        """
        modifications = []
        for serial, blk in cfg.blocks.items():
            if blk.nsucc == 0:
                # Use entry block (0) as dummy target
                modifications.append(ConvertToGoto(block_serial=serial, goto_target=0))
        return modifications


class ConditionalPass(FlowGraphTransform):
    """Pass that only applies to CFGs with >2 blocks."""
    name = "conditional"

    def is_applicable(self, cfg: FlowGraph) -> bool:
        """Only apply if more than 2 blocks."""
        return cfg.num_blocks > 2

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return empty list (just for testing is_applicable)."""
        return []


# ============================================================================
# Tests
# ============================================================================


class TestInMemoryBackend:
    """Tests for InMemoryBackend protocol conformance."""

    def test_conforms_to_protocol(self):
        """InMemoryBackend should satisfy CFGBackend protocol."""
        backend = InMemoryBackend()
        assert isinstance(backend, IRTranslator)

    def test_name_property(self):
        """Backend should have 'name' property."""
        backend = InMemoryBackend()
        assert backend.name == "in_memory"

    def test_lift_empty_blocks(self):
        """Lift with empty blocks should return minimal CFG."""
        backend = InMemoryBackend()
        cfg = backend.lift()
        assert cfg.num_blocks == 0
        assert cfg.entry_serial == 0
        assert cfg.func_ea == 0

    def test_lift_with_blocks(self):
        """Lift with blocks should return FlowGraph."""
        # Create synthetic blocks
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1}

        backend = InMemoryBackend(blocks)
        cfg = backend.lift()

        assert cfg.num_blocks == 2
        assert cfg.entry_serial == 0
        assert cfg.func_ea == 0x1000
        assert 0 in cfg.blocks
        assert 1 in cfg.blocks

    def test_lower_records_modifications(self):
        """Lower should record modifications and return count."""
        backend = InMemoryBackend()
        mods = [
            ConvertToGoto(block_serial=1, goto_target=2),
            ConvertToGoto(block_serial=3, goto_target=4),
        ]

        count = backend.lower(mods)

        assert count == 2
        assert len(backend.applied_modifications) == 2
        assert backend.applied_modifications[0].block_serial == 1
        assert backend.applied_modifications[1].block_serial == 3

    def test_verify_always_true(self):
        """Verify should always return True (mock has no validation)."""
        backend = InMemoryBackend()
        assert backend.verify() is True


class TestCFGPass:
    """Tests for FlowGraphTransform abstract base class."""

    def test_noop_pass_returns_empty_list(self):
        """NoOpPass should return empty modification list."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0)
        pass_instance = NoOpPass()

        result = pass_instance.transform(cfg)

        assert result == []

    def test_count_blocks_pass_finds_terminals(self):
        """CountBlocksPass should return ConvertToGoto for terminal blocks."""
        # Create CFG: 0 -> 1, 2 (terminals)
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk0, 1: blk1, 2: blk2}, entry_serial=0, func_ea=0x1000)

        pass_instance = CountBlocksPass()
        result = pass_instance.transform(cfg)

        # Should find 2 terminal blocks (1 and 2)
        assert len(result) == 2
        assert all(isinstance(mod, ConvertToGoto) for mod in result)
        serials = {mod.block_serial for mod in result}
        assert serials == {1, 2}

    def test_is_applicable_default_true(self):
        """Default is_applicable should return True."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0)
        pass_instance = NoOpPass()

        assert pass_instance.is_applicable(cfg) is True

    def test_is_applicable_custom_logic(self):
        """Custom is_applicable should be honored."""
        # Small CFG (2 blocks)
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        small_cfg = FlowGraph(blocks={0: blk0, 1: blk1}, entry_serial=0, func_ea=0x1000)

        # Large CFG (3 blocks)
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blk0_large = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        large_cfg = FlowGraph(
            blocks={0: blk0_large, 1: blk1, 2: blk2},
            entry_serial=0, func_ea=0x1000
        )

        pass_instance = ConditionalPass()

        # Should not apply to small CFG (2 blocks)
        assert pass_instance.is_applicable(small_cfg) is False

        # Should apply to large CFG (3 blocks)
        assert pass_instance.is_applicable(large_cfg) is True

    def test_missing_name_raises_typeerror(self):
        """Defining a pass without 'name' should raise TypeError."""
        with pytest.raises(TypeError, match="must define 'name' class attribute"):
            class MissingNamePass(FlowGraphTransform):
                def transform(self, cfg: FlowGraph) -> list[GraphModification]:
                    return []

    def test_repr(self):
        """Pass __repr__ should show class name and name attribute."""
        pass_instance = NoOpPass()
        repr_str = repr(pass_instance)

        assert "NoOpPass" in repr_str
        assert "name='noop'" in repr_str

    def test_tags_default_empty(self):
        """Default tags should be empty frozenset."""
        pass_instance = NoOpPass()
        assert pass_instance.tags == frozenset()

    def test_tags_custom(self):
        """Custom tags should be preserved."""
        pass_instance = CountBlocksPass()
        assert pass_instance.tags == frozenset({"test", "example"})


class TestIntegration:
    """Integration tests with backend + pass."""

    def test_backend_lift_pass_lower_cycle(self):
        """Full cycle: lift CFG, run pass, lower modifications."""
        # Setup backend with 3 blocks
        blk0 = BlockSnapshot(
            serial=0, block_type=4, succs=(1, 2), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blk2 = BlockSnapshot(
            serial=2, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1020, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1, 2: blk2}
        backend = InMemoryBackend(blocks)

        # Lift to FlowGraph
        cfg = backend.lift()
        assert cfg.num_blocks == 3

        # Run CountBlocksPass
        pass_instance = CountBlocksPass()
        modifications = pass_instance.transform(cfg)
        assert len(modifications) == 2  # 2 terminal blocks

        # Lower modifications
        count = backend.lower(modifications)
        assert count == 2

        # Verify
        assert backend.verify() is True
        assert len(backend.applied_modifications) == 2
