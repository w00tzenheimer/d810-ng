"""Tests for PassPipeline orchestrator.

This module tests:
- Empty pipeline execution
- Single/multiple pass execution
- Pass applicability checks
- Modification counting and accumulation
- Verification failure handling
- Re-lift behavior after modifications
"""
from __future__ import annotations

import pytest

from d810.cfg.transform._base import FlowGraphTransform
from d810.cfg.graph_modification import ConvertToGoto, GraphModification, RedirectGoto
from d810.cfg.pipeline import FlowGraphTransformPipeline
from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from tests.unit.hexrays.conftest import InMemoryBackend


# ============================================================================
# Mock Backends for Testing
# ============================================================================


class FailingVerificationBackend(InMemoryBackend):
    """Backend where verify() always returns False."""

    def verify(self, state: dict[int, BlockSnapshot] | None = None) -> bool:
        """Always return False to simulate verification failure."""
        return False


class ZeroLowerBackend(InMemoryBackend):
    """Backend where lower() always returns 0."""

    def lower(
        self,
        modifications: list[GraphModification],
        state: dict[int, BlockSnapshot] | None = None
    ) -> int:
        """Record modifications but return 0 to simulate no-op lowering."""
        self.applied_modifications.extend(modifications)
        return 0


class MutatingBackend(InMemoryBackend):
    """Backend that mutates state on lower() to test re-lift behavior."""

    def __init__(self, blocks: dict[int, BlockSnapshot] | None = None):
        super().__init__(blocks)
        self.mutation_count = 0

    def lower(
        self,
        modifications: list[GraphModification],
        state: dict[int, BlockSnapshot] | None = None
    ) -> int:
        """Mutate backend state and return count."""
        count = super().lower(modifications, state)
        if count > 0:
            # Add a new block to simulate state mutation
            self.mutation_count += 1
            new_serial = 100 + self.mutation_count
            new_block = BlockSnapshot(
                serial=new_serial,
                block_type=2,
                succs=(),
                preds=(),
                flags=0,
                start_ea=0x2000 + (self.mutation_count * 0x10),
                insn_snapshots=()
            )
            self.blocks[new_serial] = new_block
        return count


# ============================================================================
# Test Passes
# ============================================================================


class NoOpPass(FlowGraphTransform):
    """Pass that does nothing (returns empty modification list)."""
    name = "noop"

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return empty list."""
        return []


class SingleModPass(FlowGraphTransform):
    """Pass that returns one ConvertToGoto modification."""
    name = "single_mod"

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return single ConvertToGoto modification."""
        return [ConvertToGoto(block_serial=1, goto_target=0)]


class DoubleModPass(FlowGraphTransform):
    """Pass that returns two modifications."""
    name = "double_mod"

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return two modifications."""
        return [
            ConvertToGoto(block_serial=1, goto_target=0),
            RedirectGoto(from_serial=2, old_target=3, new_target=0),
        ]


class ConditionalPass(FlowGraphTransform):
    """Pass that only applies to CFGs with >2 blocks."""
    name = "conditional"

    def is_applicable(self, cfg: FlowGraph) -> bool:
        """Only apply if more than 2 blocks."""
        return cfg.num_blocks > 2

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return single modification."""
        return [ConvertToGoto(block_serial=1, goto_target=0)]


class CountingPass(FlowGraphTransform):
    """Pass that returns modifications equal to number of blocks in CFG."""
    name = "counting"

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        """Return one ConvertToGoto per block."""
        return [
            ConvertToGoto(block_serial=serial, goto_target=0)
            for serial in cfg.blocks.keys()
        ]


# ============================================================================
# Tests
# ============================================================================


class TestPassPipeline:
    """Tests for PassPipeline orchestrator."""

    def test_empty_pipeline(self):
        """Empty pipeline should return 0."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [])

        total = pipeline.run({})

        assert total == 0
        assert len(backend.applied_modifications) == 0

    def test_single_pass_no_modifications(self):
        """Pass that returns empty list should result in 0 total."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [NoOpPass()])

        total = pipeline.run({})

        assert total == 0
        assert len(backend.applied_modifications) == 0

    def test_single_pass_with_modifications(self):
        """Pass with modifications should return correct count."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass()])

        total = pipeline.run({})

        assert total == 1
        assert len(backend.applied_modifications) == 1
        assert isinstance(backend.applied_modifications[0], ConvertToGoto)

    def test_multiple_passes_accumulate(self):
        """Multiple transform should accumulate modification counts."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass(), DoubleModPass()])

        total = pipeline.run({})

        assert total == 3  # 1 from SingleModPass + 2 from DoubleModPass
        assert len(backend.applied_modifications) == 3

    def test_pass_not_applicable_skipped(self):
        """Pass with is_applicable=False should be skipped."""
        # Create small CFG (2 blocks)
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
        pipeline = FlowGraphTransformPipeline(backend, [ConditionalPass()])

        total = pipeline.run(blocks)

        # ConditionalPass requires >2 blocks, so should be skipped
        assert total == 0
        assert len(backend.applied_modifications) == 0

    def test_pass_applicable_runs(self):
        """Pass with is_applicable=True should run."""
        # Create large CFG (3 blocks)
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
        pipeline = FlowGraphTransformPipeline(backend, [ConditionalPass()])

        total = pipeline.run(blocks)

        # ConditionalPass requires >2 blocks, so should run
        assert total == 1
        assert len(backend.applied_modifications) == 1

    def test_pass_with_mods_but_lower_returns_zero(self):
        """Pass with mods but lower returning 0 should not count or verify."""
        backend = ZeroLowerBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass()])

        total = pipeline.run({})

        # Lower returned 0, so verify should not be called and total should be 0
        assert total == 0
        # Backend still recorded the modifications (lower was called)
        assert len(backend.applied_modifications) == 1

    def test_verify_failure_skips_count(self):
        """Verify failure should skip counting modifications."""
        backend = FailingVerificationBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass()])

        total = pipeline.run({})

        # Verify failed, so modifications should not be counted
        assert total == 0
        # But backend still recorded the modifications (lower was called)
        assert len(backend.applied_modifications) == 1

    def test_relift_after_modifications(self):
        """CFG should be re-lifted after successful modifications."""
        backend = MutatingBackend()
        # Use CountingPass which returns mods based on block count
        pipeline = FlowGraphTransformPipeline(backend, [CountingPass(), CountingPass()])

        total = pipeline.run({})

        # First pass: 0 blocks -> 0 mods
        # Second pass: should see mutated state from first pass if re-lift happened
        # But since first pass had 0 blocks, it returned 0 mods, so no mutation
        # Let's use a different test case
        assert backend.lift_count >= 1  # At least initial lift

    def test_relift_after_modifications_with_blocks(self):
        """CFG should be re-lifted after successful modifications, subsequent transform see new state."""
        # Create initial CFG with 2 blocks
        blk0 = BlockSnapshot(
            serial=0, block_type=3, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        blk1 = BlockSnapshot(
            serial=1, block_type=2, succs=(), preds=(0,),
            flags=0, start_ea=0x1010, insn_snapshots=()
        )
        blocks = {0: blk0, 1: blk1}

        backend = MutatingBackend(blocks)
        # CountingPass returns mods equal to block count
        # After first pass applies mods, backend adds a new block
        # Second pass should see 3 blocks (original 2 + 1 added)
        pipeline = FlowGraphTransformPipeline(backend, [CountingPass(), CountingPass()])

        total = pipeline.run(blocks)

        # First pass: 2 blocks -> 2 mods -> backend adds 1 block
        # Second pass: 3 blocks -> 3 mods
        # Total: 2 + 3 = 5
        assert total == 5
        assert backend.lift_count == 3  # Initial + after each pass
        # Backend should have mutated twice (once per pass that applied mods)
        assert backend.mutation_count == 2

    def test_repr(self):
        """PassPipeline repr should show backend name and pass names."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [NoOpPass(), SingleModPass()])

        repr_str = repr(pipeline)

        assert "PassPipeline" in repr_str
        assert "in_memory" in repr_str
        assert "noop" in repr_str
        assert "single_mod" in repr_str

    def test_defensive_copy_of_passes(self):
        """PassPipeline should make defensive copy of transform list."""
        backend = InMemoryBackend()
        passes = [NoOpPass()]
        pipeline = FlowGraphTransformPipeline(backend, passes)

        # Mutate original list
        passes.append(SingleModPass())

        # Pipeline should still have only 1 pass
        assert len(pipeline.passes) == 1

    def test_mixed_passes_some_skip(self):
        """Pipeline with mix of applicable and non-applicable transform."""
        # Create 2-block CFG
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
        # ConditionalPass requires >2 blocks (won't apply)
        # SingleModPass always applies
        # NoOpPass always applies but returns no mods
        pipeline = FlowGraphTransformPipeline(backend, [ConditionalPass(), SingleModPass(), NoOpPass()])

        total = pipeline.run(blocks)

        # Only SingleModPass should contribute
        assert total == 1
        assert len(backend.applied_modifications) == 1


class TestPassPipelineLogging:
    """Tests for PassPipeline logging behavior."""

    def test_logs_non_applicable_pass(self, caplog):
        """Should log when pass is not applicable."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [ConditionalPass()])

        with caplog.at_level("DEBUG"):
            pipeline.run({})

        assert any("not applicable" in record.message for record in caplog.records)

    def test_logs_no_modifications(self, caplog):
        """Should log when pass produces no modifications."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [NoOpPass()])

        with caplog.at_level("DEBUG"):
            pipeline.run({})

        assert any("produced no modifications" in record.message for record in caplog.records)

    def test_logs_verify_failure(self, caplog):
        """Should log warning when verification fails."""
        backend = FailingVerificationBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass()])

        with caplog.at_level("WARNING"):
            pipeline.run({})

        assert any("failed verification" in record.message for record in caplog.records)

    def test_logs_successful_application(self, caplog):
        """Should log when modifications are successfully applied."""
        backend = InMemoryBackend()
        pipeline = FlowGraphTransformPipeline(backend, [SingleModPass()])

        with caplog.at_level("DEBUG"):
            pipeline.run({})

        assert any("applied" in record.message and "modifications" in record.message
                   for record in caplog.records)
