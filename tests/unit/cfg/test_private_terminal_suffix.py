"""Tests for PrivateTerminalSuffix graph modification and PatchPlan compilation."""
from __future__ import annotations

import pytest

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import PrivateTerminalSuffix
from d810.cfg.plan import (
    PatchPlan,
    PatchPrivateTerminalSuffix,
    VirtualBlockId,
    compile_patch_plan,
)
from d810.cfg.flow.edit_simulator import (
    SimulatedEdit,
    patch_plan_to_simulated_edits,
    simulate_edits,
)


def _block(
    serial: int,
    succs: tuple[int, ...],
    preds: tuple[int, ...],
    *,
    block_type: int | None = None,
) -> BlockSnapshot:
    if block_type is None:
        block_type = 1 if succs else 0
    return BlockSnapshot(
        serial=serial,
        block_type=block_type,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


def _shared_epilogue_cfg() -> FlowGraph:
    """CFG with anchors [9, 16, 17] -> shared suffix [63, 64].

    blk[63] is 1-way (nsucc=1) -> blk[64] which is 0-way (nsucc=0).
    """
    return FlowGraph(
        blocks={
            0: _block(0, (9,), ()),
            9: _block(9, (63,), (0,)),
            16: _block(16, (63,), (0,)),
            17: _block(17, (63,), (0,)),
            63: _block(63, (64,), (9, 16, 17)),
            64: _block(64, (), (63,), block_type=1),
            65: _block(65, (), (), block_type=1),  # stop block
        },
        entry_serial=0,
        func_ea=0x1000,
    )


class TestPrivateTerminalSuffixDataclass:
    """Test the PrivateTerminalSuffix frozen dataclass."""

    def test_construction(self) -> None:
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        assert mod.anchor_serial == 9
        assert mod.shared_entry_serial == 63
        assert mod.return_block_serial == 64
        assert mod.suffix_serials == (63, 64)
        assert mod.reason == "terminal_return_shared_epilogue"

    def test_custom_reason(self) -> None:
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
            reason="test_reason",
        )
        assert mod.reason == "test_reason"

    def test_frozen(self) -> None:
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        with pytest.raises(AttributeError):
            mod.anchor_serial = 10  # type: ignore[misc]


class TestCompilePrivateTerminalSuffix:
    """Test PatchPlan compilation of PrivateTerminalSuffix."""

    def test_compile_suffix_63_64_for_anchor_9(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        plan = compile_patch_plan([mod], cfg=cfg)

        assert isinstance(plan, PatchPlan)
        assert plan.contains_block_creation

        # Should have one PatchPrivateTerminalSuffix step
        suffix_steps = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ]
        assert len(suffix_steps) == 1

        step = suffix_steps[0]
        assert step.anchor_serial == 9
        assert step.shared_entry_serial == 63
        assert step.return_block_serial == 64
        assert step.suffix_serials == (63, 64)
        assert len(step.clone_block_ids) == 2
        assert len(step.clone_assigned_serials) == 2

        # Clone serials should be >= max existing serial (65)
        assert all(s >= 65 for s in step.clone_assigned_serials)

    def test_compile_multiple_anchors(self) -> None:
        cfg = _shared_epilogue_cfg()
        mods = [
            PrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=63,
                return_block_serial=64,
                suffix_serials=(63, 64),
            )
            for anchor in [9, 16, 17]
        ]
        plan = compile_patch_plan(mods, cfg=cfg)

        suffix_steps = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ]
        assert len(suffix_steps) == 3

        # Each anchor should get its own set of clone serials
        all_clone_serials = set()
        for step in suffix_steps:
            for serial in step.clone_assigned_serials:
                assert serial not in all_clone_serials, (
                    f"Duplicate clone serial {serial}"
                )
                all_clone_serials.add(serial)

    def test_compile_rejects_empty_suffix(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(),
        )
        with pytest.raises(ValueError, match="non-empty suffix_serials"):
            compile_patch_plan([mod], cfg=cfg)

    def test_new_blocks_created_for_suffix(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        plan = compile_patch_plan([mod], cfg=cfg)

        # Should create 2 new blocks (one clone per suffix block)
        suffix_blocks = [
            b for b in plan.new_blocks
            if b.kind == "private_terminal_suffix_clone"
        ]
        assert len(suffix_blocks) == 2

        # First clone should have template_block=63
        assert suffix_blocks[0].template_block == 63
        # Second clone should have template_block=64
        assert suffix_blocks[1].template_block == 64

    def test_to_graph_modification_roundtrip(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        plan = compile_patch_plan([mod], cfg=cfg)

        step = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ][0]
        roundtripped = step.to_graph_modification()
        assert isinstance(roundtripped, PrivateTerminalSuffix)
        assert roundtripped.anchor_serial == 9
        assert roundtripped.suffix_serials == (63, 64)


class TestSimulatorPrivateTerminalSuffix:
    """Test edit simulator support for PatchPrivateTerminalSuffix."""

    def test_simulator_rewires_anchor(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        plan = compile_patch_plan([mod], cfg=cfg)
        edits = patch_plan_to_simulated_edits(plan)

        adj = cfg.as_adjacency_dict()
        result = simulate_edits(adj, edits)

        step = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ][0]
        clone_entry = step.clone_assigned_serials[0]
        clone_return = step.clone_assigned_serials[1]

        # Anchor 9 should now point to clone_entry, not 63
        assert clone_entry in result.adj[9]
        assert 63 not in result.adj[9]

        # Clone entry should chain to clone return
        assert result.adj[clone_entry] == [clone_return]

        # Clone return should be 0-way (terminal)
        assert result.adj[clone_return] == []

        # Original suffix should remain intact
        assert 64 in result.adj[63]

    def test_simulator_creates_clones(self) -> None:
        cfg = _shared_epilogue_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=63,
            return_block_serial=64,
            suffix_serials=(63, 64),
        )
        plan = compile_patch_plan([mod], cfg=cfg)
        edits = patch_plan_to_simulated_edits(plan)

        adj = cfg.as_adjacency_dict()
        result = simulate_edits(adj, edits)

        step = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ][0]

        # Both clone serials should be in created_clones
        for clone_serial in step.clone_assigned_serials:
            assert clone_serial in result.created_clones

    def test_multiple_anchors_each_get_private_chain(self) -> None:
        cfg = _shared_epilogue_cfg()
        mods = [
            PrivateTerminalSuffix(
                anchor_serial=anchor,
                shared_entry_serial=63,
                return_block_serial=64,
                suffix_serials=(63, 64),
            )
            for anchor in [9, 16]
        ]
        plan = compile_patch_plan(mods, cfg=cfg)
        edits = patch_plan_to_simulated_edits(plan)

        adj = cfg.as_adjacency_dict()
        result = simulate_edits(adj, edits)

        suffix_steps = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ]
        assert len(suffix_steps) == 2

        # Each anchor should point to its own clone entry
        for step in suffix_steps:
            anchor = step.anchor_serial
            clone_entry = step.clone_assigned_serials[0]
            assert clone_entry in result.adj[anchor]

        # Anchor 17 still points to original shared entry
        assert 63 in result.adj[17]


class TestSingleBlockSuffix:
    """Test edge case: suffix is a single block (return block only)."""

    def _single_block_suffix_cfg(self) -> FlowGraph:
        return FlowGraph(
            blocks={
                0: _block(0, (9,), ()),
                9: _block(9, (64,), (0,)),
                16: _block(16, (64,), (0,)),
                64: _block(64, (), (9, 16), block_type=1),
                65: _block(65, (), (), block_type=1),
            },
            entry_serial=0,
            func_ea=0x1000,
        )

    def test_compile_single_block_suffix(self) -> None:
        cfg = self._single_block_suffix_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=64,
            return_block_serial=64,
            suffix_serials=(64,),
        )
        plan = compile_patch_plan([mod], cfg=cfg)

        suffix_steps = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ]
        assert len(suffix_steps) == 1
        assert len(suffix_steps[0].clone_assigned_serials) == 1

    def test_simulator_rewires_single_suffix(self) -> None:
        cfg = self._single_block_suffix_cfg()
        mod = PrivateTerminalSuffix(
            anchor_serial=9,
            shared_entry_serial=64,
            return_block_serial=64,
            suffix_serials=(64,),
        )
        plan = compile_patch_plan([mod], cfg=cfg)
        edits = patch_plan_to_simulated_edits(plan)

        adj = cfg.as_adjacency_dict()
        result = simulate_edits(adj, edits)

        step = [
            s for s in plan.steps if isinstance(s, PatchPrivateTerminalSuffix)
        ][0]
        clone_serial = step.clone_assigned_serials[0]

        # Anchor 9 points to clone, not 64
        assert clone_serial in result.adj[9]
        assert 64 not in result.adj[9]

        # Clone is 0-way
        assert result.adj[clone_serial] == []

        # Anchor 16 still points to original
        assert 64 in result.adj[16]
