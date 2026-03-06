"""Unit tests for flowgraph module.

Tests the frozen dataclass IR for CFG snapshots without requiring IDA runtime.
"""
from __future__ import annotations

import logging

import pytest

from d810.core.typing import TYPE_CHECKING
from d810.cfg.flowgraph import InsnSnapshot, BlockSnapshot, FlowGraph

if TYPE_CHECKING:
    from d810.hexrays.ir.mop_snapshot import MopSnapshot


class TestInsnSnapshot:
    """Test InsnSnapshot creation, properties, and immutability."""

    def test_creation(self) -> None:
        """Test basic creation with valid parameters."""
        insn = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        assert insn.opcode == 0x10
        assert insn.ea == 0x1000
        assert insn.operands == ()
        assert len(insn.operands) == 0

    def test_with_operands(self) -> None:
        """Test creation with operand snapshots."""
        # Use None as placeholder since we can't import MopSnapshot in pure unit tests
        ops = (None, None, None)  # type: ignore
        insn = InsnSnapshot(opcode=0x20, ea=0x2000, operands=ops)
        assert len(insn.operands) == 3

    def test_repr(self) -> None:
        """Test __repr__ output format."""
        insn = InsnSnapshot(opcode=0xAB, ea=0xDEADBEEF, operands=())
        r = repr(insn)
        assert "InsnSnapshot" in r
        assert "0xab" in r  # opcode in hex
        assert "0xdeadbeef" in r  # ea in hex
        assert "nops=0" in r

    def test_immutability(self) -> None:
        """Test that InsnSnapshot is frozen (immutable)."""
        insn = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        with pytest.raises(Exception):  # FrozenInstanceError in dataclasses
            insn.opcode = 0x99  # type: ignore

    def test_equality(self) -> None:
        """Test equality comparison."""
        insn1 = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        insn2 = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        insn3 = InsnSnapshot(opcode=0x20, ea=0x1000, operands=())
        assert insn1 == insn2
        assert insn1 != insn3

    def test_hashable(self) -> None:
        """Test that InsnSnapshot is hashable (can be used in sets/dicts)."""
        insn1 = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        insn2 = InsnSnapshot(opcode=0x20, ea=0x2000, operands=())
        s = {insn1, insn2}
        assert len(s) == 2
        assert insn1 in s

    def test_negative_ea_validation(self) -> None:
        """Test that negative ea raises ValueError."""
        with pytest.raises(ValueError, match="ea must be non-negative"):
            InsnSnapshot(opcode=0x10, ea=-1, operands=())

    def test_non_tuple_operands_validation(self) -> None:
        """Test that non-tuple operands raises TypeError."""
        with pytest.raises(TypeError, match="operands must be tuple"):
            InsnSnapshot(opcode=0x10, ea=0x1000, operands=[])  # type: ignore

    def test_negative_opcode_validation(self) -> None:
        """Test that negative opcode raises ValueError."""
        with pytest.raises(ValueError, match="opcode must be non-negative"):
            InsnSnapshot(opcode=-1, ea=0x1000, operands=())


class TestBlockSnapshot:
    """Test BlockSnapshot creation, properties, and validation."""

    def test_creation(self) -> None:
        """Test basic creation with valid parameters."""
        blk = BlockSnapshot(
            serial=0,
            block_type=3,
            succs=(1,),
            preds=(),
            flags=0,
            start_ea=0x1000,
            insn_snapshots=()
        )
        assert blk.serial == 0
        assert blk.block_type == 3
        assert blk.succs == (1,)
        assert blk.preds == ()
        assert blk.flags == 0
        assert blk.start_ea == 0x1000
        assert blk.insn_snapshots == ()
        assert blk.tail_opcode is None

    def test_tail_opcode_defaults_from_last_instruction(self) -> None:
        """BlockSnapshot derives tail_opcode when instruction snapshots exist."""
        blk = BlockSnapshot(
            serial=0,
            block_type=3,
            succs=(1,),
            preds=(),
            flags=0,
            start_ea=0x1000,
            insn_snapshots=(
                InsnSnapshot(opcode=0x10, ea=0x1000, operands=()),
                InsnSnapshot(opcode=0x77, ea=0x1004, operands=()),
            ),
        )

        assert blk.tail_opcode == 0x77

    def test_properties(self) -> None:
        """Test nsucc and npred computed properties."""
        blk = BlockSnapshot(
            serial=1,
            block_type=4,
            succs=(2, 3),
            preds=(0,),
            flags=0,
            start_ea=0x2000,
            insn_snapshots=()
        )
        assert blk.nsucc == 2
        assert blk.npred == 1

    def test_repr(self) -> None:
        """Test __repr__ output format."""
        blk = BlockSnapshot(
            serial=5,
            block_type=4,
            succs=(6, 7),
            preds=(3, 4),
            flags=0x10,
            start_ea=0x5000,
            insn_snapshots=()
        )
        r = repr(blk)
        assert "BlockSnapshot" in r
        assert "serial=5" in r
        assert "type=4" in r
        assert "(6, 7)" in r
        assert "(3, 4)" in r
        assert "ninsns=0" in r

    def test_immutability(self) -> None:
        """Test that BlockSnapshot is frozen (immutable)."""
        blk = BlockSnapshot(
            serial=0, block_type=1, succs=(1,), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        with pytest.raises(Exception):
            blk.serial = 99  # type: ignore

    @pytest.mark.parametrize("serial", [-1, -100])
    def test_negative_serial_validation(self, serial: int) -> None:
        """Test that negative serial raises ValueError."""
        with pytest.raises(ValueError, match="serial must be non-negative"):
            BlockSnapshot(
                serial=serial, block_type=1, succs=(), preds=(),
                flags=0, start_ea=0x1000, insn_snapshots=()
            )

    @pytest.mark.parametrize("block_type", [-1, 7, 100])
    def test_invalid_block_type_validation(self, block_type: int) -> None:
        """Test that invalid block_type raises ValueError."""
        with pytest.raises(ValueError, match="block_type must be 0-6"):
            BlockSnapshot(
                serial=0, block_type=block_type, succs=(), preds=(),
                flags=0, start_ea=0x1000, insn_snapshots=()
            )

    def test_negative_start_ea_validation(self) -> None:
        """Test that negative start_ea raises ValueError."""
        with pytest.raises(ValueError, match="start_ea must be non-negative"):
            BlockSnapshot(
                serial=0, block_type=1, succs=(), preds=(),
                flags=0, start_ea=-1, insn_snapshots=()
            )

    @pytest.mark.parametrize("block_type", [0, 1, 2, 3, 4, 5, 6])
    def test_valid_block_types(self, block_type: int) -> None:
        """Test all valid block types (0-6)."""
        blk = BlockSnapshot(
            serial=0, block_type=block_type, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        assert blk.block_type == block_type

    def test_non_tuple_succs_validation(self) -> None:
        """Test that non-tuple succs raises TypeError."""
        with pytest.raises(TypeError, match="succs must be tuple"):
            BlockSnapshot(
                serial=0, block_type=1, succs=[1],  # type: ignore
                preds=(), flags=0, start_ea=0x1000, insn_snapshots=()
            )

    def test_non_tuple_preds_validation(self) -> None:
        """Test that non-tuple preds raises TypeError."""
        with pytest.raises(TypeError, match="preds must be tuple"):
            BlockSnapshot(
                serial=0, block_type=1, succs=(), preds=[0],  # type: ignore
                flags=0, start_ea=0x1000, insn_snapshots=()
            )

    def test_non_tuple_insn_snapshots_validation(self) -> None:
        """Test that non-tuple insn_snapshots raises TypeError."""
        with pytest.raises(TypeError, match="insn_snapshots must be tuple"):
            BlockSnapshot(
                serial=0, block_type=1, succs=(), preds=(),
                flags=0, start_ea=0x1000, insn_snapshots=[]  # type: ignore
            )


class TestPortableCFG:
    """Test FlowGraph creation, properties, and topology queries."""

    def test_empty_cfg(self) -> None:
        """Test creation of empty CFG (edge case)."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        assert cfg.num_blocks == 0
        assert cfg.entry_serial == 0
        assert cfg.func_ea == 0x1000
        assert cfg.metadata == {}

    def test_single_block_cfg(self) -> None:
        """Test single-block CFG."""
        blk = BlockSnapshot(
            serial=0, block_type=0, succs=(), preds=(),
            flags=0, start_ea=0x1000, insn_snapshots=()
        )
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        assert cfg.num_blocks == 1
        assert cfg.get_block(0) == blk
        assert cfg.successors(0) == ()
        assert cfg.predecessors(0) == ()

    def test_linear_cfg(self) -> None:
        """Test linear 3-block CFG (0 -> 1 -> 2)."""
        blocks = {
            0: BlockSnapshot(0, 3, succs=(1,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 3, succs=(2,), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=()),
            2: BlockSnapshot(2, 2, succs=(), preds=(1,), flags=0, start_ea=0x1200, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
        assert cfg.num_blocks == 3
        assert cfg.successors(0) == (1,)
        assert cfg.successors(1) == (2,)
        assert cfg.successors(2) == ()
        assert cfg.predecessors(0) == ()
        assert cfg.predecessors(1) == (0,)
        assert cfg.predecessors(2) == (1,)

    def test_diamond_cfg(self) -> None:
        """Test diamond CFG (0 -> 1,2 -> 3)."""
        blocks = {
            0: BlockSnapshot(0, 4, succs=(1, 2), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 3, succs=(3,), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=()),
            2: BlockSnapshot(2, 3, succs=(3,), preds=(0,), flags=0, start_ea=0x1200, insn_snapshots=()),
            3: BlockSnapshot(3, 2, succs=(), preds=(1, 2), flags=0, start_ea=0x1300, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
        assert cfg.num_blocks == 4
        assert cfg.successors(0) == (1, 2)
        assert cfg.successors(1) == (3,)
        assert cfg.successors(2) == (3,)
        assert cfg.predecessors(3) == (1, 2)

    def test_complex_cfg_with_backedge(self) -> None:
        """Test complex 5-block CFG with loop (backedge 4 -> 1)."""
        blocks = {
            0: BlockSnapshot(0, 3, succs=(1,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 4, succs=(2, 3), preds=(0, 4), flags=0, start_ea=0x1100, insn_snapshots=()),
            2: BlockSnapshot(2, 3, succs=(4,), preds=(1,), flags=0, start_ea=0x1200, insn_snapshots=()),
            3: BlockSnapshot(3, 2, succs=(), preds=(1,), flags=0, start_ea=0x1300, insn_snapshots=()),
            4: BlockSnapshot(4, 3, succs=(1,), preds=(2,), flags=0, start_ea=0x1400, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
        assert cfg.num_blocks == 5
        assert cfg.successors(0) == (1,)
        assert cfg.successors(1) == (2, 3)
        assert cfg.successors(4) == (1,)  # backedge
        assert cfg.predecessors(1) == (0, 4)
        assert set(cfg.successors(1)) == {2, 3}

    def test_get_block_missing(self) -> None:
        """Test get_block returns None for missing serial."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        assert cfg.get_block(99) is None

    def test_successors_missing_block(self) -> None:
        """Test successors returns empty tuple for missing block."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        assert cfg.successors(99) == ()

    def test_predecessors_missing_block(self) -> None:
        """Test predecessors returns empty tuple for missing block."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        assert cfg.predecessors(99) == ()

    def test_as_adjacency_dict(self) -> None:
        """Test as_adjacency_dict conversion."""
        blocks = {
            0: BlockSnapshot(0, 4, succs=(1, 2), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 2, succs=(), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=()),
            2: BlockSnapshot(2, 2, succs=(), preds=(0,), flags=0, start_ea=0x1200, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
        adj = cfg.as_adjacency_dict()
        assert adj == {0: [1, 2], 1: [], 2: []}
        # Verify it's mutable (returns lists, not tuples)
        adj[0].append(99)
        assert 99 not in cfg.successors(0)  # Original CFG unchanged

    def test_repr(self) -> None:
        """Test __repr__ output format."""
        blocks = {
            0: BlockSnapshot(0, 3, succs=(1,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 2, succs=(), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0xDEADBEEF)
        r = repr(cfg)
        assert "PortableCFG" in r
        assert "nblocks=2" in r
        assert "entry=0" in r
        assert "0xdeadbeef" in r

    def test_immutability(self) -> None:
        """Test that FlowGraph is frozen (immutable)."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        with pytest.raises(Exception):
            cfg.entry_serial = 99  # type: ignore

    def test_negative_func_ea_validation(self) -> None:
        """Test that negative func_ea raises ValueError."""
        with pytest.raises(ValueError, match="func_ea must be non-negative"):
            FlowGraph(blocks={}, entry_serial=0, func_ea=-1)

    def test_invalid_entry_serial_validation(self) -> None:
        """Test that non-existent entry_serial raises ValueError."""
        blk = BlockSnapshot(0, 0, succs=(), preds=(), flags=0, start_ea=0x1000, insn_snapshots=())
        with pytest.raises(ValueError, match="entry_serial 99 not in blocks"):
            FlowGraph(blocks={0: blk}, entry_serial=99, func_ea=0x1000)

    def test_dangling_successor_warning(self, caplog) -> None:
        """Test that dangling successor references log warnings."""
        blk = BlockSnapshot(0, 3, succs=(99,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=())
        with caplog.at_level(logging.WARNING):
            cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        assert "non-existent successor 99" in caplog.text
        assert cfg.num_blocks == 1  # Still created successfully

    def test_dangling_predecessor_warning(self, caplog) -> None:
        """Test that dangling predecessor references log warnings."""
        blk = BlockSnapshot(0, 0, succs=(), preds=(99,), flags=0, start_ea=0x1000, insn_snapshots=())
        with caplog.at_level(logging.WARNING):
            cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        assert "non-existent predecessor 99" in caplog.text
        assert cfg.num_blocks == 1

    def test_metadata(self) -> None:
        """Test metadata field usage."""
        metadata = {"pass_name": "test_pass", "iteration": 5, "tags": ["optimized"]}
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000, metadata=metadata)
        assert cfg.metadata == metadata
        assert cfg.metadata["pass_name"] == "test_pass"

    def test_equality(self) -> None:
        """Test equality comparison."""
        blk = BlockSnapshot(0, 0, succs=(), preds=(), flags=0, start_ea=0x1000, insn_snapshots=())
        cfg1 = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        cfg2 = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        cfg3 = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x2000)
        assert cfg1 == cfg2
        assert cfg1 != cfg3

    def test_blocks_immutable(self) -> None:
        """FlowGraph.blocks should not allow mutation after construction."""
        blk = BlockSnapshot(serial=0, block_type=2, succs=(), preds=(), flags=0, start_ea=0x1000, insn_snapshots=())
        cfg = FlowGraph(blocks={0: blk}, entry_serial=0, func_ea=0x1000)
        with pytest.raises(TypeError):
            cfg.blocks[99] = blk  # type: ignore

    def test_metadata_immutable(self) -> None:
        """FlowGraph.metadata should not allow mutation after construction."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000, metadata={"key": "value"})
        with pytest.raises(TypeError):
            cfg.metadata["new_key"] = "new_value"  # type: ignore

    def test_not_hashable(self) -> None:
        """FlowGraph with MappingProxyType is not hashable (values may be mutable)."""
        cfg = FlowGraph(blocks={}, entry_serial=0, func_ea=0x1000)
        with pytest.raises(TypeError):
            hash(cfg)


class TestPortableCFGIntegration:
    """Integration tests for realistic CFG scenarios."""

    def test_complete_diamond_with_instructions(self) -> None:
        """Test diamond CFG with instruction snapshots."""
        # Create instruction snapshots (with no operands for simplicity)
        insn0 = InsnSnapshot(opcode=0x10, ea=0x1000, operands=())
        insn1 = InsnSnapshot(opcode=0x20, ea=0x1100, operands=())
        insn2 = InsnSnapshot(opcode=0x30, ea=0x1200, operands=())
        insn3 = InsnSnapshot(opcode=0x40, ea=0x1300, operands=())

        blocks = {
            0: BlockSnapshot(0, 4, succs=(1, 2), preds=(), flags=0, start_ea=0x1000, insn_snapshots=(insn0,)),
            1: BlockSnapshot(1, 3, succs=(3,), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=(insn1,)),
            2: BlockSnapshot(2, 3, succs=(3,), preds=(0,), flags=0, start_ea=0x1200, insn_snapshots=(insn2,)),
            3: BlockSnapshot(3, 2, succs=(), preds=(1, 2), flags=0, start_ea=0x1300, insn_snapshots=(insn3,)),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)

        # Verify structure
        assert cfg.num_blocks == 4
        assert len(cfg.get_block(0).insn_snapshots) == 1
        assert cfg.get_block(1).insn_snapshots[0].ea == 0x1100

        # Verify topology
        entry = cfg.get_block(0)
        assert entry is not None
        assert entry.nsucc == 2
        assert set(entry.succs) == {1, 2}

        exit_block = cfg.get_block(3)
        assert exit_block is not None
        assert exit_block.nsucc == 0
        assert exit_block.npred == 2

    def test_loop_structure(self) -> None:
        """Test loop with proper backedge tracking."""
        # Simple loop: 0 -> 1 -> 2 -> 1, 2 -> 3
        blocks = {
            0: BlockSnapshot(0, 3, succs=(1,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 3, succs=(2,), preds=(0, 2), flags=0, start_ea=0x1100, insn_snapshots=()),
            2: BlockSnapshot(2, 4, succs=(1, 3), preds=(1,), flags=0, start_ea=0x1200, insn_snapshots=()),
            3: BlockSnapshot(3, 2, succs=(), preds=(2,), flags=0, start_ea=0x1300, insn_snapshots=()),
        }
        cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)

        # Verify loop header has backedge
        loop_header = cfg.get_block(1)
        assert loop_header is not None
        assert loop_header.npred == 2
        assert 2 in loop_header.preds  # backedge from block 2

        # Verify latch block
        latch = cfg.get_block(2)
        assert latch is not None
        assert 1 in latch.succs  # backedge to header

    def test_multi_entry_warning(self, caplog) -> None:
        """Test CFG with unreachable blocks (partial snapshot scenario)."""
        blocks = {
            0: BlockSnapshot(0, 3, succs=(1,), preds=(), flags=0, start_ea=0x1000, insn_snapshots=()),
            1: BlockSnapshot(1, 2, succs=(), preds=(0,), flags=0, start_ea=0x1100, insn_snapshots=()),
            99: BlockSnapshot(99, 2, succs=(), preds=(88,), flags=0, start_ea=0x9900, insn_snapshots=()),
        }
        with caplog.at_level(logging.WARNING):
            cfg = FlowGraph(blocks=blocks, entry_serial=0, func_ea=0x1000)
        # Block 99 references non-existent predecessor 88
        assert "non-existent predecessor 88" in caplog.text
        assert cfg.num_blocks == 3
