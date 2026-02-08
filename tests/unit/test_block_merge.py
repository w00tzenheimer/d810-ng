"""Unit tests for the BlockMerger flow optimization rule.

Tests the merge logic with mocks, verifying that blocks are correctly
identified as mergeable and that the goto NOP is applied when conditions
are satisfied.

These tests do NOT require IDA Pro -- all IDA types are mocked.
"""
from __future__ import annotations

import pathlib
import sys
import types
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

# ---------------------------------------------------------------------------
# Ensure the project src/ is on sys.path (conftest.py normally handles this,
# but we guard against edge cases like direct invocation).
# ---------------------------------------------------------------------------
_PROJECT_SRC = str(pathlib.Path(__file__).resolve().parents[2] / "src")
if _PROJECT_SRC not in sys.path:
    sys.path.insert(0, _PROJECT_SRC)


# ---------------------------------------------------------------------------
# Build a strict mock for ida_hexrays that controls dir() output.
# This is necessary because hexrays_helpers.py iterates dir(ida_hexrays)
# looking for attributes prefixed with MMAT_, m_, mop_ and sorts the
# resulting (value, name) tuples.  MagicMock auto-creates attributes on
# access, so we need __dir__ to return only the names we explicitly set.
# ---------------------------------------------------------------------------

def _build_ida_hexrays_mock() -> MagicMock:
    """Return a MagicMock for ida_hexrays with controlled __dir__."""
    attrs: dict[str, object] = {
        # Opcode constants
        "m_goto": 0x40,
        "m_nop": 0x00,
        "m_jz": 0x31,
        "m_jnz": 0x30,
        "m_mov": 0x01,
        "m_jae": 0x35,
        "m_jb": 0x36,
        "m_ja": 0x37,
        "m_jbe": 0x38,
        "m_jg": 0x39,
        "m_jge": 0x3A,
        "m_jl": 0x3B,
        "m_jle": 0x3C,
        # Operand type constants
        "mop_b": 6,
        "mop_n": 2,
        "mop_r": 1,
        "mop_d": 4,
        # Maturity levels
        "MMAT_ZERO": 0,
        "MMAT_GENERATED": 10,
        "MMAT_PREOPTIMIZED": 15,
        "MMAT_LOCOPT": 20,
        "MMAT_CALLS": 25,
        "MMAT_GLBOPT1": 30,
        "MMAT_GLBOPT2": 35,
        "MMAT_GLBOPT3": 40,
        "MMAT_LVARS": 45,
        # Block type constants
        "BLT_NONE": 0,
        "BLT_STOP": 1,
        "BLT_0WAY": 2,
        "BLT_1WAY": 3,
        "BLT_2WAY": 4,
        "BLT_NWAY": 5,
        "BLT_XTRN": 6,
    }

    mock = MagicMock()
    for name, value in attrs.items():
        setattr(mock, name, value)

    # Types that need to be real classes for singledispatch / isinstance
    mock.mblock_t = MagicMock
    mock.mba_t = MagicMock
    mock.mop_t = MagicMock
    mock.minsn_t = MagicMock

    # Override __dir__ so that dir(ida_hexrays) only returns our attrs
    all_names = list(attrs.keys()) + ["mblock_t", "mba_t", "mop_t", "minsn_t"]
    mock.__dir__ = lambda self=None: all_names  # noqa: ARG005

    # Also define get_mreg_name for deferred_modifier
    mock.get_mreg_name = MagicMock(return_value="m_goto")

    return mock


@pytest.fixture(scope="module", autouse=True)
def _mock_ida_modules():
    """Inject mock IDA modules so we can import BlockMerger without IDA.

    On teardown we restore **all** modules (IDA stubs *and* any d810 modules)
    to the exact state they were in before the fixture ran.  This prevents
    contamination of other test modules that may have already imported d810
    packages with the real (``None``) IDA stubs.
    """
    mock_ida_hexrays = _build_ida_hexrays_mock()

    # Other IDA modules that d810 may import transitively
    mock_idc = MagicMock()
    mock_idaapi = MagicMock()
    mock_ida_kernwin = MagicMock()
    mock_ida_diskio = MagicMock()
    mock_ida_diskio.get_user_idadir.return_value = "/tmp/mock_idadir"

    modules_to_mock = {
        "ida_hexrays": mock_ida_hexrays,
        "idc": mock_idc,
        "idaapi": mock_idaapi,
        "ida_kernwin": mock_ida_kernwin,
        "ida_diskio": mock_ida_diskio,
    }

    # Snapshot the complete set of IDA + d810 modules before we touch anything.
    saved: dict[str, types.ModuleType | None] = {}
    for name in list(sys.modules):
        if name in modules_to_mock or name == "d810" or name.startswith("d810."):
            saved[name] = sys.modules.get(name)

    # Inject mocks
    for name, mock_mod in modules_to_mock.items():
        sys.modules[name] = mock_mod

    # Evict cached d810 modules so they re-import with the mocked IDA stubs.
    for mod_name in sorted(sys.modules, reverse=True):
        if mod_name == "d810" or mod_name.startswith("d810."):
            del sys.modules[mod_name]

    yield mock_ida_hexrays

    # --- Teardown: restore the pre-fixture module state exactly. ---

    # 1. Remove any d810 modules that were (re-)imported during the tests.
    for mod_name in sorted(sys.modules, reverse=True):
        if mod_name == "d810" or mod_name.startswith("d810."):
            del sys.modules[mod_name]

    # 2. Restore every saved entry (IDA stubs + d810 modules).
    for name, orig in saved.items():
        if orig is not None:
            sys.modules[name] = orig
        else:
            sys.modules.pop(name, None)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mop(mop_type: int, block_ref: int | None = None) -> MagicMock:
    """Create a mock mop_t operand."""
    mop = MagicMock()
    mop.t = mop_type
    if block_ref is not None:
        mop.b = block_ref
    return mop


def _make_tail(opcode: int, dest_mop: MagicMock | None = None) -> MagicMock:
    """Create a mock minsn_t tail instruction."""
    tail = MagicMock()
    tail.opcode = opcode
    if dest_mop is not None:
        tail.d = dest_mop
    else:
        tail.d = MagicMock()
    return tail


def _make_block(
    serial: int,
    *,
    nsucc: int = 0,
    npred: int = 0,
    succ_list: list[int] | None = None,
    pred_list: list[int] | None = None,
    tail: MagicMock | None = None,
    mba: MagicMock | None = None,
) -> MagicMock:
    """Create a mock mblock_t.

    Parameters
    ----------
    serial : int
        Block serial number.
    nsucc / npred : int
        Number of successors / predecessors (used when lists are not given).
    succ_list / pred_list : list[int] | None
        Explicit successor / predecessor serial lists.
    tail : MagicMock | None
        Tail instruction mock.
    mba : MagicMock | None
        Parent mbl_array_t mock.
    """
    blk = MagicMock()
    blk.serial = serial

    if succ_list is not None:
        blk.nsucc.return_value = len(succ_list)
        blk.succ.side_effect = lambda i: succ_list[i]
    else:
        blk.nsucc.return_value = nsucc

    if pred_list is not None:
        blk.npred.return_value = len(pred_list)
        blk.pred.side_effect = lambda i: pred_list[i]
    else:
        blk.npred.return_value = npred

    blk.tail = tail
    blk.mba = mba if mba is not None else MagicMock()
    return blk


def _make_mba(blocks: dict[int, MagicMock]) -> MagicMock:
    """Create a mock mba_t (mbl_array_t) that resolves ``get_mblock``."""
    mba = MagicMock()
    mba.qty = max(blocks.keys()) + 1 if blocks else 0
    mba.get_mblock.side_effect = lambda s: blocks.get(s)
    return mba


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestCanMerge:
    """Tests for BlockMerger._can_merge static method."""

    def _get_can_merge(self):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        return BlockMerger._can_merge

    # -- happy path --

    def test_mergeable_pair(self, _mock_ida_modules):
        """Two blocks satisfying all criteria should be mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert can_merge(blk) is True

    # -- rejection: no tail --

    def test_no_tail_rejects(self, _mock_ida_modules):
        """Block with no tail instruction is not mergeable."""
        can_merge = self._get_can_merge()
        blk = _make_block(serial=0, succ_list=[1], tail=None)
        assert can_merge(blk) is False

    # -- rejection: wrong opcode --

    def test_non_goto_tail_rejects(self, _mock_ida_modules):
        """Block whose tail is not m_goto is not mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        tail = _make_tail(mock_hex.m_jz)  # conditional jump
        blk = _make_block(serial=0, succ_list=[1], tail=tail)

        assert can_merge(blk) is False

    # -- rejection: multiple successors --

    def test_multiple_successors_rejects(self, _mock_ida_modules):
        """Block with more than one successor is not mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1, 2], tail=tail)

        assert can_merge(blk) is False

    # -- rejection: no successors --

    def test_zero_successors_rejects(self, _mock_ida_modules):
        """Block with no successors is not mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[], tail=tail)

        assert can_merge(blk) is False

    # -- rejection: destination mop type is not mop_b --

    def test_non_mop_b_destination_rejects(self, _mock_ida_modules):
        """Goto whose destination is not a block reference is not mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        dest_mop = _make_mop(mock_hex.mop_b + 99, block_ref=1)  # wrong type
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert can_merge(blk) is False

    # -- rejection: goto target != successor serial --

    def test_mismatched_goto_target_rejects(self, _mock_ida_modules):
        """Goto targeting a different block than the sole successor rejects."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        # goto points to block 5, but successor is block 1
        dest_mop = _make_mop(mock_hex.mop_b, block_ref=5)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert can_merge(blk) is False

    # -- rejection: successor has multiple predecessors --

    def test_multiple_predecessors_on_successor_rejects(self, _mock_ida_modules):
        """Successor with more than one predecessor is not mergeable."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=2)  # two predecessors
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert can_merge(blk) is False

    # -- rejection: self-referencing goto --

    def test_self_referencing_goto_rejects(self, _mock_ida_modules):
        """Block whose goto points to itself must NOT be mergeable.

        A self-referencing goto (serial == successor serial) could cause
        infinite loops in IDA's optimizer if we NOP the goto.
        """
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        # Block 3 has a goto targeting itself (block 3)
        self_blk = _make_block(serial=3, npred=1, succ_list=[3])
        mba = _make_mba({3: self_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=3)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        self_blk.tail = tail
        self_blk.mba = mba

        assert can_merge(self_blk) is False

    # -- rejection: successor not found in mba --

    def test_successor_not_in_mba_rejects(self, _mock_ida_modules):
        """If mba.get_mblock returns None for the successor, reject."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        mba = _make_mba({})  # empty -- successor 1 not found

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert can_merge(blk) is False


class TestOptimize:
    """Tests for BlockMerger.optimize."""

    def _make_merger(self):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        return BlockMerger()

    def test_optimize_returns_1_on_merge(self, _mock_ida_modules):
        """optimize() returns 1 and NOPs the goto when merge conditions hold."""
        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        result = merger.optimize(blk)

        assert result == 1
        blk.make_nop.assert_called_once_with(tail)

    def test_optimize_returns_0_when_not_mergeable(self, _mock_ida_modules):
        """optimize() returns 0 and does not NOP when conditions fail."""
        merger = self._make_merger()

        # Block with no tail -- not mergeable
        blk = _make_block(serial=0, succ_list=[1], tail=None)

        result = merger.optimize(blk)

        assert result == 0
        blk.make_nop.assert_not_called()

    def test_optimize_does_not_nop_when_successor_has_many_preds(
        self, _mock_ida_modules
    ):
        """No NOP when the successor has multiple predecessors."""
        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        succ_blk = _make_block(serial=1, npred=3)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        result = merger.optimize(blk)

        assert result == 0
        blk.make_nop.assert_not_called()


class TestClassAttributes:
    """Tests for BlockMerger class-level attributes."""

    def test_name(self, _mock_ida_modules):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger

        assert BlockMerger.NAME == "block_merger"

    def test_description(self, _mock_ida_modules):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger

        assert "split" in BlockMerger.DESCRIPTION.lower() or "merge" in BlockMerger.DESCRIPTION.lower()

    def test_uses_deferred_cfg_false(self, _mock_ida_modules):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger

        assert BlockMerger.USES_DEFERRED_CFG is False

    def test_safe_maturities(self, _mock_ida_modules):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        import ida_hexrays

        assert ida_hexrays.MMAT_CALLS in BlockMerger.SAFE_MATURITIES
        assert ida_hexrays.MMAT_GLBOPT1 in BlockMerger.SAFE_MATURITIES


class TestMethodCallVerification:
    """Verify that npred() and nsucc() are called on the correct blocks."""

    def _get_can_merge(self):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        return BlockMerger._can_merge

    def test_nsucc_called_on_source_block(self, _mock_ida_modules):
        """nsucc() must be called exactly once on the source block."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        can_merge(blk)

        blk.nsucc.assert_called_once()

    def test_npred_called_on_successor_block(self, _mock_ida_modules):
        """npred() must be called exactly once on the successor block."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        can_merge(blk)

        succ_blk.npred.assert_called_once()

    def test_npred_not_called_when_nsucc_wrong(self, _mock_ida_modules):
        """When nsucc() != 1, npred() should not be called on any successor."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        # Two successors -- should reject before reaching npred
        blk = _make_block(serial=0, succ_list=[1, 2], tail=tail, mba=mba)

        can_merge(blk)

        succ_blk.npred.assert_not_called()

    def test_succ_called_on_source_block(self, _mock_ida_modules):
        """blk.succ(0) must be called to retrieve the successor serial."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        can_merge(blk)

        blk.succ.assert_called_once_with(0)

    def test_get_mblock_called_on_mba(self, _mock_ida_modules):
        """mba.get_mblock(succ_serial) must be called to retrieve successor."""
        can_merge = self._get_can_merge()
        mock_hex = _mock_ida_modules

        succ_blk = _make_block(serial=1, npred=1)
        mba = _make_mba({1: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        can_merge(blk)

        mba.get_mblock.assert_called_once_with(1)


class TestLogging:
    """Verify that the merge action is logged with correct block serials.

    We patch the module-level ``logger`` object directly rather than
    relying on ``caplog`` because :func:`d810.core.getLogger` returns a
    custom :class:`D810Logger` that replaces the stdlib logger in the
    manager dict, which can desynchronise from the handler ``caplog``
    installs.
    """

    def _make_merger(self):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        return BlockMerger()

    def test_merge_logs_block_serials(self, _mock_ida_modules):
        """A successful merge must log both block serials at INFO level."""
        import d810.optimizers.microcode.flow.block_merge as bm_mod

        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        succ_blk = _make_block(serial=7, npred=1)
        mba = _make_mba({7: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=7)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=3, succ_list=[7], tail=tail, mba=mba)

        with patch.object(bm_mod.logger, "info") as mock_info:
            result = merger.optimize(blk)

        assert result == 1
        mock_info.assert_called_once()
        msg = mock_info.call_args[0][0] % mock_info.call_args[0][1:]
        assert "3" in msg and "7" in msg, (
            f"Expected log with serials 3 and 7, got: {msg!r}"
        )

    def test_no_log_when_not_mergeable(self, _mock_ida_modules):
        """When merge conditions are not met, no merge log should be emitted."""
        import d810.optimizers.microcode.flow.block_merge as bm_mod

        merger = self._make_merger()

        blk = _make_block(serial=0, succ_list=[1], tail=None)

        with patch.object(bm_mod.logger, "info") as mock_info:
            result = merger.optimize(blk)

        assert result == 0
        mock_info.assert_not_called()

    def test_log_contains_block_merger_prefix(self, _mock_ida_modules):
        """The log message should contain 'BlockMerger' for traceability."""
        import d810.optimizers.microcode.flow.block_merge as bm_mod

        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        succ_blk = _make_block(serial=2, npred=1)
        mba = _make_mba({2: succ_blk})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=2)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk = _make_block(serial=0, succ_list=[2], tail=tail, mba=mba)

        with patch.object(bm_mod.logger, "info") as mock_info:
            merger.optimize(blk)

        mock_info.assert_called_once()
        msg = mock_info.call_args[0][0] % mock_info.call_args[0][1:]
        assert "BlockMerger" in msg, (
            f"Expected 'BlockMerger' in log, got: {msg!r}"
        )


class TestChainScenarios:
    """Integration-style tests verifying chain-like sequences.

    These test that optimize() is correct when called per-block on a
    chain of small blocks (as the BlockOptimizerManager would).
    """

    def _make_merger(self):
        from d810.optimizers.microcode.flow.block_merge import BlockMerger
        return BlockMerger()

    def test_chain_of_three_blocks(self, _mock_ida_modules):
        """A chain A -> B -> C where each link is mergeable.

        Calling optimize on A and then B should both return 1.
        """
        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        # Build blocks: 0 -> 1 -> 2
        blk_2 = _make_block(serial=2, npred=1, nsucc=0)
        blk_1 = _make_block(serial=1, npred=1, succ_list=[2])
        blk_0 = _make_block(serial=0, npred=0, succ_list=[1])

        mba = _make_mba({0: blk_0, 1: blk_1, 2: blk_2})

        # Block 0 -> 1
        dest_mop_0 = _make_mop(mock_hex.mop_b, block_ref=1)
        tail_0 = _make_tail(mock_hex.m_goto, dest_mop=dest_mop_0)
        blk_0.tail = tail_0
        blk_0.mba = mba

        # Block 1 -> 2
        dest_mop_1 = _make_mop(mock_hex.mop_b, block_ref=2)
        tail_1 = _make_tail(mock_hex.m_goto, dest_mop=dest_mop_1)
        blk_1.tail = tail_1
        blk_1.mba = mba

        assert merger.optimize(blk_0) == 1
        blk_0.make_nop.assert_called_once_with(tail_0)

        assert merger.optimize(blk_1) == 1
        blk_1.make_nop.assert_called_once_with(tail_1)

    def test_branch_in_chain_stops_merge(self, _mock_ida_modules):
        """A -> B (2 preds) -> C: merge at A should fail."""
        mock_hex = _mock_ida_modules
        merger = self._make_merger()

        blk_1 = _make_block(serial=1, npred=2)  # two predecessors
        mba = _make_mba({1: blk_1})

        dest_mop = _make_mop(mock_hex.mop_b, block_ref=1)
        tail = _make_tail(mock_hex.m_goto, dest_mop=dest_mop)
        blk_0 = _make_block(serial=0, succ_list=[1], tail=tail, mba=mba)

        assert merger.optimize(blk_0) == 0
        blk_0.make_nop.assert_not_called()
