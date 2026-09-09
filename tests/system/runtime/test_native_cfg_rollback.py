"""Native rollback must restore bodies and identity, not just CFG serials."""
import platform

import ida_hexrays as hx
import pytest

from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier
from tests.system.runtime.conftest import gen_microcode_at_maturity, get_func_ea
from tests.system.runtime.mutation_gateway import make_mutation_gateway


def signature(mba):
    result = []
    for serial in range(mba.qty):
        block = mba.get_mblock(serial)
        body = []
        instruction = block.head
        while instruction is not None:
            body.append(instruction.serialize())
            instruction = instruction.next
        result.append((block.start, block.end, block.type,
                       tuple(block.succset), tuple(block.predset), tuple(body)))
    return tuple(result)


@pytest.mark.ida_required
class TestNativeCfgRollback:
    binary_name = "libobfuscated.dylib" if platform.system() == "Darwin" else "libobfuscated.dll"

    def _fixture(self):
        mba = gen_microcode_at_maturity(get_func_ea("test_cst_simplification"), hx.MMAT_GLBOPT1)
        assert mba is not None
        mba.verify(True)
        modifier = DeferredGraphModifier(mba, mutation_gateway=make_mutation_gateway(mba))
        modifier._begin_mutation_batch()
        return mba, modifier

    @pytest.mark.parametrize("middle", [False, True])
    def test_restores_inserted_blocks_and_changed_instructions(self, libobfuscated_setup, middle):
        mba, modifier = self._fixture()
        before = signature(mba)
        snapshot = modifier._capture_rollback_snapshot()
        block = next(mba.get_mblock(n) for n in range(1, mba.qty - 1)
                     if mba.get_mblock(n).head is not None)
        # Two insertions also exercise restoration of serials shifted twice.
        for position in (1 if middle else mba.qty - 1, mba.qty):
            inserted = mba.copy_block(block, position, hx.CPBLK_MINREF)
            modifier._mutation_gateway.record_observed_insert(
                insertion_serial=position, returned_serial=inserted.serial)
        block.make_nop(block.head)
        assert signature(mba) != before
        assert modifier._restore_from_snapshot(snapshot)
        mba.verify(True)
        assert signature(mba) == before

    def test_missing_original_block_refuses_without_mutation(self, libobfuscated_setup):
        mba, modifier = self._fixture()
        snapshot = modifier._capture_rollback_snapshot()
        block = mba.get_mblock(1)
        for n in range(mba.qty):
            mba.get_mblock(n).predset.clear()
            mba.get_mblock(n).succset.clear()
        mba.remove_block(block)
        before = signature(mba)
        assert not modifier._restore_from_snapshot(snapshot)
        assert signature(mba) == before

    def test_changed_maturity_refuses_without_mutation(self, libobfuscated_setup):
        mba, modifier = self._fixture()
        snapshot = modifier._capture_rollback_snapshot()
        mba.maturity = hx.MMAT_GLBOPT2
        before = signature(mba)
        assert not modifier._restore_from_snapshot(snapshot)
        assert signature(mba) == before

    def test_retired_identity_refuses_even_with_same_native_address(self, libobfuscated_setup):
        mba, modifier = self._fixture()
        snapshot = modifier._capture_rollback_snapshot()
        gateway = modifier._mutation_gateway
        # Model allocator address reuse deterministically: the native pointer is
        # unchanged, but its original identity has been retired and replaced.
        handle = gateway.identity_index.handle_for_serial(1)
        gateway.record_remove(handle)
        gateway.record_observed_insert(insertion_serial=1, returned_serial=1)
        before = signature(mba)
        assert not modifier._restore_from_snapshot(snapshot)
        assert signature(mba) == before
