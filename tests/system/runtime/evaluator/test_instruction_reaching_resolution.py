"""d81-w2u9: resolve values at an instruction, not a register location.

Real SDK instructions and the real evaluator/query; the small graph shell
supplies deterministic UD chains without depending on optimizer scheduling.
"""

import ida_hexrays as hr
import pytest
import idapro
import shutil
from pathlib import Path

from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from tests.system.runtime.evaluator.test_exact_fragment_chains import (
    _Block,
    _BlockChains,
    _GraphChains,
    _Mba,
    _Instruction,
    _stack,
)
from d810.evaluator.hexrays_microcode.chains import find_reaching_defs_for_stkvar


@pytest.fixture(scope="module", autouse=True)
def _sdk_database(tmp_path_factory):
    source = Path(__file__).resolve().parents[4] / "samples/bins/libobfuscated.dll"
    target = tmp_path_factory.mktemp("instruction-reaching") / source.name
    shutil.copyfile(source, target)
    assert idapro.open_database(str(target), False) == 0
    try:
        assert hr.init_hexrays_plugin()
        yield
    finally:
        idapro.close_database(False)


def _ins(ea, opcode, dst, *, src=None, number=0):
    ins = hr.minsn_t(ea)
    ins.opcode = opcode
    ins.d.make_reg(dst, 4)
    if src is None:
        ins.l.make_number(number, 4)
    else:
        ins.l.make_reg(src, 4)
        if opcode != hr.m_mov:
            ins.r.make_number(number, 4)
    return ins


def _graph(instructions, incoming):
    blocks = tuple(_Block(i, tuple(items)) for i, items in enumerate(instructions))
    chains = _GraphChains(
        {
            i: _BlockChains(register_targets=tuple(preds))
            for i, preds in enumerate(incoming)
        }
    )
    mba = _Mba(blocks, ud=chains, du=chains)
    mba.entry_ea = 0x1000
    for block in blocks:
        block.mba = mba
        block.start = block.head.ea
        block.nextb = block
        block.predset = tuple(incoming[block.serial])
        block.succset = tuple(
            i for i, preds in enumerate(incoming) if block.serial in preds
        )
    return mba


def _resolve(interpreter, mba, block_serial, ins):
    env = MicroCodeEnvironment()
    env.set_cur_flow(mba.get_mblock(block_serial), ins)
    return interpreter._resolve_mop_via_def_use(ins.l, env)


def test_read_modify_write_reads_the_previous_register_definition():
    seed = _ins(0x1000, hr.m_mov, 8, number=20)
    update = _ins(0x1004, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x1008, hr.m_mov, 12, src=8)
    mba = _graph(((seed, update, use),), ((0,),))
    assert _resolve(MicroCodeInterpreter(), mba, 0, use) == 17


def test_cached_value_does_not_cross_instruction_positions():
    seed = _ins(0x1000, hr.m_mov, 8, number=20)
    first = _ins(0x1004, hr.m_mov, 12, src=8)
    update = _ins(0x1008, hr.m_mov, 8, number=7)
    second = _ins(0x100C, hr.m_mov, 12, src=8)
    mba = _graph(((seed, first, update, second),), ((0,),))
    interpreter = MicroCodeInterpreter()
    assert _resolve(interpreter, mba, 0, first) == 20
    assert _resolve(interpreter, mba, 0, second) == 7


def test_unseeded_loop_carried_read_still_abstains():
    update = _ins(0x1000, hr.m_add, 8, src=8, number=1)
    use = _ins(0x1004, hr.m_mov, 12, src=8)
    mba = _graph(((update, use),), ((0,),))
    assert _resolve(MicroCodeInterpreter(), mba, 0, use) is None


def test_partial_register_write_is_not_skipped_during_recursive_resolution():
    seed = _ins(0x1000, hr.m_mov, 8, number=20)
    partial = _ins(0x1004, hr.m_mov, 8, number=99)
    partial.d.size = partial.l.size = 1
    update = _ins(0x1008, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x100C, hr.m_mov, 12, src=8)
    mba = _graph(((seed, partial, update, use),), ((0,),))
    # The actual result is 96, not 17. Byte composition is not supported here;
    # abstention is mandatory until the overlapping write can be reconstructed.
    assert _resolve(MicroCodeInterpreter(), mba, 0, use) is None


@pytest.mark.parametrize("pred,want", [(0, 17), (1, 27)])
def test_selected_path_survives_recursive_read_in_shared_update(pred, want):
    left = _ins(0x1000, hr.m_mov, 8, number=20)
    right = _ins(0x2000, hr.m_mov, 8, number=30)
    update = _ins(0x3000, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x4000, hr.m_mov, 12, src=8)
    mba = _graph(((left,), (right,), (update,), (use,)), ((), (), (0, 1), (2,)))
    interpreter = MicroCodeInterpreter()
    interpreter.set_merge_predecessor_context(3, (2, pred))
    assert _resolve(interpreter, mba, 3, use) == want


def test_shared_update_without_path_does_not_invent_a_value():
    left = _ins(0x1000, hr.m_mov, 8, number=20)
    right = _ins(0x2000, hr.m_mov, 8, number=30)
    update = _ins(0x3000, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x4000, hr.m_mov, 12, src=8)
    mba = _graph(((left,), (right,), (update,), (use,)), ((), (), (0, 1), (2,)))
    assert _resolve(MicroCodeInterpreter(), mba, 3, use) is None


def test_aliased_stack_use_retains_block_entry_fallback():
    seed = _Instruction(0x1000, destination=_stack())
    use = _Instruction(0x2000, source=_stack())
    mba = _graph(((seed,), (use,)), ((), (0,)))
    mba.minstkref = 0x10
    # Restricted-memory chains genuinely contain nothing for this aliased cell.
    assert [
        (d.block_serial, d.ins_ea)
        for d in find_reaching_defs_for_stkvar(mba, 1, 0x20, 4, use_ea=0x2000)
    ] == [(0, 0x1000)]


@pytest.mark.parametrize("opcode", [hr.m_stx, hr.m_call, hr.m_icall, hr.m_mov])
def test_aliased_stack_local_clobber_is_not_skipped(opcode):
    seed = _Instruction(0x1000, destination=_stack())
    clobber = _Instruction(0x1004)
    clobber.opcode = opcode
    if opcode == hr.m_mov:
        clobber.d = _stack()
        clobber.d.size = 1
    use = _Instruction(0x1008, source=_stack())
    mba = _graph(((seed, clobber, use),), ((),))
    mba.minstkref = 0x10
    assert find_reaching_defs_for_stkvar(mba, 0, 0x20, 4, use_ea=0x1008) == []


def test_duplicate_definition_anchor_abstains():
    seed = _ins(0x1000, hr.m_mov, 8, number=20)
    shadow = _ins(0x1000, hr.m_mov, 8, number=7)
    use = _ins(0x1008, hr.m_mov, 12, src=8)
    mba = _graph(((seed, shadow, use),), ((0,),))
    assert _resolve(MicroCodeInterpreter(), mba, 0, use) is None


def test_nested_call_clobber_is_not_skipped():
    seed = _ins(0x1000, hr.m_mov, 8, number=20)
    call = hr.minsn_t(0x1004)
    call.opcode = hr.m_call
    holder = _ins(0x1004, hr.m_mov, 12)
    holder.l.erase()
    holder.l._make_insn(call)
    holder.l.size = 4
    update = _ins(0x1008, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x100C, hr.m_mov, 12, src=8)
    mba = _graph(((seed, holder, update, use),), ((0,),))
    assert _resolve(MicroCodeInterpreter(), mba, 0, use) is None


def test_incoming_path_without_a_definition_is_not_dropped():
    left = _ins(0x1000, hr.m_mov, 8, number=20)
    right = _ins(0x2000, hr.m_mov, 12, number=30)
    update = _ins(0x3000, hr.m_sub, 8, src=8, number=3)
    use = _ins(0x4000, hr.m_mov, 12, src=8)
    mba = _graph(((left,), (right,), (update,), (use,)), ((), (), (0, 1), (2,)))
    # UD omits the unseeded right edge. CFG coverage must not.
    mba._graph._ud._targets_by_block[2] = _BlockChains(register_targets=(0,))
    assert _resolve(MicroCodeInterpreter(), mba, 3, use) is None
