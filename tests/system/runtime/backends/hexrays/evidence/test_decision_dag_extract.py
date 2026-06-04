"""Runtime tests for the live-BST -> DecisionDag extractor.

Drives :func:`extract_decision_dag` with ``SimpleNamespace`` shims shaped like
``mblock_t`` / ``minsn_t`` / ``mop_t`` (real ``ida_hexrays`` opcode + mop-type
constants, no full decompile), reproducing the ground-truth sub_7FFD3338C040
dispatcher BST path so routing matches ``.tmp/bst_trace.py``.

IDA-dependent (reads ``ida_hexrays`` constants) -> system/runtime, not a unit.
"""
from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.backends.hexrays.evidence.decision_dag_extract import extract_decision_dag

STK = 0x64  # state var mop_S.s.off (raw), as in sub_7FFD


class _Blk:
    def __init__(self, tail, succs):
        self.tail = tail
        self._succs = [int(s) for s in succs]

    def succ(self, i):
        return self._succs[i]

    def nsucc(self):
        return len(self._succs)


def _state():
    return SimpleNamespace(t=ida_hexrays.mop_S, s=SimpleNamespace(off=STK))


def _const(value):
    return SimpleNamespace(t=ida_hexrays.mop_n, nnn=SimpleNamespace(value=value))


def _target(block):
    return SimpleNamespace(b=block)


def _cmp(opcode, const, jump_target, fallthrough):
    # tail: ``OP state, #const, @jump_target``; succs = [fallthrough, jump_target].
    tail = SimpleNamespace(
        opcode=opcode, l=_state(), r=_const(const), d=_target(jump_target)
    )
    return _Blk(tail, [fallthrough, jump_target])


def _leaf():
    return _Blk(tail=None, succs=[2])


def _mba(blocks):
    return SimpleNamespace(get_mblock=lambda s: blocks.get(int(s)))


def _sub7ffd_mba():
    return _mba(
        {
            2: _cmp(ida_hexrays.m_jbe, 0x37B42A3F, 112, 3),
            3: _cmp(ida_hexrays.m_jbe, 0x606DC165, 58, 4),
            4: _cmp(ida_hexrays.m_ja, 0x6B588048, 36, 5),
            36: _cmp(ida_hexrays.m_ja, 0x737189D4, 49, 37),
            49: _cmp(ida_hexrays.m_ja, 0x7C2C021F, 53, 50),
            53: _cmp(ida_hexrays.m_jnz, 0x7C2C0220, 55, 54),
            55: _cmp(ida_hexrays.m_jnz, 0x7D9C16EC, 57, 56),
            57: _leaf(),
            56: _leaf(),
            112: _leaf(),
            58: _leaf(),
            5: _leaf(),
            37: _leaf(),
            50: _leaf(),
            54: _leaf(),
        }
    )


def test_extract_routes_match_microcode():
    dag = extract_decision_dag(
        _sub7ffd_mba(), dispatcher_entry_serial=2, state_var_stkoff=STK
    )
    assert dag.route(0x7FDCE054) == 57  # != 0x7D9C16EC -> jump arm (blk35's state)
    assert dag.route(0x7D9C16EC) == 56  # == 0x7D9C16EC -> fallthrough arm
    sib = dag.sibling_arms()
    assert 56 in sib[57] and 57 in sib[56]
    assert set(dag.nodes) == {2, 3, 4, 36, 49, 53, 55}  # comparisons only


def test_extract_skips_handler_internal_conditional():
    # A comparison whose operands are NOT the state var (a handler's own branch,
    # e.g. ``jl var_1C8, #0x80``) is a leaf, never a BST node.
    handler = _Blk(
        SimpleNamespace(
            opcode=ida_hexrays.m_jl,
            l=SimpleNamespace(t=ida_hexrays.mop_l, l=SimpleNamespace(idx=99)),
            r=_const(0x80),
            d=_target(11),
        ),
        [10, 11],
    )
    mba = _mba({2: handler, 10: _leaf(), 11: _leaf()})
    dag = extract_decision_dag(mba, dispatcher_entry_serial=2, state_var_stkoff=STK)
    assert dag.nodes == {}
    assert dag.route(0x1234) == 2  # root is a leaf -> routes to itself


def test_extract_flips_op_when_state_var_on_right():
    # ``jbe #3, state`` == ``state >= 3`` (jae): state=5 -> 5>=3 -> jump target.
    tail = SimpleNamespace(
        opcode=ida_hexrays.m_jbe, l=_const(3), r=_state(), d=_target(20)
    )
    mba = _mba({2: _Blk(tail, [21, 20]), 20: _leaf(), 21: _leaf()})
    dag = extract_decision_dag(mba, dispatcher_entry_serial=2, state_var_stkoff=STK)
    assert dag.nodes[2].op == "jae"
    assert dag.route(5) == 20
    assert dag.route(2) == 21
