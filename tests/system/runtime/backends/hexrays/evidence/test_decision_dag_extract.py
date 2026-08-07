"""Runtime tests for the live condition-chain -> DecisionDag extractor.

Drives :func:`extract_decision_dag` with ``SimpleNamespace`` shims shaped like
``mblock_t`` / ``minsn_t`` / ``mop_t`` (real ``ida_hexrays`` opcode + mop-type
constants, no full decompile), reproducing the ground-truth sub_7FFD3338C040
dispatcher condition-chain path so routing matches ``.tmp/condition_chain_trace.py``.

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
    # e.g. ``jl var_1C8, #0x80``) is a leaf, never a condition-chain node.
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


def _reg(reg, valnum=0):
    return SimpleNamespace(t=ida_hexrays.mop_r, r=reg, valnum=valnum)


def _entry_load(reg, valnum, fallthrough, jump_target, const):
    """``xdu state -> reg{valnum}`` then ``jg state, #const, @jump``."""
    load = SimpleNamespace(
        opcode=ida_hexrays.m_xdu, l=_state(), r=None, d=_reg(reg, valnum), next=None
    )
    blk = _cmp(ida_hexrays.m_jg, const, jump_target, fallthrough)
    blk.head = load
    return blk


def test_extract_rejects_same_register_with_different_value_number():
    """Regression, ticket lpccp-htcb (sub_7FFE50C44430 blk 99).

    A handler whose entry block recomputes into the SAME register the chain
    compares (``jnz eax.4{131}, #0`` from a local ``m_xdu`` MBA opaque predicate)
    must be a LEAF.  Matching on register number alone made it a chain node
    ``state != 0 -> @default``, crediting its whole 165,391,921-state cell -- and
    with it state 0x2DDD5B9C -- to the dispatcher's default arm.
    """
    STATE_REG, STATE_VN, IMPOSTOR_VN = 8, 7, 131
    DEFAULT_ARM, LOW_SUBTREE = 191, 11
    blocks = {
        # entry: loads the state var into eax{7}, then the BST root
        # ``jg state, #0x3BC233F2`` -- 0x402FE6E3 is signed-greater, so it takes
        # the jump arm into blk 58 (mirrors the real root at 0x7FFE50C444D4).
        11: _leaf(),
        4: _entry_load(STATE_REG, STATE_VN, LOW_SUBTREE, 58, 0x3BC233F2),
        # real chain node: compares eax{7} -- same register AND same value number
        58: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, STATE_VN),
                r=_const(0x402FE6E3),
                d=_target(DEFAULT_ARM),
            ),
            [59, DEFAULT_ARM],
        ),
        # handler entry: same register, DIFFERENT value number -> must be a leaf
        59: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, IMPOSTOR_VN),
                r=_const(0),
                d=_target(DEFAULT_ARM),
            ),
            [100, DEFAULT_ARM],
        ),
        100: _leaf(),
        DEFAULT_ARM: _leaf(),
    }
    dag = extract_decision_dag(
        _mba(blocks), dispatcher_entry_serial=4, state_var_stkoff=STK
    )

    assert 59 not in dag.nodes, "opaque-predicate handler was mistaken for a chain node"
    assert set(dag.nodes) == {4, 58}
    # state 0x402FE6E3 takes blk 58's equality fallthrough into the handler,
    # which must now terminate there instead of being routed to the default arm.
    assert dag.route(0x402FE6E3) == 59


def test_extract_accepts_register_when_value_numbers_are_unavailable():
    """Value numbering is not always populated -- an unknown valnum must not reject.

    Guards the ticket lpccp-htcb fix against the mirror failure (a guard that
    discards valid work): shims with ``valnum=0`` on both sides still route.
    """
    STATE_REG = 8
    blocks = {
        4: _entry_load(STATE_REG, 0, 58, 191, 0x3BC233F2),
        58: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, 0),
                r=_const(0x402FE6E3),
                d=_target(191),
            ),
            [59, 191],
        ),
        59: _leaf(),
        191: _leaf(),
    }
    dag = extract_decision_dag(
        _mba(blocks), dispatcher_entry_serial=4, state_var_stkoff=STK
    )
    assert set(dag.nodes) == {4, 58}


def test_extract_completes_a_reg_only_identity_from_the_entry_load():
    """Regression, ticket lpccp-w81p (sub_7FFE50C44430).

    A dual-homed dispatcher compares the STACK slot at its BST root and the
    REGISTER at every deeper node.  Recovery hands down only the register (its
    contract treats ``state_var_reg`` as "register with no stack home"), so the
    root failed to parse; ``_descend_to_root`` cannot walk past a 2-way block,
    and the whole chain collapsed to an empty DAG -- 59 matchable nodes lost to
    one unmatched root.  The entry block's own ``xdu stack -> reg`` proves the
    missing half.
    """
    STATE_REG, STATE_VN, DEFAULT_ARM = 8, 7, 191
    blocks = {
        # entry: xdu %var_310 -> eax{7}, then a root comparing the STACK slot
        4: _entry_load(STATE_REG, STATE_VN, 11, 58, 0x3BC233F2),
        # deeper node: compares the REGISTER
        58: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, STATE_VN),
                r=_const(0x402FE6E3),
                d=_target(DEFAULT_ARM),
            ),
            [59, DEFAULT_ARM],
        ),
        11: _leaf(),
        59: _leaf(),
        DEFAULT_ARM: _leaf(),
    }
    dag = extract_decision_dag(
        _mba(blocks),
        dispatcher_entry_serial=4,
        state_var_stkoff=None,
        state_var_reg=STATE_REG,
    )

    assert set(dag.nodes) == {4, 58}, "reg-only identity must still parse the stack root"
    assert dag.route(0x402FE6E3) == 59


def test_reg_only_identity_still_rejects_a_different_value_number():
    """The lpccp-htcb gate must stay armed on the explicit-register path.

    Supplying ``state_var_reg`` used to skip alias detection entirely, leaving
    the value number unknown and the impostor gate disarmed -- so fixing
    lpccp-w81p by passing the register through would have silently undone
    lpccp-htcb.  The entry load supplies the valnum either way.
    """
    STATE_REG, STATE_VN, IMPOSTOR_VN, DEFAULT_ARM = 8, 7, 131, 191
    blocks = {
        4: _entry_load(STATE_REG, STATE_VN, 11, 58, 0x3BC233F2),
        58: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, STATE_VN),
                r=_const(0x402FE6E3),
                d=_target(DEFAULT_ARM),
            ),
            [59, DEFAULT_ARM],
        ),
        # handler whose entry recomputes into the same register
        59: _Blk(
            SimpleNamespace(
                opcode=ida_hexrays.m_jnz,
                l=_reg(STATE_REG, IMPOSTOR_VN),
                r=_const(0),
                d=_target(DEFAULT_ARM),
            ),
            [100, DEFAULT_ARM],
        ),
        11: _leaf(),
        100: _leaf(),
        DEFAULT_ARM: _leaf(),
    }
    dag = extract_decision_dag(
        _mba(blocks),
        dispatcher_entry_serial=4,
        state_var_stkoff=None,
        state_var_reg=STATE_REG,
    )

    assert 59 not in dag.nodes
    assert set(dag.nodes) == {4, 58}


def test_extract_register_resident_state_var_without_stack_slot():
    state_reg = 20
    tail = SimpleNamespace(
        opcode=ida_hexrays.m_jnz,
        l=SimpleNamespace(t=ida_hexrays.mop_r, r=state_reg),
        r=_const(0x82F1899D),
        d=_target(30),
    )
    mba = _mba({2: _Blk(tail, [31, 30]), 30: _leaf(), 31: _leaf()})

    dag = extract_decision_dag(
        mba,
        dispatcher_entry_serial=2,
        state_var_stkoff=None,
        state_var_reg=state_reg,
    )

    assert dag.nodes[2].op == "jnz"
    assert dag.route(0x82F1899D) == 31
    assert dag.route(0xDEADBEEF) == 30
