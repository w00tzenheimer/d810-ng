"""Written-state completeness receipt collection (ticket d81-pk0f).

``d81-8xhg`` accepts a WIDE comparison-tree leaf as an exact route for state
``s`` when ``s`` is the only *written* state constant inside ``[lo, hi)``.  That
is closed-world reasoning over the written-state set, so it is only sound when
the set over-approximates every value the state slot can hold.

The original collector could not promise that: ``_extract_state_from_block``
returns the FIRST write in a block and stops, non-constant and unresolvable
writes silently produce nothing, sub-``MIN_STATE_CONSTANT`` constants were
dropped, and an lvar the extractor cannot map to a stack offset was neither
matched nor reported.  Every one of those holes let a value reach an interval
while being absent from the set, which is exactly the shape that turns
"absent" into a false proof.

These tests pin the receipt: the collector enumerates EVERY write, classifies
each one, and the route is REFUSED whenever any write could not be classified.

The fakes below are duck-typed microcode operands, not mocks of an ``ida_*``
module: the vocabulary comes from the backend's own
``condition_chain_runtime`` shim, whose no-IDA fallback is already unit-tested
in ``test_condition_chain_runtime.py``.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from d810.analyses.control_flow.route_exactness import (
    REASON_BELOW_MIN_STATE_CONSTANT,
    REASON_BLOCK_UNREADABLE,
    REASON_NONCONSTANT_WRITE,
    REASON_NO_STATE_VARIABLE,
    REASON_UNRESOLVED_WRITE,
    REASON_UNSUPPORTED_ALIAS,
    is_exact_route_interval,
)
from d810.backends.hexrays import condition_chain_runtime
from d810.backends.hexrays.evidence import condition_chain_analysis as cca

# Microcode vocabulary, matching the real ``idaapi`` numbering closely enough
# for the extractor; only the *identity* of the values matters here.
_VOCABULARY = SimpleNamespace(
    m_mov=4,
    m_stx=62,
    m_add=28,
    m_xor=31,
    m_ldx=61,
    mop_r=1,
    mop_n=2,
    mop_S=5,
    mop_d=6,
    mop_a=8,
    mop_l=9,
)

_STATE_STKOFF = 48
# Two constants that share one wide comparison-tree leaf.
_LO = 0x1B7B68FD
_HI = 0x208318D7
_STATE = 0x1CAFDDE5
_SECOND_STATE = 0x1E000000
_OUTSIDE = 0x76B1AD38


@pytest.fixture(autouse=True)
def _microcode_vocabulary(monkeypatch):
    """Give the extractor an opcode/operand vocabulary without a live IDA."""
    monkeypatch.setattr(condition_chain_runtime, "_idaapi", lambda: _VOCABULARY)
    saved = (cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP)
    cca._maps_initialized = False
    cca._init_constants()
    yield
    cca._maps_initialized, cca.OPCODE_MAP, cca.MOP_TYPE_MAP = saved


def _num(value: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_n, nnn=SimpleNamespace(value=value), size=size)


def _stk(offset: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_S, s=SimpleNamespace(off=offset), size=size)


def _reg(register_id: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_r, r=register_id, size=size)


def _lvar(idx: int, size: int = 4):
    return SimpleNamespace(t=_VOCABULARY.mop_l, l=SimpleNamespace(idx=idx), size=size)


def _addr_of(inner):
    return SimpleNamespace(t=_VOCABULARY.mop_a, a=inner, size=8)


def _insn(opcode: int, left=None, right=None, dest=None):
    return SimpleNamespace(opcode=opcode, l=left, r=right, d=dest, next=None)


def _block(*insns, predset=()):
    head = None
    for insn in reversed(insns):
        insn.next = head
        head = insn
    return SimpleNamespace(head=head, predset=tuple(predset))


class _Mba:
    """Minimal block array: ``qty`` / ``get_mblock`` / ``vars``."""

    def __init__(self, blocks, lvars=()):
        self._blocks = list(blocks)
        self.qty = len(self._blocks)
        self.vars = list(lvars)

    def get_mblock(self, serial):
        return self._blocks[serial]


def _collect(mba, **kwargs):
    return cca._collect_written_state_set(mba, _STATE_STKOFF, **kwargs)


def _mov_state(value: int):
    return _insn(_VOCABULARY.m_mov, left=_num(value), dest=_stk(_STATE_STKOFF))


# ---------------------------------------------------------------------------
# Completeness-preserving: every write is enumerated and classified.
# ---------------------------------------------------------------------------


def test_single_constant_write_yields_a_complete_receipt():
    receipt = _collect(_Mba([_block(_mov_state(_STATE))]))

    assert receipt.complete
    assert receipt.reasons == ()
    assert receipt.constants == frozenset({_STATE})
    assert is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_second_state_write_in_the_same_block_is_collected():
    """The d81-pk0f hole: only the FIRST write per block used to be collected.

    Both constants share the leaf ``[_LO, _HI)``, so collecting the second one
    turns the leaf back into the shared corridor it really is.
    """
    receipt = _collect(
        _Mba([_block(_mov_state(_STATE), _mov_state(_SECOND_STATE))])
    )

    assert receipt.complete
    assert receipt.constants == frozenset({_STATE, _SECOND_STATE})
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_sub_threshold_constants_are_retained_not_dropped():
    """A small constant cannot be PROVEN to be a non-selector, so it stays.

    Retaining it over-approximates (safe); dropping it would let the leaf look
    isolated when a small value also reaches it.
    """
    receipt = _collect(_Mba([_block(_mov_state(_STATE), _mov_state(0x10))]))

    assert receipt.complete
    assert 0x10 in receipt.constants
    assert not is_exact_route_interval(
        lo=0, hi=_HI, state=_STATE, written_states=receipt
    )
    # The selector-only view the legacy decision-DAG consumer needs drops it,
    # and says so.
    selector_view = receipt.filtered(cca.MIN_STATE_CONSTANT)
    assert selector_view.constants == frozenset({_STATE})
    assert not selector_view.complete
    assert REASON_BELOW_MIN_STATE_CONSTANT in selector_view.reasons


# ---------------------------------------------------------------------------
# Completeness-breaking: each reason must abstain.
# ---------------------------------------------------------------------------


def test_nonconstant_write_makes_the_receipt_incomplete():
    receipt = _collect(
        _Mba(
            [
                _block(
                    _mov_state(_STATE),
                    _insn(_VOCABULARY.m_mov, left=_reg(9), dest=_stk(_STATE_STKOFF)),
                )
            ]
        )
    )

    assert not receipt.complete
    assert REASON_NONCONSTANT_WRITE in receipt.reasons
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_computed_write_through_a_non_move_opcode_is_nonconstant():
    receipt = _collect(
        _Mba(
            [
                _block(
                    _mov_state(_STATE),
                    _insn(
                        _VOCABULARY.m_add,
                        left=_stk(_STATE_STKOFF),
                        right=_num(1),
                        dest=_stk(_STATE_STKOFF),
                    ),
                )
            ]
        )
    )

    assert not receipt.complete
    assert REASON_NONCONSTANT_WRITE in receipt.reasons
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_unresolvable_stack_store_makes_the_receipt_incomplete():
    """An ``m_stx`` through a stack-flavoured address we cannot pin may alias."""
    receipt = _collect(
        _Mba(
            [
                _block(
                    _mov_state(_STATE),
                    _insn(
                        _VOCABULARY.m_stx,
                        left=_num(_SECOND_STATE),
                        right=_addr_of(_reg(4)),
                        dest=_num(4),
                    ),
                )
            ]
        )
    )

    assert not receipt.complete
    assert REASON_UNRESOLVED_WRITE in receipt.reasons
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_unmappable_lvar_write_is_reported_as_an_unsupported_alias():
    """An ``mop_l`` we can neither match nor rule out is not silently ignored."""
    receipt = _collect(
        _Mba(
            [
                _block(
                    _mov_state(_STATE),
                    _insn(_VOCABULARY.m_mov, left=_num(_SECOND_STATE), dest=_lvar(7)),
                )
            ],
            lvars=(),
        )
    )

    assert not receipt.complete
    assert REASON_UNSUPPORTED_ALIAS in receipt.reasons
    assert not is_exact_route_interval(
        lo=_LO, hi=_HI, state=_STATE, written_states=receipt
    )


def test_known_lvar_index_keeps_the_receipt_complete():
    """With the lvar index known the operand is decidable, so nothing abstains."""
    receipt = _collect(
        _Mba([_block(_insn(_VOCABULARY.m_mov, left=_num(_STATE), dest=_lvar(7)))]),
        state_var_lvar_idx=7,
    )

    assert receipt.complete
    assert receipt.constants == frozenset({_STATE})


def test_unreadable_block_makes_the_receipt_incomplete():
    receipt = _collect(_Mba([_block(_mov_state(_STATE)), None]))

    assert not receipt.complete
    assert REASON_BLOCK_UNREADABLE in receipt.reasons


def test_missing_state_variable_yields_an_incomplete_receipt():
    receipt = cca._collect_written_state_set(_Mba([]), None)

    assert not receipt.complete
    assert receipt.reasons == (REASON_NO_STATE_VARIABLE,)
    assert receipt.constants == frozenset()


def test_truncated_block_enumeration_costs_completeness():
    writes = [
        _mov_state(_STATE + index)
        for index in range(cca.MAX_STATE_WRITES_PER_BLOCK + 2)
    ]
    receipt = _collect(_Mba([_block(*writes)]))

    assert not receipt.complete
    assert "multi_write_block" in receipt.reasons


def test_initial_state_is_part_of_the_ground_set():
    receipt = _collect(
        _Mba([_block(_mov_state(_OUTSIDE))]), initial_state=_STATE
    )

    assert receipt.complete
    assert receipt.constants == frozenset({_OUTSIDE, _STATE})


# ---------------------------------------------------------------------------
# Computed writes (ticket d81-czrc) feeding the receipt.
#
# ``xor ecx, eax -> statevar`` is invisible to the in-block folder because the
# definitions of ``ecx`` / ``eax`` live one hop up, in the predecessors.  Left
# alone it lands as NONCONSTANT and costs the receipt its completeness, which
# in turn makes every range-leaf route abstain (d81-8xhg).  Resolving it across
# the predecessor partitions is what lets the two tickets compose.
# ---------------------------------------------------------------------------

_ECX = 16
_EAX = 24
_PARTITION_A = (0x5FDB1F09, 0x1D431D66)  # xor -> 0x4298026F
_PARTITION_B = (0x33AA1100, 0x0F0F0F0F)  # xor -> 0x3CA51E0F
_FOLDED_A = 0x4298026F
_FOLDED_B = 0x3CA51E0F


def _mov_reg(register_id: int, value: int):
    return _insn(_VOCABULARY.m_mov, left=_num(value), dest=_reg(register_id))


def _partition(pair):
    return _block(_mov_reg(_ECX, pair[0]), _mov_reg(_EAX, pair[1]))


def _xor_into_state(*preds):
    return _block(
        _insn(
            _VOCABULARY.m_xor,
            left=_reg(_ECX),
            right=_reg(_EAX),
            dest=_stk(_STATE_STKOFF),
        ),
        predset=preds,
    )


def test_computed_write_folds_into_a_complete_receipt():
    """Both partitions fold, so the receipt keeps its closure."""
    receipt = _collect(
        _Mba([_partition(_PARTITION_A), _partition(_PARTITION_B), _xor_into_state(0, 1)])
    )

    assert receipt.complete
    assert receipt.reasons == ()
    assert receipt.constants == frozenset({_FOLDED_A, _FOLDED_B})


def test_folded_computed_states_participate_in_route_exactness():
    """The folded constants are real members, so they can refuse a leaf.

    Without the fold the receipt is incomplete and the range branch abstains;
    with it, the leaf spanning BOTH folded states is correctly refused while
    the leaf isolating one is accepted.
    """
    receipt = _collect(
        _Mba([_partition(_PARTITION_A), _partition(_PARTITION_B), _xor_into_state(0, 1)])
    )

    assert not is_exact_route_interval(
        lo=_FOLDED_B, hi=_FOLDED_A + 1, state=_FOLDED_A, written_states=receipt
    )
    assert is_exact_route_interval(
        lo=_FOLDED_A, hi=_FOLDED_A + 0x1000, state=_FOLDED_A, written_states=receipt
    )


def test_unresolvable_partition_leaves_the_receipt_incomplete():
    """All-or-nothing: one partition without a constant abstains entirely."""
    blind = _block(_mov_reg(_ECX, _PARTITION_B[0]))  # ``eax`` never defined
    receipt = _collect(_Mba([_partition(_PARTITION_A), blind, _xor_into_state(0, 1)]))

    assert not receipt.complete
    assert REASON_NONCONSTANT_WRITE in receipt.reasons
    assert _FOLDED_A not in receipt.constants


def test_two_computed_writes_in_one_block_are_not_substituted():
    """``_find_computed_state_write`` resolves only the LAST non-literal writer.

    Substituting for both would attest to a value that was never proven, so the
    fold declines and the receipt honestly reports the unfolded writes.
    """
    doubled = _block(
        _insn(
            _VOCABULARY.m_xor,
            left=_reg(_ECX),
            right=_reg(_EAX),
            dest=_stk(_STATE_STKOFF),
        ),
        _insn(
            _VOCABULARY.m_add,
            left=_reg(_ECX),
            right=_reg(_EAX),
            dest=_stk(_STATE_STKOFF),
        ),
        predset=(0, 1),
    )
    receipt = _collect(_Mba([_partition(_PARTITION_A), _partition(_PARTITION_B), doubled]))

    assert not receipt.complete
    assert REASON_NONCONSTANT_WRITE in receipt.reasons
