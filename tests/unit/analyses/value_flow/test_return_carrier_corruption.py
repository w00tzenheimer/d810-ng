"""Return-carrier corruption proof (tickets llr-ytow + d81-fzlo).

The headline tests encode the real sub_7FFD3338C040 scenario measured from the
GLBOPT1 diag snapshots: IDA's MBA fold leaves two dead constant writes to the
return register on the byte-count early-exit paths -- ``mov #0xB5, al{151}``
(blk61) and ``mov #0x4F409D9CACFE95C, rax{157}`` (blk37). Both HAD a real
consumer at the pre-fold snapshot (the byte-4 shift / byte-5 guard) which the
fold orphaned, both have empty DU-chains now, and both are strictly dominated by
the counter carrier ``add [%var_690],#1, rax{10}`` (blk4). They must be proven
droppable.

The severance gate (ticket d81-fzlo) is the primary trigger: a genuine constant
return that was NEVER consumed (e.g. ``result = carrier; LOBYTE(result) = k;
return``) is absent from the pre-fold set, so it is kept even when both pillars
would otherwise pass -- closing the false-drop the static v1 proof was exposed to.
"""

from __future__ import annotations

from d810.analyses.value_flow.return_carrier_corruption import (
    CarrierCorruptionProof,
    KeepReason,
    ReturnRegDef,
    prove_return_const_droppable,
)

# Carrier blocks measured from the diag snapshot (full-rax stack/arg-sourced
# return defs): blk4 = counter (*v17+1), blk31 = (v55 & 0x78), blk49 = a5+0xD0.
SUB7FFD_CARRIER_BLOCKS = frozenset({4, 31, 49})
# Strict dominators of the two corruptor blocks include the counter carrier blk4.
SUB7FFD_CASCADE_DOMINATORS = frozenset({0, 1, 4, 5, 31, 49})


def test_0xB5_partial_corruption_is_droppable():
    """blk61 ``mov #0xB5, al{151}`` -- severed, partial, 0 uses, carrier dominates."""
    target = ReturnRegDef(
        block=61,
        ea=0x180018F75,
        ssa=151,
        is_const=True,
        is_partial=True,
        const_value=0xB5,
    )
    proof = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,
    )
    assert isinstance(proof, CarrierCorruptionProof)
    assert proof.dominating_carrier_blocks == (4, 31, 49)
    assert "0xb5" in proof.reason


def test_0x4F40_full_corruption_is_droppable():
    """blk37 ``mov #0x4F40..95C, rax{157}`` -- severed, full, 0 uses, dominated."""
    target = ReturnRegDef(
        block=37,
        ea=0x18001954F,
        ssa=157,
        is_const=True,
        is_partial=False,
        const_value=0x4F409D9CACFE95C,
    )
    proof = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,
    )
    assert isinstance(proof, CarrierCorruptionProof)
    assert 4 in proof.dominating_carrier_blocks


def test_legit_partial_return_not_severed_is_kept():
    """The v2 soundness guarantee (d81-fzlo).

    A legitimate ``result = carrier; LOBYTE(result) = k; return`` would pass BOTH
    pillars (the byte write has no value-use; a stack/arg carrier dominates), so
    the static v1 proof would WRONGLY drop it. The severance gate keeps it because
    the value never had a consumer to lose to a fold.
    """
    target = ReturnRegDef(
        block=70,
        ea=0x1800A0,
        ssa=300,
        is_const=True,
        is_partial=True,
        const_value=0x5,
    )
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=False,  # never consumed -> not a fold victim
        du_chain_uses=0,  # P1 would pass
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,  # P2 would pass
    )
    assert result == (None, KeepReason.NOT_SEVERED)


def test_severance_gate_precedes_uses_pillar():
    """The severance gate is checked before Pillar 1 (audit-trail ordering)."""
    target = ReturnRegDef(
        block=70,
        ea=0x1800A0,
        ssa=301,
        is_const=True,
        is_partial=False,
        const_value=0x9,
    )
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=False,
        du_chain_uses=2,  # would be HAS_USES if reached
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,
    )
    assert result == (None, KeepReason.NOT_SEVERED)


def test_0x5644_sentinel_return_is_kept():
    """blk9 sentinel: severed but no dominating carrier -> the genuine return."""
    target = ReturnRegDef(
        block=9,
        ea=0x9,
        ssa=200,
        is_const=True,
        is_partial=False,
        const_value=0x5644FD01B1049C4B,
    )
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        # blk16/blk62 carriers *reach* blk9 by cross-path bleed but do NOT
        # strictly dominate it -- the dominance test must exclude them.
        carrier_blocks=frozenset({16, 62}),
        strict_dominators=frozenset({0, 1}),
    )
    assert result == (None, KeepReason.NO_DOMINATING_CARRIER)


def test_def_with_surviving_use_is_kept():
    """Pillar 1 fail-closed: any explicit use blocks the drop."""
    target = ReturnRegDef(7, 0x7, 5, is_const=True, is_partial=False, const_value=1)
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=2,
        carrier_blocks=frozenset({4}),
        strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.HAS_USES)


def test_untagged_return_def_is_kept():
    """No SSA version -> cannot prove an empty DU-chain -> fail-closed keep."""
    target = ReturnRegDef(9, 0x9, None, is_const=True, is_partial=False, const_value=7)
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        carrier_blocks=frozenset({4}),
        strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.UNTAGGED_DEF)


def test_non_const_def_is_out_of_scope():
    """Only literal ``mov #imm`` writes are candidates."""
    target = ReturnRegDef(7, 0x7, 5, is_const=False, is_partial=False)
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        carrier_blocks=frozenset({4}),
        strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.NOT_CONST)


def test_self_block_carrier_does_not_count_as_dominator():
    """A carrier in the candidate's own block is not a *strict* dominator."""
    target = ReturnRegDef(37, 0x18001954F, 157, is_const=True, is_partial=False)
    # Carrier is blk37 itself; strict_dominators excludes 37 -> no dominator.
    result = prove_return_const_droppable(
        target,
        was_consumed_prefold=True,
        du_chain_uses=0,
        carrier_blocks=frozenset({37}),
        strict_dominators=frozenset({0, 1}),
    )
    assert result == (None, KeepReason.NO_DOMINATING_CARRIER)
