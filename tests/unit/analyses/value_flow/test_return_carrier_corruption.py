"""Return-carrier corruption proof (ticket llr-ytow).

The headline tests encode the real sub_7FFD3338C040 scenario measured from the
GLBOPT1_post_d810 diag snapshot: d810's MBA fold leaves two dead constant writes
to the return register on the byte-count early-exit paths --
``mov #0xB5, al{151}`` (blk61) and ``mov #0x4F409D9CACFE95C, rax{157}`` (blk37)
-- both with empty DU-chains and both strictly dominated by the counter carrier
``add [%var_690],#1, rax{10}`` (blk4). They must be proven droppable. The
genuine ``mov #0x5644FD01B1049C4B, rax`` sentinel return (blk9) has no carrier
behind it and must be kept.
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
    """blk61 ``mov #0xB5, al{151}`` -- partial, 0 uses, carrier dominates."""
    target = ReturnRegDef(
        block=61, ea=0x180018F75, ssa=151,
        is_const=True, is_partial=True, const_value=0xB5,
    )
    proof = prove_return_const_droppable(
        target,
        du_chain_uses=0,
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,
    )
    assert isinstance(proof, CarrierCorruptionProof)
    assert proof.dominating_carrier_blocks == (4, 31, 49)
    assert "0xb5" in proof.reason


def test_0x4F40_full_corruption_is_droppable():
    """blk37 ``mov #0x4F40..95C, rax{157}`` -- full overwrite, 0 uses, dominated."""
    target = ReturnRegDef(
        block=37, ea=0x18001954F, ssa=157,
        is_const=True, is_partial=False, const_value=0x4F409D9CACFE95C,
    )
    proof = prove_return_const_droppable(
        target,
        du_chain_uses=0,
        carrier_blocks=SUB7FFD_CARRIER_BLOCKS,
        strict_dominators=SUB7FFD_CASCADE_DOMINATORS,
    )
    assert isinstance(proof, CarrierCorruptionProof)
    assert 4 in proof.dominating_carrier_blocks


def test_0x5644_sentinel_return_is_kept():
    """blk9 sentinel: const with no dominating carrier -> the genuine return."""
    target = ReturnRegDef(
        block=9, ea=0x9, ssa=200,
        is_const=True, is_partial=False, const_value=0x5644FD01B1049C4B,
    )
    result = prove_return_const_droppable(
        target,
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
        target, du_chain_uses=2,
        carrier_blocks=frozenset({4}), strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.HAS_USES)


def test_untagged_return_def_is_kept():
    """No SSA version -> cannot prove an empty DU-chain -> fail-closed keep."""
    target = ReturnRegDef(9, 0x9, None, is_const=True, is_partial=False, const_value=7)
    result = prove_return_const_droppable(
        target, du_chain_uses=0,
        carrier_blocks=frozenset({4}), strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.UNTAGGED_DEF)


def test_non_const_def_is_out_of_scope():
    """Only literal ``mov #imm`` writes are candidates."""
    target = ReturnRegDef(7, 0x7, 5, is_const=False, is_partial=False)
    result = prove_return_const_droppable(
        target, du_chain_uses=0,
        carrier_blocks=frozenset({4}), strict_dominators=frozenset({4}),
    )
    assert result == (None, KeepReason.NOT_CONST)


def test_self_block_carrier_does_not_count_as_dominator():
    """A carrier in the candidate's own block is not a *strict* dominator."""
    target = ReturnRegDef(37, 0x18001954F, 157, is_const=True, is_partial=False)
    # Carrier is blk37 itself; strict_dominators excludes 37 -> no dominator.
    result = prove_return_const_droppable(
        target, du_chain_uses=0,
        carrier_blocks=frozenset({37}), strict_dominators=frozenset({0, 1}),
    )
    assert result == (None, KeepReason.NO_DOMINATING_CARRIER)
