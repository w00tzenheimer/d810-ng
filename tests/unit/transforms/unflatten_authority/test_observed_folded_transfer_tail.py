"""Structural accounting for a native block whose control transfer folded.

A committed transformation can leave a native block physically present with a
folded-away control-transfer tail: the conditional it carried is proven static
and removed, so the block becomes a fall-through and, when the tail was its
only microinstruction, carries no origin at all.  The block is still the same
catalog block -- identity is its binding plus its native range, not its
instruction count -- and the tail it lost is neither an effect site nor a
terminal site, so no effect or terminal obligation is discharged silently.
The control-flow consequence stays with the topology and route obligations.
"""

from __future__ import annotations

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.block_identity import NativeEaInterval, StableBlockIdentity
from d810.transforms.cfg_transaction import NativeBlockRef, PlanBlockRef
from d810.transforms.unflatten_authority import model
from d810.transforms.unflatten_authority.evaluate import (
    _observed_folded_transfer_tail_covered,
    _observed_identity_backed_origin_loss,
)


def _native_ref(*, start: int, end: int, instruction_eas: tuple[int, ...]):
    """One native reference whose physical entry precedes its instructions."""

    key = NativePreanalysisKey(
        "folded-tail-input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64,
    )
    return NativeBlockRef(StableBlockIdentity.from_intervals(
        (NativeEaInterval(start, end),),
        native_key=key,
        exact_instruction_eas=instruction_eas,
    ))


def test_folded_control_transfer_tail_keeps_its_source_block_accounted() -> None:
    """A block folded down to a fall-through is still structurally present."""

    total = _native_ref(start=0x1000, end=0x1020, instruction_eas=(0x1010,))
    assert _observed_folded_transfer_tail_covered(
        block_ref=total,
        anchor_ea=0x1000,
        source_origins={0x1010},
        candidate_origins=set(),
        transfer_ea=0x1010,
        effect_and_terminal_eas=frozenset(),
    )

    partial = _native_ref(
        start=0x1000, end=0x1020, instruction_eas=(0x1004, 0x1010),
    )
    assert _observed_folded_transfer_tail_covered(
        block_ref=partial,
        anchor_ea=0x1000,
        source_origins={0x1004, 0x1010},
        candidate_origins={0x1004},
        transfer_ea=0x1010,
        effect_and_terminal_eas=frozenset(),
    )


def test_folded_tail_term_refuses_every_genuinely_lost_block() -> None:
    """Only the control-transfer tail may vanish, and only in native scope."""

    ref = _native_ref(start=0x1000, end=0x1020, instruction_eas=(0x1004, 0x1010))
    base = {
        "block_ref": ref,
        "anchor_ea": 0x1000,
        "source_origins": {0x1004, 0x1010},
        "candidate_origins": {0x1004},
        "transfer_ea": 0x1010,
        "effect_and_terminal_eas": frozenset(),
    }

    def covered(**changes) -> bool:
        return _observed_folded_transfer_tail_covered(**{**base, **changes})

    assert covered()
    # An effect or terminal row at the folded EA is never accounted here.
    assert not covered(effect_and_terminal_eas=frozenset({0x1010}))
    # Losing a non-tail origin is a real loss.
    assert not covered(candidate_origins={0x1010})
    # Losing the body as well as the tail is a real loss.
    assert not covered(candidate_origins=set())
    # A foreign origin is not a subset at all.
    assert not covered(candidate_origins={0x1004, 0x2000})
    # An anchor outside every native range denotes another block.
    assert not covered(anchor_ea=0x9000)
    # A non-native reference has no native range to anchor the claim.
    assert not covered(block_ref=PlanBlockRef("folded", "helper"))
    # Nothing missing is not a fold.
    assert not covered(candidate_origins={0x1004, 0x1010})
    # A block with no control-transfer tail cannot use this term.
    assert not covered(transfer_ea=None)


def test_lineage_witness_accepts_only_identity_backed_origin_loss() -> None:
    """Preserved lineage is backed by the identity, not the origin count."""

    ref = _native_ref(start=0x1000, end=0x1020, instruction_eas=(0x1004, 0x1010))
    base = {
        "phase": model.UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
        "block_ref": ref,
        "anchor_ea": 0x1000,
        "source_origins": {0x1004, 0x1010},
        "candidate_origins": {0x1004},
    }

    def backed(**changes) -> bool:
        return _observed_identity_backed_origin_loss(**{**base, **changes})

    assert backed()
    # The folded-empty block keeps the identity its binding already proved.
    assert backed(candidate_origins=set())
    # Equal origins are not a loss, and a superset is not this block.
    assert not backed(candidate_origins={0x1004, 0x1010})
    assert not backed(candidate_origins={0x1004, 0x2000})
    # An anchor outside every native range denotes another block.
    assert not backed(anchor_ea=0x9000)
    # A non-native reference must still keep its anchor among its origins.
    assert not backed(block_ref=PlanBlockRef("folded", "helper"))
    assert backed(
        block_ref=PlanBlockRef("folded", "helper"),
        anchor_ea=0x1004,
    )
    # Origin loss is only ever admitted at the observation boundary.
    assert not backed(
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
    )
