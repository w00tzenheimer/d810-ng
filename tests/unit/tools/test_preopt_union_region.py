from d810.analyses.control_flow.materialized_indirect_transfer import (
    MaterializedIndirectTransfer,
)
from tools.scripts.rhad_investigation.preopt_union_region import (
    PreoptUnionAbstentionReason,
    plan_preopt_union_region,
    select_missing_preopt_union_region,
)


def _route(
    target_ea: int,
    ranges: tuple[tuple[int, int], ...],
) -> MaterializedIndirectTransfer:
    return MaterializedIndirectTransfer(
        source_jmp_ea=target_ea - 4,
        source_block_ea=target_ea - 8,
        materialized_anchor_eas=(),
        target_eas=(target_ea,),
        resolver_kind="static_handler_entry_route",
        owned_native_ranges=ranges,
    )


def test_union_region_merges_overlapping_handler_closures_once() -> None:
    plan = plan_preopt_union_region(
        (
            _route(0x401000, ((0x401000, 0x401020), (0x401010, 0x401030))),
            _route(0x402000, ((0x401030, 0x401040),)),
        )
    )

    assert plan.seed_eas == (0x401000, 0x402000)
    assert plan.primary_seed_ea == 0x401000
    assert plan.seed_native_ranges == (
        (0x401000, ((0x401000, 0x401030),)),
        (0x402000, ((0x401030, 0x401040),)),
    )
    assert plan.native_ranges == ((0x401000, 0x401040),)
    assert plan.abstentions == ()


def test_union_region_abstains_on_missing_and_conflicting_owned_ranges() -> None:
    plan = plan_preopt_union_region(
        (
            _route(0x501000, ()),
            _route(0x502000, ((0x502000, 0x502010),)),
            _route(0x502000, ((0x502000, 0x502020),)),
        )
    )

    assert plan.seed_eas == ()
    assert plan.primary_seed_ea is None
    assert plan.native_ranges == ()
    assert {(row.target_ea, row.reason) for row in plan.abstentions} == {
        (0x501000, PreoptUnionAbstentionReason.MISSING_OWNED_RANGES),
        (0x502000, PreoptUnionAbstentionReason.AMBIGUOUS_OWNED_RANGES),
    }


def test_union_region_ignores_unrelated_transfer_kinds() -> None:
    unrelated = MaterializedIndirectTransfer(
        source_jmp_ea=0x601000,
        source_block_ea=0x601000,
        materialized_anchor_eas=(),
        target_eas=(0x602000,),
        resolver_kind="static_fixpoint",
        owned_native_ranges=((0x602000, 0x602010),),
    )

    plan = plan_preopt_union_region((unrelated,))

    assert plan.seed_eas == ()
    assert plan.native_ranges == ()
    assert plan.abstentions == ()


def test_missing_union_region_keeps_only_seed_closures_absent_from_live_mba() -> None:
    plan = plan_preopt_union_region(
        (
            _route(0x701000, ((0x701000, 0x701020),)),
            _route(0x702000, ((0x702000, 0x702020), (0x702020, 0x702030))),
            _route(0x703000, ((0x703000, 0x703010),)),
        )
    )

    missing = select_missing_preopt_union_region(
        plan,
        frozenset({0x701000, 0x703000}),
    )

    assert missing.seed_eas == (0x702000,)
    assert missing.primary_seed_ea == 0x702000
    assert missing.seed_native_ranges == ((0x702000, ((0x702000, 0x702030),)),)
    assert missing.native_ranges == ((0x702000, 0x702030),)
    assert missing.abstentions == ()
