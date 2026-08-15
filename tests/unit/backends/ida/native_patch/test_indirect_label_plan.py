from d810.backends.ida.native_patch.indirect_label_plan import (
    IndirectLabelPlanBuildError,
    IndirectLabelPlanFailureReason,
    _missing_cref_targets,
)


def test_lossless_recreation_error_carries_exact_item_transition() -> None:
    error = IndirectLabelPlanBuildError(
        "cannot losslessly recreate 'data:6' as 'code:7' at 0x180013eaa",
        reason=IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED,
        ea=0x180013EAA,
        before_shape="data:6",
        after_shape="code:7",
    )

    assert (
        error.reason
        is IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED
    )
    assert error.ea == 0x180013EAA
    assert error.before_shape == "data:6"
    assert error.after_shape == "code:7"
    assert str(error) == (
        "cannot losslessly recreate 'data:6' as 'code:7' at 0x180013eaa"
    )


def test_existing_automatic_flow_edge_satisfies_target_materialization() -> None:
    assert (
        _missing_cref_targets(
            "cref3:0x2000@0x13@a",
            {0x2000},
        )
        == ()
    )


def test_only_genuinely_missing_targets_require_user_edges() -> None:
    assert _missing_cref_targets(
        "cref3:0x2000@0x13@a,0x3000@0x11@u",
        {0x2000, 0x3000, 0x4000, 0x5000},
    ) == (0x4000, 0x5000)
