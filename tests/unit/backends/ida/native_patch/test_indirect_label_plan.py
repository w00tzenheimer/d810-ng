import json

from d810.backends.ida.native_patch.indirect_label_plan import (
    IndirectLabelPlanBuildError,
    IndirectLabelPlanFailureReason,
    _bundle_cref_targets,
    _item_transition_order,
    _missing_cref_targets,
)
from d810.backends.ida.native_patch.metadata import is_reversible_data_item_state


def _data_snapshot(*, ea: int = 0x1000, head_ea: int | None = None) -> str:
    if head_ea is None:
        head_ea = ea
    return "data:v1:" + json.dumps(
        {
            "bytes": "488d0dba3401",
            "ea": ea,
            "flags": 0x10009400,
            "full_flags": [
                0x10009548,
                0x10038D,
                0x20030D,
                0x3003BA,
                0x200334,
                0x500301,
            ],
            "head_ea": head_ea,
            "name": "",
            "offset": ea - head_ea,
            "size": 6,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def test_reversible_data_snapshot_is_complete_and_address_bound() -> None:
    token = _data_snapshot()

    assert is_reversible_data_item_state(token)
    assert is_reversible_data_item_state(token, expected_ea=0x1000)
    assert not is_reversible_data_item_state(token, expected_ea=0x1001)
    assert not is_reversible_data_item_state("data:6")
    assert not is_reversible_data_item_state(token.removesuffix("}"))


def test_shared_data_item_groups_later_targets_as_unknown() -> None:
    from d810.backends.ida.native_patch.indirect_label_plan import (
        _group_item_transition_before,
    )

    seen: set[int] = set()
    first = _data_snapshot(ea=0x1000, head_ea=0x1000)
    second = _data_snapshot(ea=0x1002, head_ea=0x1000)

    assert (
        _group_item_transition_before(
            first, target_ea=0x1000, seen_data_heads=seen
        )
        == first
    )
    assert (
        _group_item_transition_before(
            second, target_ea=0x1002, seen_data_heads=seen
        )
        == "unknown"
    )


def test_item_transitions_promote_highest_target_first_for_overlap_safety() -> None:
    """A lower instruction can consume the next data item's first byte."""

    assert _item_transition_order((0x1800169AA, 0x1800169DE, 0x180016A06)) == (
        0x180016A06,
        0x1800169DE,
        0x1800169AA,
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


def test_function_tail_adoption_error_has_stable_reason() -> None:
    error = IndirectLabelPlanBuildError(
        "function-tail adoption is not yet proven losslessly reversible",
        reason=IndirectLabelPlanFailureReason.FUNCTION_TAIL_ADOPTION_UNSUPPORTED,
    )

    assert (
        error.reason
        is IndirectLabelPlanFailureReason.FUNCTION_TAIL_ADOPTION_UNSUPPORTED
    )
    assert error.ea is None
    assert error.before_shape is None
    assert error.after_shape is None


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


def test_cref_targets_share_one_exact_after_token() -> None:
    after, missing = _bundle_cref_targets(
        "cref3:0x2000@0x13@a",
        {0x3000, 0x4000},
        xref_type=0x13,
    )

    assert missing == (0x3000, 0x4000)
    assert after == (
        "cref3:0x2000@0x13@a,0x3000@0x13@u,0x4000@0x13@u"
    )
