import json

import pytest

from d810.backends.ida.native_patch.indirect_label_plan import (
    IndirectLabelPlanBuildError,
    IndirectLabelPlanFailureReason,
    _bundle_cref_targets,
    _item_transition_order,
    _missing_cref_targets,
)
from d810.backends.ida.native_patch.metadata import (
    is_reversible_data_item_state,
    reversible_data_item_head,
)


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


def _data_snapshot_v2(
    *,
    ea: int = 0x1000,
    head_ea: int | None = None,
    xrefs: list[dict[str, object]] | None = None,
) -> str:
    if head_ea is None:
        head_ea = ea
    if xrefs is None:
        xrefs = [
            {
                "source_ea": 0x1000,
                "target_ea": 0x3000,
                "xref_type": 0x20,
                "user_owned": False,
                "is_code": False,
            },
            {
                "source_ea": 0x2000,
                "target_ea": 0x1000,
                "xref_type": 0x10,
                "user_owned": True,
                "is_code": True,
            },
        ]
    return "data:v2:" + json.dumps(
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
            "xrefs": xrefs,
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


def test_reversible_data_snapshot_v2_preserves_canonical_xref_witness() -> None:
    token = _data_snapshot_v2()

    assert is_reversible_data_item_state(token)
    assert is_reversible_data_item_state(token, expected_ea=0x1000)
    assert reversible_data_item_head(token) == 0x1000
    assert not is_reversible_data_item_state(token, expected_ea=0x1001)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload["xrefs"][0].pop("xref_type"),
        lambda payload: payload["xrefs"][0].update(extra=True),
        lambda payload: payload["xrefs"][0].update(source_ea=True),
        lambda payload: payload["xrefs"][0].update(target_ea=-1),
        lambda payload: payload["xrefs"][0].update(xref_type=-1),
        lambda payload: payload["xrefs"][0].update(user_owned="true"),
        lambda payload: payload["xrefs"][0].update(is_code=1),
        lambda payload: payload["xrefs"].reverse(),
        lambda payload: payload["xrefs"].append(dict(payload["xrefs"][0])),
        lambda payload: payload.update(ea=0x1001),
        lambda payload: payload.update(head_ea=0x1001),
        lambda payload: payload.update(offset=6),
        lambda payload: payload.update(size=0),
        lambda payload: payload.update(size=7),
    ),
)
def test_reversible_data_snapshot_v2_rejects_noncanonical_payloads(mutate) -> None:
    payload = json.loads(_data_snapshot_v2().removeprefix("data:v2:"))
    mutate(payload)
    token = "data:v2:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))

    assert not is_reversible_data_item_state(token)


@pytest.mark.parametrize(
    "token",
    (
        "data:v2:{",
        _data_snapshot_v2().replace("data:v2:", "data:v2:not-json:", 1),
        "data:1400",
    ),
)
def test_reversible_data_snapshot_v2_rejects_malformed_or_generic_tokens(
    token: str,
) -> None:
    assert not is_reversible_data_item_state(token)


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
