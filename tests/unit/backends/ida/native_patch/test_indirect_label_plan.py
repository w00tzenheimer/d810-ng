import json

import pytest

from d810.backends.ida.native_patch.indirect_label_plan import (
    DecodedClosureBoundaryStop,
    DecodedClosureInstruction,
    DecodedClosureTransfer,
    DecodedClosureTransferKind,
    IndirectLabelPlanBuildError,
    IndirectLabelPlanFailureReason,
    _bundle_cref_targets,
    _item_transition_order,
    _missing_cref_targets,
    _project_group_witnesses,
    _reverse_group_witnesses,
    _bounded_decoded_cfg_closure,
    _extent_is_fully_covered,
)
from d810.backends.ida.native_patch.metadata import (
    _parse_scoped_item_state,
    _predict_decoded_code_xrefs,
    _predict_decoded_lea_data_xrefs,
    is_reversible_data_item_state,
    reversible_data_item_head,
)
from d810.transforms.native_patch_plan import NativeMetadataAction, NativeMetadataActionKind


def _scoped_item_v2(*, item_state: str = "code:4", targets=(0x1000, 0x1002)) -> str:
    origin = _data_snapshot_v2(ea=0x1000, head_ea=0x1000)
    payload = json.loads(origin.removeprefix("data:v2:"))
    return "item-xrefs:v2:" + json.dumps(
        {
            "ea": 0x1000,
            "group_targets": list(targets),
            "head_ea": 0x1000,
            "item_state": item_state,
            "origin_data_state": origin,
            "size": 6,
            "xrefs": payload["xrefs"],
        },
        sort_keys=True,
        separators=(",", ":"),
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
        lambda payload: payload.pop("bytes"),
        lambda payload: payload.pop("ea"),
        lambda payload: payload.pop("flags"),
        lambda payload: payload.pop("full_flags"),
        lambda payload: payload.pop("head_ea"),
        lambda payload: payload.pop("name"),
        lambda payload: payload.pop("offset"),
        lambda payload: payload.pop("size"),
        lambda payload: payload.pop("xrefs"),
        lambda payload: payload.update(extra=True),
        lambda payload: payload["xrefs"][0].pop("xref_type"),
        lambda payload: payload["xrefs"][0].pop("source_ea"),
        lambda payload: payload["xrefs"][0].pop("target_ea"),
        lambda payload: payload["xrefs"][0].pop("user_owned"),
        lambda payload: payload["xrefs"][0].pop("is_code"),
        lambda payload: payload["xrefs"][0].update(extra=True),
        lambda payload: payload["xrefs"].clear(),
        lambda payload: payload.update(ea=True),
        lambda payload: payload.update(flags=True),
        lambda payload: payload.update(head_ea=True),
        lambda payload: payload.update(offset=True),
        lambda payload: payload.update(size=True),
        lambda payload: payload["full_flags"].__setitem__(0, True),
        lambda payload: payload.update(ea=-1),
        lambda payload: payload.update(flags=-1),
        lambda payload: payload.update(head_ea=-1),
        lambda payload: payload.update(offset=-1),
        lambda payload: payload.update(size=-1),
        lambda payload: payload["full_flags"].__setitem__(0, -1),
        lambda payload: payload["xrefs"][0].update(source_ea=True),
        lambda payload: payload["xrefs"][0].update(target_ea=True),
        lambda payload: payload["xrefs"][0].update(xref_type=True),
        lambda payload: payload["xrefs"][0].update(target_ea=-1),
        lambda payload: payload["xrefs"][0].update(xref_type=-1),
        lambda payload: payload["xrefs"][0].update(user_owned=1),
        lambda payload: payload["xrefs"][0].update(is_code=0),
        lambda payload: payload["xrefs"][0].update(source_ea=-1),
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


def test_reversible_data_snapshot_v2_rejects_noncanonical_json() -> None:
    payload = json.loads(_data_snapshot_v2().removeprefix("data:v2:"))

    assert not is_reversible_data_item_state(
        "data:v2:" + json.dumps(payload, indent=2)
    )


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


def _scoped_item(*, item_state: str = "code:4") -> str:
    payload = json.loads(_data_snapshot_v2().removeprefix("data:v2:"))
    return "item-xrefs:v1:" + json.dumps(
        {
            "ea": payload["ea"],
            "head_ea": payload["head_ea"],
            "item_state": item_state,
            "size": payload["size"],
            "xrefs": payload["xrefs"],
        },
        sort_keys=True,
        separators=(",", ":"),
    )


@pytest.mark.parametrize(
    "item_state",
    ("code:4", _data_snapshot_v2()),
)
def test_scoped_item_xref_token_is_canonical_and_scope_bound(item_state: str) -> None:
    token = _scoped_item(item_state=item_state)
    parsed = _parse_scoped_item_state(token, expected_ea=0x1000)

    assert parsed is not None
    assert parsed["head_ea"] == 0x1000
    assert parsed["size"] == 6
    assert parsed["item_state"] == item_state
    assert _parse_scoped_item_state(token, expected_ea=0x1001) is None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.pop("ea"),
        lambda payload: payload.pop("head_ea"),
        lambda payload: payload.pop("item_state"),
        lambda payload: payload.pop("size"),
        lambda payload: payload.pop("xrefs"),
        lambda payload: payload.update(extra=True),
        lambda payload: payload.update(ea=True),
        lambda payload: payload.update(head_ea=True),
        lambda payload: payload.update(size=True),
        lambda payload: payload.update(ea=-1),
        lambda payload: payload.update(head_ea=-1),
        lambda payload: payload.update(size=-1),
        lambda payload: payload.update(size=0),
        lambda payload: payload["xrefs"].clear(),
        lambda payload: payload["xrefs"][0].pop("is_code"),
        lambda payload: payload["xrefs"][0].pop("source_ea"),
        lambda payload: payload["xrefs"][0].pop("target_ea"),
        lambda payload: payload["xrefs"][0].pop("xref_type"),
        lambda payload: payload["xrefs"][0].pop("user_owned"),
        lambda payload: payload["xrefs"][0].update(extra=True),
        lambda payload: payload["xrefs"][0].update(source_ea=True),
        lambda payload: payload["xrefs"][0].update(target_ea=True),
        lambda payload: payload["xrefs"][0].update(xref_type=True),
        lambda payload: payload["xrefs"][0].update(target_ea=-1),
        lambda payload: payload["xrefs"][0].update(xref_type=-1),
        lambda payload: payload["xrefs"][0].update(user_owned="true"),
        lambda payload: payload["xrefs"][0].update(is_code=1),
        lambda payload: payload["xrefs"][0].update(source_ea=-1),
        lambda payload: payload["xrefs"][0].update(user_owned=1),
        lambda payload: payload.update(item_state=123),
        lambda payload: payload["xrefs"].reverse(),
        lambda payload: payload["xrefs"].append(dict(payload["xrefs"][0])),
        lambda payload: payload.update(item_state="data:v2:{}"),
    ),
)
def test_scoped_item_xref_token_rejects_noncanonical_payloads(mutate) -> None:
    payload = json.loads(_scoped_item().removeprefix("item-xrefs:v1:"))
    mutate(payload)
    token = "item-xrefs:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )

    assert _parse_scoped_item_state(token) is None


def test_scoped_item_xref_token_rejects_noncanonical_json_and_inner_scope_drift() -> None:
    payload = json.loads(_scoped_item().removeprefix("item-xrefs:v1:"))
    assert _parse_scoped_item_state(
        "item-xrefs:v1:" + json.dumps(payload, indent=2)
    ) is None
    payload["item_state"] = _data_snapshot_v2(ea=0x1002)
    drifted = "item-xrefs:v1:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )
    assert _parse_scoped_item_state(drifted) is None


def test_scoped_item_unknown_is_not_a_task1_admission_token() -> None:
    assert _parse_scoped_item_state(_scoped_item(item_state="unknown")) is None


def test_scoped_item_v2_preserves_group_provenance_and_allows_member_unknown() -> None:
    token = _scoped_item_v2(item_state="unknown")
    parsed = _parse_scoped_item_state(token, expected_ea=0x1000)

    assert parsed is not None
    assert parsed["origin_data_state"].startswith("data:v2:")
    assert parsed["group_targets"] == (0x1000, 0x1002)

    later = json.loads(token.removeprefix("item-xrefs:v2:"))
    later["ea"] = 0x1002
    later["item_state"] = "unknown"
    later["xrefs"].append(
        {
            "is_code": False,
            "source_ea": 0x1002,
            "target_ea": 0x2000,
            "user_owned": False,
            "xref_type": 0x14,
        }
    )
    later["xrefs"] = sorted(
        later["xrefs"], key=lambda row: (
            row["source_ea"], row["target_ea"], row["xref_type"],
            row["user_owned"], row["is_code"],
        )
    )
    later_token = "item-xrefs:v2:" + json.dumps(
        later, sort_keys=True, separators=(",", ":")
    )
    assert _parse_scoped_item_state(later_token, expected_ea=0x1002) is not None


@pytest.mark.parametrize(
    "mutate",
    (
        lambda payload: payload.update(group_targets=[0x1002, 0x1000]),
        lambda payload: payload.update(group_targets=[]),
        lambda payload: payload.update(origin_data_state=_data_snapshot_v2(ea=0x1002)),
        lambda payload: payload.update(group_targets=[0x1000, 0x2000]),
    ),
)
def test_scoped_item_v2_rejects_mismatched_group_provenance(mutate) -> None:
    payload = json.loads(_scoped_item_v2().removeprefix("item-xrefs:v2:"))
    mutate(payload)
    token = "item-xrefs:v2:" + json.dumps(payload, sort_keys=True, separators=(",", ":"))

    assert _parse_scoped_item_state(token) is None


def test_scoped_item_v2_accepts_singleton_group_provenance() -> None:
    payload = json.loads(_scoped_item_v2().removeprefix("item-xrefs:v2:"))
    payload["group_targets"] = [0x1000]
    token = "item-xrefs:v2:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )

    assert _parse_scoped_item_state(token, expected_ea=0x1000) is not None


@pytest.mark.parametrize(
    ("feature", "operand_type", "target", "expected"),
    (
        (
            0x2,
            0xA,
            0x2000,
            ((0x1000, 0x1004, 0x14, False, True), (0x1000, 0x2000, 0x15, False, True)),
        ),
        (
            0x2,
            0xB,
            0x3000,
            ((0x1000, 0x1004, 0x14, False, True), (0x1000, 0x3000, 0x16, False, True)),
        ),
        (
            0x4 | 0x1,
            0xA,
            0x4000,
            ((0x1000, 0x4000, 0x17, False, True),),
        ),
        (
            0x4 | 0x1,
            0xB,
            0x5000,
            ((0x1000, 0x5000, 0x18, False, True),),
        ),
        (
            0x4,
            0xA,
            0x6000,
            ((0x1000, 0x1004, 0x14, False, True), (0x1000, 0x6000, 0x17, False, True)),
        ),
        (0x2, 0xC, 0x7000, ((0x1000, 0x1004, 0x14, False, True),)),
        (0x4 | 0x1, 0xC, 0x8000, ()),
    ),
)
def test_decoded_code_xref_effect_matrix(
    feature: int,
    operand_type: int,
    target: int,
    expected: tuple[tuple[int, int, int, bool, bool], ...],
) -> None:
    assert _predict_decoded_code_xrefs(
        0x1000,
        4,
        feature,
        operand_type,
        target,
        cf_stop=0x1,
        cf_call=0x2,
        cf_jump=0x4,
        o_near=0xA,
        o_far=0xB,
        badaddr=-1,
        fl_f=0x14,
        fl_cn=0x15,
        fl_cf=0x16,
        fl_jn=0x17,
        fl_jf=0x18,
    ) == expected


@pytest.mark.parametrize(
    "mutate",
    (
        lambda values: values.update(processor=2),
        lambda values: values.update(mnemonic=2),
        lambda values: values.update(operand_type=3),  # o_displ
        lambda values: values.update(operand_type=4),  # o_phrase
        lambda values: values.update(operand_type=5),  # o_imm
        lambda values: values.update(operand_segment=4),
        lambda values: values.update(operand_offb=0),
        lambda values: values.update(mapped_data_ea=-1),
        lambda values: values.update(mapped_data_loaded=False),
    ),
)
def test_decoded_lea_data_effect_fails_closed_for_unproved_shapes(mutate) -> None:
    values = {
        "processor": 1,
        "x86_processor": 1,
        "mnemonic": 92,
        "lea_mnemonic": 92,
        "operand_type": 2,
        "mem_operand": 2,
        "operand_segment": 30,
        "cs_register": 30,
        "operand_offb": 3,
        "mapped_data_ea": 0x180061E6E,
        "mapped_data_loaded": True,
        "badaddr": -1,
        "dr_o": 1,
    }
    mutate(values)

    assert _predict_decoded_lea_data_xrefs(0x180016E6A, **values) == ()


def test_decoded_lea_data_effect_predicts_only_proven_auto_data_row() -> None:
    assert _predict_decoded_lea_data_xrefs(
        0x180016E6A,
        processor=1,
        x86_processor=1,
        mnemonic=92,
        lea_mnemonic=92,
        operand_type=2,
        mem_operand=2,
        operand_segment=30,
        cs_register=30,
        operand_offb=3,
        mapped_data_ea=0x180061E6E,
        mapped_data_loaded=True,
        badaddr=-1,
        dr_o=1,
    ) == ((0x180016E6A, 0x180061E6E, 1, False, False),)


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


def _replay_fixture() -> tuple[
    list[NativeMetadataAction],
    dict[int, tuple[tuple[int, int, int, bool, bool], ...]],
    dict[int, tuple[int, int, tuple[tuple[int, int, int, bool, bool], ...]]],
]:
    low, high = 0x2006, 0x2016
    origin = tuple((low + index, low + index + 1, 0x15, False, True) for index in range(5))
    actions = [
        NativeMetadataAction(NativeMetadataActionKind.RECREATE_ITEM, 0x200E, "data", "code")
        for _ in range(5)
    ]
    actions.extend(
        (
            NativeMetadataAction(NativeMetadataActionKind.RECREATE_ITEM, 0x2000, "data", "code"),
            NativeMetadataAction(NativeMetadataActionKind.UPDATE_XREF, 0x3000, "before", "after"),
            NativeMetadataAction(NativeMetadataActionKind.RECREATE_ITEM, 0x200E, "seal", "seal"),
        )
    )
    boundary = (0x2000, low + 1, 0x15, False, True)
    user = (0x3000, low + 2, 0x13, True, True)
    effects = {
        index: ((low + 8 + index, low + 9 + index, 0x15, False, True),)
        for index in range(5)
    }
    effects[5] = (boundary,)
    effects[6] = (user,)
    effects[7] = ()
    return actions, effects, {low: (low, high, origin)}


def test_group_witness_replay_routes_adjacent_effect_in_global_order() -> None:
    actions, effects, groups = _replay_fixture()

    projected = _project_group_witnesses(actions, effects, groups)
    boundary = (0x2000, 0x2007, 0x15, False, True)
    user = (0x3000, 0x2008, 0x13, True, True)

    for index in range(5):
        assert boundary not in projected[index][0x2006][1]
    assert boundary in projected[5][0x2006][1]
    assert user in projected[6][0x2006][1]
    assert len(projected[7][0x2006][1]) == 12

    reversed_projection = _reverse_group_witnesses(actions, effects, groups)
    assert boundary in reversed_projection[5][0x2006][1]
    assert boundary not in reversed_projection[5][0x2006][0]
    assert reversed_projection[0][0x2006][0] == groups[0x2006][2]


def test_group_witness_replay_rejects_preexisting_predicted_row() -> None:
    actions, effects, groups = _replay_fixture()
    low, high, origin = groups[0x2006]
    boundary = effects[5][0]
    groups[0x2006] = (low, high, origin + (boundary,))

    with pytest.raises(IndirectLabelPlanBuildError, match="already exists"):
        _project_group_witnesses(actions, effects, groups)


def test_group_witness_replay_does_not_fabricate_non_touching_effects() -> None:
    actions, effects, groups = _replay_fixture()
    effects[5] = ((0x3000, 0x4000, 0x15, False, True),)

    projected = _project_group_witnesses(actions, effects, groups)
    assert projected[5][0x2006][0] == projected[5][0x2006][1]


def test_bounded_closure_follows_only_authorized_in_range_successors() -> None:
    def rows(source: int, target: int) -> tuple[int, int, int, bool, bool]:
        return (source, target, 0x15, False, True)
    graph = {
        0x1000: DecodedClosureInstruction(
            ea=0x1000,
            size=2,
            effects=(rows(0x1000, 0x1002),),
            control_edges=((0x1002, "fallthrough", True),),
        ),
        0x1002: DecodedClosureInstruction(
            ea=0x1002,
            size=2,
            effects=(rows(0x1002, 0x1004),),
            control_edges=((0x1004, "fallthrough", True),),
        ),
        0x1004: DecodedClosureInstruction(
            ea=0x1004,
            size=2,
            effects=(rows(0x1004, 0x2000),),
            control_edges=((0x2000, "direct_near", True),),
        ),
    }

    result = _bounded_decoded_cfg_closure(
        group_low=0x1000,
        group_high=0x1006,
        roots=(0x1000,),
        decode=graph.__getitem__,
    )

    assert result.items == ((0x1000, 2), (0x1002, 2), (0x1004, 2))
    assert result.xrefs == (
        rows(0x1000, 0x1002),
        rows(0x1002, 0x1004),
        rows(0x1004, 0x2000),
    )
    assert result.roots == (0x1000,)


def test_bounded_closure_seeds_authorized_external_source_by_in_range_target() -> None:
    row = (0x0F00, 0x1000, 0x19, False, True)
    graph = {
        0x1000: DecodedClosureInstruction(
            ea=0x1000,
            size=2,
            effects=((0x1000, 0x1002, 0x15, False, True),),
            control_edges=((0x1002, "fallthrough", True),),
        ),
        0x1002: DecodedClosureInstruction(
            ea=0x1002,
            size=2,
            effects=((0x1002, 0x2000, 0x19, False, True),),
            control_edges=((0x2000, "direct_near", True),),
        ),
    }

    result = _bounded_decoded_cfg_closure(
        group_low=0x1000,
        group_high=0x1004,
        roots=(0x1000,),
        decode=graph.__getitem__,
        seed_effects=(row,),
    )

    assert result.roots == (0x1000,)
    assert row in result.xrefs


def test_decoded_unconditional_near_transfer_is_classified_without_cf_jump() -> None:
    assert _predict_decoded_code_xrefs(
        0x1000,
        2,
        0x01,  # CF_STOP without CF_JUMP
        1,  # o_near
        0x2000,
        cf_stop=0x01,
        cf_call=0x02,
        cf_jump=0x04,
        o_near=1,
        o_far=2,
        badaddr=-1,
        fl_f=0x15,
        fl_cn=0x13,
        fl_cf=0x14,
        fl_jn=0x19,
        fl_jf=0x16,
    ) == ((0x1000, 0x2000, 0x19, False, True),)


def test_decoded_conditional_near_transfer_retains_fallthrough_and_direct_edge() -> None:
    assert _predict_decoded_code_xrefs(
        0x1000,
        2,
        0x00,
        0xA,
        0x2000,
        cf_stop=0x01,
        cf_call=0x02,
        cf_jump=0x04,
        o_near=0xA,
        o_far=0xB,
        badaddr=-1,
        fl_f=0x15,
        fl_cn=0x13,
        fl_cf=0x14,
        fl_jn=0x19,
        fl_jf=0x16,
        conditional_near=True,
    ) == (
        (0x1000, 0x1002, 0x15, False, True),
        (0x1000, 0x2000, 0x19, False, True),
    )


@pytest.mark.parametrize(
    "kind",
    (
        DecodedClosureTransferKind.CALL,
        DecodedClosureTransferKind.FAR,
        DecodedClosureTransferKind.INDIRECT,
    ),
)
def test_bounded_closure_rejects_unproved_transfer_classes(kind) -> None:
    graph = {
        0x1000: DecodedClosureInstruction(
            0x1000,
            2,
            ((0x1000, 0x2000, 0x15, False, True),),
            (DecodedClosureTransfer(0x2000, kind, True, "test-unproved"),),
        )
    }
    with pytest.raises(IndirectLabelPlanBuildError, match="direct provenance"):
        _bounded_decoded_cfg_closure(
            group_low=0x1000,
            group_high=0x1002,
            roots=(0x1000,),
            decode=graph.__getitem__,
        )


def test_boundary_stop_rejects_effect_without_proven_fallthrough() -> None:
    graph = {
        0x1000: DecodedClosureBoundaryStop(
            0x1000,
            ((0x1000, 0x1002, 0x15, False, True),),
            (DecodedClosureTransfer(
                0x1002,
                DecodedClosureTransferKind.DIRECT_NEAR,
                True,
                "test-effect-bearing-boundary",
            ),),
        )
    }
    with pytest.raises(IndirectLabelPlanBuildError, match="boundary"):
        _bounded_decoded_cfg_closure(
            group_low=0x1000,
            group_high=0x1002,
            roots=(0x1000,),
            decode=graph.__getitem__,
        )


def test_bounded_closure_accepts_proven_unknown_suffix_destruction_extent() -> None:
    """A transient crossing may consume only an exact loaded UNKNOWN suffix."""
    graph = {
        0x1000: DecodedClosureInstruction(
            0x1000,
            6,
            ((0x1000, 0x1006, 0x15, False, True),),
            (DecodedClosureTransfer(
                0x1006,
                DecodedClosureTransferKind.FALLTHROUGH,
                True,
                "ida-loaded-unknown-suffix",
            ),),
            (0x1000, 0x1006),
        )
    }

    result = _bounded_decoded_cfg_closure(
        group_low=0x1000,
        group_high=0x1004,
        roots=(0x1000,),
        decode=graph.__getitem__,
    )

    assert result.items == ((0x1000, 6),)
    assert result.xrefs == ((0x1000, 0x1006, 0x15, False, True),)


@pytest.mark.parametrize(
    ("extents", "expected"),
    (
        (((0x1000, 0x1010),), True),
        (((0x1000, 0x1008), (0x1008, 0x1010)), True),
        (((0x1000, 0x1008), (0x1009, 0x1010)), False),
        (((0x0FF0, 0x1010),), True),
    ),
)
def test_crossing_extent_requires_complete_planned_clear_partition(extents, expected):
    assert _extent_is_fully_covered(0x1000, 0x1010, extents) is expected


@pytest.mark.parametrize(
    "mutate",
    (
        lambda graph: graph.update(
            {
                0x1000: DecodedClosureInstruction(
                    0x1000, 2, ((0x1000, 0x1001, 0x15, False, True),),
                    ((0x1001, "fallthrough", True),),
                )
            }
        ),
        lambda graph: graph.update(
            {
                0x1000: DecodedClosureInstruction(
                        0x1000, 3, ((0x1000, 0x1002, 0x15, False, True),),
                        ((0x1002, "fallthrough", True),),
                )
            }
        ),
        lambda graph: graph.update({0x1000: None}),
        lambda graph: graph.update(
            {
                0x1000: DecodedClosureInstruction(
                    0x1000, 2, ((0x1000, 0x1003, 0x15, False, True),),
                    ((0x1003, "fallthrough", True),),
                )
            }
        ),
    ),
)
def test_bounded_closure_fails_closed_for_invalid_decode_or_target(mutate) -> None:
    graph = {
        0x1000: DecodedClosureInstruction(
            0x1000, 2, ((0x1000, 0x1002, 0x15, False, True),),
            ((0x1002, "fallthrough", True),),
        ),
        0x1002: DecodedClosureInstruction(0x1002, 2, (), ()),
    }
    mutate(graph)

    with pytest.raises(IndirectLabelPlanBuildError):
        _bounded_decoded_cfg_closure(
            group_low=0x1000,
            group_high=0x1004,
            roots=(0x1000,),
            decode=graph.__getitem__,
        )
