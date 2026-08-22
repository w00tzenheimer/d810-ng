"""Focused tests for the strict legacy compatibility codec."""

from __future__ import annotations

import hashlib
import importlib
import inspect

import pytest

from d810.ir.flowgraph import BlockKind, BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot
from d810.transforms.cfg_transaction import LogicalBlockRef
from d810.transforms.plan import PatchPlan

from d810.transforms.unflatten_authority.model import (
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
from d810.transforms.unflatten_authority.proposal import LEGACY_UNFLATTEN_KEYS
from d810.transforms.unflatten_authority.legacy_keys import EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA


def _codec():
    return importlib.import_module("d810.transforms.unflatten_authority.legacy_codec")


def _metadata():
    values = {
        key: {"nested": [key, (1, 2)], "scalar": 3}
        for key in LEGACY_UNFLATTEN_KEYS
    }
    return (("ordinary", ["keep", ("shape",)]), *values.items())


def _shadow_plan(metadata):
    codec = _codec()
    cleaned, shadow = codec.capture_legacy_unflatten_shadow(
        plan_id="plan", snapshot_id="snapshot", source_generation=3,
        metadata=metadata,
    )
    plan = PatchPlan(
        plan_id="plan", snapshot_id="snapshot", source_generation=3,
        metadata=cleaned,
    )
    object.__setattr__(plan, "legacy_unflatten_shadow", shadow)
    return plan, shadow


def _decode_context(codec, *, evidence=None, generation=3, ref=None):
    source = FlowGraph(
        {0: BlockSnapshot(
            0, 0, (), (), 0, 0x1000,
            (InsnSnapshot(0, 0x1000, (), kind=InsnKind.RET, native_ea=0x1000),),
            kind=BlockKind.STOP,
        )},
        0,
        0x1000,
    )
    return codec.LegacyUnflattenDecodeContext(
        "plan", source, generation,
        ((0, ref or LogicalBlockRef("legacy", "b0", 1)),), evidence,
    )


def test_shadow_envelope_replays_each_payload_byte_for_byte() -> None:
    """Replay preserves every nested container shape and exact wire bytes."""

    codec = _codec()
    assert callable(codec.capture_legacy_unflatten_shadow)
    assert callable(codec.replay_legacy_unflatten_shadow)
    ordinary = (("ordinary", ["keep", ("shape",)]),)
    cleaned, shadow = codec.capture_legacy_unflatten_shadow(
        plan_id="plan", snapshot_id="snapshot", source_generation=3,
        metadata=(*ordinary, ("dispatcher_corridor_coverage", {"x": [1, (2,)]})),
    )
    assert cleaned == ordinary
    plan = PatchPlan(
        plan_id="plan", snapshot_id="snapshot", source_generation=3,
        metadata=cleaned,
    )
    object.__setattr__(plan, "legacy_unflatten_shadow", shadow)
    view = codec.replay_legacy_unflatten_shadow(plan)
    assert dict(view.metadata)["dispatcher_corridor_coverage"] == {
        "x": [1, (2,)]
    }
    assert dict(view.metadata)["ordinary"] == ["keep", ("shape",)]
    assert view.metadata_value("dispatcher_corridor_coverage") == {"x": [1, (2,)]}
    assert view.metadata_dict()["ordinary"] == ["keep", ("shape",)]
    assert view.steps == plan.steps
    assert shadow.entries[0].canonical_payload == codec.legacy_canonical_bytes(
        {"x": [1, (2,)]}
    )


def test_capture_pins_all_current_reserved_keys_and_preserves_ordinary_pairs() -> None:
    codec = _codec()
    cleaned, shadow = codec.capture_legacy_unflatten_shadow(
        plan_id="plan", snapshot_id="snapshot", source_generation=3,
        metadata=_metadata(),
    )
    assert cleaned == (("ordinary", ["keep", ("shape",)]),)
    assert shadow is not None
    assert tuple(entry.key for entry in shadow.entries) == tuple(sorted(LEGACY_UNFLATTEN_KEYS))
    assert all(
        entry.payload_sha256 == hashlib.sha256(entry.canonical_payload).hexdigest()
        for entry in shadow.entries
    )


def test_capture_rejects_duplicate_reserved_and_hostile_values() -> None:
    codec = _codec()
    with pytest.raises(ValueError, match="more than once"):
        codec.capture_legacy_unflatten_shadow(
            plan_id="plan", snapshot_id="snapshot", source_generation=0,
            metadata=(("use_def_severance_audit", 1), ("use_def_severance_audit", 2)),
        )
    with pytest.raises(TypeError, match="exact str"):
        codec.capture_legacy_unflatten_shadow(
            plan_id="plan", snapshot_id="snapshot", source_generation=0,
            metadata=((type("Alias", (str,), {})("use_def_severance_audit"), 1),),
        )
    with pytest.raises(TypeError):
        codec.capture_legacy_unflatten_shadow(
            plan_id="plan", snapshot_id="snapshot", source_generation=0,
            metadata=(("use_def_severance_audit", object()),),
        )


def test_capture_accepts_patchplan_one_shot_metadata_and_rejects_mapping_subclass_value() -> None:
    codec = _codec()
    one_shot = iter((
        ("ordinary", ["kept", (1,)]),
        ("dispatcher_corridor_coverage", {"ok": True}),
    ))
    cleaned, shadow = codec.capture_legacy_unflatten_shadow(
        plan_id="plan", snapshot_id="snapshot", source_generation=0,
        metadata=one_shot,
    )
    assert cleaned == (("ordinary", ["kept", (1,)]),)
    assert shadow is not None

    class MappingDict(dict):
        pass

    with pytest.raises(TypeError):
        codec.capture_legacy_unflatten_shadow(
            plan_id="plan", snapshot_id="snapshot", source_generation=0,
            metadata=(("dispatcher_corridor_coverage", MappingDict(ok=True)),),
        )


def test_replay_rejects_payload_digest_identity_and_noncanonical_wire_tampering() -> None:
    codec = _codec()
    plan, shadow = _shadow_plan(
        (("dispatcher_corridor_coverage", {"nested": [1, (2,)]}),)
    )
    assert shadow is not None
    original = shadow.entries[0].canonical_payload
    tampered = bytearray(original)
    tampered[-2] = ord("3") if tampered[-2] != ord("3") else ord("4")
    object.__setattr__(shadow.entries[0], "canonical_payload", bytes(tampered))
    with pytest.raises(ValueError):
        codec.replay_legacy_unflatten_shadow(plan)
    object.__setattr__(shadow.entries[0], "canonical_payload", original)
    object.__setattr__(shadow.entries[0], "payload_sha256", "0" * 64)
    with pytest.raises(ValueError):
        codec.replay_legacy_unflatten_shadow(plan)

    object.__setattr__(shadow.entries[0], "payload_sha256", hashlib.sha256(original).hexdigest())
    object.__setattr__(shadow, "plan_id", "other")
    with pytest.raises(ValueError, match="plan_id"):
        codec.replay_legacy_unflatten_shadow(plan)


def test_decode_is_absent_without_reserved_and_requires_route_evidence() -> None:
    codec = _codec()
    context = _decode_context(codec)
    absent = codec.decode_legacy_unflatten_contract((("ordinary", 1),), context=context)
    assert absent.route is UnflattenPlanRoute.ORDINARY
    missing = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"value": [1, (2,)]}),), context=context
    )
    assert missing.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING


def test_missing_route_precedes_reserved_duplicate_and_malformed_details() -> None:
    codec = _codec()
    context = _decode_context(codec)
    result = codec.decode_legacy_unflatten_contract(
        (
            ("dispatcher_corridor_coverage", {"serial": 7}),
            ("dispatcher_corridor_coverage", {"generation": "stale"}),
            ("unknown_authority_receipt", object()),
        ),
        context=context,
    )
    assert result.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING
    assert result.detail_code == "legacy_route_evidence_missing"


def test_hostile_nested_mapping_is_typed_rejection() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef

    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)

    class HostileMapping(dict):
        def __iter__(self):
            raise RuntimeError("hostile")

        def items(self):
            raise RuntimeError("hostile")

    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", HostileMapping()),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.detail_code == "legacy_payload_shape_invalid"


def test_decode_rejects_strict_shape_failures_and_defers_known_families() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    from d810.transforms.cfg_transaction import NativeBlockRef
    context = _decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity))
    serial = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"serial": 7}),), context=context
    )
    assert serial.detail_code == "legacy_serial_requires_ea"
    stale = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"generation": 9}),), context=context
    )
    assert stale.detail_code == "legacy_source_generation_mismatch"
    deferred = codec.decode_legacy_unflatten_contract(
        (("exact_state_branch_effect_exclusions", {"value": [1, (2,)]}),),
        context=context,
    )
    assert deferred.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
    assert deferred.detail_code == "legacy_exact_effect_not_enabled"


def test_exact_decode_context_accepts_only_owned_typed_inputs() -> None:
    codec = _codec()
    fields = set(inspect.signature(codec.LegacyUnflattenDecodeContext).parameters)
    assert {"plan_inputs", "use_def_witness"} <= fields
    assert not {
        "dispatcher_entry_serial", "dispatcher_member_serials",
        "authoritative_handler_serials", "redirect_digest",
    } & fields
    with pytest.raises(TypeError):
        codec.LegacyUnflattenDecodeContext(
            "plan", _decode_context(codec).source, 3,
            ((0, LogicalBlockRef("legacy", "b0", 1)),), None,
            dispatcher_entry_serial=0,
        )


def test_exact_legacy_decode_roundtrips_through_the_producer_builder() -> None:
    from dataclasses import replace
    from .test_bind import _exact_fixture
    source, proposal, exclusion, refs = _exact_fixture()
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )
    payload = ((EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (exclusion.to_metadata(),)),)
    decoded = _codec().decode_legacy_unflatten_contract(payload, context=context)
    assert decoded.route is UnflattenPlanRoute.LEGACY_ADAPTED
    assert decoded.proposal is not None
    assert decoded.proposal.claims == proposal.claims
    assert decoded.proposal.plan_inputs == proposal.plan_inputs
    assert _codec().decode_legacy_value(_codec().encode_legacy_value(payload)) == payload
    foreign_ref = LogicalBlockRef("foreign", "b9", 9)
    foreign = replace(
        proposal.plan_inputs, dispatcher_entry_ref=foreign_ref,
        dispatcher_member_refs=(foreign_ref, *proposal.plan_inputs.dispatcher_member_refs[1:]),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, foreign, proposal.use_def_witness,
        )
    substituted_handler = replace(
        proposal.plan_inputs,
        authoritative_handlers=(replace(
            proposal.plan_inputs.authoritative_handlers[0], block_ref=foreign_ref,
        ),),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, substituted_handler, proposal.use_def_witness,
        )
    with pytest.raises(TypeError, match="use-def witness"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, proposal.plan_inputs, None,
        )
    with pytest.raises(ValueError, match="incomplete"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, None, proposal.use_def_witness,
        )
    foreign_owner = replace(
        proposal.use_def_witness,
        redirect_owner_refs=(LogicalBlockRef("foreign", "owner", 11),),
    )
    with pytest.raises(ValueError, match="foreign ref"):
        _codec().LegacyUnflattenDecodeContext(
            proposal.plan_id, source, 1, tuple(sorted(refs.items())),
            proposal.route_evidence, proposal.plan_inputs, foreign_owner,
        )
    mutated = replace(
        proposal.use_def_witness,
        state_identity=type(proposal.plan_inputs.state_identity)(
            proposal.plan_inputs.state_identity.kind,
            proposal.plan_inputs.state_identity.offset + 1,
        ),
    )
    mutated_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, mutated,
    )
    rejected = _codec().decode_legacy_unflatten_contract(payload, context=mutated_context)
    assert rejected.detail_code == "legacy_exact_effect_payload_invalid"
    from d810.transforms.unflatten_authority import model
    shape_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, replace(
            proposal.plan_inputs, shape=model.UnflattenPlanShape.PARTIAL_REWRITE,
        ), proposal.use_def_witness,
    )
    assert _codec().decode_legacy_unflatten_contract(
        payload, context=shape_context,
    ).detail_code == "legacy_exact_effect_payload_invalid"
    handler = proposal.plan_inputs.authoritative_handlers[0]
    handler_context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, replace(
            proposal.plan_inputs,
            authoritative_handlers=(replace(handler, normalized_states=(99,)),),
        ), proposal.use_def_witness,
    )
    assert _codec().decode_legacy_unflatten_contract(
        payload, context=handler_context,
    ).detail_code == "legacy_exact_effect_payload_invalid"


def test_exact_raw_codec_rejects_lossy_scalar_and_shape_coercions() -> None:
    from .test_bind import _exact_fixture

    codec = _codec()
    _source, _proposal, exclusion, _refs = _exact_fixture()
    base = exclusion.to_metadata()

    class IntSubclass(int):
        pass

    for value in (0.9, +0.9, True, "7", IntSubclass(7)):
        payload = dict(base)
        payload["normalized_state"] = value
        assert codec.exact_state_branch_effect_exclusion_from_metadata(payload) is None

    nested = dict(base)
    nested["source"] = list(base["source"].items())
    assert codec.exact_state_branch_effect_exclusion_from_metadata(nested) is None


def test_exact_legacy_decode_rejects_mixed_reserved_families() -> None:
    from .test_bind import _exact_fixture

    source, proposal, exclusion, refs = _exact_fixture()
    context = _codec().LegacyUnflattenDecodeContext(
        proposal.plan_id, source, 1, tuple(sorted(refs.items())),
        proposal.route_evidence, proposal.plan_inputs, proposal.use_def_witness,
    )
    payload = (
        (EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA, (exclusion.to_metadata(),)),
        ("dispatcher_corridor_coverage", {"serial": 1, "ea": 0x1000}),
    )
    rejected = _codec().decode_legacy_unflatten_contract(payload, context=context)
    assert rejected.detail_code == "legacy_exact_effect_mixed_reserved_families"


def test_r2_requires_dedicated_lossless_wire_and_neutral_key_owner() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    keys = importlib.import_module("d810.transforms.unflatten_authority.legacy_keys")
    value = {"nested": [1, (2, -0.0)], "text": "cafe"}
    encoded = wire.encode_legacy_value(value)
    assert wire.decode_legacy_value(encoded) == value
    assert keys.LEGACY_UNFLATTEN_KEYS == LEGACY_UNFLATTEN_KEYS


def test_shadow_view_metadata_is_explicit_and_wire_revalidation_is_required() -> None:
    codec = _codec()
    assert isinstance(codec.LegacyShadowPlanView.metadata, property)


@pytest.mark.parametrize(
    "value",
    [None, False, True, 0, -1, 2**130, -2**130, -0.0, 1.25, "utf-8 cafe", b"raw", [], (),
     {"a": [1, (2,)]}],
)
def test_legacy_wire_roundtrips_closed_values(value) -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    encoded = wire.encode_legacy_value(value)
    decoded = wire.decode_legacy_value(encoded)
    if isinstance(value, float) and value != value:
        assert decoded != decoded
    else:
        assert decoded == value
    assert wire.encode_legacy_value(decoded) == encoded


def test_legacy_wire_preserves_float_bits_container_shapes_and_dict_order() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    import struct

    negative_zero = struct.unpack(">d", bytes.fromhex("8000000000000000"))[0]
    nan_bits = bytes.fromhex("7ff8000000000042")
    nan_value = struct.unpack(">d", nan_bits)[0]
    first = {"a": [negative_zero, (nan_value,)]}
    second = {"b": 1, "a": 2}
    reversed_second = {"a": 2, "b": 1}
    first_wire = wire.encode_legacy_value(first)
    assert wire.encode_legacy_value(wire.decode_legacy_value(first_wire)) == first_wire
    decoded_nan = wire.decode_legacy_value(first_wire)["a"][1][0]
    assert struct.pack(">d", decoded_nan) == nan_bits
    assert wire.encode_legacy_value(second) != wire.encode_legacy_value(reversed_second)


def test_legacy_wire_rejects_subclasses_cycles_and_mutated_framing() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")

    class IntSubclass(int):
        pass

    class DictSubclass(dict):
        pass

    with pytest.raises(TypeError):
        wire.encode_legacy_value(IntSubclass(1))
    with pytest.raises(TypeError):
        wire.encode_legacy_value(DictSubclass(a=1))
    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(ValueError):
        wire.encode_legacy_value(cyclic)

    encoded = wire.encode_legacy_value([1])
    for mutated in (encoded + b"\x00", encoded[:-1], bytes((0x7F,))):
        with pytest.raises((TypeError, ValueError)):
            wire.decode_legacy_value(mutated)


def test_legacy_wire_rejects_nonminimal_integer_and_length_encodings() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    # int(1) with a two-byte magnitude length, and list count encoded as 0x80 0x00.
    with pytest.raises(ValueError):
        wire.decode_legacy_value(bytes((2, 0, 2, 0, 1)))
    with pytest.raises(ValueError):
        wire.decode_legacy_value(bytes((6, 0x80, 0x00)))


def test_legacy_wire_enforces_documented_depth_limit() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    limit = wire.MAX_LEGACY_WIRE_DEPTH

    def nested(depth):
        value = 0
        for _ in range(depth):
            value = [value]
        return value

    assert wire.decode_legacy_value(wire.encode_legacy_value(nested(limit))) == nested(limit)
    with pytest.raises(ValueError):
        wire.encode_legacy_value(nested(limit + 1))
    with pytest.raises(ValueError):
        wire.decode_legacy_value(b"\x06\x01" + wire.encode_legacy_value(nested(limit)))


def test_legacy_wire_rejects_shared_mutable_identity() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    shared_list = [1]
    shared_dict = {"value": 1}
    with pytest.raises(ValueError):
        wire.encode_legacy_value([shared_list, shared_list])
    with pytest.raises(ValueError):
        wire.encode_legacy_value({"a": shared_dict, "b": [shared_dict]})


def test_legacy_wire_roundtrips_lone_surrogates_with_surrogatepass() -> None:
    wire = importlib.import_module("d810.transforms.unflatten_authority.legacy_wire")
    for value in ("\ud800", "\udfff", "ok-\ud800-\udfff"):
        encoded = wire.encode_legacy_value(value)
        assert wire.decode_legacy_value(encoded) == value


def test_shadow_envelope_requires_exact_identifier_and_generation_primitives() -> None:
    from d810.transforms.unflatten_authority.legacy_wire import encode_legacy_value
    from d810.transforms.unflatten_authority.model import (
        LegacyShadowEntry,
        LegacyUnflattenShadowEnvelope,
    )

    payload = encode_legacy_value(1)
    entry = LegacyShadowEntry(
        "dispatcher_corridor_coverage", payload, hashlib.sha256(payload).hexdigest()
    )

    class TextSubclass(str):
        pass

    for plan_id, snapshot_id, generation in (
        (TextSubclass("plan"), "snapshot", 1),
        ("plan", TextSubclass("snapshot"), 1),
        ("plan", "snapshot", True),
    ):
        with pytest.raises((TypeError, ValueError)):
            LegacyUnflattenShadowEnvelope(1, plan_id, snapshot_id, generation, (entry,))


def test_family_detail_registry_is_immutable_and_complete() -> None:
    keys = importlib.import_module("d810.transforms.unflatten_authority.legacy_keys")
    assert set(keys.LEGACY_FAMILY_DETAIL_CODES) == set(keys.LEGACY_UNFLATTEN_KEYS)
    with pytest.raises(TypeError):
        keys.LEGACY_FAMILY_DETAIL_CODES["new"] = "bad"


def test_context_rejects_bool_source_block_serial() -> None:
    codec = _codec()
    source = FlowGraph(
        {0: BlockSnapshot(
            True, 0, (), (), 0, 0x1000,
            (InsnSnapshot(0, 0x1000, (), kind=InsnKind.RET, native_ea=0x1000),),
            kind=BlockKind.STOP,
        )},
        0,
        0x1000,
    )
    with pytest.raises((TypeError, ValueError)):
        codec.LegacyUnflattenDecodeContext(
            "plan", source, 3,
            ((0, LogicalBlockRef("legacy", "b0", 1)),), None,
        )


def test_shadow_view_hides_transport_and_revalidates_metadata_on_access() -> None:
    codec = _codec()
    plan, shadow = _shadow_plan((
        ("dispatcher_corridor_coverage", {"nested": [1, (2,)]}),
    ))
    view = codec.replay_legacy_unflatten_shadow(plan)
    with pytest.raises(AttributeError):
        _ = view.legacy_unflatten_shadow

    class KeySubclass(str):
        pass

    object.__setattr__(view, "replay_metadata", ((KeySubclass("ordinary"), 1),))
    with pytest.raises((TypeError, ValueError)):
        _ = view.metadata


def test_deep_route_validation_is_typed_rejection() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef

    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    value = 0
    for _ in range(1500):
        value = [value]
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", value),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL


def test_decode_revalidates_mutated_context_before_route_presence() -> None:
    codec = _codec()
    context = _decode_context(codec)
    reserved = (("dispatcher_corridor_coverage", {"value": 1}),)

    class TextSubclass(str):
        pass

    mutations = (
        ("plan_id", TextSubclass("plan")),
        ("source", object()),
        ("source_generation", True),
        ("block_refs_by_serial", ()),
        ("canonical_route_evidence", object()),
    )
    for field, value in mutations:
        object.__setattr__(context, field, value)
        result = codec.decode_legacy_unflatten_contract(reserved, context=context)
        assert type(result) is codec.LegacyUnflattenRejected
        assert result.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
        assert result.detail_code == "legacy_decode_context_invalid"
        object.__setattr__(context, field, getattr(_decode_context(codec), field))
    invalid = codec.decode_legacy_unflatten_contract(reserved, context=object())
    assert invalid.detail_code == "legacy_decode_context_invalid"


def test_decode_genuine_no_route_context_still_reports_route_missing() -> None:
    codec = _codec()
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"value": 1}),),
        context=_decode_context(codec),
    )
    assert result.reason is UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING


def test_shadow_boundaries_reject_equal_valued_plan_identity_subclasses() -> None:
    codec = _codec()
    plan, shadow = _shadow_plan(
        (("dispatcher_corridor_coverage", {"value": 1}),)
    )
    assert shadow is not None

    class TextSubclass(str):
        pass

    from d810.transforms.unflatten_authority.proposal import validate_shadow_for_plan

    for field in ("plan_id", "snapshot_id"):
        object.__setattr__(plan, field, TextSubclass(getattr(plan, field)))
        with pytest.raises(ValueError):
            codec.replay_legacy_unflatten_shadow(plan)
        rejected = validate_shadow_for_plan(plan, shadow)
        assert rejected.reason is UnflattenAuthorityReason.MALFORMED_PROPOSAL
        assert rejected.detail_code == "shadow_plan_identity_invalid"
        object.__setattr__(plan, field, field.replace("_id", ""))


def test_decode_scans_all_nested_generation_values() -> None:
    codec = _codec()
    from .test_model import _canonical_evidence, import_authority_model
    from d810.transforms.cfg_transaction import NativeBlockRef
    model = import_authority_model()
    evidence, identity = _canonical_evidence(model)
    result = codec.decode_legacy_unflatten_contract(
        (("dispatcher_corridor_coverage", {"rows": [{"generation": 3}, {"generation": 9}]}),),
        context=_decode_context(codec, evidence=evidence, ref=NativeBlockRef(identity)),
    )
    assert result.detail_code == "legacy_source_generation_mismatch"


def test_shadow_model_and_plan_validation_reject_exactness_mutations() -> None:
    plan, shadow = _shadow_plan((("dispatcher_corridor_coverage", {"x": 1}),))
    from d810.transforms.unflatten_authority.proposal import validate_shadow_for_plan

    object.__setattr__(shadow, "schema_version", True)
    rejected = validate_shadow_for_plan(plan, shadow)
    assert rejected.detail_code == "shadow_invariants_invalid"
    object.__setattr__(shadow, "schema_version", 1)

    class KeySubclass(str):
        pass

    object.__setattr__(shadow.entries[0], "key", KeySubclass(shadow.entries[0].key))
    rejected = validate_shadow_for_plan(plan, shadow)
    assert rejected.detail_code == "shadow_invariants_invalid"
