"""Focused tests for canonical unflatten-authority identities."""

from __future__ import annotations

from dataclasses import dataclass, replace
import json

import pytest

from d810.transforms.unflatten_authority.ids import (
    DigestFixture,
    GraphRecord,
    SUBJECT_SCHEMA,
    canonical_bytes,
    canonical_decode,
    content_id,
    semantic_graph_fingerprint,
    subject_id,
    _graph_projection,
    _claim_factory,
    _evidence_factory,
    _subject_factory,
    claim_id,
    evidence_id,
)
from d810.transforms.unflatten_authority import model
from .helpers import block_ref

from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind, InsnSnapshot, MopSnapshot, OperandKind
from d810.ir.semantics import PredicateKind
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind

UnflattenAuthorityPhase = model.UnflattenAuthorityPhase


_PINNED_DIGEST = "sha256:07fd10c22a620eaab0a3639ae738586023c380b1027b2b84684be9fd4a5a9165"


def test_canonical_digest_fixture_is_pinned() -> None:
    fixture = DigestFixture(4198400, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native", None))
    assert canonical_bytes(fixture) == (
        b'{"n":"DigestFixture","t":"record","v":[["ea",{"t":"int","v":"4198400"}],'
        b'["phase",{"n":"UnflattenAuthorityPhase","t":"enum","v":{"t":"str","v":"projected_preflight"}}],'
        b'["refs",{"t":"tuple","v":[{"t":"str","v":"native"},{"t":"none"}]}]]}'
    )
    assert content_id("digest-fixture.v1", fixture) == _PINNED_DIGEST


def test_canonical_encoding_preserves_sequence_and_inverse_types() -> None:
    values = ([1, 2], (1, 2), frozenset({1, 2}))
    encoded = tuple(canonical_bytes(value) for value in values)
    assert len(set(encoded)) == 3
    assert canonical_decode(encoded[0]) == [1, 2]
    assert canonical_decode(encoded[1]) == (1, 2)
    assert canonical_decode(encoded[2]) == frozenset({1, 2})


def test_canonical_encoding_rejects_omitted_unknown_and_float_values() -> None:
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(object())
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(1.5)
    assert content_id("optional.v1", {"value": None}) != content_id("optional.v1", {})


def test_canonical_encoding_rejects_recursive_root_and_record_cycles() -> None:
    recursive_mapping = {}
    recursive_mapping["self"] = recursive_mapping
    recursive_list = []
    recursive_list.append(recursive_list)
    recursive_record_mapping = {}
    recursive_record_mapping["self"] = recursive_record_mapping
    forged_external = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    object.__setattr__(forged_external, "input_identity", forged_external)
    values = (
        recursive_mapping,
        recursive_list,
        DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, (recursive_record_mapping,)),
        forged_external,
    )
    for value in values:
        with pytest.raises(ValueError):
            canonical_bytes(value)
        with pytest.raises(ValueError):
            content_id("cycle.v1", value)


def test_canonical_mapping_order_and_object_identity_do_not_change_digest() -> None:
    @dataclass(frozen=True)
    class Unknown:
        value: int

    assert content_id("mapping.v1", {"a": 1, "b": 2}) == content_id("mapping.v1", {"b": 2, "a": 1})
    assert content_id("fixture.v1", DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",))) == content_id("fixture.v1", DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("native",)))
    with pytest.raises((TypeError, ValueError)):
        canonical_bytes(Unknown(3))

    with pytest.raises((TypeError, ValueError)):
        canonical_bytes({"unknown": Unknown(3)})


def test_subject_id_uses_only_exact_kind_role_locator_preimage() -> None:
    locator = model.BlockSubjectLocator(block_ref("subject"), 0x1000)
    expected = content_id(SUBJECT_SCHEMA, (
        model.SemanticSubjectKind.BLOCK,
        model.SemanticSubjectRole.SOURCE_ENTRY,
        locator,
    ))
    assert subject_id(model.SemanticSubjectKind.BLOCK, model.SemanticSubjectRole.SOURCE_ENTRY, locator) == expected
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.SOURCE_ENTRY,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    with pytest.raises(ValueError):
        model.SemanticSubjectRef(
            subject.kind, subject.role, "sha256:" + "0" * 64,
            subject.block_ref, subject.anchor_ea, subject.locator,
        )
    assert subject.subject_id == expected


def test_inverse_decodes_exact_registered_types_and_rejects_noncanonical_wire() -> None:
    fixture = DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("x", None))
    encoded = canonical_bytes(fixture)
    assert canonical_decode(encoded) == fixture
    assert type(canonical_decode(encoded)) is DigestFixture
    assert canonical_decode(canonical_bytes(UnflattenAuthorityPhase.PROJECTED_PREFLIGHT)) is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"DigestFixture"', b'"n":"Unknown"'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"UnflattenAuthorityPhase"', b'"n":"UnknownEnum"'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'projected_preflight', b'unknown_value'))
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"v":[["ea"', b'"v":[["extra",{"t":"none"}],["ea"'))
    parsed = json.loads(encoded)
    parsed["v"] = parsed["v"][:-1]
    with pytest.raises(ValueError):
        canonical_decode(json.dumps(parsed, separators=(",", ":")).encode())
    parsed = json.loads(encoded)
    parsed["v"].append(parsed["v"][0])
    with pytest.raises(ValueError):
        canonical_decode(json.dumps(parsed, separators=(",", ":")).encode())
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"record","n":"DigestFixture","v":{}}')
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"none","v":null}')
    with pytest.raises(ValueError):
        canonical_decode(b'{"t":"map","v":[[{"t":"str","v":"a"},{"t":"int","v":"1"}],[{"t":"str","v":"a"},{"t":"int","v":"2"}]]}')
    with pytest.raises(ValueError):
        canonical_decode(b' {"t":"none"} ')
    with pytest.raises(ValueError):
        canonical_decode(encoded.replace(b'"n":"DigestFixture","t":"record"', b'"t":"record","n":"DigestFixture"'))


def test_inverse_round_trips_representative_model_and_external_records() -> None:
    locator = model.BlockSubjectLocator(block_ref("roundtrip"), 0x1000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    key = NativePreanalysisKey("input", "x86", 64, 0, "f" * 64, "p" * 64, "s" * 64)
    storage = StorageIdentity(StorageIdentityKind.REGISTER, 1)
    for value in (subject, key, storage):
        decoded = canonical_decode(canonical_bytes(value))
        assert type(decoded) is type(value)
        assert decoded == value


def test_claim_and_evidence_factories_recompute_ids_and_reject_forgery() -> None:
    locator = model.BlockSubjectLocator(block_ref("authority"), 0x1000)
    subject = _subject_factory(
        model.SemanticSubjectRef,
        kind=model.SemanticSubjectKind.BLOCK,
        role=model.SemanticSubjectRole.EFFECT_SITE,
        block_ref=locator.block_ref,
        anchor_ea=locator.anchor_ea,
        locator=locator,
    )
    claim = _claim_factory(
        model.LocalAliasEffectScalarizationClaim,
        kind=model.UnflattenClaimKind.LOCAL_ALIAS_EFFECT_SCALARIZATION,
        owner_subject=subject,
        step_index=0,
        host_ea=0x1000,
        host_opcode=1,
        alias_token="alias",
        base_token="base",
        host_text_sha1=None,
        value_size=None,
        step_digest="sha256:" + "1" * 64,
        source_generation=0,
    )
    evidence = _evidence_factory(
        model.AuthorityEvidence,
        kind=model.AuthorityEvidenceKind.REACHABILITY,
        subject=subject,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        payload=model.ReachabilityEvidencePayload(subject.subject_id, subject.subject_id, True, (subject.subject_id,)),
    )
    assert claim.claim_id == claim_id(claim)
    assert evidence.evidence_id == evidence_id(evidence)
    with pytest.raises(ValueError):
        replace(claim, claim_id="sha256:" + "0" * 64)
    with pytest.raises(ValueError):
        replace(evidence, evidence_id="sha256:" + "0" * 64)


def test_graph_projection_has_pinned_record_shapes_and_rejects_malformed_graphs() -> None:
    graph = _graph()
    projected = _graph_projection(graph)
    assert type(projected) is GraphRecord
    assert tuple(field.name for field in projected.__dataclass_fields__.values()) == (
        "func_ea", "entry_serial", "blocks",
    )
    assert tuple(field.name for field in projected.blocks[0].__dataclass_fields__.values()) == (
        "serial", "block_type", "raw_block_type", "kind", "flags", "start_ea",
        "native_start_ea", "succs", "preds", "tail_opcode", "raw_tail_opcode",
        "tail_kind", "instructions",
    )
    instruction_fields = tuple(field.name for field in projected.blocks[0].instructions[0].__dataclass_fields__.values())
    assert instruction_fields == (
        "opcode", "raw_opcode", "kind", "ea", "native_ea", "value_op_kind",
        "control_transfer_kind", "call_kind", "predicate_kind", "branch_predicate",
        "compare_width", "is_conditional_jump", "is_unconditional_jump", "is_call",
        "l", "r", "d", "opcode_attrs", "display_text_sha256",
    )
    assert tuple(field.name for field in projected.blocks[0].instructions[0].l.__dataclass_fields__.values()) == (
        "t", "raw_operand_type", "kind", "size", "value", "stkoff", "reg",
        "block_ref", "gaddr", "lvar_off", "lvar_stkoff", "switch_cases",
        "stack_refs", "sub_kind", "sub_value_op_kind", "sub_raw_opcode",
        "sub_predicate_kind", "sub_l", "sub_r", "args",
    )
    assert type(canonical_decode(canonical_bytes(projected))) is GraphRecord
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(replace(graph, blocks={7: graph.blocks[0], 1: graph.blocks[1]}))
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(replace(graph, blocks={
            0: replace(graph.blocks[0], succs=()), 1: graph.blocks[1],
        }))
    legacy = replace(graph.blocks[0].insn_snapshots[0], l=None, operands=("legacy",))
    legacy_graph = replace(graph, blocks={
        **graph.blocks, 0: replace(graph.blocks[0], insn_snapshots=(legacy,)),
    })
    with pytest.raises(ValueError):
        semantic_graph_fingerprint(legacy_graph)


def test_typed_operand_correspondence_manifest_is_closed() -> None:
    graph = _graph()
    insn = graph.blocks[0].insn_snapshots[0]
    left_operand = insn.l
    r = MopSnapshot(t=1, size=4, reg=1, kind=OperandKind.REGISTER)
    d = MopSnapshot(t=1, size=4, reg=2, kind=OperandKind.REGISTER)

    def with_insn(changed):
        return replace(graph, blocks={
            **graph.blocks, 0: replace(graph.blocks[0], insn_snapshots=(changed,)),
        })

    malformed = (
        replace(insn, operands=(left_operand, r), operand_slots=(("l", left_operand), ("r", r))),
        replace(insn, operand_slots=()),
        replace(insn, operands=(left_operand, left_operand), operand_slots=(("l", left_operand), ("l", left_operand))),
        replace(insn, operands=(left_operand, r), operand_slots=(("r", r), ("l", left_operand)), r=r),
        replace(insn, operands=(left_operand, r), operand_slots=(("l", left_operand),), r=r),
    )
    for changed in malformed:
        with pytest.raises((TypeError, ValueError)):
            semantic_graph_fingerprint(with_insn(changed))

    typed_only = replace(insn, operands=(), operand_slots=())
    assert semantic_graph_fingerprint(with_insn(typed_only))
    operandless = replace(insn, l=None, r=None, d=None, operands=(), operand_slots=())
    assert semantic_graph_fingerprint(with_insn(operandless))

    complete = replace(
        insn,
        r=r,
        d=d,
        operands=(left_operand, r, d),
        operand_slots=(("l", left_operand), ("r", r), ("d", d)),
    )
    complete_graph = with_insn(complete)
    baseline = semantic_graph_fingerprint(complete_graph)
    changed_transitional = replace(
        complete,
        operands=(object(), object(), object()),
        operand_slots=(("l", object()), ("r", object()), ("d", object())),
    )
    assert semantic_graph_fingerprint(with_insn(changed_transitional)) == baseline


def test_pinned_internal_records_reject_wrong_runtime_field_types() -> None:
    fixture = DigestFixture(3, UnflattenAuthorityPhase.PROJECTED_PREFLIGHT, ("x", None))
    projected = _graph_projection(_graph())
    block = projected.blocks[0]
    insn = block.instructions[0]
    mop = insn.l
    invalid = (
        replace(fixture, ea=True),
        replace(fixture, phase="projected_preflight"),
        replace(fixture, refs=["x"]),
        replace(mop, t=True),
        replace(mop, kind=InsnKind.MOV),
        replace(mop, switch_cases=[]),
        replace(mop, stack_refs=("bad",)),
        replace(mop, args=[mop]),
        replace(insn, opcode=True),
        replace(insn, kind=OperandKind.REGISTER),
        replace(insn, value_op_kind=InsnKind.MOV),
        replace(insn, is_call=1),
        replace(insn, l=1),
        replace(insn, opcode_attrs={1: "bad"}),
        replace(insn, display_text_sha256="A" * 64),
        replace(block, serial=True),
        replace(block, succs=[1]),
        replace(block, instructions=[insn]),
        replace(block, tail_kind=OperandKind.REGISTER),
        replace(projected, func_ea=True),
        replace(projected, entry_serial="0"),
        replace(projected, blocks=[block]),
        replace(projected, blocks=(projected.blocks[1], projected.blocks[0])),
        replace(projected, blocks=(replace(block, succs=(1, 1)), projected.blocks[1])),
    )
    for value in invalid:
        with pytest.raises((TypeError, ValueError)):
            canonical_bytes(value)

    encoded = canonical_bytes(projected)
    malformed = encoded.replace(
        b'["func_ea",{"t":"int","v":"4096"}]',
        b'["func_ea",{"t":"str","v":"4096"}]',
    )
    with pytest.raises((TypeError, ValueError)):
        canonical_decode(malformed)


def _graph() -> FlowGraph:
    instruction = InsnSnapshot(
        opcode=1,
        raw_opcode=1,
        ea=0x1000,
        operands=(MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER),),
        operand_slots=(("l", MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER)),),
        l=MopSnapshot(t=1, size=4, reg=0, kind=OperandKind.REGISTER),
        display_text="mov r0, r1",
        kind=InsnKind.MOV,
        value_op_kind=ValueOpKind.MOVE,
        predicate_kind=None,
        compare_width=4,
        native_ea=0x1000,
    )
    return FlowGraph(
        {
            0: BlockSnapshot(0, 1, (1,), (), 0, 0x1000, (instruction,)),
            1: BlockSnapshot(1, 1, (), (0,), 0, 0x1010, ()),
        },
        entry_serial=0,
        func_ea=0x1000,
    )


@pytest.mark.parametrize(
    "change",
    [
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], opcode=2),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], raw_opcode=2),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], kind=InsnKind.STORE),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], value_op_kind=ValueOpKind.STORE),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], predicate_kind=PredicateKind.EQ),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], branch_predicate=PredicateKind.EQ),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], compare_width=8),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], l=MopSnapshot(t=1, size=4, reg=1, kind=OperandKind.REGISTER)),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], l=MopSnapshot(t=2, size=4, value=7, kind=OperandKind.NUMBER)),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], native_ea=0x1004),
        lambda graph: replace(graph.blocks[0].insn_snapshots[0], display_text="mov r0, r2"),
    ],
)
def test_semantic_graph_fingerprint_changes_for_instruction_semantics(change) -> None:
    baseline = _graph()
    changed_insn = change(baseline)
    changed = replace(
        baseline,
        blocks={**baseline.blocks, 0: replace(baseline.blocks[0], insn_snapshots=(changed_insn,))},
    )
    assert semantic_graph_fingerprint(baseline) != semantic_graph_fingerprint(changed)


def test_semantic_graph_fingerprint_changes_for_topology_and_entry() -> None:
    baseline = semantic_graph_fingerprint(_graph())
    graph = _graph()
    topology = replace(
        graph,
        blocks={
            **graph.blocks,
            0: replace(graph.blocks[0], succs=()),
            1: replace(graph.blocks[1], preds=()),
        },
    )
    alternate_entry = replace(_graph(), entry_serial=1)
    assert baseline != semantic_graph_fingerprint(topology)
    assert baseline != semantic_graph_fingerprint(alternate_entry)
