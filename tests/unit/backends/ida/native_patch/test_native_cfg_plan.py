from __future__ import annotations

import dataclasses
import hashlib

import pytest

from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder
from d810.backends.ida.native_patch.native_cfg_plan import (
    DatabaseAttestation,
    NativeCfgPlanBuildReason,
    build_native_cfg_plan,
)
from d810.backends.ida.native_patch.origin_mapper import (
    NativeDecodedControlTransfer,
    NativeOriginDecode,
)
from d810.core.execution_journal import (
    DecompilationSessionId,
    ExecutionAttemptId,
    ExecutionEffectRef,
)
from d810.ir.edge_state_contract import EdgeStateContract
from d810.ir.maturity import IRMaturity
from d810.ir.native_origin import NativeInstructionIdentity
from d810.ir.native_range_projection import NativeRange
from d810.ir.semantics import PredicateKind
from d810.transforms.native_cfg_normalization import (
    NativeCfgBlockRangeBinding,
    NativeCfgEdgeIntent,
    NativeCfgEdgeKind,
    NativeCfgNormalizationIntent,
)
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionOwnership,
    NativeItemHead,
    NativeItemKind,
    NativeItemShape,
)

pytestmark = pytest.mark.pure_python


def _insn(ea: int, size: int, mnemonic: str) -> NativeInstructionIdentity:
    return NativeInstructionIdentity(
        ea=ea,
        end_ea=ea + size,
        bytes_hash=f"hash:{ea:x}",
        mnemonic=mnemonic,
        operand_shape=(),
        pc_relative_sites=(),
    )


class _Mapper:
    def __init__(self, rows: dict[tuple[tuple[int, int], ...], NativeOriginDecode]):
        self.rows = rows

    def decode_ranges(self, ranges):
        key = tuple((item.start_ea, item.end_ea) for item in ranges)
        return self.rows.get(key, NativeOriginDecode((), ()))


class _Reader:
    def __init__(self, image: bytes, ownership: NativeFunctionOwnership):
        self.image = image
        self.ownership = ownership
        self.write_count = 0

    def read_current_bytes(self, start_ea, end_ea):
        if start_ea < 0x1000 or end_ea > 0x1100:
            return None
        return self.image[start_ea - 0x1000 : end_ea - 0x1000]

    read_original_bytes = read_current_bytes

    def read_patch_rows(self, start_ea, end_ea):
        return ()

    def read_item_shape(self, start_ea, end_ea):
        return NativeItemShape(
            (
                NativeItemHead(
                    ea=start_ea,
                    size=end_ea - start_ea,
                    kind=NativeItemKind.CODE,
                    user_defined=False,
                ),
            )
        )

    def read_incoming_refs(self, start_ea, end_ea):
        return ()

    def read_function_ownership(self, ea):
        return self.ownership if 0x1000 <= ea < 0x1100 else None


def _binding(serial: int, ea: int, end: int | None = None):
    return NativeCfgBlockRangeBinding(
        block_serial=serial,
        microcode_native_ea=ea,
        ctree_statement_indices=(serial + 1,),
        native_ranges=(NativeRange(ea, end or ea + 1),),
    )


def _case(kind: NativeCfgEdgeKind):
    image = bytearray(b"\x90" * 0x100)
    if kind is NativeCfgEdgeKind.REDIRECT:
        source = _insn(0x1000, 5, "jmp")
        inherited_serials = (1,)
        inherited_eas = (0x1010,)
        final_serials = (2,)
        final_eas = (0x1020,)
        predicate = None
    elif kind is NativeCfgEdgeKind.FORCE_TAKEN:
        source = _insn(0x1000, 6, "jne")
        inherited_serials = (1, 2)
        inherited_eas = (0x1006, 0x1020)
        final_serials = (2,)
        final_eas = (0x1020,)
        predicate = PredicateKind.NE
    else:
        source = _insn(0x1000, 2, "jne")
        inherited_serials = (1, 2)
        inherited_eas = (0x1002, 0x1020)
        final_serials = (1,)
        final_eas = (0x1002,)
        predicate = PredicateKind.NE
    image[: source.length] = b"\x75\x00" + b"\x90" * (source.length - 2)
    source = dataclasses.replace(
        source,
        bytes_hash=hashlib.sha256(bytes(image[: source.length])).hexdigest(),
    )
    ownership = NativeFunctionOwnership(
        owning_function_entry_ea=0x1000,
        chunk_ranges=(NativeAddressRange(0x1000, 0x1100),),
    )
    reader = _Reader(bytes(image), ownership)
    function_identity = __import__(
        "d810.transforms.native_patch_plan", fromlist=["NativeFunctionIdentity"]
    ).NativeFunctionIdentity(
        entry_ea=0x1000,
        chunk_ranges=ownership.chunk_ranges,
        inherited_bytes_hash=hashlib.sha256(bytes(image)).hexdigest(),
    )
    target_rows = {
        ea: NativeOriginDecode((_insn(ea, 1, "nop"),), ()) for ea in set(final_eas)
    }
    rows = {
        ((0x1000, source.end_ea),): NativeOriginDecode(
            (source,),
            (
                NativeDecodedControlTransfer(
                    source,
                    (
                        tuple(reversed(inherited_eas))
                        if len(inherited_eas) == 2
                        else inherited_eas
                    ),
                    predicate,
                ),
            ),
        ),
        **{
            ((ea, ea + 1),): decode
            for ea, decode in target_rows.items()
            if ea != 0x1000
        },
    }
    bindings = [_binding(0, 0x1000, source.end_ea)]
    for serial, ea in zip(final_serials, final_eas, strict=True):
        if serial == 0:
            continue
        bindings.append(_binding(serial, ea))
    intent = NativeCfgNormalizationIntent(
        function_ea=0x1000,
        maturity=IRMaturity.GLOBAL_OPTIMIZED,
        baseline_cfg_fingerprint="baseline",
        target_cfg_fingerprint="target",
        target_ctree_range_fingerprint="ctree-ranges",
        block_range_bindings=tuple(bindings),
        edge_intents=(
            NativeCfgEdgeIntent(
                source_block=0,
                source_native_ea=0x1000,
                inherited_successors=inherited_serials,
                final_successors=final_serials,
                inherited_target_native_eas=inherited_eas,
                target_native_eas=final_eas,
                kind=kind,
                owner_pass_ids=("lower_state_machine",),
                receipt_refs=(ExecutionEffectRef("mutation", "receipt-1"),),
                state_contract=EdgeStateContract(
                    source_stack_delta=0,
                    target_stack_delta=0,
                    proof_ids=("state-proof",),
                ),
            ),
        ),
        intent_hash="intent-hash",
    )
    attestation = DatabaseAttestation(
        database_identity=NativeDatabaseIdentity(
            idb_uuid="uuid",
            input_file_hash="input",
            processor="metapc",
            bitness=64,
            image_base=0x1000,
            database_path_hash="path",
        ),
        function_identity=function_identity,
        authorizing_attempt_id=ExecutionAttemptId(DecompilationSessionId("session"), 1),
        architecture="x86",
        endianness="little",
    )
    return intent, reader, _Mapper(rows), attestation


@pytest.mark.parametrize(
    "kind",
    (
        NativeCfgEdgeKind.REDIRECT,
        NativeCfgEdgeKind.FORCE_TAKEN,
        NativeCfgEdgeKind.FORCE_FALLTHROUGH,
    ),
)
def test_builds_supported_edge_plan(kind):
    intent, reader, mapper, attestation = _case(kind)
    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.reason is None
    assert outcome.plan is not None
    assert outcome.plan.issuer_id == "stage-c-native-cfg-normalizer"
    assert outcome.plan.patch_class == "semantic_deobfuscation"
    assert outcome.plan.proof_id == "native-cfg-intent-v1:intent-hash"
    assert outcome.plan.proof_hash == intent.target_cfg_fingerprint
    assert outcome.plan.provenance[:1] == ("stage-c-native-cfg",)
    assert outcome.plan.native_origin_map_fingerprint == "ctree-ranges"
    assert reader.write_count == 0


def test_target_head_can_be_validated_from_function_range_without_ctree_row() -> None:
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    intent = dataclasses.replace(
        intent,
        block_range_bindings=(intent.block_range_bindings[0],),
    )
    mapper.rows[((0x1000, 0x1100),)] = NativeOriginDecode(
        (_insn(0x1020, 1, "nop"),),
        (),
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.plan is not None


def test_source_transfer_can_be_validated_from_function_range_without_ctree_row() -> (
    None
):
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    source_decode = mapper.rows[((0x1000, 0x1005),)]
    target_decode = mapper.rows[((0x1020, 0x1021),)]
    intent = dataclasses.replace(intent, block_range_bindings=())
    mapper.rows[((0x1000, 0x1100),)] = NativeOriginDecode(
        (*source_decode.instructions, *target_decode.instructions),
        source_decode.control_transfers,
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.plan is not None


def test_source_hint_selects_one_transfer_inside_a_broad_ctree_range() -> None:
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    source_binding = dataclasses.replace(
        intent.block_range_bindings[0],
        native_ranges=(NativeRange(0x1000, 0x1010),),
    )
    intent = dataclasses.replace(
        intent,
        block_range_bindings=(source_binding, *intent.block_range_bindings[1:]),
    )
    source = _insn(0x1000, 5, "jmp")
    source = dataclasses.replace(
        source,
        bytes_hash=hashlib.sha256(reader.image[:5]).hexdigest(),
    )
    other = _insn(0x1008, 5, "jmp")
    mapper.rows[((0x1000, 0x1010),)] = NativeOriginDecode(
        (source, other),
        (
            NativeDecodedControlTransfer(source, (0x1010,), None),
            NativeDecodedControlTransfer(other, (0x1010,), None),
        ),
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.plan is not None
    assert outcome.plan.operations[0].range.start_ea == 0x1000


def test_builds_two_way_retarget_with_native_fallthrough() -> None:
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.FORCE_TAKEN)
    edge = dataclasses.replace(
        intent.edge_intents[0],
        final_successors=(2, 3),
        target_native_eas=(0x1006, 0x1030),
        kind=NativeCfgEdgeKind.REDIRECT,
    )
    intent = dataclasses.replace(
        intent,
        block_range_bindings=(
            intent.block_range_bindings[0],
            _binding(3, 0x1030),
            _binding(2, 0x1006),
        ),
        edge_intents=(edge,),
    )
    mapper.rows[((0x1030, 0x1031),)] = NativeOriginDecode(
        (_insn(0x1030, 1, "nop"),), ()
    )
    mapper.rows[((0x1006, 0x1007),)] = NativeOriginDecode(
        (_insn(0x1006, 1, "nop"),), ()
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.plan is not None
    operation = outcome.plan.operations[0]
    assert operation.expected_after_successors == (0x1030, 0x1006)
    assert operation.expected_after_shape.heads[0].mnemonic == "jne"
    assert len(operation.replacement_bytes) == 6


def test_source_hint_outside_frozen_ranges_abstains_without_writes():
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    bad_binding = _binding(0, 0x1001, 0x1005)
    intent = __import__("dataclasses").replace(
        intent,
        block_range_bindings=(bad_binding, *intent.block_range_bindings[1:]),
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.reason == NativeCfgPlanBuildReason.SOURCE_HINT_OUTSIDE_RANGE.value
    assert reader.write_count == 0


def test_missing_unique_current_terminator_abstains_without_writes():
    intent, reader, _mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=_Mapper({}),
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.reason is not None
    assert outcome.reason.startswith(
        NativeCfgPlanBuildReason.AMBIGUOUS_NATIVE_TERMINATOR.value
    )
    assert reader.write_count == 0


def test_decode_capture_byte_race_abstains_without_writes():
    intent, reader, mapper, attestation = _case(NativeCfgEdgeKind.REDIRECT)
    key = ((0x1000, 0x1005),)
    decoded = mapper.rows[key]
    transfer = decoded.control_transfers[0]
    stale_instruction = dataclasses.replace(
        transfer.instruction,
        bytes_hash=hashlib.sha256(b"different bytes").hexdigest(),
    )
    mapper.rows[key] = NativeOriginDecode(
        (stale_instruction,),
        (
            NativeDecodedControlTransfer(
                stale_instruction,
                transfer.successors,
                transfer.predicate,
            ),
        ),
    )

    outcome = build_native_cfg_plan(
        intent=intent,
        reader=reader,
        origin_mapper=mapper,
        encoder=MinimalX86BranchEncoder(),
        attestation=attestation,
    )

    assert outcome.reason == NativeCfgPlanBuildReason.STALE_NATIVE_TERMINATOR.value
    assert reader.write_count == 0
