"""Lower one discovered indirect-label request to a metadata-only patch plan.

This backend is the live-IDA half of the Task 7 migration.  It may *read*
IDA to capture a proposal, but every mutation remains in ``NativePatchGateway``
through ``IdaMetadataActionExecutor``.  The module deliberately accepts only
primitive request fields, never an object from ``d810.hexrays``: backends sit
below Hex-Rays in the import contract.
"""

from __future__ import annotations

import hashlib
import enum
from dataclasses import dataclass

from d810.backends.ida.native_patch.capture import (
    IdaLiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.metadata import (
    IdaMetadataActionExecutor,
    reversible_data_item_head,
    is_reversible_data_item_state,
)
from d810.capabilities.native_patch import (
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.core.execution_journal import ExecutionAttemptId
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeEncodingEvidence,
    NativeFunctionIdentity,
    NativeMetadataAction,
    NativeMetadataActionKind,
    NativePatchOperation,
    NativePatchPlan,
)

__all__ = [
    "IndirectLabelPlanBuildError",
    "IndirectLabelPlanFailureReason",
    "IndirectLabelPlanRequest",
    "build_indirect_label_metadata_plan",
]

class IndirectLabelPlanFailureReason(str, enum.Enum):
    """Stable machine-readable reasons for planner abstention receipts."""

    UNCLASSIFIED = "unclassified"
    LOSSLESS_ITEM_RECREATION_UNSUPPORTED = "lossless_item_recreation_unsupported"


class IndirectLabelPlanBuildError(ValueError):
    """Live evidence cannot honestly lower the requested materialization."""

    def __init__(
        self,
        message: str,
        *,
        reason: IndirectLabelPlanFailureReason = (
            IndirectLabelPlanFailureReason.UNCLASSIFIED
        ),
        ea: int | None = None,
        before_shape: str | None = None,
        after_shape: str | None = None,
    ) -> None:
        super().__init__(message)
        if not isinstance(reason, IndirectLabelPlanFailureReason):
            raise TypeError("reason must be an IndirectLabelPlanFailureReason")
        if (
            reason
            is IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED
        ):
            if ea is None or not before_shape or not after_shape:
                raise ValueError(
                    "lossless item recreation errors require EA and both shapes"
                )
        self.reason = reason
        self.ea = None if ea is None else int(ea)
        self.before_shape = before_shape
        self.after_shape = after_shape


@dataclass(frozen=True, slots=True)
class IndirectLabelPlanRequest:
    function_ea: int
    label_start: int
    label_end: int
    table_address: int
    table_count: int
    target_eas: tuple[int, ...]
    dispatch_jump_ea: int | None
    switch_start_ea: int | None
    install_switch_info: bool
    state_base: int
    state_var_stkoff: int | None


def _instruction_shape(ea: int) -> NativeInstructionSequenceShape:
    import ida_ua
    import idc

    instruction = ida_ua.insn_t()
    size = int(ida_ua.decode_insn(instruction, int(ea)))
    if size <= 0:
        raise IndirectLabelPlanBuildError(f"cannot decode instruction at {ea:#x}")
    return NativeInstructionSequenceShape(
        heads=(
            NativeInstructionHead(
                ea=int(ea),
                length=size,
                mnemonic=str(idc.print_insn_mnem(int(ea)) or "unknown"),
                operand_shapes=(),
                successors=(),
            ),
        )
    )


def _instruction_size(ea: int) -> int:
    return _instruction_shape(int(ea)).heads[0].length


def _matches_rsp_state_write(ea: int, state_var_stkoff: int) -> int | None:
    import ida_bytes

    if int(ida_bytes.get_byte(ea)) != 0xC7:
        return None
    if int(ida_bytes.get_byte(ea + 1)) != 0x44:
        return None
    if int(ida_bytes.get_byte(ea + 2)) != 0x24:
        return None
    if int(ida_bytes.get_byte(ea + 3)) != (int(state_var_stkoff) & 0xFF):
        return None
    return int(ida_bytes.get_dword(ea + 4)) & 0xFFFFFFFF


def _following_jump_ea(start_ea: int, stop_ea: int) -> int | None:
    import ida_bytes
    import idaapi
    import idc

    badaddr = int(getattr(idaapi, "BADADDR", -1))
    ea = int(ida_bytes.next_head(int(start_ea), int(stop_ea)))
    local_stop = min(int(stop_ea), int(start_ea) + 0x80)
    while ea != badaddr and ea < local_stop:
        if str(idc.print_insn_mnem(ea) or "").lower() == "jmp":
            return int(ea)
        next_ea = int(ida_bytes.next_head(ea, int(stop_ea)))
        if next_ea == badaddr or next_ea <= ea:
            break
        ea = next_ea
    return None


def _parse_cref_state(token: str) -> set[tuple[int, int, bool]]:
    if not token.startswith("cref3:"):
        raise IndirectLabelPlanBuildError(f"unsupported xref state {token!r}")
    rows: set[tuple[int, int, bool]] = set()
    for row in token.removeprefix("cref3:").split(","):
        if not row:
            continue
        target_text, separator, remainder = row.partition("@")
        type_text, separator2, owner_text = remainder.partition("@")
        if not separator or not separator2 or owner_text not in {"a", "u"}:
            raise IndirectLabelPlanBuildError(f"unsupported xref state {token!r}")
        rows.add((int(target_text, 16), int(type_text, 16), owner_text == "u"))
    return rows


def _cref_state(rows: set[tuple[int, int, bool]]) -> str:
    return "cref3:" + ",".join(
        f"{target:#x}@{xref_type:#x}@{'u' if user_owned else 'a'}"
        for target, xref_type, user_owned in sorted(rows)
    )


def _missing_cref_targets(token: str, targets: set[int]) -> tuple[int, ...]:
    """Return targets not already delivered by any code-xref representation.

    IDA permits a source-target relation to be represented as an automatic
    flow edge, a jump edge, or a user-owned edge.  Adding a user jump edge over
    an existing automatic flow edge is not stable: reanalysis canonicalizes it
    back to the flow edge.  The planner therefore treats any existing edge to
    the target as already materialized and emits no redundant write.
    """
    existing_targets = {
        target for target, _xref_type, _user in _parse_cref_state(token)
    }
    return tuple(sorted(set(int(target) for target in targets) - existing_targets))


def _bundle_cref_targets(
    before: str, targets: set[int], *, xref_type: int
) -> tuple[str, tuple[int, ...]]:
    """Build one exact after-token for all missing targets at one source."""

    missing = _missing_cref_targets(before, targets)
    if not missing:
        return before, ()
    wanted = _parse_cref_state(before)
    wanted.update((target, int(xref_type), True) for target in missing)
    return _cref_state(wanted), missing


def _group_item_transition_before(
    before: str,
    *,
    target_ea: int,
    seen_data_heads: set[int],
) -> str:
    """Plan one shared data item as a reversible first-plus-unknown sequence.

    IDA's label table can place several instruction targets inside one scalar
    data item. The first target removes that item and retains its snapshot;
    later targets are genuinely ``unknown`` after that removal. Reverse
    journal order restores the later unknowns first, then the first action
    recreates the enclosing item.
    """

    head_ea = reversible_data_item_head(before, expected_ea=int(target_ea))
    if head_ea is None:
        return before
    if head_ea in seen_data_heads:
        return "unknown"
    seen_data_heads.add(head_ea)
    return before


def _item_transition_order(target_eas: tuple[int, ...]) -> tuple[int, ...]:
    """Order item promotions high-to-low to avoid adjacent-item overlap.

    IDA can decode an instruction at a lower target across the boundary of a
    following data item.  If that lower promotion runs first, IDA clears the
    following item before its own action can verify the recorded snapshot.
    Promoting the highest target first removes its enclosing item explicitly;
    lower targets then observe the intentional ``unknown`` grouped state.
    Reverse journal order restores the lower instruction before recreating the
    enclosing data item, so the transition remains lossless.
    """

    return tuple(sorted((int(ea) for ea in target_eas), reverse=True))


def _with_user_cref(
    executor: IdaMetadataActionExecutor,
    *,
    source_ea: int,
    target_ea: int,
) -> NativeMetadataAction | None:
    import ida_xref

    before = executor.read_state(NativeMetadataActionKind.UPDATE_XREF, source_ea)
    wanted = _parse_cref_state(before)
    wanted.add((int(target_ea), int(ida_xref.fl_JN), True))
    after = _cref_state(wanted)
    if after == before:
        return None
    return NativeMetadataAction(
        kind=NativeMetadataActionKind.UPDATE_XREF,
        ea=int(source_ea),
        expected_before=before,
        expected_after=after,
    )


def _function_identity(
    reader: IdaLiveDatabaseReader,
    *,
    ownership,
) -> NativeFunctionIdentity:
    image = b"".join(
        reader.read_current_bytes(chunk.start_ea, chunk.end_ea) or b""
        for chunk in ownership.chunk_ranges
    )
    if not image:
        raise IndirectLabelPlanBuildError("cannot capture owning function bytes")
    return NativeFunctionIdentity(
        entry_ea=ownership.owning_function_entry_ea,
        chunk_ranges=ownership.chunk_ranges,
        inherited_bytes_hash=hashlib.sha256(image).hexdigest(),
    )


def _database_identity(function_ea: int) -> NativeDatabaseIdentity:
    """Use the attested loader SHA and durable IDB UUID, never a path hash.

    The input path remains a locator only, so it is retained solely as the
    non-authoritative ``database_path_hash`` field.  A missing loader SHA or
    durable attestation is an abstention boundary: manufacturing an identity
    from path/processor/image-base would make certificates portable across
    distinct inputs.
    """
    import ida_nalt
    import idaapi

    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    resolution = resolve_native_preanalysis_identity(
        int(function_ea), profile_config={}
    )
    native_key = resolution.native_key
    database_uuid = resolution.identity_resolution.database_uuid
    if (
        native_key is None
        or database_uuid is None
        or not resolution.external_evidence_allowed
    ):
        raise IndirectLabelPlanBuildError(
            "missing attested loader identity or durable database UUID: "
            + resolution.identity_resolution.reason
        )
    path = str(ida_nalt.get_input_file_path() or "<unnamed-idb>")
    image_base = int(idaapi.get_imagebase())
    path_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return NativeDatabaseIdentity(
        idb_uuid=database_uuid,
        input_file_hash=native_key.input_identity.removeprefix("sha256:"),
        processor=native_key.processor,
        bitness=native_key.bitness,
        image_base=image_base,
        database_path_hash=path_hash,
    )


def build_indirect_label_metadata_plan(
    request: IndirectLabelPlanRequest,
    *,
    authorizing_attempt_id: ExecutionAttemptId,
) -> NativePatchPlan:
    """Capture one fully evidenced, zero-byte materialization plan.

    Any missing decode, ownership, or metadata state raises
    :class:`IndirectLabelPlanBuildError`; callers must turn that into a
    read-only abstention rather than approximating an IDA mutation.
    """
    if not isinstance(authorizing_attempt_id, ExecutionAttemptId):
        raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")
    dispatch_jump_ea = request.dispatch_jump_ea
    if dispatch_jump_ea is None:
        raise IndirectLabelPlanBuildError("indirect dispatch jump was not found")
    reader = IdaLiveDatabaseReader()
    executor = IdaMetadataActionExecutor()
    shape = _instruction_shape(int(dispatch_jump_ea))
    anchor = NativeAddressRange(
        int(dispatch_jump_ea), int(dispatch_jump_ea) + shape.heads[0].length
    )
    captured = capture_range_evidence(
        reader,
        anchor,
        function_ea=int(request.function_ea),
    )
    if not captured.ok or captured.evidence is None:
        raise IndirectLabelPlanBuildError(str(captured.reason))
    evidence = captured.evidence

    actions: list[NativeMetadataAction] = []
    import ida_bytes
    import ida_funcs

    requires_tail = any(
        (owner := ida_funcs.get_func(int(target_ea))) is None
        or int(owner.start_ea) != int(request.function_ea)
        for target_ea in request.target_eas
    )
    if requires_tail:
        # A detached tail requires a positive live-IDB adoption oracle before
        # it can become an authorized writer route.  The bundled fixture has
        # no detached creatable code span, so this transition is intentionally
        # unavailable rather than carrying an unproven append/remove inverse.
        raise IndirectLabelPlanBuildError(
            "function-tail adoption is not yet proven losslessly reversible"
        )

    seen_data_heads: set[int] = set()
    for target_ea in _item_transition_order(request.target_eas):
        before = executor.read_state(NativeMetadataActionKind.RECREATE_ITEM, target_ea)
        after = f"code:{_instruction_size(target_ea)}"
        if before == "unknown":
            flags = ida_bytes.get_flags(int(target_ea))
            if not (
                ida_bytes.is_unknown(flags)
                and int(ida_bytes.get_item_head(int(target_ea))) == int(target_ea)
            ):
                raise IndirectLabelPlanBuildError(
                    f"target is not an explicit unknown item head at {target_ea:#x}"
                )
            # Required function reanalysis/redo reclaims such an item as code
            # during restore, so UNKNOWN -> CODE has no lossless inverse yet.
            # Its head witness is intentionally checked above to make the
            # refusal diagnostic precise rather than conflating it with tails.
            raise IndirectLabelPlanBuildError(
                "unknown-item recreation is not yet proven reversible after "
                f"required reanalysis at {target_ea:#x}"
            )
        elif before == after:
            # Keep the target's final item witness stable across a rerun.  The
            # gateway recognizes this as a no-op and never calls IDA's item
            # writer, but the certificate still proves the same target set.
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(target_ea),
                    expected_before=before,
                    expected_after=after,
                )
            )
        elif is_reversible_data_item_state(before, expected_ea=int(target_ea)):
            # A narrow scalar-data snapshot preserves the exact IDA flags,
            # per-byte flags, and bytes needed to reverse the data->code
            # promotion.  Generic ``data:<size>`` remains fail-closed.
            expected_before = _group_item_transition_before(
                before,
                target_ea=int(target_ea),
                seen_data_heads=seen_data_heads,
            )
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(target_ea),
                    expected_before=expected_before,
                    expected_after=after,
                )
            )
        elif before != after:
            raise IndirectLabelPlanBuildError(
                f"cannot losslessly recreate {before!r} as {after!r} at {target_ea:#x}",
                reason=(
                    IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED
                ),
                ea=int(target_ea),
                before_shape=before,
                after_shape=after,
            )

    import idaapi

    badaddr = int(getattr(idaapi, "BADADDR", -1))
    fallthrough_ea = int(ida_bytes.next_head(int(dispatch_jump_ea), badaddr))
    alternate_source = int(ida_bytes.prev_head(int(dispatch_jump_ea), 0))
    targets_by_source: dict[int, set[int]] = {}
    for target_ea in request.target_eas:
        source_ea = int(dispatch_jump_ea)
        if (
            int(target_ea) == fallthrough_ea
            and alternate_source != badaddr
            and alternate_source < int(dispatch_jump_ea)
        ):
            source_ea = alternate_source
        targets_by_source.setdefault(source_ea, set()).add(int(target_ea))
    import idc

    # A table label physically adjacent to a no-fallthrough jump needs an
    # explicit flow boundary for Hex-Rays to retain the separate handler body.
    # IDA removes every synthetic representation we measured during required
    # reanalysis, so the gateway cannot create or certify one. Accept an
    # already-normalized boundary, otherwise abstain before journal prepare.
    for target_ea in request.target_eas:
        previous_ea = int(ida_bytes.prev_head(int(target_ea), int(request.function_ea)))
        if previous_ea == badaddr or previous_ea >= int(target_ea):
            continue
        if int(ida_bytes.next_head(previous_ea, int(target_ea) + 16)) != int(target_ea):
            continue
        if str(idc.print_insn_mnem(previous_ea) or "").lower() != "jmp":
            continue
        boundary_state = executor.read_state(
            NativeMetadataActionKind.UPDATE_XREF,
            previous_ea,
        )
        if int(target_ea) in _missing_cref_targets(
            boundary_state, {int(target_ea)}
        ):
            # This edge is an analysis-only block-boundary hint, not a
            # requested semantic mutation. Do not manufacture a user xref
            # merely to satisfy a planner witness; actual requested xrefs
            # below remain transactional and fail closed.
            continue
        actions.append(
            NativeMetadataAction(
                kind=NativeMetadataActionKind.UPDATE_XREF,
                ea=previous_ea,
                expected_before=boundary_state,
                expected_after=boundary_state,
            )
        )
    if request.state_var_stkoff is not None:
        target_by_state = {
            int(request.state_base) + index: int(target_ea)
            for index, target_ea in enumerate(request.target_eas)
        }
        for ea in range(int(request.function_ea), int(request.label_end) - 7):
            state_value = _matches_rsp_state_write(ea, int(request.state_var_stkoff))
            if state_value is None:
                continue
            target_ea = target_by_state.get(state_value)
            if target_ea is None:
                continue
            source_ea = _following_jump_ea(ea, int(request.label_end)) or ea
            # These resolved-state crefs are optional analysis hints.  The
            # legacy writer also tolerates their initial rejection and only
            # refreshes them after handler-body reanalysis.  A native plan
            # cannot promise an exact reversible after-state from an undefined
            # source, so include only sources that are already instruction
            # heads; the required dispatcher fan-out above is unaffected.
            if not ida_bytes.is_code(ida_bytes.get_flags(int(source_ea))):
                continue
            targets_by_source.setdefault(source_ea, set()).add(target_ea)
    for source_ea, targets in sorted(targets_by_source.items()):
        before = executor.read_state(NativeMetadataActionKind.UPDATE_XREF, source_ea)
        import ida_xref

        # One action owns the complete source fan-out.  The executor applies
        # the user-edge additions as a local failure-atomic batch, so the
        # journal can reverse the entire source transition as one state move.
        after, missing_targets = _bundle_cref_targets(
            before, targets, xref_type=int(ida_xref.fl_JN)
        )
        if not missing_targets:
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=source_ea,
                    expected_before=before,
                    expected_after=before,
                )
            )
        else:
            # Keep all additions for one source in one failure-atomic action.
            # IDA can drop an earlier user edge while the same source is being
            # revisited, so sequential expected-before witnesses are not
            # stable on the live database.
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=source_ea,
                    expected_before=before,
                    expected_after=after,
                )
            )

    if request.install_switch_info:
        # IDA canonicalizes a persisted switch record (including flags,
        # version, and expression EA) only after ``set_switch_info``.  A
        # read-only planner cannot capture that exact post-state without
        # first mutating the database, so this route remains fail-closed
        # until the SDK supplies a pure canonicalization API.
        raise IndirectLabelPlanBuildError(
            "switch-info installation has no read-only exact after-state witness"
        )

    if not actions:
        raise IndirectLabelPlanBuildError(
            "label request has no required metadata change"
        )

    operation = NativePatchOperation(
        operation_id="indirect-label-metadata",
        range=anchor,
        expected_current_bytes=evidence.expected_current_bytes,
        expected_original_bytes=evidence.expected_original_bytes,
        expected_patch_rows=evidence.expected_patch_rows,
        expected_before_shape=shape,
        expected_item_shape=evidence.expected_item_shape,
        expected_incoming_refs=evidence.expected_incoming_refs,
        expected_function_ownership=evidence.expected_function_ownership,
        replacement_bytes=evidence.expected_current_bytes,
        expected_after_shape=shape,
        expected_after_successors=(),
        encoding_evidence=NativeEncodingEvidence(
            provider_id="ida-metadata-only",
            provider_version="1",
            final_ea=int(dispatch_jump_ea),
            opcode_intent="metadata_only",
            emitted_hash=hashlib.sha256(evidence.expected_current_bytes).hexdigest(),
            independent_decode_hash=hashlib.sha256(
                repr(shape).encode("utf-8")
            ).hexdigest(),
        ),
        relocation_evidence=(),
        metadata_actions=tuple(actions),
        restore_snapshot=evidence.restore_snapshot,
        writes_bytes=False,
    )
    database_identity = _database_identity(int(request.function_ea))
    function_identity = _function_identity(
        reader,
        ownership=evidence.expected_function_ownership,
    )
    request_fingerprint = hashlib.sha256(repr(request).encode("utf-8")).hexdigest()
    return NativePatchPlan(
        plan_id=f"indirect-label:{request_fingerprint[:16]}",
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=database_identity,
        function_identity=function_identity,
        inherited_function_fingerprint=function_identity.inherited_bytes_hash,
        target_cfg_fingerprint=request_fingerprint,
        native_origin_map_fingerprint=request_fingerprint,
        architecture="x86",
        bitness=database_identity.bitness,
        endianness="little",
        processor=database_identity.processor,
        issuer_id="indirect-label-materializer",
        proof_id="indirect-label-discovery",
        proof_hash=request_fingerprint,
        provenance=("indirect_jump_labels",),
        operations=(operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=authorizing_attempt_id,
    )
