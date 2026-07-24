"""Live Hex-Rays realization of portable semantic fragment plans."""

from __future__ import annotations

from dataclasses import dataclass, field

import ida_hexrays
import ida_range

from d810.core.typing import Protocol, TYPE_CHECKING, runtime_checkable
from d810.hexrays.ir.exact_data_flow import (
    find_reaching_defs_for_reg_use,
    find_reaching_defs_for_stkvar_use,
    find_uses_reached_by_reg_definition,
    find_uses_reached_by_stkvar_definition,
)
from d810.hexrays.ir.exact_value_ranges import (
    ExactValueRangeQueryUnavailable,
    prove_exact_unsigned_range,
)
from d810.hexrays.ir.flag_queries import (
    ConditionCodeQueryUnavailable,
    condition_code_write_eas,
    instruction_writes_condition_codes,
)
from d810.hexrays.mutation.ir_translator import capture_mop_snapshot
from d810.hexrays.opcode_lift import (
    branch_opcode_for_predicate,
    branch_predicate_from_opcode,
    value_op_from_opcode,
)
from d810.hexrays.ir.logical_block_proxy import (
    LogicalBlockProxy,
    LogicalBlockVersion,
)
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
)
from d810.hexrays.mutation.semantic_fragment_inventory import (
    SemanticFragmentRootInventory,
    SemanticFragmentRootInventoryItem,
    semantic_fragment_root_group_id,
)
from d810.ir.block_identity import BlockHandleProvenance
from d810.ir.expressions import ValueOpKind
from d810.ir.flowgraph import BlockKind, InsnSnapshot
from d810.ir.predicate_expressions import exact_branch_predicate_kind
from d810.ir.semantic_edge import SemanticEdgeRole
from d810.ir.semantics import PredicateKind, inverted_predicate_kind
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.transforms.fragment_plan import (
    FragmentBlockMaterialization,
    FragmentBlockRole,
    FragmentConditionalSelectEnvelope,
    FragmentImportedConditionalSelectEnvelope,
    FragmentNativeBody,
    FragmentPlan,
    FragmentRangeObservation,
    FragmentReturnCarrier,
    FragmentReturnSource,
    FragmentReturnSourceKind,
    FragmentTerminalReturn,
)
from d810.transforms.fragment_validation import (
    FragmentBindingState,
    FragmentValidationPostcondition,
    PublishedFragmentObservation,
    ProjectedDataFlowRelation,
    ProjectedFallthroughHelper,
    ProjectedFragment,
    ProjectedFragmentBlock,
    ProjectedIdentityBinding,
    ProjectedRangeFact,
    ProjectedRootFallthroughHelper,
    ProjectedTerminalEffectDiagnostic,
    validate_published_fragment_projection,
)

if TYPE_CHECKING:
    from d810.hexrays.mutation.deferred_modifier import DeferredGraphModifier


_BADADDR = 0xFFFFFFFFFFFFFFFF


def _iter_block_instructions(block):
    instruction = block.head
    while instruction is not None:
        yield instruction
        if instruction is block.tail:
            break
        instruction = instruction.next


def _capture_predicate_insn_snapshot(instruction) -> InsnSnapshot:
    """Lift only portable operands, avoiding provenance-owned mop clones."""
    opcode = int(instruction.opcode)
    predicate = branch_predicate_from_opcode(opcode)
    return InsnSnapshot(
        opcode=opcode,
        ea=int(instruction.ea),
        operands=(),
        l=capture_mop_snapshot(instruction.l),
        r=capture_mop_snapshot(instruction.r),
        d=capture_mop_snapshot(instruction.d),
        value_op_kind=value_op_from_opcode(opcode),
        predicate_kind=predicate,
        branch_predicate=predicate,
        is_conditional_jump=predicate is not None,
    )


class SemanticFragmentBackendRejected(RuntimeError):
    """The live backend cannot realize a plan without guessing."""


@dataclass(frozen=True, slots=True)
class SemanticFragmentRuntimeBinding:
    """One exact logical version used by a live fragment transaction."""

    block_id: str
    proxy: LogicalBlockProxy
    version: LogicalBlockVersion
    state: FragmentBindingState


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootEdgeBinding:
    """One serial-free incoming edge whose root authority will change."""

    edge_id: str
    root_block_id: str
    predecessor: SemanticFragmentRuntimeBinding
    original: SemanticFragmentRuntimeBinding
    replacement: SemanticFragmentRuntimeBinding
    role: SemanticEdgeRole
    requires_helper: bool
    publication_helper: SemanticFragmentRuntimeBinding | None = None


@dataclass(frozen=True, slots=True)
class SemanticFragmentRootPublicationGroup:
    """One predecessor-atomic root authority change."""

    group_id: str
    predecessor: SemanticFragmentRuntimeBinding
    edges: tuple[SemanticFragmentRootEdgeBinding, ...]
    original_predecessor_type: int
    original_predecessor_flags: int
    original_conditional_opcode: int | None = None
    original_call_opcode: int | None = None
    original_taken: SemanticFragmentRuntimeBinding | None = None
    original_fallthrough: SemanticFragmentRuntimeBinding | None = None

    @property
    def conditional(self) -> bool:
        return self.original_conditional_opcode is not None

    @property
    def call_fallthrough(self) -> bool:
        return self.original_call_opcode is not None


@dataclass(slots=True)
class SemanticFragmentRootPublicationToken:
    """Complete rollback authority captured before the first root write."""

    plan_id: str
    atomic_group_id: str
    groups: tuple[SemanticFragmentRootPublicationGroup, ...]
    attempted_group_ids: list[str] = field(default_factory=list)

    def group(self, group_id: str) -> SemanticFragmentRootPublicationGroup:
        for group in self.groups:
            if group.group_id == group_id:
                return group
        raise SemanticFragmentBackendRejected(
            f"root publication token has no group {group_id!r}"
        )


@dataclass(slots=True)
class SemanticFragmentBackendState:
    """Transaction-local serial-free bindings for one staged fragment."""

    plan_id: str
    atomic_group_id: str
    bindings: dict[str, SemanticFragmentRuntimeBinding] = field(default_factory=dict)
    staged_block_ids: list[str] = field(default_factory=list)
    fallthrough_helpers: list[ProjectedFallthroughHelper] = field(default_factory=list)
    root_fallthrough_helpers: list[ProjectedRootFallthroughHelper] = field(
        default_factory=list
    )
    instruction_origins_by_block_id: dict[str, dict[int, int]] = field(
        default_factory=dict
    )
    original_mba_outline_ranges: tuple[tuple[int, int], ...] | None = None
    staged_mba_outline_ranges: tuple[tuple[int, int], ...] = ()
    original_mba_had_outlines: bool | None = None
    projection: ProjectedFragment | None = None

    def binding(self, block_id: str) -> SemanticFragmentRuntimeBinding:
        try:
            return self.bindings[str(block_id)]
        except KeyError as exc:
            raise SemanticFragmentBackendRejected(
                f"fragment block {block_id!r} has no live logical binding"
            ) from exc

    def live_instruction_ea(self, block_id: str, native_ea: int) -> int:
        """Resolve one portable native anchor to its transaction-local live EA."""
        native_ea = int(native_ea)
        matches = tuple(
            live_ea
            for live_ea, candidate_native_ea in self.instruction_origins_by_block_id.get(
                str(block_id),
                {},
            ).items()
            if int(candidate_native_ea) == native_ea
        )
        if len(matches) > 1:
            raise SemanticFragmentBackendRejected(
                f"fragment instruction origin is ambiguous at "
                f"{block_id}@0x{native_ea:X}"
            )
        return native_ea if not matches else int(matches[0])


@runtime_checkable
class SemanticNativeBodyMaterializer(Protocol):
    """Backend adapter that populates one gateway-owned native body staging context."""

    def stage_native_body(
        self,
        *,
        context: "SemanticNativeBodyStagingContext",
        native_body: FragmentNativeBody,
    ) -> None:
        """Populate every block in ``native_body`` without publishing authority."""


@dataclass(slots=True)
class SemanticNativeBodyStagingContext:
    """Gateway-owned staging surface for one closed imported native body."""

    _modifier: DeferredGraphModifier
    plan: FragmentPlan
    native_body: FragmentNativeBody
    reference_version: LogicalBlockVersion
    state: SemanticFragmentBackendState
    transaction_id: str
    _receipt_count: int
    _identity_generation: int
    _staged_block_ids: list[str] = field(default_factory=list)
    _populated_block_ids: list[str] = field(default_factory=list)

    def stage_block(self, block_id: str):
        """Create, bind, and return one unpublished imported-native block."""
        block_id = str(block_id)
        if block_id not in self.native_body.block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} does not own "
                f"fragment block {block_id!r}"
            )
        if block_id in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} was staged more than once"
            )
        block = self.plan.block(block_id)
        if (
            block.role is not FragmentBlockRole.IMPORTED
            or block.materialization is not FragmentBlockMaterialization.IMPORT_NATIVE
            or block.native_body_id != self.native_body.body_id
            or block.stable_identity is None
        ):
            raise SemanticFragmentBackendRejected(
                f"fragment block {block_id!r} is not an imported member of "
                f"native body {self.native_body.body_id!r}"
            )

        version = self._modifier._stage_imported_native_semantic_block(
            reference_version=self.reference_version,
            stable_identity=block.stable_identity,
        )
        if (
            version.handle.provenance is not BlockHandleProvenance.IMPORTED_NATIVE
            or version.handle.stable_identity != block.stable_identity
        ):
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} received the wrong logical identity"
            )
        gateway = _gateway(self._modifier)
        proxy = gateway.identity_index.logical_proxy_for_handle(version.handle)
        if proxy is None:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} has no logical proxy"
            )
        if proxy.resolve() is not None:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} exposed published authority"
            )
        if proxy.resolve(transaction_id=self.transaction_id) is not version:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} lacks its staged logical version"
            )
        binding = SemanticFragmentRuntimeBinding(
            block_id=block_id,
            proxy=proxy,
            version=version,
            state=FragmentBindingState.STAGED,
        )
        self.state.bindings[block_id] = binding
        self.state.staged_block_ids.append(block_id)
        self._staged_block_ids.append(block_id)
        return _live_block_for_binding(self._modifier, binding)

    def populate_block(
        self,
        *,
        block_id: str,
        instructions: tuple[tuple[int, object], ...],
        block_flags: int,
    ) -> None:
        """Populate one staged block through the central mutation backend."""
        block_id = str(block_id)
        if block_id not in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body population references unstaged block {block_id!r}"
            )
        if block_id in self._populated_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body block {block_id!r} was populated more than once"
            )
        origin_bindings = (
            self._modifier._populate_imported_native_semantic_block(
                version=self.state.binding(block_id).version,
                instructions=instructions,
                block_flags=int(block_flags),
            )
        )
        for live_ea, native_ea in origin_bindings:
            self.bind_instruction_origin(
                block_id=block_id,
                live_ea=live_ea,
                native_ea=native_ea,
            )
        self._populated_block_ids.append(block_id)

    def bind_instruction_origin(
        self,
        *,
        block_id: str,
        live_ea: int,
        native_ea: int,
    ) -> None:
        """Bind one verifier-safe live instruction EA to its portable native origin."""
        block_id = str(block_id)
        live_ea = int(live_ea)
        native_ea = int(native_ea)
        if block_id not in self._staged_block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin references unstaged block {block_id!r}"
            )
        block = self.plan.block(block_id)
        identity = block.stable_identity
        if (
            identity is None
            or live_ea < 0
            or live_ea >= _BADADDR
            or native_ea < 0
            or native_ea >= _BADADDR
            or not identity.native_ranges.contains(native_ea)
        ):
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin is outside {block_id!r}"
            )
        live_block = _live_block_for_binding(
            self._modifier,
            self.state.binding(block_id),
        )
        matching_instructions = tuple(
            instruction
            for instruction in _iter_block_instructions(live_block)
            if int(getattr(instruction, "ea", -1) or -1) == live_ea
        )
        if len(matching_instructions) != 1:
            raise SemanticFragmentBackendRejected(
                f"native body live instruction is ambiguous at {block_id}@0x{live_ea:X}"
            )
        origins = self.state.instruction_origins_by_block_id.setdefault(
            block_id,
            {},
        )
        if live_ea in origins:
            raise SemanticFragmentBackendRejected(
                f"native body instruction origin was bound more than once at "
                f"{block_id}@0x{native_ea:X}"
            )
        origins[live_ea] = native_ea

    def validate_complete(self) -> None:
        """Reject partial bodies or materializers that changed publication authority."""
        if tuple(self._staged_block_ids) != self.native_body.block_ids:
            raise SemanticFragmentBackendRejected(
                f"native body {self.native_body.body_id!r} staged blocks "
                f"{tuple(self._staged_block_ids)!r}, expected "
                f"{self.native_body.block_ids!r}"
            )
        for block_id in self._staged_block_ids:
            live_block = _live_block_for_binding(
                self._modifier,
                self.state.binding(block_id),
            )
            live_eas = tuple(
                int(getattr(instruction, "ea", -1) or -1)
                for instruction in _iter_block_instructions(live_block)
            )
            bound_live_eas = set(
                self.state.instruction_origins_by_block_id.get(block_id, {})
            )
            if (
                len(set(live_eas)) != len(live_eas)
                or any(live_ea < 0 or live_ea >= _BADADDR for live_ea in live_eas)
                or set(live_eas) != bound_live_eas
            ):
                raise SemanticFragmentBackendRejected(
                    f"native body {self.native_body.body_id!r} has an "
                    f"unbound live instruction in {block_id!r}"
                )
            for live_ea, native_ea in (
                self.state.instruction_origins_by_block_id.get(
                    block_id,
                    {},
                ).items()
            ):
                mapped_ea = int(self._modifier.mba.map_fict_ea(int(live_ea)))
                if mapped_ea != int(native_ea) or not _ranges_cover_interval(
                    _mba_outline_ranges(self._modifier.mba),
                    int(native_ea),
                    int(native_ea) + 1,
                ):
                    raise SemanticFragmentBackendRejected(
                        "native body instruction address is outside live MBA "
                        f"ownership: {block_id}@0x{int(native_ea):X} "
                        f"live=0x{int(live_ea):X} mapped=0x{mapped_ea:X}"
                    )
        gateway = _gateway(self._modifier)
        if gateway.active_batch_id != self.transaction_id:
            raise SemanticFragmentBackendRejected(
                "native body materializer changed the active fragment transaction"
            )
        if len(gateway.receipts) != self._receipt_count:
            raise SemanticFragmentBackendRejected(
                "native body materializer issued an independent mutation receipt"
            )
        if gateway.identity_index.generation != self._identity_generation:
            raise SemanticFragmentBackendRejected(
                "native body materializer changed published identity generation"
            )


def _gateway(modifier: DeferredGraphModifier):
    gateway = modifier._mutation_gateway
    if gateway is None or not gateway.active:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging requires an active mutation gateway"
        )
    return gateway


def _transaction_id(modifier: DeferredGraphModifier) -> str:
    gateway = _gateway(modifier)
    batch_id = gateway.active_batch_id
    if batch_id is None:
        raise SemanticFragmentBackendRejected(
            "semantic fragment staging has no active transaction id"
        )
    return batch_id


def _mba_outline_ranges(mba: object) -> tuple[tuple[int, int], ...]:
    ranges = mba.mbr.ranges
    return tuple(
        (
            int(ranges[index].start_ea),
            int(ranges[index].end_ea),
        )
        for index in range(int(ranges.size()))
    )


def _merge_native_ranges(
    ranges: tuple[tuple[int, int], ...],
) -> tuple[tuple[int, int], ...]:
    merged: list[tuple[int, int]] = []
    for start_ea, end_ea in sorted(
        (int(start_ea), int(end_ea))
        for start_ea, end_ea in ranges
    ):
        if start_ea < 0 or end_ea <= start_ea or end_ea >= _BADADDR:
            raise SemanticFragmentBackendRejected(
                "semantic native-body range is invalid"
            )
        if not merged or start_ea > merged[-1][1]:
            merged.append((start_ea, end_ea))
            continue
        previous_start, previous_end = merged[-1]
        merged[-1] = (
            previous_start,
            max(previous_end, end_ea),
        )
    return tuple(merged)


def _replace_mba_outline_ranges(
    mba: object,
    ranges: tuple[tuple[int, int], ...],
) -> None:
    mba.mbr.ranges.clear()
    for start_ea, end_ea in ranges:
        mba.mbr.ranges.push_back(
            ida_range.range_t(int(start_ea), int(end_ea))
        )


def _ranges_cover_interval(
    ranges: tuple[tuple[int, int], ...],
    start_ea: int,
    end_ea: int,
) -> bool:
    return any(
        int(owned_start) <= int(start_ea)
        and int(end_ea) <= int(owned_end)
        for owned_start, owned_end in ranges
    )


def _stage_native_body_address_ranges(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    requested = tuple(
        (int(native_range.start_ea), int(native_range.end_ea))
        for native_body in plan.native_bodies
        for native_range in native_body.native_ranges
    )
    if not requested:
        return
    if (
        state.original_mba_outline_ranges is not None
        or state.original_mba_had_outlines is not None
    ):
        raise SemanticFragmentBackendRejected(
            "semantic native-body ranges were staged more than once"
        )
    original = _mba_outline_ranges(modifier.mba)
    merged = _merge_native_ranges((*original, *requested))
    had_outlines = bool(
        int(modifier.mba.get_mba_flags2())
        & int(ida_hexrays.MBA2_HAS_OUTLINES)
    )
    state.original_mba_outline_ranges = original
    state.original_mba_had_outlines = had_outlines
    try:
        _replace_mba_outline_ranges(modifier.mba, merged)
        modifier.mba.set_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
        observed = _mba_outline_ranges(modifier.mba)
        if observed != merged or any(
            not _ranges_cover_interval(
                observed,
                int(start_ea),
                int(end_ea),
            )
            for start_ea, end_ea in requested
        ):
            raise SemanticFragmentBackendRejected(
                "semantic native-body range publication was incomplete"
            )
    except Exception:
        _replace_mba_outline_ranges(modifier.mba, original)
        if had_outlines:
            modifier.mba.set_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
        else:
            modifier.mba.clr_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
        raise
    state.staged_mba_outline_ranges = merged


def _restore_native_body_address_ranges(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
) -> None:
    original = state.original_mba_outline_ranges
    had_outlines = state.original_mba_had_outlines
    if original is None or had_outlines is None:
        return
    _replace_mba_outline_ranges(modifier.mba, original)
    if had_outlines:
        modifier.mba.set_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
    else:
        modifier.mba.clr_mba_flags2(int(ida_hexrays.MBA2_HAS_OUTLINES))
    if _mba_outline_ranges(modifier.mba) != original:
        raise SemanticFragmentBackendRejected(
            "semantic native-body range rollback was incomplete"
        )


def _stage_native_bodies(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    *,
    reference_version: LogicalBlockVersion,
) -> None:
    if not plan.native_bodies:
        return
    materializer = modifier._semantic_native_body_materializer
    if materializer is None:
        raise SemanticFragmentBackendRejected(
            "fragment plan requires an imported native-body materializer"
        )
    if not isinstance(materializer, SemanticNativeBodyMaterializer):
        raise TypeError(
            "semantic native-body materializer does not satisfy its backend protocol"
        )
    gateway = _gateway(modifier)
    transaction_id = _transaction_id(modifier)
    _stage_native_body_address_ranges(modifier, plan, state)
    for native_body in plan.native_bodies:
        context = SemanticNativeBodyStagingContext(
            _modifier=modifier,
            plan=plan,
            native_body=native_body,
            reference_version=reference_version,
            state=state,
            transaction_id=transaction_id,
            _receipt_count=len(gateway.receipts),
            _identity_generation=gateway.identity_index.generation,
        )
        materializer.stage_native_body(
            context=context,
            native_body=native_body,
        )
        context.validate_complete()


def _published_binding(
    modifier: DeferredGraphModifier,
    block_id: str,
    stable_identity,
) -> SemanticFragmentRuntimeBinding:
    gateway = _gateway(modifier)
    rebound = gateway.identity_index.rebind_identity(stable_identity)
    if rebound.block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} does not rebind uniquely"
        )
    proxy = gateway.identity_index.logical_proxy_for_handle(rebound.block.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no logical proxy"
        )
    version = proxy.resolve()
    if version is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {block_id!r} has no published version"
        )
    return SemanticFragmentRuntimeBinding(
        block_id=str(block_id),
        proxy=proxy,
        version=version,
        state=FragmentBindingState.PUBLISHED,
    )


def _live_block_for_binding(
    modifier: DeferredGraphModifier,
    binding: SemanticFragmentRuntimeBinding,
):
    gateway = _gateway(modifier)
    bound = gateway.identity_index.resolve_logical_version(
        binding.version,
        transaction_id=_transaction_id(modifier),
    )
    if bound is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} has no transaction-local physical version"
        )
    block = modifier.mba.get_mblock(int(bound.serial))
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} is absent from the live MBA"
        )
    return block


def _clone_replacement(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    replacement_block,
) -> None:
    original_binding = state.binding(str(replacement_block.replaces_block_id))
    staged = modifier._stage_detached_semantic_replacement(
        original_version=original_binding.version,
    )

    state.bindings[replacement_block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=replacement_block.block_id,
        proxy=original_binding.proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
    )
    state.staged_block_ids.append(replacement_block.block_id)


def _normalize_conditional_select_replacement(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    operation,
) -> None:
    """Rewrite one proven live conditional-select only on its detached clone."""
    normalization = operation.computed_branch_normalization
    envelope = (
        None
        if normalization is None
        else normalization.conditional_select_envelope
    )
    if normalization is None or envelope is None:
        return
    if isinstance(envelope, FragmentImportedConditionalSelectEnvelope):
        return
    if not isinstance(envelope, FragmentConditionalSelectEnvelope):
        raise SemanticFragmentBackendRejected(
            "conditional-select normalization has no recognized backend owner"
        )
    source_plan_block = plan.block(operation.source_block_id)
    original_block_id = source_plan_block.replaces_block_id
    if original_block_id is None:
        raise SemanticFragmentBackendRejected(
            "conditional-select normalization source has no replaced original"
        )
    original = _live_block_for_binding(
        modifier,
        state.binding(original_block_id),
    )
    replacement = _live_block_for_binding(
        modifier,
        state.binding(operation.source_block_id),
    )
    selected = _live_block_for_binding(
        modifier,
        state.binding(envelope.selected_value_block_id),
    )
    join = _live_block_for_binding(
        modifier,
        state.binding(envelope.join_block_id),
    )
    label = (
        f"operation={operation.operation_id!r} "
        f"source=blk{int(original.serial)}@0x{int(original.start):X} "
        f"predicate=0x{int(envelope.predicate_ea):X} "
        f"selected=blk{int(selected.serial)}@0x{int(selected.start):X} "
        f"join=blk{int(join.serial)}@0x{int(join.start):X} "
        f"transfer=0x{int(normalization.unresolved_transfer_ea):X}"
    )
    original_instructions = tuple(_iter_block_instructions(original))
    replacement_instructions = tuple(_iter_block_instructions(replacement))
    selected_instructions = tuple(_iter_block_instructions(selected))
    original_tail = original.tail
    replacement_tail = replacement.tail
    join_tail = join.tail
    observed_predicate = exact_branch_predicate_kind(
        tuple(
            _capture_predicate_insn_snapshot(instruction)
            for instruction in original_instructions
        ),
        condition_producer_ea=int(normalization.condition_producer_ea),
    )
    replacement_predicate = exact_branch_predicate_kind(
        tuple(
            _capture_predicate_insn_snapshot(instruction)
            for instruction in replacement_instructions
        ),
        condition_producer_ea=int(normalization.condition_producer_ea),
    )
    explicit_target = (
        None
        if original_tail is None
        or int(original_tail.d.t) != int(ida_hexrays.mop_b)
        else int(original_tail.d.b)
    )
    original_successors = tuple(int(value) for value in original.succset)
    nonexplicit_targets = tuple(
        serial
        for serial in original_successors
        if explicit_target is not None and serial != explicit_target
    )
    semantic_true_target = None
    if observed_predicate is normalization.predicate_kind:
        semantic_true_target = explicit_target
    elif (
        observed_predicate is not None
        and inverted_predicate_kind(observed_predicate)
        is normalization.predicate_kind
        and len(nonexplicit_targets) == 1
    ):
        semantic_true_target = nonexplicit_targets[0]
    condition_indexes = tuple(
        index
        for index, instruction in enumerate(replacement_instructions)
        if int(instruction.ea) == int(normalization.condition_producer_ea)
    )
    cut_indexes = tuple(
        index
        for index, instruction in enumerate(replacement_instructions)
        if int(instruction.ea) == int(operation.predicate_anchor_ea)
    )
    if (
        int(original.type) != int(ida_hexrays.BLT_2WAY)
        or set(original_successors) != {int(selected.serial), int(join.serial)}
        or explicit_target is None
        or len(nonexplicit_targets) != 1
        or original.nextb is None
        or int(original.nextb.serial) != nonexplicit_targets[0]
        or observed_predicate is not envelope.observed_predicate_kind
        or semantic_true_target != int(selected.serial)
        or original_tail is None
        or int(original_tail.ea) != int(envelope.predicate_ea)
        or replacement_tail is None
        or int(replacement_tail.ea) != int(envelope.predicate_ea)
        or replacement_predicate is not envelope.observed_predicate_kind
        or tuple(
            (int(instruction.ea), int(instruction.opcode))
            for instruction in replacement_instructions
        )
        != tuple(
            (int(instruction.ea), int(instruction.opcode))
            for instruction in original_instructions
        )
        or int(selected.type) != int(ida_hexrays.BLT_1WAY)
        or tuple(int(value) for value in selected.succset)
        != (int(join.serial),)
        or tuple(int(value) for value in selected.predset)
        != (int(original.serial),)
        or selected.nextb is None
        or int(selected.nextb.serial) != int(join.serial)
        or len(selected_instructions) != 1
        or value_op_from_opcode(int(selected_instructions[0].opcode))
        is not ValueOpKind.MOVE
        or int(selected_instructions[0].ea) != int(envelope.predicate_ea)
        or set(int(value) for value in join.predset)
        != {int(original.serial), int(selected.serial)}
        or int(join.type) != int(ida_hexrays.BLT_0WAY)
        or join_tail is None
        or int(join_tail.opcode) != int(ida_hexrays.m_ijmp)
        or int(join_tail.ea) != int(normalization.unresolved_transfer_ea)
        or not condition_indexes
        or len(cut_indexes) != 1
        or max(condition_indexes) >= cut_indexes[0]
        or cut_indexes[0] >= len(replacement_instructions) - 1
    ):
        raise SemanticFragmentBackendRejected(
            "live conditional-select envelope changed before detached "
            f"normalization; {label}"
        )
    branch = ida_hexrays.minsn_t(replacement_tail)
    branch.ea = int(operation.predicate_anchor_ea)
    if int(branch.opcode) == int(ida_hexrays.m_jcnd):
        expression = (
            None
            if int(branch.l.t) != int(ida_hexrays.mop_d)
            else branch.l.d
        )
        if (
            observed_predicate is normalization.predicate_kind
        ):
            pass
        elif (
            observed_predicate is PredicateKind.SGE
            and normalization.predicate_kind is PredicateKind.SLT
            and expression is not None
            and int(expression.opcode) == int(ida_hexrays.m_lnot)
            and int(expression.l.t) == int(ida_hexrays.mop_d)
        ):
            oriented_condition = ida_hexrays.mop_t()
            oriented_condition.assign(expression.l)
            if int(oriented_condition.t) == int(ida_hexrays.mop_z):
                raise SemanticFragmentBackendRejected(
                    "live conditional-select inner predicate could not be "
                    f"cloned independently; {label}"
                )
            branch.l.assign(oriented_condition)
        else:
            raise SemanticFragmentBackendRejected(
                "live conditional-select truthiness predicate cannot be "
                f"oriented exactly; {label}"
            )
    else:
        branch_opcode = branch_opcode_for_predicate(
            normalization.predicate_kind
        )
        if branch_opcode is None:
            raise SemanticFragmentBackendRejected(
                "live conditional-select predicate has no Hex-Rays branch "
                f"opcode; {label}"
            )
        branch.opcode = int(branch_opcode)
    modifier.replace_instruction_suffix_now(
        replacement,
        cut_ea=int(operation.predicate_anchor_ea),
        replacement=branch,
    )


def _normalize_replacement_computed_branches(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    for operation in plan.operations:
        normalization = operation.computed_branch_normalization
        if (
            normalization is None
            or normalization.conditional_select_envelope is None
        ):
            continue
        _normalize_conditional_select_replacement(
            modifier,
            plan,
            state,
            operation,
        )


def _create_empty_block(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    block,
    *,
    reference_version: LogicalBlockVersion,
) -> None:
    staged = modifier._stage_empty_semantic_block(
        reference_version=reference_version,
    )
    gateway = _gateway(modifier)
    proxy = gateway.identity_index.logical_proxy_for_handle(staged.handle)
    if proxy is None:
        raise SemanticFragmentBackendRejected(
            f"synthetic fragment block {block.block_id!r} has no logical proxy"
        )
    state.bindings[block.block_id] = SemanticFragmentRuntimeBinding(
        block_id=block.block_id,
        proxy=proxy,
        version=staged,
        state=FragmentBindingState.STAGED,
    )
    state.staged_block_ids.append(block.block_id)


def _realize_operations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    for operation in plan.operations:
        source = state.binding(operation.source_block_id)
        direct_rewrite_anchor_ea = (
            state.live_instruction_ea(
                operation.source_block_id,
                plan.block(operation.source_block_id).semantic_anchor_ea,
            )
            if len(operation.edges) == 1
            and operation.edges[0].role is SemanticEdgeRole.DIRECT
            else None
        )
        helper_version = modifier._realize_semantic_edge_operation(
            LogicalSemanticEdgeOperation(
                source=source.proxy,
                edges=tuple(
                    LogicalSemanticEdge(
                        role=edge.role,
                        target=state.binding(edge.target_block_id).proxy,
                    )
                    for edge in operation.edges
                ),
                predicate_anchor_ea=(
                    None
                    if operation.predicate_anchor_ea is None
                    else state.live_instruction_ea(
                        operation.source_block_id,
                        operation.predicate_anchor_ea,
                    )
                ),
                rewrite_anchor_ea=direct_rewrite_anchor_ea,
                description=f"fragment operation {operation.operation_id}",
            )
        )
        helper_edges = tuple(
            edge
            for edge in operation.edges
            if edge.role
            in {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        )
        if not helper_edges:
            if helper_version is not None:
                raise SemanticFragmentBackendRejected(
                    "semantic fragment operation unexpectedly created a helper"
                )
            continue
        if len(helper_edges) != 1 or helper_version is None:
            raise SemanticFragmentBackendRejected(
                "semantic fallthrough operation did not create exactly one helper"
            )
        helper_block_id = f"fallthrough-helper:{operation.operation_id}"
        if helper_block_id in state.bindings:
            raise SemanticFragmentBackendRejected(
                f"semantic fallthrough helper id collision: {helper_block_id!r}"
            )
        gateway = _gateway(modifier)
        helper_proxy = gateway.identity_index.logical_proxy_for_handle(
            helper_version.handle
        )
        if helper_proxy is None:
            raise SemanticFragmentBackendRejected(
                "semantic fallthrough helper has no logical proxy"
            )
        state.bindings[helper_block_id] = SemanticFragmentRuntimeBinding(
            block_id=helper_block_id,
            proxy=helper_proxy,
            version=helper_version,
            state=FragmentBindingState.STAGED,
        )
        state.staged_block_ids.append(helper_block_id)
        fallthrough_target = helper_edges[0].target_block_id
        state.fallthrough_helpers.append(
            ProjectedFallthroughHelper(
                helper_block_id=helper_block_id,
                operation_id=operation.operation_id,
                source_block_id=operation.source_block_id,
                semantic_target_block_id=fallthrough_target,
            )
        )


def _block_kind(block_type: int) -> BlockKind:
    return {
        int(ida_hexrays.BLT_NONE): BlockKind.NONE,
        int(ida_hexrays.BLT_STOP): BlockKind.STOP,
        int(ida_hexrays.BLT_XTRN): BlockKind.EXTERNAL,
        int(ida_hexrays.BLT_0WAY): BlockKind.ZERO_WAY,
        int(ida_hexrays.BLT_1WAY): BlockKind.ONE_WAY,
        int(ida_hexrays.BLT_2WAY): BlockKind.TWO_WAY,
        int(ida_hexrays.BLT_NWAY): BlockKind.N_WAY,
    }.get(int(block_type), BlockKind.UNKNOWN)


def _instruction_eas(
    block,
    instruction_origins: dict[int, int] | None = None,
) -> tuple[int, ...]:
    instruction_origins = instruction_origins or {}
    result: list[int] = []
    for instruction in _iter_block_instructions(block):
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        ea = int(instruction_origins.get(live_ea, live_ea))
        if 0 <= ea < _BADADDR and ea not in result:
            result.append(ea)
    return tuple(result)


_RETURN_CARRIER_OPCODES = {
    ValueOpKind.MOVE: int(ida_hexrays.m_mov),
    ValueOpKind.ZEXT: int(ida_hexrays.m_xdu),
    ValueOpKind.SEXT: int(ida_hexrays.m_xds),
}


def _return_mreg() -> int:
    try:
        return int(ida_hexrays.reg2mreg(0))
    except Exception as exc:
        raise SemanticFragmentBackendRejected(
            "Hex-Rays return-register identity is unavailable"
        ) from exc


def _native_instruction_rows(
    state: SemanticFragmentBackendState,
    block_id: str,
    block,
) -> tuple[tuple[int, object], ...]:
    origins = state.instruction_origins_by_block_id.get(str(block_id), {})
    rows: list[tuple[int, object]] = []
    for instruction in _iter_block_instructions(block):
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        native_ea = int(origins.get(live_ea, live_ea))
        if 0 <= native_ea < _BADADDR:
            rows.append((native_ea, instruction))
    return tuple(rows)


def _bind_synthesized_instruction_origin(
    state: SemanticFragmentBackendState,
    *,
    block_id: str,
    live_ea: int,
    native_ea: int,
) -> None:
    block_id = str(block_id)
    live_ea = int(live_ea)
    native_ea = int(native_ea)
    origins = state.instruction_origins_by_block_id.setdefault(block_id, {})
    if live_ea in origins or native_ea in origins.values():
        raise SemanticFragmentBackendRejected(
            f"semantic fragment instruction origin is ambiguous at "
            f"{block_id}@0x{native_ea:X}"
        )
    origins[live_ea] = native_ea


def _storage_operand(
    mba,
    storage: StorageIdentity,
    *,
    width: int,
):
    operand = ida_hexrays.mop_t()
    if storage.kind is StorageIdentityKind.GLOBAL:
        operand.make_gvar(int(storage.offset))
    elif storage.kind is StorageIdentityKind.STACK:
        try:
            vd_offset = int(mba.stkoff_ida2vd(int(storage.offset)))
        except Exception as exc:
            raise SemanticFragmentBackendRejected(
                "fragment return stack source cannot bind to the live MBA"
            ) from exc
        operand.make_stkvar(mba, vd_offset)
    else:
        raise SemanticFragmentBackendRejected(
            "fragment return source has unsupported storage identity"
        )
    operand.size = int(width)
    return operand


def _return_source_operand(
    mba,
    source: FragmentReturnSource,
    *,
    live_ea: int,
):
    operand = ida_hexrays.mop_t()
    if source.kind is FragmentReturnSourceKind.CONSTANT:
        operand.make_number(
            int(source.constant),
            int(source.width),
            int(live_ea),
        )
        return operand

    storage = source.storage_identity
    if storage is None:
        raise SemanticFragmentBackendRejected(
            "fragment return source lost its storage identity"
        )
    inner = _storage_operand(mba, storage, width=source.width)
    if source.kind is FragmentReturnSourceKind.STORAGE_VALUE:
        operand.assign(inner)
        return operand
    if source.kind is not FragmentReturnSourceKind.ADDRESS_OF_STORAGE:
        raise SemanticFragmentBackendRejected(
            "fragment return source has unsupported portable kind"
        )
    try:
        address = ida_hexrays.mop_addr_t(
            inner,
            int(source.width),
            int(source.width),
        )
        operand.assign(address)
        operand.size = int(source.width)
    except Exception as exc:
        raise SemanticFragmentBackendRejected(
            "fragment return address source cannot be materialized"
        ) from exc
    return operand


def _stack_identity_from_operand(mba, operand) -> StorageIdentity | None:
    stack_ref = getattr(operand, "s", None)
    if stack_ref is None:
        return None
    try:
        ida_offset = int(mba.stkoff_vd2ida(int(stack_ref.off)))
    except Exception:
        return None
    if ida_offset < 0:
        return None
    return StorageIdentity(StorageIdentityKind.STACK, ida_offset)


def _storage_identity_from_operand(mba, operand) -> StorageIdentity | None:
    operand_type = int(getattr(operand, "t", -1))
    if operand_type == int(ida_hexrays.mop_v):
        offset = int(getattr(operand, "g", -1))
        if offset < 0:
            return None
        return StorageIdentity(StorageIdentityKind.GLOBAL, offset)
    if operand_type == int(ida_hexrays.mop_S):
        return _stack_identity_from_operand(mba, operand)
    return None


def _observed_return_source(mba, operand) -> FragmentReturnSource | None:
    operand_type = int(getattr(operand, "t", -1))
    width = int(getattr(operand, "size", 0))
    try:
        if operand_type == int(ida_hexrays.mop_n):
            number = getattr(operand, "nnn", None)
            if number is None:
                return None
            return FragmentReturnSource(
                kind=FragmentReturnSourceKind.CONSTANT,
                width=width,
                constant=int(number.value),
            )
        storage = _storage_identity_from_operand(mba, operand)
        if storage is not None:
            return FragmentReturnSource(
                kind=FragmentReturnSourceKind.STORAGE_VALUE,
                width=width,
                storage_identity=storage,
            )
        if operand_type != int(ida_hexrays.mop_a):
            return None
        address = getattr(operand, "a", None)
        inner = None if address is None else getattr(address, "v", None)
        if inner is None:
            inner = address
        storage = _storage_identity_from_operand(mba, inner)
        if storage is None:
            return None
        return FragmentReturnSource(
            kind=FragmentReturnSourceKind.ADDRESS_OF_STORAGE,
            width=width,
            storage_identity=storage,
        )
    except (TypeError, ValueError):
        return None


def _diagnose_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
    block,
) -> tuple[FragmentReturnCarrier | None, str]:
    rows = _native_instruction_rows(state, planned.block_id, block)
    carrier_matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.carrier_ea
    )
    if len(carrier_matches) == 1:
        carrier_index = carrier_matches[0]
        state_matches = tuple(
            index
            for index, (native_ea, _instruction) in enumerate(rows)
            if native_ea == planned.state_write_ea and index < carrier_index
        )
    else:
        carrier_index = -1
        state_matches = ()
    if len(state_matches) != 1 or len(carrier_matches) != 1:
        row_coordinates = tuple(
            (
                hex(native_ea),
                hex(int(getattr(instruction, "ea", -1) or -1)),
                int(getattr(instruction, "opcode", -1)),
            )
            for native_ea, instruction in rows
        )
        return (
            None,
            f"anchor_cardinality state_before_carrier={len(state_matches)} "
            f"carrier={len(carrier_matches)} rows={row_coordinates!r}",
        )
    state_index = state_matches[0]
    instruction = rows[carrier_index][1]
    operation = value_op_from_opcode(int(getattr(instruction, "opcode", -1)))
    destination = getattr(instruction, "d", None)
    right = getattr(instruction, "r", None)
    if operation not in _RETURN_CARRIER_OPCODES:
        return (
            None,
            f"unsupported_opcode={int(getattr(instruction, 'opcode', -1))}",
        )
    if destination is None:
        return None, "destination_missing"
    destination_type = int(getattr(destination, "t", -1))
    if destination_type != int(ida_hexrays.mop_r):
        return None, f"destination_type={destination_type}"
    destination_register = int(getattr(destination, "r", -1))
    expected_register = _return_mreg()
    if destination_register != expected_register:
        return (
            None,
            f"destination_register={destination_register} expected={expected_register}",
        )
    destination_width = int(getattr(destination, "size", 0))
    if destination_width <= 0:
        return None, f"destination_width={destination_width}"
    right_type = int(getattr(right, "t", -1)) if right is not None else -1
    if right_type != int(ida_hexrays.mop_z):
        return None, f"right_operand_type={right_type}"
    source = _observed_return_source(modifier.mba, getattr(instruction, "l", None))
    if source is None:
        left = getattr(instruction, "l", None)
        return (
            None,
            f"source_unavailable type={int(getattr(left, 't', -1))} "
            f"width={int(getattr(left, 'size', 0))}",
        )
    try:
        return (
            FragmentReturnCarrier(
                carrier_id=planned.carrier_id,
                block_id=planned.block_id,
                state_write_ea=rows[state_index][0],
                carrier_ea=rows[carrier_index][0],
                operation=operation,
                source=source,
                return_width=int(destination.size),
                corridor_instruction_eas=tuple(
                    native_ea
                    for native_ea, _instruction in rows[state_index : carrier_index + 1]
                ),
            ),
            "matched",
        )
    except (TypeError, ValueError) as exc:
        return None, f"portable_carrier_rejected={type(exc).__name__}"


def _observe_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
    block,
) -> FragmentReturnCarrier | None:
    observed, _reason = _diagnose_return_carrier(
        modifier,
        state,
        planned,
        block,
    )
    return observed


def _project_return_carriers(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
) -> tuple[FragmentReturnCarrier, ...]:
    observed: list[FragmentReturnCarrier] = []
    for planned in plan.return_carriers:
        block = live_by_id.get(planned.block_id)
        if block is None:
            continue
        carrier = _observe_return_carrier(modifier, state, planned, block)
        if carrier is not None:
            observed.append(carrier)
    return tuple(observed)


def _project_terminal_effect_diagnostics(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
) -> tuple[ProjectedTerminalEffectDiagnostic, ...]:
    diagnostics: list[ProjectedTerminalEffectDiagnostic] = []
    for planned in plan.return_carriers:
        block = live_by_id.get(planned.block_id)
        if block is None:
            diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=planned.carrier_id,
                    reason="live_block_missing",
                )
            )
            continue
        carrier, reason = _diagnose_return_carrier(
            modifier,
            state,
            planned,
            block,
        )
        if carrier is None:
            diagnostics.append(
                ProjectedTerminalEffectDiagnostic(
                    effect_id=planned.carrier_id,
                    reason=reason,
                )
            )
    return tuple(diagnostics)


def _observe_terminal_return(
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    planned: FragmentTerminalReturn,
    block,
    observed_carriers: tuple[FragmentReturnCarrier, ...],
) -> FragmentTerminalReturn | None:
    rows = _native_instruction_rows(state, planned.block_id, block)
    matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.instruction_ea
    )
    if len(matches) != 1 or matches[0] != len(rows) - 1:
        return None
    instruction = rows[matches[0]][1]
    if (
        int(getattr(instruction, "opcode", -1)) != int(ida_hexrays.m_ret)
        or any(
            int(getattr(getattr(instruction, slot, None), "t", -1))
            != int(ida_hexrays.mop_z)
            for slot in ("l", "r", "d")
        )
        or int(block.type) != int(ida_hexrays.BLT_0WAY)
        or tuple(int(value) for value in block.succset)
    ):
        return None

    carrier_by_id = {
        carrier.carrier_id: carrier for carrier in observed_carriers
    }
    linked_routes = tuple(
        route for route in plan.terminal_routes if route.return_id == planned.return_id
    )
    linked_carriers = tuple(
        carrier_by_id.get(route.carrier_id) for route in linked_routes
    )
    if (
        not linked_carriers
        or any(carrier is None for carrier in linked_carriers)
        or len({carrier.return_width for carrier in linked_carriers if carrier}) != 1
    ):
        return None
    return_width = next(
        carrier.return_width for carrier in linked_carriers if carrier is not None
    )
    try:
        return FragmentTerminalReturn(
            return_id=planned.return_id,
            block_id=planned.block_id,
            instruction_ea=rows[matches[0]][0],
            return_width=return_width,
        )
    except (TypeError, ValueError):
        return None


def _project_terminal_returns(
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    observed_carriers: tuple[FragmentReturnCarrier, ...],
) -> tuple[FragmentTerminalReturn, ...]:
    observed: list[FragmentTerminalReturn] = []
    for planned in plan.terminal_returns:
        block = live_by_id.get(planned.block_id)
        if block is None:
            continue
        terminal_return = _observe_terminal_return(
            plan,
            state,
            planned,
            block,
            observed_carriers,
        )
        if terminal_return is not None:
            observed.append(terminal_return)
    return tuple(observed)


def _materialize_return_carrier(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    planned: FragmentReturnCarrier,
) -> None:
    block = _live_block_for_binding(modifier, state.binding(planned.block_id))
    rows = _native_instruction_rows(state, planned.block_id, block)
    carrier_matches = tuple(
        instruction
        for native_ea, instruction in rows
        if native_ea == planned.carrier_ea
    )
    if carrier_matches:
        observed = _observe_return_carrier(modifier, state, planned, block)
        if len(carrier_matches) != 1 or observed != planned:
            raise SemanticFragmentBackendRejected(
                f"fragment return carrier conflicts at "
                f"{planned.block_id}@0x{planned.carrier_ea:X}"
            )
        return

    prefix = planned.corridor_instruction_eas[:-1]
    prefix_positions: list[int] = []
    for native_ea in prefix:
        matches = tuple(
            index
            for index, (candidate_ea, _instruction) in enumerate(rows)
            if candidate_ea == native_ea
        )
        if len(matches) != 1:
            raise SemanticFragmentBackendRejected(
                f"fragment return corridor is ambiguous at "
                f"{planned.block_id}@0x{native_ea:X}"
            )
        prefix_positions.append(matches[0])
    if any(
        following != current + 1
        for current, following in zip(prefix_positions, prefix_positions[1:])
    ):
        raise SemanticFragmentBackendRejected(
            f"fragment return corridor is not contiguous in {planned.block_id!r}"
        )

    live_ea = int(modifier.mba.alloc_fict_ea(planned.carrier_ea))
    try:
        instruction = ida_hexrays.minsn_t(live_ea)
        instruction.opcode = _RETURN_CARRIER_OPCODES[planned.operation]
        source = _return_source_operand(
            modifier.mba,
            planned.source,
            live_ea=live_ea,
        )
        instruction.l.assign(source)
        instruction.r.erase()
        instruction.d.make_reg(_return_mreg(), planned.return_width)
        modifier.insert_instruction_now(
            block,
            instruction,
            rows[prefix_positions[-1]][1],
        )
    except Exception as exc:
        if isinstance(exc, SemanticFragmentBackendRejected):
            raise
        raise SemanticFragmentBackendRejected(
            f"fragment return carrier could not be synthesized at "
            f"{planned.block_id}@0x{planned.carrier_ea:X}"
        ) from exc
    _bind_synthesized_instruction_origin(
        state,
        block_id=planned.block_id,
        live_ea=live_ea,
        native_ea=planned.carrier_ea,
    )
    modifier.mark_blocks_dirty_now(block)
    if _observe_return_carrier(modifier, state, planned, block) != planned:
        raise SemanticFragmentBackendRejected(
            f"fragment return carrier failed live observation at "
            f"{planned.block_id}@0x{planned.carrier_ea:X}"
        )


def _materialize_terminal_return(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    planned: FragmentTerminalReturn,
) -> None:
    block = _live_block_for_binding(modifier, state.binding(planned.block_id))
    if tuple(int(value) for value in block.succset):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return block {planned.block_id!r} has successors"
        )
    rows = _native_instruction_rows(state, planned.block_id, block)
    matches = tuple(
        index
        for index, (native_ea, _instruction) in enumerate(rows)
        if native_ea == planned.instruction_ea
    )
    if len(matches) > 1 or (matches and matches[0] != len(rows) - 1):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return is ambiguous at "
            f"{planned.block_id}@0x{planned.instruction_ea:X}"
        )
    if matches:
        instruction = rows[matches[0]][1]
    else:
        tail = block.tail
        if tail is not None and (
            ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or int(tail.opcode)
            in {
                int(ida_hexrays.m_goto),
                int(ida_hexrays.m_ijmp),
                int(ida_hexrays.m_jtbl),
                int(ida_hexrays.m_call),
                int(ida_hexrays.m_icall),
                int(ida_hexrays.m_ret),
            }
        ):
            raise SemanticFragmentBackendRejected(
                f"fragment terminal return cannot append after a closing "
                f"instruction in {planned.block_id!r}"
            )
        live_ea = int(modifier.mba.alloc_fict_ea(planned.instruction_ea))
        instruction = ida_hexrays.minsn_t(live_ea)
        modifier.insert_instruction_now(block, instruction, block.tail)
        _bind_synthesized_instruction_origin(
            state,
            block_id=planned.block_id,
            live_ea=live_ea,
            native_ea=planned.instruction_ea,
        )
    instruction.opcode = int(ida_hexrays.m_ret)
    instruction.l.erase()
    instruction.r.erase()
    instruction.d.erase()
    modifier.configure_block_now(
        block,
        block_type=int(ida_hexrays.BLT_0WAY),
        flags=(
            int(block.flags)
            & ~int(ida_hexrays.MBL_GOTO)
            & ~int(ida_hexrays.MBL_CALL)
        ),
    )
    modifier.mark_blocks_dirty_now(block)
    observed_carriers = _project_return_carriers(
        modifier,
        plan,
        state,
        {
            carrier.block_id: _live_block_for_binding(
                modifier,
                state.binding(carrier.block_id),
            )
            for carrier in plan.return_carriers
        },
    )
    if (
        _observe_terminal_return(
            plan,
            state,
            planned,
            block,
            observed_carriers,
        )
        != planned
    ):
        raise SemanticFragmentBackendRejected(
            f"fragment terminal return failed live observation at "
            f"{planned.block_id}@0x{planned.instruction_ea:X}"
        )


def _materialize_terminal_effects(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    gateway = _gateway(modifier)
    for carrier in plan.return_carriers:
        _materialize_return_carrier(modifier, state, carrier)
        gateway.record_semantic_fragment_return_carrier(
            carrier_id=carrier.carrier_id,
            block=state.binding(carrier.block_id).version.handle,
        )
    for terminal_return in plan.terminal_returns:
        _materialize_terminal_return(
            modifier,
            plan,
            state,
            terminal_return,
        )
        gateway.record_semantic_fragment_terminal_return(
            return_id=terminal_return.return_id,
            block=state.binding(terminal_return.block_id).version.handle,
        )


def _site_instruction_matches(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
    *,
    context: str,
):
    block = live_by_id.get(site.block_id)
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"{context} {site.site_id!r} has no live block"
        )
    matches = []
    origins = state.instruction_origins_by_block_id.get(str(site.block_id), {})
    instruction = block.head
    while instruction is not None:
        live_ea = int(getattr(instruction, "ea", -1) or -1)
        native_ea = int(origins.get(live_ea, live_ea))
        if native_ea == int(site.instruction_ea):
            matches.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return block, tuple(matches)


def _exact_site_instruction(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
    *,
    context: str,
):
    block, matches = _site_instruction_matches(
        state,
        live_by_id,
        site,
        context=context,
    )
    if len(matches) != 1:
        raise SemanticFragmentBackendRejected(
            f"{context} {site.site_id!r} is ambiguous at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}: "
            f"observed {len(matches)} top-level instructions"
        )
    return block, matches[0]


def _require_logical_flag_producer(
    state: SemanticFragmentBackendState,
    live_by_id: dict[str, object],
    site,
) -> None:
    _block, matches = _site_instruction_matches(
        state,
        live_by_id,
        site,
        context="flag-corridor producer",
    )
    if not matches:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} is missing at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}"
        )
    try:
        writer_count = sum(
            instruction_writes_condition_codes(instruction)
            for instruction in matches
        )
    except ConditionCodeQueryUnavailable as exc:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} cannot be classified at "
            f"{site.block_id}@0x{int(site.instruction_ea):X}"
        ) from exc
    if writer_count == 0:
        raise SemanticFragmentBackendRejected(
            f"flag-corridor producer {site.site_id!r} is not a condition-code "
            f"writer at {site.block_id}@0x{int(site.instruction_ea):X}"
        )


def _require_flag_corridor_sites(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> None:
    for corridor in plan.flag_corridors:
        _require_logical_flag_producer(
            state,
            live_by_id,
            corridor.producer,
        )
        _exact_site_instruction(
            state,
            live_by_id,
            corridor.consumer,
            context="flag-corridor consumer",
        )


def _project_flag_writes(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> dict[str, frozenset[int]]:
    result = {block_id: frozenset() for block_id in live_by_id}
    if not plan.flag_corridors:
        return result
    _require_flag_corridor_sites(state, plan, live_by_id)
    for block_id, block in live_by_id.items():
        try:
            observations = condition_code_write_eas(block)
        except ConditionCodeQueryUnavailable as exc:
            raise SemanticFragmentBackendRejected(
                f"condition-code writes cannot be observed for {block_id}"
            ) from exc
        origins = state.instruction_origins_by_block_id.get(str(block_id), {})
        result[block_id] = frozenset(
            int(origins.get(int(live_ea), int(live_ea)))
            for live_ea in observations
        )
    return result


def _project_value_ranges(
    state: SemanticFragmentBackendState,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
) -> tuple[ProjectedRangeFact, ...]:
    facts: list[ProjectedRangeFact] = []
    for assumption in plan.value_range_assumptions:
        site = assumption.site
        block, instruction = _exact_site_instruction(
            state,
            live_by_id,
            site,
            context="value-range site",
        )
        storage = site.storage_identity
        if storage is None:
            raise SemanticFragmentBackendRejected(
                f"value-range site {site.site_id!r} has no portable storage identity"
            )
        try:
            proof = prove_exact_unsigned_range(
                block,
                instruction,
                storage,
                site.width,
                at_end=(
                    assumption.observation is FragmentRangeObservation.AFTER_INSTRUCTION
                ),
                required_lo=assumption.lo,
                required_hi=assumption.hi,
            )
        except ExactValueRangeQueryUnavailable as exc:
            raise SemanticFragmentBackendRejected(
                f"value range cannot be observed at "
                f"{site.block_id}@0x{int(site.instruction_ea):X}"
            ) from exc
        if proof is not None:
            facts.append(
                ProjectedRangeFact(
                    site_id=site.site_id,
                    value_id=site.value_id,
                    observation=assumption.observation,
                    lo=proof.lo,
                    hi=proof.hi,
                )
            )
    return tuple(facts)


def _unowned_endpoint(modifier: DeferredGraphModifier, serial: int) -> str:
    block = modifier.mba.get_mblock(int(serial))
    if block is not None:
        for candidate in (
            int(getattr(block, "start", -1) or -1),
            int(getattr(getattr(block, "head", None), "ea", -1) or -1),
        ):
            if 0 <= candidate < _BADADDR:
                return f"unowned:blk{int(serial)}@0x{candidate:X}"
    return "unowned@unknown-ea"


def _query_reaching_definitions(
    modifier: DeferredGraphModifier,
    site,
    live_block,
):
    storage = site.storage_identity
    if storage is None:
        raise SemanticFragmentBackendRejected(
            f"data-flow use {site.site_id!r} has no portable storage identity"
        )
    if storage.kind is StorageIdentityKind.REGISTER:
        return find_reaching_defs_for_reg_use(
            modifier.mba,
            int(live_block.serial),
            int(site.instruction_ea),
            int(storage.offset),
            int(site.width),
        )
    if storage.kind is StorageIdentityKind.STACK:
        return find_reaching_defs_for_stkvar_use(
            modifier.mba,
            int(live_block.serial),
            int(site.instruction_ea),
            int(storage.offset),
            int(site.width),
        )
    raise SemanticFragmentBackendRejected(
        f"data-flow use {site.site_id!r} has unsupported storage namespace "
        f"{storage.kind.name.lower()}"
    )


def _query_reached_uses(
    modifier: DeferredGraphModifier,
    site,
    live_block,
):
    storage = site.storage_identity
    if storage is None:
        raise SemanticFragmentBackendRejected(
            f"data-flow definition {site.site_id!r} has no portable storage identity"
        )
    if storage.kind is StorageIdentityKind.REGISTER:
        return find_uses_reached_by_reg_definition(
            modifier.mba,
            int(live_block.serial),
            int(site.instruction_ea),
            int(storage.offset),
            int(site.width),
        )
    if storage.kind is StorageIdentityKind.STACK:
        return find_uses_reached_by_stkvar_definition(
            modifier.mba,
            int(live_block.serial),
            int(site.instruction_ea),
            int(storage.offset),
            int(site.width),
        )
    raise SemanticFragmentBackendRejected(
        f"data-flow definition {site.site_id!r} has unsupported storage namespace "
        f"{storage.kind.name.lower()}"
    )


def _require_unambiguous_observed_anchors(
    modifier: DeferredGraphModifier,
    observations,
    ids_by_serial: dict[int, str],
    *,
    role: str,
) -> None:
    seen: set[tuple[int, int]] = set()
    for observation in observations:
        coordinate = (int(observation.block_serial), int(observation.ins_ea))
        if coordinate not in seen:
            seen.add(coordinate)
            continue
        endpoint = ids_by_serial.get(coordinate[0])
        if endpoint is None:
            endpoint = _unowned_endpoint(modifier, coordinate[0])
        raise SemanticFragmentBackendRejected(
            f"data-flow {role} observation is ambiguous at "
            f"{endpoint}@0x{coordinate[1]:X}"
        )


def _observed_site_id(
    modifier: DeferredGraphModifier,
    observation,
    candidates,
    ids_by_serial: dict[int, str],
    *,
    storage,
    width: int,
    role: str,
) -> str:
    block_serial = int(observation.block_serial)
    instruction_ea = int(observation.ins_ea)
    block_id = ids_by_serial.get(block_serial)
    matches = tuple(
        site
        for site in candidates
        if block_id == site.block_id
        and instruction_ea == int(site.instruction_ea)
        and storage == site.storage_identity
        and int(width) == int(site.width)
    )
    endpoint = (
        block_id if block_id is not None else _unowned_endpoint(modifier, block_serial)
    )
    if len(matches) > 1:
        raise SemanticFragmentBackendRejected(
            f"planned data-flow {role} is ambiguous at {endpoint}@0x{instruction_ea:X}"
        )
    if matches:
        return matches[0].site_id
    return f"unplanned-{role}:{storage.key}:{endpoint}@0x{instruction_ea:X}"


def _project_data_flow_relations(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    live_by_id: dict[str, object],
    ids_by_serial: dict[int, str],
) -> tuple[ProjectedDataFlowRelation, ...]:
    definitions = tuple(
        obligation.definition for obligation in plan.data_flow_obligations
    )
    uses = tuple(
        use for obligation in plan.data_flow_obligations for use in obligation.uses
    )
    relations: set[ProjectedDataFlowRelation] = set()
    for obligation in plan.data_flow_obligations:
        definition = obligation.definition
        storage = definition.storage_identity
        if storage is None:
            raise SemanticFragmentBackendRejected(
                f"data-flow definition {definition.site_id!r} is unbound"
            )
        definition_block = live_by_id.get(definition.block_id)
        if definition_block is None:
            raise SemanticFragmentBackendRejected(
                f"data-flow definition {definition.site_id!r} has no live block"
            )
        reached_uses = tuple(
            _query_reached_uses(modifier, definition, definition_block)
        )
        _require_unambiguous_observed_anchors(
            modifier,
            reached_uses,
            ids_by_serial,
            role="use",
        )
        for observed_use in reached_uses:
            use_site_id = _observed_site_id(
                modifier,
                observed_use,
                uses,
                ids_by_serial,
                storage=storage,
                width=definition.width,
                role="use",
            )
            relations.add(
                ProjectedDataFlowRelation(
                    value_id=definition.value_id,
                    definition_site_id=definition.site_id,
                    use_site_id=use_site_id,
                    use_def_observed=False,
                    def_use_observed=True,
                )
            )

        for use in obligation.uses:
            use_block = live_by_id.get(use.block_id)
            if use_block is None:
                raise SemanticFragmentBackendRejected(
                    f"data-flow use {use.site_id!r} has no live block"
                )
            reaching_definitions = tuple(
                _query_reaching_definitions(modifier, use, use_block)
            )
            _require_unambiguous_observed_anchors(
                modifier,
                reaching_definitions,
                ids_by_serial,
                role="definition",
            )
            for observed_definition in reaching_definitions:
                definition_site_id = _observed_site_id(
                    modifier,
                    observed_definition,
                    definitions,
                    ids_by_serial,
                    storage=storage,
                    width=use.width,
                    role="definition",
                )
                relations.add(
                    ProjectedDataFlowRelation(
                        value_id=definition.value_id,
                        definition_site_id=definition_site_id,
                        use_site_id=use.site_id,
                        use_def_observed=True,
                        def_use_observed=False,
                    )
                )
    return tuple(
        sorted(
            relations,
            key=lambda relation: (
                relation.value_id,
                relation.definition_site_id,
                relation.use_site_id,
                relation.use_def_observed,
                relation.def_use_observed,
            ),
        )
    )


def _project_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
    *,
    simulate_root_publication: bool = True,
) -> ProjectedFragment:
    root_helper_ids = {
        helper.helper_block_id for helper in state.root_fallthrough_helpers
    }
    live_by_id = {}
    for block_id, binding in state.bindings.items():
        live = _try_live_block_for_binding(modifier, binding)
        if live is None:
            if block_id not in root_helper_ids:
                raise SemanticFragmentBackendRejected(
                    f"fragment block {block_id!r} has no live physical version"
                )
            continue
        live_by_id[block_id] = live
    ids_by_serial: dict[int, str] = {}
    for block_id, block in live_by_id.items():
        serial = int(block.serial)
        if serial in ids_by_serial:
            raise SemanticFragmentBackendRejected(
                "two fragment block ids resolve to one physical version"
            )
        ids_by_serial[serial] = block_id

    successors: dict[str, list[str]] = {}
    predecessors: dict[str, list[str]] = {}
    kinds: dict[str, BlockKind] = {}
    physical_positions: dict[str, int] = {}
    instruction_eas: dict[str, tuple[int, ...]] = {}
    for block_id, block in live_by_id.items():
        successors[block_id] = [
            ids_by_serial.get(
                int(serial),
                _unowned_endpoint(modifier, int(serial)),
            )
            for serial in block.succset
        ]
        predecessors[block_id] = [
            ids_by_serial.get(
                int(serial),
                _unowned_endpoint(modifier, int(serial)),
            )
            for serial in block.predset
        ]
        kinds[block_id] = _block_kind(int(block.type))
        physical_positions[block_id] = int(block.serial)
        instruction_eas[block_id] = _instruction_eas(
            block,
            state.instruction_origins_by_block_id.get(block_id),
        )
    flag_write_eas = _project_flag_writes(state, plan, live_by_id)

    if simulate_root_publication:
        for root_id in plan.roots:
            replacement = plan.block(root_id)
            original_id = str(replacement.replaces_block_id)
            for predecessor_id in tuple(predecessors[original_id]):
                if predecessor_id not in successors:
                    raise SemanticFragmentBackendRejected(
                        "root predecessor is outside the closed fragment projection"
                    )
                role = _incoming_root_edge_role(
                    live_by_id[predecessor_id],
                    live_by_id[original_id],
                )
                requires_helper = _root_edge_requires_helper(
                    live_by_id[predecessor_id],
                    live_by_id[original_id],
                    role,
                )
                predecessors[original_id].remove(predecessor_id)
                projected_target_id = root_id
                if requires_helper:
                    matching_helpers = tuple(
                        helper
                        for helper in state.root_fallthrough_helpers
                        if helper.source_block_id == predecessor_id
                        and helper.root_block_id == root_id
                    )
                    if len(matching_helpers) != 1:
                        raise SemanticFragmentBackendRejected(
                            "physical root fallthrough lacks one reserved helper"
                        )
                    helper = matching_helpers[0]
                    helper_id = helper.helper_block_id
                    insertion_position = physical_positions[predecessor_id] + 1
                    for block_id, position in tuple(physical_positions.items()):
                        if position >= insertion_position:
                            physical_positions[block_id] = position + 1
                    kinds[helper_id] = BlockKind.ONE_WAY
                    physical_positions[helper_id] = insertion_position
                    instruction_eas[helper_id] = ()
                    flag_write_eas[helper_id] = frozenset()
                    successors[helper_id] = [root_id]
                    predecessors[helper_id] = [predecessor_id]
                    predecessors[root_id].append(helper_id)
                    projected_target_id = helper_id
                else:
                    predecessors[root_id].append(predecessor_id)
                successors[predecessor_id] = [
                    projected_target_id if target_id == original_id else target_id
                    for target_id in successors[predecessor_id]
                ]

    entry_ids = tuple(
        block_id for block_id, block in live_by_id.items() if int(block.serial) == 0
    )
    if len(entry_ids) != 1:
        raise SemanticFragmentBackendRejected(
            "fragment plan must own exactly one projected function entry"
        )

    projected_blocks = tuple(
        ProjectedFragmentBlock(
            block_id=block_id,
            kind=kinds[block_id],
            successors=tuple(successors[block_id]),
            predecessors=tuple(predecessors[block_id]),
            physical_position=physical_positions[block_id],
            instruction_eas=instruction_eas[block_id],
            flag_write_eas=flag_write_eas[block_id],
        )
        for block_id in successors
    )
    projected_bindings = tuple(
        ProjectedIdentityBinding(
            block_id=binding.block_id,
            logical_owner_id=binding.proxy.proxy_token,
            version=binding.version.version_id.version,
            generation=binding.version.generation,
            state=binding.state,
            stable_identity=binding.version.handle.stable_identity,
            previous_version=(
                None
                if binding.version.predecessor_version_id is None
                else binding.version.predecessor_version_id.version
            ),
        )
        for binding in state.bindings.values()
    )
    data_flow_relations = _project_data_flow_relations(
        modifier,
        plan,
        live_by_id,
        ids_by_serial,
    )
    value_ranges = _project_value_ranges(state, plan, live_by_id)
    return_carriers = _project_return_carriers(
        modifier,
        plan,
        state,
        live_by_id,
    )
    terminal_effect_diagnostics = _project_terminal_effect_diagnostics(
        modifier,
        plan,
        state,
        live_by_id,
    )
    terminal_returns = _project_terminal_returns(
        plan,
        state,
        live_by_id,
        return_carriers,
    )
    return ProjectedFragment(
        entry_block_id=entry_ids[0],
        blocks=projected_blocks,
        identity_bindings=projected_bindings,
        fallthrough_helpers=tuple(state.fallthrough_helpers),
        root_fallthrough_helpers=tuple(state.root_fallthrough_helpers),
        return_carriers=return_carriers,
        terminal_returns=terminal_returns,
        terminal_effect_diagnostics=terminal_effect_diagnostics,
        data_flow_relations=data_flow_relations,
        value_ranges=value_ranges,
    )


def _try_live_block_for_binding(
    modifier: DeferredGraphModifier,
    binding: SemanticFragmentRuntimeBinding,
):
    gateway = _gateway(modifier)
    bound = gateway.identity_index.resolve_logical_version(
        binding.version,
        transaction_id=_transaction_id(modifier),
    )
    if bound is None:
        return None
    block = modifier.mba.get_mblock(int(bound.serial))
    if block is None:
        raise SemanticFragmentBackendRejected(
            f"fragment block {binding.block_id!r} is absent from the live MBA"
        )
    return block


def _binding_for_live_serial(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    serial: int,
) -> SemanticFragmentRuntimeBinding:
    matches = tuple(
        binding
        for binding in state.bindings.values()
        if (
            (live := _try_live_block_for_binding(modifier, binding)) is not None
            and int(live.serial) == int(serial)
        )
    )
    if len(matches) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor is not owned by exactly one fragment binding"
        )
    return matches[0]


def _incoming_root_edge_role(predecessor, original) -> SemanticEdgeRole:
    successors = tuple(int(value) for value in predecessor.succset)
    original_serial = int(original.serial)
    if successors == (original_serial,):
        tail = predecessor.tail
        if tail is not None and int(tail.opcode) in {
            int(ida_hexrays.m_call),
            int(ida_hexrays.m_icall),
        }:
            if (
                predecessor.nextb is None
                or int(predecessor.nextb.serial) != original_serial
            ):
                raise SemanticFragmentBackendRejected(
                    "call root predecessor physical fallthrough is not adjacent"
                )
            return SemanticEdgeRole.CALL_FALLTHROUGH
        return SemanticEdgeRole.DIRECT
    tail = predecessor.tail
    if (
        len(successors) != 2
        or tail is None
        or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or getattr(tail, "d", None) is None
        or int(tail.d.t) != int(ida_hexrays.mop_b)
    ):
        raise SemanticFragmentBackendRejected(
            "root predecessor is not a supported one-way or conditional edge"
        )
    taken_serial = int(tail.d.b)
    fallthroughs = tuple(
        successor for successor in successors if successor != taken_serial
    )
    if taken_serial not in successors or len(fallthroughs) != 1:
        raise SemanticFragmentBackendRejected(
            "root predecessor conditional topology is inconsistent"
        )
    if original_serial == taken_serial:
        return SemanticEdgeRole.CONDITIONAL_TAKEN
    if original_serial != fallthroughs[0]:
        raise SemanticFragmentBackendRejected(
            "root predecessor does not target its declared original"
        )
    if predecessor.nextb is None or int(predecessor.nextb.serial) != original_serial:
        raise SemanticFragmentBackendRejected(
            "root predecessor physical fallthrough is not adjacent"
        )
    return SemanticEdgeRole.CONDITIONAL_FALLTHROUGH


def _root_edge_requires_helper(
    predecessor,
    original,
    role: SemanticEdgeRole,
) -> bool:
    if role in {
        SemanticEdgeRole.CALL_FALLTHROUGH,
        SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
    }:
        return True
    if role is not SemanticEdgeRole.DIRECT:
        return False

    tail = predecessor.tail
    if tail is not None and int(tail.opcode) == int(ida_hexrays.m_goto):
        left = getattr(tail, "l", None)
        if (
            left is None
            or int(left.t) != int(ida_hexrays.mop_b)
            or int(left.b) != int(original.serial)
        ):
            raise SemanticFragmentBackendRejected(
                "direct root predecessor goto does not target its original"
            )
        return False
    if tail is not None and (
        ida_hexrays.is_mcode_jcond(int(tail.opcode))
        or int(tail.opcode)
        in {
            int(ida_hexrays.m_ijmp),
            int(ida_hexrays.m_jtbl),
            int(ida_hexrays.m_ret),
        }
    ):
        raise SemanticFragmentBackendRejected(
            "direct root predecessor has an unsupported closing transfer"
        )
    if predecessor.nextb is None or int(predecessor.nextb.serial) != int(
        original.serial
    ):
        raise SemanticFragmentBackendRejected(
            "implicit direct root fallthrough is not physically adjacent"
        )
    return True


def plan_semantic_fragment_root_inventory(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> SemanticFragmentRootInventory:
    """Inspect all incoming root roles without retaining live coordinates."""
    gateway = modifier._mutation_gateway
    if gateway is None or gateway.active:
        raise SemanticFragmentBackendRejected(
            "root inventory requires an idle mutation gateway"
        )
    live_by_id = {}
    ids_by_serial: dict[int, str] = {}
    for block in plan.blocks:
        if block.materialization is not FragmentBlockMaterialization.REUSE_PUBLISHED:
            continue
        if block.stable_identity is None:
            continue
        rebound = gateway.identity_index.rebind_identity(block.stable_identity)
        if rebound.block is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory block {block.block_id!r} does not rebind uniquely"
            )
        live = modifier.mba.get_mblock(int(rebound.block.serial))
        if live is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory block {block.block_id!r} is absent from the MBA"
            )
        if int(live.serial) in ids_by_serial:
            raise SemanticFragmentBackendRejected(
                "root inventory maps two plan blocks to one physical version"
            )
        live_by_id[block.block_id] = live
        ids_by_serial[int(live.serial)] = block.block_id

    items: list[SemanticFragmentRootInventoryItem] = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = live_by_id.get(original_block_id)
        if original is None:
            raise SemanticFragmentBackendRejected(
                f"root inventory lacks original {original_block_id!r}"
            )
        predecessor_serials = tuple(int(value) for value in original.predset)
        if not predecessor_serials:
            raise SemanticFragmentBackendRejected(
                f"root inventory original {original_block_id!r} has no predecessors"
            )
        for predecessor_serial in predecessor_serials:
            predecessor_block_id = ids_by_serial.get(predecessor_serial)
            predecessor = modifier.mba.get_mblock(predecessor_serial)
            if predecessor_block_id is None or predecessor is None:
                raise SemanticFragmentBackendRejected(
                    "root inventory predecessor is outside the closed fragment plan"
                )
            role = _incoming_root_edge_role(predecessor, original)
            requires_helper = _root_edge_requires_helper(
                predecessor,
                original,
                role,
            )
            items.append(
                SemanticFragmentRootInventoryItem(
                    edge_id=(f"{root_block_id}:{predecessor_block_id}:{role.value}"),
                    root_block_id=root_block_id,
                    original_block_id=original_block_id,
                    predecessor_block_id=predecessor_block_id,
                    role=role,
                    requires_helper=requires_helper,
                )
            )
    return SemanticFragmentRootInventory(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        items=tuple(items),
    )


def _reserve_root_fallthrough_helpers(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    state: SemanticFragmentBackendState,
) -> None:
    candidates: list[tuple[str, str]] = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = state.binding(original_block_id)
        original_live = _live_block_for_binding(modifier, original)
        for predecessor_serial in tuple(int(value) for value in original_live.predset):
            predecessor = _binding_for_live_serial(
                modifier,
                state,
                predecessor_serial,
            )
            predecessor_live = _live_block_for_binding(modifier, predecessor)
            role = _incoming_root_edge_role(predecessor_live, original_live)
            if _root_edge_requires_helper(
                predecessor_live,
                original_live,
                role,
            ):
                candidates.append((predecessor.block_id, root_block_id))

    gateway = _gateway(modifier)
    for predecessor_block_id, root_block_id in candidates:
        helper_block_id = (
            f"root-fallthrough-helper:{predecessor_block_id}:{root_block_id}"
        )
        if helper_block_id in state.bindings:
            raise SemanticFragmentBackendRejected(
                f"root fallthrough helper id collision: {helper_block_id!r}"
            )
        handle = gateway.identity_index.create_synthetic_handle()
        staged = gateway.reserve_new_proxy(handle)
        proxy = gateway.identity_index.logical_proxy_for_handle(handle)
        if proxy is None:
            raise SemanticFragmentBackendRejected(
                "reserved root fallthrough helper has no logical proxy"
            )
        state.bindings[helper_block_id] = SemanticFragmentRuntimeBinding(
            block_id=helper_block_id,
            proxy=proxy,
            version=staged,
            state=FragmentBindingState.STAGED,
        )
        state.root_fallthrough_helpers.append(
            ProjectedRootFallthroughHelper(
                helper_block_id=helper_block_id,
                source_block_id=predecessor_block_id,
                root_block_id=root_block_id,
            )
        )


def _group_semantic_fragment_root_edges(
    modifier: DeferredGraphModifier,
    state: SemanticFragmentBackendState,
    edges: tuple[SemanticFragmentRootEdgeBinding, ...],
) -> tuple[SemanticFragmentRootPublicationGroup, ...]:
    """Capture complete predecessor authority before any root is published."""
    edges_by_predecessor: dict[str, list[SemanticFragmentRootEdgeBinding]] = {}
    for edge in edges:
        edges_by_predecessor.setdefault(edge.predecessor.block_id, []).append(edge)

    groups: list[SemanticFragmentRootPublicationGroup] = []
    for predecessor_block_id, grouped_edges in edges_by_predecessor.items():
        predecessor_binding = grouped_edges[0].predecessor
        if any(
            edge.predecessor.version is not predecessor_binding.version
            for edge in grouped_edges
        ):
            raise SemanticFragmentBackendRejected(
                "root publication group has inconsistent predecessor authority"
            )
        if any(
            edge.requires_helper != (edge.publication_helper is not None)
            for edge in grouped_edges
        ):
            raise SemanticFragmentBackendRejected(
                "root publication helper authority differs from its inventory"
            )
        predecessor = _live_block_for_binding(modifier, predecessor_binding)
        roles = frozenset(edge.role for edge in grouped_edges)
        conditional_roles = {
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
        if roles == {SemanticEdgeRole.CALL_FALLTHROUGH}:
            if len(grouped_edges) != 1:
                raise SemanticFragmentBackendRejected(
                    "call root publication group contains multiple edges"
                )
            tail = predecessor.tail
            successors = tuple(int(value) for value in predecessor.succset)
            if (
                int(predecessor.nsucc()) != 1
                or tail is None
                or int(tail.opcode)
                not in {
                    int(ida_hexrays.m_call),
                    int(ida_hexrays.m_icall),
                }
                or predecessor.nextb is None
                or tuple(successors) != (int(predecessor.nextb.serial),)
            ):
                raise SemanticFragmentBackendRejected(
                    "call root publication group lost its physical fallthrough"
                )
            original_fallthrough = _binding_for_live_serial(
                modifier,
                state,
                successors[0],
            )
            if (
                grouped_edges[0].original.version
                is not original_fallthrough.version
            ):
                raise SemanticFragmentBackendRejected(
                    "call root edge does not match its captured fallthrough"
                )
            groups.append(
                SemanticFragmentRootPublicationGroup(
                    group_id=semantic_fragment_root_group_id(
                        predecessor_block_id
                    ),
                    predecessor=predecessor_binding,
                    edges=tuple(grouped_edges),
                    original_predecessor_type=int(predecessor.type),
                    original_predecessor_flags=int(predecessor.flags),
                    original_call_opcode=int(tail.opcode),
                    original_fallthrough=original_fallthrough,
                )
            )
            continue
        if roles == {SemanticEdgeRole.DIRECT}:
            if len(grouped_edges) != 1:
                raise SemanticFragmentBackendRejected(
                    "direct root publication group contains multiple edges"
                )
            groups.append(
                SemanticFragmentRootPublicationGroup(
                    group_id=semantic_fragment_root_group_id(
                        predecessor_block_id
                    ),
                    predecessor=predecessor_binding,
                    edges=tuple(grouped_edges),
                    original_predecessor_type=int(predecessor.type),
                    original_predecessor_flags=int(predecessor.flags),
                )
            )
            continue
        if (
            not roles.issubset(conditional_roles)
            or len(grouped_edges) > 2
            or len(roles) != len(grouped_edges)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group must contain at most one "
                "taken edge and one fallthrough edge"
            )
        tail = predecessor.tail
        successors = tuple(int(value) for value in predecessor.succset)
        if (
            int(predecessor.nsucc()) != 2
            or tail is None
            or not ida_hexrays.is_mcode_jcond(int(tail.opcode))
            or getattr(tail, "d", None) is None
            or int(tail.d.t) != int(ida_hexrays.mop_b)
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group lost its original predicate"
            )
        taken_serial = int(tail.d.b)
        fallthrough_serials = tuple(
            successor for successor in successors if successor != taken_serial
        )
        if taken_serial not in successors or len(fallthrough_serials) != 1:
            raise SemanticFragmentBackendRejected(
                "conditional root publication group has inconsistent arms"
            )
        fallthrough_serial = int(fallthrough_serials[0])
        if (
            predecessor.nextb is None
            or int(predecessor.nextb.serial) != fallthrough_serial
        ):
            raise SemanticFragmentBackendRejected(
                "conditional root publication group lacks physical fallthrough"
            )
        original_taken = _binding_for_live_serial(
            modifier,
            state,
            taken_serial,
        )
        original_fallthrough = _binding_for_live_serial(
            modifier,
            state,
            fallthrough_serial,
        )
        for edge in grouped_edges:
            expected_original = (
                original_taken
                if edge.role is SemanticEdgeRole.CONDITIONAL_TAKEN
                else original_fallthrough
            )
            if edge.original.version is not expected_original.version:
                raise SemanticFragmentBackendRejected(
                    "conditional root edge does not match its captured arm"
                )
        groups.append(
            SemanticFragmentRootPublicationGroup(
                group_id=semantic_fragment_root_group_id(
                    predecessor_block_id
                ),
                predecessor=predecessor_binding,
                edges=tuple(grouped_edges),
                original_predecessor_type=int(predecessor.type),
                original_predecessor_flags=int(predecessor.flags),
                original_conditional_opcode=int(tail.opcode),
                original_taken=original_taken,
                original_fallthrough=original_fallthrough,
            )
        )
    return tuple(groups)


def prepare_semantic_fragment_root_publication(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
    inventory: SemanticFragmentRootInventory,
) -> SemanticFragmentRootPublicationToken:
    """Capture every incoming root edge before exposing any staged version."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise SemanticFragmentBackendRejected(
            "staged semantic fragment does not match root publication request"
        )
    if (
        inventory.plan_id != plan.plan_id
        or inventory.atomic_group_id != plan.atomic_group_id
    ):
        raise SemanticFragmentBackendRejected(
            "root inventory does not match the staged fragment"
        )

    edges: list[SemanticFragmentRootEdgeBinding] = []
    for root_block_id in plan.roots:
        replacement = state.binding(root_block_id)
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        original = state.binding(original_block_id)
        original_live = _live_block_for_binding(modifier, original)
        replacement_live = _live_block_for_binding(modifier, replacement)
        replacement_predecessors = tuple(
            _binding_for_live_serial(
                modifier,
                state,
                int(predecessor_serial),
            )
            for predecessor_serial in replacement_live.predset
        )
        if any(
            predecessor.state is FragmentBindingState.PUBLISHED
            for predecessor in replacement_predecessors
        ):
            raise SemanticFragmentBackendRejected(
                f"replacement root {root_block_id!r} is already exposed "
                "to published authority"
            )
        predecessor_serials = tuple(int(value) for value in original_live.predset)
        if not predecessor_serials:
            raise SemanticFragmentBackendRejected(
                f"owned original {original_block_id!r} has no incoming root authority"
            )
        for predecessor_serial in predecessor_serials:
            predecessor = _binding_for_live_serial(
                modifier,
                state,
                predecessor_serial,
            )
            if predecessor.state is not FragmentBindingState.PUBLISHED:
                raise SemanticFragmentBackendRejected(
                    "root predecessor must be a published logical version"
                )
            predecessor_live = _live_block_for_binding(modifier, predecessor)
            role = _incoming_root_edge_role(predecessor_live, original_live)
            requires_helper = _root_edge_requires_helper(
                predecessor_live,
                original_live,
                role,
            )
            publication_helper = None
            if requires_helper:
                matching_helpers = tuple(
                    helper
                    for helper in state.root_fallthrough_helpers
                    if helper.source_block_id == predecessor.block_id
                    and helper.root_block_id == root_block_id
                )
                if len(matching_helpers) != 1:
                    raise SemanticFragmentBackendRejected(
                        "physical root fallthrough lacks one reserved helper"
                    )
                publication_helper = state.binding(matching_helpers[0].helper_block_id)
            edge_id = f"{root_block_id}:{predecessor.block_id}:{role.value}"
            edges.append(
                SemanticFragmentRootEdgeBinding(
                    edge_id=edge_id,
                    root_block_id=root_block_id,
                    predecessor=predecessor,
                    original=original,
                    replacement=replacement,
                    role=role,
                    requires_helper=requires_helper,
                    publication_helper=publication_helper,
                )
            )
    edge_ids = tuple(edge.edge_id for edge in edges)
    if len(set(edge_ids)) != len(edge_ids):
        raise SemanticFragmentBackendRejected(
            "semantic fragment root publication contains duplicate edges"
        )
    actual_inventory = tuple(
        (
            edge.edge_id,
            edge.root_block_id,
            edge.predecessor.block_id,
            edge.role,
            edge.requires_helper,
        )
        for edge in edges
    )
    planned_inventory = tuple(
        (
            item.edge_id,
            item.root_block_id,
            item.predecessor_block_id,
            item.role,
            item.requires_helper,
        )
        for item in inventory.items
    )
    if actual_inventory != planned_inventory:
        raise SemanticFragmentBackendRejected(
            "live root ownership changed after the publication inventory"
        )
    unsupported = tuple(
        edge
        for edge in edges
        if edge.role
        not in {
            SemanticEdgeRole.CALL_FALLTHROUGH,
            SemanticEdgeRole.DIRECT,
            SemanticEdgeRole.CONDITIONAL_TAKEN,
            SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
        }
    )
    if unsupported:
        raise SemanticFragmentBackendRejected(
            "root publication requires a supported predecessor-atomic lowering"
        )
    groups = _group_semantic_fragment_root_edges(
        modifier,
        state,
        tuple(edges),
    )
    grouped_edge_ids = tuple(
        edge.edge_id for group in groups for edge in group.edges
    )
    if set(grouped_edge_ids) != set(edge_ids) or len(grouped_edge_ids) != len(edge_ids):
        raise SemanticFragmentBackendRejected(
            "root publication groups do not cover the complete edge inventory"
        )
    return SemanticFragmentRootPublicationToken(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        groups=groups,
    )


def observe_published_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> PublishedFragmentObservation:
    """Observe the actual live graph without projecting another root rewrite."""
    state = modifier._semantic_fragment_state
    if state is None:
        raise SemanticFragmentBackendRejected("semantic fragment is not staged")
    projection = _project_fragment(
        modifier,
        plan,
        state,
        simulate_root_publication=False,
    )
    validation = validate_published_fragment_projection(plan, projection)
    outcomes_by_subject: dict[str, list] = {}
    for outcome in validation.outcomes:
        outcomes_by_subject.setdefault(outcome.subject_id, []).append(outcome)

    published_roots = []
    for root_block_id in plan.roots:
        original_block_id = str(plan.block(root_block_id).replaces_block_id)
        if not projection.block(original_block_id).predecessors and bool(
            projection.block(root_block_id).predecessors
        ):
            published_roots.append(root_block_id)

    observable_operations = []
    for operation in plan.operations:
        relevant = outcomes_by_subject.get(operation.operation_id, ())
        required_topology = {
            FragmentValidationPostcondition.OPERATION_TOPOLOGY,
        }
        if operation.roles.intersection(
            {
                SemanticEdgeRole.CALL_FALLTHROUGH,
                SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
            }
        ):
            required_topology.add(
                FragmentValidationPostcondition.FALLTHROUGH_TOPOLOGY
            )
        topology = tuple(
            outcome
            for outcome in relevant
            if outcome.postcondition in required_topology
        )
        if (
            len(topology) == len(required_topology)
            and {outcome.postcondition for outcome in topology}
            == required_topology
            and all(outcome.passed for outcome in topology)
        ):
            observable_operations.append(operation)

    observable_return_carriers = tuple(
        carrier
        for carrier in projection.return_carriers
        if any(
            outcome.postcondition
            is FragmentValidationPostcondition.RETURN_CARRIER_INTEGRITY
            and outcome.subject_id == carrier.carrier_id
            and outcome.passed
            for outcome in validation.outcomes
        )
    )
    observable_terminal_returns = tuple(
        terminal_return
        for terminal_return in projection.terminal_returns
        if any(
            outcome.postcondition
            is FragmentValidationPostcondition.TERMINAL_RETURN_INTEGRITY
            and outcome.subject_id == terminal_return.return_id
            and outcome.passed
            for outcome in validation.outcomes
        )
    )
    return PublishedFragmentObservation(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
        published_root_ids=tuple(published_roots),
        observable_operations=tuple(observable_operations),
        semantic_outcomes=validation.outcomes,
        fallthrough_helpers=projection.fallthrough_helpers,
        root_fallthrough_helpers=projection.root_fallthrough_helpers,
        observable_return_carriers=observable_return_carriers,
        observable_terminal_returns=observable_terminal_returns,
    )


def stage_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> ProjectedFragment:
    """Stage direct replacement routes without exposing any publication root."""
    if not isinstance(plan, FragmentPlan):
        raise TypeError("semantic fragment backend requires a FragmentPlan")
    if modifier._semantic_fragment_state is not None:
        raise RuntimeError("a semantic fragment is already staged")
    state = SemanticFragmentBackendState(
        plan_id=plan.plan_id,
        atomic_group_id=plan.atomic_group_id,
    )
    modifier._semantic_fragment_state = state
    try:
        for block in plan.blocks:
            if block.materialization is FragmentBlockMaterialization.REUSE_PUBLISHED:
                state.bindings[block.block_id] = _published_binding(
                    modifier,
                    block.block_id,
                    block.stable_identity,
                )
        for block in plan.blocks:
            if block.role is FragmentBlockRole.REPLACEMENT:
                _clone_replacement(modifier, state, block)
        _normalize_replacement_computed_branches(
            modifier,
            plan,
            state,
        )
        reference_version = state.binding(plan.roots[0]).version
        _stage_native_bodies(
            modifier,
            plan,
            state,
            reference_version=reference_version,
        )
        for block in plan.blocks:
            if block.materialization is FragmentBlockMaterialization.CREATE_EMPTY:
                _create_empty_block(
                    modifier,
                    state,
                    block,
                    reference_version=reference_version,
                )
        _materialize_terminal_effects(modifier, plan, state)
        _realize_operations(modifier, plan, state)
        _reserve_root_fallthrough_helpers(modifier, plan, state)
        projection = _project_fragment(modifier, plan, state)
        state.projection = projection
        return projection
    except Exception:
        discard_staged_semantic_fragment(modifier, plan)
        raise


def discard_staged_semantic_fragment(
    modifier: DeferredGraphModifier,
    plan: FragmentPlan,
) -> None:
    """Remove every unpublished physical version staged for ``plan``."""
    state = modifier._semantic_fragment_state
    if state is None:
        return
    if state.plan_id != plan.plan_id or state.atomic_group_id != plan.atomic_group_id:
        raise RuntimeError("staged semantic fragment does not match discard request")
    modifier._discard_detached_semantic_versions(
        tuple(state.binding(block_id).version for block_id in state.staged_block_ids)
    )
    _restore_native_body_address_ranges(modifier, state)
    modifier._semantic_fragment_state = None


__all__ = [
    "SemanticFragmentBackendRejected",
    "SemanticFragmentBackendState",
    "SemanticFragmentRootEdgeBinding",
    "SemanticFragmentRootPublicationGroup",
    "SemanticFragmentRootPublicationToken",
    "SemanticNativeBodyMaterializer",
    "SemanticNativeBodyStagingContext",
    "discard_staged_semantic_fragment",
    "observe_published_semantic_fragment",
    "plan_semantic_fragment_root_inventory",
    "prepare_semantic_fragment_root_publication",
    "stage_semantic_fragment",
]
