"""Production participant for immutable PatchPlan CFG transactions."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
import hashlib

from d810.analyses.control_flow.graph_checks import (
    EffectfulReachabilityResult,
    check_entry_reachability_not_collapsed,
    check_effectful_reachability_preserved,
    check_terminal_reachability_preserved,
)
from d810.analyses.control_flow.effect_branch_exclusion import (
    EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
    validate_exact_state_branch_effect_exclusion,
)
from d810.transforms.dispatcher_corridor_coverage import (
    DispatcherRemovalPreflightValidation,
)
from d810.transforms.unflatten_authority.legacy_codec import (
    exact_state_branch_effect_exclusion_from_metadata,
    LegacyShadowCodecReceipt,
)
from d810.transforms.unflatten_authority.diagnostics import (
    LegacyPhaseOutcome,
    PhaseTimings,
    ShadowParityPayload,
    ShadowParityCounters,
)
from d810.transforms.unflatten_authority.model import (
    SemanticGraphInventory,
    UnflattenAuthorityPhase,
    UnflattenAuthorityReason,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import (
    BoundCfgTransaction,
    CfgGenerationPoisoned,
    CfgProjection,
    PatchPlanExecutionResult,
    PreparedCfgTransaction,
    LogicalBlockRef,
    NativeBlockRef,
    PlanBlockRef,
    TransactionAttemptId,
)
from d810.transforms.contract import CfgContract
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.plan import (
    PatchConvertToGoto,
    PatchLowerConditionalStateTransition,
    PatchPlan,
    PatchRemoveEdge,
    PatchRedirectBranch,
    PatchRedirectGoto,
    PatchScalarizeLocalAliasAccess,
)
from d810.hexrays.mutation.patch_binding import bind_patch_plan
from d810.transforms.patch_binding import (
    BoundPatchPlan,
    validate_bound_patch_plan,
)
from d810.transforms.unflatten_authority.gates import GenericCfgGateBundle
from d810.hexrays.mutation.semantic_ownership import (
    find_patch_plan_semantic_ownership_overlap,
    format_patch_plan_semantic_ownership_overlap,
)


def _iter_plan_refs(value: object):
    if isinstance(value, (NativeBlockRef, LogicalBlockRef, PlanBlockRef)):
        yield value
        return
    if isinstance(value, tuple):
        for item in value:
            yield from _iter_plan_refs(item)
        return
    if is_dataclass(value):
        for item in fields(value):
            if not item.name.startswith("_"):
                yield from _iter_plan_refs(getattr(value, item.name))


def _iter_named_plan_refs(value: object, prefix: str = ""):
    if isinstance(value, (NativeBlockRef, LogicalBlockRef, PlanBlockRef)):
        yield prefix, value
        return
    if isinstance(value, tuple):
        for index, item in enumerate(value):
            yield from _iter_named_plan_refs(item, f"{prefix}[{index}]")
        return
    if is_dataclass(value):
        for item in fields(value):
            if not item.name.startswith("_"):
                name = item.name if not prefix else f"{prefix}.{item.name}"
                yield from _iter_named_plan_refs(getattr(value, item.name), name)


class _PlanObservationFilteringEmitter:
    """Keep the preflight plan receipt while suppressing its later duplicate."""

    def __init__(self, delegate: object, plan_event: type) -> None:
        self._delegate = delegate
        self._plan_event = plan_event

    def emit_isolated(self, event: type, payload: object, *args, **kwargs):
        if event is self._plan_event:
            return ()
        return self._delegate.emit_isolated(event, payload, *args, **kwargs)

    def __getattr__(self, name: str):
        return getattr(self._delegate, name)


def _patch_plan_observation_items(plan: PatchPlan, snapshot: FlowGraph):
    from d810.hexrays.mutation.mba_mutation_events import (
        MbaMutationPlanItem,
        MbaMutationPlanTarget,
    )

    source_coordinates = dict(plan.source_coordinates)

    def coordinate(ref: object) -> tuple[int | None, int | None]:
        serial = source_coordinates.get(ref)
        if serial is None:
            return None, None
        block = snapshot.get_block(int(serial))
        if block is None:
            return None, None
        native_ea = getattr(block, "native_start_ea", None)
        anchor = int(block.start_ea if native_ea is None else native_ea)
        return int(serial), anchor

    def extra_targets(named_refs, excluded):
        return tuple(
            MbaMutationPlanTarget(
                role=role,
                serial=serial,
                anchor_ea=anchor,
            )
            for role, ref in named_refs
            if role not in excluded
            for serial, anchor in (coordinate(ref),)
            if anchor is not None
        )

    def shape(step: object):
        if isinstance(step, PatchRedirectBranch):
            return (
                step.from_serial,
                step.old_target,
                step.new_target,
                "block_target_change",
                "immutable PatchPlan step",
                (),
            )
        if isinstance(step, PatchRedirectGoto):
            return (
                step.from_serial,
                step.old_target,
                step.new_target,
                "block_goto_change",
                "immutable PatchPlan step",
                (),
            )
        if isinstance(step, PatchLowerConditionalStateTransition):
            _false_serial, false_anchor = coordinate(step.false_target_serial)
            false_target = (
                ""
                if false_anchor is None
                else f"; false_target=0x{int(false_anchor):X}"
            )
            return (
                step.source_serial,
                step.old_dispatcher_serial,
                step.true_target_serial,
                "lower_conditional_state_transition",
                f"immutable PatchPlan step{false_target}",
                extra_targets(
                    (("false_target", step.false_target_serial),),
                    {"source_serial", "old_dispatcher_serial", "true_target_serial"},
                ),
            )
        if isinstance(step, PatchConvertToGoto):
            return (
                step.block_serial,
                None,
                step.goto_target,
                "convert_to_goto",
                "immutable PatchPlan step",
                (),
            )
        if isinstance(step, PatchRemoveEdge):
            return (
                step.from_serial,
                step.to_serial,
                None,
                "remove_edge",
                "immutable PatchPlan step",
                (),
            )
        named_refs = tuple(_iter_named_plan_refs(step))

        def pick(*roles):
            for role in roles:
                for named_role, ref in named_refs:
                    if named_role == role:
                        return named_role, ref
            return None, None

        source_role, source_ref = pick(
            "source_serial",
            "from_serial",
            "block_serial",
            "pred_serial",
            "jtbl_serial",
        )
        old_role, old_ref = pick(
            "apply_old_target",
            "old_target",
            "old_target_serial",
            "old_dispatcher_serial",
        )
        target_role, target_ref = pick(
            "new_target",
            "new_target_serial",
            "target_serial",
            "goto_target",
            "final_target",
            "succ_serial",
            "keep_target",
            "keep_target_serial",
            "conditional_target",
            "header_target",
        )
        if source_ref is None and named_refs:
            source_role, source_ref = named_refs[0]
        excluded = {role for role in (source_role, old_role, target_role) if role}
        return (
            source_ref,
            old_ref,
            target_ref,
            f"patch_{type(step).__name__}",
            "immutable PatchPlan step",
            extra_targets(named_refs, excluded),
        )

    items = []
    for item_index, step in enumerate(plan.steps):
        source_ref, old_ref, target_ref, mutation_kind, reason, additional_targets = shape(
            step
        )
        source_serial, source_anchor = coordinate(source_ref)
        old_target_serial, old_target_anchor = coordinate(old_ref)
        target_serial, target_anchor = coordinate(target_ref)
        items.append(
            MbaMutationPlanItem(
                item_index=int(item_index),
                mutation_kind=mutation_kind,
                source_serial=source_serial if source_anchor is not None else None,
                source_anchor_ea=source_anchor,
                old_target_serial=(
                    old_target_serial if old_target_anchor is not None else None
                ),
                old_target_anchor_ea=old_target_anchor,
                target_serial=target_serial if target_anchor is not None else None,
                target_anchor_ea=target_anchor,
                disposition="planned",
                reason=reason,
                additional_targets=additional_targets,
            )
        )
    return tuple(items)


def _publish_patch_plan_observation(
    participant: "HexRaysPatchTransactionParticipant",
    snapshot: FlowGraph,
) -> None:
    """Publish plan evidence before projected preflight, without opening a batch."""
    from d810.hexrays.mutation.mba_mutation_events import (
        MbaMutationPlanned,
        StructuralMutationKind,
    )

    gateway = participant.gateway
    emitter = getattr(gateway, "event_emitter", None)
    if emitter is None:
        return
    event = MbaMutationPlanned(
        session_id=str(gateway.session_id),
        function_ea=int(snapshot.func_ea),
        maturity=int(getattr(gateway, "maturity", 0)),
        mba_generation=int(participant.attempt_id.generation),
        evidence_generation=int(
            getattr(gateway.identity_index, "evidence_generation", 0)
        ),
        mutation_batch_id=participant.attempt_id.attempt_id,
        kind=StructuralMutationKind.BLOCK_REPLACE,
        planned_operation_count=len(participant.plan.steps),
        description=f"PatchPlan {participant.plan.plan_id}",
        items=_patch_plan_observation_items(participant.plan, snapshot),
    )
    emit_observation = getattr(gateway, "_emit_observation", None)
    if callable(emit_observation):
        emit_observation(
            phase="planned",
            event_type=MbaMutationPlanned,
            payload=event,
            mutation_batch_id=participant.attempt_id.attempt_id,
        )
    else:
        emitter.emit_isolated(MbaMutationPlanned, event)
    gateway.event_emitter = _PlanObservationFilteringEmitter(
        emitter,
        MbaMutationPlanned,
    )
def _has_dispatcher_removal_obligation(plan_metadata: object) -> bool:
    """Whether a plan claims exact full dispatcher-corridor retirement."""
    if not isinstance(plan_metadata, Mapping):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    )

    coverage = plan_metadata.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    if not isinstance(coverage, dict):
        return False
    raw_covered_corridors = coverage.get("covered_corridors")
    raw_residual_corridors = coverage.get("residual_corridors")
    if not isinstance(raw_covered_corridors, (tuple, list)) or not isinstance(
        raw_residual_corridors, (tuple, list)
    ):
        return False
    residual_corridors = tuple(raw_residual_corridors)
    return (
        bool(coverage.get("enumeration_complete", False))
        and not residual_corridors
        and coverage.get("planned_completion_status")
        == "planned_dispatcher_corridors_covered"
    )


def _has_dispatcher_coverage_metadata(plan_metadata: object) -> bool:
    if not isinstance(plan_metadata, Mapping):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    )

    return DISPATCHER_CORRIDOR_COVERAGE_METADATA in plan_metadata


def _has_dispatcher_removal_proof_metadata(plan_metadata: object) -> bool:
    if not isinstance(plan_metadata, Mapping):
        return False
    from d810.transforms.dispatcher_corridor_coverage import (
        DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    )

    return DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA in plan_metadata


@dataclass(frozen=True, slots=True)
class _LegacyEffectReplay:
    """Closed transaction-local result for the legacy effect replay."""

    accepted: bool
    effect_serials: frozenset[int]

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("legacy replay accepted must be an exact bool")
        if type(self.effect_serials) is not frozenset or any(
            type(serial) is not int or serial < 0
            for serial in self.effect_serials
        ):
            raise TypeError("legacy replay effect serials must be a frozenset of ints")


@dataclass(frozen=True, slots=True)
class _LegacyGateDecision:
    """Closed transaction-local aggregate of one legacy gate boundary."""

    accepted: bool
    reason_scope: UnflattenAuthorityReason
    replay: _LegacyEffectReplay

    def __post_init__(self) -> None:
        if type(self.accepted) is not bool:
            raise TypeError("legacy gate accepted must be an exact bool")
        if type(self.reason_scope) is not UnflattenAuthorityReason:
            raise TypeError("legacy gate reason must be UnflattenAuthorityReason")
        if type(self.replay) is not _LegacyEffectReplay:
            raise TypeError("legacy gate replay must be _LegacyEffectReplay")


def _legacy_gate_decision(
    phase: UnflattenAuthorityPhase,
    replay: _LegacyEffectReplay,
    *,
    terminal_passed: bool,
    effectful_passed: bool,
    entry_passed: bool,
    entry_allowance_passed: bool,
    dispatcher_removal_rejected: bool,
    coverage_rejected: bool,
) -> _LegacyGateDecision:
    """Fold the former generic legacy gates into one diagnostic decision."""

    for name, value in (
        ("terminal_passed", terminal_passed),
        ("effectful_passed", effectful_passed),
        ("entry_passed", entry_passed),
        ("entry_allowance_passed", entry_allowance_passed),
        ("dispatcher_removal_rejected", dispatcher_removal_rejected),
        ("coverage_rejected", coverage_rejected),
    ):
        if type(value) is not bool:
            raise TypeError(f"legacy gate {name} must be an exact bool")
    accepted = replay.accepted and terminal_passed and effectful_passed and (
        entry_passed or entry_allowance_passed
    ) and not dispatcher_removal_rejected and not coverage_rejected
    reason = (
        UnflattenAuthorityReason.ACCEPTED
        if accepted
        else (
            UnflattenAuthorityReason.PROJECTED_BINDING_FAILED
            if phase is UnflattenAuthorityPhase.PROJECTED_PREFLIGHT
            else UnflattenAuthorityReason.LIVE_BINDING_FAILED
        )
    )
    return _LegacyGateDecision(accepted, reason, replay)


def _validated_exact_effect_exclusions(
    source: FlowGraph,
    projected: FlowGraph,
    plan_metadata: object,
) -> _LegacyEffectReplay:
    """Replay every typed semantic effect exclusion against immutable inputs."""

    if not isinstance(plan_metadata, Mapping):
        return _LegacyEffectReplay(True, frozenset())
    raw = plan_metadata.get(EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA)
    if raw is None:
        return _LegacyEffectReplay(True, frozenset())
    if not isinstance(raw, (tuple, list)):
        return _LegacyEffectReplay(False, frozenset())
    parsed = tuple(
        exact_state_branch_effect_exclusion_from_metadata(payload)
        for payload in raw
    )
    if any(proof is None for proof in parsed):
        return _LegacyEffectReplay(False, frozenset())
    proofs = tuple(proof for proof in parsed if proof is not None)
    effect_serials = tuple(int(proof.discarded_effect_serial) for proof in proofs)
    if len(effect_serials) != len(set(effect_serials)):
        return _LegacyEffectReplay(False, frozenset())
    if any(
        not validate_exact_state_branch_effect_exclusion(source, projected, proof)
        for proof in proofs
    ):
        return _LegacyEffectReplay(False, frozenset())
    return _LegacyEffectReplay(True, frozenset(effect_serials))


def _apply_exact_effect_exclusions(
    result: EffectfulReachabilityResult,
    allowed_serials: frozenset[int],
) -> EffectfulReachabilityResult:
    """Remove only replayed infeasible effect blocks from a strict verdict."""

    uncovered = frozenset(result.lost_block_serials - allowed_serials)
    if not result.lost_block_serials or uncovered == result.lost_block_serials:
        return result
    return EffectfulReachabilityResult(
        passed=not uncovered,
        pre_effectful_block_serials=result.pre_effectful_block_serials,
        post_reachable_effectful_block_serials=frozenset(
            result.post_reachable_effectful_block_serials
            | (result.lost_block_serials - uncovered)
        ),
        lost_block_serials=uncovered,
        reason=(
            ""
            if not uncovered
            else "reachable effectful blocks became unreachable"
        ),
    )


def _reachable_serials(graph: FlowGraph) -> frozenset[int]:
    seen: set[int] = set()
    pending = [int(graph.entry_serial)]
    while pending:
        serial = pending.pop()
        if serial in seen:
            continue
        seen.add(serial)
        block = graph.get_block(serial)
        if block is not None:
            pending.extend(int(target) for target in block.succs)
    return frozenset(seen)


def _transaction_reachability_removal_validation(
    candidate: object,
    *,
    coverage_validation: object | None,
    terminal_passed: bool,
    effectful_passed: bool,
    entry_passed: bool,
    switch_cycle_hazard: bool,
) -> object:
    """Publish ordinary transaction safety as removal-proof authority.

    The narrow retirement classifiers are alternatives for plans whose entry
    reachability changes.  When the ordinary transaction contract itself
    proves entry, terminal, effects, and exact corridor coverage, retain that
    stronger observed fact instead of publishing no applied removal proof.
    """
    if bool(getattr(candidate, "passed", False)):
        return candidate
    proof = getattr(candidate, "proof", None)
    if (
        proof is None
        or coverage_validation is None
        or not bool(getattr(coverage_validation, "passed", False))
        or not terminal_passed
        or not effectful_passed
        or not entry_passed
        or switch_cycle_hazard
        or not bool(getattr(proof, "coverage_enumeration_complete", False))
        or int(getattr(proof, "residual_corridor_count", -1)) != 0
        or not getattr(proof, "authoritative_handlers", ())
        or set(getattr(proof, "authoritative_handlers", ()))
        != set(getattr(proof, "post_reachable_handlers", ()))
        or set(getattr(proof, "pre_reachable_terminals", ()))
        != set(getattr(proof, "post_reachable_terminals", ()))
    ):
        return candidate
    from d810.transforms.dispatcher_corridor_coverage import (
        DispatcherRemovalPreflightValidation,
    )

    return DispatcherRemovalPreflightValidation(
        passed=True,
        reason="transaction_reachability_contract",
        proof=proof,
    )


def _requires_observed_identity_canonicalization(plan: PatchPlan) -> bool:
    """Whether applying *plan* can insert a helper that shifts live serials."""
    for step in plan.steps:
        match step:
            case PatchLowerConditionalStateTransition():
                return True
            case PatchRedirectBranch(fallthrough_helper_block_id=helper):
                if helper is not None:
                    return True
    return False


def _legacy_phase_outcome(
    phase: UnflattenAuthorityPhase,
    source_inventory: SemanticGraphInventory,
    effectful: EffectfulReachabilityResult,
    removal_validation: DispatcherRemovalPreflightValidation | None,
    decision: _LegacyGateDecision,
) -> LegacyPhaseOutcome:
    """Capture already-computed legacy loss anchors at the decision boundary."""

    inventory_by_serial = {row.serial: row for row in source_inventory.blocks}
    serials = set(int(serial) for serial in effectful.lost_block_serials)
    proof = None if removal_validation is None else removal_validation.proof
    if proof is not None:
        proof_serials = frozenset(int(serial) for serial in proof.lost_blocks)
        proof_anchors = tuple(proof.lost_block_anchors)
        if (
            len(proof_anchors) != len(set(proof_anchors))
            or frozenset(anchor.serial for anchor in proof_anchors) != proof_serials
        ):
            raise ValueError("legacy removal proof serial/anchor rows differ")
        serials.update(proof_serials)
        for anchor in proof_anchors:
            row = inventory_by_serial.get(anchor.serial)
            if row is None or row.anchor_ea != anchor.ea:
                raise ValueError("legacy removal proof anchor differs from source inventory")
    missing = tuple(sorted(serial for serial in serials if serial not in inventory_by_serial))
    if missing:
        raise ValueError(f"legacy loss anchor is absent from source inventory: {missing}")
    if any(inventory_by_serial[serial].anchor_ea is None for serial in serials):
        raise ValueError("legacy loss anchor is unresolved in source inventory")
    anchors = tuple(sorted(
        (serial, int(inventory_by_serial[serial].anchor_ea))
        for serial in serials
    ))
    return LegacyPhaseOutcome(
        phase=phase,
        accepted=decision.accepted,
        reason_scope=decision.reason_scope,
        anchored_losses=anchors,
    )


def _conditional_lowering_projection_failure(
    plan: PatchPlan,
    snapshot: FlowGraph,
) -> str | None:
    """Return a fail-closed reason for an unresolvable typed lowering."""
    source_coordinates = dict(plan.source_coordinates)
    for step in plan.steps:
        match step:
            case PatchLowerConditionalStateTransition(
                source_serial=source,
                old_dispatcher_serial=old_dispatcher,
                false_target_serial=false_target,
                true_target_serial=true_target,
            ):
                refs = (
                    ("source_serial", source),
                    ("old_dispatcher_serial", old_dispatcher),
                    ("false_target_serial", false_target),
                    ("true_target_serial", true_target),
                )
            case _:
                continue
        missing: list[str] = []
        for field_name, ref in refs:
            if isinstance(ref, int) and not isinstance(ref, bool):
                serial = int(ref)
            else:
                serial = source_coordinates.get(ref)
            if serial is None:
                missing.append(field_name)
            elif int(serial) not in snapshot.blocks:
                missing.append(f"{field_name}={int(serial)}")
        if missing:
            return "missing source coordinates: " + ", ".join(missing)
    return None


class PatchTransactionPreflightRejected(RuntimeError):
    """An immutable PatchPlan obligation failed before any SDK write."""

    def __init__(
        self,
        message: str,
        *,
        projected_dispatcher_removal_validation: object | None = None,
        projected_dispatcher_coverage_validation: object | None = None,
        unflatten_verdict: object | None = None,
    ) -> None:
        super().__init__(message)
        self.projected_dispatcher_removal_validation = (
            projected_dispatcher_removal_validation
        )
        self.projected_dispatcher_coverage_validation = (
            projected_dispatcher_coverage_validation
        )
        self.unflatten_verdict = unflatten_verdict


class PatchTransactionPostObservationRejected(RuntimeError):
    """The realized live graph lost a preflighted reachability obligation."""

    def __init__(
        self,
        message: str,
        *,
        observed_dispatcher_removal_validation: object | None = None,
        observed_dispatcher_coverage_validation: object | None = None,
        unflatten_verdict: object | None = None,
    ) -> None:
        super().__init__(message)
        self.observed_dispatcher_removal_validation = (
            observed_dispatcher_removal_validation
        )
        self.observed_dispatcher_coverage_validation = (
            observed_dispatcher_coverage_validation
        )
        self.unflatten_verdict = unflatten_verdict


class PatchTransactionPoisoned(CfgGenerationPoisoned):
    """Poisoned live generation carrying already-observed CFG verdicts."""

    def __init__(
        self,
        failure: object,
        *,
        observed_dispatcher_removal_validation: object | None = None,
        observed_dispatcher_coverage_validation: object | None = None,
        unflatten_verdict: object | None = None,
    ) -> None:
        super().__init__(failure)
        self.observed_dispatcher_removal_validation = (
            observed_dispatcher_removal_validation
        )
        self.observed_dispatcher_coverage_validation = (
            observed_dispatcher_coverage_validation
        )
        self.unflatten_verdict = unflatten_verdict


@dataclass(frozen=True, slots=True, kw_only=True)
class PreparedPatchCfgTransaction(PreparedCfgTransaction):
    """Prepared generic transaction carrying optional semantic authority."""

    plan: PatchPlan
    unflatten_authority: object | None = None
    projected_unflatten_verdict: object | None = None
    projected_unflatten_timing: PhaseTimings | None = None
    legacy_shadow_receipt: LegacyShadowCodecReceipt | None = None
    legacy_shadow_codec_error: str | None = None

    def __post_init__(self) -> None:
        PreparedCfgTransaction.__post_init__(self)
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("prepared patch transaction requires a PatchPlan")


@dataclass(frozen=True, slots=True)
class PatchTransactionExecution(PatchPlanExecutionResult):
    """Committed ordinary PatchPlan result returned by the shared coordinator."""

    applied_count: int
    graph: FlowGraph
    receipt: object
    creation_receipts: tuple[object, ...] = ()
    projected_dispatcher_removal_validation: object | None = None
    projected_dispatcher_coverage_validation: object | None = None
    observed_dispatcher_removal_validation: object | None = None
    observed_dispatcher_coverage_validation: object | None = None
    projected_unflatten_verdict: object | None = None
    observed_unflatten_verdict: object | None = None
    projected_unflatten_timing: PhaseTimings | None = None
    observed_unflatten_timing: PhaseTimings | None = None
    shadow_parity_payload: ShadowParityPayload | None = None
    legacy_shadow_codec_error: str | None = None
    shadow_parity_error: str | None = None

    def __post_init__(self) -> None:
        PatchPlanExecutionResult.__post_init__(self)
        if self.applied_count <= 0:
            raise ValueError("patch execution requires a positive applied count")


@dataclass(frozen=True, slots=True)
class BoundPatchCfgTransaction(BoundCfgTransaction):
    """Generic transaction authority plus the exact final-boundary binding."""

    plan: PatchPlan | None = None
    patch_binding: BoundPatchPlan | None = None
    unflatten_authority: object | None = None

    def __post_init__(self) -> None:
        BoundCfgTransaction.__post_init__(self)
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("bound patch transaction requires a PatchPlan")
        if type(self.patch_binding) is not BoundPatchPlan:
            raise TypeError("bound patch transaction requires final live binding")
        validate_bound_patch_plan(self.patch_binding)
        if (
            self.patch_binding.plan is not self.plan
            or self.patch_binding.attempt_id != self.prepared.attempt_id
            or self.patch_binding.session_id != self.session_id
            or self.patch_binding.generation != self.generation
            or self.patch_binding.bindings != self.bindings
        ):
            raise ValueError("bound patch transaction authority differs")


@dataclass(slots=True)
class HexRaysPatchTransactionParticipant:
    """Project, preflight, bind, realize, and observe one live PatchPlan."""

    gateway: object
    translator: object
    mba: object
    plan: PatchPlan
    contract: object | None = None
    post_apply_hook: object | None = None
    attempt_authority: TransactionAttemptId | None = None
    attempt_id: TransactionAttemptId = field(init=False)
    _projection: CfgProjection | None = field(default=None, init=False, repr=False)
    _snapshot: FlowGraph | None = field(default=None, init=False, repr=False)
    _prepared: PreparedPatchCfgTransaction | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _bound: BoundPatchCfgTransaction | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _applied_count: int | None = field(default=None, init=False, repr=False)
    _observed_dispatcher_removal_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _observed_dispatcher_coverage_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _projected_dispatcher_removal_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _projected_dispatcher_coverage_validation: object | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _validated_effect_exclusion_serials: frozenset[int] = field(
        default=frozenset(),
        init=False,
        repr=False,
    )
    _unflatten_authority: object | None = field(default=None, init=False, repr=False)
    _projected_unflatten_verdict: object | None = field(default=None, init=False, repr=False)
    _observed_unflatten_verdict: object | None = field(default=None, init=False, repr=False)
    _projected_unflatten_timing: PhaseTimings | None = field(default=None, init=False, repr=False)
    _observed_unflatten_timing: PhaseTimings | None = field(default=None, init=False, repr=False)
    _legacy_shadow_receipt: LegacyShadowCodecReceipt | None = field(default=None, init=False, repr=False)
    _shadow_parity_payload: ShadowParityPayload | None = field(default=None, init=False, repr=False)
    _projected_legacy_outcome: LegacyPhaseOutcome | None = field(default=None, init=False, repr=False)
    _observed_legacy_outcome: LegacyPhaseOutcome | None = field(default=None, init=False, repr=False)
    _legacy_shadow_codec_error: str | None = field(default=None, init=False, repr=False)
    _shadow_parity_error: str | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("patch participant requires a PatchPlan")
        identity_index = getattr(self.gateway, "identity_index", None)
        if identity_index is None:
            raise TypeError("patch participant requires an identity index")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch participant requires an idle gateway")
        expected_session_id = str(self.gateway.session_id)
        expected_generation = int(self.gateway.generation)
        attempt_authority = self.attempt_authority
        if attempt_authority is None:
            self.attempt_id = TransactionAttemptId.new(
                self.plan.plan_id,
                expected_session_id,
                expected_generation,
            )
        else:
            if not isinstance(attempt_authority, TransactionAttemptId):
                raise TypeError("patch participant requires TransactionAttemptId authority")
            if (
                attempt_authority.plan_id != self.plan.plan_id
                or attempt_authority.session_id != expected_session_id
                or attempt_authority.generation != expected_generation
            ):
                raise ValueError("patch participant attempt authority differs")
            self.attempt_id = attempt_authority

    def project(self, plan: object, snapshot: object) -> CfgProjection:
        if plan is not self.plan:
            raise ValueError("patch projection changed exact plan authority")
        if not isinstance(snapshot, FlowGraph):
            raise TypeError("patch projection requires an immutable FlowGraph")
        if self._projection is not None:
            raise RuntimeError("patch projection authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch projection requires an idle gateway")
        lowering_projection_failure = _conditional_lowering_projection_failure(
            self.plan,
            snapshot,
        )
        if lowering_projection_failure is not None:
            raise PatchTransactionPreflightRejected(
                "conditional state lowering projection rejected: "
                f"{lowering_projection_failure}"
            )
        self.gateway._record_cfg_attempt_planned(
            plan_id=self.plan.plan_id,
            plan_refs=tuple(spec.block_id for spec in self.plan.new_blocks),
            attempt=self.attempt_id,
        )
        projection = project_patch_plan(
            snapshot,
            self.plan,
            snapshot_id=self.plan.snapshot_id,
        )
        self.gateway._record_cfg_projected()
        self._snapshot = snapshot
        self._projection = projection
        return projection

    def _reject_committed_semantic_overlap(self) -> None:
        authority = getattr(self.gateway, "lifecycle_authority", None)
        if authority is None:
            return
        overlap = find_patch_plan_semantic_ownership_overlap(
            self.plan,
            self.gateway.identity_index,
            authority.committed_semantic_ownership(),
        )
        if overlap is not None:
            raise PatchTransactionPreflightRejected(
                format_patch_plan_semantic_ownership_overlap(overlap)
            )

    def preflight(self, projection: CfgProjection) -> PreparedCfgTransaction:
        if projection is not self._projection:
            raise ValueError("patch preflight changed immutable projection authority")
        if self._prepared is not None:
            raise RuntimeError("patch preflight authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch preflight requires an idle gateway")
        snapshot = self._snapshot
        if snapshot is None:
            raise RuntimeError("patch preflight lacks immutable source snapshot")
        self._reject_committed_semantic_overlap()
        unflatten_route_applicable = (
            self.plan.unflatten_proposal is not None
            or self.plan.legacy_unflatten_shadow is not None
        )
        legacy_view = _legacy_plan_view(self.plan)
        validated_effect_exclusions = _validated_exact_effect_exclusions(
            snapshot,
            projection.graph,
            legacy_view,
        )
        if not validated_effect_exclusions.accepted and not unflatten_route_applicable:
            raise PatchTransactionPreflightRejected(
                "projected effect exclusion rejected: malformed or stale exact proof"
            )
        self._validated_effect_exclusion_serials = validated_effect_exclusions.effect_serials
        terminal_reachability = check_terminal_reachability_preserved(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        effectful_reachability_raw = check_effectful_reachability_preserved(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        effectful_reachability = _apply_exact_effect_exclusions(
            effectful_reachability_raw,
            self._validated_effect_exclusion_serials,
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        entry_allowance_passed = False
        entry_allowance_reason: str | None = None
        entry_allowance = None
        projected_coverage_validation = None
        if _has_dispatcher_coverage_metadata(legacy_view):
            from d810.transforms.dispatcher_corridor_coverage import (
                has_unreachable_cyclic_switch_dispatcher_residue,
                validate_dispatcher_corridor_coverage_metadata,
                validate_dispatcher_removal_preflight_proof,
                validate_terminal_switch_cycle_break_allowance,
            )

            projected_coverage_validation = (
                validate_dispatcher_corridor_coverage_metadata(
                    snapshot,
                    post_graph=projection.graph,
                    plan_metadata=legacy_view,
                )
            )
            self._projected_dispatcher_coverage_validation = (
                projected_coverage_validation
            )
            projected_switch_cycle_hazard = (
                has_unreachable_cyclic_switch_dispatcher_residue(
                    snapshot,
                    post_graph=projection.graph,
                    plan_metadata=legacy_view,
                )
            )
        else:
            projected_switch_cycle_hazard = False
        dispatcher_removal_obligation = _has_dispatcher_removal_obligation(
            legacy_view
        )
        has_dispatcher_removal_proof = _has_dispatcher_removal_proof_metadata(
            legacy_view
        )
        if _has_dispatcher_coverage_metadata(legacy_view) and (
            not entry_reachability.passed or has_dispatcher_removal_proof
        ):
            candidate_allowance = validate_dispatcher_removal_preflight_proof(
                snapshot,
                post_graph=projection.graph,
                plan_metadata=legacy_view,
                validated_exact_effect_exclusion_serials=(
                    self._validated_effect_exclusion_serials
                ),
                patch_plan=self.plan,
            )
            candidate_allowance = validate_terminal_switch_cycle_break_allowance(
                snapshot,
                post_graph=projection.graph,
                patch_plan=self.plan,
                removal_validation=candidate_allowance,
            )
            dead_component = getattr(
                candidate_allowance,
                "detached_dead_handler_component",
                None,
            )
            if dead_component is not None:
                dead_effects = frozenset(
                    int(anchor.serial)
                    for anchor in dead_component.lost_effects
                )
                effectful_reachability = _apply_exact_effect_exclusions(
                    effectful_reachability,
                    dead_effects,
                )
            candidate_allowance = _transaction_reachability_removal_validation(
                candidate_allowance,
                coverage_validation=projected_coverage_validation,
                terminal_passed=terminal_reachability.passed,
                effectful_passed=effectful_reachability.passed,
                entry_passed=entry_reachability.passed,
                switch_cycle_hazard=projected_switch_cycle_hazard,
            )
            entry_allowance_reason = candidate_allowance.reason
            if (
                not entry_reachability.passed
                or projected_switch_cycle_hazard
                or candidate_allowance.passed
            ):
                entry_allowance = candidate_allowance
                self._projected_dispatcher_removal_validation = entry_allowance
                entry_allowance_reason = entry_allowance.reason
                if terminal_reachability.passed:
                    entry_allowance_passed = entry_allowance.passed
        dispatcher_removal_rejected = (
            dispatcher_removal_obligation
            and (
                projected_switch_cycle_hazard
                or (
                    not entry_reachability.passed
                    and (entry_allowance is None or not entry_allowance.passed)
                )
            )
        )
        projected_coverage_rejected = (
            projected_coverage_validation is not None
            and not projected_coverage_validation.passed
        )
        projected_legacy_decision = _legacy_gate_decision(
            UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
            validated_effect_exclusions,
            terminal_passed=terminal_reachability.passed,
            effectful_passed=effectful_reachability.passed,
            entry_passed=entry_reachability.passed,
            entry_allowance_passed=entry_allowance_passed,
            dispatcher_removal_rejected=dispatcher_removal_rejected,
            coverage_rejected=projected_coverage_rejected,
        )
        if not unflatten_route_applicable and (
            not terminal_reachability.passed
            or not effectful_reachability.passed
            or (not entry_reachability.passed and not entry_allowance_passed)
            or dispatcher_removal_rejected
            or projected_coverage_rejected
        ):
            effectful_detail = ""
            if not effectful_reachability.passed:
                effectful_lost = ", ".join(
                    f"blk{serial}@0x{int(snapshot.blocks[serial].start_ea):x}"
                    for serial in sorted(effectful_reachability.lost_block_serials)
                    if serial in snapshot.blocks
                )
                effectful_detail = (
                    f"effectful={effectful_reachability.reason}"
                    f"; lost={effectful_lost}; "
                )
            dispatcher_removal_detail = (
                ""
                if entry_allowance_reason is None
                else f"; dispatcher_removal={entry_allowance_reason}"
            )
            if (
                projected_coverage_validation is not None
                and not projected_coverage_validation.passed
            ):
                dispatcher_removal_detail += (
                    "; dispatcher_coverage="
                    f"{projected_coverage_validation.reason}"
                )
            raise PatchTransactionPreflightRejected(
                "projected reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"{effectful_detail}"
                f"entry={entry_reachability.reason}"
                f"{dispatcher_removal_detail}",
                projected_dispatcher_removal_validation=entry_allowance,
                projected_dispatcher_coverage_validation=(
                    projected_coverage_validation
                ),
            )
        contract = self.contract
        if contract is None:
            CfgContract().verify_projection(projection, scope="full")
            obligations = ("cfg_projection",)
        else:
            contract.verify_projection(projection, scope="full")
            contract.verify(self.mba, projection=projection, phase="pre")
            obligations = ("cfg_projection", "live_pre_check")
        from d810.transforms.unflatten_authority import transaction_api
        from d810.transforms.unflatten_authority.model import (
            UnflattenAuthorityPreparationAccepted,
            UnflattenAuthorityNotApplicable,
            UnflattenAuthorityPreparationRejected,
        )

        semantic_gates = GenericCfgGateBundle(
            entry_reachability,
            effectful_reachability_raw,
            effectful_reachability,
            terminal_reachability,
        )

        semantic_timed_result = (
            transaction_api.prepare_unflatten_authority_timed(
                source=snapshot,
                projection=projection,
                plan=self.plan,
                attempt_id=self.attempt_id,
                generic_gates=semantic_gates,
            )
            if self.plan.unflatten_proposal is not None
            or self.plan.legacy_unflatten_shadow is not None
            else UnflattenAuthorityNotApplicable(
                route=transaction_api.UnflattenPlanRoute.ORDINARY
            )
        )
        if isinstance(
            semantic_timed_result, transaction_api.TimedUnflattenAuthorityResult
        ):
            semantic_result = semantic_timed_result.result
            self._projected_unflatten_timing = semantic_timed_result.timings
        else:
            semantic_result = semantic_timed_result
        if type(semantic_result) not in (
            UnflattenAuthorityNotApplicable,
            UnflattenAuthorityPreparationAccepted,
            UnflattenAuthorityPreparationRejected,
        ):
            raise TypeError("canonical projected authority returned malformed outcome")
        if isinstance(semantic_result, UnflattenAuthorityNotApplicable):
            if unflatten_route_applicable:
                raise PatchTransactionPreflightRejected(
                    "applicable unflatten route returned not-applicable",
                )
            semantic_authority = None
            semantic_verdict = None
        elif isinstance(semantic_result, UnflattenAuthorityPreparationAccepted):
            semantic_authority = semantic_result.prepared
            semantic_verdict = semantic_result.verdict
            if self.plan.legacy_unflatten_shadow is not None:
                try:
                    self._projected_legacy_outcome = _legacy_phase_outcome(
                        UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
                        semantic_authority.source_inventory,
                        effectful_reachability_raw,
                        entry_allowance,
                        projected_legacy_decision,
                    )
                except (TypeError, ValueError) as error:
                    self._shadow_parity_error = str(error)
            if self.plan.legacy_unflatten_shadow is not None:
                try:
                    self._legacy_shadow_receipt = transaction_api.adapt_plan_legacy_shadow(
                        source=snapshot, prepared=semantic_result.prepared,
                    )
                except (TypeError, ValueError):
                    # Keep the legacy decision unchanged, but retain the
                    # adaptation failure for the owner diagnostic boundary.
                    self._legacy_shadow_receipt = None
                    self._legacy_shadow_codec_error = "legacy shadow codec adaptation rejected"
        else:
            semantic_verdict = semantic_result.verdict
            semantic_authority = None
        if semantic_verdict is not None:
            from d810.hexrays.observability import observe_unflatten_authority_phase
            from d810.transforms.unflatten_authority.diagnostics import phase_observation
            observe_unflatten_authority_phase(
                mba=self.mba,
                verdict=semantic_verdict,
                observation_factory=lambda: (phase_observation(
                    semantic_verdict,
                    maturity=str(self.plan.source_maturity),
                    source_ea=int(snapshot.func_ea),
                    timings=self._projected_unflatten_timing,
                    codec_receipt=self._legacy_shadow_receipt,
                    codec_error=self._legacy_shadow_codec_error,
                    correlation=self.attempt_id,
                    parity_error=self._shadow_parity_error,
                ),),
            )
        canonical_rejected = (
            not isinstance(semantic_result, UnflattenAuthorityPreparationAccepted)
            and not isinstance(semantic_result, UnflattenAuthorityNotApplicable)
        )
        if canonical_rejected:
            self._legacy_shadow_codec_error = (
                "canonical projected authority rejected before shadow receipt"
            )
            raise PatchTransactionPreflightRejected(
                "projected unflatten authority rejected",
                unflatten_verdict=semantic_verdict,
            )
        self._projected_unflatten_verdict = semantic_verdict
        self._unflatten_authority = semantic_authority
        semantic_obligations = ()
        if semantic_verdict is not None and semantic_verdict.safety_case is not None:
            semantic_obligations = tuple(
                f"{item.subject.subject_id}:{item.dimension.value}"
                for item in semantic_verdict.safety_case.required_obligations
            )
        prepared = PreparedPatchCfgTransaction(
            attempt_id=self.attempt_id,
            projection=projection,
            obligation_ids=tuple(obligations) + semantic_obligations,
            plan=self.plan,
            unflatten_authority=semantic_authority,
            projected_unflatten_verdict=semantic_verdict,
            projected_unflatten_timing=self._projected_unflatten_timing,
            legacy_shadow_receipt=self._legacy_shadow_receipt,
            legacy_shadow_codec_error=self._legacy_shadow_codec_error,
        )
        self.gateway._record_cfg_preflighted()
        self._prepared = prepared
        return prepared

    def bind(
        self,
        prepared: PreparedPatchCfgTransaction,
        identity_index: object,
    ) -> BoundCfgTransaction:
        if prepared is not self._prepared:
            raise ValueError("patch binding changed immutable preflight authority")
        if identity_index is not self.gateway.identity_index:
            raise ValueError("patch binding received a foreign identity index")
        if self._bound is not None:
            raise RuntimeError("patch binding authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch binding requires an idle gateway")
        self.gateway._prepare_patch_binding(
            prepared.attempt_id,
            serial_quantity=int(getattr(self.mba, "qty", 0) or 0),
        )
        patch_binding = bind_patch_plan(
            self.plan,
            identity_index,
            prepared.attempt_id,
        )
        bound_plan = patch_binding.bound_plan
        bound_authority = None
        if prepared.unflatten_authority is not None:
            from d810.transforms.unflatten_authority import transaction_api
            from d810.transforms.unflatten_authority.model import (
                UnflattenAuthorityBindingAccepted,
                UnflattenAuthorityBindingRejected,
            )

            bind_result = transaction_api.bind_prepared_unflatten_authority(
                prepared=prepared.unflatten_authority,
                patch_binding=bound_plan,
            )
            if type(bind_result) not in (
                UnflattenAuthorityBindingAccepted,
                UnflattenAuthorityBindingRejected,
            ):
                raise TypeError("canonical bind returned malformed outcome")
            if bind_result is None:
                bound_authority = None
            elif not isinstance(bind_result, UnflattenAuthorityBindingAccepted):
                raise PatchTransactionPreflightRejected(
                    "bound unflatten authority rejected",
                    unflatten_verdict=bind_result.verdict,
                )
            else:
                bound_authority = bind_result.authority
        self.gateway.register_patch_plan_reservations(patch_binding.reservations)
        self.gateway._record_cfg_bound()
        bound = BoundPatchCfgTransaction(
            prepared=prepared,
            session_id=prepared.attempt_id.session_id,
            generation=prepared.attempt_id.generation,
            bindings=bound_plan.bindings,
            plan=self.plan,
            patch_binding=bound_plan,
            unflatten_authority=bound_authority,
        )
        self._bound = bound
        return bound

    def realize(self, bound: BoundCfgTransaction, gateway: object) -> object:
        if bound is not self._bound:
            raise ValueError("patch realization changed exact binding authority")
        if gateway is not self.gateway:
            raise ValueError("patch realization received a foreign gateway")
        return self.translator.lower(
            self.plan,
            self.mba,
            mutation_gateway=self.gateway,
            bound_transaction=bound,
            post_apply_hook=self.post_apply_hook,
        )

    def observe(self, receipt: object, live_graph: object) -> FlowGraph:
        if live_graph is not self.mba:
            raise ValueError("patch observation received a foreign live graph")
        if not isinstance(receipt, int) or isinstance(receipt, bool) or receipt <= 0:
            raise TypeError("patch observation requires a positive realization count")
        if self._bound is None:
            raise RuntimeError("patch observation lacks exact binding authority")
        observed = self.translator.lift(self.mba)
        if not isinstance(observed, FlowGraph):
            raise TypeError("patch observation requires a portable FlowGraph")
        self.gateway.observe_patch_realization(
            observed,
            applied_operation_count=receipt,
        )
        self._applied_count = receipt
        return observed

    @property
    def applied_count(self) -> int:
        if self._applied_count is None:
            raise RuntimeError("patch participant has no observed operation count")
        return self._applied_count


def _first_failure(error: Exception, phase: str) -> tuple[str, str]:
    reason = str(error) or "runtime failure"
    return reason, f"runtime:{phase}"


def _request_poison_restart(gateway: object, failure: object) -> None:
    authority = getattr(gateway, "lifecycle_authority", None)
    if authority is None:
        return
    request = getattr(authority, "request_cfg_generation_restart", None)
    if not callable(request):
        raise TypeError("CFG lifecycle authority lacks poisoned restart control")
    request(failure.attempt_id, failure)


def _legacy_plan_view(plan: PatchPlan) -> Mapping[str, object]:
    """Replay one immutable legacy view for the complete validation phase.

    The replay is deliberately performed once.  Every still-decisive legacy
    validator in that phase receives this same Mapping view, preserving the
    captured canonical payloads instead of decoding a separate metadata dict.
    """
    if plan.legacy_unflatten_shadow is not None:
        from d810.transforms.unflatten_authority.legacy_codec import (
            replay_legacy_unflatten_shadow,
        )

        return replay_legacy_unflatten_shadow(plan)
    return plan.metadata_dict()


@dataclass(slots=True)
class _PatchTransactionLifecycle:
    participant: HexRaysPatchTransactionParticipant
    bound: BoundPatchCfgTransaction
    gateway: object
    plan: PatchPlan
    prepared: PreparedCfgTransaction
    failure_phase: str = "begin"

    def begin(self, patch_plan: PatchPlan) -> BoundPatchCfgTransaction:
        self.failure_phase = "begin"
        if patch_plan is not self.plan or self.bound.prepared is not self.prepared:
            raise ValueError("coordinator changed exact patch authority")
        return self.bound

    def realize(
        self,
        patch_plan: PatchPlan,
        begun: BoundPatchCfgTransaction,
    ) -> object:
        self.failure_phase = "realization"
        if patch_plan is not self.plan or begun is not self.bound:
            raise ValueError("patch realization changed coordinator authority")
        return self.participant.realize(begun, self.gateway)

    def observe(self, patch_plan: PatchPlan, realized: object) -> FlowGraph:
        self.failure_phase = "observation"
        if patch_plan is not self.plan:
            raise ValueError("patch observation changed coordinator authority")
        return self.participant.observe(realized, self.participant.mba)

    def validate(self, patch_plan: PatchPlan, observed: object) -> FlowGraph:
        self.failure_phase = "post_observation_contract"
        if patch_plan is not self.plan or not isinstance(observed, FlowGraph):
            raise TypeError("patch validation requires its observed FlowGraph")
        source = self.participant._snapshot
        if source is None:
            raise RuntimeError("patch validation lacks immutable source authority")
        observed_validation_graph = observed
        unflatten_route_applicable = (
            self.plan.unflatten_proposal is not None
            or self.plan.legacy_unflatten_shadow is not None
        )
        active_unflatten_authority = self.bound.unflatten_authority
        if active_unflatten_authority is not None:
            from d810.transforms.unflatten_authority.transaction_api import (
                revalidate_bound_patch_plan_against_prepared,
            )

            try:
                revalidate_bound_patch_plan_against_prepared(
                    active_unflatten_authority.prepared,
                    self.bound.patch_binding,
                )
            except (TypeError, ValueError) as error:
                raise PatchTransactionPostObservationRejected(
                    "observed bound authority changed before canonical validation"
                ) from error
        legacy_view = _legacy_plan_view(self.plan)
        projection = self.participant._projection
        if projection is None:
            raise RuntimeError("patch validation lacks immutable projection authority")
        validated_effect_exclusions = _validated_exact_effect_exclusions(
            source,
            projection.graph,
            legacy_view,
        )
        # Typed unflatten authority owns helper/resegmentation lineage.  Its
        # observed graph must remain raw so the authority evaluator consumes
        # the exact transaction-bound origins; ordinary legacy plans retain
        # the compatibility canonicalizer until their later migration slice.
        if (
            active_unflatten_authority is None
            and _requires_observed_identity_canonicalization(self.plan)
        ):
            from d810.transforms.dispatcher_corridor_coverage import (
                DispatcherCorridorCoverageValidation,
                canonicalize_observed_dispatcher_graph,
            )

            try:
                observed_validation_graph = canonicalize_observed_dispatcher_graph(
                    source,
                    observed,
                    self.plan,
                )
            except ValueError as error:
                observed_coverage_validation = (
                    DispatcherCorridorCoverageValidation(
                        passed=False,
                        reason="dispatcher_corridor_coverage_identity_drift",
                        function_ea=int(source.func_ea),
                    )
                    if _has_dispatcher_coverage_metadata(legacy_view)
                    else None
                )
                self.participant._observed_dispatcher_coverage_validation = (
                    observed_coverage_validation
                )
                raise PatchTransactionPostObservationRejected(
                    f"observed CFG identity rejected: {error}",
                    observed_dispatcher_coverage_validation=(
                        observed_coverage_validation
                    ),
                ) from error
        if not unflatten_route_applicable and (
            not validated_effect_exclusions.accepted
            or validated_effect_exclusions.effect_serials
            != self.participant._validated_effect_exclusion_serials
        ):
            raise PatchTransactionPostObservationRejected(
                "observed effect exclusion rejected: exact proof authority drift; "
                f"projected={tuple(sorted(self.participant._validated_effect_exclusion_serials))} "
                f"observed={tuple(sorted(validated_effect_exclusions.effect_serials))}"
            )
        terminal_reachability = check_terminal_reachability_preserved(
            source,
            post_cfg=observed_validation_graph,
        )
        effectful_reachability_raw = check_effectful_reachability_preserved(
            source,
            post_cfg=observed_validation_graph,
        )
        effectful_reachability = _apply_exact_effect_exclusions(
            effectful_reachability_raw,
            self.participant._validated_effect_exclusion_serials,
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            source,
            post_cfg=observed_validation_graph,
        )
        entry_allowance_passed = False
        observed_validation = None
        observed_coverage_validation = None
        if _has_dispatcher_coverage_metadata(legacy_view):
            from d810.transforms.dispatcher_corridor_coverage import (
                has_unreachable_cyclic_switch_dispatcher_residue,
                validate_dispatcher_corridor_coverage_metadata,
                validate_dispatcher_removal_preflight_proof,
                validate_terminal_switch_cycle_break_allowance,
            )

            observed_coverage_validation = (
                validate_dispatcher_corridor_coverage_metadata(
                    source,
                    post_graph=observed_validation_graph,
                    plan_metadata=legacy_view,
                )
            )
            self.participant._observed_dispatcher_coverage_validation = (
                observed_coverage_validation
            )
            observed_switch_cycle_hazard = (
                has_unreachable_cyclic_switch_dispatcher_residue(
                    source,
                    post_graph=observed_validation_graph,
                    plan_metadata=legacy_view,
                )
            )
        else:
            observed_switch_cycle_hazard = False
        dispatcher_removal_obligation = _has_dispatcher_removal_obligation(
            legacy_view
        )
        has_dispatcher_removal_proof = _has_dispatcher_removal_proof_metadata(
            legacy_view
        )
        if _has_dispatcher_coverage_metadata(legacy_view) and (
            not entry_reachability.passed or has_dispatcher_removal_proof
        ):
            candidate_validation = validate_dispatcher_removal_preflight_proof(
                source,
                post_graph=observed_validation_graph,
                plan_metadata=legacy_view,
                validated_exact_effect_exclusion_serials=(
                    self.participant._validated_effect_exclusion_serials
                ),
                patch_plan=self.plan,
            )
            candidate_validation = validate_terminal_switch_cycle_break_allowance(
                source,
                post_graph=observed_validation_graph,
                patch_plan=self.plan,
                removal_validation=candidate_validation,
            )
            dead_component = getattr(
                candidate_validation,
                "detached_dead_handler_component",
                None,
            )
            if dead_component is not None:
                effectful_reachability = _apply_exact_effect_exclusions(
                    effectful_reachability,
                    frozenset(
                        int(anchor.serial)
                        for anchor in dead_component.lost_effects
                    ),
                )
            candidate_validation = _transaction_reachability_removal_validation(
                candidate_validation,
                coverage_validation=observed_coverage_validation,
                terminal_passed=terminal_reachability.passed,
                effectful_passed=effectful_reachability.passed,
                entry_passed=entry_reachability.passed,
                switch_cycle_hazard=observed_switch_cycle_hazard,
            )
            if (
                not entry_reachability.passed
                or observed_switch_cycle_hazard
                or candidate_validation.passed
            ):
                observed_validation = candidate_validation
                self.participant._observed_dispatcher_removal_validation = (
                    observed_validation
                )
                if terminal_reachability.passed:
                    entry_allowance_passed = observed_validation.passed
        observed_removal_rejected = (
            dispatcher_removal_obligation
            and (
                observed_switch_cycle_hazard
                or (
                    not entry_reachability.passed
                    and (
                        observed_validation is None
                        or not observed_validation.passed
                    )
                )
            )
        )
        # A partial plan may lack a narrow full-retirement proof, but coverage
        # is still an applied diagnostic claim.  Recompute it from the observed
        # graph independently of proof validity before any applied publication.
        observed_coverage_rejected = (
            observed_coverage_validation is not None
            and not observed_coverage_validation.passed
        )
        # A bound transaction-derived alias claim is the only typed path that
        # may defer an observed effectful failure to semantic evaluation.  The
        # evaluator then scopes the allowance to its exact STORE relation;
        # this is deliberately not a serial/EA exclusion set.
        bound_claims = ()
        if active_unflatten_authority is not None:
            bound_claims = active_unflatten_authority.prepared.claims
        from d810.transforms.unflatten_authority.model import (
            LocalAliasEffectScalarizationClaim,
            UnflattenAuthorityVerdict,
        )
        has_local_alias_claim = any(
            type(claim) is LocalAliasEffectScalarizationClaim
            for claim in bound_claims
        )
        observed_replay = validated_effect_exclusions
        if (
            validated_effect_exclusions.effect_serials
            != self.participant._validated_effect_exclusion_serials
        ):
            observed_replay = _LegacyEffectReplay(
                False, validated_effect_exclusions.effect_serials,
            )
        observed_legacy_decision = _legacy_gate_decision(
            UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
            observed_replay,
            terminal_passed=terminal_reachability.passed,
            effectful_passed=(
                effectful_reachability.passed or has_local_alias_claim
            ),
            entry_passed=entry_reachability.passed,
            entry_allowance_passed=entry_allowance_passed,
            dispatcher_removal_rejected=observed_removal_rejected,
            coverage_rejected=observed_coverage_rejected,
        )
        if not unflatten_route_applicable and (
            not terminal_reachability.passed
            or (not effectful_reachability.passed and not has_local_alias_claim)
            or (not entry_reachability.passed and not entry_allowance_passed)
            or observed_removal_rejected
            or observed_coverage_rejected
        ):
            effectful_detail = ""
            if not effectful_reachability.passed:
                effectful_lost = ", ".join(
                    f"blk{serial}@0x{int(source.blocks[serial].start_ea):x}"
                    for serial in sorted(effectful_reachability.lost_block_serials)
                    if serial in source.blocks
                )
                effectful_detail = (
                    f"effectful={effectful_reachability.reason}"
                    f"; lost={effectful_lost}; "
                )
            detail = (
                ""
                if observed_validation is None
                else f"; dispatcher_removal={observed_validation.reason}"
            )
            if (
                observed_coverage_validation is not None
                and not observed_coverage_validation.passed
            ):
                detail += (
                    "; dispatcher_coverage="
                    f"{observed_coverage_validation.reason}"
                )
            raise PatchTransactionPostObservationRejected(
                "observed reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"{effectful_detail}"
                f"entry={entry_reachability.reason}{detail}",
                observed_dispatcher_removal_validation=observed_validation,
                observed_dispatcher_coverage_validation=(
                    observed_coverage_validation
                ),
            )
        if self.plan.legacy_unflatten_shadow is not None and active_unflatten_authority is not None:
            try:
                self.participant._observed_legacy_outcome = _legacy_phase_outcome(
                    UnflattenAuthorityPhase.OBSERVED_POST_APPLY,
                    active_unflatten_authority.prepared.source_inventory,
                    effectful_reachability_raw,
                    observed_validation,
                    observed_legacy_decision,
                )
            except (TypeError, ValueError) as error:
                self.participant._shadow_parity_error = str(error)
        if active_unflatten_authority is not None:
            from d810.transforms.unflatten_authority import transaction_api
            semantic_gates = GenericCfgGateBundle(
                entry_reachability,
                effectful_reachability_raw,
                effectful_reachability,
                terminal_reachability,
            )

            semantic_timed_result = transaction_api.revalidate_observed_unflatten_authority_timed(
                authority=active_unflatten_authority,
                observed=observed_validation_graph,
                observed_generation=int(self.gateway.generation),
                generic_gates=semantic_gates,
            )
            if not isinstance(
                semantic_timed_result, transaction_api.TimedUnflattenAuthorityResult
            ):
                raise TypeError("canonical observed authority returned malformed outcome")
            semantic_verdict = semantic_timed_result.result
            if type(semantic_verdict) is not UnflattenAuthorityVerdict:
                raise TypeError("canonical observed authority returned malformed verdict")
            self.participant._observed_unflatten_timing = semantic_timed_result.timings
            self.participant._observed_unflatten_verdict = semantic_verdict
            if active_unflatten_authority is not None:
                self.participant._observed_unflatten_verdict = semantic_verdict
                parity_payload = None
            if active_unflatten_authority is not None and (
                self.participant._legacy_shadow_receipt is not None
                and self.participant._projected_legacy_outcome is not None
                and self.participant._observed_legacy_outcome is not None
                and self.participant._projected_unflatten_verdict is not None
                and self.participant._projected_unflatten_verdict.safety_case is not None
                and semantic_verdict is not None
                and semantic_verdict.safety_case is not None
            ):
                from d810.transforms.unflatten_authority.diagnostics import (
                    compare_shadow_parity,
                )
                try:
                    parity_payload = compare_shadow_parity(
                        self.participant._projected_legacy_outcome,
                        self.participant._projected_unflatten_verdict,
                        self.participant._observed_legacy_outcome,
                        semantic_verdict,
                        projected_counters=ShadowParityCounters.from_case(
                            self.participant._projected_unflatten_verdict.safety_case,
                        ),
                        observed_counters=ShadowParityCounters.from_case(
                            semantic_verdict.safety_case,
                        ),
                        codec_receipt=self.participant._legacy_shadow_receipt,
                    )
                    self.participant._shadow_parity_payload = parity_payload
                except Exception as error:
                    self.participant._shadow_parity_error = str(error)
            if active_unflatten_authority is not None:
                from d810.hexrays.observability import observe_unflatten_authority_phase
                from d810.transforms.unflatten_authority.diagnostics import phase_observation
                observe_unflatten_authority_phase(
                    mba=self.participant.mba,
                    verdict=semantic_verdict,
                    observation_factory=lambda: (phase_observation(
                        semantic_verdict,
                        maturity=str(self.plan.source_maturity),
                        source_ea=int(observed.func_ea),
                        timings=self.participant._observed_unflatten_timing,
                        codec_receipt=self.participant._legacy_shadow_receipt,
                        codec_error=self.participant._legacy_shadow_codec_error,
                        parity_payload=parity_payload,
                        parity_error=self.participant._shadow_parity_error,
                        correlation=active_unflatten_authority.attempt_id,
                        projected_case=active_unflatten_authority.prepared.projected_case,
                    ),),
                )
                if not semantic_verdict.accepted:
                    raise PatchTransactionPostObservationRejected(
                        "observed unflatten authority rejected",
                        unflatten_verdict=semantic_verdict,
                    )
        post_projection = CfgProjection(
            plan_id=self.prepared.projection.plan_id,
            snapshot_id=self.prepared.projection.snapshot_id,
            graph=observed_validation_graph,
            focus_refs=self.prepared.projection.focus_refs,
        )
        contract = self.participant.contract
        if contract is None:
            CfgContract().verify_projection(post_projection, scope="full")
        else:
            contract.verify_projection(post_projection, scope="full")
        return observed

    def commit(
        self,
        patch_plan: PatchPlan,
        validated: object,
    ) -> PatchTransactionExecution:
        self.failure_phase = "commit"
        if patch_plan is not self.plan or not isinstance(validated, FlowGraph):
            raise TypeError("patch commit requires its validated FlowGraph")
        creation_receipts = tuple(self.gateway.plan_creation_receipts)
        receipt = self.gateway.commit()
        return PatchTransactionExecution(
            applied_count=self.participant.applied_count,
            graph=validated,
            receipt=receipt,
            creation_receipts=creation_receipts,
            projected_dispatcher_removal_validation=(
                self.participant._projected_dispatcher_removal_validation
            ),
            projected_dispatcher_coverage_validation=(
                self.participant._projected_dispatcher_coverage_validation
            ),
            observed_dispatcher_removal_validation=(
                self.participant._observed_dispatcher_removal_validation
            ),
            observed_dispatcher_coverage_validation=(
                self.participant._observed_dispatcher_coverage_validation
            ),
            projected_unflatten_verdict=self.participant._projected_unflatten_verdict,
            observed_unflatten_verdict=self.participant._observed_unflatten_verdict,
            projected_unflatten_timing=self.participant._projected_unflatten_timing,
            observed_unflatten_timing=self.participant._observed_unflatten_timing,
            shadow_parity_payload=self.participant._shadow_parity_payload,
            legacy_shadow_codec_error=self.participant._legacy_shadow_codec_error,
            shadow_parity_error=self.participant._shadow_parity_error,
        )

    def fail(self, patch_plan: PatchPlan, error: Exception, phase: str) -> None:
        del patch_plan, phase
        if getattr(self.gateway, "generation_poisoned", False):
            failure = self.gateway.transaction_failure
            if failure is not None:
                _request_poison_restart(self.gateway, failure)
            return
        reason, obligation = _first_failure(error, self.failure_phase)
        if getattr(self.gateway, "mutation_started", False):
            failure = self.gateway._poison_cfg_generation(
                reason=reason,
                failure_phase=self.failure_phase,
                first_failed_obligation=obligation,
            )
            _request_poison_restart(self.gateway, failure)
            raise PatchTransactionPoisoned(
                failure,
                observed_dispatcher_removal_validation=(
                    self.participant._observed_dispatcher_removal_validation
                ),
                observed_dispatcher_coverage_validation=(
                    self.participant._observed_dispatcher_coverage_validation
                ),
                unflatten_verdict=self.participant._observed_unflatten_verdict,
            ) from error
        if self.gateway.transaction_failure is None:
            self.gateway._record_clean_cfg_failure(
                reason=reason,
                failure_phase=self.failure_phase,
                first_failed_obligation=obligation,
            )
        self.gateway.abort(reason=reason)


def execute_patch_transaction(
    root_gateway: object,
    translator: object,
    plan: PatchPlan,
    mba: object,
    *,
    pre_cfg: FlowGraph,
    contract: object | None = None,
    post_apply_hook: object | None = None,
    attempt_id: TransactionAttemptId | None = None,
) -> PatchTransactionExecution:
    """Execute one ordinary PatchPlan through immutable authority and one coordinator."""
    if not isinstance(plan, PatchPlan):
        raise TypeError("patch transaction requires a PatchPlan")
    if not isinstance(pre_cfg, FlowGraph):
        raise TypeError("patch transaction requires an immutable pre-CFG")
    gateway = root_gateway.new_transaction()
    participant = HexRaysPatchTransactionParticipant(
        gateway=gateway,
        translator=translator,
        mba=mba,
        plan=plan,
        contract=contract,
        post_apply_hook=post_apply_hook,
        attempt_authority=attempt_id,
    )
    phase = "projection"
    try:
        _publish_patch_plan_observation(participant, pre_cfg)
        projected = participant.project(plan, pre_cfg)
        phase = "preflight"
        prepared = participant.preflight(projected)
        phase = "binding"
        bound = participant.bind(prepared, gateway.identity_index)
    except Exception as error:
        reason, obligation = _first_failure(error, phase)
        if gateway.current_transaction_attempt is not None:
            gateway._record_clean_cfg_failure(
                reason=reason,
                failure_phase=phase,
                first_failed_obligation=obligation,
            )
            gateway.abort(reason=reason)
        raise
    if not isinstance(bound, BoundPatchCfgTransaction):
        raise TypeError("patch participant returned invalid binding authority")
    from d810.transforms.fragment_to_patch import (
        CfgTransactionCoordinator,
        PatchTransactionParticipant,
    )

    lifecycle = _PatchTransactionLifecycle(
        participant=participant,
        bound=bound,
        gateway=gateway,
        plan=plan,
        prepared=prepared,
    )
    return CfgTransactionCoordinator(lifecycle).execute(
        PatchTransactionParticipant(),
        plan,
    )


__all__ = [
    "BoundPatchCfgTransaction",
    "HexRaysPatchTransactionParticipant",
    "PreparedPatchCfgTransaction",
    "PatchTransactionExecution",
    "PatchTransactionPoisoned",
    "PatchTransactionPostObservationRejected",
    "PatchTransactionPreflightRejected",
    "execute_patch_transaction",
]
