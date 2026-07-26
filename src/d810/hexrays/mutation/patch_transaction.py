"""Production participant for immutable PatchPlan CFG transactions."""

from __future__ import annotations

from dataclasses import dataclass, field

from d810.analyses.control_flow.graph_checks import (
    check_entry_reachability_not_collapsed,
    check_terminal_reachability_preserved,
)
from d810.analyses.control_flow.native_preanalysis_session import (
    CommittedSemanticFragmentOwnership,
)
from d810.ir.block_identity import (
    StableBlockIdentity,
    stable_block_identities_overlap,
    stable_block_identity_semantic_anchor,
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
    TransactionAttemptId,
)
from d810.transforms.contract import CfgContract
from d810.transforms.edit_simulator import project_patch_plan
from d810.transforms.plan import PatchPlan
from d810.hexrays.mutation.patch_binding import BoundPatchPlan, bind_patch_plan


class PatchTransactionPreflightRejected(RuntimeError):
    """An immutable PatchPlan obligation failed before any SDK write."""


class PatchTransactionPostObservationRejected(RuntimeError):
    """The realized live graph lost a preflighted reachability obligation."""


@dataclass(frozen=True, slots=True)
class PatchTransactionExecution(PatchPlanExecutionResult):
    """Committed ordinary PatchPlan result returned by the shared coordinator."""

    applied_count: int
    graph: FlowGraph
    receipt: object
    creation_receipts: tuple[object, ...] = ()

    def __post_init__(self) -> None:
        PatchPlanExecutionResult.__post_init__(self)
        if self.applied_count <= 0:
            raise ValueError("patch execution requires a positive applied count")


@dataclass(frozen=True, slots=True)
class BoundPatchCfgTransaction(BoundCfgTransaction):
    """Generic transaction authority plus the exact final-boundary binding."""

    plan: PatchPlan | None = None
    patch_binding: BoundPatchPlan | None = None

    def __post_init__(self) -> None:
        BoundCfgTransaction.__post_init__(self)
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("bound patch transaction requires a PatchPlan")
        if not isinstance(self.patch_binding, BoundPatchPlan):
            raise TypeError("bound patch transaction requires final live binding")
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
    attempt_id: TransactionAttemptId = field(init=False)
    _projection: CfgProjection | None = field(default=None, init=False, repr=False)
    _snapshot: FlowGraph | None = field(default=None, init=False, repr=False)
    _prepared: PreparedCfgTransaction | None = field(
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

    def __post_init__(self) -> None:
        if not isinstance(self.plan, PatchPlan):
            raise TypeError("patch participant requires a PatchPlan")
        identity_index = getattr(self.gateway, "identity_index", None)
        if identity_index is None:
            raise TypeError("patch participant requires an identity index")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch participant requires an idle gateway")
        self.attempt_id = TransactionAttemptId.new(
            self.plan.plan_id,
            str(self.gateway.session_id),
            int(self.gateway.generation),
        )

    def project(self, plan: object, snapshot: object) -> CfgProjection:
        if plan is not self.plan:
            raise ValueError("patch projection changed exact plan authority")
        if not isinstance(snapshot, FlowGraph):
            raise TypeError("patch projection requires an immutable FlowGraph")
        if self._projection is not None:
            raise RuntimeError("patch projection authority is single-use")
        if bool(getattr(self.gateway, "active", False)):
            raise RuntimeError("patch projection requires an idle gateway")
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

    def _portable_identity_for_ref(
        self,
        ref: NativeBlockRef | LogicalBlockRef,
    ) -> StableBlockIdentity | None:
        if isinstance(ref, NativeBlockRef):
            return ref.identity
        if isinstance(ref, LogicalBlockRef):
            return self.gateway.identity_index.published_identity_for_logical_ref(ref)
        raise TypeError("semantic ownership preflight requires a portable block ref")

    def _reject_committed_semantic_overlap(self) -> None:
        authority = getattr(self.gateway, "lifecycle_authority", None)
        if authority is None:
            return
        publications = authority.committed_semantic_ownership()
        if not isinstance(publications, tuple) or any(
            not isinstance(item, CommittedSemanticFragmentOwnership)
            for item in publications
        ):
            raise TypeError("semantic ownership lifecycle result is not typed")
        for ref, _coordinate in self.plan.source_coordinates:
            identity = self._portable_identity_for_ref(ref)
            if identity is None:
                continue
            for publication in publications:
                for owner in publication.owners:
                    if not stable_block_identities_overlap(
                        owner.stable_identity,
                        identity,
                    ):
                        continue
                    anchor_ea = stable_block_identity_semantic_anchor(identity)
                    raise PatchTransactionPreflightRejected(
                        f"patch plan {self.plan.plan_id} overlaps committed "
                        f"semantic plan {publication.plan_id} operation "
                        f"{owner.operation_id} source {owner.source_block_id} at "
                        f"0x{anchor_ea:X}"
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
        terminal_reachability = check_terminal_reachability_preserved(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            snapshot,
            post_adj=projection.graph.as_adjacency_dict(),
        )
        if not terminal_reachability.passed or not entry_reachability.passed:
            raise PatchTransactionPreflightRejected(
                "projected reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"entry={entry_reachability.reason}"
            )
        contract = self.contract
        if contract is None:
            CfgContract().verify_projection(projection, scope="full")
            obligations = ("cfg_projection",)
        else:
            contract.verify_projection(projection, scope="full")
            contract.verify(self.mba, projection=projection, phase="pre")
            obligations = ("cfg_projection", "live_pre_check")
        prepared = PreparedCfgTransaction(
            attempt_id=self.attempt_id,
            projection=projection,
            obligation_ids=obligations,
        )
        self.gateway._record_cfg_preflighted()
        self._prepared = prepared
        return prepared

    def bind(
        self,
        prepared: PreparedCfgTransaction,
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
        self.gateway.register_patch_plan_reservations(patch_binding.reservations)
        self.gateway._record_cfg_bound()
        bound = BoundPatchCfgTransaction(
            prepared=prepared,
            session_id=prepared.attempt_id.session_id,
            generation=prepared.attempt_id.generation,
            bindings=patch_binding.bindings,
            plan=self.plan,
            patch_binding=patch_binding,
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
    reason = str(error) or type(error).__name__
    return reason, f"runtime:{phase}"


def _request_poison_restart(gateway: object, failure: object) -> None:
    authority = getattr(gateway, "lifecycle_authority", None)
    if authority is None:
        return
    request = getattr(authority, "request_cfg_generation_restart", None)
    if not callable(request):
        raise TypeError("CFG lifecycle authority lacks poisoned restart control")
    request(failure.attempt_id, failure)


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
        terminal_reachability = check_terminal_reachability_preserved(
            source,
            post_cfg=observed,
        )
        entry_reachability = check_entry_reachability_not_collapsed(
            source,
            post_cfg=observed,
        )
        if not terminal_reachability.passed or not entry_reachability.passed:
            raise PatchTransactionPostObservationRejected(
                "observed reachability rejected: "
                f"terminal={terminal_reachability.reason}; "
                f"entry={entry_reachability.reason}"
            )
        post_projection = CfgProjection(
            plan_id=self.prepared.projection.plan_id,
            snapshot_id=self.prepared.projection.snapshot_id,
            graph=observed,
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
            raise CfgGenerationPoisoned(failure) from error
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
    )
    phase = "projection"
    try:
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
    "PatchTransactionExecution",
    "PatchTransactionPostObservationRejected",
    "PatchTransactionPreflightRejected",
    "execute_patch_transaction",
]
