"Diagnostic observation event dataclasses.\n\nEvent types live here under :mod:`d810.core` so the SQLite sink in\n:mod:`d810.core.diag.event_handlers` can subscribe without importing\nfrom upper layers (:mod:`d810.preanalysis`, :mod:`d810.cfg`,\n:mod:`d810.hexrays`) -- which the layered-architecture import-linter\ncontract forbids.\n\nDomain observability modules (:mod:`d810.core.observability_recon`,\n:mod:`d810.core.observability_cfg`, :mod:`d810.hexrays.observability`)\nre-export the events relevant to their domain and own the\n``observe_*`` emit helpers. Subscribers consume the dataclasses\ndirectly from this module.\n\nZero imports from :mod:`d810.core.diag` -- the sink subscribes to\nthese types but does not own them.\n"

from __future__ import annotations

from dataclasses import dataclass, field
import json
from uuid import uuid4

from d810.core.observability import SnapshotRef
from d810.core.observability_models import (
    BlockSnapshot,
    DagEdge,
    DagNode,
    Modification,
)
from d810.core.semantic_route_oracle import RouteOracleComparison
from d810.core.typing import Any


# ---------------------------------------------------------------------------
# Hex-Rays domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CaptureMbaSnapshotRequested:
    """Hex-Rays requested a full MBA capture under ``snapshot``.

    The diag subscriber inserts a row in ``snapshots`` and binds
    ``snapshot.key`` to the assigned SQLite id; subsequent
    ``*Observed`` events that carry the same ``snapshot`` then resolve
    to that id and write child rows.
    """

    snapshot: SnapshotRef
    blocks: tuple[BlockSnapshot, ...]


@dataclass(frozen=True)
class DiagnosticSessionObserved:
    """Manager-owned decompilation session entered or changed terminal state."""

    session_id: str
    func_ea: int
    top_level_epoch: int
    native_key_json: str
    status: str
    timestamp: float = 0.0


@dataclass(frozen=True)
class InputIdentityResolutionObserved:
    """Durable identity provenance for one D810 decompilation session."""

    session_id: str
    func_ea: int
    status: str
    provenance: str | None
    mismatch_field: str | None
    external_evidence_allowed: bool
    database_uuid: str | None
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not isinstance(self.session_id, str) or not self.session_id.strip():
            raise ValueError("session_id must be non-empty")
        if int(self.func_ea) < 0:
            raise ValueError("func_ea must be non-negative")
        if not isinstance(self.status, str) or not self.status.strip():
            raise ValueError("status must be non-empty")
        for field_name in ("provenance", "mismatch_field", "database_uuid"):
            value = getattr(self, field_name)
            if value is not None and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"{field_name} must be non-empty when set")
        if not isinstance(self.external_evidence_allowed, bool):
            raise TypeError("external_evidence_allowed must be a bool")


@dataclass(frozen=True)
class LifecycleEventObserved:
    """Portable event-native diagnostic record with optional snapshot context."""

    session_id: str
    func_ea: int
    event_kind: str
    snapshot: SnapshotRef | None = None
    provider: str | None = None
    maturity: str | None = None
    phase: str | None = None
    evidence_generation: int | None = None
    mba_generation_before: int | None = None
    mba_generation_after: int | None = None
    correlation_id: str | None = None
    summary: str = ""
    payload: dict[str, Any] = field(default_factory=dict)
    timestamp: float = 0.0


@dataclass(frozen=True)
class FrontendNormalizationPlanIntentObserved:
    """Receipt-backed, typed frontend normalization plan intent."""

    session_id: str
    func_ea: int
    evidence_generation: int
    work_item_id: str
    plan_id: str
    atomic_group_id: str
    publication_revision: int
    block_count: int
    operation_count: int
    imported_block_count: int
    native_body_count: int
    published_operation_ids: tuple[str, ...]
    selected_obligation_ids: tuple[str, ...]
    remaining_obligation_ids: tuple[str, ...]
    unreachable_obligation_ids: tuple[str, ...]
    complete_plan_json: str
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        for field_name in (
            "session_id",
            "work_item_id",
            "plan_id",
            "atomic_group_id",
            "complete_plan_json",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if int(self.func_ea) < 0:
            raise ValueError("func_ea must be non-negative")
        for field_name in (
            "evidence_generation",
            "publication_revision",
            "block_count",
            "operation_count",
            "imported_block_count",
            "native_body_count",
        ):
            if int(getattr(self, field_name)) < 0:
                raise ValueError(f"{field_name} must be non-negative")
        for field_name in (
            "published_operation_ids",
            "selected_obligation_ids",
            "remaining_obligation_ids",
            "unreachable_obligation_ids",
        ):
            values = tuple(str(value) for value in getattr(self, field_name))
            if any(not value.strip() for value in values):
                raise ValueError(f"{field_name} must contain non-empty identifiers")
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must not contain duplicates")
            object.__setattr__(self, field_name, values)


@dataclass(frozen=True)
class SemanticOutputVerifiedObserved:
    """Typed semantic-output verification receipt and witness identity."""

    session_id: str
    func_ea: int
    verifier_id: str
    witness_id: str
    summary: str
    native_anchor_ea: int
    evidence_generation: int
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        for field_name in (
            "session_id",
            "verifier_id",
            "witness_id",
            "summary",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if int(self.func_ea) < 0:
            raise ValueError("func_ea must be non-negative")
        if int(self.native_anchor_ea) < 0:
            raise ValueError("native_anchor_ea must be non-negative")
        if int(self.evidence_generation) < 0:
            raise ValueError("evidence_generation must be non-negative")


@dataclass(frozen=True)
class PassContractEvidencePublished:
    """One anchored native pass-contract output accepted by the driver."""

    session_id: str
    func_ea: int
    evidence_generation: int
    maturity: str
    pass_id: str
    evidence_token: str
    native_anchor_eas: tuple[int, ...]
    summary: str
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        for field_name in (
            "session_id",
            "maturity",
            "pass_id",
            "evidence_token",
            "summary",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")
        if int(self.func_ea) < 0:
            raise ValueError("func_ea must be non-negative")
        if int(self.evidence_generation) < 0:
            raise ValueError("evidence_generation must be non-negative")
        anchors = tuple(int(anchor) for anchor in self.native_anchor_eas)
        if not anchors:
            raise ValueError("pass contract evidence requires native anchors")
        if any(anchor < 0 for anchor in anchors):
            raise ValueError("pass contract evidence anchors must be non-negative")
        if anchors != tuple(sorted(set(anchors))):
            raise ValueError(
                "pass contract evidence anchors must be ordered and unique"
            )
        object.__setattr__(self, "native_anchor_eas", anchors)


@dataclass(frozen=True)
class EvidenceGenerationObserved:
    session_id: str
    func_ea: int
    operation: str
    previous_generation: int
    resulting_generation: int
    evidence_family: str
    outcome: str
    owner: str
    reason: str
    snapshot: SnapshotRef | None = None
    provider: str | None = None
    maturity: str | None = None
    phase: str | None = None
    timestamp: float = 0.0


@dataclass(frozen=True)
class IdentityDecisionObserved:
    session_id: str
    func_ea: int
    decision_kind: str
    consumer: str
    identity_role: str
    native_key_json: str
    exact_eas_json: str
    native_ranges_json: str
    primary_anchor_ea: int | None
    current_serial: int | None
    mba_generation: int
    evidence_generation: int
    maturity: str
    outcome: str
    candidates_json: str
    reason: str
    snapshot: SnapshotRef | None = None
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if self.current_serial is not None and self.primary_anchor_ea is None:
            raise ValueError("a serial identity decision requires an EA anchor")
        if self.primary_anchor_ea is None:
            raise ValueError("an identity decision requires an EA anchor")
        if int(self.mba_generation) < 0 or int(self.evidence_generation) < 0:
            raise ValueError("identity decision generations must be non-negative")


@dataclass(frozen=True)
class MutationPlanItemObserved:
    item_index: int
    mutation_kind: str
    source_serial: int | None
    source_anchor_ea: int | None
    source_identity_json: str | None
    target_serial: int | None
    target_anchor_ea: int | None
    target_identity_json: str | None
    disposition: str
    reason: str

    def __post_init__(self) -> None:
        if self.source_serial is not None and self.source_anchor_ea is None:
            raise ValueError("a planned source serial requires an EA anchor")
        if self.target_serial is not None and self.target_anchor_ea is None:
            raise ValueError("a planned target serial requires an EA anchor")


@dataclass(frozen=True)
class FragmentValidationOutcomeObserved:
    """One queryable semantic-fragment validation result."""

    phase: str
    postcondition: str
    subject_id: str
    passed: bool
    reason: str
    block_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.phase not in {"prepublication", "postpublication"}:
            raise ValueError("fragment validation phase is invalid")
        if not self.postcondition or not self.subject_id:
            raise ValueError("fragment validation requires a postcondition and subject")
        object.__setattr__(self, "passed", bool(self.passed))
        object.__setattr__(
            self,
            "block_ids",
            tuple(str(block_id) for block_id in self.block_ids),
        )


@dataclass(frozen=True)
class LogicalBlockVersionTransitionObserved:
    """One complete logical-version state transition without MBA serials."""

    proxy_token: str
    version: int
    physical_handle_token: str
    generation: int
    provenance: str
    stable_identity_json: str | None
    anchor_ea: int | None
    predecessor_version: int | None
    from_state: str
    to_state: str

    def __post_init__(self) -> None:
        states = {"staged", "published", "retired", "aborted"}
        proxy_token = str(self.proxy_token)
        physical_handle_token = str(self.physical_handle_token)
        version = int(self.version)
        generation = int(self.generation)
        predecessor_version = (
            None if self.predecessor_version is None else int(self.predecessor_version)
        )
        anchor_ea = None if self.anchor_ea is None else int(self.anchor_ea)
        if not proxy_token or not physical_handle_token:
            raise ValueError(
                "logical-version transition requires logical and physical tokens"
            )
        if version < 0 or generation < 0:
            raise ValueError(
                "logical-version number and generation must be non-negative"
            )
        if predecessor_version is not None and (
            predecessor_version < 0 or predecessor_version >= version
        ):
            raise ValueError("logical-version predecessor must be an earlier version")
        if self.from_state not in states or self.to_state not in states:
            raise ValueError("logical-version transition state is invalid")
        if (self.from_state, self.to_state) not in {
            ("published", "retired"),
            ("staged", "published"),
            ("staged", "aborted"),
        }:
            raise ValueError("logical-version transition is not authoritative")
        synthetic_provenance = {"created_synthetic", "observed_ephemeral"}
        if self.provenance not in {
            "native",
            "imported_native",
            *synthetic_provenance,
        }:
            raise ValueError("logical-version provenance is invalid")
        if self.provenance in synthetic_provenance:
            if self.stable_identity_json is not None or anchor_ea is not None:
                raise ValueError(
                    "synthetic logical version cannot claim native identity"
                )
        else:
            if self.stable_identity_json is None or anchor_ea is None:
                raise ValueError(
                    "native logical version requires identity and EA anchor"
                )
            try:
                identity_payload = json.loads(self.stable_identity_json)
            except (TypeError, ValueError) as exc:
                raise ValueError(
                    "logical-version stable identity JSON is invalid"
                ) from exc
            if not isinstance(identity_payload, dict):
                raise ValueError("logical-version stable identity must be an object")
            if anchor_ea < 0:
                raise ValueError("logical-version EA anchor must be non-negative")
        object.__setattr__(self, "proxy_token", proxy_token)
        object.__setattr__(self, "version", version)
        object.__setattr__(
            self,
            "physical_handle_token",
            physical_handle_token,
        )
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "anchor_ea", anchor_ea)
        object.__setattr__(
            self,
            "predecessor_version",
            predecessor_version,
        )


@dataclass(frozen=True)
class FragmentRootPublicationGroupObserved:
    """Serial-free ownership and outcome for one root predecessor group."""

    group_id: str
    predecessor_block_id: str
    predecessor_anchor_ea: int
    edge_ids: tuple[str, ...]
    edge_roles: tuple[str, ...]
    original_block_ids: tuple[str, ...]
    replacement_block_ids: tuple[str, ...]
    publication_attempted: bool = False
    publication_succeeded: bool = False
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None

    def __post_init__(self) -> None:
        group_id = str(self.group_id)
        predecessor_block_id = str(self.predecessor_block_id)
        if group_id != f"root-group:{predecessor_block_id}":
            raise ValueError("root publication group identity drifted")
        if int(self.predecessor_anchor_ea) < 0:
            raise ValueError("root publication group requires an EA anchor")
        edge_ids = tuple(str(edge_id) for edge_id in self.edge_ids)
        edge_roles = tuple(str(role) for role in self.edge_roles)
        original_block_ids = tuple(
            str(block_id) for block_id in self.original_block_ids
        )
        replacement_block_ids = tuple(
            str(block_id) for block_id in self.replacement_block_ids
        )
        edge_count = len(edge_ids)
        if (
            edge_count == 0
            or len(set(edge_ids)) != edge_count
            or len(edge_roles) != edge_count
            or len(original_block_ids) != edge_count
            or len(replacement_block_ids) != edge_count
            or any(not edge_id for edge_id in edge_ids)
            or any(not block_id for block_id in original_block_ids)
            or any(not block_id for block_id in replacement_block_ids)
            or any(
                role
                not in {
                    "direct",
                    "call_fallthrough",
                    "conditional_taken",
                    "conditional_fallthrough",
                }
                for role in edge_roles
            )
        ):
            raise ValueError(
                "root publication group requires aligned semantic edge ownership"
            )
        publication_attempted = bool(self.publication_attempted)
        publication_succeeded = bool(self.publication_succeeded)
        rollback_attempted = bool(self.rollback_attempted)
        rollback_succeeded = (
            None if self.rollback_succeeded is None else bool(self.rollback_succeeded)
        )
        if publication_succeeded and not publication_attempted:
            raise ValueError("root publication cannot succeed before its attempt")
        if rollback_attempted != (rollback_succeeded is not None):
            raise ValueError(
                "root-group rollback outcome is present exactly when attempted"
            )
        if rollback_attempted and not publication_attempted:
            raise ValueError("root-group rollback requires publication attempt")
        object.__setattr__(self, "group_id", group_id)
        object.__setattr__(self, "predecessor_block_id", predecessor_block_id)
        object.__setattr__(
            self,
            "predecessor_anchor_ea",
            int(self.predecessor_anchor_ea),
        )
        object.__setattr__(self, "edge_ids", edge_ids)
        object.__setattr__(self, "edge_roles", edge_roles)
        object.__setattr__(self, "original_block_ids", original_block_ids)
        object.__setattr__(self, "replacement_block_ids", replacement_block_ids)
        object.__setattr__(
            self,
            "publication_attempted",
            publication_attempted,
        )
        object.__setattr__(
            self,
            "publication_succeeded",
            publication_succeeded,
        )
        object.__setattr__(self, "rollback_attempted", rollback_attempted)
        object.__setattr__(self, "rollback_succeeded", rollback_succeeded)


@dataclass(frozen=True)
class CfgCreationWitnessObserved:
    """Portable ownership and coordinate evidence for one plan-local block."""

    local_block_id: str
    provenance: str | None
    reserved_handle_token: str | None = None
    logical_proxy_token: str | None = None
    logical_version: int | None = None
    logical_generation: int | None = None
    insertion_quantity_before: int | None = None
    insertion_quantity_after: int | None = None
    requested_insertion_serial: int | None = None
    returned_serial: int | None = None
    invalidated: bool = False
    state: str = "planned"

    def __post_init__(self) -> None:
        if not str(self.local_block_id):
            raise ValueError("creation witness requires a plan-local block id")
        if self.provenance is not None and self.provenance not in {
            "native",
            "imported_native",
            "created_synthetic",
            "observed_ephemeral",
        }:
            raise ValueError("creation witness provenance is invalid")
        if self.state not in {
            "planned",
            "reserved",
            "bound",
            "observed",
            "committed",
            "invalidated",
        }:
            raise ValueError("creation witness state is invalid")
        numeric = (
            self.logical_version,
            self.logical_generation,
            self.insertion_quantity_before,
            self.insertion_quantity_after,
            self.requested_insertion_serial,
            self.returned_serial,
        )
        if any(value is not None and int(value) < 0 for value in numeric):
            raise ValueError("creation witness coordinates must be non-negative")
        requires_coordinates = self.state == "bound" or (
            self.state == "committed"
            and self.provenance in {"created_synthetic", "imported_native"}
        )
        if requires_coordinates and (
            self.requested_insertion_serial is None or self.returned_serial is None
        ):
            raise ValueError("bound creation witness requires both coordinates")


@dataclass(frozen=True)
class CfgTransactionAttemptObserved:
    """One ordered portable CFG transaction phase and its current witnesses."""

    session_id: str
    func_ea: int
    plan_id: str
    attempt_id: str
    phase: str
    phase_index: int
    mba_generation: int
    evidence_generation: int
    mutation_started: bool
    poisoned: bool
    first_failure_obligation: str | None = None
    first_failure_phase: str | None = None
    first_failure_reason: str | None = None
    interr_code: int | None = None
    creation_witnesses: tuple[CfgCreationWitnessObserved, ...] = ()
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        phases = {
            "planned",
            "projected",
            "preflighted",
            "bound",
            "realizing",
            "observed",
            "committed",
            "rejected_clean",
            "poisoned_restart_required",
        }
        if self.phase not in phases:
            raise ValueError("CFG transaction phase is invalid")
        if not self.session_id or not self.plan_id or not self.attempt_id:
            raise ValueError("CFG transaction authority is incomplete")
        if (
            min(
                int(self.phase_index),
                int(self.mba_generation),
                int(self.evidence_generation),
            )
            < 0
        ):
            raise ValueError("CFG transaction counters must be non-negative")
        if bool(self.poisoned) != (self.phase == "poisoned_restart_required"):
            raise ValueError("CFG transaction poison flag is invalid")
        failure_fields = (
            self.first_failure_obligation,
            self.first_failure_phase,
            self.first_failure_reason,
        )
        if any(failure_fields) and not self.first_failure_reason:
            raise ValueError("CFG transaction failure requires a reason")
        if any(
            not isinstance(witness, CfgCreationWitnessObserved)
            for witness in self.creation_witnesses
        ):
            raise TypeError("CFG transaction contains an invalid creation witness")
        if len({w.local_block_id for w in self.creation_witnesses}) != len(
            self.creation_witnesses
        ):
            raise ValueError("CFG transaction witnesses must be unique")


@dataclass(frozen=True)
class MutationPlanObserved:
    session_id: str
    func_ea: int
    mutation_batch_id: str
    mutation_kind: str
    planned_operation_count: int
    mba_generation: int
    evidence_generation: int
    maturity: str
    description: str
    items: tuple[MutationPlanItemObserved, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    fragment_plan_json: str = ""
    root_publication_groups: tuple[FragmentRootPublicationGroupObserved, ...] = ()
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        fragment_fields = (
            bool(self.fragment_plan_id),
            bool(self.fragment_atomic_group_id),
            bool(self.fragment_plan_json),
        )
        if any(fragment_fields) and not all(fragment_fields):
            raise ValueError(
                "fragment mutation plan requires id, atomic group, and payload"
            )
        if (self.mutation_kind == "fragment_publication") != all(fragment_fields):
            raise ValueError(
                "fragment publication must carry its complete portable plan"
            )
        if all(fragment_fields) != bool(self.root_publication_groups):
            raise ValueError("fragment publication plan requires root-group inventory")
        if any(
            not isinstance(group, FragmentRootPublicationGroupObserved)
            for group in self.root_publication_groups
        ) or len({group.group_id for group in self.root_publication_groups}) != len(
            self.root_publication_groups
        ):
            raise TypeError("fragment mutation plan contains invalid root groups")
        if any(
            group.publication_attempted
            or group.publication_succeeded
            or group.rollback_attempted
            for group in self.root_publication_groups
        ):
            raise ValueError(
                "fragment mutation plan requires pristine root-group inventory"
            )
        if all(fragment_fields):
            try:
                payload = json.loads(self.fragment_plan_json)
            except (TypeError, ValueError) as exc:
                raise ValueError("fragment publication plan JSON is invalid") from exc
            if not isinstance(payload, dict) or (
                payload.get("plan_id") != self.fragment_plan_id
                or payload.get("atomic_group_id") != self.fragment_atomic_group_id
            ):
                raise ValueError(
                    "fragment publication plan JSON identity does not match"
                )


@dataclass(frozen=True)
class SemanticFragmentRouteOracleComparedObserved:
    """One pre-root detached-route comparison batch for a fragment plan."""

    session_id: str
    func_ea: int
    mutation_batch_id: str
    run_id: str
    plan_id: str
    atomic_group_id: str
    mba_generation: int
    evidence_generation: int
    maturity: str
    reference_ledger_identities: tuple[tuple[str, str], ...]
    comparisons: tuple[RouteOracleComparison, ...]
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if not all(
            str(value)
            for value in (
                self.session_id,
                self.mutation_batch_id,
                self.run_id,
                self.plan_id,
                self.atomic_group_id,
                self.maturity,
            )
        ):
            raise ValueError("fragment route oracle requires complete identity")
        if int(self.mba_generation) < 0 or int(self.evidence_generation) < 0:
            raise ValueError("fragment route oracle generations must be non-negative")
        comparisons = tuple(self.comparisons)
        if not comparisons or any(
            not isinstance(comparison, RouteOracleComparison)
            for comparison in comparisons
        ):
            raise ValueError("fragment route oracle requires comparisons")
        ledger_identities = tuple(
            (str(route_id), str(ledger_identity))
            for route_id, ledger_identity in self.reference_ledger_identities
        )
        if tuple(route_id for route_id, _ledger in ledger_identities) != tuple(
            comparison.route_id for comparison in comparisons
        ) or any(not ledger_identity for _route, ledger_identity in ledger_identities):
            raise ValueError("fragment route oracle requires aligned ledger identities")
        object.__setattr__(self, "comparisons", comparisons)
        object.__setattr__(
            self,
            "reference_ledger_identities",
            ledger_identities,
        )


@dataclass(frozen=True)
class SemanticFragmentFailureObserved:
    """One ordered fragment-transaction failure persisted for diagnosis."""

    failure_kind: str
    phase: str
    error_type: str
    error_message: str
    interr_code: int | None = None
    verification_context: str = ""

    def __post_init__(self) -> None:
        if self.failure_kind not in {
            "stage",
            "publication",
            "rollback",
            "verifier",
        }:
            raise ValueError("semantic-fragment failure kind is invalid")
        if not self.phase or not self.error_type or not self.error_message:
            raise ValueError(
                "semantic-fragment failure requires phase, type, and message"
            )
        if self.interr_code is not None and int(self.interr_code) <= 0:
            raise ValueError("semantic-fragment INTERR code must be positive")
        if self.verification_context and self.failure_kind != "verifier":
            raise ValueError("only verifier failures may carry verification context")


@dataclass(frozen=True)
class MutationReceiptObserved:
    session_id: str
    func_ea: int
    mutation_batch_id: str
    mutation_kind: str
    pre_generation: int
    post_generation: int
    planned_operation_count: int
    applied_operation_count: int
    evidence_generation: int
    maturity: str
    outcome: str
    description: str
    reason: str
    affected_identity_json: tuple[str, ...] = ()
    affected_anchor_eas: tuple[int, ...] = ()
    fragment_plan_id: str = ""
    fragment_atomic_group_id: str = ""
    root_publication_groups: tuple[FragmentRootPublicationGroupObserved, ...] = ()
    fragment_staged: bool = False
    root_publication_attempted: bool = False
    root_publication_succeeded: bool = False
    rollback_attempted: bool = False
    rollback_succeeded: bool | None = None
    validation_outcomes: tuple[FragmentValidationOutcomeObserved, ...] = ()
    version_transitions: tuple[LogicalBlockVersionTransitionObserved, ...] = ()
    fragment_failures: tuple[SemanticFragmentFailureObserved, ...] = ()
    timestamp: float = 0.0

    def __post_init__(self) -> None:
        if (
            self.outcome == "committed"
            and int(self.post_generation) != int(self.pre_generation) + 1
        ):
            raise ValueError("a committed receipt must advance one MBA generation")
        if self.outcome == "aborted" and int(self.post_generation) != int(
            self.pre_generation
        ):
            raise ValueError("an aborted receipt cannot advance the MBA generation")
        if len(self.affected_identity_json) != len(self.affected_anchor_eas):
            raise ValueError("receipt identities and EA anchors must align")
        if any(
            not isinstance(outcome, FragmentValidationOutcomeObserved)
            for outcome in self.validation_outcomes
        ):
            raise TypeError("fragment receipt contains an invalid validation outcome")
        if any(
            not isinstance(transition, LogicalBlockVersionTransitionObserved)
            for transition in self.version_transitions
        ):
            raise TypeError("mutation receipt contains an invalid version transition")
        if any(
            not isinstance(failure, SemanticFragmentFailureObserved)
            for failure in self.fragment_failures
        ):
            raise TypeError("fragment receipt contains an invalid failure fact")
        has_fragment = bool(self.fragment_plan_id)
        if has_fragment != bool(self.fragment_atomic_group_id):
            raise ValueError("fragment receipt requires plan and atomic-group ids")
        if (self.mutation_kind == "fragment_publication") != has_fragment:
            raise ValueError("fragment publication receipt requires fragment identity")
        if has_fragment != bool(self.root_publication_groups):
            raise ValueError(
                "fragment publication receipt requires root-group outcomes"
            )
        if any(
            not isinstance(group, FragmentRootPublicationGroupObserved)
            for group in self.root_publication_groups
        ) or len({group.group_id for group in self.root_publication_groups}) != len(
            self.root_publication_groups
        ):
            raise TypeError("fragment receipt contains invalid root groups")
        if self.root_publication_succeeded and not self.root_publication_attempted:
            raise ValueError("root publication cannot succeed before it is attempted")
        if self.rollback_attempted != (self.rollback_succeeded is not None):
            raise ValueError(
                "rollback success is present exactly when rollback was attempted"
            )
        if self.outcome == "committed" and has_fragment:
            if (
                not self.fragment_staged
                or not self.root_publication_succeeded
                or self.rollback_attempted
                or self.fragment_failures
                or any(
                    not group.publication_attempted
                    or not group.publication_succeeded
                    or group.rollback_attempted
                    for group in self.root_publication_groups
                )
            ):
                raise ValueError(
                    "committed fragment requires staged and published authority"
                )
            phases = {outcome.phase for outcome in self.validation_outcomes}
            if phases != {"prepublication", "postpublication"} or not all(
                outcome.passed for outcome in self.validation_outcomes
            ):
                raise ValueError(
                    "committed fragment requires passed pre/post validation"
                )
        if not has_fragment and (
            self.fragment_staged
            or self.root_publication_attempted
            or self.root_publication_succeeded
            or self.rollback_attempted
            or self.rollback_succeeded is not None
            or self.validation_outcomes
            or self.root_publication_groups
            or self.fragment_failures
        ):
            raise ValueError(
                "non-fragment receipt cannot carry fragment transaction state"
            )


# ---------------------------------------------------------------------------
# Preanalysis domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DagObserved:
    "Preanalysis observed a DAG (state-graph) snapshot."

    snapshot: SnapshotRef
    nodes: tuple[DagNode, ...]
    edges: tuple[DagEdge, ...]


@dataclass(frozen=True)
class DagFrontierClosureDiagnosticsObserved:
    "Preanalysis observed DAG-frontier closure verifier diagnostics."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class ConditionChainIntervalDispatcherObserved:
    "Preanalysis observed recovered condition-chain interval-dispatcher rows.\n\n    The producer may not have a fresh SnapshotRef at the emission site, so the\n    diag sink attaches these rows to the latest snapshot for ``func_ea``.\n"

    func_ea: int
    maturity: str
    dispatcher_entry_block: int | None
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class StateDispatcherRowsObserved:
    "Preanalysis observed exact state-dispatcher rows."

    func_ea: int
    maturity: str
    dispatcher_entry_block: int | None
    dispatcher_kind: str
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class OptblockCallbackExceptionObserved:
    """One exception that escaped an optblock callback toward the SWIG boundary.

    The callback adapter records the function and block context before it
    re-raises, allowing the diagnostic subscriber to persist the traceback
    without giving runtime code any SQLite dependency.
    """

    func_ea: int
    maturity: str
    block_serial: int | None
    block_ea: int | None
    error_type: str
    error_message: str
    traceback_text: str
    occurrence_id: str = field(default_factory=lambda: uuid4().hex)

    def __post_init__(self) -> None:
        if int(self.func_ea) < 0:
            raise ValueError("func_ea must be non-negative")
        if (self.block_serial is None) != (self.block_ea is None):
            raise ValueError("block_serial and block_ea must be provided together")
        if self.block_serial is not None and int(self.block_serial) < 0:
            raise ValueError("block_serial must be non-negative")
        if self.block_ea is not None and int(self.block_ea) < 0:
            raise ValueError("block_ea must be non-negative")
        for field_name in (
            "maturity",
            "error_type",
            "error_message",
            "traceback_text",
            "occurrence_id",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be non-empty")


@dataclass(frozen=True)
class UnflattenDispatcherCorridorCoverageObserved:
    """Preanalysis observed covered and residual dispatcher-entry corridors.

    Lowering has no fresh :class:`SnapshotRef` at this point.  The diagnostic
    sink therefore binds the typed observations to the latest capture for the
    function, buffering planned observations until that capture exists when
    necessary.  A terminal ``applied`` or ``rejected_preflight`` batch without
    a capture receives an explicit diagnostic-only anchor snapshot, so the
    planned-to-final transaction history cannot disappear.
    """

    func_ea: int
    observations: tuple[Any, ...]


@dataclass(frozen=True)
class StateTransitionDispatchResolutionsObserved:
    "Preanalysis observed transition resolutions through exact dispatcher rows."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class SwitchCaseTransitionFactsObserved:
    "Preanalysis observed switch-table case transition facts."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class BranchOwnershipProofsObserved:
    "Preanalysis observed conditional branch ownership proof rows."

    snapshot: SnapshotRef
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class BranchWitnessDecisionsObserved:
    "Preanalysis observed branch-witness projection decisions."

    func_ea: int
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class ExitPathShortcutDecisionsObserved:
    "Preanalysis observed exit-path shortcut/liveness decisions."

    func_ea: int
    rows: tuple[Any, ...]


@dataclass(frozen=True)
class DagLocalFactsObserved:
    "Preanalysis observed node-local DAG facts for a LinearizedStateDag.\n\n    ``dag`` is duck-typed: it must expose the attributes consumed by\n    :func:`d810.core.diag.snapshot.snapshot_dag_local_facts`.\n"

    snapshot: SnapshotRef
    dag: Any


@dataclass(frozen=True)
class FactObservationsObserved:
    "Preanalysis observed a batch of fact observations for a function/snapshot."

    snapshot: SnapshotRef
    func_ea: int
    observations: tuple[Any, ...]


@dataclass(frozen=True)
class FactMappingsObserved:
    "Preanalysis observed a batch of fact mappings."

    snapshot: SnapshotRef
    func_ea: int
    mappings: tuple[Any, ...]


@dataclass(frozen=True)
class FactConsumersObserved:
    "Preanalysis observed a batch of fact-consumer records."

    snapshot: SnapshotRef
    func_ea: int
    consumers: tuple[Any, ...]


@dataclass(frozen=True)
class FactConsumersForLatestSnapshot:
    "Preanalysis observed fact-consumer records to attach to the latest snapshot.\n\n    Late-binding variant for post-hoc fact-consumer logging where the\n    rows do not correspond to a specific just-emitted capture but to\n    after-the-fact audit of strategy decisions. The subscriber finds\n    the latest ``snapshots`` row for ``func_ea`` and writes the rows\n    there, deduplicating against existing ``fact_consumers`` rows.\n"

    func_ea: int
    consumers: tuple[Any, ...]


@dataclass(frozen=True)
class FactConflictsObserved:
    "Preanalysis observed a batch of fact conflicts."

    snapshot: SnapshotRef
    func_ea: int
    conflicts: tuple[Any, ...]


@dataclass(frozen=True)
class ModificationsObserved:
    "Preanalysis observed a batch of reconstruction modifications."

    snapshot: SnapshotRef
    modifications: tuple[Modification, ...]


@dataclass(frozen=True)
class RenderedProgramObserved:
    "Preanalysis observed a rendered linearized program.\n\n    ``program`` is duck-typed: subscribers introspect the attributes\n    consumed by :func:`d810.core.diag.snapshot.snapshot_rendered_program`.\n"

    snapshot: SnapshotRef
    program: Any


@dataclass(frozen=True)
class ReachabilityObserved:
    "Preanalysis observed block reachability/classification for a snapshot."

    snapshot: SnapshotRef
    all_serials: frozenset[int]
    reachable: frozenset[int] = field(default_factory=frozenset)
    condition_chain_serials: frozenset[int] = field(default_factory=frozenset)
    gutted: frozenset[int] = field(default_factory=frozenset)
    claimed_sources: frozenset[int] = field(default_factory=frozenset)


# ---------------------------------------------------------------------------
# CFG domain
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CfgProvenanceObserved:
    """CFG mutation observed a single attribution-tagged event.

    Mirrors the legacy ``log_cfg_provenance`` signature: callers emit
    one of these per CREATE / DELETE / SOFT_KILL / SEVER_EDGE /
    REDIRECT_EDGE / RENUMBER / MERGE / NOP_INSNS / BULK_DEEP_CLEAN
    action site. The diag subscriber persists rows into the
    ``cfg_provenance`` table under the next captured snapshot.
    """

    pass_name: str
    action: str
    block_serial: int
    target_serial: int | None = None
    reason: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
    block_label: str | None = None
    block_ea: int | None = None
    target_label: str | None = None
    target_ea: int | None = None
    maturity_label: str | None = None


@dataclass(frozen=True)
class CfgProvenanceForLatestSnapshot:
    'CFG provenance that should attach to the latest function snapshot.\n\n    Most CFG mutation provenance is naturally tied to the next MBA\n    capture, so :class:`CfgProvenanceObserved` buffers until that\n    capture occurs. Preanalysis and planning diagnostics can be late-bound:\n    they may explain why a rewrite was *not* selected, so there may be\n    no subsequent snapshot to flush against. This event lets those\n    diagnostics use the same ``cfg_provenance`` table while explicitly\n    requesting "latest snapshot for this function" attribution.\n'

    func_ea: int
    events: tuple[CfgProvenanceObserved, ...]


@dataclass(frozen=True)
class WatchBlockTransitionObserved:
    """DeferredGraphModifier.apply observed a watch-block shape transition."""

    func_ea: int
    apply_session_id: str
    mod_index: int | None
    mod_type: str
    phase: str
    block_serial: int
    prev_type_name: str | None
    prev_succs: tuple[int, ...] | None
    prev_preds: tuple[int, ...] | None
    now_type_name: str | None
    now_succs: tuple[int, ...] | None
    now_preds: tuple[int, ...] | None


@dataclass(frozen=True)
class BlockLineageDrainRequested:
    """The diag sink is about to flush block-lineage rows.

    Emitted by :func:`d810.core.diag.snapshot.snapshot_mba` immediately
    after the snapshots row is created. ``conn`` and ``snapshot_id``
    are the live SQLite handle and row id; subscribers (currently
    :mod:`d810.transforms.block_lineage`) drain their pending buffer and
    write rows directly. ``snapshot`` is the optional SnapshotRef
    (``None`` when called from a direct ``snapshot_mba`` invocation
    outside the event API).
    """

    conn: Any
    snapshot_id: int
    snapshot: SnapshotRef | None = None


__all__ = [
    # Hex-Rays
    "CaptureMbaSnapshotRequested",
    "DiagnosticSessionObserved",
    "InputIdentityResolutionObserved",
    "FrontendNormalizationPlanIntentObserved",
    "PassContractEvidencePublished",
    "FragmentRootPublicationGroupObserved",
    "SemanticOutputVerifiedObserved",
    "SemanticFragmentFailureObserved",
    # Preanalysis
    "BranchOwnershipProofsObserved",
    "BranchWitnessDecisionsObserved",
    "ConditionChainIntervalDispatcherObserved",
    "ExitPathShortcutDecisionsObserved",
    "DagFrontierClosureDiagnosticsObserved",
    "DagLocalFactsObserved",
    "DagObserved",
    "FactConflictsObserved",
    "FactConsumersForLatestSnapshot",
    "FactConsumersObserved",
    "FactMappingsObserved",
    "FactObservationsObserved",
    "ModificationsObserved",
    "ReachabilityObserved",
    "RenderedProgramObserved",
    "OptblockCallbackExceptionObserved",
    "StateDispatcherRowsObserved",
    "UnflattenDispatcherCorridorCoverageObserved",
    "StateTransitionDispatchResolutionsObserved",
    "SwitchCaseTransitionFactsObserved",
    # CFG
    "BlockLineageDrainRequested",
    "CfgProvenanceForLatestSnapshot",
    "CfgProvenanceObserved",
    "WatchBlockTransitionObserved",
]
