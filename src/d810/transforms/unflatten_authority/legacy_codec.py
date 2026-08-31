"""Strict, non-authoritative transport for legacy unflatten metadata.

The compatibility path deliberately stops at a typed rejection until the
family-specific adapters are implemented.  It is nevertheless executable:
legacy values are captured losslessly, integrity checked, and replayed through
the same closed canonical wire format used by authority records.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
import hashlib

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
)
from d810.core.typing import Literal, TypeAlias
from d810.ir.flowgraph import FlowGraph
from d810.ir.block_identity import StableBlockIdentity
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.plan import normalized_metadata_items
from d810.ir.storage_identity import storage_identity_from_record
from d810.analyses.control_flow.effect_branch_exclusion import ExactStateBranchEffectExclusion

from .legacy_keys import (
    CONCRETE_STATE_ROUTE_PROVENANCE_METADATA,
    DISPATCHER_CORRIDOR_COVERAGE_METADATA,
    DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA,
    EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
    FULL_UNFLATTENING_CLAIM_METADATA,
    LEGACY_FAMILY_DETAIL_CODES,
    LEGACY_UNFLATTEN_KEYS,
    NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA,
    UNFLATTEN_COMPLETION_STATUS_METADATA,
    USE_DEF_SEVERANCE_AUDIT_METADATA,
)
from .legacy_wire import decode_legacy_value, encode_legacy_value
from .model import (
    BlockSubjectLocator,
    CorridorCoverageForecast,
    CorridorCoveragePath,
    CorridorCoveragePathNode,
    CorridorSemanticExclusion,
    CorridorPathDisposition,
    CorridorSubjectLocator,
    EquivalentSemanticRouteClaim,
    EffectSubjectLocator,
    LegacyUnflattenShadowEnvelope,
    ProposedUnflattenContract,
    RetirementCandidateCatalog,
    RetirementPlanMember,
    DispatcherRetirementCandidate,
    RetiredDispatcherInfrastructureClaim,
    TerminalCycleBreakClaim,
    TerminalKind,
    TerminalSubjectLocator,
    SemanticSubjectRef,
    SemanticSubjectKind,
    SemanticSubjectRole,
    UnflattenClaimKind,
    UnflattenAuthorityReason,
    UnflattenPlanShape,
    UnflattenPlanRoute,
    UnflattenPlanInputCatalog,
    UseDefFragmentWitness,
)
from .ids import _claim_factory, _subject_factory, authority_id, canonical_bytes, content_id
# Keep one owner for this set.  In particular, the exact-effect spelling is
# imported through proposal.py from its producer rather than copied here.
LEGACY_RESERVED_KEYS = LEGACY_UNFLATTEN_KEYS


def _legacy_route_operation_key(
    value: object,
) -> tuple[str, int, int | None, int | None] | None:
    if type(value) is not tuple or len(value) != 4:
        return None
    mutation_kind, source_serial, old_target_serial, target_serial = value
    if type(mutation_kind) is not str or not mutation_kind.strip():
        return None
    if any(separator in mutation_kind for separator in ("\x00", "\n", "\r")):
        return None

    def serial(candidate: object) -> int | None:
        if candidate is None:
            return None
        if type(candidate) is not int or candidate < 0:
            return None
        return candidate

    source = serial(source_serial)
    if source is None:
        return None
    old_target = serial(old_target_serial)
    if old_target_serial is not None and old_target is None:
        return None
    target = serial(target_serial)
    if target_serial is not None and target is None:
        return None
    return (mutation_kind.strip(), source, old_target, target)


@dataclass(frozen=True, slots=True)
class NativeBoundTransitionRouteReceipt:
    """Typed projection of one legacy native-bound route receipt."""

    fact_id: str
    native_ea: int
    current_block: str
    state: int
    target: int
    target_block: str
    operation_key: tuple[str, int, int | None, int | None]

    def __post_init__(self) -> None:
        if type(self.fact_id) is not str or not self.fact_id:
            raise ValueError("native-bound route fact id is malformed")
        if type(self.native_ea) is not int or not 0 <= self.native_ea < 0xFFFFFFFFFFFFFFFF:
            raise ValueError("native-bound route native EA is malformed")
        if type(self.current_block) is not str or not self.current_block:
            raise ValueError("native-bound route source block is malformed")
        if type(self.state) is not int or not 0 <= self.state <= 0xFFFFFFFF:
            raise ValueError("native-bound route state is malformed")
        if type(self.target) is not int or self.target < 0:
            raise ValueError("native-bound route target is malformed")
        if type(self.target_block) is not str or not self.target_block:
            raise ValueError("native-bound route target block is malformed")
        operation_key = _legacy_route_operation_key(self.operation_key)
        if operation_key is None:
            raise ValueError("native-bound route operation key is malformed")
        object.__setattr__(self, "operation_key", operation_key)


def _legacy_block_label(value: str, label: str) -> tuple[int, int]:
    """Decode the exact ``blk<serial>@0x<EA>`` diagnostic coordinate."""

    if not value.startswith("blk") or "@0x" not in value:
        raise ValueError(f"legacy {label} label is malformed")
    serial_text, ea_text = value[3:].split("@0x", 1)
    try:
        serial = int(serial_text, 10)
        anchor_ea = int(ea_text, 16)
    except ValueError as exc:
        raise ValueError(f"legacy {label} label is malformed") from exc
    if serial < 0 or anchor_ea < 0 or value != f"blk{serial}@0x{anchor_ea:X}":
        raise ValueError(f"legacy {label} label is not canonical")
    return serial, anchor_ea


def _route_diagnostic_values(proof: object, key: str) -> tuple[str, ...]:
    return tuple(
        value
        for name, value in getattr(proof, "diagnostic_provenance", ())
        if name == key
    )


def select_route_proof_ids_from_legacy_metadata(
    payload: object,
    *,
    route_evidence: CanonicalSemanticEvidence,
    key: str,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef],
) -> tuple[str, ...]:
    """Validate one legacy route family against canonical route evidence.

    The legacy rows are selectors only.  They never become authority and are
    discarded after exact state/target/source matching against the already
    sealed canonical route proofs.
    """

    if type(payload) not in (tuple, list) or not payload:
        raise ValueError("legacy route metadata must be a non-empty sequence")
    if key not in {
        "concrete_state_route_provenance",
        "native_bound_transition_route_receipts",
    }:
        raise ValueError("unknown legacy route family")
    refs_by_serial = dict(block_refs_by_serial)
    matched_ids: list[str] = []
    for row in payload:
        if type(row) is not dict:
            raise ValueError("legacy route row must be an exact mapping")
        if key == "concrete_state_route_provenance":
            required = {"site", "normalized_state", "target_handler", "source_kinds"}
            if set(row) != required or row["site"] != "entry":
                raise ValueError("legacy concrete route row is malformed")
            state = row["normalized_state"]
            target_serial = row["target_handler"]
            sources = row["source_kinds"]
            if type(state) is not int or type(target_serial) is not int:
                raise ValueError("legacy concrete route scalar is malformed")
            if type(sources) is not tuple or any(type(item) is not str for item in sources):
                raise ValueError("legacy concrete route provenance is malformed")
            if not sources or sources != tuple(sorted(set(sources))):
                raise ValueError("legacy concrete route provenance is not canonical")
            source_ea = None
            source_label = None
            target_label = None
            fact_id = None
        else:
            required = {
                "fact_id", "native_ea", "native_ea_hex", "current_block", "state",
                "target", "target_block",
            }
            if set(row) != required:
                raise ValueError("legacy native-bound route row is malformed")
            state = row["state"]
            target_serial = row["target"]
            source_ea = row["native_ea"]
            if (
                type(row["fact_id"]) is not str
                or type(source_ea) is not int
                or type(row["native_ea_hex"]) is not str
                or type(row["current_block"]) is not str
                or type(state) is not int
                or type(target_serial) is not int
                or type(row["target_block"]) is not str
            ):
                raise ValueError("legacy native-bound route scalar is malformed")
            if row["native_ea_hex"] != f"0x{source_ea:X}":
                raise ValueError("legacy native-bound route EA is inconsistent")
            if not 0 <= state <= 0xFFFFFFFF:
                raise ValueError("legacy native-bound route state is not exact 32-bit")
            source_label = _legacy_block_label(row["current_block"], "source block")
            target_label = _legacy_block_label(row["target_block"], "target block")
            fact_id = row["fact_id"].strip()
            if not fact_id or fact_id != row["fact_id"]:
                raise ValueError("legacy native-bound route fact id is malformed")
            if target_label[0] != target_serial:
                raise ValueError("legacy native-bound route target label is inconsistent")
        target_ref = refs_by_serial.get(target_serial)
        if type(target_ref) is not NativeBlockRef:
            raise ValueError("legacy route target is foreign")
        if target_label is not None and not target_ref.identity.native_ranges.contains(
            target_label[1]
        ):
            raise ValueError("legacy route target label is foreign")
        candidates = []
        for proof in route_evidence.route_proofs:
            if source_ea is not None:
                write = proof.state_write
                if write is None or write.instruction_ea != source_ea:
                    continue
                source_ref = refs_by_serial.get(source_label[0])
                if (
                    type(source_ref) is not NativeBlockRef
                    or write.identity != source_ref.identity
                    or not source_ref.identity.native_ranges.contains(source_label[1])
                    or _route_diagnostic_values(proof, "fact_id") != (fact_id,)
                ):
                    continue
            elif _route_diagnostic_values(proof, "source_kinds") != (
                "|".join(sources),
            ):
                continue
            for destination in proof.destinations:
                if (
                    destination.state_constant == state
                    and destination.target_identity == target_ref.identity
                    and (
                        target_label is None
                        or destination.target_anchor_ea == target_label[1]
                    )
                ):
                    candidates.append(proof)
        if len({proof.proof_id for proof in candidates}) != 1:
            raise ValueError("legacy route row has zero or multiple canonical matches")
        matched_ids.append(candidates[0].proof_id)
    if len(matched_ids) != len(set(matched_ids)):
        raise ValueError("legacy route rows select the same canonical proof more than once")
    return tuple(matched_ids)


def equivalent_route_claims_from_legacy_metadata(
    payload: object,
    *,
    proposal: ProposedUnflattenContract,
    key: str,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef],
) -> tuple[object, ...]:
    """Resolve nominal legacy selectors to exact already-minted route claims."""

    matched_ids = select_route_proof_ids_from_legacy_metadata(
        payload,
        route_evidence=proposal.route_evidence,
        key=key,
        block_refs_by_serial=block_refs_by_serial,
    )
    matched_id_set = set(matched_ids)
    claims = tuple(
        claim
        for claim in proposal.claims
        if type(claim) is EquivalentSemanticRouteClaim
        and len(claim.route_proof_ids) == 1
        and claim.route_proof_ids[0] in matched_id_set
    )
    if len(claims) != len(matched_id_set):
        raise ValueError("legacy route rows did not resolve to canonical claims")
    return claims


def exact_state_branch_effect_exclusion_from_metadata(
    payload: object,
) -> ExactStateBranchEffectExclusion | None:
    """Parse the exact legacy record without coercing any raw values."""

    if type(payload) is not dict:
        return None
    legacy_keys = {
        "normalized_state", "source", "predicate", "selected_target",
        "discarded_effect", "state_identity",
    }
    current_keys = {*legacy_keys, "site_specific"}
    payload_keys = set(payload)
    if payload_keys == legacy_keys:
        site_specific = False
    elif payload_keys == current_keys and type(payload["site_specific"]) is bool:
        site_specific = payload["site_specific"]
    else:
        return None

    def exact_int(value: object) -> int:
        if type(value) is not int:
            raise TypeError("exact-effect fields require built-in int values")
        return value

    def anchor(name: str, *fields: str) -> tuple[int, ...] | None:
        value = payload.get(name)
        if type(value) is not dict or set(value) != set(fields):
            return None
        try:
            return tuple(exact_int(value[field]) for field in fields)
        except (KeyError, TypeError, ValueError):
            return None

    source = anchor("source", "serial", "ea", "write_ea")
    predicate = anchor("predicate", "serial", "ea", "branch_ea")
    selected = anchor("selected_target", "serial", "ea")
    discarded = anchor("discarded_effect", "serial", "ea")
    identity_payload = payload.get("state_identity")
    if any(item is None for item in (source, predicate, selected, discarded)) or type(identity_payload) is not dict:
        return None
    try:
        if set(identity_payload) != {"kind", "prefix", "offset", "key"}:
            return None
        if (
            type(identity_payload["kind"]) is not str
            or type(identity_payload["prefix"]) is not str
            or type(identity_payload["offset"]) is not int
            or type(identity_payload["key"]) is not str
        ):
            return None
        state = exact_int(payload["normalized_state"])
        identity = storage_identity_from_record(identity_payload)
        if identity.to_record() != identity_payload:
            return None
    except (KeyError, TypeError, ValueError, OverflowError):
        return None
    if not 0 <= state <= 0xFFFFFFFF:
        return None
    try:
        return ExactStateBranchEffectExclusion(
            normalized_state=state,
            source_serial=source[0], source_ea=source[1], source_write_ea=source[2],
            predicate_serial=predicate[0], predicate_ea=predicate[1], predicate_branch_ea=predicate[2],
            selected_target_serial=selected[0], selected_target_ea=selected[1],
            discarded_effect_serial=discarded[0], discarded_effect_ea=discarded[1],
            state_identity=identity,
            site_specific=site_specific,
        )
    except (TypeError, ValueError, OverflowError):
        return None


def _exact_text(value: object, label: str) -> None:
    if type(value) is not str or not value.strip():
        raise TypeError(f"{label} must be a non-empty exact str")


def _exact_generation(value: object, label: str) -> None:
    if type(value) is not int or value < 0:
        raise TypeError(f"{label} must be a non-negative exact int")


def _metadata(metadata: object) -> tuple[tuple[object, object], ...]:
    """Use the stable legacy metadata parser, retaining order and duplicates."""

    try:
        items = normalized_metadata_items(metadata)
    except Exception as exc:
        raise ValueError("legacy metadata shape is invalid") from exc
    for key, _value in items:
        if type(key) is not str:
            raise TypeError("legacy metadata keys must be exact str")
    return items


def native_bound_transition_route_receipts_from_plan(
    plan: object,
) -> tuple[NativeBoundTransitionRouteReceipt, ...]:
    """Decode legacy route rows into a typed diagnostic projection.

    The caller must not inspect the reserved metadata payload.  Malformed or
    absent compatibility rows are ignored, matching the old diagnostic's
    fail-closed behavior; this projection never participates in authority.
    """

    metadata_dict = getattr(plan, "metadata_dict", None)
    if not callable(metadata_dict):
        return ()
    try:
        metadata = metadata_dict()
    except Exception:
        return ()
    if type(metadata) is not dict:
        return ()
    rows = metadata.get(NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA)
    if type(rows) is not tuple:
        return ()
    projected: list[NativeBoundTransitionRouteReceipt] = []
    for row in rows:
        if type(row) is not dict:
            continue
        required = {
            "fact_id",
            "native_ea",
            "native_ea_hex",
            "current_block",
            "state",
            "target",
            "target_block",
            "operation_key",
        }
        if set(row) != required:
            continue
        native_ea = row["native_ea"]
        if type(native_ea) is not int or row["native_ea_hex"] != f"0x{native_ea:X}":
            continue
        try:
            projected.append(
                NativeBoundTransitionRouteReceipt(
                    fact_id=row["fact_id"],
                    native_ea=native_ea,
                    current_block=row["current_block"],
                    state=row["state"],
                    target=row["target"],
                    target_block=row["target_block"],
                    operation_key=row["operation_key"],
                )
            )
        except (TypeError, ValueError):
            continue
    return tuple(projected)


def decode_legacy_canonical_payload(payload: bytes) -> object:
    """Decode one canonical payload and require a byte-identical re-encode."""

    value = decode_legacy_value(payload)
    if encode_legacy_value(value) != payload:
        raise ValueError("legacy payload is not byte-canonical")
    return value


# Descriptive aliases used by persistence adapters and tests.
legacy_canonical_bytes = encode_legacy_value
legacy_canonical_decode = decode_legacy_canonical_payload


def corridor_coverage_forecast_from_legacy_metadata(
    payload: object,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: dict[int, NativeBlockRef | LogicalBlockRef],
    source_function_ea: int,
) -> CorridorCoverageForecast:
    """Convert the legacy path report once at typed proposal attachment."""

    if type(payload) is not dict:
        raise ValueError("legacy corridor coverage must be an exact dict")
    if set(payload) - {
        "function_ea", "dispatcher", "completion_status", "planned_completion_status",
        "application_status", "full_unflattening_claim", "enumeration_complete",
        "covered_corridors", "residual_corridors", "semantic_exclusions",
    }:
        raise ValueError("legacy corridor coverage contains unknown fields")
    required = {"dispatcher", "enumeration_complete", "covered_corridors", "residual_corridors"}
    if not required <= set(payload):
        raise ValueError("legacy corridor coverage is incomplete")
    if type(payload["enumeration_complete"]) is not bool:
        raise TypeError("legacy corridor enumeration_complete must be an exact bool")
    if type(payload["covered_corridors"]) is not list or type(payload["residual_corridors"]) is not list:
        raise TypeError("legacy corridor partitions must be exact lists")
    if type(payload.get("function_ea")) is not int or payload["function_ea"] != source_function_ea:
        raise ValueError("legacy corridor function_ea differs from source")
    required_statuses = {
        "completion_status", "planned_completion_status", "application_status",
        "full_unflattening_claim",
    }
    if not required_statuses <= set(payload):
        raise ValueError("legacy corridor status presentation is incomplete")
    if payload["completion_status"] != "pending_patch_application":
        raise ValueError("legacy corridor completion status is not pending")
    if payload["application_status"] != "pending":
        raise ValueError("legacy corridor application status is not pending")
    if payload["full_unflattening_claim"] is not False:
        raise ValueError("legacy corridor must not claim full unflattening")
    for name in ("completion_status", "planned_completion_status", "application_status"):
        if type(payload[name]) is not str:
            raise TypeError(f"legacy corridor {name} must be an exact str")
    if type(payload["full_unflattening_claim"]) is not bool:
        raise TypeError("legacy corridor full_unflattening_claim must be an exact bool")
    if type(block_refs_by_serial) is not dict:
        raise TypeError("legacy corridor serial map must be an exact dict")
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    if set(block_refs_by_serial.values()) != set(catalog) or len(block_refs_by_serial) != len(catalog):
        raise ValueError("legacy corridor serial map must cover the exact source catalog")
    if any(type(serial) is not int or serial < 0 for serial in block_refs_by_serial):
        raise TypeError("legacy corridor serial map has a malformed serial")
    if any(type(ref) not in (NativeBlockRef, LogicalBlockRef) for ref in block_refs_by_serial.values()):
        raise TypeError("legacy corridor serial map has a malformed ref")
    if payload["dispatcher"] is None or type(payload["dispatcher"]) is not dict:
        raise ValueError("legacy corridor dispatcher anchor is required")

    def anchor(raw: object, label: str) -> tuple[int, int]:
        if type(raw) is not dict or set(raw) != {"serial", "ea", "label"}:
            raise ValueError(f"{label} anchor shape is not exact")
        serial, ea, text = raw["serial"], raw["ea"], raw["label"]
        if type(serial) is not int or serial < 0 or type(ea) is not int or ea < 0 or type(text) is not str:
            raise TypeError(f"{label} anchor scalar shape is not exact")
        if text != f"blk{serial}@0x{ea:x}":
            raise ValueError(f"{label} anchor label drifted")
        ref = block_refs_by_serial.get(serial)
        if ref is None or ref not in catalog or catalog[ref].anchor_ea != ea:
            raise ValueError(f"{label} anchor is foreign to source catalog")
        return serial, ea

    dispatcher_serial, dispatcher_ea = anchor(payload["dispatcher"], "dispatcher")
    dispatcher_ref = block_refs_by_serial[dispatcher_serial]
    if dispatcher_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("legacy corridor dispatcher differs from plan entry")
    raw_exclusions: list[CorridorSemanticExclusion] = []
    raw_exclusion_payloads = payload.get("semantic_exclusions", [])
    if type(raw_exclusion_payloads) is not list:
        raise TypeError("legacy semantic exclusions must be an exact list")
    for raw in raw_exclusion_payloads:
        if type(raw) is not dict or set(raw) != {"normalized_state", "source", "feeder", "prefix", "root", "state_identity"}:
            raise ValueError("legacy semantic exclusion shape is not exact")
        if type(raw["normalized_state"]) is not int or raw["normalized_state"] < 0:
            raise TypeError("legacy semantic exclusion state is malformed")
        source_serial, source_ea = anchor(raw["source"], "semantic exclusion source")
        feeder = None
        if raw["feeder"] is not None:
            feeder_serial, feeder_ea = anchor(raw["feeder"], "semantic exclusion feeder")
            feeder = CorridorCoveragePathNode(block_refs_by_serial[feeder_serial], feeder_ea)
        prefix_serial, prefix_ea = anchor(raw["prefix"], "semantic exclusion prefix")
        root_serial, root_ea = anchor(raw["root"], "semantic exclusion root")
        if type(raw["state_identity"]) is not dict:
            raise TypeError("legacy semantic exclusion identity is malformed")
        identity = storage_identity_from_record(raw["state_identity"])
        if identity.to_record() != raw["state_identity"]:
            raise ValueError("legacy semantic exclusion identity is not canonical")
        source_node = CorridorCoveragePathNode(block_refs_by_serial[source_serial], source_ea)
        prefix_node = CorridorCoveragePathNode(block_refs_by_serial[prefix_serial], prefix_ea)
        root_node = CorridorCoveragePathNode(block_refs_by_serial[root_serial], root_ea)
        typed = ("unflatten.corridor-semantic-exclusion.v1", raw["normalized_state"], identity, source_node, feeder, prefix_node, root_node)
        exclusion = CorridorSemanticExclusion(
            authority_id(typed), authority_id(("unflatten.corridor-semantic-exclusion-digest.v1", typed)),
            raw["normalized_state"], identity, source_node, feeder, prefix_node, root_node,
        )
        raw_exclusions.append(exclusion)

    def path_row(raw: object, disposition: CorridorPathDisposition) -> CorridorCoveragePath:
        if type(raw) is not dict or set(raw) != {"source", "state_merge", "dispatcher_feeder", "dispatcher", "path", "label"}:
            raise ValueError("legacy corridor path shape is not exact")
        if type(raw["path"]) is not list or len(raw["path"]) < 2:
            raise TypeError("legacy corridor path must be an exact list of at least two nodes")
        anchors = tuple(anchor(item, "corridor path") for item in raw["path"])
        if anchor(raw["source"], "corridor source") != anchors[0] or anchor(raw["dispatcher"], "corridor dispatcher") != anchors[-1]:
            raise ValueError("legacy corridor path endpoints drifted")
        if raw["state_merge"] is not None and anchor(raw["state_merge"], "corridor state merge") not in anchors:
            raise ValueError("legacy corridor state merge is outside path")
        if raw["state_merge"] is not None and anchor(raw["state_merge"], "corridor state merge") != anchors[-3]:
            raise ValueError("legacy corridor state merge must be the exact path[-3] node")
        if anchor(raw["dispatcher_feeder"], "corridor dispatcher feeder") != anchors[-2]:
            raise ValueError("legacy corridor dispatcher feeder is not penultimate")
        if raw["label"] != " -> ".join(f"blk{serial}@0x{ea:x}" for serial, ea in anchors):
            raise ValueError("legacy corridor path label drifted")
        nodes = tuple(CorridorCoveragePathNode(block_refs_by_serial[serial], ea) for serial, ea in anchors)
        suffixes = {
            exclusion.exclusion_id: tuple(
                node for node in (exclusion.source, exclusion.feeder, exclusion.prefix, exclusion.root)
                if node is not None
            )
            for exclusion in raw_exclusions
        }
        linked = tuple(
            exclusion for exclusion in raw_exclusions
            if len(suffixes[exclusion.exclusion_id]) <= len(nodes)
            and nodes[-len(suffixes[exclusion.exclusion_id]):] == suffixes[exclusion.exclusion_id]
        )
        exclusions = tuple(sorted(exclusion.exclusion_id for exclusion in linked))
        if linked and disposition is CorridorPathDisposition.RESIDUAL:
            raise ValueError("semantic exclusion cannot relabel a residual path")
        actual_disposition = CorridorPathDisposition.SEMANTICALLY_EXCLUDED if linked else disposition
        state_merge = None if raw["state_merge"] is None else CorridorCoveragePathNode(
            block_refs_by_serial[anchor(raw["state_merge"], "corridor state merge")[0]],
            anchor(raw["state_merge"], "corridor state merge")[1],
        )
        path_id = authority_id((
            "unflatten.corridor-coverage-path.v1", nodes, state_merge,
            actual_disposition, exclusions,
        ))
        return CorridorCoveragePath(
            path_id, nodes, state_merge, actual_disposition, exclusions,
        )

    covered_paths = tuple(
        path_row(raw, CorridorPathDisposition.STRUCTURALLY_COVERED)
        for raw in payload["covered_corridors"]
    )
    residual_paths = tuple(
        path_row(raw, CorridorPathDisposition.RESIDUAL)
        for raw in payload["residual_corridors"]
    )
    covered_domain = {(path.nodes, path.state_merge) for path in covered_paths}
    if len(covered_domain) != len(covered_paths):
        raise ValueError("legacy corridor paths must be unique")
    residual_domain = {(path.nodes, path.state_merge) for path in residual_paths}
    if len(residual_domain) != len(residual_paths):
        raise ValueError("legacy corridor paths must be unique")
    # The covered/residual partition is a partition of the raw corridor
    # domain.  Disposition is deliberately excluded from this key: it is a
    # classification of a path, not a second path identity.
    if covered_domain & residual_domain:
        raise ValueError(
            "legacy corridor paths must be unique; covered/residual raw path domains overlap"
        )
    paths = covered_paths + residual_paths
    if len({path.path_id for path in paths}) != len(paths):
        raise ValueError("legacy corridor paths must be unique")
    paths = tuple(sorted(paths, key=lambda path: path.path_id))
    covered = tuple(path.path_id for path in paths if path.disposition is not CorridorPathDisposition.RESIDUAL)
    residual = tuple(path.path_id for path in paths if path.disposition is CorridorPathDisposition.RESIDUAL)
    exclusion_paths = tuple(
        (exclusion.exclusion_id, tuple(
            path.path_id for path in paths if exclusion.exclusion_id in path.semantic_exclusion_ids
        ))
        for exclusion in sorted(raw_exclusions, key=lambda item: item.exclusion_id)
    )
    if any(not linked_paths for _exclusion_id, linked_paths in exclusion_paths):
        raise ValueError("legacy semantic exclusion does not map to any exact path suffix")
    digests = tuple(sorted((item.exclusion_id, item.digest) for item in raw_exclusions))
    exclusions = tuple(sorted(raw_exclusions, key=lambda item: item.exclusion_id))
    expected_planned = (
        "abstained_dispatcher_missing" if payload["dispatcher"] is None else
        "planned_partial_residual_dispatcher" if residual else
        "abstained_incomplete_corridor_enumeration" if not payload["enumeration_complete"] else
        "planned_dispatcher_corridors_covered"
    )
    if payload["planned_completion_status"] != expected_planned:
        raise ValueError("legacy corridor planned completion status is not derived")
    forecast_id = authority_id((
        "unflatten.corridor-coverage-forecast.v1", proposal.plan_id,
        payload["function_ea"], proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref, dispatcher_ea,
        paths, covered, residual, payload["enumeration_complete"], digests, exclusions, exclusion_paths,
    ))
    return CorridorCoverageForecast(
        forecast_id, proposal.plan_id, payload["function_ea"], proposal.source_identity_catalog.native_key,
        proposal.source_identity_catalog.generation, dispatcher_ref, dispatcher_ea,
        paths, covered, residual, payload["enumeration_complete"], digests, exclusions, exclusion_paths,
    )


def retirement_claim_from_legacy_proof(
    payload: object,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef],
) -> RetiredDispatcherInfrastructureClaim:
    """Convert one legacy retirement-proof family into a serial-free claim.

    The legacy payload is transport only.  Serials are used to resolve the
    captured anchors against the immutable source catalog and are discarded
    before the returned claim is minted.  The adapter accepts the historical
    preflight, interval-normalizer, state-transition, and comparison-corridor
    spellings; every malformed, duplicate, unknown, or foreign row rejects.
    """

    if type(payload) is not dict:
        raise ValueError("legacy retirement proof must be an exact mapping")
    if type(proposal) is not ProposedUnflattenContract:
        raise TypeError("legacy retirement conversion requires a closed proposal")
    if type(block_refs_by_serial) is not dict:
        raise TypeError("legacy retirement serial map must be an exact dict")
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}
    if len(block_refs_by_serial) != len(catalog):
        raise ValueError("legacy retirement serial map must cover the exact catalog")
    if len(set(block_refs_by_serial.values())) != len(block_refs_by_serial):
        raise ValueError("legacy retirement serial map contains duplicate refs")
    if set(block_refs_by_serial.values()) != set(catalog):
        raise ValueError("legacy retirement serial map must cover the exact catalog")
    if any(
        type(serial) is not int or serial < 0
        or type(ref) not in (NativeBlockRef, LogicalBlockRef)
        for serial, ref in block_refs_by_serial.items()
    ):
        raise ValueError("legacy retirement serial map contains a non-canonical row")
    by_serial = dict(block_refs_by_serial)
    if len(by_serial) != len(block_refs_by_serial):
        raise ValueError("legacy retirement serial map contains duplicate serials")
    by_anchor: dict[int, NativeBlockRef | LogicalBlockRef] = {}
    for item in proposal.source_identity_catalog.blocks:
        prior = by_anchor.get(item.anchor_ea)
        if prior is not None and prior != item.block_ref:
            raise ValueError("legacy retirement anchor-only lookup is ambiguous")
        by_anchor[item.anchor_ea] = item.block_ref

    family_fields = (
        "retired_infrastructure", "retired_state_plumbing", "retired_corridor",
    )
    if any(key not in (*family_fields, "proof_ids") for key in payload):
        raise ValueError("legacy retirement proof contains an unknown field")
    present = [field for field in family_fields if field in payload]
    if len(present) != 1:
        raise ValueError("legacy retirement proof family is missing or ambiguous")
    raw_rows = payload[present[0]]
    if type(raw_rows) is not tuple or not raw_rows:
        raise ValueError("legacy retirement proof members must be an exact tuple")
    rows: list[tuple[str, int, NativeBlockRef | LogicalBlockRef]] = []
    declared_retired: dict[NativeBlockRef | LogicalBlockRef, bool] = {}
    partitioned = False
    seen: set[NativeBlockRef | LogicalBlockRef] = set()
    family_roles = {
        "retired_infrastructure": {
            "comparison_dispatcher", "comparison_corridor", "dispatcher_feeder", "state_merge",
        },
        "retired_state_plumbing": {
            "dispatcher_state_feeder", "dispatcher_state_merge", "state_normalizer",
        },
        "retired_corridor": {"comparison_corridor"},
    }
    for raw in raw_rows:
        if type(raw) is not dict or set(raw) not in ({"role", "anchor"}, {"role", "anchor", "retired"}):
            raise ValueError("legacy retirement proof member is malformed")
        if "retired" in raw:
            partitioned = True
            if type(raw["retired"]) is not bool:
                raise ValueError("legacy retirement proof retired flag is malformed")
        role = raw["role"]
        anchor = raw["anchor"]
        if type(role) is not str or role not in family_roles[present[0]]:
            raise ValueError("legacy retirement proof role is malformed")
        if type(anchor) is not dict or set(anchor) != {"serial", "ea"}:
            raise ValueError("legacy retirement proof anchor is malformed")
        serial, ea = anchor["serial"], anchor["ea"]
        if type(serial) is not int or serial < 0 or type(ea) is not int or ea < 0:
            raise ValueError("legacy retirement proof anchor coordinates are malformed")
        ref = by_serial.get(serial)
        if ref is None or ref not in catalog:
            raise ValueError("legacy retirement proof member is foreign")
        if catalog[ref].anchor_ea != ea or by_anchor.get(ea) != ref:
            raise ValueError("legacy retirement proof member anchor drifted")
        if ref in seen:
            raise ValueError("legacy retirement proof contains duplicate members")
        seen.add(ref)
        declared_retired[ref] = raw.get("retired", True)
        rows.append((role, ea, ref))
    plan_refs = tuple(proposal.plan_inputs.dispatcher_member_refs)
    # Producer plan inputs are serial-canonical; retirement catalogs use the
    # closed authority-ref order required by their canonical model boundary.
    canonical_plan_refs = tuple(sorted(plan_refs, key=canonical_bytes))
    if any(ref not in plan_refs for _role, _ea, ref in rows):
        raise ValueError("legacy retirement proof member is outside the plan catalog")
    if not rows:
        raise ValueError("legacy retirement proof does not account for any plan member")
    row_refs = tuple(ref for _role, _ea, ref in rows)
    expected_order = tuple(ref for ref in canonical_plan_refs if ref in set(row_refs))
    if row_refs != expected_order:
        raise ValueError("legacy retirement proof member order is not canonical")
    if partitioned and set(row_refs) != set(plan_refs):
        raise ValueError("partitioned retirement proof must cover the full plan catalog")
    retired_refs = {
        ref for _role, _ea, ref in rows if declared_retired.get(ref, True)
    }
    if not retired_refs:
        raise ValueError("legacy retirement proof proposes no eligible candidate")
    entry_ref = proposal.plan_inputs.dispatcher_entry_ref
    entry = catalog.get(entry_ref)
    if entry is None:
        raise ValueError("dispatcher entry is absent from source catalog")
    member_subjects = tuple(
        _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            block_ref=ref,
            anchor_ea=ea,
            locator=BlockSubjectLocator(ref, ea),
        )
        for _role, ea, ref in rows if ref in retired_refs
    )
    corridor = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.CORRIDOR,
        role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=entry_ref,
        anchor_ea=entry.anchor_ea,
        locator=CorridorSubjectLocator(
            content_id("unflatten.corridor.v1", plan_refs),
            entry_ref,
            entry.anchor_ea,
            canonical_plan_refs,
            tuple(catalog[ref].anchor_ea for ref in canonical_plan_refs),
        ),
    )
    infrastructure = next(
        (subject for subject in member_subjects if subject.block_ref == entry_ref),
        _subject_factory(
            SemanticSubjectRef,
            kind=SemanticSubjectKind.BLOCK,
            role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
            block_ref=entry_ref,
            anchor_ea=entry.anchor_ea,
            locator=BlockSubjectLocator(entry_ref, entry.anchor_ea),
        ),
    )
    generation = proposal.source_identity_catalog.generation
    rows_by_ref = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    plan_members = tuple(
        RetirementPlanMember(
            ref,
            rows_by_ref[ref].anchor_ea,
            rows_by_ref[ref].native_instruction_eas,
        )
        for ref in canonical_plan_refs
    )
    candidates = []
    for role, ea, ref in rows:
        if ref not in retired_refs:
            continue
        evidence_ids = (authority_id((
            "unflatten.legacy-retirement-candidate-evidence.v1",
            present[0], ref, ea, role, generation,
        )),)
        candidates.append(DispatcherRetirementCandidate(
            ref,
            ea,
            role,
            evidence_ids,
            generation,
            authority_id((
                "unflatten.dispatcher-retirement-candidate.v1",
                ref, ea, role, evidence_ids, generation,
            )),
        ))
    candidates = tuple(sorted(candidates, key=canonical_bytes))
    candidate_catalog = RetirementCandidateCatalog(
        authority_id((
            "unflatten.dispatcher-retirement-candidate-catalog.v1",
            generation, plan_members, candidates,
        )),
        generation,
        plan_members,
        candidates,
    )
    compatibility_evidence_id = authority_id((
        "unflatten.legacy-retirement-candidates.v1",
        present[0], candidate_catalog.catalog_id,
    ))
    supplied_ids = payload.get("proof_ids")
    if supplied_ids is not None:
        if (
            type(supplied_ids) is not tuple
            or supplied_ids != (compatibility_evidence_id,)
        ):
            raise ValueError("legacy retirement proof IDs are not content-authoritative")
    return _claim_factory(
        RetiredDispatcherInfrastructureClaim,
        kind=UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
        infrastructure_subject=infrastructure,
        corridor_subject=corridor,
        member_subjects=member_subjects,
        candidate_evidence_ids=tuple(sorted({
            evidence_id
            for candidate in candidates
            for evidence_id in candidate.evidence_ids
        })),
        source_generation=generation,
        candidate_catalog=candidate_catalog,
    )


def terminal_cycle_claim_from_legacy_proof(
    payload: object,
    *,
    proposal: ProposedUnflattenContract,
    block_refs_by_serial: Mapping[int, NativeBlockRef | LogicalBlockRef],
) -> TerminalCycleBreakClaim:
    """Adapt the current transaction preflight terminal proof to a typed claim.

    Only the exact historical removal-validation payload schema is accepted.
    A legacy reason, serial allowance, or ad-hoc proof spelling is never
    sufficient to mint terminal authority.
    """
    if type(payload) is not dict or set(payload) != {
        "validation_status", "reason", "proof", "terminal_switch_cycle_break",
    }:
        raise ValueError("legacy terminal proof schema is unsupported")
    if payload["validation_status"] != "accepted" or payload["reason"] != "terminal_switch_cycle_break":
        raise ValueError("legacy terminal proof validation status is not accepted")
    proof_payload = payload["proof"]
    if type(proof_payload) is not dict or set(proof_payload) != {
        "function_ea", "dispatcher", "proof_status", "reason",
        "authoritative_handlers", "post_reachable_handlers",
        "pre_reachable_terminals", "post_reachable_terminals",
        "retired_infrastructure", "lost_blocks", "state_plumbing",
        "producer_safety", "coverage_enumeration_complete",
        "residual_corridor_count",
    }:
        raise ValueError("legacy terminal proof lacks the current removal proof")
    raw = payload["terminal_switch_cycle_break"]
    if type(raw) is not dict or set(raw) != {
        "dispatcher", "terminal_source", "shared_merge", "terminal_target",
        "terminal_stop", "retired_residue",
    }:
        raise ValueError("legacy terminal proof is not the current transaction schema")
    if type(proposal) is not ProposedUnflattenContract or type(block_refs_by_serial) is not dict:
        raise TypeError("terminal conversion requires closed proposal and serial map")
    catalog = {item.block_ref: item for item in proposal.source_identity_catalog.blocks}

    def anchor(value: object, label: str) -> tuple[NativeBlockRef | LogicalBlockRef, int]:
        if type(value) is not dict or set(value) != {"serial", "ea", "label"}:
            raise ValueError(f"legacy terminal {label} anchor is malformed")
        serial, ea = value["serial"], value["ea"]
        if (
            type(serial) is not int or serial < 0
            or type(ea) is not int or ea < 0
            or type(value["label"]) is not str
            or value["label"] != f"blk{serial}@0x{ea:x}"
        ):
            raise ValueError(f"legacy terminal {label} anchor is malformed")
        ref = block_refs_by_serial.get(serial)
        witness = catalog.get(ref)
        if ref is None or witness is None or witness.anchor_ea != ea:
            raise ValueError(f"legacy terminal {label} anchor is foreign")
        return ref, ea

    dispatcher_ref, dispatcher_ea = anchor(raw["dispatcher"], "dispatcher")
    if dispatcher_ref != proposal.plan_inputs.dispatcher_entry_ref:
        raise ValueError("legacy terminal dispatcher is not the plan dispatcher")
    terminal_source_ref, terminal_source_ea = anchor(
        raw["terminal_source"], "source",
    )
    merge_ref, merge_ea = anchor(raw["shared_merge"], "merge")
    target_ref, target_ea = anchor(raw["terminal_target"], "target")
    stop_ref, stop_ea = anchor(raw["terminal_stop"], "stop")
    residue = raw["retired_residue"]
    if type(residue) not in (tuple, list) or not residue:
        raise ValueError("legacy terminal residue must be non-empty")
    residue_rows = tuple(anchor(item, "residue") for item in residue)
    residue_refs = tuple(ref for ref, _ea in residue_rows)
    if len(set(residue_refs)) != len(residue_refs) or merge_ref not in residue_refs:
        raise ValueError("legacy terminal residue is not an exact closed set")
    plan_members = set(proposal.plan_inputs.dispatcher_member_refs)
    if not set(residue_refs) <= plan_members:
        raise ValueError("legacy terminal residue is outside the plan member set")
    lost_rows = proof_payload["lost_blocks"]
    if type(lost_rows) not in (tuple, list):
        raise ValueError("legacy terminal proof lost-block rows are malformed")
    lost = tuple(anchor(item, "lost") for item in lost_rows)
    if tuple(lost) != tuple(residue_rows):
        raise ValueError("legacy terminal residue disagrees with the removal proof")
    terminal_identity = (
        target_ref.identity
        if type(target_ref) is NativeBlockRef
        else StableBlockIdentity.from_instruction_eas(
            catalog[target_ref].native_instruction_eas,
            native_key=proposal.source_identity_catalog.native_key,
        )
    )
    terminal_source_identity = (
        terminal_source_ref.identity
        if type(terminal_source_ref) is NativeBlockRef
        else StableBlockIdentity.from_instruction_eas(
            catalog[terminal_source_ref].native_instruction_eas,
            native_key=proposal.source_identity_catalog.native_key,
        )
    )
    terminal_proofs = tuple(
        proof for proof in proposal.route_evidence.route_proofs
        if proof.source_identity == terminal_source_identity
        and proof.source_anchor_ea == terminal_source_ea
        and sum(
                destination.target_identity == terminal_identity
                and destination.target_anchor_ea == target_ea
            for destination in proof.destinations
        ) == 1
    )
    if len(terminal_proofs) != 1:
        raise ValueError("legacy terminal proof does not bind one canonical route")
    cycle = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.CORRIDOR,
        role=SemanticSubjectRole.DISPATCHER_CORRIDOR,
        block_ref=dispatcher_ref,
        anchor_ea=dispatcher_ea,
        locator=CorridorSubjectLocator(
            authority_id(("unflatten.terminal-cycle.v1", proposal.plan_id, residue_refs)),
            dispatcher_ref, dispatcher_ea, residue_refs,
            tuple(catalog[ref].anchor_ea for ref in residue_refs),
        ),
    )
    cleanup = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.BLOCK,
        role=SemanticSubjectRole.DISPATCHER_INFRASTRUCTURE,
        block_ref=merge_ref,
        anchor_ea=merge_ea,
        locator=BlockSubjectLocator(merge_ref, merge_ea),
    )
    terminal = _subject_factory(
        SemanticSubjectRef,
        kind=SemanticSubjectKind.TERMINAL,
        role=SemanticSubjectRole.TERMINAL_SITE,
        block_ref=stop_ref,
        anchor_ea=stop_ea,
        locator=TerminalSubjectLocator(
            stop_ref, stop_ea, TerminalKind.STOP, stop_ea,
        ),
    )
    return _claim_factory(
        TerminalCycleBreakClaim,
        kind=UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
        cycle_subject=cycle,
        cleanup_source_subject=cleanup,
        terminal_subject=terminal,
        terminal_route_proof_ids=(terminal_proofs[0].proof_id,),
        source_generation=proposal.source_identity_catalog.generation,
    )


@dataclass(frozen=True, slots=True)
class LegacyFamilyAdaptation:
    key: str
    family: str
    result_ids: tuple[str, ...]
    canonical_payload: bytes
    payload_sha256: str

    def __post_init__(self) -> None:
        if type(self.key) is not str or self.key not in LEGACY_RESERVED_KEYS:
            raise ValueError("adaptation key is not a reserved legacy key")
        if type(self.family) is not str or not self.family:
            raise TypeError("adaptation family must be a non-empty string")
        ids = tuple(self.result_ids)
        if any(type(value) is not str or not value for value in ids):
            raise TypeError("adaptation result IDs must be exact strings")
        if ids != tuple(sorted(set(ids))):
            raise ValueError("adaptation result IDs must be canonical and unique")
        if type(self.canonical_payload) is not bytes or not self.canonical_payload:
            raise TypeError("adaptation payload must be non-empty bytes")
        if type(self.payload_sha256) is not str or hashlib.sha256(self.canonical_payload).hexdigest() != self.payload_sha256:
            raise ValueError("adaptation payload digest does not match")
        object.__setattr__(self, "result_ids", ids)


@dataclass(frozen=True, slots=True)
class LegacyShadowCodecReceipt:
    """Codec-minted proof that every shadow entry was actually adapted."""

    shadow: LegacyUnflattenShadowEnvelope
    adaptations: tuple[LegacyFamilyAdaptation, ...]

    def __post_init__(self) -> None:
        if type(self.shadow) is not LegacyUnflattenShadowEnvelope:
            raise TypeError("shadow must be a LegacyUnflattenShadowEnvelope")
        expected = tuple(entry.key for entry in self.shadow.entries)
        adaptations = tuple(self.adaptations)
        if any(type(item) is not LegacyFamilyAdaptation for item in adaptations):
            raise TypeError("adaptations must contain LegacyFamilyAdaptation values")
        if tuple(item.key for item in adaptations) != expected:
            raise ValueError("adaptations must cover every shadow entry exactly once")
        expected_rows = tuple((entry.key, entry.canonical_payload, entry.payload_sha256) for entry in self.shadow.entries)
        actual_rows = tuple((item.key, item.canonical_payload, item.payload_sha256) for item in adaptations)
        if actual_rows != expected_rows:
            raise ValueError("adaptation payload identity changed")

    @property
    def consumed_keys(self) -> tuple[str, ...]:
        return tuple(item.key for item in self.adaptations)

    @property
    def payloads(self) -> tuple[tuple[str, bytes, str], ...]:
        return tuple((item.key, item.canonical_payload, item.payload_sha256) for item in self.adaptations)


@dataclass(frozen=True, slots=True)
class LegacyUnflattenDecodeContext:
    plan_id: str
    source: FlowGraph
    source_generation: int
    block_refs_by_serial: tuple[
        tuple[int, NativeBlockRef | LogicalBlockRef], ...
    ]
    canonical_route_evidence: CanonicalSemanticEvidence | None
    plan_inputs: UnflattenPlanInputCatalog | None = None
    use_def_witness: UseDefFragmentWitness | None = None
    canonical_proposal: ProposedUnflattenContract | None = None

    def __post_init__(self) -> None:
        _exact_text(self.plan_id, "plan_id")
        if type(self.source) is not FlowGraph:
            raise TypeError("source must be an exact FlowGraph")
        _exact_generation(self.source_generation, "source_generation")
        if type(self.block_refs_by_serial) is not tuple:
            raise TypeError("block_refs_by_serial must be an exact tuple")
        serials: list[int] = []
        refs: list[object] = []
        for pair in self.block_refs_by_serial:
            if type(pair) is not tuple or len(pair) != 2:
                raise TypeError("block_refs_by_serial requires (serial, ref) pairs")
            serial, ref = pair
            if type(serial) is not int or serial < 0:
                raise TypeError("block serials must be non-negative exact ints")
            if type(ref) not in (NativeBlockRef, LogicalBlockRef):
                raise TypeError("block refs must be exact NativeBlockRef/LogicalBlockRef")
            serials.append(serial)
            refs.append(ref)
        if len(set(serials)) != len(serials) or len(set(refs)) != len(refs):
            raise ValueError("block_refs_by_serial must be unique")
        if tuple(serials) != tuple(sorted(serials)):
            raise ValueError("block_refs_by_serial must be sorted by serial")
        try:
            source_serials = tuple(sorted(self.source.blocks))
        except TypeError as exc:
            raise TypeError("source block keys must be sortable exact ints") from exc
        if not source_serials:
            raise ValueError("source graph must not be empty")
        if tuple(serials) != source_serials:
            raise ValueError("block_refs_by_serial must exactly cover source blocks")
        for serial in source_serials:
            block = self.source.blocks[serial]
            if (
                type(serial) is not int
                or type(block.serial) is not int
                or block.serial != serial
            ):
                raise ValueError("source block serial does not match mapping key")
        route = self.canonical_route_evidence
        if route is not None:
            try:
                CanonicalSemanticEvidence.__post_init__(route)
            except Exception as exc:
                raise ValueError("canonical route evidence is invalid") from exc
            if route.generation != self.source_generation:
                raise ValueError("canonical route evidence generation is stale")
        native_refs = [ref for ref in refs if type(ref) is NativeBlockRef]
        if native_refs or route is not None:
            native_key = (
                route.native_key
                if route is not None
                else native_refs[0].identity.native_key
            )
            if any(ref.identity.native_key != native_key for ref in native_refs):
                raise ValueError("source block references have foreign native keys")
            try:
                from .producer_api import build_source_identity_catalog

                build_source_identity_catalog(
                    self.source,
                    dict(self.block_refs_by_serial),
                    native_key=native_key,
                    source_generation=self.source_generation,
                    canonical_route_evidence=route,
                )
            except Exception as exc:
                raise ValueError("source identity catalog is invalid") from exc
        else:
            for serial in source_serials:
                block = self.source.blocks[serial]
                origins = tuple(
                    instruction.native_ea
                    if instruction.native_ea is not None
                    else instruction.ea
                    for instruction in block.insn_snapshots
                )
                if not origins or any(type(origin) is not int for origin in origins):
                    raise ValueError("source block has invalid native origins")
                anchor = (
                    block.native_start_ea
                    if block.native_start_ea is not None
                    else block.start_ea
                )
                if anchor not in origins:
                    raise ValueError("source block anchor is outside native origins")
        if self.canonical_route_evidence is not None and type(
            self.canonical_route_evidence
        ) is not CanonicalSemanticEvidence:
            raise TypeError("canonical_route_evidence must be closed")
        if self.plan_inputs is not None:
            if type(self.plan_inputs) is not UnflattenPlanInputCatalog:
                raise TypeError("plan_inputs must be closed")
            from .ids import validate_canonical_roundtrip
            validate_canonical_roundtrip(self.plan_inputs, UnflattenPlanInputCatalog)
            plan_refs = {
                self.plan_inputs.source_entry_ref,
                self.plan_inputs.dispatcher_entry_ref,
                *self.plan_inputs.dispatcher_member_refs,
                *(handler.block_ref for handler in self.plan_inputs.authoritative_handlers),
            }
            if any(ref not in refs for ref in plan_refs):
                raise ValueError("exact legacy plan inputs contain a foreign ref")
            if self.use_def_witness is None or type(self.use_def_witness) is not UseDefFragmentWitness:
                raise TypeError("exact legacy adaptation requires an owned use-def witness")
            validate_canonical_roundtrip(self.use_def_witness, UseDefFragmentWitness)
            if any(ref not in refs for ref in self.use_def_witness.redirect_owner_refs):
                raise ValueError("exact legacy use-def witness contains a foreign ref")
            if self.canonical_route_evidence is None:
                raise ValueError("exact legacy adaptation requires canonical route evidence")
        elif self.use_def_witness is not None:
            raise ValueError("exact legacy producer inputs are incomplete")
        if self.canonical_proposal is not None:
            if type(self.canonical_proposal) is not ProposedUnflattenContract:
                raise TypeError("canonical_proposal must be closed")
            if self.canonical_proposal.plan_id != self.plan_id:
                raise ValueError("canonical proposal belongs to a foreign plan")
            if self.canonical_proposal.source_identity_catalog.generation != self.source_generation:
                raise ValueError("canonical proposal generation is stale")
            if self.canonical_proposal.route_evidence is not self.canonical_route_evidence:
                raise ValueError("canonical proposal route evidence differs from context")
            if self.plan_inputs is not None and self.canonical_proposal.plan_inputs != self.plan_inputs:
                raise ValueError("canonical proposal plan inputs differ from context")
            if self.use_def_witness is not None and self.canonical_proposal.use_def_witness != self.use_def_witness:
                raise ValueError("canonical proposal use-def witness differs from context")


@dataclass(frozen=True, slots=True)
class LegacyUnflattenAbsent:
    route: Literal[UnflattenPlanRoute.ORDINARY]

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.ORDINARY:
            raise ValueError("absent route must be ORDINARY")


@dataclass(frozen=True, slots=True)
class LegacyUnflattenDecoded:
    route: Literal[UnflattenPlanRoute.LEGACY_ADAPTED]
    proposal: ProposedUnflattenContract

    def __post_init__(self) -> None:
        if self.route is not UnflattenPlanRoute.LEGACY_ADAPTED:
            raise ValueError("decoded route must be LEGACY_ADAPTED")
        if type(self.proposal) is not ProposedUnflattenContract:
            raise TypeError("decoded proposal must be closed")


@dataclass(frozen=True, slots=True)
class LegacyUnflattenRejected:
    reason: UnflattenAuthorityReason
    key: str | None
    detail_code: str

    def __post_init__(self) -> None:
        if type(self.reason) is not UnflattenAuthorityReason:
            raise TypeError("rejection reason must be closed")
        if self.key is not None and type(self.key) is not str:
            raise TypeError("rejection key must be an exact str")
        if type(self.detail_code) is not str or not self.detail_code.strip():
            raise ValueError("rejection detail_code must not be blank")


LegacyUnflattenDecodeResult: TypeAlias = (
    LegacyUnflattenAbsent | LegacyUnflattenDecoded | LegacyUnflattenRejected
)


def _looks_authoritative(key: str) -> bool:
    lowered = key.lower()
    return any(
        token in lowered
        for token in (
            "unflatten",
            "dispatcher",
            "severance",
            "route_provenance",
            "transition_route",
            "authority",
        )
    )


def _walk_payload(value: object, *, path: str = "") -> tuple[str, str] | None:
    """Find stale generation and serial-without-EA records fail-closed."""

    if isinstance(value, Mapping):
        keys = tuple(value)
        if any(type(key) is not str for key in keys):
            return ("", "legacy_payload_mapping_key_invalid")
        if "source_generation" in value or "generation" in value:
            for name in ("source_generation", "generation"):
                if name in value:
                    generation = value[name]
                    if type(generation) is not int:
                        return (name, "legacy_source_generation_invalid")
        if ("serial" in value) != ("ea" in value):
            return ("serial", "legacy_serial_requires_ea")
        if "serial" in value and (
            (value["serial"] is None) != (value["ea"] is None)
        ):
            return ("serial", "legacy_serial_requires_ea")
        for key, item in value.items():
            found = _walk_payload(item, path=f"{path}.{key}")
            if found is not None:
                return found
    elif type(value) in (list, tuple, frozenset):
        for index, item in enumerate(value):
            found = _walk_payload(item, path=f"{path}[{index}]")
            if found is not None:
                return found
    return None


def _payload_generations(value: object) -> tuple[int, ...]:
    found: list[int] = []
    if isinstance(value, Mapping):
        for name in ("source_generation", "generation"):
            if name in value and type(value[name]) is int:
                found.append(value[name])
        for item in value.values():
            found.extend(_payload_generations(item))
    elif type(value) in (list, tuple, frozenset):
        for item in value:
            found.extend(_payload_generations(item))
    return tuple(found)


def _family_detail(key: str) -> str | None:
    return LEGACY_FAMILY_DETAIL_CODES.get(key)


def _use_def_failure(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    executed = value.get("executed")
    atomic = value.get("fragment_atomic")
    clean = value.get("clean")
    severance_count = value.get("severance_count")
    violations = value.get("violations")
    if executed is False or atomic is False:
        return "legacy_use_def_audit_unavailable"
    if type(severance_count) is int and severance_count > 0:
        return "legacy_use_def_audit_severed"
    if isinstance(violations, (list, tuple)) and violations:
        return "legacy_use_def_audit_severed"
    if clean is True and (
        executed is not True
        or atomic is not True
        or severance_count != 0
        or violations not in ((), [], None)
    ):
        return "legacy_use_def_audit_contradictory"
    return None


def _proposal_claim_kinds(proposal: ProposedUnflattenContract) -> frozenset[UnflattenClaimKind]:
    return frozenset(claim.kind for claim in proposal.claims)


def _adapt_known_family(
    key: str,
    value: object,
    *,
    context: LegacyUnflattenDecodeContext,
    coverage_payload: object | None = None,
) -> ProposedUnflattenContract | None:
    """Validate one migrated legacy family against the sealed proposal.

    The canonical proposal is supplied by the producer boundary.  This
    adapter consumes legacy facts only as selectors/checks; it never mints a
    second authority or changes the proposal decision.
    """

    proposal = context.canonical_proposal
    if proposal is None:
        return None
    kinds = _proposal_claim_kinds(proposal)
    if key == USE_DEF_SEVERANCE_AUDIT_METADATA:
        if not isinstance(value, Mapping) or set(value) - {"function_ea", "executed", "fragment_atomic", "severance_count", "violations", "clean"}:
            raise ValueError("legacy use-def audit must be an exact mapping")
        if not {"function_ea", "executed", "fragment_atomic", "severance_count", "violations"} <= set(value):
            raise ValueError("legacy use-def audit is incomplete")
        witness = context.use_def_witness
        if witness is None or _use_def_failure(value) is not None:
            raise ValueError("legacy use-def audit is not clean")
        if type(value["function_ea"]) is not int or value["function_ea"] != context.source.func_ea:
            raise ValueError("legacy use-def function differs from source")
        if value.get("executed") is not witness.executed or value.get("fragment_atomic") is not witness.fragment_atomic:
            raise ValueError("legacy use-def execution facts differ from witness")
        if value.get("severance_count") != witness.actionable_non_state_severance_count:
            raise ValueError("legacy use-def count differs from witness")
        violations = value.get("violations", ())
        if tuple(violations) != witness.violation_ids:
            raise ValueError("legacy use-def violations differ from witness")
        return proposal
    if key == DISPATCHER_CORRIDOR_COVERAGE_METADATA:
        forecast = corridor_coverage_forecast_from_legacy_metadata(
            value,
            proposal=proposal,
            block_refs_by_serial=dict(context.block_refs_by_serial),
            source_function_ea=context.source.func_ea,
        )
        if proposal.corridor_coverage_forecast != forecast:
            raise ValueError("legacy corridor forecast differs from canonical proposal")
        return proposal
    if key == FULL_UNFLATTENING_CLAIM_METADATA:
        if type(value) is not bool or coverage_payload is None or not isinstance(coverage_payload, Mapping):
            raise ValueError("legacy full-unflattening marker requires exact coverage")
        if value != coverage_payload.get("full_unflattening_claim"):
            raise ValueError("legacy full-unflattening marker differs from coverage")
        return proposal
    if key == DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA:
        candidates: list[object] = []
        for adapter in (retirement_claim_from_legacy_proof, terminal_cycle_claim_from_legacy_proof):
            try:
                candidates.append(adapter(
                    value,
                    proposal=proposal,
                    block_refs_by_serial=dict(context.block_refs_by_serial),
                ))
            except (TypeError, ValueError):
                continue
        matches = tuple(
            candidate for candidate in candidates
            if any(item == candidate for item in proposal.claims)
        )
        if len(matches) != 1:
            raise ValueError("legacy removal proof does not bind one canonical claim")
        return proposal
    if key == UNFLATTEN_COMPLETION_STATUS_METADATA:
        if type(value) is not str or coverage_payload is None or not isinstance(coverage_payload, Mapping):
            raise TypeError("legacy completion status requires exact coverage")
        if value != coverage_payload.get("completion_status"):
            raise ValueError("legacy completion status differs from coverage")
        return proposal
    if key in {CONCRETE_STATE_ROUTE_PROVENANCE_METADATA, NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA}:
        if UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE not in kinds:
            raise ValueError("legacy route family has no equivalent-route claim")
        return proposal
    if key == EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA:
        if UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT not in kinds:
            raise ValueError("legacy exact-effect family has no canonical claim")
        return proposal
    return None


def _exact_family_result_ids(
    key: str,
    value: object,
    *,
    context: LegacyUnflattenDecodeContext,
) -> tuple[str, ...]:
    """Adapt one exact family directly against the sealed proposal."""

    proposal = context.canonical_proposal
    if proposal is None:
        raise ValueError("exact family adaptation requires a canonical proposal")
    refs = dict(context.block_refs_by_serial)
    serial_by_ref = {ref: serial for serial, ref in refs.items()}
    if key in {
        CONCRETE_STATE_ROUTE_PROVENANCE_METADATA,
        NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA,
    }:
        claims = equivalent_route_claims_from_legacy_metadata(
            value, proposal=proposal, key=key, block_refs_by_serial=refs,
        )
        actual = tuple(sorted(claim.claim_id for claim in claims))
        if any(
            claim.kind is not UnflattenClaimKind.EQUIVALENT_SEMANTIC_ROUTE
            or not claim.route_proof_ids
            for claim in claims
        ):
            raise ValueError(f"legacy {key} claims differ from canonical proposal")
        return actual
    if key != EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA:
        raise ValueError(f"unknown exact legacy family {key}")
    if type(value) not in (tuple, list) or not value:
        raise ValueError("legacy exact-effect payload is malformed")
    exclusions = tuple(
        exact_state_branch_effect_exclusion_from_metadata(item) for item in value
    )
    if any(item is None for item in exclusions):
        raise ValueError("legacy exact-effect payload is malformed")
    matches: list[str] = []
    for exclusion in exclusions:
        if exclusion is None:
            raise ValueError("legacy exact-effect payload is malformed")
        claim_matches: list[str] = []
        for claim in proposal.claims:
            if claim.kind is not UnflattenClaimKind.EXACT_INFEASIBLE_EFFECT:
                continue
            source = claim.source_subject.locator
            predicate = claim.predicate_subject.locator
            selected = claim.selected_target_subject.locator
            effect = claim.discarded_effect_subject.locator
            if (
                type(source) is not BlockSubjectLocator
                or type(predicate) is not BlockSubjectLocator
                or type(selected) is not BlockSubjectLocator
                or type(effect) is not EffectSubjectLocator
            ):
                continue
            if (
                exclusion.normalized_state == claim.normalized_state
                and exclusion.source_serial == serial_by_ref.get(source.block_ref, -1)
                and exclusion.source_ea == source.anchor_ea
                and exclusion.source_write_ea == claim.source_write_ea
                and exclusion.predicate_serial == serial_by_ref.get(predicate.block_ref, -1)
                and exclusion.predicate_ea == predicate.anchor_ea
                and exclusion.predicate_branch_ea == claim.predicate_branch_ea
                and exclusion.selected_target_serial == serial_by_ref.get(selected.block_ref, -1)
                and exclusion.selected_target_ea == selected.anchor_ea
                and exclusion.discarded_effect_serial == serial_by_ref.get(effect.owner_ref, -1)
                and exclusion.discarded_effect_ea == claim.discarded_effect_ea
                and exclusion.state_identity == claim.state_identity
            ):
                claim_matches.append(claim.claim_id)
        if len(claim_matches) != 1:
            raise ValueError("legacy exact-effect row does not bind one canonical claim")
        matches.extend(claim_matches)
    if len(matches) != len(exclusions) or len(matches) != len(set(matches)):
        raise ValueError("legacy exact-effect payload does not bind canonical claims")
    return tuple(sorted(matches))


def _family_result_ids(
    key: str,
    value: object,
    *,
    proposal: ProposedUnflattenContract,
    context: LegacyUnflattenDecodeContext,
) -> tuple[str, ...]:
    if key == USE_DEF_SEVERANCE_AUDIT_METADATA:
        witness = context.use_def_witness
        if witness is None:
            raise ValueError("legacy use-def family has no canonical witness")
        return tuple(sorted((witness.fragment_id, witness.redirect_digest)))
    if key in {DISPATCHER_CORRIDOR_COVERAGE_METADATA, FULL_UNFLATTENING_CLAIM_METADATA, UNFLATTEN_COMPLETION_STATUS_METADATA}:
        if proposal.corridor_coverage_forecast is None:
            raise ValueError("legacy coverage family has no canonical forecast")
        return (proposal.corridor_coverage_forecast.forecast_id,)
    if key == DISPATCHER_REMOVAL_PREFLIGHT_PROOF_METADATA:
        return tuple(sorted(
            claim.claim_id
            for claim in proposal.claims
            if claim.kind in {
                UnflattenClaimKind.RETIRED_DISPATCHER_INFRASTRUCTURE,
                UnflattenClaimKind.TERMINAL_CYCLE_BREAK,
            }
        ))
    if key in {CONCRETE_STATE_ROUTE_PROVENANCE_METADATA, NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA}:
        return _exact_family_result_ids(key, value, context=context)
    if key == EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA:
        return _exact_family_result_ids(key, value, context=context)
    raise ValueError(f"unknown migrated legacy family {key}")


def adapt_legacy_unflatten_shadow(
    shadow: LegacyUnflattenShadowEnvelope,
    *,
    context: LegacyUnflattenDecodeContext,
) -> LegacyShadowCodecReceipt:
    """Adapt every captured legacy entry through its exact family decoder.

    The returned receipt is minted from the envelope itself.  No caller
    supplied consumed-key assertion participates in the proof.
    """

    if type(context) is not LegacyUnflattenDecodeContext:
        raise TypeError("context must be LegacyUnflattenDecodeContext")
    if context.canonical_proposal is None:
        raise ValueError("full shadow adaptation requires a canonical proposal")
    envelope = shadow
    if type(envelope) is not LegacyUnflattenShadowEnvelope:
        raise TypeError("persistence adaptation requires a legacy envelope")
    envelope.__post_init__()
    if envelope.plan_id != context.plan_id or envelope.source_generation != context.source_generation:
        raise ValueError("shadow envelope identity differs from decode context")
    if any(entry.key not in LEGACY_RESERVED_KEYS for entry in envelope.entries):
        raise ValueError("shadow contains an unsupported reserved legacy key")

    values: dict[str, object] = {}
    for entry in envelope.entries:
        payload = entry.canonical_payload
        if type(payload) is not bytes or hashlib.sha256(payload).hexdigest() != entry.payload_sha256:
            raise ValueError(f"legacy shadow payload integrity mismatch for {entry.key}")
        value = decode_legacy_canonical_payload(payload)
        values[entry.key] = value
    proposal = context.canonical_proposal
    coverage = values.get(DISPATCHER_CORRIDOR_COVERAGE_METADATA)
    adaptations: list[LegacyFamilyAdaptation] = []
    for entry in envelope.entries:
        value = values[entry.key]
        if entry.key in {
            CONCRETE_STATE_ROUTE_PROVENANCE_METADATA,
            NATIVE_BOUND_TRANSITION_ROUTE_RECEIPTS_METADATA,
            EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
        }:
            result_ids = _exact_family_result_ids(entry.key, value, context=context)
        else:
            adapted = _adapt_known_family(
                entry.key, value, context=context, coverage_payload=coverage,
            )
            if adapted is None or adapted != proposal:
                raise ValueError(f"legacy {entry.key} family did not match canonical proposal")
            result_ids = _family_result_ids(
                entry.key, value, proposal=proposal, context=context,
            )
        adaptations.append(LegacyFamilyAdaptation(
            entry.key,
            entry.key,
            result_ids,
            entry.canonical_payload,
            entry.payload_sha256,
        ))
    return LegacyShadowCodecReceipt(envelope, tuple(adaptations))


def decode_legacy_unflatten_contract(
    metadata: tuple[tuple[str, object], ...],
    *,
    context: LegacyUnflattenDecodeContext,
) -> LegacyUnflattenDecodeResult:
    """Classify legacy metadata without inventing a semantic route."""

    if type(context) is not LegacyUnflattenDecodeContext:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            None,
            "legacy_decode_context_invalid",
        )
    try:
        LegacyUnflattenDecodeContext.__post_init__(context)
    except Exception:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            None,
            "legacy_decode_context_invalid",
        )
    try:
        items = _metadata(metadata)
    except TypeError:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            None,
            "legacy_metadata_key_type_invalid",
        )
    except ValueError:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            None,
            "legacy_metadata_shape_invalid",
        )

    reserved = [key for key, _value in items if key in LEGACY_RESERVED_KEYS]
    unknown = [
        key for key, _value in items if key not in LEGACY_RESERVED_KEYS and _looks_authoritative(key)
    ]
    if not reserved:
        if unknown:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                unknown[0],
                "legacy_unknown_authoritative_key",
            )
        return LegacyUnflattenAbsent(UnflattenPlanRoute.ORDINARY)

    # Presence of any reserved legacy evidence is itself a route claim.  A
    # missing canonical route therefore wins over duplicate, partial, or
    # malformed payload details, so callers cannot probe the old schema
    # through a non-authoritative context.
    if context.canonical_route_evidence is None:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.LEGACY_ROUTE_EVIDENCE_MISSING,
            reserved[0],
            "legacy_route_evidence_missing",
        )
    if unknown:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            unknown[0],
            "legacy_unknown_authoritative_key",
        )
    if len(reserved) != len(set(reserved)):
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            next(key for key in reserved if reserved.count(key) > 1),
            "legacy_duplicate_reserved_key",
        )

    for key, value in items:
        if key not in LEGACY_RESERVED_KEYS:
            continue
        try:
            audit_failure = (
                _use_def_failure(value)
                if key == USE_DEF_SEVERANCE_AUDIT_METADATA
                else None
            )
            generations = _payload_generations(value)
            found = _walk_payload(value)
        except Exception:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                key,
                "legacy_payload_shape_invalid",
            )
        if audit_failure is not None:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                key,
                audit_failure,
            )
        if any(generation != context.source_generation for generation in generations):
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                key,
                "legacy_source_generation_mismatch",
            )
        if found is not None:
            field, detail = found
            if detail == "legacy_source_generation_invalid":
                return LegacyUnflattenRejected(
                    UnflattenAuthorityReason.MALFORMED_PROPOSAL, key, detail
                )
            if field in {"source_generation", "generation"}:
                generation = value.get(field) if isinstance(value, Mapping) else None
                if generation != context.source_generation:
                    return LegacyUnflattenRejected(
                        UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                        key,
                        "legacy_source_generation_mismatch",
                    )
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL, key, detail
            )

    if EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA in reserved:
        if len(reserved) != 1:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
                "legacy_exact_effect_mixed_reserved_families",
            )
        if context.plan_inputs is None or context.use_def_witness is None:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
                "legacy_exact_effect_not_enabled",
            )
        try:
            exact_values = [
                value for key, value in items
                if key == EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA
            ]
            if len(exact_values) != 1 or type(exact_values[0]) not in (tuple, list):
                raise ValueError("exact-effect legacy payload must be one sequence")
            exclusions = tuple(
                exact_state_branch_effect_exclusion_from_metadata(payload)
                for payload in exact_values[0]
            )
            if not exclusions or any(exclusion is None for exclusion in exclusions):
                raise ValueError("exact-effect legacy payload contains an invalid exclusion")
            typed_exclusions = tuple(exclusion for exclusion in exclusions if exclusion is not None)
            state_identity = typed_exclusions[0].state_identity
            if any(exclusion.state_identity != state_identity for exclusion in typed_exclusions):
                raise ValueError("exact-effect legacy payload has mixed state identities")
            if context.use_def_witness.state_identity != state_identity:
                raise ValueError("exact-effect legacy use-def state identity mismatch")
            from .producer_api import (
                _exact_effect_claim,
                build_proposal,
                build_source_identity_catalog,
            )
            refs_by_serial = dict(context.block_refs_by_serial)
            serial_by_ref = {ref: serial for serial, ref in refs_by_serial.items()}
            plan_inputs = context.plan_inputs
            dispatcher_entry_serial = serial_by_ref[plan_inputs.dispatcher_entry_ref]
            dispatcher_member_serials = tuple(
                sorted(serial_by_ref[ref] for ref in plan_inputs.dispatcher_member_refs)
            )
            authoritative_handler_serials = tuple(
                sorted(serial_by_ref[handler.block_ref] for handler in plan_inputs.authoritative_handlers)
            )
            selected_route_proof_ids: tuple[str, ...] = ()
            if plan_inputs.shape is UnflattenPlanShape.PARTIAL_REWRITE:
                source_catalog = build_source_identity_catalog(
                    context.source,
                    refs_by_serial,
                    native_key=context.canonical_route_evidence.native_key,
                    source_generation=context.source_generation,
                    canonical_route_evidence=context.canonical_route_evidence,
                )
                exact_claims = tuple(
                    _exact_effect_claim(
                        exclusion=exclusion,
                        source=context.source,
                        source_catalog=source_catalog,
                        block_refs_by_serial=refs_by_serial,
                        canonical_route_evidence=context.canonical_route_evidence,
                        state_identity=state_identity,
                    )
                    for exclusion in typed_exclusions
                )
                selected_route_proof_ids = tuple(sorted({
                    proof_id
                    for claim in exact_claims
                    for proof_id in claim.route_proof_ids
                }))

            proposal = build_proposal(
                plan_id=context.plan_id,
                source=context.source,
                block_refs_by_serial=refs_by_serial,
                source_generation=context.source_generation,
                canonical_route_evidence=context.canonical_route_evidence,
                selected_route_proof_ids=selected_route_proof_ids,
                exact_state_effect_exclusions=typed_exclusions,
                dispatcher_entry_serial=dispatcher_entry_serial,
                dispatcher_member_serials=dispatcher_member_serials,
                authoritative_handler_serials=authoritative_handler_serials,
                state_identity=state_identity,
                use_def_witness=context.use_def_witness,
            )
            if (
                proposal.plan_inputs != context.plan_inputs
                or proposal.use_def_witness != context.use_def_witness
            ):
                raise ValueError("exact legacy typed inputs were normalized or substituted")
        except Exception:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                EXACT_STATE_BRANCH_EFFECT_EXCLUSIONS_METADATA,
                "legacy_exact_effect_payload_invalid",
            )
        return LegacyUnflattenDecoded(UnflattenPlanRoute.LEGACY_ADAPTED, proposal)

    route_keys = {
        "concrete_state_route_provenance",
        "native_bound_transition_route_receipts",
    }
    route_keys_present = tuple(
        key for key in reserved
        if key in route_keys
    )
    if route_keys_present:
        if len(reserved) != 1 or reserved[0] not in route_keys:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                reserved[0],
                "legacy_route_mixed_reserved_families",
            )
        if context.plan_inputs is None or context.use_def_witness is None:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                reserved[0],
                "legacy_route_not_enabled",
            )
        try:
            from .producer_api import build_proposal

            refs_by_serial = dict(context.block_refs_by_serial)
            serial_by_ref = {ref: serial for serial, ref in refs_by_serial.items()}
            plan_inputs = context.plan_inputs
            selected_ids = select_route_proof_ids_from_legacy_metadata(
                dict(items)[reserved[0]],
                route_evidence=context.canonical_route_evidence,
                key=reserved[0],
                block_refs_by_serial=refs_by_serial,
            )
            proposal = build_proposal(
                plan_id=context.plan_id,
                source=context.source,
                block_refs_by_serial=refs_by_serial,
                source_generation=context.source_generation,
                canonical_route_evidence=context.canonical_route_evidence,
                exact_state_effect_exclusions=(),
                dispatcher_entry_serial=serial_by_ref[plan_inputs.dispatcher_entry_ref],
                dispatcher_member_serials=tuple(
                    sorted(serial_by_ref[ref] for ref in plan_inputs.dispatcher_member_refs)
                ),
                authoritative_handler_serials=tuple(
                    sorted(serial_by_ref[handler.block_ref] for handler in plan_inputs.authoritative_handlers)
                ),
                state_identity=plan_inputs.state_identity,
                use_def_witness=context.use_def_witness,
                selected_route_proof_ids=selected_ids,
            )
            matched_claims = equivalent_route_claims_from_legacy_metadata(
                dict(items)[reserved[0]],
                proposal=proposal,
                key=reserved[0],
                block_refs_by_serial=refs_by_serial,
            )
            proposal = replace(proposal, claims=tuple(matched_claims))
        except Exception:
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                reserved[0],
                "legacy_route_payload_invalid",
            )
        return LegacyUnflattenDecoded(UnflattenPlanRoute.LEGACY_ADAPTED, proposal)

    # Once a producer has supplied the sealed canonical proposal, every
    # migrated legacy family is adapted as a transport check.  The proposal
    # remains the sole semantic authority.
    if context.canonical_proposal is not None:
        try:
            adapted = _adapt_known_family(
                reserved[0], dict(items)[reserved[0]], context=context,
            )
        except (TypeError, ValueError):
            return LegacyUnflattenRejected(
                UnflattenAuthorityReason.MALFORMED_PROPOSAL,
                reserved[0],
                "legacy_family_payload_invalid",
            )
        if adapted is not None:
            return LegacyUnflattenDecoded(UnflattenPlanRoute.LEGACY_ADAPTED, adapted)

    detail_code = _family_detail(reserved[0])
    if detail_code is None:
        return LegacyUnflattenRejected(
            UnflattenAuthorityReason.MALFORMED_PROPOSAL,
            reserved[0],
            "legacy_family_detail_unavailable",
        )
    return LegacyUnflattenRejected(
        UnflattenAuthorityReason.MALFORMED_PROPOSAL,
        reserved[0],
        detail_code,
    )


__all__ = [
    "LEGACY_RESERVED_KEYS",
    "LegacyFamilyAdaptation",
    "LegacyShadowCodecReceipt",
    "LegacyUnflattenAbsent",
    "LegacyUnflattenDecoded",
    "LegacyUnflattenDecodeContext",
    "LegacyUnflattenDecodeResult",
    "LegacyUnflattenRejected",
    "NativeBoundTransitionRouteReceipt",
    "adapt_legacy_unflatten_shadow",
    "decode_legacy_canonical_payload",
    "decode_legacy_unflatten_contract",
    "equivalent_route_claims_from_legacy_metadata",
    "legacy_canonical_bytes",
    "legacy_canonical_decode",
    "native_bound_transition_route_receipts_from_plan",
    "retirement_claim_from_legacy_proof",
    "select_route_proof_ids_from_legacy_metadata",
]
