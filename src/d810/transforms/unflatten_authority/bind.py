"""Exact source/projected identity binding for typed unflatten subjects."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import weakref

from d810.analyses.control_flow.effect_branch_exclusion import (
    ExactStateBranchEffectExclusion,
    validate_exact_state_branch_effect_exclusion,
)
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from . import model, producer_api
from .ids import canonical_bytes, semantic_graph_fingerprint, validate_canonical_roundtrip


def _canonical_digest(value: object, label: str) -> None:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(char not in "0123456789abcdef" for char in value[7:])
    ):
        raise ValueError(f"{label} must be a canonical sha256 ID")


def _validate_exact_result_authority(
    *,
    proposal: model.ProposedUnflattenContract,
    exclusion: ExactStateBranchEffectExclusion,
    claim: model.ExactInfeasibleEffectClaim,
    source_serial_by_ref: dict[object, int],
) -> None:
    producer_api.validate_exact_effect_semantics(
        proposal=proposal,
        exclusion=exclusion,
        claim=claim,
        source_catalog=proposal.source_identity_catalog,
        route_evidence=proposal.route_evidence,
        source_serial_by_ref=source_serial_by_ref,
    )


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ExactEffectBindingResult:
    """The only binding output admitted for an exact-effect claim."""

    def __new__(cls, *args: object, **kwargs: object):
        raise TypeError("ExactEffectBindingResult can only be minted by bind_exact_effect_claim")

    claim: model.ExactInfeasibleEffectClaim
    proposal: model.ProposedUnflattenContract
    exclusion: ExactStateBranchEffectExclusion
    source_catalog: model.SourceIdentityCatalog
    source_serial_rows: tuple[tuple[object, int], ...]
    projected_serial_rows: tuple[tuple[object, int], ...]
    source_bindings: tuple[model.PhaseSubjectBinding, ...]
    projected_bindings: tuple[model.PhaseSubjectBinding, ...]
    source_graph_fingerprint: str
    projected_graph_fingerprint: str
    generation: int
    _content_seal: str = field(init=False, repr=False, compare=False)

    @property
    def claim_id(self) -> str:
        return self.claim.claim_id

    def _validate_fields(self) -> None:
        if type(self.claim) is not model.ExactInfeasibleEffectClaim:
            raise TypeError("claim must be the closed exact-effect claim")
        validate_canonical_roundtrip(self.claim, model.ExactInfeasibleEffectClaim)
        if type(self.proposal) is not model.ProposedUnflattenContract:
            raise TypeError("proposal must be the closed exact-effect proposal")
        if type(self.exclusion) is not ExactStateBranchEffectExclusion:
            raise TypeError("exclusion must be the closed exact-effect record")
        validate_canonical_roundtrip(self.proposal, model.ProposedUnflattenContract)
        self.exclusion.__post_init__()
        if type(self.source_catalog) is not model.SourceIdentityCatalog:
            raise TypeError("source_catalog must be the closed identity catalog")
        validate_canonical_roundtrip(self.source_catalog, model.SourceIdentityCatalog)
        if self.proposal.source_identity_catalog != self.source_catalog:
            raise ValueError("result catalog must equal proposal catalog")
        if (
            self.claim.source_generation != self.generation
            or self.source_catalog.generation != self.generation
        ):
            raise ValueError("exact-effect claim, catalog, and binding generation must match")
        catalog_refs = tuple(item.block_ref for item in self.source_catalog.blocks)
        catalog_ref_set = set(catalog_refs)
        claim_owned_refs = {
            subject.block_ref
            for subject in (
                self.claim.source_subject,
                self.claim.predicate_subject,
                self.claim.selected_target_subject,
                self.claim.discarded_effect_subject,
            )
        }
        if any(ref is None for ref in claim_owned_refs) or len(claim_owned_refs) != 4:
            raise ValueError("exact-effect claim must own four distinct block references")

        def validate_rows(
            rows: object,
            label: str,
        ) -> dict[object, int]:
            if type(rows) is not tuple:
                raise TypeError(f"{label} must be an exact tuple")
            parsed: list[tuple[object, int]] = []
            for row in rows:
                if type(row) is not tuple or len(row) != 2:
                    raise TypeError(f"{label} must contain (ref, serial) rows")
                ref, serial = row
                if type(ref) not in (NativeBlockRef, LogicalBlockRef):
                    raise TypeError(f"{label} contains a foreign ref")
                validate_canonical_roundtrip(ref, type(ref))
                if type(serial) is not int or serial < 0:
                    raise ValueError(f"{label} contains a non-canonical serial")
                parsed.append((ref, serial))
            refs = tuple(ref for ref, _serial in parsed)
            serials = tuple(serial for _ref, serial in parsed)
            if len(set(refs)) != len(refs) or len(set(serials)) != len(serials):
                raise ValueError(f"{label} contains duplicate rows")
            expected_order = tuple(
                item.block_ref
                for item in self.source_catalog.blocks
                if item.block_ref in claim_owned_refs
            )
            if refs != expected_order:
                raise ValueError(f"{label} must use canonical catalog order")
            if set(refs) != claim_owned_refs:
                raise ValueError(f"{label} must exactly cover the claim-owned references")
            if not set(refs) <= catalog_ref_set:
                raise ValueError(f"{label} contains a foreign catalog reference")
            return dict(parsed)

        source_serial_by_ref = validate_rows(self.source_serial_rows, "source serial rows")
        projected_serial_by_ref = validate_rows(self.projected_serial_rows, "projected serial rows")
        if type(self.source_bindings) is not tuple or type(self.projected_bindings) is not tuple:
            raise TypeError("exact-effect bindings must be exact tuples")
        if not self.source_bindings or not self.projected_bindings:
            raise ValueError("exact-effect bindings must not be empty")
        if any(type(item) is not model.PhaseSubjectBinding for item in self.source_bindings):
            raise TypeError("source_bindings must be closed phase bindings")
        if any(type(item) is not model.PhaseSubjectBinding for item in self.projected_bindings):
            raise TypeError("projected_bindings must be closed phase bindings")
        for item in (*self.source_bindings, *self.projected_bindings):
            validate_canonical_roundtrip(item, model.PhaseSubjectBinding)
        source_ids = tuple(item.subject.subject_id for item in self.source_bindings)
        projected_ids = tuple(item.subject.subject_id for item in self.projected_bindings)
        if source_ids != tuple(sorted(source_ids)) or projected_ids != tuple(sorted(projected_ids)):
            raise ValueError("exact-effect bindings must use canonical subject order")
        if len(set(source_ids)) != len(source_ids) or len(set(projected_ids)) != len(projected_ids):
            raise ValueError("exact-effect bindings must not duplicate subjects")
        if set(source_ids) != set(projected_ids):
            raise ValueError("source/projected exact-effect subjects must match")
        for item in (*self.source_bindings, *self.projected_bindings):
            if item.status is not model.SubjectBindingStatus.UNIQUE:
                raise ValueError("exact-effect binding result cannot contain missing subjects")
        if any(item.phase is not model.UnflattenAuthorityPhase.PRODUCER_FORECAST for item in self.source_bindings):
            raise ValueError("source exact-effect bindings have the wrong phase")
        if any(item.phase is not model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT for item in self.projected_bindings):
            raise ValueError("projected exact-effect bindings have the wrong phase")
        projected_by_id = {item.subject.subject_id: item for item in self.projected_bindings}
        if any(item.role is not projected_by_id[item.subject.subject_id].role for item in self.source_bindings):
            raise ValueError("source/projected exact-effect roles must match")
        _canonical_digest(self.source_graph_fingerprint, "source graph fingerprint")
        _canonical_digest(self.projected_graph_fingerprint, "projected graph fingerprint")
        if type(self.generation) is not int or isinstance(self.generation, bool) or self.generation < 0:
            raise ValueError("binding generation must be an exact non-negative int")
        if any(item.generation != self.generation for item in (*self.source_bindings, *self.projected_bindings)):
            raise ValueError("exact-effect binding generations must be uniform")
        if any(item.graph_fingerprint != self.source_graph_fingerprint for item in self.source_bindings):
            raise ValueError("source binding fingerprints must be uniform")
        if any(item.graph_fingerprint != self.projected_graph_fingerprint for item in self.projected_bindings):
            raise ValueError("projected binding fingerprints must be uniform")
        expected_subjects = {
            subject.subject_id for subject in (
                self.claim.source_subject,
                self.claim.predicate_subject,
                self.claim.selected_target_subject,
                self.claim.discarded_effect_subject,
            )
        }
        if set(source_ids) != expected_subjects or set(projected_ids) != expected_subjects:
            raise ValueError("bindings are not cryptographically tied to the claim")
        source_binding_refs = {item.block_ref for item in self.source_bindings}
        projected_binding_refs = {item.block_ref for item in self.projected_bindings}
        if source_binding_refs != claim_owned_refs or projected_binding_refs != claim_owned_refs:
            raise ValueError("binding rows must exactly cover the claim-owned references")
        if self.claim.source_generation != self.generation:
            raise ValueError("claim generation does not match result generation")
        _validate_exact_result_authority(
            proposal=self.proposal,
            exclusion=self.exclusion,
            claim=self.claim,
            source_serial_by_ref=source_serial_by_ref,
        )
        witnesses = {item.block_ref: item for item in self.source_catalog.blocks}
        for item in self.source_bindings:
            witness = witnesses.get(item.block_ref)
            serial = source_serial_by_ref.get(item.block_ref)
            if witness is None or serial is None:
                raise ValueError("source binding refers to a foreign catalog row")
            if (
                item.serial != serial
                or item.anchor_ea != witness.anchor_ea
                or item.native_instruction_eas != witness.native_instruction_eas
                or item.generation != self.source_catalog.generation
            ):
                raise ValueError("source binding is not truthfully bound to its catalog row")
        for item in self.projected_bindings:
            witness = witnesses.get(item.block_ref)
            serial = projected_serial_by_ref.get(item.block_ref)
            if witness is None or serial is None:
                raise ValueError("projected binding refers to a foreign catalog row")
            if (
                item.serial != serial
                or item.anchor_ea != witness.anchor_ea
                or item.native_instruction_eas != witness.native_instruction_eas
                or item.generation != self.source_catalog.generation
            ):
                raise ValueError("projected binding is not truthfully bound to its catalog row")


def _binding_content_seal(result: ExactEffectBindingResult) -> str:
    exclusion = result.exclusion
    exclusion_payload = (
        exclusion.normalized_state,
        exclusion.source_serial,
        exclusion.source_ea,
        exclusion.source_write_ea,
        exclusion.predicate_serial,
        exclusion.predicate_ea,
        exclusion.predicate_branch_ea,
        exclusion.selected_target_serial,
        exclusion.selected_target_ea,
        exclusion.discarded_effect_serial,
        exclusion.discarded_effect_ea,
        exclusion.state_identity,
    )
    payload = (
        result.claim,
        result.proposal,
        exclusion_payload,
        result.source_catalog,
        result.source_serial_rows,
        result.projected_serial_rows,
        result.source_bindings,
        result.projected_bindings,
        result.source_graph_fingerprint,
        result.projected_graph_fingerprint,
        result.generation,
    )
    return "sha256:" + hashlib.sha256(canonical_bytes(payload)).hexdigest()


def _locator_refs(subject: model.SemanticSubjectRef) -> tuple[object, ...]:
    locator = subject.locator
    if type(locator) is model.BlockSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.EdgeSubjectLocator:
        return (locator.source_ref, locator.target_ref)
    if type(locator) is model.RouteSubjectLocator:
        return (locator.source_ref, *locator.destination_refs)
    if type(locator) is model.EffectSubjectLocator:
        return (locator.owner_ref,)
    if type(locator) is model.HandlerSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.TerminalSubjectLocator:
        return (locator.block_ref,)
    if type(locator) is model.ValueFlowSubjectLocator:
        return tuple(locator.redirect_owner_refs)
    if type(locator) is model.CorridorSubjectLocator:
        return (locator.entry_ref, *locator.member_refs)
    raise TypeError("subject locator is not closed")


def bind_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind every subject against one immutable catalog and exact generation.

    The binding operation deliberately accepts no serial fallback and no
    nearest-anchor matching.  A missing, duplicate, foreign, stale, or
    partially matching row is a rejection rather than an ambiguous binding.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    if set(serial_by_ref) != set(witnesses):
        raise ValueError("serial binding must exactly cover the source catalog")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas for ref, witness in witnesses.items()
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if set(origins) != set(witnesses):
        raise ValueError("native-origin binding must exactly cover the source catalog")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        refs = _locator_refs(subject)
        if any(ref not in witnesses for ref in refs):
            raise ValueError("subject contains a foreign or missing source reference")
        for ref in refs:
            expected = tuple(witnesses[ref].native_instruction_eas)
            supplied = tuple(origins[ref])
            if supplied != expected:
                raise ValueError("native instruction origins do not exactly match catalog")
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        owner = subject.block_ref
        if owner not in witnesses or subject.anchor_ea is None:
            raise ValueError("subject has no exact owner anchor")
        witness = witnesses[owner]
        if subject.anchor_ea != witness.anchor_ea or subject.anchor_ea not in witness.native_instruction_eas:
            raise ValueError("subject anchor is a near-match for its source witness")
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness.native_instruction_eas,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


bind_source_subjects = bind_subjects


def bind_projected_subjects(
    subjects: Sequence[model.SemanticSubjectRef],
    *,
    catalog: model.SourceIdentityCatalog,
    phase: model.UnflattenAuthorityPhase,
    graph_fingerprint: str,
    generation: int,
    serial_by_ref: Mapping[object, int],
    native_instruction_eas_by_ref: Mapping[object, Sequence[int]] | None = None,
) -> tuple[model.PhaseSubjectBinding, ...]:
    """Bind source subjects against a possibly lossy projected graph.

    The projected map is intentionally allowed to omit source references.  A
    subject whose exact owner is absent is represented as ``MISSING``; it is
    not rebound by serial, anchor proximity, or a fabricated projected ref.
    """

    if type(catalog) is not model.SourceIdentityCatalog:
        raise TypeError("catalog must be a SourceIdentityCatalog")
    validate_canonical_roundtrip(catalog, model.SourceIdentityCatalog)
    if type(phase) is not model.UnflattenAuthorityPhase:
        raise TypeError("phase must be an UnflattenAuthorityPhase")
    if type(graph_fingerprint) is not str or not graph_fingerprint.startswith("sha256:"):
        raise ValueError("graph_fingerprint must be a canonical ID")
    if type(generation) is not int or isinstance(generation, bool) or generation != catalog.generation:
        raise ValueError("binding generation does not match source catalog")
    witnesses = {item.block_ref: item for item in catalog.blocks}
    if len(witnesses) != len(catalog.blocks):
        raise ValueError("source catalog contains duplicate block references")
    if any(ref not in witnesses for ref in serial_by_ref):
        raise ValueError("projected serial binding contains a foreign source reference")
    serials = tuple(serial_by_ref.values())
    if any(type(serial) is not int or serial < 0 for serial in serials):
        raise ValueError("serial bindings must be exact non-negative integers")
    if len(set(serials)) != len(serials):
        raise ValueError("serial bindings must be unique")
    origins = (
        {
            ref: witness.native_instruction_eas
            for ref, witness in witnesses.items()
            if ref in serial_by_ref
        }
        if native_instruction_eas_by_ref is None
        else native_instruction_eas_by_ref
    )
    if native_instruction_eas_by_ref is not None and set(origins) != set(serial_by_ref):
        raise ValueError("projected native-origin binding must cover every projected reference")
    if any(ref not in witnesses or ref not in serial_by_ref for ref in origins):
        raise ValueError("projected native-origin binding contains a foreign reference")
    for ref, supplied in origins.items():
        if tuple(supplied) != tuple(witnesses[ref].native_instruction_eas):
            raise ValueError("native instruction origins do not exactly match catalog")

    result: list[model.PhaseSubjectBinding] = []
    seen_subjects: set[str] = set()
    for subject in subjects:
        if type(subject) is not model.SemanticSubjectRef:
            raise TypeError("subjects must contain SemanticSubjectRef values")
        validate_canonical_roundtrip(subject, model.SemanticSubjectRef)
        if subject.subject_id in seen_subjects:
            raise ValueError("subject bindings contain duplicate subjects")
        seen_subjects.add(subject.subject_id)
        refs = _locator_refs(subject)
        if any(ref not in witnesses for ref in refs):
            raise ValueError("subject contains a foreign or missing source reference")
        owner = subject.block_ref
        if subject.kind is model.SemanticSubjectKind.VALUE_FLOW:
            owner_present = False
        else:
            if owner is None:
                raise ValueError("projected subject has no exact owner")
            owner_present = owner in serial_by_ref
        complete = all(ref in serial_by_ref for ref in refs)
        if not owner_present or not complete:
            result.append(model.PhaseSubjectBinding(
                subject=subject,
                phase=phase,
                block_ref=None,
                graph_fingerprint=graph_fingerprint,
                generation=generation,
                status=model.SubjectBindingStatus.MISSING,
                serial=None,
                anchor_ea=None,
                native_instruction_eas=(),
                role=subject.role,
            ))
            continue
        witness = witnesses[owner]
        if subject.anchor_ea is None or subject.anchor_ea != witness.anchor_ea:
            raise ValueError("subject anchor is a near-match for its source witness")
        if subject.anchor_ea not in tuple(origins.get(owner, ())):
            raise ValueError("projected subject origin does not exactly match catalog")
        result.append(model.PhaseSubjectBinding(
            subject=subject,
            phase=phase,
            block_ref=owner,
            graph_fingerprint=graph_fingerprint,
            generation=generation,
            status=model.SubjectBindingStatus.UNIQUE,
            serial=serial_by_ref[owner],
            anchor_ea=subject.anchor_ea,
            native_instruction_eas=witness.native_instruction_eas,
            role=subject.role,
        ))
    return tuple(sorted(result, key=lambda item: item.subject.subject_id))


def _graph_bind_exact_effect_claim(
    *,
    source: FlowGraph,
    projected: FlowGraph,
    source_block_refs_by_serial: Mapping[int, object],
    projected_serial_by_ref: Mapping[object, int],
    exclusion: ExactStateBranchEffectExclusion,
    claim: model.ExactInfeasibleEffectClaim,
    proposal: model.ProposedUnflattenContract,
    generation: int,
    _mint_result: object,
    _lifecycle_secret: object,
) -> ExactEffectBindingResult:
    """Replay exact source/projected topology before emitting bindings.

    This facade is intentionally narrower than the generic binders. It accepts
    only the exact-effect claim, replays the immutable source/projected proof,
    correlates every claim locator to the source catalog, and returns source
    and projected phase bindings. Any changed topology, identity, generation,
    or claim/exclusion field rejects the complete fragment.
    """

    if type(source) is not FlowGraph or type(projected) is not FlowGraph:
        raise TypeError("exact-effect binding requires exact FlowGraph values")
    if type(exclusion) is not ExactStateBranchEffectExclusion:
        raise TypeError("exact-effect binding requires the closed exclusion type")
    if type(claim) is not model.ExactInfeasibleEffectClaim:
        raise TypeError("exact-effect binding requires the closed claim type")
    if type(proposal) is not model.ProposedUnflattenContract:
        raise TypeError("exact-effect binding requires the closed proposal type")
    validate_canonical_roundtrip(proposal, model.ProposedUnflattenContract)
    validate_canonical_roundtrip(claim, model.ExactInfeasibleEffectClaim)
    if claim not in proposal.claims or claim.source_generation != generation:
        raise ValueError("exact-effect claim is foreign to the proposal generation")
    if proposal.source_identity_catalog.generation != generation:
        raise ValueError("exact-effect proposal generation is stale")
    if not validate_exact_state_branch_effect_exclusion(source, projected, exclusion):
        raise ValueError("exact-effect source/projected topology is not exact")

    if type(source_block_refs_by_serial) is not dict:
        raise TypeError("source serial map must be an exact dict")
    source_rows = tuple(source_block_refs_by_serial.items())
    if any(
        type(serial) is not int or serial < 0
        or type(ref) not in (NativeBlockRef, LogicalBlockRef)
        for serial, ref in source_rows
    ):
        raise ValueError("source serial map contains a non-canonical row")
    for _serial, ref in source_rows:
        validate_canonical_roundtrip(ref, type(ref))
    by_serial = dict(source_rows)
    catalog_by_ref = {
        item.block_ref: item for item in proposal.source_identity_catalog.blocks
    }
    if set(by_serial.values()) != set(catalog_by_ref):
        raise ValueError("source serial map does not exactly cover the proposal catalog")
    for serial, ref in by_serial.items():
        block = source.get_block(serial)
        anchor = None if block is None else block.native_start_ea
        if anchor is None and block is not None:
            anchor = block.start_ea
        if block is None or type(anchor) is not int or anchor != catalog_by_ref[ref].anchor_ea:
            raise ValueError("source block identity does not match the proposal catalog")
    if type(projected_serial_by_ref) is not dict:
        raise TypeError("projected serial map must be an exact dict")
    projected_rows = tuple(projected_serial_by_ref.items())
    if any(
        type(ref) not in (NativeBlockRef, LogicalBlockRef)
        or type(serial) is not int or serial < 0
        for ref, serial in projected_rows
    ):
        raise ValueError("projected serial map contains a non-canonical row")
    for ref, _serial in projected_rows:
        validate_canonical_roundtrip(ref, type(ref))
    projected_rows_map = dict(projected_rows)
    if len(projected_rows_map) != len(projected_rows) or len({serial for _ref, serial in projected_rows}) != len(projected_rows):
        raise ValueError("projected serial map contains duplicate identity rows")
    for ref, serial in projected_rows:
        block = projected.get_block(serial)
        anchor = None if block is None else block.native_start_ea
        if anchor is None and block is not None:
            anchor = block.start_ea
        if ref not in catalog_by_ref or block is None or type(anchor) is not int or anchor != catalog_by_ref[ref].anchor_ea:
            raise ValueError("projected block identity is foreign or missing")
    exclusion_refs = {}
    for name in (
        "source_serial", "predicate_serial", "selected_target_serial",
        "discarded_effect_serial",
    ):
        serial = getattr(exclusion, name)
        if serial not in by_serial:
            raise ValueError("exact-effect exclusion refers to an unknown source serial")
        exclusion_refs[name] = by_serial[serial]
    if claim.state_identity != exclusion.state_identity:
        raise ValueError("exact-effect claim state identity is not exclusion-bound")
    if claim.normalized_state != exclusion.normalized_state:
        raise ValueError("exact-effect claim state value is not exclusion-bound")
    if claim.source_write_ea != exclusion.source_write_ea:
        raise ValueError("exact-effect claim source write is not exclusion-bound")
    if claim.predicate_branch_ea != exclusion.predicate_branch_ea:
        raise ValueError("exact-effect claim predicate branch is not exclusion-bound")
    discarded_witness = catalog_by_ref[exclusion_refs["discarded_effect_serial"]]
    if claim.discarded_effect_subject.anchor_ea != discarded_witness.anchor_ea:
        raise ValueError("exact-effect claim discarded block anchor is foreign")
    if claim.discarded_effect_subject.locator.instruction_ea != claim.discarded_effect_ea:
        raise ValueError("exact-effect claim discarded effect EA is not locator-bound")
    expected_claim = producer_api.build_exact_effect_claim(
        exclusion=exclusion,
        source=source,
        source_catalog=proposal.source_identity_catalog,
        block_refs_by_serial=by_serial,
        canonical_route_evidence=proposal.route_evidence,
        state_identity=proposal.plan_inputs.state_identity,
    )
    if claim != expected_claim or claim.claim_id != expected_claim.claim_id:
        raise ValueError("exact-effect claim does not match canonical producer reconstruction")
    if claim.source_subject.block_ref != exclusion_refs["source_serial"]:
        raise ValueError("exact-effect claim source identity is foreign")
    if claim.predicate_subject.block_ref != exclusion_refs["predicate_serial"]:
        raise ValueError("exact-effect claim predicate identity is foreign")
    if claim.selected_target_subject.block_ref != exclusion_refs["selected_target_serial"]:
        raise ValueError("exact-effect claim selected identity is foreign")
    if claim.discarded_effect_subject.block_ref != exclusion_refs["discarded_effect_serial"]:
        raise ValueError("exact-effect claim discarded identity is foreign")
    source_origins = {
        ref: witness.native_instruction_eas
        for ref, witness in catalog_by_ref.items()
    }
    exact_subjects = tuple({
        item.subject_id: item for item in (
            claim.effect_subject, claim.source_subject, claim.predicate_subject,
            claim.selected_target_subject, claim.discarded_effect_subject,
        )
    }.values())
    source_bindings = bind_source_subjects(
        exact_subjects,
        catalog=proposal.source_identity_catalog,
        phase=model.UnflattenAuthorityPhase.PRODUCER_FORECAST,
        graph_fingerprint=semantic_graph_fingerprint(source),
        generation=generation,
        serial_by_ref={ref: serial for serial, ref in by_serial.items()},
        native_instruction_eas_by_ref=source_origins,
    )
    projected_bindings = bind_projected_subjects(
        exact_subjects,
        catalog=proposal.source_identity_catalog,
        phase=model.UnflattenAuthorityPhase.PROJECTED_PREFLIGHT,
        graph_fingerprint=semantic_graph_fingerprint(projected),
        generation=generation,
        serial_by_ref=projected_rows_map,
    )
    if any(item.status is not model.SubjectBindingStatus.UNIQUE for item in projected_bindings):
        raise ValueError("exact-effect projected bindings must be unique")
    expected_serials = {
        by_serial[getattr(exclusion, field)]: getattr(exclusion, field)
        for field in (
            "source_serial", "predicate_serial", "selected_target_serial",
            "discarded_effect_serial",
        )
    }
    if any(projected_rows_map.get(ref) != serial for ref, serial in expected_serials.items()):
        raise ValueError("projected exact-effect serials do not match the exclusion")
    source_fingerprint = semantic_graph_fingerprint(source)
    projected_fingerprint = semantic_graph_fingerprint(projected)
    if any(item.graph_fingerprint != source_fingerprint for item in source_bindings):
        raise ValueError("source bindings do not contain the measured graph fingerprint")
    if any(item.graph_fingerprint != projected_fingerprint for item in projected_bindings):
        raise ValueError("projected bindings do not contain the measured graph fingerprint")
    source_rows = tuple(
        (item.block_ref, {ref: serial for serial, ref in by_serial.items()}[item.block_ref])
        for item in proposal.source_identity_catalog.blocks
        if item.block_ref in {
            subject.block_ref
            for subject in (
                claim.source_subject,
                claim.predicate_subject,
                claim.selected_target_subject,
                claim.discarded_effect_subject,
            )
        }
    )
    projected_rows = tuple(
        (item.block_ref, projected_rows_map[item.block_ref])
        for item in proposal.source_identity_catalog.blocks
        if item.block_ref in projected_rows_map
        and item.block_ref in {
            subject.block_ref
            for subject in (
                claim.source_subject,
                claim.predicate_subject,
                claim.selected_target_subject,
                claim.discarded_effect_subject,
            )
        }
    )
    if _lifecycle_secret is None:
        raise TypeError("exact-effect binding lifecycle is closed")
    return _mint_result(
        claim=claim,
        proposal=proposal,
        exclusion=exclusion,
        source_catalog=proposal.source_identity_catalog,
        source_serial_rows=source_rows,
        projected_serial_rows=projected_rows,
        source_bindings=source_bindings,
        projected_bindings=projected_bindings,
        source_graph_fingerprint=source_fingerprint,
        projected_graph_fingerprint=projected_fingerprint,
        generation=generation,
    )


def _make_binding_entrypoint(graph_impl=_graph_bind_exact_effect_claim):
    registry: dict[int, tuple[weakref.ReferenceType[ExactEffectBindingResult], str]] = {}
    lifecycle_secret = object()

    def validate(result: ExactEffectBindingResult) -> None:
        if type(result) is not ExactEffectBindingResult:
            raise TypeError("exact-effect result must be closed")
        registered = registry.get(id(result))
        if registered is None or registered[0]() is not result:
            raise ValueError("exact-effect result was not minted by the graph binder")
        if result._content_seal != registered[1] or registered[1] != _binding_content_seal(result):
            raise ValueError("exact-effect binding content seal does not match")
        result._validate_fields()

    def mint(**values: object) -> ExactEffectBindingResult:
        result = object.__new__(ExactEffectBindingResult)
        for name, value in values.items():
            object.__setattr__(result, name, value)
        object.__setattr__(result, "_content_seal", _binding_content_seal(result))
        identity = id(result)
        def cleanup(reference: weakref.ReferenceType[ExactEffectBindingResult]) -> None:
            registered = registry.get(identity)
            if registered is not None and registered[0] is reference:
                registry.pop(identity, None)
        reference = weakref.ref(result, cleanup)
        registry[identity] = (reference, result._content_seal)
        validate(result)
        return result

    def entrypoint(**kwargs: object) -> ExactEffectBindingResult:
        return graph_impl(
            **kwargs, _mint_result=mint, _lifecycle_secret=lifecycle_secret,
        )

    return entrypoint, validate


bind_exact_effect_claim, validate_exact_effect_binding_result = _make_binding_entrypoint()
del _make_binding_entrypoint
del _graph_bind_exact_effect_claim


__all__ = [
    "ExactEffectBindingResult",
    "validate_exact_effect_binding_result",
    "bind_subjects",
    "bind_source_subjects",
    "bind_projected_subjects",
    "bind_exact_effect_claim",
]
