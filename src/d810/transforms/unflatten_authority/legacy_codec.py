"""Strict, non-authoritative transport for legacy unflatten metadata.

The compatibility path deliberately stops at a typed rejection until the
family-specific adapters are implemented.  It is nevertheless executable:
legacy values are captured losslessly, integrity checked, and replayed through
the same closed canonical wire format used by authority records.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import hashlib

from d810.analyses.control_flow.semantic_route_evidence import (
    CanonicalSemanticEvidence,
)
from d810.core.typing import Any, Literal, TypeAlias
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import LogicalBlockRef, NativeBlockRef
from d810.transforms.plan import PatchPlan, normalized_metadata_items

from .legacy_keys import (
    LEGACY_FAMILY_DETAIL_CODES,
    LEGACY_UNFLATTEN_KEYS,
    USE_DEF_SEVERANCE_AUDIT_METADATA,
)
from .legacy_wire import decode_legacy_value, encode_legacy_value
from .model import (
    LegacyShadowEntry,
    LegacyUnflattenShadowEnvelope,
    ProposedUnflattenContract,
    UnflattenAuthorityReason,
    UnflattenPlanRoute,
)
# Keep one owner for this set.  In particular, the exact-effect spelling is
# imported through proposal.py from its producer rather than copied here.
LEGACY_RESERVED_KEYS = LEGACY_UNFLATTEN_KEYS


def _exact_text(value: object, label: str) -> None:
    if type(value) is not str or not value.strip():
        raise TypeError(f"{label} must be a non-empty exact str")


def _exact_generation(value: object, label: str) -> None:
    if type(value) is not int or value < 0:
        raise TypeError(f"{label} must be a non-negative exact int")


def _metadata(metadata: object) -> tuple[tuple[object, object], ...]:
    """Use PatchPlan's one stable parser, retaining order and duplicates."""

    try:
        items = normalized_metadata_items(metadata)
    except Exception as exc:
        raise ValueError("legacy metadata shape is invalid") from exc
    for key, _value in items:
        if type(key) is not str:
            raise TypeError("legacy metadata keys must be exact str")
    return items


def capture_legacy_unflatten_shadow(
    *,
    plan_id: str,
    snapshot_id: str,
    source_generation: int,
    metadata: tuple[tuple[str, object], ...],
) -> tuple[tuple[tuple[str, object], ...], LegacyUnflattenShadowEnvelope | None]:
    """Capture reserved values and return metadata safe for a typed plan.

    Ordinary entries are returned as the exact parsed pair objects.  Reserved
    entries are each captured once, sorted in the closed envelope, and removed
    from the top-level metadata channel.
    """

    _exact_text(plan_id, "plan_id")
    _exact_text(snapshot_id, "snapshot_id")
    _exact_generation(source_generation, "source_generation")
    items = _metadata(metadata)
    reserved: dict[str, object] = {}
    ordinary: list[tuple[str, object]] = []
    for key, value in items:
        if key not in LEGACY_RESERVED_KEYS:
            ordinary.append((key, value))
            continue
        if key in reserved:
            raise ValueError("reserved legacy metadata key occurs more than once")
        # canonical_bytes is deliberately called on the exact current value;
        # it rejects open/hostile objects instead of coercing them.
        canonical_payload = encode_legacy_value(value)
        reserved[key] = (value, canonical_payload)

    if not reserved:
        return tuple(ordinary), None

    entries = tuple(
        LegacyShadowEntry(
            key,
            payload,
            hashlib.sha256(payload).hexdigest(),
        )
        for key, (_value, payload) in sorted(reserved.items())
    )
    envelope = LegacyUnflattenShadowEnvelope(
        1,
        plan_id,
        snapshot_id,
        source_generation,
        entries,
    )
    return tuple(ordinary), envelope


def decode_legacy_canonical_payload(payload: bytes) -> object:
    """Decode one canonical payload and require a byte-identical re-encode."""

    value = decode_legacy_value(payload)
    if encode_legacy_value(value) != payload:
        raise ValueError("legacy payload is not byte-canonical")
    return value


# Descriptive aliases used by persistence adapters and tests.
legacy_canonical_bytes = encode_legacy_value
legacy_canonical_decode = decode_legacy_canonical_payload


@dataclass(frozen=True, slots=True)
class LegacyShadowPlanView:
    """A read-only replay view; it is never a second ``PatchPlan``."""

    plan: PatchPlan
    replay_metadata: tuple[tuple[str, object], ...]

    def __post_init__(self) -> None:
        if type(self.plan) is not PatchPlan:
            raise TypeError("shadow view requires an exact PatchPlan")
        items = _metadata(self.replay_metadata)
        object.__setattr__(self, "replay_metadata", items)

    def __getattr__(self, name: str) -> Any:
        # The explicit metadata property wins; all other plan attributes are
        # delegated without copying or mutation.
        if name == "legacy_unflatten_shadow":
            raise AttributeError("legacy shadow transport is hidden from the view")
        return getattr(self.plan, name)

    @property
    def legacy_unflatten_shadow(self) -> None:
        """Hide the transport envelope from the replay consumer."""

        raise AttributeError("legacy shadow transport is hidden from the view")

    @property
    def metadata(self) -> tuple[tuple[str, object], ...]:
        return _metadata(self.replay_metadata)

    def metadata_dict(self) -> dict[str, object]:
        return dict(normalized_metadata_items(self.metadata))

    def metadata_value(self, key: str, default: object = None) -> object:
        if type(key) is not str:
            raise TypeError("metadata key must be an exact str")
        return self.metadata_dict().get(key, default)


def replay_legacy_unflatten_shadow(plan: PatchPlan) -> LegacyShadowPlanView:
    """Validate and replay a plan's exact temporary shadow envelope."""

    if type(plan) is not PatchPlan:
        raise TypeError("legacy shadow replay requires an exact PatchPlan")
    if (
        type(plan.plan_id) is not str
        or type(plan.snapshot_id) is not str
        or type(plan.source_generation) is not int
    ):
        raise ValueError("owning PatchPlan identity/generation must be exact")
    shadow = plan.legacy_unflatten_shadow
    if type(shadow) is not LegacyUnflattenShadowEnvelope:
        raise ValueError("plan has no exact legacy shadow envelope")
    try:
        LegacyUnflattenShadowEnvelope.__post_init__(shadow)
    except Exception as exc:
        raise ValueError("legacy shadow envelope is invalid") from exc
    if type(shadow.schema_version) is not int:
        raise ValueError("legacy shadow schema_version must be exact")
    if type(shadow.plan_id) is not str or type(shadow.snapshot_id) is not str:
        raise ValueError("legacy shadow identifiers must be exact strings")
    if type(shadow.source_generation) is not int:
        raise ValueError("legacy shadow source_generation must be exact")
    if shadow.plan_id != plan.plan_id:
        raise ValueError("legacy shadow plan_id mismatch")
    if shadow.snapshot_id != plan.snapshot_id:
        raise ValueError("legacy shadow snapshot_id mismatch")
    if type(plan.source_generation) is not int or (
        shadow.source_generation != plan.source_generation
    ):
        raise ValueError("legacy shadow source_generation mismatch")

    ordinary = _metadata(plan.metadata)
    if any(key in LEGACY_RESERVED_KEYS for key, _value in ordinary):
        raise ValueError("legacy shadow plan retains reserved metadata")
    replayed: list[tuple[str, object]] = list(ordinary)
    for entry in shadow.entries:
        if (
            type(entry.key) is not str
            or type(entry.canonical_payload) is not bytes
            or type(entry.payload_sha256) is not str
        ):
            raise ValueError("legacy shadow entry fields must be exact")
        try:
            payload = entry.canonical_payload
            if hashlib.sha256(payload).hexdigest() != entry.payload_sha256:
                raise ValueError("legacy shadow payload digest mismatch")
            value = decode_legacy_canonical_payload(payload)
        except Exception as exc:
            raise ValueError("legacy shadow payload is invalid") from exc
        replayed.append((entry.key, value))
    return LegacyShadowPlanView(plan, tuple(replayed))


@dataclass(frozen=True, slots=True)
class LegacyUnflattenDecodeContext:
    plan_id: str
    source: FlowGraph
    source_generation: int
    block_refs_by_serial: tuple[
        tuple[int, NativeBlockRef | LogicalBlockRef], ...
    ]
    canonical_route_evidence: CanonicalSemanticEvidence | None

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

    # Family adapters are intentionally owned by later vertical tasks.
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
    "LegacyShadowPlanView",
    "LegacyUnflattenAbsent",
    "LegacyUnflattenDecoded",
    "LegacyUnflattenDecodeContext",
    "LegacyUnflattenDecodeResult",
    "LegacyUnflattenRejected",
    "capture_legacy_unflatten_shadow",
    "decode_legacy_canonical_payload",
    "decode_legacy_unflatten_contract",
    "legacy_canonical_bytes",
    "legacy_canonical_decode",
    "replay_legacy_unflatten_shadow",
]
