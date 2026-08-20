"""Persistent IDB const annotation for function-referenced global data items."""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import Enum
import json

import ida_funcs
import ida_hexrays
import ida_nalt
import ida_typeinf
import ida_xref
import idaapi
import idautils

from d810.analyses.value_flow.global_constness import (
    GlobalConstReason,
    GlobalItemConstDecision,
    GlobalItemConstEvidence,
    decide_global_item_const,
)
from d810.backends.hexrays.evidence.global_constness import (
    capture_hexrays_global_item_const_evidence,
    capture_hexrays_global_item_range_const_evidence,
)
from d810.backends.ida.type_serialization import (
    SerializedTinfoParts,
    capture_serialized_tinfo,
    serialize_tinfo,
)
from d810.capabilities.idb_preparation import (
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core import typing
from d810.core.logging import getLogger
from d810.core.persistence import Netnode

logger = getLogger("d810.backends.hexrays.global_const_annotation")

_PROPOSAL_NODE_NAME = "$ d810.global_const_proposals.v1"
_PROPOSAL_SCHEMA_VERSION = 1
_PROPOSAL_KEY_PREFIX = "proposal:v1:"
PENDING_PREPARATION_REASON = "next preparation round"
_SIZE_TO_BTF = {
    1: ida_typeinf.BTF_UINT8,
    2: ida_typeinf.BTF_UINT16,
    4: ida_typeinf.BTF_UINT32,
    8: ida_typeinf.BTF_UINT64,
}


class GlobalConstAnnotationStatus(str, Enum):
    QUEUED = "queued"
    ALREADY_QUEUED = "already_queued"
    CANCELLED = "cancelled"
    APPLIED = "applied"
    REMOVED = "removed"
    ALREADY_CONST = "already_const"
    OWNED_CONST = "owned_const"
    SKIPPED_POLICY = "skipped_policy"
    SKIPPED_NO_TYPE = "skipped_no_type"
    PRESERVED_USER_TYPE = "preserved_user_type"
    APPLY_FAILED = "apply_failed"


@dataclass(frozen=True, slots=True)
class ReferencedGlobalItem:
    evidence: GlobalItemConstEvidence
    decision: GlobalItemConstDecision
    source_eas: tuple[int, ...]
    referenced_eas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class DynamicGlobalTableAccess:
    """A bounded table footprint proven by architecture-neutral microcode."""

    item_head: int
    item_end: int
    element_size: int
    element_count: int
    instruction_ea: int


@dataclass(frozen=True, slots=True)
class GlobalConstAnnotationProposal:
    """Exact type change awaiting an explicit preparation transaction."""

    function_ea: int
    item_head: int
    item_end: int
    before: SerializedTypeSnapshot
    after: SerializedTypeSnapshot
    reason: GlobalConstReason

    @property
    def identity(self) -> tuple[object, ...]:
        """Stable durable identity used by preparation consumers.

        The proposal store is IDB-local, so the database identity is supplied
        by the owning journal/controller.  Within that scope, these fields are
        the exact queued before/after change and function attribution.
        """

        return (
            int(self.function_ea),
            int(self.item_head),
            int(self.item_end),
            self.before,
            self.after,
        )

    @property
    def type_delta(self) -> PreparationTypeDelta:
        return PreparationTypeDelta(self.item_head, self.before, self.after)


@dataclass(frozen=True, slots=True)
class GlobalConstAnnotationOutcome:
    item_head: int
    item_end: int
    status: GlobalConstAnnotationStatus
    reason: GlobalConstReason
    type_before: str | None = None
    type_after: str | None = None
    proposal: GlobalConstAnnotationProposal | None = None


@dataclass(frozen=True, slots=True)
class GlobalConstAnnotationReport:
    function_ea: int
    outcomes: tuple[GlobalConstAnnotationOutcome, ...]

    @property
    def applied_count(self) -> int:
        return sum(
            outcome.status is GlobalConstAnnotationStatus.APPLIED
            for outcome in self.outcomes
        )

    @property
    def queued_count(self) -> int:
        return sum(
            outcome.status is GlobalConstAnnotationStatus.QUEUED
            for outcome in self.outcomes
        )

    @property
    def queued_proposals(self) -> tuple[GlobalConstAnnotationProposal, ...]:
        """Return only newly queued exact proposals from this observation."""

        return tuple(
            outcome.proposal
            for outcome in self.outcomes
            if outcome.status is GlobalConstAnnotationStatus.QUEUED
            and outcome.proposal is not None
        )

    @property
    def proposal_candidates(self) -> tuple[GlobalConstAnnotationProposal, ...]:
        """Return every exact proposal represented by this report.

        ``queued_proposals`` is intentionally limited to newly queued work for
        the preparation status lane.  Observation deduplication also needs the
        canonical identity of an ``ALREADY_QUEUED`` proposal, so it consumes
        this complete outcome projection instead of reconstructing identity
        from a discovered access shape.
        """

        return tuple(
            outcome.proposal
            for outcome in self.outcomes
            if outcome.proposal is not None
        )

    @property
    def cancelled_count(self) -> int:
        return sum(
            outcome.status is GlobalConstAnnotationStatus.CANCELLED
            for outcome in self.outcomes
        )

    @property
    def removed_count(self) -> int:
        return sum(
            outcome.status is GlobalConstAnnotationStatus.REMOVED
            for outcome in self.outcomes
        )

    @property
    def changed_count(self) -> int:
        return (
            self.applied_count
            + self.removed_count
            + self.queued_count
            + self.cancelled_count
        )


def _mop_constant(mop: object) -> int | None:
    if mop is None or int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_n):
        return None
    try:
        return int(mop.nnn.value)
    except Exception:
        return None


def _bounded_unsigned_range(
    mop: object,
    *,
    depth: int = 0,
) -> tuple[int, int] | None:
    """Prove a small unsigned interval for the supported index expression."""

    if mop is None or depth > 12:
        return None
    constant = _mop_constant(mop)
    if constant is not None:
        return constant, constant
    if int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_d):
        return None
    instruction = getattr(mop, "d", None)
    if instruction is None:
        return None
    opcode = int(instruction.opcode)
    if opcode in {
        int(ida_hexrays.m_xdu),
        int(ida_hexrays.m_low),
    }:
        return _bounded_unsigned_range(instruction.l, depth=depth + 1)
    if opcode == int(ida_hexrays.m_and):
        left_constant = _mop_constant(instruction.l)
        right_constant = _mop_constant(instruction.r)
        mask = right_constant if right_constant is not None else left_constant
        if mask is None or mask < 0:
            return None
        return 0, mask
    if opcode not in {int(ida_hexrays.m_add), int(ida_hexrays.m_mul)}:
        return None
    left = _bounded_unsigned_range(instruction.l, depth=depth + 1)
    right = _bounded_unsigned_range(instruction.r, depth=depth + 1)
    if left is None or right is None:
        return None
    if opcode == int(ida_hexrays.m_add):
        return left[0] + right[0], left[1] + right[1]
    products = (
        left[0] * right[0],
        left[0] * right[1],
        left[1] * right[0],
        left[1] * right[1],
    )
    return min(products), max(products)


def _global_base(mop: object) -> int | None:
    if mop is None or int(getattr(mop, "t", -1)) != int(ida_hexrays.mop_a):
        return None
    inner = getattr(mop, "a", None)
    if inner is None:
        return None
    try:
        if int(getattr(inner, "t", -1)) == int(ida_hexrays.mop_v):
            return int(inner.g)
        if int(getattr(inner, "t", -1)) == int(ida_hexrays.mop_S):
            return int(inner.s.start_ea)
    except Exception:
        pass
    return None


def discover_dynamic_global_table_access(
    instruction: object,
) -> DynamicGlobalTableAccess | None:
    """Recover ``base + bounded_offset`` from one Hex-Rays ``ldx``."""

    if instruction is None or int(getattr(instruction, "opcode", -1)) != int(
        ida_hexrays.m_ldx
    ):
        return None
    address = getattr(instruction, "r", None)
    if address is None or int(getattr(address, "t", -1)) != int(ida_hexrays.mop_d):
        return None
    add = getattr(address, "d", None)
    if add is None or int(getattr(add, "opcode", -1)) != int(ida_hexrays.m_add):
        return None
    base = _global_base(add.l)
    offset_mop = add.r
    if base is None:
        base = _global_base(add.r)
        offset_mop = add.l
    if base is None:
        return None
    offset_range = _bounded_unsigned_range(offset_mop)
    if offset_range is None or offset_range[0] != 0:
        return None
    try:
        element_size = int(instruction.d.size)
    except Exception:
        return None
    if element_size not in _SIZE_TO_BTF:
        return None
    item_size = offset_range[1] + element_size
    if item_size <= element_size or item_size % element_size:
        return None
    element_count = item_size // element_size
    if element_count <= 1 or element_count > 1_000_000:
        return None
    return DynamicGlobalTableAccess(
        item_head=base,
        item_end=base + item_size,
        element_size=element_size,
        element_count=element_count,
        instruction_ea=int(getattr(instruction, "ea", 0) or 0),
    )


def referenced_global_items(function_ea: int) -> tuple[ReferencedGlobalItem, ...]:
    """Return canonical global data items referenced by one IDA function."""

    function = ida_funcs.get_func(int(function_ea))
    if function is None:
        return ()

    references: dict[int, tuple[GlobalItemConstEvidence, set[int], set[int]]] = {}
    badaddr = int(idaapi.BADADDR)
    for source_ea in idautils.FuncItems(int(function.start_ea)):
        referenced_ea = int(ida_xref.get_first_dref_from(int(source_ea)))
        while referenced_ea != badaddr:
            evidence = capture_hexrays_global_item_const_evidence(referenced_ea)
            if evidence.item_end > evidence.item_head:
                existing = references.get(evidence.item_head)
                if existing is None:
                    existing = (evidence, set(), set())
                    references[evidence.item_head] = existing
                existing[1].add(int(source_ea))
                existing[2].add(referenced_ea)
            referenced_ea = int(
                ida_xref.get_next_dref_from(int(source_ea), referenced_ea)
            )

    return tuple(
        ReferencedGlobalItem(
            evidence=evidence,
            decision=decide_global_item_const(evidence),
            source_eas=tuple(sorted(source_eas)),
            referenced_eas=tuple(sorted(referenced_eas)),
        )
        for evidence, source_eas, referenced_eas in (
            references[item_head] for item_head in sorted(references)
        )
    )


def _tinfo_for(item_head: int, item_size: int) -> ida_typeinf.tinfo_t | None:
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, int(item_head)) and not tif.empty():
        return tif
    btf = _SIZE_TO_BTF.get(int(item_size))
    if btf is None:
        return None
    tif.create_simple_type(btf)
    return tif


def _array_tinfo(element_size: int, element_count: int) -> ida_typeinf.tinfo_t:
    element = ida_typeinf.tinfo_t()
    element.create_simple_type(_SIZE_TO_BTF[int(element_size)])
    array = ida_typeinf.tinfo_t()
    if not array.create_array(element, int(element_count), 0):
        raise RuntimeError("unable to create bounded global table type")
    return array


def _type_rendering(tif: ida_typeinf.tinfo_t) -> str:
    try:
        return str(tif.dstr())
    except Exception:
        return str(tif)


def _snapshot_from_parts(
    parts: SerializedTinfoParts | None,
) -> SerializedTypeSnapshot:
    if parts is None:
        return SerializedTypeSnapshot.absent()
    return SerializedTypeSnapshot.from_parts(
        parts.type_bytes,
        parts.field_bytes,
        parts.field_comment_bytes,
    )


def _snapshot_from_tinfo(tif: ida_typeinf.tinfo_t) -> SerializedTypeSnapshot:
    return _snapshot_from_parts(serialize_tinfo(tif))


def _snapshot_payload(snapshot: SerializedTypeSnapshot) -> dict[str, typing.Any]:
    return {
        "present": snapshot.present,
        "type": None if snapshot.type_bytes is None else snapshot.type_bytes.hex(),
        "fields": None if snapshot.field_bytes is None else snapshot.field_bytes.hex(),
        "field_comments": (
            None
            if snapshot.field_comment_bytes is None
            else snapshot.field_comment_bytes.hex()
        ),
    }


def _snapshot_from_payload(payload: object) -> SerializedTypeSnapshot:
    if not isinstance(payload, dict):
        raise ValueError("serialized type snapshot payload must be a mapping")
    if not bool(payload.get("present")):
        return SerializedTypeSnapshot.absent()

    def _component(name: str, *, required: bool = False) -> bytes | None:
        value = payload.get(name)
        if value is None:
            if required:
                raise ValueError(f"missing proposal type component {name}")
            return None
        if not isinstance(value, str):
            raise ValueError(f"proposal type component {name} must be hex")
        return bytes.fromhex(value)

    type_bytes = _component("type", required=True)
    assert type_bytes is not None
    return SerializedTypeSnapshot.from_parts(
        type_bytes,
        _component("fields"),
        _component("field_comments"),
    )


def _proposal_payload(
    proposal: GlobalConstAnnotationProposal,
) -> dict[str, typing.Any]:
    return {
        "schema": _PROPOSAL_SCHEMA_VERSION,
        "function_ea": proposal.function_ea,
        "item_head": proposal.item_head,
        "item_end": proposal.item_end,
        "before": _snapshot_payload(proposal.before),
        "after": _snapshot_payload(proposal.after),
        "reason": proposal.reason.value,
    }


def _proposal_from_payload(payload: object) -> GlobalConstAnnotationProposal:
    if (
        not isinstance(payload, dict)
        or payload.get("schema") != _PROPOSAL_SCHEMA_VERSION
    ):
        raise ValueError("unsupported global const proposal payload")
    return GlobalConstAnnotationProposal(
        function_ea=int(payload["function_ea"]),
        item_head=int(payload["item_head"]),
        item_end=int(payload["item_end"]),
        before=_snapshot_from_payload(payload["before"]),
        after=_snapshot_from_payload(payload["after"]),
        reason=GlobalConstReason(str(payload["reason"])),
    )


def _proposal_store_key(
    proposal: GlobalConstAnnotationProposal,
    database_identity: str,
) -> str:
    """Build the durable key from the complete canonical proposal identity."""

    identity = {
        "database_identity": str(database_identity),
        "function_ea": int(proposal.function_ea),
        "item_head": int(proposal.item_head),
        "item_end": int(proposal.item_end),
        "before": _snapshot_payload(proposal.before),
        "after": _snapshot_payload(proposal.after),
    }
    return _PROPOSAL_KEY_PREFIX + json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    )


def _database_identity_from_key(key: object) -> str | None:
    if not isinstance(key, str) or not key.startswith(_PROPOSAL_KEY_PREFIX):
        return None
    try:
        payload = json.loads(key[len(_PROPOSAL_KEY_PREFIX) :])
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None
    identity = payload.get("database_identity")
    return identity if isinstance(identity, str) else None


def _delete_proposal(
    proposal_store: MutableMapping[int | str, typing.Any], key: int | str
) -> None:
    try:
        del proposal_store[key]
    except KeyError:
        pass


def _proposal_store_keys(
    store: MutableMapping[int | str, typing.Any],
) -> tuple[int | str, ...]:
    if hasattr(store, "iterkeys"):
        keys = tuple(store.iterkeys())
    else:
        keys = tuple(store.keys())
    return tuple(
        key
        for key in keys
        if isinstance(key, int)
        or (isinstance(key, str) and key.startswith(_PROPOSAL_KEY_PREFIX))
    )


def _iter_proposal_entries(
    store: MutableMapping[int | str, typing.Any],
) -> tuple[tuple[int | str, GlobalConstAnnotationProposal], ...]:
    entries: list[tuple[int | str, GlobalConstAnnotationProposal]] = []
    for key in _proposal_store_keys(store):
        payload = store.get(key)
        if payload is None:
            continue
        try:
            proposal = _proposal_from_payload(payload)
        except (KeyError, TypeError, ValueError):
            logger.warning("discarding malformed global const proposal at %r", key)
            _delete_proposal(store, key)
            continue
        entries.append((key, proposal))
    return tuple(entries)


def _database_matches_key(key: int | str, database_identity: str | None) -> bool:
    if database_identity is None:
        return True
    key_database_identity = _database_identity_from_key(key)
    # Integer keys predate database-scoped canonical keys.  Read them as
    # legacy entries while the IDB-local store is migrated by the next write.
    return key_database_identity is None or key_database_identity == database_identity


def _proposal_sort_key(proposal: GlobalConstAnnotationProposal) -> tuple[object, ...]:
    def snapshot_key(snapshot: SerializedTypeSnapshot) -> tuple[object, ...]:
        return (
            snapshot.present,
            snapshot.type_bytes or b"",
            snapshot.field_bytes or b"",
            snapshot.field_comment_bytes or b"",
        )

    return (
        int(proposal.function_ea),
        int(proposal.item_head),
        int(proposal.item_end),
        snapshot_key(proposal.before),
        snapshot_key(proposal.after),
    )


def _delete_matching_item_proposals(
    store: MutableMapping[int | str, typing.Any],
    *,
    database_identity: str,
    function_ea: int,
    item_head: int,
) -> bool:
    deleted = False
    for key, proposal in _iter_proposal_entries(store):
        if not _database_matches_key(key, database_identity):
            continue
        if (
            int(proposal.function_ea) == int(function_ea)
            and int(proposal.item_head) == int(item_head)
        ):
            _delete_proposal(store, key)
            deleted = True
    return deleted


def _queue_payload(
    store: MutableMapping[int | str, typing.Any],
    proposal: GlobalConstAnnotationProposal,
    *,
    database_identity: str,
) -> GlobalConstAnnotationStatus:
    payload = _proposal_payload(proposal)
    key = _proposal_store_key(proposal, database_identity)
    status = (
        GlobalConstAnnotationStatus.ALREADY_QUEUED
        if store.get(key) == payload
        else GlobalConstAnnotationStatus.QUEUED
    )
    # Migrate a matching pre-v1 integer entry without dropping a changed
    # proposal at the same item address.
    for legacy_key, existing in _iter_proposal_entries(store):
        if not isinstance(legacy_key, int):
            continue
        if existing.identity == proposal.identity:
            status = GlobalConstAnnotationStatus.ALREADY_QUEUED
            _delete_proposal(store, legacy_key)
    store[key] = payload
    return status


def pending_global_const_proposals(
    *,
    proposal_store: MutableMapping[int | str, typing.Any] | None = None,
    database_identity: str | None = None,
) -> tuple[GlobalConstAnnotationProposal, ...]:
    """Return the durable, deterministic proposal queue for this IDB."""

    store = Netnode(_PROPOSAL_NODE_NAME) if proposal_store is None else proposal_store
    entries = tuple(
        (key, proposal)
        for key, proposal in _iter_proposal_entries(store)
        if _database_matches_key(key, database_identity)
    )
    return tuple(
        proposal
        for _key, proposal in sorted(
            entries,
            key=lambda entry: (_proposal_sort_key(entry[1]), str(entry[0])),
        )
    )


def acknowledge_global_const_proposals(
    proposals: tuple[GlobalConstAnnotationProposal, ...],
    *,
    proposal_store: MutableMapping[int | str, typing.Any] | None = None,
    database_identity: str | None = None,
) -> None:
    """Remove only queue entries that still exactly match applied proposals."""

    store = Netnode(_PROPOSAL_NODE_NAME) if proposal_store is None else proposal_store
    entries = _iter_proposal_entries(store)
    for proposal in proposals:
        for key, existing in entries:
            if not _database_matches_key(key, database_identity):
                continue
            if existing.identity == proposal.identity:
                _delete_proposal(store, key)


def annotate_function_global_consts(
    function_ea: int,
    *,
    proposal_store: MutableMapping[int | str, typing.Any] | None = None,
    database_identity: str = "",
) -> GlobalConstAnnotationReport:
    """Queue exact const proposals without mutating IDB metadata in Hex-Rays."""

    store: MutableMapping[int | str, typing.Any]
    store = Netnode(_PROPOSAL_NODE_NAME) if proposal_store is None else proposal_store
    outcomes: list[GlobalConstAnnotationOutcome] = []

    for item in referenced_global_items(int(function_ea)):
        evidence = item.evidence
        item_head = int(evidence.item_head)
        item_size = int(evidence.item_end - evidence.item_head)
        tif = _tinfo_for(item_head, item_size)
        if tif is None:
            outcomes.append(
                GlobalConstAnnotationOutcome(
                    item_head=item_head,
                    item_end=evidence.item_end,
                    status=GlobalConstAnnotationStatus.SKIPPED_NO_TYPE,
                    reason=item.decision.reason,
                )
            )
            continue

        live_before = _snapshot_from_parts(capture_serialized_tinfo(item_head))
        before_rendering = None if not live_before.present else _type_rendering(tif)
        if not item.decision.can_persist_const:
            if _delete_matching_item_proposals(
                store,
                database_identity=database_identity,
                function_ea=int(function_ea),
                item_head=item_head,
            ):
                status = GlobalConstAnnotationStatus.CANCELLED
            else:
                status = (
                    GlobalConstAnnotationStatus.PRESERVED_USER_TYPE
                    if tif.is_const()
                    else GlobalConstAnnotationStatus.SKIPPED_POLICY
                )
            outcomes.append(
                GlobalConstAnnotationOutcome(
                    item_head=item_head,
                    item_end=evidence.item_end,
                    status=status,
                    reason=item.decision.reason,
                    type_before=before_rendering,
                    type_after=before_rendering,
                )
            )
            continue

        if tif.is_const():
            outcomes.append(
                GlobalConstAnnotationOutcome(
                    item_head=item_head,
                    item_end=evidence.item_end,
                    status=GlobalConstAnnotationStatus.ALREADY_CONST,
                    reason=item.decision.reason,
                    type_before=before_rendering,
                    type_after=before_rendering,
                )
            )
            continue

        updated = tif.copy()
        updated.set_const()
        after_rendering = _type_rendering(updated)
        proposal = GlobalConstAnnotationProposal(
            function_ea=int(function_ea),
            item_head=item_head,
            item_end=int(evidence.item_end),
            before=live_before,
            after=_snapshot_from_tinfo(updated),
            reason=item.decision.reason,
        )
        status = _queue_payload(
            store,
            proposal,
            database_identity=database_identity,
        )
        outcomes.append(
            GlobalConstAnnotationOutcome(
                item_head=item_head,
                item_end=evidence.item_end,
                status=status,
                reason=item.decision.reason,
                type_before=before_rendering,
                type_after=after_rendering,
                proposal=proposal,
            )
        )

    return GlobalConstAnnotationReport(
        function_ea=int(function_ea),
        outcomes=tuple(outcomes),
    )


def annotate_global_table_access(
    access: DynamicGlobalTableAccess,
    *,
    function_ea: int = 0,
    proposal_store: MutableMapping[int | str, typing.Any] | None = None,
    database_identity: str = "",
) -> GlobalConstAnnotationReport:
    """Queue const for one bounded table without writing inside Hex-Rays."""

    store: MutableMapping[int | str, typing.Any]
    store = Netnode(_PROPOSAL_NODE_NAME) if proposal_store is None else proposal_store
    evidence = capture_hexrays_global_item_range_const_evidence(
        access.item_head,
        access.item_end,
    )
    decision = decide_global_item_const(evidence)
    item_head = int(access.item_head)
    existing = ida_typeinf.tinfo_t()
    has_existing = bool(
        ida_nalt.get_tinfo(existing, item_head) and not existing.empty()
    )
    tif = (
        existing
        if has_existing
        else _array_tinfo(
            access.element_size,
            access.element_count,
        )
    )
    before_rendering = _type_rendering(tif) if has_existing else None
    live_before = _snapshot_from_parts(capture_serialized_tinfo(item_head))

    if has_existing:
        try:
            existing_size = int(tif.get_size())
        except Exception:
            existing_size = -1
        if existing_size != int(access.item_end - access.item_head):
            outcome = GlobalConstAnnotationOutcome(
                item_head=item_head,
                item_end=access.item_end,
                status=GlobalConstAnnotationStatus.PRESERVED_USER_TYPE,
                reason=decision.reason,
                type_before=before_rendering,
                type_after=before_rendering,
            )
            return GlobalConstAnnotationReport(int(function_ea), (outcome,))

    if not decision.can_persist_const:
        if _delete_matching_item_proposals(
            store,
            database_identity=database_identity,
            function_ea=int(function_ea),
            item_head=item_head,
        ):
            status = GlobalConstAnnotationStatus.CANCELLED
        else:
            status = (
                GlobalConstAnnotationStatus.PRESERVED_USER_TYPE
                if has_existing and tif.is_const()
                else GlobalConstAnnotationStatus.SKIPPED_POLICY
            )
        outcome = GlobalConstAnnotationOutcome(
            item_head=item_head,
            item_end=access.item_end,
            status=status,
            reason=decision.reason,
            type_before=before_rendering,
            type_after=before_rendering,
        )
        return GlobalConstAnnotationReport(int(function_ea), (outcome,))

    current_rendering = _type_rendering(tif)
    if tif.is_const():
        outcome = GlobalConstAnnotationOutcome(
            item_head=item_head,
            item_end=access.item_end,
            status=GlobalConstAnnotationStatus.ALREADY_CONST,
            reason=decision.reason,
            type_before=current_rendering,
            type_after=current_rendering,
        )
        return GlobalConstAnnotationReport(int(function_ea), (outcome,))

    updated = tif.copy()
    updated.set_const()
    after_rendering = _type_rendering(updated)
    proposal = GlobalConstAnnotationProposal(
        function_ea=int(function_ea),
        item_head=item_head,
        item_end=int(access.item_end),
        before=live_before,
        after=_snapshot_from_tinfo(updated),
        reason=decision.reason,
    )
    status = _queue_payload(
        store,
        proposal,
        database_identity=database_identity,
    )
    outcome = GlobalConstAnnotationOutcome(
        item_head=item_head,
        item_end=access.item_end,
        status=status,
        reason=decision.reason,
        type_before=before_rendering,
        type_after=after_rendering,
        proposal=proposal,
    )
    return GlobalConstAnnotationReport(int(function_ea), (outcome,))


__all__ = [
    "GlobalConstAnnotationProposal",
    "GlobalConstAnnotationOutcome",
    "GlobalConstAnnotationReport",
    "GlobalConstAnnotationStatus",
    "DynamicGlobalTableAccess",
    "PENDING_PREPARATION_REASON",
    "ReferencedGlobalItem",
    "acknowledge_global_const_proposals",
    "annotate_global_table_access",
    "annotate_function_global_consts",
    "discover_dynamic_global_table_access",
    "pending_global_const_proposals",
    "referenced_global_items",
]
