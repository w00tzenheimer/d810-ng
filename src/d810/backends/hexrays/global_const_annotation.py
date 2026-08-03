"""Persistent IDB const annotation for function-referenced global data items."""

from __future__ import annotations

from collections.abc import MutableMapping
from dataclasses import dataclass
from enum import Enum

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
from d810.core.logging import getLogger
from d810.core.persistence import Netnode
from d810.core.typing import Any

logger = getLogger("D810.backends.hexrays.global_const_annotation")

_RECEIPT_NODE_NAME = "$ d810.global_const_annotations.v1"
_RECEIPT_SCHEMA_VERSION = 1
_SIZE_TO_BTF = {
    1: ida_typeinf.BTF_UINT8,
    2: ida_typeinf.BTF_UINT16,
    4: ida_typeinf.BTF_UINT32,
    8: ida_typeinf.BTF_UINT64,
}


class GlobalConstAnnotationStatus(str, Enum):
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
class GlobalConstAnnotationOutcome:
    item_head: int
    item_end: int
    status: GlobalConstAnnotationStatus
    reason: GlobalConstReason
    type_before: str | None = None
    type_after: str | None = None


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
    def removed_count(self) -> int:
        return sum(
            outcome.status is GlobalConstAnnotationStatus.REMOVED
            for outcome in self.outcomes
        )

    @property
    def changed_count(self) -> int:
        return self.applied_count + self.removed_count


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


def _delete_receipt(receipt_store: MutableMapping[int, Any], item_head: int) -> None:
    try:
        del receipt_store[int(item_head)]
    except KeyError:
        pass


def _receipt_matches_current(receipt: object, current_type: str) -> bool:
    return (
        isinstance(receipt, dict)
        and receipt.get("schema") == _RECEIPT_SCHEMA_VERSION
        and receipt.get("applied_type") == current_type
    )


def annotate_function_global_consts(
    function_ea: int,
    *,
    receipt_store: MutableMapping[int, Any] | None = None,
) -> GlobalConstAnnotationReport:
    """Persist safe const qualifiers and repair only D810-owned stale ones."""

    store: MutableMapping[int, Any]
    store = Netnode(_RECEIPT_NODE_NAME) if receipt_store is None else receipt_store
    outcomes: list[GlobalConstAnnotationOutcome] = []

    for item in referenced_global_items(int(function_ea)):
        evidence = item.evidence
        item_head = int(evidence.item_head)
        item_size = int(evidence.item_end - evidence.item_head)
        tif = _tinfo_for(item_head, item_size)
        receipt = store.get(item_head)
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

        before = _type_rendering(tif)
        if not item.decision.can_persist_const:
            if receipt is not None and _receipt_matches_current(receipt, before):
                updated = tif.copy()
                updated.clr_const()
                after = _type_rendering(updated)
                if ida_typeinf.apply_tinfo(
                    item_head,
                    updated,
                    ida_typeinf.TINFO_DEFINITE,
                ):
                    _delete_receipt(store, item_head)
                    status = GlobalConstAnnotationStatus.REMOVED
                else:
                    status = GlobalConstAnnotationStatus.APPLY_FAILED
                outcomes.append(
                    GlobalConstAnnotationOutcome(
                        item_head=item_head,
                        item_end=evidence.item_end,
                        status=status,
                        reason=item.decision.reason,
                        type_before=before,
                        type_after=after
                        if status is GlobalConstAnnotationStatus.REMOVED
                        else before,
                    )
                )
                continue
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
                    type_before=before,
                    type_after=before,
                )
            )
            continue

        if tif.is_const():
            outcomes.append(
                GlobalConstAnnotationOutcome(
                    item_head=item_head,
                    item_end=evidence.item_end,
                    status=(
                        GlobalConstAnnotationStatus.OWNED_CONST
                        if receipt is not None
                        and _receipt_matches_current(receipt, before)
                        else GlobalConstAnnotationStatus.ALREADY_CONST
                    ),
                    reason=item.decision.reason,
                    type_before=before,
                    type_after=before,
                )
            )
            continue

        if receipt is not None:
            outcomes.append(
                GlobalConstAnnotationOutcome(
                    item_head=item_head,
                    item_end=evidence.item_end,
                    status=GlobalConstAnnotationStatus.PRESERVED_USER_TYPE,
                    reason=item.decision.reason,
                    type_before=before,
                    type_after=before,
                )
            )
            continue

        updated = tif.copy()
        updated.set_const()
        after = _type_rendering(updated)
        if ida_typeinf.apply_tinfo(
            item_head,
            updated,
            ida_typeinf.TINFO_DEFINITE,
        ):
            store[item_head] = {
                "schema": _RECEIPT_SCHEMA_VERSION,
                "item_head": item_head,
                "original_type": before,
                "applied_type": after,
            }
            status = GlobalConstAnnotationStatus.APPLIED
            logger.debug(
                "persistent global const applied at 0x%X for function 0x%X",
                item_head,
                int(function_ea),
            )
        else:
            status = GlobalConstAnnotationStatus.APPLY_FAILED
        outcomes.append(
            GlobalConstAnnotationOutcome(
                item_head=item_head,
                item_end=evidence.item_end,
                status=status,
                reason=item.decision.reason,
                type_before=before,
                type_after=after
                if status is GlobalConstAnnotationStatus.APPLIED
                else before,
            )
        )

    return GlobalConstAnnotationReport(
        function_ea=int(function_ea),
        outcomes=tuple(outcomes),
    )


def annotate_global_table_access(
    access: DynamicGlobalTableAccess,
    *,
    receipt_store: MutableMapping[int, Any] | None = None,
) -> GlobalConstAnnotationReport:
    """Persist const for one bounded dynamic table access."""

    store: MutableMapping[int, Any]
    store = Netnode(_RECEIPT_NODE_NAME) if receipt_store is None else receipt_store
    evidence = capture_hexrays_global_item_range_const_evidence(
        access.item_head,
        access.item_end,
    )
    decision = decide_global_item_const(evidence)
    item_head = int(access.item_head)
    receipt = store.get(item_head)
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
    before = _type_rendering(tif) if has_existing else None

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
                type_before=before,
                type_after=before,
            )
            return GlobalConstAnnotationReport(0, (outcome,))

    if not decision.can_persist_const:
        if (
            has_existing
            and before is not None
            and receipt is not None
            and _receipt_matches_current(receipt, before)
        ):
            updated = tif.copy()
            updated.clr_const()
            after = _type_rendering(updated)
            removed = bool(
                ida_typeinf.apply_tinfo(
                    item_head,
                    updated,
                    ida_typeinf.TINFO_DEFINITE,
                )
            )
            if removed:
                _delete_receipt(store, item_head)
            outcome = GlobalConstAnnotationOutcome(
                item_head=item_head,
                item_end=access.item_end,
                status=(
                    GlobalConstAnnotationStatus.REMOVED
                    if removed
                    else GlobalConstAnnotationStatus.APPLY_FAILED
                ),
                reason=decision.reason,
                type_before=before,
                type_after=after if removed else before,
            )
            return GlobalConstAnnotationReport(0, (outcome,))
        outcome = GlobalConstAnnotationOutcome(
            item_head=item_head,
            item_end=access.item_end,
            status=(
                GlobalConstAnnotationStatus.PRESERVED_USER_TYPE
                if has_existing and tif.is_const()
                else GlobalConstAnnotationStatus.SKIPPED_POLICY
            ),
            reason=decision.reason,
            type_before=before,
            type_after=before,
        )
        return GlobalConstAnnotationReport(0, (outcome,))

    current_rendering = _type_rendering(tif)
    if tif.is_const():
        status = (
            GlobalConstAnnotationStatus.OWNED_CONST
            if receipt is not None
            and _receipt_matches_current(receipt, current_rendering)
            else GlobalConstAnnotationStatus.ALREADY_CONST
        )
        outcome = GlobalConstAnnotationOutcome(
            item_head=item_head,
            item_end=access.item_end,
            status=status,
            reason=decision.reason,
            type_before=current_rendering,
            type_after=current_rendering,
        )
        return GlobalConstAnnotationReport(0, (outcome,))
    if receipt is not None:
        outcome = GlobalConstAnnotationOutcome(
            item_head=item_head,
            item_end=access.item_end,
            status=GlobalConstAnnotationStatus.PRESERVED_USER_TYPE,
            reason=decision.reason,
            type_before=current_rendering,
            type_after=current_rendering,
        )
        return GlobalConstAnnotationReport(0, (outcome,))

    updated = tif.copy()
    updated.set_const()
    after = _type_rendering(updated)
    applied = bool(
        ida_typeinf.apply_tinfo(
            item_head,
            updated,
            ida_typeinf.TINFO_DEFINITE,
        )
    )
    if applied:
        store[item_head] = {
            "schema": _RECEIPT_SCHEMA_VERSION,
            "item_head": item_head,
            "original_type": before,
            "applied_type": after,
            "item_end": int(access.item_end),
        }
    outcome = GlobalConstAnnotationOutcome(
        item_head=item_head,
        item_end=access.item_end,
        status=(
            GlobalConstAnnotationStatus.APPLIED
            if applied
            else GlobalConstAnnotationStatus.APPLY_FAILED
        ),
        reason=decision.reason,
        type_before=before,
        type_after=after if applied else before,
    )
    return GlobalConstAnnotationReport(0, (outcome,))


__all__ = [
    "GlobalConstAnnotationOutcome",
    "GlobalConstAnnotationReport",
    "GlobalConstAnnotationStatus",
    "DynamicGlobalTableAccess",
    "ReferencedGlobalItem",
    "annotate_global_table_access",
    "annotate_function_global_consts",
    "discover_dynamic_global_table_access",
    "referenced_global_items",
]
