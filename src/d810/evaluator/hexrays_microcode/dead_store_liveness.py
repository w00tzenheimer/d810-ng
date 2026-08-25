"""Exact, read-only GLBOPT2 liveness evidence for scalar dead stores."""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter

import ida_hexrays

from d810.core.logging import getLogger

from d810.analyses.value_flow.dead_store import (
    DeadStoreCandidate,
    DeadStoreEvidence,
    DeadStoreRejection,
    DeadStoreRejectionReason,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind
from d810.hexrays.ir.exact_data_flow import instruction_takes_stack_address

__all__ = ["HexRaysDeadStoreLivenessBackend"]

logger = getLogger(__name__)


@dataclass(frozen=True, slots=True)
class _LiveStorage:
    identity: StorageIdentity
    width: int


def _iter_instructions(block: object):
    instruction = getattr(block, "head", None)
    tail = getattr(block, "tail", None)
    while instruction is not None:
        yield instruction
        if instruction is tail:
            break
        instruction = getattr(instruction, "next", None)


def _live_storage(destination: object | None) -> _LiveStorage | None:
    if destination is None:
        return None
    try:
        operand_type = int(destination.t)
        width = int(destination.size)
    except (AttributeError, TypeError, ValueError):
        return None
    if width <= 0:
        return None
    if operand_type == int(ida_hexrays.mop_r):
        try:
            offset = int(destination.r)
        except (AttributeError, TypeError, ValueError):
            return None
        kind = StorageIdentityKind.REGISTER
    elif operand_type == int(ida_hexrays.mop_S):
        try:
            offset = int(destination.s.off)
        except (AttributeError, TypeError, ValueError):
            return None
        kind = StorageIdentityKind.STACK
    else:
        return None
    return _LiveStorage(StorageIdentity(kind, offset), width)


def _location_list(block: object, destination: object):
    """Let Hex-Rays map a direct destination into its native list coordinates."""
    location = ida_hexrays.mlist_t()
    block.append_def_list(
        location,
        destination,
        ida_hexrays.MUST_ACCESS,
    )
    return location


def _block_start_ea(block: object) -> int:
    try:
        return int(block.start)
    except (AttributeError, TypeError, ValueError):
        return -1


def _rejection(
    block: object,
    instruction: object | None,
    reason: DeadStoreRejectionReason,
    detail: str = "",
) -> DeadStoreRejection:
    return DeadStoreRejection(
        block_serial=int(getattr(block, "serial", 0) or 0),
        block_start_ea=max(0, _block_start_ea(block)),
        insn_ea=max(0, int(getattr(instruction, "ea", 0) or 0)),
        reason=reason,
        detail=detail,
    )


def _stack_alias_rejection(
    mba: object,
    location: object,
) -> DeadStoreRejectionReason | None:
    """Reject protected stack storage; exact accesses govern liveness.

    ``mba.aliased_memory`` is a deliberately broad may-alias universe and can
    cover ordinary locals whenever any frame address escapes.  It is not, by
    itself, evidence that this exact definition is observed.  Exact stack
    accesses are checked with native MUST-use/def lists, while explicit address
    escapes are vetoed separately by the shared exact-data-flow tracker.
    """
    nodel = getattr(mba, "nodel_memory", None)
    if nodel is None:
        return DeadStoreRejectionReason.ALIAS_INFORMATION_UNAVAILABLE
    try:
        if bool(nodel.has_common(location)):
            return DeadStoreRejectionReason.NODEL_STORAGE
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return DeadStoreRejectionReason.ALIAS_INFORMATION_UNAVAILABLE

    return None


def _access_lists(
    block: object,
    instruction: object,
    *,
    storage_kind: StorageIdentityKind,
):
    try:
        use_access = (
            ida_hexrays.MUST_ACCESS
            if storage_kind is StorageIdentityKind.STACK
            else ida_hexrays.MAY_ACCESS
        )
        use_list = block.build_use_list(instruction, use_access)
        must_def = block.build_def_list(instruction, ida_hexrays.MUST_ACCESS)
        may_def = (
            must_def
            if storage_kind is StorageIdentityKind.STACK
            else block.build_def_list(instruction, ida_hexrays.MAY_ACCESS)
        )
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return None
    return use_list, may_def, must_def


def _definition_outcome(
    mba: object,
    *,
    start_block: object,
    start_instruction: object,
    storage: _LiveStorage,
    location: object,
) -> tuple[DeadStoreRejectionReason | None, str]:
    """Prove every path kills or exits without reading this exact definition."""
    initial_accesses = _access_lists(
        start_block,
        start_instruction,
        storage_kind=storage.identity.kind,
    )
    if initial_accesses is None:
        return DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "definition_lists"
    initial_uses, _initial_may_def, initial_must_def = initial_accesses
    try:
        if bool(initial_uses.has_common(location)):
            return DeadStoreRejectionReason.REACHED_USE, "read_modify_write"
        if not bool(initial_must_def.includes(location)):
            return DeadStoreRejectionReason.PARTIAL_DEFINITION, "definition_not_full"
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "definition_membership"

    visiting: set[tuple[int, int]] = set()
    complete: dict[tuple[int, int], tuple[DeadStoreRejectionReason | None, str]] = {}

    def visit(block: object, first_instruction: object | None):
        serial = int(getattr(block, "serial", -1))
        key = (serial, id(first_instruction))
        if key in complete:
            return complete[key]
        if key in visiting:
            return DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "live_cycle"
        visiting.add(key)
        try:
            instruction = first_instruction
            while instruction is not None:
                accesses = _access_lists(
                    block,
                    instruction,
                    storage_kind=storage.identity.kind,
                )
                if accesses is None:
                    result = (
                        DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                        f"lists@0x{int(getattr(instruction, 'ea', 0)):x}",
                    )
                    complete[key] = result
                    return result
                uses, may_def, must_def = accesses
                try:
                    if bool(uses.has_common(location)):
                        result = (
                            DeadStoreRejectionReason.REACHED_USE,
                            f"blk{serial}@0x{int(getattr(instruction, 'ea', 0)):x}",
                        )
                        complete[key] = result
                        return result
                    if bool(must_def.includes(location)):
                        result = (None, "killed")
                        complete[key] = result
                        return result
                    if bool(may_def.has_common(location)):
                        result = (
                            DeadStoreRejectionReason.PARTIAL_DEFINITION,
                            f"blk{serial}@0x{int(getattr(instruction, 'ea', 0)):x}",
                        )
                        complete[key] = result
                        return result
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    result = (
                        DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                        "access_membership",
                    )
                    complete[key] = result
                    return result
                if instruction is getattr(block, "tail", None):
                    break
                instruction = getattr(instruction, "next", None)

            try:
                successor_count = int(block.nsucc())
            except (AttributeError, RuntimeError, TypeError, ValueError):
                result = (DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "successors")
                complete[key] = result
                return result
            if successor_count == 0:
                result = (
                    (None, "dead_at_exit")
                    if storage.identity.kind is StorageIdentityKind.STACK
                    else (DeadStoreRejectionReason.RETURN_CARRIER, "register_at_exit")
                )
                complete[key] = result
                return result
            for index in range(successor_count):
                try:
                    successor = mba.get_mblock(int(block.succ(index)))
                except (AttributeError, IndexError, RuntimeError, TypeError, ValueError):
                    result = (DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "successor")
                    complete[key] = result
                    return result
                if successor is None:
                    result = (DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "successor")
                    complete[key] = result
                    return result
                result = visit(successor, getattr(successor, "head", None))
                if result[0] is not None:
                    complete[key] = result
                    return result
            result = (None, "all_paths_dead")
            complete[key] = result
            return result
        finally:
            visiting.remove(key)

    return visit(start_block, getattr(start_instruction, "next", None))


class HexRaysDeadStoreLivenessBackend:
    """Collect exact scalar dead-store evidence from one live GLBOPT2 MBA."""

    def collect(self, mba: object) -> DeadStoreEvidence:
        maturity = int(getattr(mba, "maturity", -1))
        if maturity != int(ida_hexrays.MMAT_GLBOPT2):
            try:
                block = mba.get_mblock(0)
            except Exception:
                block = SimpleBlock()
            return DeadStoreEvidence(
                rejections=(
                    _rejection(
                        block,
                        None,
                        DeadStoreRejectionReason.WRONG_MATURITY,
                        str(maturity),
                    ),
                ),
                authoritative=True,
            )

        try:
            mba.build_graph()
        except (AttributeError, RuntimeError, TypeError, ValueError):
            return DeadStoreEvidence(
                authoritative=True,
                rejections=(
                    DeadStoreRejection(
                        block_serial=0,
                        block_start_ea=0,
                        insn_ea=0,
                        reason=DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                        detail="build_graph",
                    ),
                ),
            )

        address_escape_cache: dict[tuple[int, int], bool] = {}

        def stack_address_escapes(storage: _LiveStorage) -> bool:
            key = (storage.identity.offset, storage.width)
            cached = address_escape_cache.get(key)
            if cached is not None:
                return cached
            escaped = False
            for block_serial in range(int(getattr(mba, "qty", 0) or 0)):
                candidate_block = mba.get_mblock(block_serial)
                if candidate_block is None:
                    continue
                if any(
                    instruction_takes_stack_address(
                        candidate_instruction,
                        stack_offset=storage.identity.offset,
                        size=storage.width,
                    )
                    for candidate_instruction in _iter_instructions(candidate_block)
                ):
                    escaped = True
                    break
            address_escape_cache[key] = escaped
            return escaped

        candidates: list[DeadStoreCandidate] = []
        rejections: list[DeadStoreRejection] = []
        for serial in range(int(getattr(mba, "qty", 0) or 0)):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            try:
                block.make_lists_ready()
            except (AttributeError, RuntimeError, TypeError, ValueError):
                rejections.append(
                    _rejection(
                        block,
                        None,
                        DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                        "make_lists_ready",
                    )
                )
                continue
            instructions = tuple(_iter_instructions(block))
            ea_counts: dict[int, int] = {}
            for instruction in instructions:
                ea = int(getattr(instruction, "ea", -1))
                ea_counts[ea] = ea_counts.get(ea, 0) + 1
            for ordinal, instruction in enumerate(instructions):
                storage = _live_storage(getattr(instruction, "d", None))
                if storage is None:
                    continue
                ea = int(getattr(instruction, "ea", -1))
                if ea < 0 or ea_counts.get(ea, 0) != 1:
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.AMBIGUOUS_DEFINITION,
                        )
                    )
                    continue
                try:
                    effectful = bool(instruction.has_side_effects(False))
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    effectful = True
                if effectful:
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.EFFECTFUL_RHS,
                        )
                    )
                    continue
                try:
                    location = _location_list(block, getattr(instruction, "d", None))
                    location_empty = bool(location.empty())
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    location_empty = True
                    location = None
                if location_empty or location is None:
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                            "destination_location",
                        )
                    )
                    continue
                if storage.identity.kind is StorageIdentityKind.STACK:
                    alias_reason = _stack_alias_rejection(mba, location)
                    if alias_reason is not None:
                        rejections.append(
                            _rejection(block, instruction, alias_reason)
                        )
                        continue
                    if stack_address_escapes(storage):
                        rejections.append(
                            _rejection(
                                block,
                                instruction,
                                DeadStoreRejectionReason.ALIASED_STORAGE,
                                "exact_stack_address_escape",
                            )
                        )
                        continue
                reason, detail = _definition_outcome(
                    mba,
                    start_block=block,
                    start_instruction=instruction,
                    storage=storage,
                    location=location,
                )
                if reason is not None:
                    rejections.append(_rejection(block, instruction, reason, detail))
                    continue
                candidates.append(
                    DeadStoreCandidate(
                        block_serial=serial,
                        block_start_ea=_block_start_ea(block),
                        insn_ea=ea,
                        ordinal=ordinal,
                        opcode=int(getattr(instruction, "opcode", -1)),
                        destination=storage.identity,
                        destination_width=storage.width,
                    )
                )
        evidence = DeadStoreEvidence(
            candidates=tuple(candidates),
            rejections=tuple(rejections),
            authoritative=True,
        )
        reason_counts = Counter(
            rejection.reason.value for rejection in evidence.rejections
        )
        logger.info(
            "GLBOPT2 DSE evidence candidates=%d rejections=%d reasons=%s",
            len(evidence.candidates),
            len(evidence.rejections),
            dict(sorted(reason_counts.items())),
        )
        return evidence


class SimpleBlock:
    """Fallback coordinate used only when a wrong-maturity MBA has no block 0."""

    serial = 0
    start = 0
