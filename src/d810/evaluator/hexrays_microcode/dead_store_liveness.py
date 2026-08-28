"""Exact, read-only GLBOPT2 liveness evidence for scalar dead stores."""

from __future__ import annotations

from dataclasses import dataclass
from collections import Counter

import ida_hexrays

from d810.core.logging import getLogger
from d810.analyses.data_flow.exceptions import FixpointDidNotConverge

from d810.analyses.value_flow.dead_store import (
    DeadStoreCandidate,
    DeadStoreEvidence,
    DeadStoreRejection,
    DeadStoreRejectionReason,
)
from d810.analyses.value_flow.instruction_value_flow import (
    InstructionValueFlowResult,
    analyze_instruction_value_flow,
)
from d810.ir.locations import RegisterLocation, StackSlot, StorageLocation
from d810.ir.value_refs import DefinitionRef, InstructionUseKind
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


def _portable_location(storage: _LiveStorage) -> StorageLocation:
    if storage.identity.kind is StorageIdentityKind.REGISTER:
        return RegisterLocation(
            register_id=int(storage.identity.offset),
            size=int(storage.width),
        )
    return StackSlot(
        offset=int(storage.identity.offset),
        size=int(storage.width),
    )


def _same_native_location(left: object, right: object) -> bool:
    """Require two live destination mappings to denote the same exact bytes."""
    try:
        return bool(left.includes(right)) and bool(right.includes(left))
    except (AttributeError, RuntimeError, TypeError, ValueError):
        return False


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


def _retained_definition_reason(
    instruction_flow: object,
    value_flow: InstructionValueFlowResult,
    definition: DefinitionRef,
) -> tuple[DeadStoreRejectionReason, str]:
    uses = value_flow.def_use.uses_of(definition)
    if uses:
        use = uses[0]
        coordinate = instruction_flow.coordinate(use.insn)
        reason = (
            DeadStoreRejectionReason.PARTIAL_DEFINITION
            if any(item.kind is InstructionUseKind.PARTIAL_DEFINITION for item in uses)
            else DeadStoreRejectionReason.REACHED_USE
        )
        return (
            reason,
            f"blk{coordinate.block_serial}@0x{coordinate.insn_ea:x}",
        )
    if isinstance(definition.location, RegisterLocation):
        return DeadStoreRejectionReason.RETURN_CARRIER, "register_at_exit"
    return DeadStoreRejectionReason.CHAIN_UNAVAILABLE, "live_cycle"


class HexRaysDeadStoreLivenessBackend:
    """Collect exact scalar dead-store evidence from one live GLBOPT2 MBA."""

    def __init__(self, instruction_flow_builder) -> None:
        self._instruction_flow_builder = instruction_flow_builder

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

        tracked_locations: list[StorageLocation] = []
        native_locations: dict[StorageLocation, object] = {}
        unavailable_locations: set[StorageLocation] = set()
        for serial in range(int(getattr(mba, "qty", 0) or 0)):
            block = mba.get_mblock(serial)
            if block is None:
                continue
            for instruction in _iter_instructions(block):
                storage = _live_storage(getattr(instruction, "d", None))
                if storage is None:
                    continue
                location = _portable_location(storage)
                if location not in tracked_locations:
                    tracked_locations.append(location)
                try:
                    native_location = _location_list(
                        block, getattr(instruction, "d", None)
                    )
                    if bool(native_location.empty()):
                        unavailable_locations.add(location)
                    elif location not in native_locations:
                        native_locations[location] = native_location
                    elif not _same_native_location(
                        native_locations[location], native_location
                    ):
                        unavailable_locations.add(location)
                except (AttributeError, RuntimeError, TypeError, ValueError):
                    unavailable_locations.add(location)
        if not tracked_locations:
            return DeadStoreEvidence(authoritative=True)

        for location in unavailable_locations:
            native_locations.pop(location, None)
        analyzable_locations = tuple(
            location
            for location in tracked_locations
            if location not in unavailable_locations
        )

        try:
            instruction_flow = self._instruction_flow_builder(
                mba,
                analyzable_locations,
                native_locations=native_locations,
            )
            value_flow = analyze_instruction_value_flow(
                instruction_flow.graph,
                live_at_exit=frozenset(
                    location
                    for location in analyzable_locations
                    if isinstance(location, RegisterLocation)
                ),
            )
        except (FixpointDidNotConverge, RuntimeError, ValueError) as exc:
            return DeadStoreEvidence(
                authoritative=True,
                rejections=(
                    DeadStoreRejection(
                        block_serial=0,
                        block_start_ea=0,
                        insn_ea=0,
                        reason=DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                        detail=f"instruction_value_flow:{exc}",
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
                portable_location = _portable_location(storage)
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
                        rejections.append(_rejection(block, instruction, alias_reason))
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
                if portable_location in unavailable_locations:
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                            "destination_location_consensus",
                        )
                    )
                    continue
                try:
                    handle = instruction_flow.handle_for(serial, ordinal)
                    access = instruction_flow.graph.facts_by_node[handle]
                except (KeyError, TypeError, ValueError):
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.CHAIN_UNAVAILABLE,
                            "instruction_coordinate",
                        )
                    )
                    continue
                if portable_location in access.uses:
                    rejections.append(
                        _rejection(
                            block,
                            instruction,
                            DeadStoreRejectionReason.REACHED_USE,
                            "read_modify_write",
                        )
                    )
                    continue
                if portable_location not in access.must_defs:
                    reason = (
                        DeadStoreRejectionReason.PARTIAL_DEFINITION
                        if portable_location in access.may_defs
                        else DeadStoreRejectionReason.CHAIN_UNAVAILABLE
                    )
                    detail = (
                        "definition_not_full"
                        if reason is DeadStoreRejectionReason.PARTIAL_DEFINITION
                        else "definition_membership"
                    )
                    rejections.append(_rejection(block, instruction, reason, detail))
                    continue
                definition = DefinitionRef(
                    location=portable_location,
                    version=int(handle),
                )
                if not value_flow.is_definition_dead(definition):
                    reason, detail = _retained_definition_reason(
                        instruction_flow,
                        value_flow,
                        definition,
                    )
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
