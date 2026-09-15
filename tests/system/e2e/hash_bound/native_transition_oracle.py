"""Fail-closed bounded execution of exact native transition slices.

This is test support, not D810 recovery authority.  Callers must supply the
complete instruction slice and every concrete register or memory assumption.
Execution that leaves the slice, touches unmapped state, exceeds its budget, or
reaches no uniquely named target is unresolved.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import time


class NativeTransitionStatus(str, Enum):
    RESOLVED = "resolved"
    INFEASIBLE = "infeasible"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True, slots=True)
class NativeInstruction:
    ea: int
    data: bytes

    def __post_init__(self) -> None:
        if int(self.ea) < 0 or not self.data:
            raise ValueError("native instruction requires an EA and bytes")


@dataclass(frozen=True, slots=True)
class NativeTransitionRequest:
    instructions: tuple[NativeInstruction, ...]
    entry_ea: int
    target_partitions: tuple[tuple[str, tuple[int, ...]], ...]
    register_assumptions: tuple[tuple[str, int], ...]
    memory_assumptions: tuple[tuple[int, bytes], ...]
    instruction_budget: int
    target_observation_ea: int | None = None
    selector_observation: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class NativeTransitionReceipt:
    status: NativeTransitionStatus
    target: str | None
    reason: str
    instruction_eas: tuple[int, ...]
    wall_seconds: float
    request_fingerprint: str
    selector_value: int | None


@dataclass(frozen=True, slots=True)
class NativeImageSlice:
    """Exact linked-image evidence plus synthetic execution assumptions."""

    image_base: int
    request: NativeTransitionRequest
    linked_memory: tuple[tuple[int, bytes], ...]


@dataclass(frozen=True, slots=True)
class NativeCfgBlock:
    start_ea: int
    instruction_eas: tuple[int, ...]
    successor_eas: tuple[int, ...]
    selector_write_eas: tuple[int, ...]
    observable_effect_eas: tuple[int, ...]
    selector_live_in_write_eas: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class NativeSelectorRoute:
    source_ea: int
    state_write_ea: int
    dispatcher_entry_ea: int
    corridor_block_eas: tuple[int, ...]


def enumerate_selector_routes(
    blocks: tuple[NativeCfgBlock, ...],
    *,
    dispatcher_entries: tuple[int, ...],
) -> tuple[NativeSelectorRoute, ...]:
    """Enumerate effect-free native write-to-dispatcher corridors.

    A write-only join receives one route per native predecessor arm. A block
    that computes its selector locally before writing it remains one route,
    regardless of predecessor count. Observable effects in the source block
    remain executed when its terminator is rewritten; only effects in bypassed
    intermediate corridor blocks prevent certification.
    """

    by_start = {int(block.start_ea): block for block in blocks}
    if len(by_start) != len(blocks):
        raise ValueError("native CFG contains duplicate block starts")
    predecessors: dict[int, list[int]] = {start: [] for start in by_start}
    for block in blocks:
        for successor in block.successor_eas:
            if int(successor) in predecessors:
                predecessors[int(successor)].append(int(block.start_ea))
    dispatcher_set = {int(ea) for ea in dispatcher_entries}
    routes: list[NativeSelectorRoute] = []
    for write_block in blocks:
        for state_write_ea in write_block.selector_write_eas:
            corridor = [int(write_block.start_ea)]
            current = write_block
            seen = {int(write_block.start_ea)}
            dispatcher_entry: int | None = None
            valid = True
            while dispatcher_entry is None:
                successors = tuple(int(ea) for ea in current.successor_eas)
                if len(successors) != 1:
                    valid = False
                    break
                successor = successors[0]
                if successor in dispatcher_set:
                    dispatcher_entry = successor
                    break
                if successor in seen or successor not in by_start:
                    valid = False
                    break
                current = by_start[successor]
                if current.observable_effect_eas or current.selector_write_eas:
                    valid = False
                    break
                corridor.append(successor)
                seen.add(successor)
            if not valid or dispatcher_entry is None:
                continue
            incoming = tuple(sorted(predecessors[int(write_block.start_ea)]))
            write_depends_on_predecessor = int(state_write_ea) in {
                int(ea) for ea in write_block.selector_live_in_write_eas
            }
            sources = (
                incoming
                if write_depends_on_predecessor and len(incoming) > 1
                else (int(write_block.start_ea),)
            )
            routes.extend(
                NativeSelectorRoute(
                    source_ea=source,
                    state_write_ea=int(state_write_ea),
                    dispatcher_entry_ea=dispatcher_entry,
                    corridor_block_eas=tuple(corridor),
                )
                for source in sources
            )
    return tuple(
        sorted(
            routes,
            key=lambda route: (
                route.state_write_ea,
                route.source_ea,
                route.dispatcher_entry_ea,
            ),
        )
    )


def _request_fingerprint(request: NativeTransitionRequest) -> str:
    payload = {
        "entry_ea": hex(int(request.entry_ea)),
        "instruction_budget": int(request.instruction_budget),
        "instructions": [
            [hex(int(instruction.ea)), instruction.data.hex()]
            for instruction in request.instructions
        ],
        "memory_assumptions": [
            [hex(int(ea)), bytes(data).hex()] for ea, data in request.memory_assumptions
        ],
        "register_assumptions": [
            [str(name).lower(), hex(int(value))]
            for name, value in request.register_assumptions
        ],
        "target_partitions": [
            [str(name), [hex(int(ea)) for ea in eas]]
            for name, eas in request.target_partitions
        ],
        "target_observation_ea": (
            None
            if request.target_observation_ea is None
            else hex(int(request.target_observation_ea))
        ),
        "selector_observation": (
            None
            if request.selector_observation is None
            else [
                hex(int(request.selector_observation[0])),
                int(request.selector_observation[1]),
            ]
        ),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(encoded.encode("ascii")).hexdigest()


def _register_id(name: str) -> int:
    from unicorn import x86_const

    attribute = "UC_X86_REG_" + str(name).upper()
    try:
        return int(getattr(x86_const, attribute))
    except AttributeError as exc:
        raise ValueError(f"unsupported register assumption: {name}") from exc


def _page(ea: int) -> int:
    return int(ea) & ~0xFFF


def prove_native_transition(
    request: NativeTransitionRequest,
) -> NativeTransitionReceipt:
    started_at = time.monotonic()
    fingerprint = _request_fingerprint(request)
    executed: list[int] = []

    def receipt(
        status: NativeTransitionStatus,
        *,
        target: str | None = None,
        reason: str = "",
        selector_value: int | None = None,
    ) -> NativeTransitionReceipt:
        return NativeTransitionReceipt(
            status=status,
            target=target,
            reason=reason,
            instruction_eas=tuple(executed),
            wall_seconds=time.monotonic() - started_at,
            request_fingerprint=fingerprint,
            selector_value=selector_value,
        )

    if request.instruction_budget <= 0:
        return receipt(
            NativeTransitionStatus.UNRESOLVED,
            reason="invalid_instruction_budget",
        )
    instructions = {int(item.ea): item for item in request.instructions}
    if len(instructions) != len(request.instructions):
        return receipt(
            NativeTransitionStatus.UNRESOLVED,
            reason="duplicate_instruction_ea",
        )
    if int(request.entry_ea) not in instructions:
        return receipt(
            NativeTransitionStatus.UNRESOLVED,
            reason="entry_not_in_slice",
        )
    if (
        request.target_observation_ea is not None
        and int(request.target_observation_ea) not in instructions
    ):
        return receipt(
            NativeTransitionStatus.UNRESOLVED,
            reason="target_observation_not_in_slice",
        )
    if request.selector_observation is not None:
        selector_ea, selector_width = request.selector_observation
        if int(selector_width) not in {1, 2, 4, 8} or int(selector_ea) < 0:
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason="invalid_selector_observation",
            )

    targets: dict[int, str] = {}
    for name, eas in request.target_partitions:
        if not name or not eas:
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason="empty_target_partition",
            )
        for ea in eas:
            normalized = int(ea)
            if normalized in targets:
                return receipt(
                    NativeTransitionStatus.UNRESOLVED,
                    reason="target_partitions_overlap",
                )
            targets[normalized] = str(name)

    try:
        from unicorn import (
            UC_ARCH_X86,
            UC_HOOK_CODE,
            UC_HOOK_MEM_INVALID,
            UC_MEM_FETCH_PROT,
            UC_MEM_FETCH_UNMAPPED,
            UC_MEM_READ_PROT,
            UC_MEM_READ_UNMAPPED,
            UC_MEM_WRITE_PROT,
            UC_MEM_WRITE_UNMAPPED,
            UC_MODE_64,
            Uc,
            UcError,
        )
    except ImportError:
        return receipt(
            NativeTransitionStatus.UNRESOLVED,
            reason="unicorn_unavailable",
        )

    emulator = Uc(UC_ARCH_X86, UC_MODE_64)
    pages = {_page(item.ea) for item in request.instructions} | {
        page
        for ea in targets
        # Unicorn may translate beyond a named target before its code hook runs.
        # Map one successor page as decode padding, but never populate it with
        # executable evidence. The hook still resolves only the exact target
        # and rejects every other address before executing it.
        for page in (_page(ea), _page(ea) + 0x1000)
    }
    for ea, data in request.memory_assumptions:
        if not data:
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason="empty_memory_assumption",
            )
        first = _page(ea)
        last = _page(int(ea) + len(data) - 1)
        pages.update(range(first, last + 0x1000, 0x1000))
    for page in sorted(pages):
        emulator.mem_map(page, 0x1000)
    for instruction in request.instructions:
        emulator.mem_write(int(instruction.ea), instruction.data)
    for ea, data in request.memory_assumptions:
        emulator.mem_write(int(ea), bytes(data))
    try:
        for name, value in request.register_assumptions:
            emulator.reg_write(_register_id(name), int(value))
    except ValueError as exc:
        return receipt(NativeTransitionStatus.UNRESOLVED, reason=str(exc))

    outcome: list[tuple[str, str | None]] = []
    target_armed = request.target_observation_ea is None
    arm_after_current = False

    def on_instruction(uc, address: int, _size: int, _user_data) -> None:
        nonlocal arm_after_current, target_armed
        if arm_after_current:
            target_armed = True
            arm_after_current = False
        target = targets.get(int(address))
        # A handler source may itself be the destination of a different route.
        # It becomes an observed destination only after this request has
        # executed at least one instruction and re-entered/reached it.
        if target is not None and target_armed and executed:
            outcome.append(("resolved", target))
            uc.emu_stop()
            return
        if int(address) not in instructions:
            outcome.append(("outside", None))
            uc.emu_stop()
            return
        if len(executed) >= int(request.instruction_budget):
            outcome.append(("budget", None))
            uc.emu_stop()
            return
        executed.append(int(address))
        if request.target_observation_ea is not None and int(address) == int(
            request.target_observation_ea
        ):
            arm_after_current = True

    emulator.hook_add(UC_HOOK_CODE, on_instruction)

    memory_error_names = {
        UC_MEM_FETCH_PROT: "protected_memory_fetch",
        UC_MEM_FETCH_UNMAPPED: "unmapped_memory_fetch",
        UC_MEM_READ_PROT: "protected_memory_read",
        UC_MEM_READ_UNMAPPED: "unmapped_memory_read",
        UC_MEM_WRITE_PROT: "protected_memory_write",
        UC_MEM_WRITE_UNMAPPED: "unmapped_memory_write",
    }

    def on_invalid_memory(
        _uc, access: int, address: int, _size: int, _value: int, _user_data
    ) -> bool:
        kind = memory_error_names.get(int(access), f"invalid_memory_access_{access}")
        outcome.append(("memory", f"{kind}:0x{int(address):X}"))
        return False

    emulator.hook_add(UC_HOOK_MEM_INVALID, on_invalid_memory)
    try:
        emulator.emu_start(int(request.entry_ea), max(pages) + 0x1000)
    except UcError as exc:
        if not outcome:
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason=f"unicorn_error:{exc.errno}",
            )

    if outcome:
        kind, target = outcome[-1]
        if kind == "resolved":
            selector_value = None
            if request.selector_observation is not None:
                selector_ea, selector_width = request.selector_observation
                try:
                    selector_value = int.from_bytes(
                        emulator.mem_read(int(selector_ea), int(selector_width)),
                        "little",
                    )
                except UcError:
                    return receipt(
                        NativeTransitionStatus.UNRESOLVED,
                        reason="selector_observation_unreadable",
                    )
            return receipt(
                NativeTransitionStatus.RESOLVED,
                target=target,
                selector_value=selector_value,
            )
        if kind == "outside":
            address = int(emulator.reg_read(_register_id("rip")))
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason=f"instruction_not_in_slice:0x{address:X}",
            )
        if kind == "budget":
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason="instruction_budget_exhausted",
            )
        if kind == "memory":
            return receipt(
                NativeTransitionStatus.UNRESOLVED,
                reason=str(target),
            )
    return receipt(
        NativeTransitionStatus.UNRESOLVED,
        reason="no_target_reached",
    )


def prove_linked_native_transition(
    image_slice: NativeImageSlice,
    *,
    read_linked_bytes: Callable[[int, int], bytes | None],
) -> NativeTransitionReceipt:
    """Verify exact image evidence before executing one bounded slice."""

    request = image_slice.request
    fingerprint = _request_fingerprint(request)

    def mismatch(reason: str) -> NativeTransitionReceipt:
        return NativeTransitionReceipt(
            status=NativeTransitionStatus.UNRESOLVED,
            target=None,
            reason=reason,
            instruction_eas=(),
            wall_seconds=0.0,
            request_fingerprint=fingerprint,
            selector_value=None,
        )

    for instruction in request.instructions:
        observed = read_linked_bytes(int(instruction.ea), len(instruction.data))
        if observed != instruction.data:
            return mismatch(
                f"linked_instruction_bytes_mismatch:0x{int(instruction.ea):X}"
            )
    for ea, expected in image_slice.linked_memory:
        observed = read_linked_bytes(int(ea), len(expected))
        if observed != expected:
            return mismatch(f"linked_memory_bytes_mismatch:0x{int(ea):X}")

    executable_request = replace(
        request,
        memory_assumptions=(
            *tuple((int(ea), bytes(data)) for ea, data in image_slice.linked_memory),
            *request.memory_assumptions,
        ),
    )
    return prove_native_transition(executable_request)


__all__ = [
    "NativeCfgBlock",
    "NativeImageSlice",
    "NativeInstruction",
    "NativeSelectorRoute",
    "NativeTransitionReceipt",
    "NativeTransitionRequest",
    "NativeTransitionStatus",
    "enumerate_selector_routes",
    "prove_linked_native_transition",
    "prove_native_transition",
]
