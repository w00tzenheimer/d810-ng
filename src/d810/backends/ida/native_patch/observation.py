"""Read-only pre-lift observation of native normalization candidates.

Task 0.3 of ``_gitless/REVERSIBLE-NATIVE-PATCHES.md``. This is the first thing in
the plan that produces native-normalization evidence, and it produces it without
any of the machinery the rest of the plan is still arguing about: no journal, no
gateway, no certificate. It proposes; it never writes and never requests a redo.

It is also how the work gets sized honestly. The receipts say how many functions
in a real sample would actually be lowerable under Mode A, before a gateway
exists to lower them.

**Why this lives under ``d810.backends.ida`` and not in
``d810.hexrays.preanalysis`` as the plan's file map proposed.** The handler needs
the branch encoder to decide whether a candidate is representable, the encoder
lives in ``d810.backends``, and the layered-architecture contract places
``d810.backends`` *above* ``d810.hexrays`` -- so a handler in ``hexrays``
importing the encoder is an upward import. Sitting beside the encoder instead
makes the dependency on the seam registry downward, which the contract allows.

**Opt-in is explicit and per function.** Nothing is observed unless the function
is registered, so installing this handler on a live database costs one set lookup
per decompilation and produces no receipts by default.
"""

from __future__ import annotations

from dataclasses import dataclass

import ida_bytes
import ida_funcs
import ida_ua
import ida_xref
import idaapi

from d810.backends.ida.native_patch.encoder import (
    AbstentionReason,
    plan_direct_jump_region,
)
from d810.core.logging import getLogger
from d810.hexrays.preanalysis.flowchart_preanalysis import (
    register_flowchart_preanalysis_handler,
    unregister_flowchart_preanalysis_handler,
)

logger = getLogger("d810.backends.ida.native_patch.observation")

__all__ = [
    "BranchObservation",
    "FunctionObservation",
    "HANDLER_NAME",
    "clear_observation_optins",
    "install_native_observation",
    "observe_function",
    "opt_in_function",
    "uninstall_native_observation",
]

HANDLER_NAME = "native_patch.observation"

_OPTED_IN: set[int] = set()


def opt_in_function(function_ea: int) -> None:
    """Mark one function as eligible for observation."""
    _OPTED_IN.add(int(function_ea))


def clear_observation_optins() -> None:
    _OPTED_IN.clear()


@dataclass(frozen=True, slots=True)
class BranchObservation:
    """One conditional branch and what a Mode A lowering would do to it."""

    site_ea: int
    size: int
    mnemonic: str
    taken_target: int
    fallthrough: int
    current_bytes: bytes
    proposed_bytes: bytes | None
    abstention: str | None
    has_interior_incoming_ref: bool
    fully_loaded: bool

    @property
    def lowerable(self) -> bool:
        """Representable *and* free of the preconditions that forbid a rewrite.

        Encodability is necessary but not sufficient: a branch into the region's
        interior means the bytes after the new instruction are still a jump
        target, and an unloaded byte can never be authorized.
        """
        return (
            self.proposed_bytes is not None
            and self.abstention is None
            and not self.has_interior_incoming_ref
            and self.fully_loaded
        )


@dataclass(frozen=True, slots=True)
class FunctionObservation:
    function_ea: int
    start_ea: int
    end_ea: int
    branches: tuple[BranchObservation, ...]

    @property
    def lowerable_count(self) -> int:
        return sum(1 for branch in self.branches if branch.lowerable)

    @property
    def abstained_count(self) -> int:
        return sum(1 for branch in self.branches if not branch.lowerable)

    def describe(self) -> str:
        return (
            f"fn={self.function_ea:#x} branches={len(self.branches)} "
            f"lowerable={self.lowerable_count} abstained={self.abstained_count}"
        )


def _has_interior_incoming_ref(start_ea: int, end_ea: int) -> bool:
    """Whether anything branches *into* the region rather than to its head.

    Mirrors the precondition retired-reference checks before overwriting a dispatcher
    tail. IDA's xrefs are evidence rather than proof of complete incoming-edge
    knowledge, so a False here is a reason not to abstain, never a licence.
    """
    for ea in range(start_ea + 1, end_ea):
        xref = ida_xref.xrefblk_t()
        ok = xref.first_to(ea, ida_xref.XREF_ALL)
        while ok:
            if xref.iscode:
                return True
            ok = xref.next_to()
    return False


def _fully_loaded(start_ea: int, end_ea: int) -> bool:
    return all(ida_bytes.is_loaded(ea) for ea in range(start_ea, end_ea))


def _is_conditional_branch(insn, mnemonic: str | None) -> bool:
    """Whether this decodes as a conditional near branch.

    ``print_insn_mnem`` returns None for bytes that decoded but are not a
    recognised instruction head -- data embedded in a function range, which
    obfuscated code produces routinely even though clean compiler output does
    not.
    """
    if not mnemonic:
        return False
    return (
        mnemonic.startswith("j")
        and mnemonic != "jmp"
        and insn.Op1.type == idaapi.o_near
    )


def observe_function(function_ea: int) -> FunctionObservation | None:
    """Decode ``function_ea`` and report Mode A candidates. Reads only."""
    func = ida_funcs.get_func(int(function_ea))
    if func is None:
        return None

    branches: list[BranchObservation] = []
    insn = ida_ua.insn_t()
    cursor = func.start_ea
    while cursor < func.end_ea:
        length = ida_ua.decode_insn(insn, cursor)
        if length <= 0:
            cursor += 1
            continue
        mnemonic = ida_ua.print_insn_mnem(cursor)
        if not _is_conditional_branch(insn, mnemonic):
            cursor += length
            continue

        taken = int(insn.Op1.addr)
        end_ea = cursor + length
        current = ida_bytes.get_bytes(cursor, length) or b""

        outcome = plan_direct_jump_region(cursor, end_ea, taken)
        proposed = outcome.sequence.data if outcome.ok else None
        abstention = None if outcome.ok else _reason_name(outcome.reason)

        branches.append(
            BranchObservation(
                site_ea=cursor,
                size=length,
                mnemonic=mnemonic,
                taken_target=taken,
                fallthrough=end_ea,
                current_bytes=current,
                proposed_bytes=proposed,
                abstention=abstention,
                has_interior_incoming_ref=_has_interior_incoming_ref(cursor, end_ea),
                fully_loaded=_fully_loaded(cursor, end_ea),
            )
        )
        cursor += length

    return FunctionObservation(
        function_ea=int(function_ea),
        start_ea=int(func.start_ea),
        end_ea=int(func.end_ea),
        branches=tuple(branches),
    )


def _reason_name(reason: AbstentionReason | None) -> str:
    return reason.value if reason is not None else "UNKNOWN"


def on_flowchart_preanalysis(*, function_ea: int, mba: object, decision, **_kw) -> None:
    """Flowchart-seam handler. Read-only by construction.

    Never sets ``request_redo``: an observation that forced a rebuild would make
    the measurement it is taking part of the thing being measured.
    """
    if int(function_ea) not in _OPTED_IN:
        return
    observation = observe_function(int(function_ea))
    if observation is None:
        decision["abstained"] = True
        decision["abstention_reason"] = "NO_FUNCTION_AT_EA"
        return
    decision["observation_receipt"] = observation
    decision["proposals"] = tuple(
        branch for branch in observation.branches if branch.lowerable
    )
    logger.debug("native observation: %s", observation.describe())


def install_native_observation() -> None:
    register_flowchart_preanalysis_handler(
        HANDLER_NAME, on_flowchart_preanalysis, read_only=True
    )


def uninstall_native_observation() -> None:
    unregister_flowchart_preanalysis_handler(HANDLER_NAME)
