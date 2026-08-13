"""Stage A dead-edge oracle: branch-direction proof for the native patch pipeline.

Closes the P0 gap recorded in ``_gitless/REVERSIBLE-NATIVE-PATCHES.md``
("MEASURED -- 'encodable' is not 'safe'"): the read-only observer
(``d810.backends.ida.native_patch.observation``) proposes Mode A candidates by
*representability* only, and representability says nothing about which way a
branch actually resolves. Measured counterexample: on ``libobfuscated.dll``
``single_iteration_simple`` at ``0x1800113b1``, the observer's own proposal
(``jnz`` -> unconditional ``jmp`` to the taken target) turns
``for (i=4660; i==4660; i=22136) a1 += 10; return a1;`` into ``return a1;`` --
the ``+10`` is lost, and every preflight invariant still passes.

Two things were missing (report section 5); this module builds the second:

1. ``EdgeStateContract`` -- eliminating a live definition. Deferred, not here.
2. **Branch-direction proof.** *This module.* Even a pure control-transfer
   swap that destroys no definition is wrong if the direction is unproven.

What this module proves, and how
--------------------------------------------------------------------------

Rather than a raw structural diff of "native flowchart" against "final
Hex-Rays CFG" (ambiguous here: at the final maturity a fully-linearized
function has *no* block boundary left at either candidate edge, so a naive
block-presence diff flags both the correct site and the corrupting one), this
oracle queries d810's own live single-trip-loop machinery directly:

* :func:`d810.evaluator.hexrays_microcode.single_trip_loop_extract.find_single_trip_peels`
  enumerates natural-loop back-edges and -- by exact def-use, dominance, and a
  Z3-discharged proof (``d810.analyses.control_flow.single_trip_loop``) --
  decides whether the loop body is *provably* single-trip. This is the same
  recognizer ``SingleTripLoopPeelRule`` uses to mutate live MBA; this module
  calls it read-only, on an mba the caller generated with d810 OFF (so no
  live peel has already happened and the back-edge is still present), and
  never mutates microcode.
* This module locally re-derives the emit preconditions
  (``d810.optimizers.microcode.flow.single_trip_loop_peel``'s P3/P4 -- pure
  header, goto latch, unique loop exit) rather than importing that module,
  because ``optimizers`` sits *above* ``backends`` in the layered-architecture
  contract and importing it here would be the exact upward import the
  contract forbids. Small, self-contained duplication across a layer
  boundary already has a precedent in this package: see
  ``native_patch_lowering.py``'s docstring on
  ``_is_pure_control_transfer_mnemonic``.
* Every microcode-block-derived native EA is then independently
  cross-checked against a fresh native decode (the same ``ida_ua`` idiom
  ``observation.py`` uses) before being trusted: the candidate site must
  decode as an unconditional ``jmp`` whose *currently encoded* target equals
  the microcode-inferred header EA, and the proposed new target must be a
  genuine native instruction head. A microcode block's ``start``/``end`` is
  documented as unreliable as a native extent (report section 8); this
  module never treats it as authorization by itself, matching
  ``origin_mapper.py``'s "a microblock's claimed boundary never by itself
  creates an owned span."

Any check failing aborts that candidate (fail closed) rather than emitting an
unproven patch -- the exact posture the P0 counterexample says the pipeline
was missing.

This is Stage A only
--------------------------------------------------------------------------

The proof this module derives is labelled by ``proof_kind``/``proof_reason``
as coming from d810's live analysis; it is not issued by a named,
registered D810 pass carrying a plan hash (report section 6.2). Routing
through a named pass issuer is Stage B and is explicitly not built here --
this module's output (:class:`DeadEdgeCandidate`) is shaped so a Stage B
issuer can wrap it (``proof_kind``/``proof_reason``/the constant facts are
already present) without this module changing.

Read-only
--------------------------------------------------------------------------

This module makes no ``patch_bytes``/``patch_byte``/``put_bytes`` call and
never touches live microcode (no ``DeferredGraphModifier``, no
``queue_goto_change``). It only reads an already-generated ``mba`` and the
live native decode. Turning a candidate into bytes remains
``d810.transforms.native_patch_lowering.lower_direct_edge``; writing remains
``d810.backends.ida.native_patch.gateway.NativePatchGateway``.
"""

from __future__ import annotations

from dataclasses import dataclass

import ida_bytes
import ida_hexrays
import ida_ua
import idaapi

from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.single_trip_loop_extract import (
    PeelCandidate,
    find_single_trip_peels,
)

logger = getLogger("d810.backends.ida.native_patch.dead_edge_oracle")

__all__ = [
    "DeadEdgeCandidate",
    "DeadEdgeAbstention",
    "find_dead_edges",
    "find_dead_edges_for_function",
    "generate_pre_lvars_microcode",
]


@dataclass(frozen=True, slots=True)
class DeadEdgeCandidate:
    """One proven-dead native edge and the direction it should be corrected to.

    ``site_ea`` is the terminator instruction to rewrite -- here always an
    *unconditional* ``jmp`` (the loop latch), which
    ``observation.py``'s conditional-branch-only scan never proposes as a
    site at all. ``current_target_ea`` is the edge this module proves is
    dead (the loop header re-test); ``proposed_target_ea`` is the edge that
    must replace it (the loop's proven-unique exit), both independently
    cross-checked against a live native decode, not trusted from microcode
    block boundaries alone.
    """

    function_ea: int
    site_ea: int
    site_size: int
    mnemonic: str
    current_target_ea: int
    proposed_target_ea: int
    header_block_serial: int
    latch_block_serial: int
    exit_block_serial: int
    proof_kind: str
    proof_reason: str
    entry_const: int
    inloop_const: int
    continue_imm: int

    def describe(self) -> str:
        return (
            f"fn={self.function_ea:#x} site={self.site_ea:#x} ({self.mnemonic}) "
            f"dead_target={self.current_target_ea:#x} "
            f"proposed_target={self.proposed_target_ea:#x} "
            f"proof={self.proof_kind}:{self.proof_reason}"
        )


@dataclass(frozen=True, slots=True)
class DeadEdgeAbstention:
    """Why a Z3-proven single-trip candidate did not yield a native edge."""

    header_block_serial: int
    latch_block_serial: int
    reason: str


def _loop_nodes(mba, latch: int, header: int) -> set[int]:
    """Nodes of the natural loop of back-edge ``latch -> header``.

    Duplicated from ``single_trip_loop_peel.py`` / ``single_trip_loop_extract.py``
    (both already carry an identical helper) rather than imported -- see the
    module docstring's layering note.
    """
    loop = {header, latch}
    stack = [latch]
    while stack:
        n = stack.pop()
        blk = mba.get_mblock(n)
        if blk is None:
            continue
        for p in list(blk.predset):
            if p not in loop:
                loop.add(p)
                stack.append(p)
    return loop


def _resolve_exit_block(mba, header: int, latch: int) -> int | None:
    """Re-derive ``single_trip_loop_peel.plan_single_trip_peel``'s P3/P4 emit
    preconditions and unique-exit resolution, without importing that module
    (see the module docstring).

    Returns the exit block serial, or ``None`` if either precondition fails
    or the exit is not unique -- an honest abstention, not a guess.
    """
    hblk = mba.get_mblock(header)
    lblk = mba.get_mblock(latch)
    if hblk is None or lblk is None:
        return None
    # P3: header is a pure-test block -- exactly one instruction (the cond jump).
    if hblk.head is None or hblk.head.next is not None:
        return None
    # P4: latch is a 1-way goto whose sole successor is the header.
    if (
        lblk.nsucc() != 1
        or lblk.tail is None
        or lblk.tail.opcode != ida_hexrays.m_goto
        or lblk.succ(0) != header
    ):
        return None
    loop_nodes = _loop_nodes(mba, latch, header)
    exits = [s for s in list(hblk.succset) if s not in loop_nodes]
    if len(exits) != 1:
        return None
    return exits[0]


def _native_block_start_ea(mblock) -> int | None:
    """The block's nominal native entry EA.

    Deliberately ``mblock.start``, not ``mblock.head.ea``. Measured on this
    exact fixture: the header block's *only* microinstruction (a fused
    compare-and-branch) is tagged ``ea=0x1800113b1`` -- the native ``jnz``
    itself -- because the preceding ``mov eax, [rsp+4]`` load at
    ``0x1800113a8`` was folded into it rather than kept as a separate
    ``.ea``-tagged microinstruction. ``head.ea`` there is the jump
    instruction's own address, not the block's entry, and using it as the
    "current target" cross-check comparand fails a genuine, correctly-taken
    native jmp against the wrong address. ``mblock.start`` is Hex-Rays'
    own nominal block-entry accounting and matched the real native block
    start in every case measured here; report section 8's caution ("a
    microblock's start/end is not a trustworthy native body *extent*")
    is about the closing edge of a range, not this single entry-point
    read, and either way this value is never trusted by itself -- see the
    independent native-decode cross-check in :func:`find_dead_edges`.
    """
    return int(mblock.start) if mblock is not None else None


def _decode_native(ea: int):
    insn = ida_ua.insn_t()
    length = ida_ua.decode_insn(insn, ea)
    if length <= 0:
        return None
    mnemonic = ida_ua.print_insn_mnem(ea)
    return insn, mnemonic, length


def find_dead_edges(
    mba, *, function_ea: int
) -> tuple[tuple[DeadEdgeCandidate, ...], tuple[DeadEdgeAbstention, ...]]:
    """Find provable dead edges in ``mba`` (generated with d810 OFF).

    Pure with respect to mutation: reads ``mba`` and the live native decode,
    writes nothing. Returns proven candidates and, separately, abstentions
    for Z3-proven single-trip loops whose native site could not be
    trustworthily derived -- reported, not silently dropped, so a sweep can
    distinguish "not this pattern" from "this pattern, but unprovable here."
    """
    candidates: list[DeadEdgeCandidate] = []
    abstentions: list[DeadEdgeAbstention] = []

    peels: tuple[PeelCandidate, ...] = tuple(
        p for p in find_single_trip_peels(mba) if p.verdict.proved
    )
    for peel in peels:
        header, latch = peel.header, peel.latch
        exit_succ = _resolve_exit_block(mba, header, latch)
        if exit_succ is None:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="EMIT_PRECONDITIONS_NOT_MET",
                )
            )
            continue

        lblk = mba.get_mblock(latch)
        hblk = mba.get_mblock(header)
        eblk = mba.get_mblock(exit_succ)
        if lblk is None or hblk is None or eblk is None or lblk.tail is None:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="MISSING_BLOCK",
                )
            )
            continue

        site_ea = int(lblk.tail.ea)
        header_ea = _native_block_start_ea(hblk)
        exit_ea = _native_block_start_ea(eblk)
        if header_ea is None or exit_ea is None:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="NO_NATIVE_EA_ANCHOR",
                )
            )
            continue

        decoded = _decode_native(site_ea)
        if decoded is None:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="SITE_NOT_DECODABLE",
                )
            )
            continue
        insn, mnemonic, length = decoded

        # Cross-check 1: the microcode anchor must correspond to a genuine
        # unconditional near jmp -- never trust the mba block boundary alone.
        if mnemonic != "jmp" or insn.Op1.type != idaapi.o_near:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="SITE_NOT_UNCONDITIONAL_JMP",
                )
            )
            continue

        # Cross-check 2: the *currently encoded* native target must agree
        # with the microcode-inferred header entry -- otherwise the mba
        # anchor and the live bytes disagree and nothing may be trusted.
        if int(insn.Op1.addr) != header_ea:
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="CURRENT_TARGET_MISMATCH",
                )
            )
            continue

        # Cross-check 3: the proposed new target must be a genuine native
        # instruction head, not a microcode-only synthetic location.
        if not ida_bytes.is_head(ida_bytes.get_flags(exit_ea)):
            abstentions.append(
                DeadEdgeAbstention(
                    header_block_serial=header,
                    latch_block_serial=latch,
                    reason="PROPOSED_TARGET_NOT_INSTRUCTION_HEAD",
                )
            )
            continue

        candidates.append(
            DeadEdgeCandidate(
                function_ea=int(function_ea),
                site_ea=site_ea,
                site_size=int(length),
                mnemonic=mnemonic,
                current_target_ea=header_ea,
                proposed_target_ea=exit_ea,
                header_block_serial=header,
                latch_block_serial=latch,
                exit_block_serial=exit_succ,
                proof_kind="single_trip_loop_peel",
                proof_reason=peel.verdict.reason,
                entry_const=peel.verdict.facts.entry_const,
                inloop_const=peel.verdict.facts.inloop_const,
                continue_imm=peel.verdict.facts.continue_imm,
            )
        )

    return tuple(candidates), tuple(abstentions)


def generate_pre_lvars_microcode(function_ea: int):
    """Generate microcode at ``MMAT_CALLS`` -- the maturity
    ``SingleTripLoopPeelRule`` (and every other ``FlowOptimizationRule``
    block rule) actually observes live, confirmed by the production
    ``DeferredGraphModifier`` trace this module's docstring cites.

    ``cfunc.mba`` (the fully-decompiled, final-maturity mba) is the wrong
    input: by ``MMAT_LVARS``, Hex-Rays has already rewritten the guard
    operand from a raw stack slot (``mop_S``) to a resolved local-variable
    reference (``mop_l``), which
    ``single_trip_loop_extract._guard_locator`` does not recognise (by
    design -- it matches the same two operand shapes the live rule's own
    recognizer matches at its actual maturity), so every candidate
    silently fails to extract facts and ``find_single_trip_peels`` returns
    nothing. Measured directly: ``cfunc.mba`` on this fixture yields zero
    peels; the identical block shape generated at ``MMAT_CALLS`` yields the
    one expected, Z3-proved candidate.

    Mirrors ``tests/system/runtime/conftest.py``'s
    ``gen_microcode_at_maturity`` helper (same SDK call, same deprecated-but-
    still-supported ``mba_ranges_t`` overload for consistency with the rest
    of this codebase) rather than importing a test helper from production
    code.
    """
    func = idaapi.get_func(int(function_ea))
    if func is None:
        return None
    mbr = ida_hexrays.mba_ranges_t(func)
    hf = ida_hexrays.hexrays_failure_t()
    return ida_hexrays.gen_microcode(
        mbr, hf, None, ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_CALLS
    )


def find_dead_edges_for_function(
    function_ea: int,
) -> tuple[tuple[DeadEdgeCandidate, ...], tuple[DeadEdgeAbstention, ...]]:
    """Generate pre-LVARS microcode for ``function_ea`` fresh (caller must
    ensure d810 is OFF) and run :func:`find_dead_edges` on it.

    Convenience wrapper for sweeps; ``find_dead_edges`` itself takes an
    already-generated ``mba`` so it stays testable against any mba a caller
    already has in hand.
    """
    mba = generate_pre_lvars_microcode(function_ea)
    if mba is None:
        return (), ()
    return find_dead_edges(mba, function_ea=function_ea)
