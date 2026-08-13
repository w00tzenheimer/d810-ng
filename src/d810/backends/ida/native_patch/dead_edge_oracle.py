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
oracle queries d810's own live proof machinery directly.

There are two recognizers, and :func:`find_dead_edges` runs both:

1. **Single-trip loop peel** -- the loop latch of a Z3-proven single-trip
   loop, corrected by retargeting it at the loop's unique exit.
2. **Opaque predicate** -- a conditional branch whose direction Z3 proves
   constant, corrected by forcing it taken (retarget to the taken target) or
   erasing it (NOP fill, fall through).

The two answer different questions and are deliberately kept separate rather
than merged behind one heuristic: the first is about a *loop's* trip count,
the second about a *branch's* condition. A site claimed by both is dropped,
not arbitrated.

Recognizer 1 works as follows:

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

import enum
from dataclasses import dataclass

import ida_bytes
import ida_hexrays
import ida_ua
import idaapi

from d810.backends.ast.z3 import Z3MopProver
from d810.core.logging import getLogger
from d810.evaluator.hexrays_microcode.single_trip_loop_extract import (
    PeelCandidate,
    find_single_trip_peels,
)

logger = getLogger("d810.backends.ida.native_patch.dead_edge_oracle")

_SINGLE_TRIP_PROOF_KIND = "single_trip_loop_peel"
_OPAQUE_PROOF_KIND = "z3_opaque_predicate"

# Equality-shaped conditional jumps. ``are_equal``/``are_unequal`` decide these
# exactly; relational jumps would need a general predicate discharge the prover
# does not expose, so they are out of scope rather than approximated.
_EQUALITY_JUMP_OPCODES = frozenset({ida_hexrays.m_jz, ida_hexrays.m_jnz})

__all__ = [
    "DeadEdgeAction",
    "DeadEdgeCandidate",
    "DeadEdgeAbstention",
    "find_dead_edges",
    "find_dead_edges_for_function",
    "generate_pre_lvars_microcode",
]


class DeadEdgeAction(str, enum.Enum):
    """How a proven-dead edge must be corrected in native bytes.

    The three values are not interchangeable encodings of one idea; each
    names a different lowering, and getting them confused is precisely the
    P0 this module exists to prevent.

    ``RETARGET``
        The site is an unconditional ``jmp`` already; only its destination is
        wrong. Lowered by ``lower_direct_edge`` to ``proposed_target_ea``.
    ``FORCE_TAKEN``
        The site is a conditional branch proven always taken. Its fallthrough
        is dead. Lowered by ``lower_direct_edge`` to the taken target.
    ``FORCE_FALLTHROUGH``
        The site is a conditional branch proven never taken. Its taken target
        is dead. Lowered by ``lower_removed_edge`` -- the branch is erased to
        NOP fill, **not** retargeted at its fallthrough. Retargeting would
        also be semantically correct here but wastes the region on a jump to
        the very next instruction; erasing keeps the region honest and lets a
        later pass see straight-line code.
    """

    RETARGET = "RETARGET"
    FORCE_TAKEN = "FORCE_TAKEN"
    FORCE_FALLTHROUGH = "FORCE_FALLTHROUGH"


@dataclass(frozen=True, slots=True)
class DeadEdgeCandidate:
    """One proven-dead native edge and the direction it should be corrected to.

    ``site_ea`` is the terminator instruction to rewrite. ``current_target_ea``
    is the edge this module proves is dead; ``proposed_target_ea`` is the edge
    that survives. Both are independently cross-checked against a live native
    decode, never trusted from microcode block boundaries alone.

    ``action`` says which lowering the proof authorizes -- see
    :class:`DeadEdgeAction`. A consumer must dispatch on it rather than
    assuming a retarget: for ``FORCE_FALLTHROUGH`` the correct emission is a
    NOP fill, and emitting a jump to ``proposed_target_ea`` instead would
    still work but is not what the proof asked for.

    ``proof_facts`` carries the recognizer-specific constants that justified
    the verdict (the single-trip loop's entry/in-loop/continue immediates; an
    opaque predicate has none). It is a tuple of pairs rather than named
    fields because the set differs per ``proof_kind`` and a Stage B issuer
    only needs to record them verbatim, not interpret them.
    """

    function_ea: int
    site_ea: int
    site_size: int
    mnemonic: str
    current_target_ea: int
    proposed_target_ea: int
    action: DeadEdgeAction
    block_serial: int
    proof_kind: str
    proof_reason: str
    proof_facts: tuple[tuple[str, int], ...] = ()

    def describe(self) -> str:
        return (
            f"fn={self.function_ea:#x} site={self.site_ea:#x} ({self.mnemonic}) "
            f"action={self.action.value} "
            f"dead_target={self.current_target_ea:#x} "
            f"proposed_target={self.proposed_target_ea:#x} "
            f"proof={self.proof_kind}:{self.proof_reason}"
        )


@dataclass(frozen=True, slots=True)
class DeadEdgeAbstention:
    """Why a candidate that *was* proven did not yield a usable native edge.

    Only raised after a proof succeeded. A branch the prover simply could not
    decide is "not this pattern" and is skipped silently -- reporting all 725
    undecided branches measured on ``libobfuscated.dll`` would bury the handful
    that were proven but unmappable, which is the signal worth surfacing.
    """

    block_serial: int
    related_block_serial: int | None
    proof_kind: str
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


def _find_single_trip_edges(
    mba, *, function_ea: int
) -> tuple[list[DeadEdgeCandidate], list[DeadEdgeAbstention]]:
    """Recognizer 1: the loop latch of a Z3-proven single-trip loop."""
    candidates: list[DeadEdgeCandidate] = []
    abstentions: list[DeadEdgeAbstention] = []

    peels: tuple[PeelCandidate, ...] = tuple(
        p for p in find_single_trip_peels(mba) if p.verdict.proved
    )
    for peel in peels:
        header, latch = peel.header, peel.latch

        def _abstain(reason: str, *, _h: int = header, _l: int = latch) -> None:
            abstentions.append(
                DeadEdgeAbstention(
                    block_serial=_l,
                    related_block_serial=_h,
                    proof_kind=_SINGLE_TRIP_PROOF_KIND,
                    reason=reason,
                )
            )

        exit_succ = _resolve_exit_block(mba, header, latch)
        if exit_succ is None:
            _abstain("EMIT_PRECONDITIONS_NOT_MET")
            continue

        lblk = mba.get_mblock(latch)
        hblk = mba.get_mblock(header)
        eblk = mba.get_mblock(exit_succ)
        if lblk is None or hblk is None or eblk is None or lblk.tail is None:
            _abstain("MISSING_BLOCK")
            continue

        site_ea = int(lblk.tail.ea)
        header_ea = _native_block_start_ea(hblk)
        exit_ea = _native_block_start_ea(eblk)
        if header_ea is None or exit_ea is None:
            _abstain("NO_NATIVE_EA_ANCHOR")
            continue

        decoded = _decode_native(site_ea)
        if decoded is None:
            _abstain("SITE_NOT_DECODABLE")
            continue
        insn, mnemonic, length = decoded

        # Cross-check 1: the microcode anchor must correspond to a genuine
        # unconditional near jmp -- never trust the mba block boundary alone.
        if mnemonic != "jmp" or insn.Op1.type != idaapi.o_near:
            _abstain("SITE_NOT_UNCONDITIONAL_JMP")
            continue

        # Cross-check 2: the *currently encoded* native target must agree
        # with the microcode-inferred header entry -- otherwise the mba
        # anchor and the live bytes disagree and nothing may be trusted.
        if int(insn.Op1.addr) != header_ea:
            _abstain("CURRENT_TARGET_MISMATCH")
            continue

        # Cross-check 3: the proposed new target must be a genuine native
        # instruction head, not a microcode-only synthetic location.
        if not ida_bytes.is_head(ida_bytes.get_flags(exit_ea)):
            _abstain("PROPOSED_TARGET_NOT_INSTRUCTION_HEAD")
            continue

        candidates.append(
            DeadEdgeCandidate(
                function_ea=int(function_ea),
                site_ea=site_ea,
                site_size=int(length),
                mnemonic=mnemonic,
                current_target_ea=header_ea,
                proposed_target_ea=exit_ea,
                action=DeadEdgeAction.RETARGET,
                block_serial=latch,
                proof_kind=_SINGLE_TRIP_PROOF_KIND,
                proof_reason=peel.verdict.reason,
                proof_facts=(
                    ("entry_const", int(peel.verdict.facts.entry_const)),
                    ("inloop_const", int(peel.verdict.facts.inloop_const)),
                    ("continue_imm", int(peel.verdict.facts.continue_imm)),
                    ("header_block_serial", int(header)),
                    ("exit_block_serial", int(exit_succ)),
                ),
            )
        )

    return candidates, abstentions


def _jump_target_serial(tail) -> int | None:
    """The microcode block serial a conditional jump targets, or None.

    ``minsn_t.d`` for a jump holds a ``mop_b`` naming the destination block.
    Anything else means this is not the shape assumed here, so abstain.
    """
    dest = getattr(tail, "d", None)
    if dest is None or int(dest.t) != ida_hexrays.mop_b:
        return None
    return int(dest.b)


def _find_opaque_edges(
    mba, *, function_ea: int
) -> tuple[list[DeadEdgeCandidate], list[DeadEdgeAbstention]]:
    """Recognizer 2: a conditional branch whose direction Z3 proves constant.

    Queries d810's own :class:`~d810.backends.ast.z3.Z3MopProver` -- the same
    prover the live opaque-predicate rules use -- on the two operands of an
    equality-shaped microcode jump. ``are_equal``/``are_unequal`` each return
    ``solver.check() == unsat`` on the *negation* of the claim, so a True is a
    discharged proof over all values of the free operands, not a sampled
    observation. Proving over all values is strictly stronger than proving
    over reachable values, so the quantification errs safe.

    Deliberately **not** ported from
    ``d810.optimizers.microcode.flow.jumps.opaque``. Those ``JnzRule*``
    classes are AST pattern matches whose ``check_candidate`` mostly returns
    True by construction; they are enumerated identities, not discharged
    proofs, and this module's contract is proof-only. Importing them would
    also be an upward layer violation (``optimizers`` sits above
    ``backends``). Asking the solver directly is both sound and more general:
    any opaque predicate Z3 can discharge is covered, not just the fifteen
    shapes someone wrote a rule for.

    Relational jumps (``m_jae``, ``m_jl``, ...) are out of scope here: the
    prover exposes equality and always-zero queries, not a general predicate
    discharge, so those branches are skipped rather than guessed at. Measured
    on ``libobfuscated.dll``: 251 relational vs 735 equality-shaped.
    """
    candidates: list[DeadEdgeCandidate] = []
    abstentions: list[DeadEdgeAbstention] = []
    prover = Z3MopProver()

    for serial in range(mba.qty):
        blk = mba.get_mblock(serial)
        if blk is None or blk.tail is None:
            continue
        tail = blk.tail
        if tail.opcode not in _EQUALITY_JUMP_OPCODES:
            continue

        def _abstain(reason: str, *, _s: int = serial) -> None:
            abstentions.append(
                DeadEdgeAbstention(
                    block_serial=_s,
                    related_block_serial=None,
                    proof_kind=_OPAQUE_PROOF_KIND,
                    reason=reason,
                )
            )

        try:
            equal = bool(prover.are_equal(tail.l, tail.r, blk=blk, ins=tail))
            unequal = bool(prover.are_unequal(tail.l, tail.r, blk=blk, ins=tail))
        except Exception:
            # A prover failure is not evidence of anything. Skip silently:
            # this is indistinguishable from "undecided", not a proven
            # candidate that failed to map.
            continue

        if equal and unequal:
            # Both discharged means the solver contradicted itself, or the two
            # operands were converted inconsistently. Either way the proof is
            # worthless. Fail closed and say so -- this must never fire, and a
            # silent skip would hide it if it ever did.
            _abstain("CONTRADICTORY_PROOF")
            continue
        if not equal and not unequal:
            continue  # undecided: not this pattern

        # m_jz takes the branch when equal; m_jnz when unequal.
        always_taken = equal if tail.opcode == ida_hexrays.m_jz else unequal

        site_ea = int(tail.ea)
        decoded = _decode_native(site_ea)
        if decoded is None:
            _abstain("SITE_NOT_DECODABLE")
            continue
        insn, mnemonic, length = decoded

        # Cross-check 1: the microcode jump must correspond to a genuine
        # native *conditional* near branch. A fused compare-and-branch can
        # carry the ea of something else entirely.
        if not mnemonic or not mnemonic.startswith("j") or mnemonic == "jmp":
            _abstain("SITE_NOT_CONDITIONAL_JCC")
            continue
        if insn.Op1.type != idaapi.o_near:
            _abstain("SITE_NOT_NEAR_BRANCH")
            continue

        taken_ea = int(insn.Op1.addr)
        fallthrough_ea = site_ea + int(length)

        # Cross-check 2: microcode and live bytes must agree on where the
        # taken edge goes. If they disagree, the ea anchor is not this branch
        # and nothing derived from it may be trusted.
        target_serial = _jump_target_serial(tail)
        if target_serial is None:
            _abstain("NO_MICROCODE_TARGET_BLOCK")
            continue
        tblk = mba.get_mblock(target_serial)
        if tblk is None:
            _abstain("MISSING_BLOCK")
            continue
        if _native_block_start_ea(tblk) != taken_ea:
            _abstain("CURRENT_TARGET_MISMATCH")
            continue

        if always_taken:
            action = DeadEdgeAction.FORCE_TAKEN
            dead_ea, surviving_ea = fallthrough_ea, taken_ea
        else:
            action = DeadEdgeAction.FORCE_FALLTHROUGH
            dead_ea, surviving_ea = taken_ea, fallthrough_ea

        # Cross-check 3: the surviving edge must land on a real instruction
        # head, never mid-instruction.
        if not ida_bytes.is_head(ida_bytes.get_flags(surviving_ea)):
            _abstain("PROPOSED_TARGET_NOT_INSTRUCTION_HEAD")
            continue

        candidates.append(
            DeadEdgeCandidate(
                function_ea=int(function_ea),
                site_ea=site_ea,
                site_size=int(length),
                mnemonic=mnemonic,
                current_target_ea=dead_ea,
                proposed_target_ea=surviving_ea,
                action=action,
                block_serial=int(serial),
                proof_kind=_OPAQUE_PROOF_KIND,
                proof_reason=(
                    "z3_proved_operands_always_equal"
                    if equal
                    else "z3_proved_operands_always_unequal"
                ),
                proof_facts=(("microcode_opcode", int(tail.opcode)),),
            )
        )

    return candidates, abstentions


def find_dead_edges(
    mba, *, function_ea: int
) -> tuple[tuple[DeadEdgeCandidate, ...], tuple[DeadEdgeAbstention, ...]]:
    """Find provable dead edges in ``mba`` (generated with d810 OFF).

    Pure with respect to mutation: reads ``mba`` and the live native decode,
    writes nothing. Runs every recognizer and merges their results.

    Returns proven candidates and, separately, abstentions for candidates that
    *were* proven but whose native site could not be trustworthily derived --
    reported, not silently dropped, so a sweep can distinguish "not this
    pattern" from "this pattern, but unmappable here."

    If two recognizers claim the same ``site_ea``, both are dropped and an
    abstention is recorded. Two independent proofs about one instruction may
    disagree on direction, and there is no principled way to pick a winner
    here; the pipeline's whole posture is that an unresolved disagreement
    means abstain.
    """
    candidates: list[DeadEdgeCandidate] = []
    abstentions: list[DeadEdgeAbstention] = []
    for recognizer in (_find_single_trip_edges, _find_opaque_edges):
        found, abstained = recognizer(mba, function_ea=function_ea)
        candidates.extend(found)
        abstentions.extend(abstained)

    by_site: dict[int, list[DeadEdgeCandidate]] = {}
    for candidate in candidates:
        by_site.setdefault(candidate.site_ea, []).append(candidate)

    accepted: list[DeadEdgeCandidate] = []
    for site_ea, claims in by_site.items():
        if len(claims) == 1:
            accepted.append(claims[0])
            continue
        logger.warning(
            "native dead-edge oracle: %d recognizers claim site %#x (%s); dropping all",
            len(claims),
            site_ea,
            ", ".join(sorted({c.proof_kind for c in claims})),
        )
        abstentions.append(
            DeadEdgeAbstention(
                block_serial=claims[0].block_serial,
                related_block_serial=None,
                proof_kind="+".join(sorted({c.proof_kind for c in claims})),
                reason="CONFLICTING_RECOGNIZER_CLAIMS",
            )
        )

    accepted.sort(key=lambda c: c.site_ea)
    return tuple(accepted), tuple(abstentions)


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
