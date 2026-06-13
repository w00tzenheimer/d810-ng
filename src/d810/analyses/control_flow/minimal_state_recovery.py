"""Minimal per-handler state-transition recovery (epic d81-jfg2).

The legacy recovery builds a whole state-transition graph by symbolically
DFS-walking multi-block handler paths, classifying exits, detecting corridors,
and running SCC analysis (``evaluate_handler_paths`` + the supplemental DAG
builder).  That machinery drifts across shared blocks into the wrong
handler/exit (e.g. ``0x610BB4D9`` collapsed to the exit state) and produces
diagnostic projections that disagree with the actual output.

This module replaces it with the minimal model:

    transition(handler) = route( fold(handler's next-state write) )

For each handler the dispatcher routes to, we run a **strictly handler-local**
forward scan that:

  * starts at the handler entry with an empty const env,
  * folds the state-var write per block (``_transfer_snapshot_constant_block``
    — the sound local fold, carrying the handler's own constants so shared
    ``xor``/``sub`` suffixes fold to *this* handler's value automatically), and
  * **hard-stops** at the dispatcher entry, *any other handler's entry block*,
    or a STOP/terminal block.

The last folded state-var value on a path is that path's next-state; a 2-way
branch inside the region yields one arm per branch (a conditional transition).
Each next-state is routed through the interval-set dispatcher to its target
handler.  No global graph, no SCC, no exit-classification heuristics, no
drifting walk.

Portable: consumes a :class:`d810.ir.flowgraph.FlowGraph` snapshot and an
:class:`d810.analyses.control_flow.interval_map.IntervalDispatcher`; no live
IDA / Hex-Rays imports.  The MBA fold runs through the registered
``forward_eval_insn`` seam (same as the existing snapshot path eval).
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.analyses.control_flow.state_machine_analysis import (
    _constant_dest_locator_snapshot,
    _eval_insn_view_snapshot,
    _is_call_insn,
    _is_goto_insn,
    _is_nop_insn,
    _is_stop_block,
    _transfer_snapshot_constant_block,
    run_snapshot_constant_fixpoint,
)
from d810.analyses.value_flow.global_init_fold import (
    compute_initializer_stable_global_reads,
)
from d810.analyses.data_flow.concolic import (
    AbstractEvidence,
    ConcolicValue,
    ConcreteStore,
    EmulationCapability,
    LocationRef,
    PrecisionStatus,
    fold_exact,
)
from d810.capabilities.providers import get_bst_walkers

logger = getLogger(__name__)

# Default bound on the handler-local corridor scan.  Real OLLVM handler bodies
# (entry -> work -> const-load -> shared MBA suffix -> dispatcher) are short; a
# small bound keeps the scan O(handler) and prevents runaway on malformed CFGs.
_MAX_CORRIDOR_DEPTH = 24

__all__ = [
    "TransitionArm",
    "HandlerTransition",
    "recover_handler_transitions",
    "StateWriteTransition",
    "TransitionProof",
    "block_has_live_carrier_write",
    "recover_state_write_transitions",
    "recover_state_write_transitions_via_fixpoint",
    "recover_state_write_transitions_via_multicell_fixpoint",
    "recover_state_write_transitions_via_partitioned_fixpoint",
    "diff_back_edge_transitions",
    "diff_back_edge_transitions_partitioned",
]

#: The oracle that resolves a back-edge next-state after the S4 C3 flip: the sound
#: region-partitioned multi-cell constant fixpoint (run_snapshot_constant_fixpoint).
_FIXPOINT_ORACLE = "region_partitioned_fixpoint"

#: The reduced-product CONCRETE leg (ticket llr-xauw): a prove-exact-or-abstain
#: ``EmulationCapability`` consulted ONLY where the abstract fixpoint fold left a
#: back-edge next-state at ``⊥`` (read_key miss).  Its ``ExactResult`` is still
#: cross-checked against the abstract floor by ``fold_exact`` before it is trusted,
#: so a wrong emulation forfeits precision, never correctness.  It NEVER overrides a
#: fixpoint-resolved transition -- it only fills genuine ⊥ gaps.
_EMULATION_ORACLE = "emulation_concrete_leg"

#: Proof KINDS for the reduced-product CONCRETE leg (ticket llr-a93i): one per
#: recovery SITE the prove-exact-or-abstain emulator can serve, so the proof
#: distribution names WHERE the concrete oracle fired -- initial-state vs back-edge
#: vs conditional-arm -- not merely THAT it fired.  All four share the
#: ``_EMULATION_ORACLE`` oracle (the oracle is the evidence SOURCE; the kind is the
#: recovery SITE), and every one is ``fold_exact``-gated before it is trusted.
#:
#: * ``initial_state_concrete_fold``   -- the prologue/entry-init state write folded
#:   by the emulator seeded from entry constants + static-initializer facts (Slice 2).
#: * ``back_edge_concrete_fold``       -- a single dispatcher back-edge's next-state,
#:   every incoming edge agreeing on one concrete value (Slice 3).
#: * ``concrete_fold_partitioned``     -- the per-immediate-predecessor split of a
#:   back-edge (one distinct concrete next-state per incoming edge).
#: * ``conditional_arm_concrete_fold`` -- a runtime-guarded branch arm of a handler,
#:   folded as one conditional transition per arm (Slice 4).
_KIND_INITIAL_STATE_CONCRETE_FOLD = "initial_state_concrete_fold"
_KIND_BACK_EDGE_CONCRETE_FOLD = "back_edge_concrete_fold"
_KIND_CONCRETE_FOLD_PARTITIONED = "concrete_fold_partitioned"
_KIND_CONDITIONAL_ARM_CONCRETE_FOLD = "conditional_arm_concrete_fold"


def _seed_concrete_store(
    out_stk: dict[int, int], out_reg: dict[int, int]
) -> ConcreteStore:
    """Project a fixpoint OUT store (stkoff/regid -> int) into a ``ConcreteStore``.

    The seeded store the concrete leg evaluates the back-edge block over: every
    converged stack/register constant at the immediate predecessor's exit becomes a
    resolved ``LocationRef`` cell, so an opaque ``state = reg_a ^ reg_b`` write whose
    operands are program values defined upstream resolves (the abstract meet
    collapses them to ⊥; the concrete leg reads them from the predecessor OUT).
    Width 8 mirrors the u64-masked state lattice; the backend's ``_seed_maps`` only
    reads STACK / REGISTER cells.
    """
    cells: dict[LocationRef, int] = {}
    for off, val in out_stk.items():
        cells[LocationRef.stack(int(off), 8)] = int(val)
    for reg, val in out_reg.items():
        cells[LocationRef.reg(int(reg), 8)] = int(val)
    return ConcreteStore.of(cells)


def _emulate_unresolved_state(
    emu: EmulationCapability,
    live_block: object,
    seeded_store: ConcreteStore,
    state_cell: LocationRef,
    *,
    spine_floor: "AbstractEvidence | None" = None,
    strict_floor: bool = False,
) -> int | None:
    """Consult the concrete leg for a single ⊥ back-edge, or ``None`` on abstain.

    Steps ``live_block`` over ``seeded_store`` via the injected
    :class:`EmulationCapability`, then ``fold_exact``-validates the outcome against the
    abstract floor ``spine_floor``.  Returns the proven concrete next-state
    (width-masked) or ``None`` when the emulator abstains / the fold is dropped.

    The floor seam (ticket llr-1d8u / P4):

    * ``spine_floor=None`` (DEFAULT) -> floor = ``AbstractEvidence.top(8)``, which is
      byte-identical to the historical ``ConcolicValue.top(8).abstract`` floor the
      ``llr-xauw`` reduced-product CONCRETE leg used.  ``AbstractEvidence.top()``
      ``contains`` every value, so soundness rests on the emulator's own
      prove-exact-or-abstain block-stepper -- the unchanged legacy behaviour.
    * ``spine_floor`` non-``⊤`` -> the AI spine's per-context ``σ#_in(c)`` projection.
      ``fold_exact`` then does REAL work: an ``ExactResult`` whose value the floor does
      NOT contain (an unsound/over-eager emulator) is dropped, so the concrete claim is
      validated against a non-trivial sound floor (the §7 (b) gate).
    * ``strict_floor=True`` (the P4 reduced-product caller) -> early-return ``None``
      ("stay ⊤") when the floor is ``⊤``.  This closes the Z3-proven VACUOUS gate: a
      ⊤ floor admits every value, so refining a ⊤ cell on its strength is unsound;
      the reduced-product path must therefore have a non-trivial floor or stay ⊤.
      The DEFAULT (``strict_floor=False``) NEVER early-returns, so every existing
      caller is behaviour-identical.
    """
    floor = spine_floor if spine_floor is not None else AbstractEvidence.top(8)
    if strict_floor and floor.is_top():
        # Reduced-product gate (b): a ⊤ floor cannot establish completeness
        # (γ(⊤) is everything), so refining on its strength is the vacuous/unsound
        # gate the Z3 proof flagged. Stay ⊤. (truth reduced_product_cff_refinement/
        # is_sound_iff; ticket llr-1d8u §0.1.)
        if logger.info_on:
            logger.info("emu-consult: ⊤ floor under strict_floor -> stay ⊤ (abstain)")
        return None
    if live_block is None:
        if logger.info_on:
            logger.info("emu-consult: no live block -> abstain")
        return None
    try:
        outcome = emu.eval_block(live_block, seeded_store)
    except Exception:  # noqa: BLE001 — an emulator failure means "cannot prove" -> abstain
        logger.debug("emulation concrete leg raised; abstaining", exc_info=True)
        if logger.info_on:
            logger.info(
                "emu-consult: blk=%s store_cells=%d -> RAISED (abstain)",
                getattr(live_block, "serial", "?"), len(getattr(seeded_store, "cells", {})),
            )
        return None
    folded = fold_exact(
        ConcolicValue(None, None, floor, floor.width, PrecisionStatus.ABSTRACT),
        outcome,
        state_cell,
    )
    resolved = folded.status is PrecisionStatus.CONCRETE and folded.concrete is not None
    # Observability (ticket llr-a93i, Slice 3): record every concrete-leg consult --
    # candidate block, seed richness, the emulator's outcome ADT, and whether
    # ``fold_exact`` accepted it -- so "does the real HexRaysBlockEmulator ever fold a
    # production back-edge?" is answerable from the log, not inferred from a 0-count in
    # the proof histogram.
    if logger.info_on:
        logger.info(
            "emu-consult: blk=%s store_cells=%d outcome=%s reason=%r folded=%s%s",
            getattr(live_block, "serial", "?"),
            len(getattr(seeded_store, "cells", {})),
            type(outcome).__name__,
            getattr(outcome, "reason", ""),
            resolved,
            (" value=0x%x" % (int(folded.concrete) & 0xFFFFFFFF)) if resolved else "",
        )
    if not resolved:
        return None
    return int(folded.concrete) & 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class TransitionProof:
    """Typed provenance for a recovered back-edge transition (ticket d81-t9ok).

    Names the oracle that resolved the next-state and whether the result is trusted,
    so the fact/proof layer (epic llr-fqam) can rank edges by evidence instead of
    trusting every emitted edge equally / a provenance allowlist.  ``kind`` is the
    resolution shape (``global_fold`` / ``region_agreed`` / ``predecessor_partitioned``
    / ``unresolved``); ``trusted`` is ``False`` for an unresolved (routed-to-return)
    back-edge a consumer must not rewrite as a handler transition.
    """

    oracle_kind: str
    kind: str
    trusted: bool
    reason: str = ""


@dataclass(frozen=True, slots=True)
class StateWriteTransition:
    """One dispatcher back-edge: a block that writes the next state then re-enters
    the dispatcher.

    The state-machine's *real* transition points are the dispatcher's
    predecessors — every block that writes the state variable and branches back
    into the comparison tree.  (For the OLLVM shape this module targets, the set
    of dispatcher predecessors is *exactly* the set of state-var-writing blocks.)
    Anchoring recovery on these back-edges — rather than on the dispatcher's
    routed *targets* (handler entries) — is robust to handlers that share
    suffixes or chain through one another's entry blocks: those interior fall
    -throughs are left as natural control flow and only the back-edge to the
    dispatcher is rewritten.
    """

    write_block: int             # redirect source (the back-edge, or a predecessor
                                 # of it when the back-edge is a per-predecessor split)
    next_state: int | None       # folded state-var value entering the dispatcher
    target_handler: int | None   # dispatcher route of next_state (None unresolved)
    is_return: bool              # routes to exit/STOP/default, or unresolved
    branch_arm: int | None       # succ index of the dispatcher edge (None => 1-way)
    via_block: int | None = None  # when set, redirect ``write_block -> via_block``
                                  # (bypass the shared back-edge) instead of
                                  # ``write_block -> dispatcher``
    proof: "TransitionProof | None" = None  # typed provenance (d81-t9ok); the
                                            # authoritative fixpoint emitter attaches
                                            # it, None = unattributed (legacy fold)


def _resolve_state_var_alias(
    flow_graph, dispatcher_entry_serial: int, state_var_stkoff: int
) -> int:
    """Follow a dispatcher-header copy ``state_var = src`` back to ``src``.

    OLLVM ``-fla`` keeps the dispatcher's *compared* state slot as a copy of the
    slot the handlers actually write the NEXT state to: the loop header does
    ``compared = next_write`` then routes on ``compared``.  At a handler
    back-edge the compared slot still holds the OLD (current) state, so folding
    it makes every handler resolve to its own incoming state -> ``route(own)`` is
    the handler itself -> self-loop, and the dispatcher collapses unchanged.  The
    slot the handlers freshly write is the copy SOURCE; fold *that* so back-edge
    next-states resolve.

    Detected structurally (no opcode interpretation -- the lifter leaves
    ``insn.kind`` UNKNOWN): a write into ``state_var_stkoff`` whose left operand
    is a *different* stack slot and whose right operand is empty is a pure copy
    (mov / widen), not arithmetic.  Returns the original offset when the header
    has no such incoming copy (clean hodur / sub_7FFD chains -> unchanged).
    """
    blk = flow_graph.get_block(int(dispatcher_entry_serial))
    if blk is None:
        return int(state_var_stkoff)
    soff = int(state_var_stkoff)
    source = soff
    for insn in getattr(blk, "insn_snapshots", ()):
        view = _eval_insn_view_snapshot(insn)
        if _constant_dest_locator_snapshot(getattr(view, "d", None)) != ("stk", soff):
            continue
        r = getattr(view, "r", None)
        if (
            _constant_dest_locator_snapshot(r) is not None
            or getattr(r, "value", None) is not None
        ):
            continue  # binary op (add/xor/...) -> not a pure copy
        lloc = _constant_dest_locator_snapshot(getattr(view, "l", None))
        if lloc is not None and lloc[0] == "stk" and lloc[1] != soff:
            source = int(lloc[1])  # last copy into state_var wins
    return source


def _operand_gaddr(mop) -> int | None:
    """Return the global address an operand names (mop_v), or ``None``."""
    if mop is None:
        return None
    g = getattr(mop, "gaddr", None)
    if g is None:
        g = getattr(mop, "g", None)
    try:
        return int(g) if g else None
    except (TypeError, ValueError):
        return None


def _detect_global_state_var(flow_graph, dispatcher_entry_serial: int) -> int | None:
    """Return the global address the dispatcher compares as its state var, or ``None``.

    Hex-Rays can forward-substitute a ``state = global`` copy into the dispatcher
    so the loop header compares a *global* directly (Approov
    ``approov_vm_dispatcher`` at GLBOPT1: ``jz $qword_180021320, #0xF6A1F``).  The
    stack state-var detection then picks a now-dead decoy slot and every back-edge
    is unresolved.  When the dispatcher-entry compare reads a global, that global
    IS the effective state variable; return its address so the recovery folds the
    handlers' next-state writes to it.  Returns ``None`` for the ordinary
    stack/register state var (no behaviour change).
    """
    blk = flow_graph.get_block(int(dispatcher_entry_serial))
    if blk is None:
        return None
    for insn in getattr(blk, "insn_snapshots", ()):
        view = _eval_insn_view_snapshot(insn)
        # The dispatcher head compares the state var: its LEFT operand (or a
        # nested compared subexpression) names the global.
        for slot in ("l", "r"):
            mop = getattr(view, slot, None)
            g = _operand_gaddr(mop)
            if g is not None:
                return g
            for sub in ("sub_l", "sub_r"):
                g = _operand_gaddr(getattr(mop, sub, None))
                if g is not None:
                    return g
    return None


def _compute_foldable_global_reads(
    flow_graph, dispatcher_entry_serial: int, initial_handler_serial: int | None
):
    """Reaching-defs-sound ``{read_ea: {gaddr: init}}`` for data-dependent globals.

    Computed over EVERY global the function reads: a handler can compute its next
    state from a writable global it later mutates (Approov: ``state = (qword |=
    0xF6A20)``), and the read folds to the global's static ``.data`` initializer
    ONLY where reaching-defs proves no store reaches it.

    The reaching-defs is anchored at the INITIAL handler (the dispatcher's target
    for the entry state), with the dispatcher entry as a *barrier* whose incoming
    edges are cut.  A flattened handler routes back through the dispatcher by the
    state value, so on the raw CFG the initial handler's own back-edge would make
    its first read look store-reachable via an infeasible self-loop.  Anchoring at
    the initial handler + cutting the dispatcher gives the real straight-line
    execution prefix: the initial handler runs first, before any handler store, so
    its global read is store-free; every other handler is reached only through the
    (cut) dispatcher and is therefore NOT folded (its store-freeness is unproven --
    a prior handler may have mutated the global).  Sound per read site, strictly
    narrower than blanket ``fold_writable_constants``.  Empty when no initial
    handler is known or no IDB read seam.
    """
    if initial_handler_serial is None:
        return {}
    fetch = getattr(get_bst_walkers(), "fetch_idb_value", None)
    if fetch is None:
        return {}
    return compute_initializer_stable_global_reads(
        flow_graph,
        fetch,
        barrier_serials={int(dispatcher_entry_serial)},
        entry_override=int(initial_handler_serial),
    )


def block_has_live_carrier_write(block, state_var_stkoff: int) -> bool:
    """``True`` if *block* writes a non-state value (a "carrier") besides the
    state-var write / control flow.

    A predecessor-partitioned back-edge ``via_block`` is normally pure state-glue:
    its only effect is the dispatcher-state write that the unflatten emitter folds
    away, so the emitter bypasses it (``ip -> route(state)``) and lets the orphaned
    block DCE.  But a conditional handler whose two arms write the next state in
    separate blocks and then *converge* on one shared block can carry a LIVE
    non-state assignment on that shared block (the Approov ``v4 = a1`` carrier that
    executes on BOTH arms before re-entering the dispatcher).  Bypassing such a
    block drops the carrier and corrupts the recovered value.

    Detected conservatively: the block holds at least one instruction that is not a
    goto / nop, whose destination is a stack/register/lvar slot *other than* the
    state-var slot (a side-effecting data write the bypass would silently drop), or
    a call (whose side effects must not be skipped).  Pure state-glue blocks (only
    the state write + goto, or only a widen of the state slot) return ``False`` and
    keep the existing bypass behaviour byte-identical.
    """
    soff = int(state_var_stkoff)
    for insn in getattr(block, "insn_snapshots", ()):
        if _is_goto_insn(insn) or _is_nop_insn(insn):
            continue
        if _is_call_insn(insn):
            return True
        view = _eval_insn_view_snapshot(insn)
        dloc = _constant_dest_locator_snapshot(getattr(view, "d", None))
        if dloc is None:
            continue  # no resolvable data destination (control flow / unknown)
        kind, ident = dloc
        if kind == "stk" and int(ident) == soff:
            continue  # the state-var write itself -- folded/bypassed as glue
        return True  # a write to some other slot -> a live carrier
    return False


def _resolve_back_edge_states(
    flow_graph,
    *,
    dispatcher,
    state_var_stkoff: int,
    dispatcher_entry: int,
    max_depth: int,
    state_var_gaddr: int | None = None,
    foldable_global_reads: object | None = None,
) -> dict[int, set[int]]:
    """Per-region forward const-fold -> the state each back-edge writes.

    Walks forward from every region entry (each dispatcher target + the function
    prologue), carrying exact stack/register constants block-by-block.  Carrying
    *region-local* constants — rather than meeting across all predecessors —
    resolves opaque ``state = reg_a ^ reg_b`` / ``sub`` writes whose register
    operands are constants set earlier in the same handler region.  Whenever the
    walk reaches a block that branches back into the dispatcher, the folded
    state value at that block is recorded for that back-edge.  A back-edge that
    folds to two distinct states across different region paths is a
    predecessor-partitioned (opaque-split) write and is reported as ambiguous.

    ``state_var_gaddr`` / ``foldable_global_reads`` enable a *global* state
    variable (see :func:`recover_state_write_transitions_via_partitioned_fixpoint`):
    next-state writes/reads of that global are tracked/folded, and the recorded
    state is read from the gaddr key instead of the stack offset.
    """

    disp = int(dispatcher_entry)
    soff = int(state_var_stkoff)
    read_key = int(state_var_gaddr) if state_var_gaddr is not None else soff
    region_entries: set[int] = {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None
    }
    entry = getattr(flow_graph, "entry_serial", None)
    if entry is not None:
        region_entries.add(int(entry))
    region_entries.discard(disp)

    # Region-entry seed: the dispatch key that routes to each region. A masked /
    # switch-table dispatcher (``switch(state & MASK)``) reaches handler ``H`` iff
    # ``state & MASK == key``, and the handler writes ``state = (state & ~MASK) | M``;
    # folding that write to ``M`` needs the incoming low bits, which ARE that key.
    # Seeding the state var with it lets the forward fold resolve the masked-OR/XOR
    # write that an empty seed cannot. Restricted to *point* rows (``hi == lo + 1``,
    # an exact single-state key) so range-row BST routers (the equality-chain
    # spine, e.g. sub_7FFD) are untouched; targets with conflicting keys (a handler
    # shared by several states, whose state-dependent write would need all of them)
    # are left unseeded.
    entry_seed: dict[int, int] = {}
    seed_conflict: set[int] = set()
    for row in getattr(dispatcher, "_rows", ()):
        target = getattr(row, "target", None)
        lo = getattr(row, "lo", None)
        hi = getattr(row, "hi", None)
        if target is None or lo is None or hi is None or int(hi) != int(lo) + 1:
            continue
        tgt = int(target)
        key = int(lo) & 0xFFFFFFFF
        if tgt in entry_seed and entry_seed[tgt] != key:
            seed_conflict.add(tgt)
        else:
            entry_seed[tgt] = key
    for tgt in seed_conflict:
        entry_seed.pop(tgt, None)

    # back-edge serial -> { immediate predecessor (None at a region head) -> states }.
    # Partitioning by the immediate predecessor recovers opaque ``state =
    # reg_a ^ reg_b`` writes whose register operands are set to *different*
    # constants on each incoming edge (the LiSA disjunctive / predecessor-
    # partitioned case): each edge folds to its own state instead of collapsing
    # to an ambiguous set.
    back_edge_states: dict[int, dict[int | None, set[int]]] = {}
    for start in sorted(region_entries):
        seed_stk = {soff: entry_seed[start]} if start in entry_seed else {}
        stack: list[tuple[int, dict, dict, frozenset[int], int, int | None]] = [
            (start, seed_stk, {}, frozenset({start}), 0, None)
        ]
        while stack:
            blk_serial, in_stk, in_reg, visited, depth, parent = stack.pop()
            block = flow_graph.get_block(blk_serial)
            if block is None:
                continue
            out_stk, out_reg = _transfer_snapshot_constant_block(
                block, dict(in_stk), dict(in_reg), soff,
                state_var_gaddr=state_var_gaddr,
                foldable_global_reads=foldable_global_reads,
            )
            succs = tuple(int(s) for s in block.succs)
            if disp in succs:
                # This block branches back into the dispatcher -- it is a
                # back-edge (the region's transition point).  Record the folded
                # state keyed by the edge we arrived on, and STOP: do not walk
                # past it into the *next* region.
                value = out_stk.get(read_key)
                if value is not None:
                    back_edge_states.setdefault(blk_serial, {}).setdefault(
                        parent, set()
                    ).add(int(value) & 0xFFFFFFFF)
                continue
            if depth >= max_depth:
                continue
            for succ in succs:
                if succ == disp or succ in visited:
                    continue
                if _is_stop_block(flow_graph.get_block(succ)):
                    continue
                stack.append(
                    (succ, out_stk, out_reg, visited | {succ}, depth + 1, blk_serial)
                )
    return back_edge_states


def recover_state_write_transitions(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[StateWriteTransition, ...]:
    """Recover one transition per dispatcher back-edge (state-write block).

    For every predecessor ``P`` of the dispatcher, the next state ``S`` it writes
    is resolved by a per-region forward fold (see
    :func:`_resolve_back_edge_states`).  The transition is ``P -> route(S)``.
    Back-edges that do not fold to a single state (unresolved, or a
    predecessor-partitioned opaque split that needs block de-sharing) are
    returned as ``is_return`` so the emitter routes them to the shared return.
    """

    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()

    # Follow a dispatcher-header copy (compared state var <- next-state slot) so
    # the fold reads the slot handlers freshly write (OLLVM -fla shadow); a clean
    # chain returns the same offset unchanged.
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    back_edge_states = _resolve_back_edge_states(
        flow_graph,
        dispatcher=dispatcher,
        state_var_stkoff=effective_stkoff,
        dispatcher_entry=disp,
        max_depth=max_depth,
    )
    default = dispatcher.default_target

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        edge_states = back_edge_states.get(pred, {})
        all_states = {s for states in edge_states.values() for s in states}

        if len(all_states) == 1:
            # Unambiguous: every incoming edge folds to the same state -> redirect
            # the back-edge itself off the dispatcher.
            state = next(iter(all_states))
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
            continue

        if all_states and all(
            ipred is not None and len(states) == 1
            for ipred, states in edge_states.items()
        ):
            # Predecessor-partitioned (opaque ``reg_a ^ reg_b`` split): each
            # incoming edge folds to its own state.  The back-edge block is pure
            # state-glue, so bypass it -- redirect every predecessor straight to
            # its own routed handler.
            for ipred, states in sorted(edge_states.items()):
                state = next(iter(states))
                target, is_ret = _classify(state)
                ip_block = flow_graph.get_block(int(ipred))
                ip_arm = (
                    [int(s) for s in ip_block.succs].index(pred)
                    if ip_block is not None and ip_block.nsucc > 1 and pred in [int(s) for s in ip_block.succs]
                    else None
                )
                out.append(
                    StateWriteTransition(
                        int(ipred), state, target, is_ret, ip_arm, via_block=pred
                    )
                )
            continue

        # Unresolved (no fold, or a predecessor maps to multiple states) -> route
        # the back-edge to the shared return.
        out.append(StateWriteTransition(pred, None, None, True, arm))

    return tuple(out)


def recover_state_write_transitions_via_fixpoint(
    flow_graph,
    dispatcher,
    *,
    dispatcher_entry_serial: int,
    out_states,
) -> tuple[StateWriteTransition, ...]:
    """Shadow of :func:`recover_state_write_transitions` sourced from the fixpoint.

    Step C1 of the S4 flip (ticket llr-1szn): instead of the ad-hoc per-region fold
    (:func:`_resolve_back_edge_states`), the next state each dispatcher back-edge writes
    is read from the sound ``StateValue`` fixpoint's converged ``out_states[pred]``.  The
    routing (``dispatcher.lookup``), return classification, and ``branch_arm`` are the
    SAME as the production emitter, so a back-edge whose fixpoint state is a singleton
    emits a **byte-identical** :class:`StateWriteTransition`.

    It is single-partition, so it cannot emit the Case-2 predecessor-partitioned opaque
    ``reg ^ reg`` split (the ``via_block`` form): those back-edges fold to ``⊤`` / a
    multi-set here and emit as an unresolved return.  :func:`diff_back_edge_transitions`
    surfaces exactly that residual -- the edges the concrete / correlated fold (step C2)
    must close before the authoritative flip.  Diagnostic only; mutates nothing.
    """
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        sv = out_states.get(pred)
        usable = (
            sv is not None
            and not getattr(sv, "is_top", False)
            and not getattr(sv, "is_bottom", False)
        )
        constants = set(getattr(sv, "constants", ())) if usable else set()
        if len(constants) == 1:
            state = next(iter(constants))
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
        else:
            out.append(StateWriteTransition(pred, None, None, True, arm))
    return tuple(out)


def recover_state_write_transitions_via_multicell_fixpoint(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
) -> tuple[StateWriteTransition, ...]:
    """B1 shadow: source each back-edge's next state from the MULTI-CELL fixpoint.

    Step C2/B1 of the S4 flip (ticket llr-kz7n).  The single-cell
    :func:`recover_state_write_transitions_via_fixpoint` tracks only the state slot
    and so emits ``(None, None, True)`` for any back-edge whose write is an opaque
    ``state = reg_a ^ reg_b`` / ``sub`` fold — the register operands it needs are not
    in its store.  This variant runs the existing global stk+reg exact-constant
    fixpoint (:func:`run_snapshot_constant_fixpoint`, whose transfer is the SAME
    :func:`_transfer_snapshot_constant_block` the production fold uses) and reads the
    folded state-slot value out of each back-edge predecessor's converged ``out``
    store.  It is still **single-partition** (constants are MET across all incoming
    edges), so a back-edge whose register operands are set to *different* constants
    on different region paths still folds to ``⊥`` here and emits an unresolved
    return — that residual is the predecessor-partitioned (Case-2) case closed by the
    region-partitioned variant (B2).  Diagnostic only; mutates nothing.
    """
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target

    # Same effective offset resolution + transfer as the production fold; only the
    # walk strategy (global fixpoint vs per-region) differs.
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    fp = run_snapshot_constant_fixpoint(flow_graph, effective_stkoff)

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        value = fp.out_stk_maps.get(pred, {}).get(effective_stkoff)
        if value is not None:
            state = int(value) & 0xFFFFFFFF
            target, is_ret = _classify(state)
            out.append(StateWriteTransition(pred, state, target, is_ret, arm))
        else:
            out.append(StateWriteTransition(pred, None, None, True, arm))
    return tuple(out)


@dataclass(frozen=True, slots=True)
class _ResolverContext:
    """The per-function inputs the ranked next-state providers share (ticket llr-xauw).

    Bundles the converged fixpoint, the seeded region fold, the optional concrete
    leg, and the ``classify`` / ``arm_of`` closures so each provider is a small
    function of ``(ctx, pred, block, arm)`` -- the single ``resolve_next_state``
    sink walks them in rank order.  Pure data; ``classify``/``arm_of`` are the same
    closures the emit loop built, so every emitted transition is byte-identical.
    """

    flow_graph: object
    fp: object
    read_key: int
    effective_stkoff: int
    state_var_gaddr: int | None
    foldable_global_reads: object | None
    seeded: dict
    emu: object | None
    live_block_for: object | None
    state_cell: object | None
    classify: object
    arm_of: object


def _provider_global_fold(ctx: _ResolverContext, pred, block, arm):
    """[floor] Unambiguous global/const fold from the converged fixpoint (B1 case).

    When the fixpoint already folded the back-edge predecessor's state slot to a
    single value, redirect the back-edge itself.  ``None`` -> defer to the next
    provider (the abstract per-edge fold partitions by immediate predecessor).
    """
    value = ctx.fp.out_stk_maps.get(pred, {}).get(ctx.read_key)
    if value is None:
        return None
    state = int(value) & 0xFFFFFFFF
    target, is_ret = ctx.classify(state)
    return [
        StateWriteTransition(
            pred, state, target, is_ret, arm,
            proof=TransitionProof(_FIXPOINT_ORACLE, "global_fold", not is_ret),
        )
    ]


def _abstract_partition_states(ctx: _ResolverContext, block):
    """Per-immediate-predecessor abstract fold of a back-edge, or ``(None, True)``.

    Applies the back-edge block's transfer to each immediate predecessor's converged
    OUT store separately -- the same partitioning :func:`_resolve_back_edge_states`
    does by walking per region.  Returns ``(edge_states, ambiguous)``: ``ambiguous``
    is ``True`` (and ``edge_states`` partial) the moment any incoming edge cannot
    fold (``⊥``), the exact gap the concrete leg / seeded fold fill.
    """
    edge_states: dict[int, int] = {}
    for ip in sorted(int(p) for p in block.preds):
        ip_block = ctx.flow_graph.get_block(ip)
        if ip_block is None:
            return edge_states, True
        out_stk, _ = _transfer_snapshot_constant_block(
            block,
            dict(ctx.fp.out_stk_maps.get(ip, {})),
            dict(ctx.fp.out_reg_maps.get(ip, {})),
            ctx.effective_stkoff,
            state_var_gaddr=ctx.state_var_gaddr,
            foldable_global_reads=ctx.foldable_global_reads,
        )
        ev = out_stk.get(ctx.read_key)
        if ev is None:
            return edge_states, True
        edge_states[int(ip)] = int(ev) & 0xFFFFFFFF
    return edge_states, False


def _provider_predecessor_partitioned(ctx, pred, block, arm, edge_states, ambiguous):
    """[floor] Predecessor-partitioned opaque split / region-agreed plain redirect.

    Reads the abstract per-edge fold (``edge_states``).  A distinct state per
    immediate predecessor -> one ``via_block`` redirect each (the opaque
    ``reg ^ reg`` split, ``predecessor_partitioned``); every edge agreeing on one
    state -> a plain back-edge redirect (``region_agreed``).  ``None`` -> defer.
    """
    if ambiguous:
        return None
    distinct = set(edge_states.values())
    if edge_states and len(distinct) > 1:
        out: list[StateWriteTransition] = []
        for ip, state in sorted(edge_states.items()):
            target, is_ret = ctx.classify(state)
            ip_arm = ctx.arm_of(ctx.flow_graph.get_block(int(ip)), pred)
            out.append(
                StateWriteTransition(
                    int(ip), state, target, is_ret, ip_arm, via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE, "predecessor_partitioned", not is_ret
                    ),
                )
            )
        return out
    if len(distinct) == 1:
        state = next(iter(distinct))
        target, is_ret = ctx.classify(state)
        return [
            StateWriteTransition(
                pred, state, target, is_ret, arm,
                proof=TransitionProof(_FIXPOINT_ORACLE, "region_agreed", not is_ret),
            )
        ]
    return None


def _provider_emulation(ctx, pred, block, arm, ambiguous):
    """[refine] The reduced-product CONCRETE leg -- ⊥-only, fold_exact-gated.

    Consulted ONLY where the abstract per-edge fold landed at ``⊥`` (``ambiguous``):
    seeds the prove-exact-or-abstain emulator per immediate predecessor from its
    converged OUT store, steps the live back-edge block, and ``fold_exact``-validates
    each result.  ``None`` -> abstain (defer to the seeded fold) -- a partial
    emulation never half-resolves a back-edge.  Never reached for an
    abstract-resolved edge, so it can only forfeit precision, never corrupt.
    """
    if not ambiguous:
        return None
    if ctx.emu is None or ctx.live_block_for is None or ctx.state_cell is None:
        return None
    emu_states = _emulate_partition_states(
        ctx.emu, ctx.live_block_for, ctx.state_cell, ctx.fp, block, pred
    )
    if emu_states is None:
        return None
    out: list[StateWriteTransition] = []
    _emit_partition_transitions(
        out, emu_states, pred, arm, ctx.flow_graph, ctx.classify, ctx.arm_of,
        oracle_kind=_EMULATION_ORACLE,
        single_kind=_KIND_BACK_EDGE_CONCRETE_FOLD,
        split_kind=_KIND_CONCRETE_FOLD_PARTITIONED,
    )
    return out


def _provider_region_seeded(ctx, pred, block, arm):
    """[floor] The seeded per-region fold (masked-OR / state-reading write).

    The global meet collapses the state var to ⊥ at the dispatcher join, so a
    ``state = (state & ~MASK) | M`` write never folds via the fixpoint; seeding each
    region's entry with its dispatch key makes it fold to ``M``.  ``None`` -> defer
    to the unresolved sink.
    """
    out: list[StateWriteTransition] = []
    if _emit_seeded_back_edge(
        out, ctx.seeded.get(pred, {}), pred, arm, ctx.flow_graph, ctx.classify, ctx.arm_of
    ):
        return out
    return None


def _resolve_next_state(ctx: _ResolverContext, pred, block, arm):
    """Single resolution sink: walk the ranked providers, return the emitted edges.

    Priority (the proof is the only differentiator -- PART A, ticket llr-xauw):

      [floor]  predecessor_partitioned split -> global_fold -> region_agreed
      [refine] emulation_oracle  (⊥-only; seeded ConcreteStore; fold_exact-gated)
      [floor]  region_seeded
      [future] (clean extension point for symbolic/solver providers)
      else     -> unresolved (routed to the shared return)

    The first provider to return a non-``None`` list wins; the abstract per-edge
    fold is computed once and shared by the partitioned + emulation providers (the
    concrete leg fires only where the abstract fold is ⊥).

    A distinct predecessor-partitioned split is ranked before ``global_fold`` because
    a shared merge block may do ``state = temp`` after each incoming edge assigns a
    different constant to ``temp``.  The global meet can fail to resolve that temp
    and leave the incoming dispatcher state in the state slot, producing a stale
    self-loop route.  When every immediate predecessor independently folds to a
    concrete next-state, those edge-local writes are the real transition anchors.
    """
    # The abstract per-edge fold, computed once: it gates BOTH the predecessor-
    # partitioned floor provider (non-⊥) and the emulation refine provider (⊥).
    edge_states, ambiguous = _abstract_partition_states(ctx, block)

    # [floor] predecessor-partitioned split.  Prefer this over a stale global_fold
    # when a shared state-write merge has one concrete next-state per incoming edge.
    if not ambiguous and len(set(edge_states.values())) > 1:
        edges = _provider_predecessor_partitioned(
            ctx, pred, block, arm, edge_states, ambiguous
        )
        if edges is not None:
            return edges

    # [floor] unambiguous global/const fold (the B1 case).
    edges = _provider_global_fold(ctx, pred, block, arm)
    if edges is not None:
        return edges

    # [floor] region-agreed plain redirect from the per-edge fold.
    edges = _provider_predecessor_partitioned(
        ctx, pred, block, arm, edge_states, ambiguous
    )
    if edges is not None:
        return edges

    # [refine] the reduced-product CONCRETE leg -- BEFORE the seeded fold can mask a
    # ⊥ with a stale dispatch-key self-loop.
    edges = _provider_emulation(ctx, pred, block, arm, ambiguous)
    if edges is not None:
        return edges

    # [floor] the seeded per-region fold (masked-OR / state-reading write).
    edges = _provider_region_seeded(ctx, pred, block, arm)
    if edges is not None:
        return edges

    # [future] symbolic / solver providers slot in here, ranked below the floor and
    # the concrete leg, above the unresolved sink.

    # else -> unresolved: route the back-edge to the shared return.
    return [
        StateWriteTransition(
            pred, None, None, True, arm,
            proof=TransitionProof(_FIXPOINT_ORACLE, "unresolved", False),
        )
    ]


def recover_state_write_transitions_via_partitioned_fixpoint(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int,
    recover_terminal_tail: bool = False,
    initial_state: int | None = None,
    emu: "EmulationCapability | None" = None,
    live_block_for: "object | None" = None,
) -> tuple[StateWriteTransition, ...]:
    """B2 shadow: predecessor-partitioned multi-cell fold -> the Case-2 ``via_block`` split.

    Step C2/B2 of the S4 flip (ticket llr-kz7n).  The single-partition multi-cell
    fixpoint (:func:`recover_state_write_transitions_via_multicell_fixpoint`) MEETs
    constants across all incoming edges of a back-edge block, so an opaque
    ``state = reg_a ^ reg_b`` write whose register operands are set to *different*
    constants on different region paths folds to ``⊥`` there (the Case-2 residual).

    This variant reads the SAME global stk+reg fixpoint, but when a back-edge does
    not fold unambiguously it **partitions by immediate predecessor**: it applies the
    back-edge block's own transfer (:func:`_transfer_snapshot_constant_block`) to each
    immediate predecessor's converged OUT store *separately*, recovering the per-edge
    folded state.  When every incoming edge folds to its own single state, it emits
    the production ``via_block`` split — ``ipred -> route(state)`` bypassing the shared
    back-edge — mirroring :func:`recover_state_write_transitions`'s Case-2 branch and
    the per-region / immediate-predecessor keying of :func:`_resolve_back_edge_states`.
    Diagnostic only; mutates nothing.

    Reduced-product CONCRETE leg (ticket llr-xauw): ``emu`` is an optional
    prove-exact-or-abstain :class:`EmulationCapability`; ``live_block_for`` maps a
    block serial to the live backend block the emulator steps.  Both default to
    ``None`` -> EXACTLY the abstract-only behaviour above (no change).  When supplied,
    a back-edge whose abstract per-edge fold lands at ``⊥`` (the opaque
    ``reg ^ reg``-next-state writers whose operands live in OTHER blocks) is consulted
    against the concrete leg, SEEDED from the immediate predecessor's converged OUT
    store; a fold that ``fold_exact``-validates emits a RESOLVED transition tagged
    ``_EMULATION_ORACLE``.  The consult fires ONLY at the genuine ⊥ gap -- it never
    overrides a fixpoint-resolved transition.
    """
    state_cell = LocationRef.stack(int(state_var_stkoff), 8) if emu is not None else None
    disp = int(dispatcher_entry_serial)
    disp_block = flow_graph.get_block(disp)
    if disp_block is None:
        return ()
    default = dispatcher.default_target
    effective_stkoff = _resolve_state_var_alias(flow_graph, disp, int(state_var_stkoff))
    # A handler can write its NEXT state through a global it reads (Approov:
    # ``state = (qword |= 0xF6A20)`` where ``qword`` is a zero-initialised ``.data``
    # global).  ``state_var_gaddr`` flags the rarer case where a global IS the
    # dispatcher state variable (Hex-Rays forward-substituted the ``state = global``
    # copy into the header); ``None`` for the ordinary stack/register state var.
    # ``foldable_global_reads`` folds reaching-defs-stable global reads to their
    # static initializer -- anchored at the INITIAL handler (the dispatcher target
    # for the entry state), which runs before any handler store -- so the
    # data-dependent next-state resolves.  None/empty -> unchanged behaviour.
    state_var_gaddr = _detect_global_state_var(flow_graph, disp)
    initial_handler = (
        dispatcher.lookup(int(initial_state) & 0xFFFFFFFF)
        if initial_state is not None
        else None
    )
    foldable_global_reads = _compute_foldable_global_reads(
        flow_graph, disp, initial_handler
    )
    read_key = int(state_var_gaddr) if state_var_gaddr is not None else effective_stkoff
    if foldable_global_reads and logger.debug_on:
        logger.debug(
            "partitioned_fixpoint: global init folds (init_handler=%s) %s",
            initial_handler,
            {
                hex(ea): {hex(g): hex(v) for g, v in m.items()}
                for ea, m in foldable_global_reads.items()
            },
        )
    fp = run_snapshot_constant_fixpoint(
        flow_graph,
        effective_stkoff,
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
    )
    # Seeded per-region fold (additive fallback): the global meet collapses the
    # state var to bottom at the dispatcher join, so a masked-OR / state-reading
    # write (``state = (state & ~MASK) | M``, abc_or_dispatch) never folds via the
    # fixpoint. _resolve_back_edge_states seeds each region's entry with its
    # dispatch key, which makes that write fold to ``M``. Used ONLY for back-edges
    # the fixpoint leaves unresolved -- it never overrides a fixpoint result.
    seeded = _resolve_back_edge_states(
        flow_graph,
        dispatcher=dispatcher,
        state_var_stkoff=effective_stkoff,
        dispatcher_entry=disp,
        max_depth=_MAX_CORRIDOR_DEPTH,
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
    )

    def _classify(state: int) -> tuple[int | None, bool]:
        routed = dispatcher.lookup(state)
        if routed is None:
            return None, True
        if default is not None and int(routed) == int(default):
            return int(routed), True
        if _is_stop_block(flow_graph.get_block(int(routed))):
            return int(routed), True
        return int(routed), False

    def _arm(block, succ_target: int) -> int | None:
        s = [int(x) for x in block.succs]
        return s.index(succ_target) if block.nsucc > 1 and succ_target in s else None

    if logger.debug_on:
        logger.debug(
            "partitioned_fixpoint: disp=%d preds=%s seeded_back_edges=%s",
            disp,
            sorted(int(p) for p in disp_block.preds),
            {k: sorted({s for v in m.values() for s in v}) for k, m in seeded.items()},
        )

    # PART A (ticket llr-xauw): one resolution sink.  Every back-edge flows through
    # ``_resolve_next_state``, which tries the ranked PROVIDERS in priority order --
    # each stamps its own ``TransitionProof`` so the ``proof`` field (not a parallel
    # emit branch) is the only differentiator between resolution methods.  The
    # ordering and per-provider behaviour are byte-identical to the previous
    # if/elif chain; only the emit site collapses to a single ``out.extend``.
    resolver_ctx = _ResolverContext(
        flow_graph=flow_graph,
        fp=fp,
        read_key=read_key,
        effective_stkoff=effective_stkoff,
        state_var_gaddr=state_var_gaddr,
        foldable_global_reads=foldable_global_reads,
        seeded=seeded,
        emu=emu,
        live_block_for=live_block_for,
        state_cell=state_cell,
        classify=_classify,
        arm_of=_arm,
    )
    out: list[StateWriteTransition] = []
    for pred in sorted(int(p) for p in disp_block.preds):
        block = flow_graph.get_block(pred)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp not in succs:
            continue
        arm = succs.index(disp) if len(succs) > 1 else None
        out.extend(_resolve_next_state(resolver_ctx, pred, block, arm))

    # Terminal-tail back-edges (Tigress decoy-exit shape): a state-write block
    # whose successor is a STOP/terminal (or otherwise never re-enters the
    # dispatcher) names its next state in the written const just as a normal
    # back-edge does, but it is NOT a dispatcher predecessor, so the loop above
    # never visits it and its valid transition is dropped (the legacy walk
    # misclassified it ``successor_kind="exit"``).  The transition is purely
    # ``block -> route(N)`` via the dispatch map -- walking successors is
    # unnecessary.  Recover it whenever the block's folded state routes to a real
    # handler; redirect its existing (terminal) successor edge onto that handler.
    #
    # INDIRECT-only (ticket llr-m9r4): this recovery is load-bearing for the
    # Tigress INDIRECT_JUMP decoy-exit shape (it kills a JUMPOUT) but ADDS
    # spurious terminal-tail transitions for equality-chain / switch profiles
    # (hodur, approov), which regressed their goldens.  Gated to the indirect
    # caller so non-indirect profiles get exactly their pre-change behavior.
    if recover_terminal_tail:
        out.extend(
            _recover_terminal_tail_transitions(
                flow_graph,
                fp,
                effective_stkoff,
                disp=disp,
                emitted=out,
                classify=_classify,
                arm_of=_arm,
            )
        )
    return tuple(out)


def _recover_terminal_tail_transitions(
    flow_graph,
    fp,
    effective_stkoff: int,
    *,
    disp: int,
    emitted: list,
    classify,
    arm_of,
) -> list[StateWriteTransition]:
    """Wire state-write blocks that route via the dispatch map but never re-enter
    the dispatcher (their successor is a STOP/terminal).

    Driven entirely by the dispatch map: a block whose converged out-state is a
    valid handler route (not return/default/STOP) is a legitimate transition
    ``block -> route(N)`` regardless of its ``successor_kind``.  Only blocks that
    (a) are not already emitted as a source/inner-predecessor, (b) are not
    dispatcher predecessors, and (c) cannot reach the dispatcher through their
    successor chain are considered -- so interior fall-throughs into a shared
    glue back-edge (handled by the predecessor-partitioned ``via_block`` split)
    are never double-wired.
    """
    already: set[int] = {int(t.write_block) for t in emitted}
    extra: list[StateWriteTransition] = []
    for serial in sorted(flow_graph.blocks):
        if serial == disp or int(serial) in already:
            continue
        block = flow_graph.get_block(serial)
        if block is None:
            continue
        succs = tuple(int(s) for s in block.succs)
        if disp in succs:
            continue  # a real dispatcher predecessor -- handled above
        value = fp.out_stk_maps.get(serial, {}).get(effective_stkoff)
        if value is None:
            continue
        state = int(value) & 0xFFFFFFFF
        target, is_ret = classify(state)
        if is_ret or target is None:
            continue  # not a real handler route -- leave as natural control flow
        if _reaches_dispatcher(flow_graph, serial, disp):
            continue  # interior write feeding a shared back-edge -- already wired
        # The block's successor is a terminal/non-dispatcher edge.  The emitter
        # redirects ``write_block -> dispatcher`` for a normal back-edge, but
        # this block points at its terminal successor, not the dispatcher.  Carry
        # that successor as ``via_block`` so the emitter re-points the existing
        # ``block -> successor`` edge onto the routed handler instead.
        if not succs:
            continue  # nothing to re-point (a true sink with no out-edge)
        old = succs[0]
        arm = arm_of(block, old)
        extra.append(
            StateWriteTransition(
                serial, state, target, False, arm, via_block=old,
                proof=TransitionProof(_FIXPOINT_ORACLE, "terminal_tail", True),
            )
        )
        already.add(int(serial))
    return extra


def _reaches_dispatcher(flow_graph, start: int, disp: int, *, bound: int = 64) -> bool:
    """``True`` if the dispatcher is forward-reachable from ``start`` (bounded)."""
    seen: set[int] = set()
    stack = [int(start)]
    steps = 0
    while stack and steps < bound:
        steps += 1
        cur = stack.pop()
        if cur in seen:
            continue
        seen.add(cur)
        block = flow_graph.get_block(cur)
        if block is None:
            continue
        for s in block.succs:
            si = int(s)
            if si == disp:
                return True
            if si not in seen:
                stack.append(si)
    return False


def _emit_seeded_back_edge(
    out: list,
    edge_map: dict[int | None, set[int]],
    pred: int,
    arm: int | None,
    flow_graph,
    classify,
    arm_of,
) -> bool:
    """Append a seeded-fold transition for a back-edge, or return ``False``.

    ``edge_map`` is ``_resolve_back_edge_states[pred]`` (immediate-pred -> states).
    Mirrors the global/partitioned emit shape: a single agreed state -> a plain
    back-edge redirect; one distinct state per immediate predecessor -> the
    ``via_block`` split.  Returns ``True`` when a transition was appended.
    """
    all_states = {s for states in edge_map.values() for s in states}
    if len(all_states) == 1:
        state = next(iter(all_states))
        target, is_ret = classify(state)
        out.append(
            StateWriteTransition(
                pred, state, target, is_ret, arm,
                proof=TransitionProof(_FIXPOINT_ORACLE, "region_seeded", not is_ret),
            )
        )
        return True
    if all_states and all(
        ip is not None and len(states) == 1 for ip, states in edge_map.items()
    ):
        for ip, states in sorted(edge_map.items()):
            state = next(iter(states))
            target, is_ret = classify(state)
            ip_block = flow_graph.get_block(int(ip))
            ip_arm = arm_of(ip_block, pred) if ip_block is not None else None
            out.append(
                StateWriteTransition(
                    int(ip), state, target, is_ret, ip_arm, via_block=pred,
                    proof=TransitionProof(
                        _FIXPOINT_ORACLE, "region_seeded_partitioned", not is_ret
                    ),
                )
            )
        return True
    return False


def _emulate_partition_states(emu, live_block_for, state_cell, fp, block, pred):
    """Per-immediate-predecessor concrete next-states for a ⊥ back-edge, or ``None``.

    The reduced-product CONCRETE leg (ticket llr-xauw).  For each immediate
    predecessor ``ip`` of the back-edge ``block``, the prove-exact-or-abstain
    emulator steps the live back-edge block (resolved by serial through
    ``live_block_for``) SEEDED from ``ip``'s converged OUT store;
    :func:`_emulate_unresolved_state` ``fold_exact``-validates each result before it
    is trusted.  Returns ``{ip -> state}`` only when EVERY incoming edge resolves;
    ``None`` on the first abstain (the caller then falls through to the unchanged
    seeded/unresolved logic -- a partial emulation never half-resolves a back-edge).
    """
    edge_states: dict[int, int] = {}
    for ip in sorted(int(p) for p in block.preds):
        concrete = _emulate_unresolved_state(
            emu,
            live_block_for(int(pred)),
            _seed_concrete_store(
                dict(fp.out_stk_maps.get(ip, {})),
                dict(fp.out_reg_maps.get(ip, {})),
            ),
            state_cell,
        )
        if concrete is None:
            return None  # any ⊥ residual -> abstain wholesale (stay seeded/unresolved)
        edge_states[int(ip)] = int(concrete) & 0xFFFFFFFF
    return edge_states or None


def _emit_partition_transitions(
    out: list,
    edge_states: dict[int, int],
    pred: int,
    arm: int | None,
    flow_graph,
    classify,
    arm_of,
    *,
    oracle_kind: str,
    single_kind: str,
    split_kind: str,
) -> None:
    """Emit the back-edge redirect(s) for a per-predecessor state map.

    Mirrors the global/seeded emit shape: every incoming edge agreeing on one state
    -> a plain ``pred -> route(state)`` redirect; a distinct state per immediate
    predecessor -> one ``via_block=pred`` split each.  ``oracle_kind``/``single_kind``
    /``split_kind`` stamp the :class:`TransitionProof` so the proof distribution
    distinguishes the concrete leg from the abstract oracle.
    """
    distinct = set(edge_states.values())
    if len(distinct) == 1:
        state = next(iter(distinct))
        target, is_ret = classify(state)
        out.append(
            StateWriteTransition(
                pred, state, target, is_ret, arm,
                proof=TransitionProof(oracle_kind, single_kind, not is_ret),
            )
        )
        return
    for ip, state in sorted(edge_states.items()):
        target, is_ret = classify(state)
        ip_block = flow_graph.get_block(int(ip))
        ip_arm = arm_of(ip_block, pred) if ip_block is not None else None
        out.append(
            StateWriteTransition(
                int(ip), state, target, is_ret, ip_arm, via_block=pred,
                proof=TransitionProof(oracle_kind, split_kind, not is_ret),
            )
        )


def diff_back_edge_transitions(production, fixpoint) -> dict:
    """Per-back-edge agreement between the production fold and the fixpoint shadow.

    Keys on ``write_block``.  A production Case-2 split (``via_block`` set) keys on the
    inner predecessor the single-partition fixpoint never emits, so it is bucketed
    ``case2_opaque`` (the expected residual, not a regression).  Returns a summary +
    the mismatching rows (``write_block``, production ``(state, target, is_return)``,
    fixpoint ``(state, target, is_return)`` or ``None``).
    """
    fmap = {t.write_block: t for t in fixpoint}
    matched = 0
    case2_opaque = 0
    mismatch: list = []
    for t in production:
        if t.via_block is not None:
            case2_opaque += 1
            continue
        f = fmap.get(t.write_block)
        if (
            f is not None
            and f.next_state == t.next_state
            and f.target_handler == t.target_handler
            and f.is_return == t.is_return
        ):
            matched += 1
        else:
            mismatch.append(
                (
                    t.write_block,
                    (t.next_state, t.target_handler, t.is_return),
                    None
                    if f is None
                    else (f.next_state, f.target_handler, f.is_return),
                )
            )
    return {
        "prod_edges": len(production),
        "fixpoint_edges": len(fixpoint),
        "matched": matched,
        "case2_opaque": case2_opaque,
        "mismatch": mismatch,
    }


def diff_back_edge_transitions_partitioned(production, fixpoint) -> dict:
    """B2-aware per-back-edge agreement: also matches the Case-2 ``via_block`` splits.

    Unlike :func:`diff_back_edge_transitions` (which buckets every production
    ``via_block`` row as an unverified ``case2_opaque`` residual), this keys split
    rows on ``(write_block, via_block)`` so the predecessor-partitioned shadow
    (:func:`recover_state_write_transitions_via_partitioned_fixpoint`) is checked
    edge-for-edge against production.  A production split that the partitioned shadow
    reproduces (same ``next_state`` / ``target_handler`` / ``is_return``) counts as
    ``matched``; one it does not reproduce becomes ``case2_opaque`` (still residual);
    plain (non-split) rows behave exactly as in the single-partition diff.
    """

    def _key(t):
        return (t.write_block, t.via_block)

    fmap = {_key(t): t for t in fixpoint}
    matched = 0
    case2_opaque = 0
    mismatch: list = []
    for t in production:
        f = fmap.get(_key(t))
        agrees = (
            f is not None
            and f.next_state == t.next_state
            and f.target_handler == t.target_handler
            and f.is_return == t.is_return
        )
        if agrees:
            matched += 1
        elif t.via_block is not None:
            # Unreproduced predecessor-partitioned split -> still the Case-2 residual.
            case2_opaque += 1
        else:
            mismatch.append(
                (
                    t.write_block,
                    (t.next_state, t.target_handler, t.is_return),
                    None
                    if f is None
                    else (f.next_state, f.target_handler, f.is_return),
                )
            )
    return {
        "prod_edges": len(production),
        "fixpoint_edges": len(fixpoint),
        "matched": matched,
        "case2_opaque": case2_opaque,
        "mismatch": mismatch,
    }


@dataclass(frozen=True, slots=True)
class TransitionArm:
    """One outgoing edge of a handler.

    A handler with a single arm is an unconditional transition; multiple arms
    (distinct ``next_state``) are a conditional transition selected by
    ``branch_block``'s 2-way branch.
    """

    next_state: int | None       # folded next-state value (None => no write found)
    target_handler: int | None   # dispatcher route of next_state (None when unresolved)
    is_return: bool              # routes to exit/STOP, or no next-state at all
    branch_block: int | None     # the 2-way block that selected this arm (None => unconditional)
    write_block: int | None      # block whose state-var write produced next_state
    exit_block: int | None       # last block of the scanned path (the boundary)
    ordered_path: tuple[int, ...] = ()  # handler-local blocks visited (entry..exit)


@dataclass(frozen=True, slots=True)
class HandlerTransition:
    """All outgoing edges recovered for one handler block."""

    handler: int                 # handler entry block serial
    states: tuple[int, ...]      # representative states the dispatcher routes here
    arms: tuple[TransitionArm, ...]

    @property
    def is_conditional(self) -> bool:
        return len(self.arms) > 1


def _handler_entries(dispatcher) -> set[int]:
    """Distinct handler blocks the dispatcher routes to (excluding the default/exit)."""
    default = dispatcher.default_target
    return {
        int(row.target)
        for row in getattr(dispatcher, "_rows", ())
        if row.target is not None and int(row.target) != (int(default) if default is not None else None)
    }


def _states_by_handler(dispatcher) -> dict[int, list[int]]:
    """Map handler block -> representative state values routed to it (one per row lo)."""
    out: dict[int, list[int]] = {}
    for row in getattr(dispatcher, "_rows", ()):
        if row.target is None:
            continue
        out.setdefault(int(row.target), []).append(int(row.lo))
    return out


def _scan_handler(
    flow_graph,
    entry: int,
    *,
    state_var_stkoff: int,
    dispatcher_entry_serial: int | None,
    handler_entries: set[int],
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> list[tuple[int | None, int | None, tuple[int, ...]]]:
    """Strictly handler-local forward scan from *entry*.

    Returns a list of ``(next_state, branch_block, ordered_path)`` — one entry
    per distinct terminal path.  ``next_state`` is the last folded state-var
    value on that path (``None`` if the handler writes no next-state).
    ``ordered_path`` is the blocks visited (entry..boundary), used downstream to
    pick the redirect source.  The scan stops at: the dispatcher entry, any
    *other* handler's entry block, or a STOP/terminal.
    """

    results: list[tuple[int | None, int | None, tuple[int, ...]]] = []
    # stack frames: (block, stk_map, reg_map, branch_block, visited, depth, path)
    stack: list[tuple[int, dict, dict, int | None, frozenset[int], int, tuple[int, ...]]] = [
        (int(entry), {}, {}, None, frozenset({int(entry)}), 0, (int(entry),))
    ]

    while stack:
        blk_serial, stk, reg, branch, visited, depth, path = stack.pop()
        block = flow_graph.get_block(blk_serial)
        if block is None:
            results.append((stk.get(state_var_stkoff), branch, path))
            continue

        # Fold this block's state-var write into the carried const env.
        nstk, nreg = _transfer_snapshot_constant_block(
            block, dict(stk), dict(reg), state_var_stkoff
        )
        running_state = nstk.get(state_var_stkoff)

        succs = tuple(int(s) for s in block.succs)

        def _is_boundary_succ(s: int) -> bool:
            if dispatcher_entry_serial is not None and s == int(dispatcher_entry_serial):
                return True
            if s in handler_entries and s != int(entry):
                return True
            succ_block = flow_graph.get_block(s)
            return _is_stop_block(succ_block)

        onward = [
            s
            for s in succs
            if s not in visited and not _is_boundary_succ(s)
        ]

        terminal = (
            not succs
            or _is_stop_block(block)
            or not onward
            or depth >= max_depth
        )
        if terminal:
            results.append((running_state, branch, path))
            continue

        # A 2-way block whose arms continue is a state-selecting branch -- EXCEPT a
        # 2-way that branches straight to the dispatcher entry (one successor IS the
        # dispatcher back-edge).  That block is the loop-back / pre-header join every
        # handler funnels through, not a state selector; attributing the branch there
        # points the conditional-arm redirect at the dispatcher pre-header instead of
        # the real in-handler selector (the identity-switch ``state = cond ? a : b``
        # shape, where the selector is upstream and the arms reconverge before looping
        # back). Keeping the prior branch in that case leaves the attribution on the
        # true upstream selector. Narrow exclusion (dispatcher-edge only) so the
        # equality-chain conditional handlers (hodur) keep their existing attribution.
        branches_to_dispatcher = (
            dispatcher_entry_serial is not None
            and int(dispatcher_entry_serial) in succs
        )
        new_branch = (
            blk_serial if (len(succs) >= 2 and not branches_to_dispatcher) else branch
        )
        for s in onward:
            stack.append(
                (s, nstk, nreg, new_branch, visited | {s}, depth + 1, path + (s,))
            )

    return results


def _classify_arm(
    next_state: int | None,
    branch_block: int | None,
    ordered_path: tuple[int, ...],
    *,
    dispatcher,
    flow_graph,
) -> TransitionArm:
    default = dispatcher.default_target
    exit_block = ordered_path[-1] if ordered_path else None
    target: int | None = None
    is_return = False
    if next_state is None:
        is_return = True
    else:
        routed = dispatcher.lookup(int(next_state) & 0xFFFFFFFF)
        if routed is None:
            is_return = True
        elif default is not None and int(routed) == int(default):
            target = int(routed)
            is_return = True
        elif _is_stop_block(flow_graph.get_block(int(routed))):
            target = int(routed)
            is_return = True
        else:
            target = int(routed)
    return TransitionArm(
        next_state=(int(next_state) & 0xFFFFFFFF) if next_state is not None else None,
        target_handler=target,
        is_return=is_return,
        branch_block=branch_block,
        write_block=exit_block,
        exit_block=exit_block,
        ordered_path=tuple(ordered_path),
    )


def recover_handler_transitions(
    flow_graph,
    dispatcher,
    state_var_stkoff: int,
    *,
    dispatcher_entry_serial: int | None = None,
    max_depth: int = _MAX_CORRIDOR_DEPTH,
) -> tuple[HandlerTransition, ...]:
    """Recover each handler's outgoing transition(s) via the minimal model.

    Args:
        flow_graph: a :class:`d810.ir.flowgraph.FlowGraph` snapshot.
        dispatcher: an :class:`IntervalDispatcher` (state value -> handler block).
        state_var_stkoff: the dispatcher state variable's stack offset.
        dispatcher_entry_serial: the dispatcher block the handlers loop back to;
            used as a scan boundary.  Falls back to the dispatcher's most-routed
            block when not supplied is intentionally NOT done — callers should
            pass it.
        max_depth: corridor-scan bound.

    Returns:
        One :class:`HandlerTransition` per handler block, ordered by serial.
    """

    handler_entries = _handler_entries(dispatcher)
    states_by_handler = _states_by_handler(dispatcher)
    results: list[HandlerTransition] = []

    for handler in sorted(handler_entries):
        paths = _scan_handler(
            flow_graph,
            handler,
            state_var_stkoff=int(state_var_stkoff),
            dispatcher_entry_serial=dispatcher_entry_serial,
            handler_entries=handler_entries,
            max_depth=max_depth,
        )
        # Dedup arms by next_state: identical next-states on multiple paths are
        # the same edge (a degenerate branch), not a conditional.
        seen: dict[int | None, TransitionArm] = {}
        for next_state, branch_block, ordered_path in paths:
            key = (int(next_state) & 0xFFFFFFFF) if next_state is not None else None
            if key in seen:
                continue
            seen[key] = _classify_arm(
                next_state,
                branch_block,
                ordered_path,
                dispatcher=dispatcher,
                flow_graph=flow_graph,
            )
        arms = tuple(seen.values())
        # A multi-path handler whose arms all fold to the same state collapses to
        # one unconditional arm with no branch attribution.
        if len(arms) == 1:
            arms = (
                TransitionArm(
                    next_state=arms[0].next_state,
                    target_handler=arms[0].target_handler,
                    is_return=arms[0].is_return,
                    branch_block=None,
                    write_block=arms[0].write_block,
                    exit_block=arms[0].exit_block,
                    ordered_path=arms[0].ordered_path,
                ),
            )
        results.append(
            HandlerTransition(
                handler=int(handler),
                states=tuple(sorted(states_by_handler.get(int(handler), ()))),
                arms=arms,
            )
        )

    return tuple(results)
