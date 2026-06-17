"""``ConcolicEmulationEngine`` -- CFF recovery by concrete execution (P2, ticket llr-8wq9).

The static-shape resolvers recognize a dispatcher by its compare *shape*; the
abstract-interpretation engine (P3) over-approximates the reachable state set. This
engine recovers a machine the EXACT-but-bounded way: by EXECUTING it. Seeded with
the anchor's initial state(s), it emulates the dispatcher to find the handler a
concrete state routes to (the selector projection is *evaluated*, so any shape
works), emulates the handler to find the next state(s), and FORKS at a conditional
handler (both arms), over a visited set. The result is tagged
``Soundness.EXACT_BOUNDED`` (design §5): exact within the explored region, silent
outside it -- so the P4 orchestrator admits its transitions only through the
completeness gate (§7).

This is the lean contract-behind replacement for the legacy
``EmulatedDispatcherUnflattener``. It reuses the PROVEN Slice 5 live oracles
(``EmulationDispatcherResolver._emulate_to_handler`` / helpers) by composition --
never forking them -- and adds two things on top:

1. **Selector-anchored discovery** (``dispatcher_anchor_discovery``) so an identity
   ``switch(state)`` machine is anchored on the SWITCHED slot, not the dominant
   self-update accumulator (fixes ``high_fan_in_pattern`` mis-ID).
2. **First-class forking transitions**: the walk core already fans both ``?:`` arms
   out; this engine RECORDS the edge ``state -> {a, b} via_block`` (Slice 5 kept
   only rows) and enumerates an identity-switch handler's ``mov #const`` next-state
   arms (which the self-update-only Slice 5 region scan misses). Complete-arm
   enumeration or abstain (§7) -- never a partial fork.

MBA next-state folding is inherited from the host stepper (``mask_subreg_reads`` +
the interpreter UD-chain history), so the XOR-masked selector path stays
byte-identical. Bounded interprocedural call folding (design §5) is a planned strict
extension -- it can only turn an abstained ``None`` into a proven handler, never
change a proven one -- tracked for a follow-up live-mba slice; until then an
un-foldable call leaves that state unresolved (sound abstain), never a wrong edge.
The ``ConcolicProvenance`` carries the ``fold_count`` / ``call_depth_hit`` slots
that extension will populate.

IDA-dependent (live ``mba`` + interpreter) -> Hex-Rays backend; the contract it
emits (``RecoveredMachine``) is portable.
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.analyses.control_flow.concolic_machine_walk import (
    ForkOutcome,
    WalkTransition,
    walk_forking_state_machine,
)
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.emulated_state_walk import DEFAULT_MAX_STATES
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.analyses.control_flow.minimal_state_recovery import _resolve_state_var_alias
from d810.analyses.value_flow.global_init_fold import (
    compute_initializer_stable_global_reads,
)
from d810.capabilities.providers import get_condition_chain_walkers
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    _SELF_UPDATE_OPS,
    EmulationDispatcherResolver,
    _Discovery,
)
from d810.core.logging import getLogger
from d810.core.observability_labels import live_block_label
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.analyses.concolic_emulation_engine")

__all__ = ["RecoveryCaps", "ConcolicProvenance", "ConcolicEmulationEngine"]

#: Bound on the dead-store liveness DFS (``_reaches_entry_unrewritten``): a flattened handler
#: region is O(handlers) blocks, so this matches the region-scan bound -- far past any real
#: obfuscated handler body (ticket llr-iy9i round 4).
_DEAD_STORE_SCAN_BOUND = 64


@dataclass(frozen=True, slots=True)
class RecoveryCaps:
    """Bounding budget for one ``recover`` call (the ``caps`` bundle, design §6).

    Defaults mirror the Slice 5 resolver constants exactly so the routed XOR path is
    byte-identical. ``max_call_depth`` is the NEW interprocedural bound.
    """

    max_states: int = DEFAULT_MAX_STATES  # = emulated_state_walk.DEFAULT_MAX_STATES
    max_call_depth: int = 3
    max_dispatch_steps: int = 256  # = resolver._MAX_DISPATCH_STEPS
    max_region_blocks: int = 64  # = resolver._MAX_REGION_BLOCKS
    min_recovered_rows: int = 2  # = resolver._MIN_RECOVERED_ROWS


@dataclass
class ConcolicProvenance:
    """Rich per-recover bookkeeping (serialized into the contract ``provenance`` tuple).

    The frozen ``RecoveredMachine.provenance`` is ``tuple[str, ...]``; this mutable
    accumulator holds the structured counters the engine maintains during the walk,
    flattened to strings on assembly so the contract stays a pure-data leaf.
    """

    engine_name: str = "concolic_emulation"
    visited_state_count: int = 0
    unresolved_state_count: int = 0
    terminal_state_count: int = 0
    truncated: bool = False
    call_depth_hit: bool = False
    fold_count: int = 0
    diverged_states: tuple[int, ...] = ()

    def as_tuple(self) -> tuple[str, ...]:
        return (
            self.engine_name,
            "visited=%d" % self.visited_state_count,
            "unresolved=%d" % self.unresolved_state_count,
            "terminal=%d" % self.terminal_state_count,
            "truncated=%s" % self.truncated,
            "call_depth_hit=%s" % self.call_depth_hit,
            "fold_count=%d" % self.fold_count,
            "diverged=%d" % len(self.diverged_states),
        )


@dataclass(frozen=True)
class _ForkRegionFacts:
    """A handler region summarized as a SET of arm transitions (>=1; 2 = conditional).

    ``arms`` is ``(opcode, const)`` per arm; ``opcode is None`` marks a
    ``mov #const`` next-state arm. EMPTY ``arms`` + ``reaches_ret`` is a pure exit.
    ``complete`` is False when an arm's next-state could not be proven -- then the
    handler is returned as UNRESOLVED (abstain), never a partial fork (§7).
    """

    arms: tuple[tuple[int | None, int | None], ...]
    reaches_ret: bool
    via_block: int
    complete: bool = True


@dataclass
class ConcolicEmulationEngine:
    """Recover a CFF machine by CONCRETE EXECUTION (design §5, soundness=EXACT_BOUNDED).

    ``mba`` is the live function microcode bound at construction (re-bound each
    decompilation). ``enabled`` carries the per-project opt-in: when ``False``,
    ``recover`` returns ``None`` immediately so the engine is inert (registered
    UNCONDITIONALLY every decompile so its bound ``mba`` is always fresh -- a stale
    ``mba`` left in the process-global registry would segfault a later non-opted-in
    function; staleness rule, plan §11).
    """

    mba: ida_hexrays.mba_t
    enabled: bool = True
    name: str = "concolic_emulation"

    # Per-recover global-carried next-state context (ticket llr-k8oa), set in
    # ``recover``: the live FlowGraph + dispatcher entry the reaching-defs barrier
    # needs, plus a per-handler ``foldable_global_reads`` cache.  ``None`` outside a
    # recover; reset every call so a re-bound ``mba`` never reads a stale graph.
    _fgr_graph: object | None = None
    _fgr_entry: int | None = None
    _fgr_cache: dict = None  # type: ignore[assignment]

    # -- MachineRecoveryEngine ----------------------------------------------------
    def recover(
        self,
        graph: FlowGraph,
        anchors: DispatcherAnchors | None = None,
        caps: object | None = None,
    ) -> RecoveredMachine | None:
        """Recover a ``RecoveredMachine`` by concrete BFS over the state set.

        ``anchors`` are the selector-anchored structural facts
        (``dispatcher_anchor_discovery.discover_anchors``); when absent or lacking a
        state slot the engine abstains (``None``). ``caps`` may be a
        :class:`RecoveryCaps`; any other value falls back to the defaults.
        """
        if not self.enabled:
            return None
        if anchors is None or anchors.dispatcher_entry_block is None:
            return None
        if anchors.state_var_stkoff is None and anchors.state_var_lvar_idx is None:
            return None
        rc = caps if isinstance(caps, RecoveryCaps) else RecoveryCaps()

        disc = self._discovery_from_anchors(graph, anchors)
        if disc is None:
            return None

        # Per-recover global-carried next-state context (ticket llr-k8oa).
        self._fgr_graph = graph
        self._fgr_entry = int(disc.entry)
        self._fgr_cache = {}

        prov = ConcolicProvenance()
        region_cache: dict[int, _ForkRegionFacts] = {}
        dispatch_blocks_seen: set[int] = set()
        mask = (1 << (disc.var_size * 8)) - 1

        # Slice 5 resolver reused as the live-oracle host (its _emulate_to_handler /
        # helpers are the proven dispatcher stepper; this engine extends the FORK +
        # interprocedural behaviour around them).
        host = EmulationDispatcherResolver(mba=self.mba)

        def resolve_handler(state: int) -> int | None:
            return self._resolve_handler(
                host, disc, state, dispatch_blocks_seen, rc, prov
            )

        def advance_states(state: int, handler: int) -> ForkOutcome:
            return self._advance_states(
                host, disc, state, handler, region_cache, mask, rc, prov
            )

        def is_terminal(handler: int) -> bool:
            return self._is_terminal(host, disc, handler, region_cache, rc)

        merged_rows: dict[int, int] = {}
        merged_visited: list[int] = []
        merged_unresolved: list[int] = []
        merged_terminal: list[int] = []
        merged_transitions: list[WalkTransition] = []
        truncated = False
        seen_states: set[int] = set()

        seeds = anchors.initial_states or (disc.initial_state,)
        for init in seeds:
            res = walk_forking_state_machine(
                int(init),
                resolve_handler,
                advance_states,
                is_terminal,
                max_states=rc.max_states,
            )
            for row in res.walk.rows:
                merged_rows.setdefault(int(row.state_const), int(row.target_block))
            for s in res.walk.visited_states:
                if s not in seen_states:
                    seen_states.add(s)
                    merged_visited.append(int(s))
            merged_unresolved.extend(int(s) for s in res.walk.unresolved_states)
            merged_terminal.extend(int(s) for s in res.walk.terminal_states)
            merged_transitions.extend(res.transitions)
            truncated = truncated or res.walk.truncated

        prov.visited_state_count = len(merged_visited)
        prov.unresolved_state_count = len(set(merged_unresolved))
        prov.terminal_state_count = len(set(merged_terminal))
        prov.truncated = truncated

        return self._build_machine(
            disc,
            anchors,
            merged_rows,
            merged_transitions,
            dispatch_blocks_seen,
            truncated,
            rc,
            prov,
        )

    # -- live oracles (injected into the portable forking walk) -------------------
    def _resolve_handler(
        self,
        host: EmulationDispatcherResolver,
        disc: _Discovery,
        state: int,
        dispatch_blocks_seen: set[int],
        caps: RecoveryCaps,
        prov: ConcolicProvenance,
    ) -> int | None:
        """Seed the state var and step the dispatcher to the handler it routes to.

        Delegates to the PROVEN Slice 5 stepper (``_emulate_to_handler``), which runs
        the concrete interpreter with ``mask_subreg_reads=True`` and the UD-chain
        history -- so MBA next-state folding is inherited here by construction (the
        XOR-masked selector path stays byte-identical). The stepper abstains
        (returns ``None``) on any value it cannot prove, so this engine never
        fabricates an edge. Bounded interprocedural call folding is a planned strict
        extension (it can only narrow ``None`` -> a proven handler, never change a
        proven one), tracked for a follow-up live-mba slice.
        """
        return host._emulate_to_handler(disc, state, dispatch_blocks_seen)

    def _advance_states(
        self,
        host: EmulationDispatcherResolver,
        disc: _Discovery,
        state: int,
        handler: int,
        region_cache: dict[int, _ForkRegionFacts],
        mask: int,
        caps: RecoveryCaps,
        prov: ConcolicProvenance,
    ) -> ForkOutcome:
        """Compute the handler's next-state fan-out + provenance (the forking edge).

        Reads the handler region's arm set via :meth:`_fork_region_facts`. A linear
        handler yields one arm -> one next state; a conditional handler yields two
        arms -> a 2-element fork (design §4). An INCOMPLETE arm set (any arm's
        next-state unprovable) yields an EMPTY fan-out (abstain) -- never a partial
        fork (§7 completeness obligation).
        """
        facts = self._fork_region_facts(host, disc, handler, region_cache, caps)
        if not facts.complete:
            prov.diverged_states = prov.diverged_states + (int(state),)
            return ForkOutcome(())  # abstain: do not emit an incomplete fork
        if not facts.arms:
            return ForkOutcome(())  # pure exit / no transition
        next_states = tuple(
            self._apply_arm(host, state, opcode, const, mask)
            for opcode, const in facts.arms
        )
        # Single-arm provenance carries the op/const; a multi-arm fork records the
        # via_block only (the two arms have distinct ops/consts).
        if len(facts.arms) == 1:
            arm_op, arm_const = facts.arms[0]
            op_str = _SELF_UPDATE_OPS.get(arm_op) if arm_op is not None else None
            return ForkOutcome(
                next_states=next_states,
                via_block=facts.via_block,
                op=op_str,
                const=arm_const,
            )
        return ForkOutcome(next_states=next_states, via_block=facts.via_block)

    @staticmethod
    def _apply_arm(
        host: EmulationDispatcherResolver,
        state: int,
        opcode: int | None,
        const: int | None,
        mask: int,
    ) -> int:
        """Apply one arm to the current state, masked to the state-var width.

        ``opcode is None`` is a ``mov #const`` absolute write (the next state IS the
        constant); otherwise it is ``state OP const`` via the Slice 5 ``_apply_op``
        (single source of truth for the operator table).
        """
        if opcode is None:
            return (int(const) & mask) if const is not None else (int(state) & mask)
        return host._apply_op(int(state), int(opcode), int(const or 0), mask)

    def _is_terminal(
        self,
        host: EmulationDispatcherResolver,
        disc: _Discovery,
        handler: int,
        region_cache: dict[int, _ForkRegionFacts],
        caps: RecoveryCaps,
    ) -> bool:
        facts = self._fork_region_facts(host, disc, handler, region_cache, caps)
        return facts.reaches_ret and not facts.arms

    # -- region summary (forking arm enumeration) ---------------------------------
    def _fork_region_facts(
        self,
        host: EmulationDispatcherResolver,
        disc: _Discovery,
        handler: int,
        cache: dict[int, _ForkRegionFacts],
        caps: RecoveryCaps,
    ) -> _ForkRegionFacts:
        """Summarize a handler region as a (possibly forking) arm set.

        Unlike the Slice 5 :meth:`_region_facts` (which collects ONLY ``state OP
        const`` self-updates -- correct for the XOR machine), this also collects
        ``state = mov #const`` absolute writes, because an identity ``switch(state)``
        machine writes its next state with a bare ``mov`` on each arm (bug #2, plan
        §3). Each ``state``-slot write reachable in the region (bounded, never
        crossing ``disc.entry``) is one arm: ``(opcode, const)`` for a self-update,
        ``(None, const)`` for a ``mov #const``.

        A conditional handler whose two arms each write a distinct next state yields
        two arms -> a first-class fork. Completeness (§7): exactly 1 (linear) or 2
        (conditional) arms is complete; >2 is a multi-way branch this engine did not
        fully enumerate -> abstain (``complete=False``), never a partial fork.
        """
        cached = cache.get(handler)
        if cached is not None:
            return cached

        arms: list[tuple[int | None, int | None]] = []
        reaches_ret = False
        seen: set[int] = set()
        stack = [int(handler)]
        while stack and len(seen) < caps.max_region_blocks:
            serial = stack.pop()
            if serial in seen or serial == disc.entry:
                continue
            seen.add(serial)
            blk = self.mba.get_mblock(serial)
            if blk is None:
                continue
            if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
                reaches_ret = True
            # A block that WRITES the state slot with a LIVE write is the handler's
            # terminal block: the next state has been committed and control flows back
            # toward the dispatcher. Record its arm(s) and do NOT expand its successors --
            # they belong to the dispatcher loop-back join (a block ALL handlers funnel
            # through), not to this handler. Without this bound the region BFS spills
            # across the join into sibling handlers / the exit path, and the reg-indirect
            # arm scan below would harvest unrelated ``mov #const -> reg`` writes.
            #
            # DEAD-STORE skip (ticket llr-iy9i round 4): an absolute-write machine
            # (``unwrap_loops``) emits a DECOY ``mov #0 -> state`` in the conditional
            # handler head that is OVERWRITTEN on every path before re-entering the
            # dispatcher (the real next states are written by the two arm blocks the
            # call-branch selects). Counting the decoy as the committed transition yields
            # a spurious self-loop and a 1-row walk. When the block's state write is dead
            # (overwritten on ALL paths to the dispatcher/exit), treat the block as a
            # pass-through: skip its decoy arm and KEEP EXPANDING into the arm blocks that
            # write the live next states. The forward-fold transition recovery
            # (minimal_state_recovery) is dead-store-correct for the same reason.
            if host._writes_stkoff(blk, int(disc.stkoff)) and not self._state_write_is_dead(
                serial, int(disc.stkoff), int(disc.entry)
            ):
                arms.extend(
                    self._block_state_arms(
                        host,
                        blk,
                        disc.stkoff,
                        foldable_global_reads=self._foldable_global_reads_for_handler(
                            int(handler)
                        ),
                    )
                )
                continue
            for i in range(blk.nsucc()):
                succ = int(blk.succ(i))
                if succ != disc.entry and succ not in seen:
                    stack.append(succ)

        # Region-level fallback for a CONDITIONAL handler that assigns the next state
        # INDIRECTLY: ``mov #c1 -> reg`` / ``mov #c2 -> reg`` on the two arms, then a
        # single ``mov reg -> state`` at the join (bug class: the per-block scan above
        # only sees the join's ``mov reg -> state``, whose source is a register, not a
        # constant -- so it records no arm). Resolve the state-write's source register
        # to the constants assigned to it across the region; each distinct constant is
        # one arm. Only applied when the direct scan found NOTHING, so it never changes
        # a linear/self-update handler.
        if not arms:
            arms = self._reg_indirect_state_arms(seen, int(disc.stkoff))

        complete = len(arms) <= 2
        facts = _ForkRegionFacts(
            arms=tuple(arms),
            reaches_ret=reaches_ret,
            via_block=int(handler),
            complete=complete,
        )
        cache[handler] = facts
        return facts

    def _state_write_is_dead(self, serial: int, stkoff: int, entry: int) -> bool:
        """``True`` iff block ``serial``'s state-slot write is PROVABLY OVERWRITTEN on every
        outgoing path before it can be used (so it is a dead decoy, not a committed transition).

        A write is dropped ONLY with positive proof of deadness -- a conservative under-approx
        so a real transition is never silently lost. ``serial``'s write is LIVE if EITHER:

        * ``serial`` has NO successors -- a terminal transition write (the unit-test model and a
          handler whose loop-back is not modeled); or
        * SOME outgoing path reaches a USE -- the dispatcher compare at ``entry`` OR a
          successor-less dead-end -- with NO intervening state-slot write (the value survives).

        It is DEAD only when ``serial`` has successors AND every outgoing path rewrites the
        state before reaching any such use (``unwrap_loops``'s decoy ``mov #0 -> i`` head, whose
        two call-branch arms both overwrite ``i`` before the ``goto`` back to the dispatcher).
        """
        blk = self.mba.get_mblock(int(serial))
        if blk is None or blk.nsucc() == 0:
            return False  # terminal transition write -> live (never dropped)
        host = EmulationDispatcherResolver(mba=self.mba)
        for i in range(blk.nsucc()):
            succ = int(blk.succ(i))
            if succ == int(entry):
                return False  # serial -> entry directly: the write is read at the compare
            if self._write_reaches_use_unrewritten(succ, stkoff, int(entry), host):
                return False
        return True

    def _write_reaches_use_unrewritten(
        self,
        start: int,
        stkoff: int,
        entry: int,
        host: EmulationDispatcherResolver,
    ) -> bool:
        """``True`` if a path ``start -> ...`` reaches a USE of the state value with NO
        intervening state-slot write -- i.e. the incoming value SURVIVES (so the upstream write
        is live).

        A USE is the dispatcher compare at ``entry`` OR a successor-less dead-end (a block that
        may read/return the value). Bounded DFS; a block that writes the state slot stops that
        path (the value is overwritten there, so it does not carry past). Conservative: any
        unre-written path to a use proves liveness, so a real transition is never dropped.
        """
        seen: set[int] = set()
        stack = [int(start)]
        while stack and len(seen) < _DEAD_STORE_SCAN_BOUND:
            cur = stack.pop()
            if cur == int(entry):
                return True  # reached the dispatcher compare unre-written -> live
            if cur in seen:
                continue
            seen.add(cur)
            blk = self.mba.get_mblock(cur)
            if blk is None:
                continue
            if host._writes_stkoff(blk, int(stkoff)):
                continue  # the value is overwritten here -> this path does not carry it
            if blk.nsucc() == 0:
                return True  # successor-less dead-end reached unre-written -> live
            for i in range(blk.nsucc()):
                stack.append(int(blk.succ(i)))
        return False

    def _reg_indirect_state_arms(
        self, region_blocks: set[int], stkoff: int
    ) -> list[tuple[int | None, int | None]]:
        """Arms from an indirect ``mov #const -> reg`` ... ``mov reg -> state`` handler.

        A conditional handler often lowers ``state = cond ? c1 : c2`` as two arm
        blocks each doing ``mov #ci -> reg`` and a join block doing ``mov reg ->
        state``.  The direct per-block scan misses this (the state write's source is a
        register).  Here we (1) find the register feeding a ``mov reg -> state`` write
        anywhere in the region, then (2) collect every ``mov #const -> reg`` for THAT
        register across the region.  Each distinct constant is a ``(None, const)`` arm
        -- the same shape as a direct ``mov #const -> state``.  Returns at most the
        distinct constants found (the caller's completeness check rejects > 2).
        """
        state_src_regs: set[int] = set()
        reg_consts: dict[int, set[int]] = {}
        for s in region_blocks:
            blk = self.mba.get_mblock(int(s))
            if blk is None:
                continue
            insn = blk.head
            while insn is not None:
                d = insn.d
                if insn.opcode == ida_hexrays.m_mov and d is not None:
                    # mov reg -> state : record the source register feeding the state.
                    if (
                        d.t == ida_hexrays.mop_S
                        and d.s is not None
                        and int(d.s.off) == int(stkoff)
                        and insn.l is not None
                        and insn.l.t == ida_hexrays.mop_r
                    ):
                        state_src_regs.add(int(insn.l.r))
                    # mov #const -> reg : record the constant assigned to the register.
                    elif (
                        d.t == ida_hexrays.mop_r
                        and insn.l is not None
                        and insn.l.t == ida_hexrays.mop_n
                    ):
                        reg_consts.setdefault(int(d.r), set()).add(
                            int(insn.l.nnn.value)
                        )
                insn = insn.next
        consts: list[int] = []
        for reg in state_src_regs:
            for c in sorted(reg_consts.get(reg, ())):
                if c not in consts:
                    consts.append(int(c))
        return [(None, int(c)) for c in consts]

    @staticmethod
    def _block_state_arms(
        host: EmulationDispatcherResolver,
        blk: ida_hexrays.mblock_t,
        stkoff: int,
        foldable_global_reads: dict[int, dict[int, int]] | None = None,
    ) -> list[tuple[int | None, int | None]]:
        """The state-slot transitions one block writes.

        ``state OP #const`` -> ``(opcode, const)`` (reuses the Slice 5
        ``_as_self_update`` / ``_self_update_const``); a final ``state = mov #const``
        -> ``(None, const)`` (the identity-switch next-state write the self-update
        scan misses). At most one ``mov`` arm per block (the last write wins, matching
        ``_mov_const_to_stkoff``), so a single-arm block stays a single arm.

        ABSOLUTE COMPUTED write fallback (ticket llr-iy9i round 4): a condition-chain
        machine (``hardened_cond_chain_simple``) writes its next state with a folded
        ``add (global ^ K) + K -> state`` -- neither ``state OP #const`` nor ``mov #const``.
        When neither direct form is found, fold the block's state-slot write to a constant in
        isolation (``_fold_state_write_in_block`` reads the IDB globals); a proven constant is
        an absolute ``(None, const)`` arm. A write the emulator cannot prove constant yields no
        arm (sound abstain), exactly like an unrecognized transition.

        GLOBAL-CARRIED next-state (ticket llr-k8oa): ``foldable_global_reads`` (when
        supplied) lets the absolute fold step the WHOLE block so a next state carried
        through a writable global -- Approov ``approov_qword |= 0xF6A20`` then
        ``state = (int)approov_qword`` -- folds to its committed constant (the
        in-block global dataflow the legacy path uses).  A direct ``mov #const`` /
        ``state OP #const`` arm is still preferred; the whole-block fold only adds the
        global-carried arm the single-instruction fold abstains on.
        """
        out: list[tuple[int | None, int | None]] = []
        insn = blk.head
        while insn is not None:
            upd = host._as_self_update(insn)
            if upd is not None and upd[0] == int(stkoff):
                const = host._self_update_const(insn)
                if const is not None:
                    out.append((int(insn.opcode), int(const)))
            insn = insn.next
        if not out:
            mov_const = host._mov_const_to_stkoff(blk, int(stkoff))
            if mov_const is not None:
                out.append((None, int(mov_const)))
        if not out and host._writes_stkoff(blk, int(stkoff)):
            folded = host._fold_state_write_in_block(
                int(blk.serial),
                int(stkoff),
                foldable_global_reads=foldable_global_reads,
            )
            if folded is not None:
                out.append((None, int(folded)))
        return out

    def _foldable_global_reads_for_handler(
        self, handler: int
    ) -> dict[int, dict[int, int]] | None:
        """Reaching-defs-sound ``{read_ea: {gaddr: init}}`` for THIS handler region.

        The global-carried next-state fold (ticket llr-k8oa) needs the set of global
        reads that fold to their ``.data`` initializer within the handler being
        summarized.  Anchored at the handler entry with the dispatcher entry as a
        reaching-defs BARRIER (its incoming edges cut): the handler runs straight-line
        from its entry before any sibling handler's store, so its read of a writable
        global is store-free and folds to the loader-supplied initializer -- exactly the
        per-read soundness ``global_init_fold`` proves and the legacy
        ``minimal_state_recovery`` path relies on.  Cached per handler.  ``None`` when no
        recover context / no walker provider (the fold then degrades to the direct,
        single-instruction path -- no global-carried recovery, but never a wrong fold).
        """
        if self._fgr_graph is None or self._fgr_entry is None:
            return None
        if self._fgr_cache is None:
            self._fgr_cache = {}
        cached = self._fgr_cache.get(int(handler))
        if cached is not None:
            return cached
        try:
            fetch = get_condition_chain_walkers().fetch_idb_value
        except Exception:  # noqa: BLE001 — no provider -> no global fold (direct path only)
            self._fgr_cache[int(handler)] = {}
            return {}
        try:
            fgr = compute_initializer_stable_global_reads(
                self._fgr_graph,
                fetch,
                barrier_serials={int(self._fgr_entry)},
                entry_override=int(handler),
            )
        except Exception:  # noqa: BLE001 — fold-set computation is best-effort -> abstain
            fgr = {}
        fgr = dict(fgr) if fgr else {}
        self._fgr_cache[int(handler)] = fgr
        return fgr

    def _discovery_from_anchors(
        self, graph: FlowGraph, anchors: DispatcherAnchors
    ) -> _Discovery | None:
        """Build the Slice 5 ``_Discovery`` (seedable skeleton) from P1 anchors.

        Needs a representative ``mop_S`` at the anchored stack offset for seeding; an
        identity ``switch(state)`` state slot may be ``mov #const``-written only, so
        any ``mop_S`` operand at that offset is acceptable (its size sets the mask).
        The initial state comes from the anchors when present, else from the Slice 5
        entry-dominance recovery (``_recover_initial_state`` over the live ``graph``).
        """
        entry = int(anchors.dispatcher_entry_block)
        stkoff = anchors.state_var_stkoff
        if stkoff is None:
            return None
        # Read/write slot split (ticket llr-k8oa): the anchored slot is the slot the
        # dispatcher COMPARES, which a ``-fla`` lowering keeps as a header copy of the
        # slot the handlers actually WRITE the next state to (Approov / OLLVM:
        # ``compared = next_write`` at the loop head, e.g. ``var_C = var_8``).  The
        # initial-state init and every handler next-state write target the SOURCE slot,
        # so anchoring on the compared copy makes init recovery + the handler write scan
        # miss them (the engine abstains).  Follow the dispatcher-header copy back to the
        # write-source slot -- the same canonical resolution the legacy
        # ``minimal_state_recovery`` path applies (``_resolve_state_var_alias``).  A clean
        # machine with no header copy resolves to itself (unchanged).
        try:
            resolved = int(_resolve_state_var_alias(graph, entry, int(stkoff)))
        except Exception:  # noqa: BLE001 — alias probe is best-effort -> keep the anchor
            resolved = int(stkoff)
        if resolved != int(stkoff):
            if logger.debug_on:
                logger.debug(
                    "concolic_emulation: anchor slot 0x%x is a header copy of write-source "
                    "slot 0x%x (entry=%d) -- retargeting",
                    int(stkoff),
                    resolved,
                    entry,
                )
            stkoff = resolved
        state_mop, var_size = self._representative_state_mop(int(stkoff))
        if state_mop is None:
            return None
        initial = (
            int(anchors.initial_states[0]) if anchors.initial_states else None
        )
        if initial is None:
            host = EmulationDispatcherResolver(mba=self.mba)
            initial = host._recover_initial_state(graph, entry, int(stkoff))
        if initial is None:
            # The Slice 5 recovery only inspects DIRECT predecessors of the dispatcher
            # entry. An identity ``switch(state)`` machine commonly initializes the
            # state slot in a prologue block one or more hops ABOVE the entry's
            # immediate predecessor (entry's pred is a join the handlers also loop back
            # through), so the direct-predecessor scan misses it. Walk the pre-header
            # chain -- the blocks reachable from the function entry WITHOUT passing
            # through the dispatcher -- for the ``mov #const -> stkoff`` initializer.
            initial = self._recover_initial_state_preheader(graph, entry, int(stkoff))
        if initial is None:
            return None
        return _Discovery(
            stkoff=int(stkoff),
            var_size=int(var_size or 4),
            state_mop=state_mop,
            entry=int(entry),
            initial_state=int(initial),
        )

    def _recover_initial_state_preheader(
        self, graph: FlowGraph, entry: int, stkoff: int
    ) -> int | None:
        """Initial state from the pre-header chain ``mov #const -> stkoff`` initializer.

        The dispatcher's true prologue initialization may sit several blocks above the
        entry's immediate predecessor (the immediate predecessor is a JOIN the handler
        back-edges also reach). The exact pre-header test is entry-dominance: a block
        is a pre-header iff it is reachable from the function entry WITHOUT passing
        through the dispatcher (back-edges reach the join only THROUGH the dispatcher,
        so they are excluded). We BFS BACK from the dispatcher entry over predecessors
        restricted to that pre-header set and return the constant the NEAREST
        pre-header block initializes the state slot to (``_mov_const_to_stkoff``). When
        more than one distinct constant is found the prologue is ambiguous -> abstain.
        """
        host = EmulationDispatcherResolver(mba=self.mba)
        entry_serial = int(getattr(graph, "entry_serial", 0))
        # Forward reachability with the dispatcher entry as a CUT.
        reach: set[int] = set()
        stack = [entry_serial]
        while stack:
            s = stack.pop()
            if s in reach:
                continue
            reach.add(s)
            if s == int(entry):
                continue  # CUT: do not traverse out of the dispatcher entry
            blk = self.mba.get_mblock(s)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                stack.append(int(blk.succ(i)))
        # BFS back from the entry over pre-header predecessors; nearest init wins.
        consts: list[int] = []
        seen: set[int] = set()
        queue = [int(entry)]
        while queue:
            s = queue.pop(0)
            blk = self.mba.get_mblock(s)
            if blk is None:
                continue
            for i in range(blk.npred()):
                p = int(blk.pred(i))
                if p == int(entry) or p not in reach or p in seen:
                    continue
                seen.add(p)
                const = host._mov_const_to_stkoff(self.mba.get_mblock(p), int(stkoff))
                if const is not None and const not in consts:
                    consts.append(int(const))
                queue.append(p)
        if len(consts) == 1:
            return int(consts[0])
        return None

    def _representative_state_mop(
        self, stkoff: int
    ) -> tuple[ida_hexrays.mop_t | None, int]:
        """Find any ``mop_S`` operand at ``stkoff`` (for seeding) + its size.

        Scans every instruction's dest/src for a stack operand at the offset. A
        write (``d``) is preferred (its size is the slot width); a read is accepted.
        """
        fallback: tuple[ida_hexrays.mop_t | None, int] = (None, 4)
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk is None:
                continue
            insn = blk.head
            while insn is not None:
                for mop in (insn.d, insn.l, insn.r):
                    if (
                        mop is not None
                        and mop.t == ida_hexrays.mop_S
                        and mop.s is not None
                        and int(mop.s.off) == int(stkoff)
                    ):
                        if mop is insn.d:
                            return mop, int(mop.size)
                        if fallback[0] is None:
                            fallback = (mop, int(mop.size))
                insn = insn.next
        return fallback

    # -- assembly -----------------------------------------------------------------
    def _build_machine(
        self,
        disc: _Discovery,
        anchors: DispatcherAnchors,
        rows_map: dict[int, int],
        transitions: list[WalkTransition],
        dispatch_blocks_seen: set[int],
        truncated: bool,
        caps: RecoveryCaps,
        prov: ConcolicProvenance,
    ) -> RecoveredMachine | None:
        """Assemble the ``RecoveredMachine`` or abstain.

        Rejects a truncated walk (state set never closed -> ordinary loop misread) or
        a sub-threshold table (accidental match), exactly the Slice 5 rule
        (resolver.py:190). Tags ``EXACT_BOUNDED`` and carries the FORKING transitions
        (the new P2 contract data) the orchestrator consumes.
        """
        if truncated or len(rows_map) < caps.min_recovered_rows:
            logger.info(
                "concolic_emulation: rejecting walk (rows=%d truncated=%s entry=%d "
                "stkoff=0x%x)",
                len(rows_map),
                truncated,
                disc.entry,
                disc.stkoff,
            )
            return None

        dispatcher_blocks = frozenset(dispatch_blocks_seen | {disc.entry})
        rows = tuple(
            MachineRow(
                state_const=int(state_const),
                target_block=int(target_block),
                dispatcher_block=int(disc.entry),
                compare_block=int(disc.entry),
                branch_kind="emulated",
                router_kind=RouterKind.CONDITION_CHAIN,
            )
            for state_const, target_block in rows_map.items()
        )
        machine_transitions = tuple(
            MachineTransition(
                src_state=int(t.src_state),
                context=(),
                next_states=tuple(int(s) for s in t.next_states),
                via_block=int(t.via_block) if t.via_block is not None else None,
                op=t.op,
                const=int(t.const) if t.const is not None else None,
            )
            for t in transitions
        )
        logger.info(
            "concolic_emulation: recovered %d rows / %d transitions by emulation "
            "(entry=%s stkoff=0x%x init=0x%x visited=%d unresolved=%d terminal=%d)",
            len(rows),
            len(machine_transitions),
            live_block_label(self._fgr_graph, disc.entry),
            disc.stkoff,
            disc.initial_state,
            prov.visited_state_count,
            prov.unresolved_state_count,
            prov.terminal_state_count,
        )
        return RecoveredMachine(
            rows=rows,
            transitions=machine_transitions,
            contexts=(),
            initial_states=(int(disc.initial_state),),
            state_var_stkoff=int(disc.stkoff),
            state_var_lvar_idx=anchors.state_var_lvar_idx,
            dispatcher_entry_block=int(disc.entry),
            dispatcher_blocks=dispatcher_blocks,
            router_kind=RouterKind.CONDITION_CHAIN,
            soundness=Soundness.EXACT_BOUNDED,
            confidence=float(len(rows)),
            provenance=prov.as_tuple(),
        )
