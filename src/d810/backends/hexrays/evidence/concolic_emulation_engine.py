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
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.analyses.control_flow.emulated_state_walk import DEFAULT_MAX_STATES
from d810.analyses.control_flow.machine_recovery_engine import DispatcherAnchors
from d810.analyses.control_flow.recovered_machine import (
    MachineRow,
    MachineTransition,
    RecoveredMachine,
    Soundness,
)
from d810.backends.hexrays.evidence.emulation_dispatcher_resolver import (
    _SELF_UPDATE_OPS,
    EmulationDispatcherResolver,
    _Discovery,
)
from d810.core.logging import getLogger
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.analyses.concolic_emulation_engine")

__all__ = ["RecoveryCaps", "ConcolicProvenance", "ConcolicEmulationEngine"]


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
            arms.extend(self._block_state_arms(host, blk, disc.stkoff))
            if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
                reaches_ret = True
            for i in range(blk.nsucc()):
                succ = int(blk.succ(i))
                if succ != disc.entry and succ not in seen:
                    stack.append(succ)

        complete = len(arms) <= 2
        facts = _ForkRegionFacts(
            arms=tuple(arms),
            reaches_ret=reaches_ret,
            via_block=int(handler),
            complete=complete,
        )
        cache[handler] = facts
        return facts

    @staticmethod
    def _block_state_arms(
        host: EmulationDispatcherResolver,
        blk: ida_hexrays.mblock_t,
        stkoff: int,
    ) -> list[tuple[int | None, int | None]]:
        """The state-slot transitions one block writes.

        ``state OP #const`` -> ``(opcode, const)`` (reuses the Slice 5
        ``_as_self_update`` / ``_self_update_const``); a final ``state = mov #const``
        -> ``(None, const)`` (the identity-switch next-state write the self-update
        scan misses). At most one ``mov`` arm per block (the last write wins, matching
        ``_mov_const_to_stkoff``), so a single-arm block stays a single arm.
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
        return out

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
            return None
        return _Discovery(
            stkoff=int(stkoff),
            var_size=int(var_size or 4),
            state_mop=state_mop,
            entry=int(entry),
            initial_state=int(initial),
        )

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
                source=DispatcherType.CONDITIONAL_CHAIN,
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
            "(entry=%d stkoff=0x%x init=0x%x visited=%d unresolved=%d terminal=%d)",
            len(rows),
            len(machine_transitions),
            disc.entry,
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
            source=DispatcherType.CONDITIONAL_CHAIN,
            soundness=Soundness.EXACT_BOUNDED,
            confidence=float(len(rows)),
            provenance=prov.as_tuple(),
        )
