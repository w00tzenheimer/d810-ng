"""Emulation-based ``DispatcherResolver`` for non-identity-selector state machines (llr-a93i, Slice 5).

The portable static resolvers recognize a dispatcher by its compare *shape*:
``EqualityChainDispatcherResolver`` matches ``state == const`` and
``SwitchTableDispatcherResolver`` matches ``switch(state & MASK)``. Neither can recover a
dispatcher whose selector is a NON-IDENTITY function of the state -- the XOR-masked
``switch((state ^ KEY) & MASK)`` with full-width ``state ^= magic`` transitions
(``abc_xor_dispatch``). There the dispatcher compares a *selector temporary*
(``t = (state ^ KEY) & 0xFF``) against sub-threshold byte labels -- the state variable
itself is read only in the selector COMPUTATION, never in the ``jz`` cascade -- and the real
32-bit states (``0x123456EF`` -> ``0x032547FE`` -> ...) are never compared directly, so both
static resolvers return ``map_rows=0`` and §1a skips the function at *discovery*.

This resolver recovers such a machine the only sound way: by EXECUTING it. It discovers the
state variable (the dominant self-``OP``-updated stack slot -- the ONE thing that is shape
invariant), the dispatcher loop head the handlers branch back to, and the prologue's initial
state, then drives the pure :func:`walk_emulated_state_machine` core with two live oracles:

* ``resolve_handler(state)`` -- seed the state var with the concrete value and step the live
  dispatcher with :class:`MicroCodeInterpreter` until control leaves the dispatcher chain
  (the selector projection is *evaluated*, so the shape is irrelevant). "Left the chain" =
  reached a block that WRITES the state var (a linear handler), ends in ``ret`` (an exit), or
  branches on non-state data (a conditional handler arm, where the emulator stalls because the
  branch depends on a value -- e.g. ``result`` -- that is not the seeded state).
* ``advance_states(state, handler)`` -- read the handler region's ``state OP const`` write(s)
  and compute the next state(s) in pure Python (one for a linear handler, two for a
  conditional arm), masked to the state-var width.

The result is an exact ``state_const -> target_block`` table keyed by the REAL state values
-- the same :class:`StateDispatcherMap` relation the static resolvers produce, consumed by the
existing emit path unchanged. It is registered ONLY when the project config opts in
(``"emulation_dispatcher": true``) and ranks at the lowest specificity, so it can never
override a static win and is inert on every non-opted-in project (golden-safe; ticket
llr-a93i, the "config-driven per project" decision).
"""
from __future__ import annotations

from dataclasses import dataclass

import ida_hexrays

from d810.core.logging import getLogger
from d810.core.observability_labels import live_block_label
from d810.capabilities.dispatcher import RouterKind
from d810.analyses.control_flow.dispatcher_recovery import (
    recover_entry_dominated_initial_state,
)
from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherResolution,
    ResolverCandidate,
    StateDispatcherMap,
    StateDispatcherRow,
)
from d810.analyses.control_flow.emulated_state_walk import walk_emulated_state_machine
from d810.capabilities.providers import get_bst_walkers
from d810.evaluator.hexrays_microcode.emulator import (
    MicroCodeEnvironment,
    MicroCodeInterpreter,
)
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.ir.flowgraph import FlowGraph

logger = getLogger("D810.analyses.emulation_dispatcher_resolver")

__all__ = ["EmulationDispatcherResolver"]

#: Self-referential transition opcodes (``state = state OP const``) the walk understands, with
#: the pure-Python operator used to advance the concrete state.
_SELF_UPDATE_OPS: dict[int, str] = {
    ida_hexrays.m_xor: "^",
    ida_hexrays.m_or: "|",
    ida_hexrays.m_and: "&",
    ida_hexrays.m_add: "+",
    ida_hexrays.m_sub: "-",
}

#: Conditional-jump opcodes a flattened dispatcher uses to compare the state var against a
#: constant -- the equality cascade (``jz``/``jnz``) AND the binary-search BST
#: (``ja``/``jae``/``jb``/...). The slot compared against a const in >=2 such blocks is the
#: dispatcher's state variable (the ABSOLUTE-mov / computed-write machines -- unwrap_loops,
#: hardened_cond_chain_simple -- whose state slot is NEVER ``state OP #const``, so the
#: dominant-self-update heuristic mis-IDs the accumulator; ticket llr-iy9i round 4).
_COMPARE_OPS: frozenset[int] = frozenset(
    {
        ida_hexrays.m_jz,
        ida_hexrays.m_jnz,
        ida_hexrays.m_ja,
        ida_hexrays.m_jae,
        ida_hexrays.m_jb,
        ida_hexrays.m_jbe,
        ida_hexrays.m_jg,
        ida_hexrays.m_jge,
        ida_hexrays.m_jl,
        ida_hexrays.m_jle,
    }
)

#: A function is only a candidate state machine if its dominant state slot is self-updated in
#: at least this many distinct blocks (one per real handler transition); fewer is an ordinary
#: loop or accumulator, not a flattened machine.
_MIN_HANDLER_BLOCKS = 2

#: Reject a recovered table smaller than this -- a genuine flattened machine has multiple
#: states; one row is indistinguishable from an accidental match.
_MIN_RECOVERED_ROWS = 2

#: Iteration caps -- a flattened dispatcher chain has O(handlers) compare/handler-region
#: blocks, so a few dozen is already far past any real obfuscated function.
_MAX_DISPATCH_STEPS = 256
_MAX_REGION_BLOCKS = 64


@dataclass(frozen=True)
class _Discovery:
    """Recovered state-machine skeleton (state var + entry + initial), pre-walk."""

    stkoff: int
    var_size: int
    state_mop: ida_hexrays.mop_t
    entry: int
    initial_state: int


@dataclass(frozen=True)
class _RegionFacts:
    """Per-handler region summary: the next-state transitions it writes + whether it returns."""

    transitions: tuple[tuple[int, int], ...]  # (opcode, const)
    reaches_ret: bool


@dataclass
class EmulationDispatcherResolver:
    """Recover a non-identity-selector state machine by concrete emulation.

    ``mba`` is the live function microcode bound at construction (re-bound each decompilation;
    idempotent-by-name registration keeps the registry from leaking stale resolvers). The
    resolver depends on the live ``mba`` for emulation, so it lives in the Hex-Rays backend; the
    walk itself is the portable :func:`walk_emulated_state_machine`.
    """

    mba: ida_hexrays.mba_t
    #: Config opt-in (``"emulation_dispatcher": true``). The resolver is registered on EVERY
    #: decompile (so its bound ``mba`` is always fresh -- a stale ``mba`` from a prior function
    #: left in the process-global registry would segfault when a later, non-opted-in function
    #: consults the chain), but ``accepts`` returns ``None`` immediately when disabled, so it is
    #: completely inert for non-opted-in projects (ticket llr-a93i).
    enabled: bool = True
    name: str = "emulation_dispatcher"
    router_kind: RouterKind = RouterKind.EQUALITY_CHAIN
    #: Lowest specificity: a genuine equality-chain (10) or switch-table (5) ALWAYS out-ranks
    #: this, so the expensive emulation walk only runs when both static resolvers decline.
    specificity: int = 1

    # -- DispatcherResolver protocol --------------------------------------------------
    def accepts(self, graph: FlowGraph) -> ResolverCandidate | None:
        """Cheap structural gate: a dominant state slot self-updated in >= 2 handler blocks.

        Runs over the live ``mba`` (O(instructions)); never emulates here. Returns ``None``
        unless the project opted in AND the function carries the flattened-state-machine
        signature, so it is inert on ordinary code and on non-opted-in projects.
        """
        if not self.enabled:
            return None
        disc = self._discover(graph)
        if disc is None:
            return None
        return ResolverCandidate(
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=1.0,
            specificity=self.specificity,
            reasons=(
                "emulated-walk",
                "stkoff=0x%x" % disc.stkoff,
                "entry=%d" % disc.entry,
                "init=0x%x" % disc.initial_state,
            ),
        )

    def resolve(
        self, graph: FlowGraph, candidate: ResolverCandidate
    ) -> DispatcherResolution | None:
        """Walk the machine by emulation and return the exact real-state -> handler map."""
        disc = self._discover(graph)
        if disc is None:
            return None
        region_cache: dict[int, _RegionFacts] = {}
        dispatch_blocks_seen: set[int] = set()
        mask = (1 << (disc.var_size * 8)) - 1

        def resolve_handler(state: int) -> int | None:
            return self._emulate_to_handler(disc, state, dispatch_blocks_seen)

        def advance_states(state: int, handler: int) -> tuple[int, ...]:
            facts = self._region_facts(disc, handler, region_cache)
            return tuple(
                self._apply_op(state, opcode, const, mask)
                for opcode, const in facts.transitions
            )

        def is_terminal(handler: int) -> bool:
            facts = self._region_facts(disc, handler, region_cache)
            return facts.reaches_ret and not facts.transitions

        result = walk_emulated_state_machine(
            disc.initial_state, resolve_handler, advance_states, is_terminal
        )
        # Reject untrustworthy walks: a runaway (truncated) means the state set never closed --
        # the signature of an ordinary loop misread as a machine -- and a sub-threshold table is
        # an accidental match. Abstaining keeps a wrong table from reaching the emit path.
        if result.truncated or len(result.rows) < _MIN_RECOVERED_ROWS:
            logger.info(
                "emulation_dispatcher: rejecting walk (rows=%d truncated=%s entry=%d stkoff=0x%x)",
                len(result.rows),
                result.truncated,
                disc.entry,
                disc.stkoff,
            )
            return None

        # The dispatcher blocks are exactly the chain blocks the emulation stepped through to
        # route every state (selector compute + jz cascade) -- never a handler. The entry is
        # always one of them.
        dispatcher_blocks = frozenset(dispatch_blocks_seen | {disc.entry})
        rows = tuple(
            StateDispatcherRow(
                state_const=int(row.state_const),
                target_block=int(row.target_block),
                dispatcher_block=int(disc.entry),
                compare_block=int(disc.entry),
                branch_kind="emulated",
                source=RouterKind.CONDITION_CHAIN,
            )
            for row in result.rows
        )
        dmap = StateDispatcherMap(
            rows=rows,
            dispatcher_entry_block=int(disc.entry),
            dispatcher_blocks=dispatcher_blocks,
            state_var_stkoff=int(disc.stkoff),
            state_var_lvar_idx=None,
            source=RouterKind.CONDITION_CHAIN,
            initial_state=int(disc.initial_state),
        )
        logger.info(
            "emulation_dispatcher: recovered %d rows by emulation "
            "(entry=%s stkoff=0x%x init=0x%x terminals=%d unresolved=%d dispatch_blocks=%d)",
            len(rows),
            live_block_label(graph, disc.entry),
            disc.stkoff,
            disc.initial_state,
            len(result.terminal_states),
            len(result.unresolved_states),
            len(dispatcher_blocks),
        )
        return DispatcherResolution(
            dispatcher_map=dmap,
            resolver_name=self.name,
            router_kind=self.router_kind,
            confidence=float(len(rows)),
            ranking_reason=candidate.reasons + ("rows=%d" % len(rows),),
        )

    # -- discovery --------------------------------------------------------------------
    def _discover(self, graph: FlowGraph) -> _Discovery | None:
        """Find the state var (dominant self-update slot), entry loop head, and initial state."""
        per_block = self._self_update_blocks()
        # Dominant self-update slot = the one self-updated in the MOST blocks (one block per
        # handler transition); shape-invariant for the equality / switch / XOR-masked machines
        # whose transitions ARE ``state OP #const`` (high_fan_in, switch_case_ollvm, abc_xor).
        stkoff = max(per_block, key=lambda k: len(per_block[k][0])) if per_block else None
        handler_blocks: set[int] = set()
        var_size = 4
        state_mop: ida_hexrays.mop_t | None = None
        if stkoff is not None:
            handler_blocks, var_size, state_mop = per_block[stkoff]
            logger.info(
                "emulation_dispatcher: discovery func=0x%x maturity=%s dom_stkoff=0x%x "
                "handler_blocks=%d var_size=%d",
                int(getattr(self.mba, "entry_ea", 0)),
                maturity_to_string(int(getattr(self.mba, "maturity", -1))),
                int(stkoff),
                len(handler_blocks),
                int(var_size),
            )
        if len(handler_blocks) < _MIN_HANDLER_BLOCKS or state_mop is None:
            # ADDITIVE fallback (ticket llr-iy9i round 4): the self-update heuristic found
            # too few ``state OP #const`` blocks -- the machine's transitions are ABSOLUTE
            # writes (``mov #const -> state`` / a folded ``add (global^K)+K -> state``), so
            # the dominant-self-update slot is an accumulator, not the state var. Anchor on
            # the slot the DISPATCHER COMPARES against constants instead (the one thing that
            # is shape-invariant for an absolute-write machine). Gated to ``<2`` self-update
            # blocks, so the three already-passing self-update machines (4-5 blocks each)
            # keep their EXACT current anchor untouched.
            logger.info(
                "emulation_dispatcher: too few self-update blocks (%d) -- "
                "trying compared-slot fallback",
                len(handler_blocks),
            )
            return self._discover_by_compared_slot(graph)

        entry = self._find_entry(handler_blocks)
        if entry is None:
            logger.info("emulation_dispatcher: reject -- no dispatcher entry found")
            return None

        initial_state = self._recover_initial_state(graph, entry, stkoff)
        if initial_state is None:
            # NESTED-MACHINE fallback (ticket llr-6rwk round 5): the dominant self-update slot
            # whose init is UNRECOVERABLE is the inner-dispatcher state var of a nested machine
            # -- its prologue write is gated BEHIND the outer dispatcher, so entry-dominance
            # recovery can't reach a prologue constant. Don't reject; fall through to the
            # compared-slot discovery, which finds the OUTER (prologue-initialized) dispatcher.
            # The flat self-update machines (high_fan_in / switch_case_ollvm / abc_xor) recover
            # a valid init here and return below, so they never reach this fall-through.
            logger.info(
                "emulation_dispatcher: dominant slot 0x%x init unrecoverable "
                "(entry=%d); trying compared-slot fallback",
                int(stkoff),
                int(entry),
            )
            return self._discover_by_compared_slot(graph)
        logger.info(
            "emulation_dispatcher: discovered entry=%d stkoff=0x%x init=0x%x handler_blocks=%d",
            int(entry),
            int(stkoff),
            int(initial_state),
            len(handler_blocks),
        )
        return _Discovery(
            stkoff=int(stkoff),
            var_size=int(var_size or 4),
            state_mop=state_mop,
            entry=int(entry),
            initial_state=int(initial_state),
        )

    def _discover_by_compared_slot(self, graph: FlowGraph) -> _Discovery | None:
        """Fallback discovery for ABSOLUTE-write machines (ticket llr-iy9i round 4).

        The state var is the slot the dispatcher COMPARES against constants -- read in a
        conditional jump (``jz``/``jnz``/``ja``/...) whose other operand is a ``#const`` -- in
        ``>=2`` blocks (the equality cascade or the binary-search BST), AND written in ``>=2``
        blocks (one per handler's next-state transition). The intersection is the soundness
        guard the ticket requires: a slot that is BOTH the dispatcher's compared operand AND
        multiply-written is the state variable, never an accidental twice-assigned local.

        The transition writes need NOT be ``mov #const``: ``unwrap_loops`` writes the next
        state with ``mov #const -> i``; ``hardened_cond_chain_simple`` writes it with a folded
        ``add (global ^ K) + K -> i`` (an absolute write whose value the concrete leg folds via
        the IDB-read globals). Both are absolute next-states the concolic walk handles.

        Entry = the compared block with the highest in-degree -- the dispatcher loop head all
        handlers branch back to (``blk2`` in both samples). Initial state = the folded value the
        prologue / pre-header writes into the slot (constant ``mov`` OR a foldable computed
        write), recovered by emulating that single write in isolation.
        """
        compared = self._compared_state_slots()
        if not compared:
            return None
        # Candidate slots: compared against a const in >=2 cond-jump blocks AND written in >=2
        # blocks. Tie-break by the MOST compared blocks (the dispatcher reads its state var the
        # most), then by the most write blocks.
        candidates = [
            off
            for off, blks in compared.items()
            if len(blks) >= _MIN_HANDLER_BLOCKS
            and self._written_block_count(off) >= _MIN_HANDLER_BLOCKS
        ]
        if not candidates:
            logger.info(
                "emulation_dispatcher: compared-slot fallback found no candidate "
                "(compared=%s)",
                {hex(k): len(v) for k, v in compared.items()},
            )
            return None
        # Rank candidates by (compared_blocks, write_blocks) DESCENDING and return the FIRST
        # whose initial state is recoverable (ticket llr-6rwk round 5). A single max()+single
        # init-test rejects a nested machine when the top-ranked (inner) slot's init is gated
        # behind the outer dispatcher; iterating lets the OUTER (prologue-initialized) slot --
        # next in rank -- supply the recoverable anchor. For the flat compared-slot machines
        # (unwrap_loops / hardened_cond_chain_simple) the top-ranked candidate already recovers,
        # so the iteration returns the SAME slot first -- their anchor is untouched.
        ranked = sorted(
            candidates,
            key=lambda off: (len(compared[off]), self._written_block_count(off)),
            reverse=True,
        )
        for stkoff in ranked:
            state_mop, var_size = self._representative_mop_at(stkoff)
            if state_mop is None:
                continue
            # Entry = highest-in-degree compared block (the dispatcher loop head handlers
            # return to), recomputed per candidate slot.
            entry = max(
                compared[stkoff],
                key=lambda s: self.mba.get_mblock(int(s)).npred(),
            )
            initial_state = self._recover_initial_state_folded(graph, entry, stkoff)
            if initial_state is None:
                logger.info(
                    "emulation_dispatcher: compared-slot candidate stkoff=0x%x init "
                    "unrecoverable (entry=%d); trying next-ranked",
                    int(stkoff),
                    int(entry),
                )
                continue
            logger.info(
                "emulation_dispatcher: compared-slot fallback discovered entry=%d "
                "stkoff=0x%x init=0x%x compared_blocks=%d write_blocks=%d",
                int(entry),
                int(stkoff),
                int(initial_state),
                len(compared[stkoff]),
                self._written_block_count(stkoff),
            )
            return _Discovery(
                stkoff=int(stkoff),
                var_size=int(var_size or 4),
                state_mop=state_mop,
                entry=int(entry),
                initial_state=int(initial_state),
            )
        logger.info(
            "emulation_dispatcher: compared-slot fallback -- no candidate yielded a "
            "recoverable initial state (candidates=%s)",
            [hex(c) for c in ranked],
        )
        return None

    def _compared_state_slots(self) -> dict[int, set[int]]:
        """Map each stack slot to the blocks that compare it against a ``#const`` in a jump.

        A flattened dispatcher routes by comparing the state var against constant labels --
        ``jz/jnz state, #const`` (equality cascade) or ``ja/jae/jb/... state, #const`` (the
        binary-search BST). One operand is the stack slot, the other a ``mop_n`` constant; a
        single ``xdu``/``xds``/``low`` widening wrapper on the compared slot is peeled (the BST
        reads ``xdu.4(state.1)``). Slots compared in only one block are not dispatcher state
        vars (an ordinary ``if`` test).
        """
        out: dict[int, set[int]] = {}
        for blk in self._blocks():
            insn = blk.head
            while insn is not None:
                if insn.opcode in _COMPARE_OPS:
                    l = self._peel_widen(insn.l)
                    r = self._peel_widen(insn.r)
                    for a, c in ((l, r), (r, l)):
                        if (
                            a is not None
                            and a.t == ida_hexrays.mop_S
                            and a.s is not None
                            and c is not None
                            and c.t == ida_hexrays.mop_n
                        ):
                            out.setdefault(int(a.s.off), set()).add(int(blk.serial))
                insn = insn.next
        return out

    def _written_block_count(self, stkoff: int) -> int:
        """Count distinct blocks that WRITE ``stkoff`` (any instruction's dest).

        Counts ABSOLUTE writes too (``mov #const``, a folded ``add (global^K)+K``), not only
        ``state OP #const`` -- the absolute-write machine's transitions. One write block per
        handler transition, so ``>=2`` confirms a multi-state machine.
        """
        seen: set[int] = set()
        for blk in self._blocks():
            insn = blk.head
            while insn is not None:
                d = insn.d
                if (
                    d is not None
                    and d.t == ida_hexrays.mop_S
                    and d.s is not None
                    and int(d.s.off) == int(stkoff)
                ):
                    seen.add(int(blk.serial))
                    break
                insn = insn.next
        return len(seen)

    @staticmethod
    def _peel_widen(mop: ida_hexrays.mop_t | None) -> ida_hexrays.mop_t | None:
        """Peel a single ``xdu``/``xds``/``low`` wrapper (the BST reads ``xdu.4(state.1)``)."""
        if mop is not None and mop.t == ida_hexrays.mop_d and mop.d is not None:
            inner = mop.d
            if (
                inner.opcode in (ida_hexrays.m_xdu, ida_hexrays.m_xds, ida_hexrays.m_low)
                and inner.l is not None
            ):
                return inner.l
        return mop

    def _representative_mop_at(
        self, stkoff: int
    ) -> tuple[ida_hexrays.mop_t | None, int]:
        """Find any ``mop_S`` operand at ``stkoff`` (a dest preferred -- its size is the slot
        width) for seeding the emulator, plus its size."""
        fallback: tuple[ida_hexrays.mop_t | None, int] = (None, 4)
        for blk in self._blocks():
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

    def _recover_initial_state_folded(
        self, graph: FlowGraph, entry: int, stkoff: int
    ) -> int | None:
        """Initial state = the folded value the prologue writes into the state slot.

        Prefer the portable constant-``mov`` recovery (``_recover_initial_state``); when that
        abstains (``hardened_cond_chain_simple`` writes its initial state with a computed
        ``add (global ^ K) + K -> state`` the ``mov #const`` scan does not see), fall back to
        EMULATING the single state-slot write of each pre-header block (the blocks reachable
        from the function entry without passing through the dispatcher) in isolation. A single
        agreed folded value is the initial state; ambiguity / no fold -> abstain.
        """
        via_const = self._recover_initial_state(graph, entry, stkoff)
        if via_const is not None:
            return int(via_const)
        # Pre-header set: forward-reachable from the function entry with the dispatcher entry as
        # a cut (handler back-edges reach the join only THROUGH the dispatcher).
        entry_serial = int(getattr(graph, "entry_serial", 0))
        reach: set[int] = set()
        stack = [entry_serial]
        while stack:
            s = stack.pop()
            if s in reach:
                continue
            reach.add(s)
            if s == int(entry):
                continue  # cut at the dispatcher entry
            blk = self.mba.get_mblock(s)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                stack.append(int(blk.succ(i)))
        # Nearest pre-header that writes the state slot, folded in isolation.
        consts: set[int] = set()
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
                folded = self._fold_state_write_in_block(p, stkoff)
                if folded is not None:
                    consts.add(int(folded))
                queue.append(p)
        if len(consts) == 1:
            return next(iter(consts))
        return None

    def _self_update_blocks(
        self,
    ) -> dict[int, tuple[set[int], int, ida_hexrays.mop_t | None]]:
        """Map each stack slot to the SET of blocks that self-``OP``-update it.

        Returns ``{stkoff: (block_serials, var_size, a_state_mop)}``. The dominant slot (most
        blocks) is the state variable; ``a_state_mop`` is a representative ``mop_S`` for seeding.
        """
        out: dict[int, tuple[set[int], int, ida_hexrays.mop_t | None]] = {}
        for blk in self._blocks():
            insn = blk.head
            while insn is not None:
                upd = self._as_self_update(insn)
                if upd is not None:
                    stkoff, size, dmop = upd
                    blocks, prev_size, prev_mop = out.get(stkoff, (set(), size, None))
                    blocks.add(int(blk.serial))
                    out[stkoff] = (blocks, prev_size or size, prev_mop or dmop)
                insn = insn.next
        return out

    def _as_self_update(
        self, insn: ida_hexrays.minsn_t
    ) -> tuple[int, int, ida_hexrays.mop_t] | None:
        """Match ``stkvar = stkvar OP #const`` (OP in :data:`_SELF_UPDATE_OPS`)."""
        if insn.opcode not in _SELF_UPDATE_OPS:
            return None
        d = insn.d
        if d is None or d.t != ida_hexrays.mop_S:
            return None
        const_present = (insn.l is not None and insn.l.t == ida_hexrays.mop_n) or (
            insn.r is not None and insn.r.t == ida_hexrays.mop_n
        )
        if not const_present:
            return None
        for src in (insn.l, insn.r):
            if (
                src is not None
                and src.t == ida_hexrays.mop_S
                and int(src.s.off) == int(d.s.off)
            ):
                return (int(d.s.off), int(d.size), d)
        return None

    def _find_entry(self, handler_blocks: set[int]) -> int | None:
        """The dispatcher loop head: the block handlers branch back to (highest in-degree).

        Every handler ends by jumping back to the dispatcher; the entry is therefore the most
        common successor of the handler blocks, tie-broken by in-degree.
        """
        succ_hist: dict[int, int] = {}
        for hb in handler_blocks:
            blk = self.mba.get_mblock(hb)
            if blk is None:
                continue
            for i in range(blk.nsucc()):
                succ = int(blk.succ(i))
                if succ not in handler_blocks:
                    succ_hist[succ] = succ_hist.get(succ, 0) + 1
        if not succ_hist:
            return None
        return max(
            succ_hist,
            key=lambda s: (succ_hist[s], self.mba.get_mblock(s).npred()),
        )

    def _recover_initial_state(
        self, graph: FlowGraph, entry: int, stkoff: int
    ) -> int | None:
        """Initial state = the ``mov #const -> state_var`` in the prologue.

        Prefer the portable entry-dominance recovery (a predecessor of ``entry`` reachable from
        the function entry WITHOUT passing through the dispatcher); fall back to the unique
        ``entry`` predecessor that initializes the slot with a constant ``mov`` (handlers update
        it with ``OP``, never a bare ``mov #const``, so only the prologue matches).
        """
        minimal = StateDispatcherMap(
            rows=(),
            dispatcher_entry_block=int(entry),
            dispatcher_blocks=frozenset(),
            state_var_stkoff=int(stkoff),
            state_var_lvar_idx=None,
            source=RouterKind.CONDITION_CHAIN,
        )
        try:
            via_dominance = recover_entry_dominated_initial_state(graph, minimal)
        except Exception:  # noqa: BLE001 — portable recovery is best-effort
            via_dominance = None
        if via_dominance is not None:
            return int(via_dominance)

        entry_blk = self.mba.get_mblock(int(entry))
        consts: set[int] = set()
        for i in range(entry_blk.npred()):
            const = self._mov_const_to_stkoff(self.mba.get_mblock(entry_blk.pred(i)), stkoff)
            if const is not None:
                consts.add(const)
        if len(consts) == 1:
            return next(iter(consts))
        return None

    # -- live oracles -----------------------------------------------------------------
    def _emulate_to_handler(
        self, disc: _Discovery, state: int, dispatch_blocks_seen: set[int]
    ) -> int | None:
        """Seed the state var = ``state`` and step the dispatcher until control leaves it.

        Records every dispatcher-chain block stepped through into ``dispatch_blocks_seen`` (the
        emit path removes them). Returns the handler serial when control reaches a state-var
        WRITE (linear handler), a ``ret`` (exit handler), or stalls on a non-state branch (a
        conditional handler arm) -- otherwise ``None`` (abstain).
        """
        try:
            # ``mask_subreg_reads`` so the dispatcher's sub-register selector read
            # (``xdu.4(var_C.1)`` of the seeded wider state) yields the low byte, not the
            # full word -- scoped to THIS interpreter so other emulation consumers
            # (tigress/hodur transition facts) keep their exact prior behaviour.
            interp = MicroCodeInterpreter(symbolic_mode=False, mask_subreg_reads=True)
            env = MicroCodeEnvironment()
            env.define(disc.state_mop, int(state) & ((1 << (disc.var_size * 8)) - 1))
            cur_blk = self.mba.get_mblock(disc.entry)
            cur_ins = cur_blk.head
            for _ in range(_MAX_DISPATCH_STEPS):
                # Reached a handler? (left the dispatcher chain)
                if cur_blk.serial != disc.entry:
                    if self._writes_stkoff(cur_blk, disc.stkoff):
                        return int(cur_blk.serial)  # linear handler (writes state)
                    if cur_blk.tail is not None and cur_blk.tail.opcode == ida_hexrays.m_ret:
                        return int(cur_blk.serial)  # exit handler (returns)
                if cur_ins is None:
                    return None
                ok = interp.eval_instruction(
                    cur_blk, cur_ins, env, raise_exception=False
                )
                if not ok:
                    # Stalled on a value that is not the seeded state (e.g. a conditional arm
                    # branching on ``result``): this block IS the handler. At the entry it means
                    # a genuine failure -> abstain.
                    if cur_blk.serial != disc.entry:
                        return int(cur_blk.serial)
                    return None
                dispatch_blocks_seen.add(int(cur_blk.serial))
                cur_blk = env.next_blk
                cur_ins = env.next_ins
                if cur_blk is None:
                    return None
        except Exception:  # noqa: BLE001 — emulation failure means "cannot prove" -> abstain
            logger.debug("emulation_dispatcher: handler emulation raised", exc_info=True)
            return None
        return None

    def _region_facts(
        self, disc: _Discovery, handler: int, cache: dict[int, _RegionFacts]
    ) -> _RegionFacts:
        """Summarize a handler region: its ``state OP const`` writes + whether it returns.

        BFS forward from ``handler`` collecting self-update writes, NEVER crossing the
        dispatcher entry (that bounds the region to one handler body), and noting whether any
        block ends in ``ret``. A linear handler yields one transition; a conditional arm yields
        two; a pure exit yields none + ``reaches_ret``.
        """
        cached = cache.get(handler)
        if cached is not None:
            return cached
        transitions: list[tuple[int, int]] = []
        reaches_ret = False
        seen: set[int] = set()
        stack = [int(handler)]
        while stack and len(seen) < _MAX_REGION_BLOCKS:
            serial = stack.pop()
            if serial in seen or serial == disc.entry:
                continue
            seen.add(serial)
            blk = self.mba.get_mblock(serial)
            insn = blk.head
            while insn is not None:
                upd = self._as_self_update(insn)
                if upd is not None and upd[0] == disc.stkoff:
                    const = self._self_update_const(insn)
                    if const is not None:
                        transitions.append((insn.opcode, const))
                insn = insn.next
            if blk.tail is not None and blk.tail.opcode == ida_hexrays.m_ret:
                reaches_ret = True
            for i in range(blk.nsucc()):
                succ = int(blk.succ(i))
                if succ != disc.entry and succ not in seen:
                    stack.append(succ)
        facts = _RegionFacts(transitions=tuple(transitions), reaches_ret=reaches_ret)
        cache[handler] = facts
        return facts

    # -- small mop/minsn helpers ------------------------------------------------------
    def _blocks(self):
        for i in range(self.mba.qty):
            blk = self.mba.get_mblock(i)
            if blk is not None:
                yield blk

    @staticmethod
    def _self_update_const(insn: ida_hexrays.minsn_t) -> int | None:
        for src in (insn.l, insn.r):
            if src is not None and src.t == ida_hexrays.mop_n:
                return int(src.nnn.value)
        return None

    def _writes_stkoff(self, blk: ida_hexrays.mblock_t, stkoff: int) -> bool:
        insn = blk.head
        while insn is not None:
            d = insn.d
            if d is not None and d.t == ida_hexrays.mop_S and int(d.s.off) == int(stkoff):
                return True
            insn = insn.next
        return False

    def _mov_const_to_stkoff(
        self, blk: ida_hexrays.mblock_t, stkoff: int
    ) -> int | None:
        insn = blk.head
        found: int | None = None
        while insn is not None:
            if (
                insn.opcode == ida_hexrays.m_mov
                and insn.d is not None
                and insn.d.t == ida_hexrays.mop_S
                and int(insn.d.s.off) == int(stkoff)
                and insn.l is not None
                and insn.l.t == ida_hexrays.mop_n
            ):
                found = int(insn.l.nnn.value)
            insn = insn.next
        return found

    def _fold_state_write_in_block(
        self,
        blk_serial: int,
        stkoff: int,
        foldable_global_reads: dict[int, dict[int, int]] | None = None,
    ) -> int | None:
        """Fold a block's LAST write to ``stkoff`` to a concrete constant, or ``None``.

        Evaluates ONLY the state-slot-writing instruction with a FRESH, empty environment
        (ticket llr-iy9i round 4): an absolute next-state write -- ``mov #const -> state`` or a
        folded ``add (global ^ K) + K -> state`` whose operands are constants + IDB-read globals
        -- is self-contained, so an empty seed folds it. Instructions that read live
        accumulator state (``add var_8, #7 -> var_8``) are NOT state-slot writes and are
        skipped. ``mask_subreg_reads`` mirrors the dispatcher stepper. Returns the folded value
        masked to the write width, or ``None`` when the emulator cannot prove a constant (e.g.
        the write genuinely depends on the incoming state).

        GLOBAL-CARRIED next-state (ticket llr-k8oa): when ``foldable_global_reads`` is
        supplied, the next state may be carried THROUGH a writable global within the same
        block -- Approov's ``approov_vm_dispatcher`` state ``0xF6A1F`` does
        ``approov_qword |= 0xF6A20`` then ``state = (int)approov_qword``.  The
        single-instruction emulator above abstains on that ``mov global -> state``: it reads
        ``approov_qword`` (a writable ``.data`` global) with a fresh env, so the read is
        "not defined".  Stepping the WHOLE block via the proven legacy forward-fold
        (``get_bst_walkers().forward_eval_insn``) folds it: the global read resolves to its
        reaching-defs-stable ``.data`` initializer (``foldable_global_reads``), the in-block
        ``|=`` write is tracked under the gaddr key, and the subsequent ``state = global``
        read folds to the committed value.  This is exactly the in-block global dataflow the
        legacy ``minimal_state_recovery`` path uses, so a global-carried machine the static
        §1a recovers post-hoc now also recovers under the concolic engine.  ``None`` (sound
        abstain) whenever no constant is proven, identical to the direct path.
        """
        blk = self.mba.get_mblock(int(blk_serial))
        if blk is None:
            return None
        if foldable_global_reads is not None:
            folded = self._fold_state_write_whole_block(
                blk, int(stkoff), foldable_global_reads
            )
            if folded is not None:
                return folded
        result: int | None = None
        insn = blk.head
        while insn is not None:
            d = insn.d
            if (
                d is not None
                and d.t == ida_hexrays.mop_S
                and d.s is not None
                and int(d.s.off) == int(stkoff)
            ):
                try:
                    interp = MicroCodeInterpreter(
                        symbolic_mode=False, mask_subreg_reads=True
                    )
                    env = MicroCodeEnvironment()
                    if interp.eval_instruction(blk, insn, env, raise_exception=False):
                        rec = env.lookup(d, raise_exception=False)
                        if rec is not None:
                            width = int(d.size) or 4
                            result = int(rec) & ((1 << (width * 8)) - 1)
                        else:
                            result = None
                    else:
                        result = None
                except Exception:  # noqa: BLE001 — fold failure -> not a constant write
                    result = None
            insn = insn.next
        return result

    def _fold_state_write_whole_block(
        self,
        blk: ida_hexrays.mblock_t,
        stkoff: int,
        foldable_global_reads: dict[int, dict[int, int]],
    ) -> int | None:
        """Forward-fold the WHOLE block, returning the constant written to ``stkoff``.

        Reuses the proven legacy stepper (``get_bst_walkers().forward_eval_insn``), which
        carries exact stack / register / global constants instruction-by-instruction in a
        per-block map.  A write to a writable global is recorded under its gaddr key, so a
        later read of that global in the SAME block (``state = (int)approov_qword`` after
        ``approov_qword |= 0xF6A20``) resolves to the committed value; a read of a global
        proven store-free folds to its ``.data`` initializer via ``foldable_global_reads``.
        Returns the LAST constant the stepper resolves for the ``stkoff`` state-slot write,
        or ``None`` when no constant is proven (sound abstain).  Any stepper failure or a
        missing walker provider also abstains -- never a wrong fold.
        """
        try:
            forward_eval_insn = get_bst_walkers().forward_eval_insn
        except Exception:  # noqa: BLE001 — no provider registered -> fall back to direct fold
            return None
        stk_map: dict[int, int] = {}
        reg_map: dict[int, int] = {}
        result: int | None = None
        insn = blk.head
        while insn is not None:
            try:
                val = forward_eval_insn(
                    insn,
                    stk_map,
                    reg_map,
                    int(stkoff),
                    mba=self.mba,
                    foldable_global_reads=foldable_global_reads,
                )
            except Exception:  # noqa: BLE001 — stepper failure -> abstain on this fold
                return None
            if val is not None:
                result = int(val)
            insn = insn.next
        if result is None:
            return None
        return int(result) & 0xFFFFFFFFFFFFFFFF

    @staticmethod
    def _apply_op(state: int, opcode: int, const: int, mask: int) -> int:
        op = _SELF_UPDATE_OPS.get(opcode, "^")
        s, c = int(state) & mask, int(const) & mask
        if op == "^":
            return (s ^ c) & mask
        if op == "|":
            return (s | c) & mask
        if op == "&":
            return (s & c) & mask
        if op == "+":
            return (s + c) & mask
        if op == "-":
            return (s - c) & mask
        return s
