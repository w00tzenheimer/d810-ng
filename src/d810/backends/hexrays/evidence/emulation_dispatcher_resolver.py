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
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
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
from d810.capabilities.dispatcher import RouterKind
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
                source=DispatcherType.CONDITIONAL_CHAIN,
            )
            for row in result.rows
        )
        dmap = StateDispatcherMap(
            rows=rows,
            dispatcher_entry_block=int(disc.entry),
            dispatcher_blocks=dispatcher_blocks,
            state_var_stkoff=int(disc.stkoff),
            state_var_lvar_idx=None,
            source=DispatcherType.CONDITIONAL_CHAIN,
            initial_state=int(disc.initial_state),
        )
        logger.info(
            "emulation_dispatcher: recovered %d rows by emulation "
            "(entry=%d stkoff=0x%x init=0x%x terminals=%d unresolved=%d dispatch_blocks=%d)",
            len(rows),
            disc.entry,
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
        if not per_block:
            return None
        # Dominant state slot = the one self-updated in the MOST blocks (one block per handler
        # transition); shape-invariant (true for equality, switch, and XOR-masked machines).
        stkoff = max(per_block, key=lambda k: len(per_block[k][0]))
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
            logger.info(
                "emulation_dispatcher: reject -- too few handler blocks (%d)",
                len(handler_blocks),
            )
            return None

        entry = self._find_entry(handler_blocks)
        if entry is None:
            logger.info("emulation_dispatcher: reject -- no dispatcher entry found")
            return None

        initial_state = self._recover_initial_state(graph, entry, stkoff)
        if initial_state is None:
            logger.info(
                "emulation_dispatcher: reject -- no initial state (entry=%d stkoff=0x%x)",
                int(entry),
                int(stkoff),
            )
            return None
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
            source=DispatcherType.CONDITIONAL_CHAIN,
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
