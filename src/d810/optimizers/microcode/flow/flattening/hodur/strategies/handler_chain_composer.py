"""HandlerChainComposerStrategy -- region-based linearization for byte-handler chains.

This is a NEW, standalone strategy implementing option (β) from ticket
``uee-b7ze``: body composition for sequential state-setter handler chains.

Motivation
----------
After ``DirectLinearization``, byte-handler producers/consumers are placed on
diverging execution paths.  IDA's data-flow optimizer determines defs no
longer dominate uses and DCEs them.  Empirical case on
``sub_7FFD3338C040``: bytes 1, 2, 4, 5 are written by handlers but wiped
from AFTER pseudocode despite being intact in our ``post_pipeline``
snapshot.

Strategy
--------
1. Detect sequential state-setter chains in the linearized state DAG: a
   sequence of state-handler nodes ``s0 -> s1 -> ... -> sn`` where each
   ``si`` is reachable only from ``s_{i-1}`` (no branching, single
   semantic edge), and each handler entry has only one effective
   predecessor.
2. For each handler-block in the chain, walk live ``minsn_t.head`` and
   collect ``m_stx`` instructions (memory writes — the byte writes), as
   well as a small set of permitted register/stkvar setup writes that
   compute the m_stx source.
3. Compose the per-handler instruction tuples into a single
   straight-line ``InsnSnapshot`` sequence.
4. Emit ``InsertBlock(pred, succ, instructions=composed)``.  ``pred`` is
   the chain entry's predecessor (chain anchor); ``succ`` is the chain
   exit's successor.

Default-OFF
-----------
Behavior is gated on ``HandlerChainComposerStrategy.HANDLER_CHAIN_COMPOSER_ENABLED``
(class flag, defaults to ``False``).  When disabled, ``plan()`` returns
``None`` and emits no modifications, so registering the strategy in
``EXPERIMENTAL_STRATEGIES`` is safe.

Family: ``FAMILY_DIRECT``.
Prerequisites: ``["direct_handler_linearization"]`` -- the chain detection
relies on the linearized DAG that ``StateWriteReconstructionStrategy``
produces.
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from d810.core.typing import TYPE_CHECKING

import ida_hexrays

from d810.core import logging
from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.graph_modification import InsertBlock
from d810.cfg.modification_builder import ModificationBuilder
from d810.hexrays.mutation.ir_translator import capture_insn_snapshot
from d810.hexrays.mutation.insn_snapshot_materializer import (
    validate_insn_snapshots,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategy import (
    FAMILY_DIRECT,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.hodur.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger("D810.hodur.strategy.handler_chain_composer")

__all__ = [
    "HandlerChainCandidate",
    "HandlerChainComposerStrategy",
]


@dataclass(frozen=True, slots=True)
class HandlerChainCandidate:
    """A detected sequential state-setter chain ready for composition."""

    handler_serials: tuple[int, ...]
    """Ordered handler-entry block serials in the chain (s0..sn)."""

    pred_serial: int
    """Predecessor block (chain anchor) feeding the first handler entry."""

    succ_serial: int
    """Successor block reached after the chain exits."""

    composed_instructions: tuple[InsnSnapshot, ...]
    """Concatenated ``m_stx`` (and supporting setup) snapshots in chain order."""

    state_values: tuple[int, ...]
    """State constants attached to each handler in the chain (informational)."""


# Opcodes that abort composition because their effects are hard to
# preserve in a relocated InsertBlock body: external side effects
# (calls), control-flow termination (ret), assembly escape (ext), and
# indirect jumps (jtbl/ijmp) that change CFG topology.  Everything else
# — arithmetic, flag setters, conditional branches, byte loads/stores
# — is composable.
_FORBIDDEN_COMPOSITION_OPCODES: frozenset[int] = frozenset(
    {
        ida_hexrays.m_call,   # external side effects
        ida_hexrays.m_icall,  # external side effects (indirect)
        ida_hexrays.m_ret,    # control-flow termination
        ida_hexrays.m_ext,    # extended assembly escape
        ida_hexrays.m_jtbl,   # indirect jump (jump-table)
        ida_hexrays.m_ijmp,   # indirect jump (computed)
    }
)


class HandlerChainComposerStrategy:
    """Compose body of byte-handler chains into a single straight-line block.

    See module docstring for the full design rationale.

    Class flag
    ----------
    ``HANDLER_CHAIN_COMPOSER_ENABLED`` (bool, default ``False``).  When
    ``False`` (the default), ``plan()`` always returns ``None`` and the
    strategy emits no modifications.  Set to ``True`` only for targeted
    experiments.
    """

    # CLASS-LEVEL GATE: keep behavior off by default.  Same pattern as
    # ``HodurUnflattener.MBL_KEEP_ENABLED``.  Set via env var
    # ``D810_ENABLE_HANDLER_CHAIN_COMPOSER=1`` to opt in.
    HANDLER_CHAIN_COMPOSER_ENABLED: bool = bool(
        int(os.environ.get("D810_ENABLE_HANDLER_CHAIN_COMPOSER", "0"))
    )

    @property
    def name(self) -> str:
        return "handler_chain_composer"

    @property
    def family(self) -> str:
        return FAMILY_DIRECT

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        """Return True when the gate is on and we have a state machine."""
        if not self.HANDLER_CHAIN_COMPOSER_ENABLED:
            return False
        if snapshot.mba is None:
            return False
        if snapshot.state_machine is None:
            return False
        if not getattr(snapshot.state_machine, "handlers", None):
            return False
        return True

    def plan(
        self, snapshot: "AnalysisSnapshot"
    ) -> "PlanFragment | None":
        """Detect chains, compose bodies, and emit InsertBlock modifications.

        Returns ``None`` when the strategy is disabled, no chains are
        detected, or composition fails.
        """
        if not self.is_applicable(snapshot):
            return None

        candidates = self.detect_chains(snapshot)
        if not candidates:
            logger.info(
                "HandlerChainComposer: no candidate chains detected"
            )
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        emitted = 0

        for candidate in candidates:
            if not candidate.composed_instructions:
                logger.info(
                    "HandlerChainComposer: chain pred=%d succ=%d has no"
                    " composable instructions; skipping",
                    candidate.pred_serial,
                    candidate.succ_serial,
                )
                continue
            reason = validate_insn_snapshots(candidate.composed_instructions)
            if reason is not None:
                logger.warning(
                    "HandlerChainComposer: snapshot validation failed for"
                    " chain pred=%d succ=%d: %s",
                    candidate.pred_serial,
                    candidate.succ_serial,
                    reason,
                )
                continue
            modifications.append(
                InsertBlock(
                    pred_serial=candidate.pred_serial,
                    succ_serial=candidate.succ_serial,
                    instructions=candidate.composed_instructions,
                )
            )
            owned_blocks.update(candidate.handler_serials)
            owned_blocks.add(candidate.pred_serial)
            emitted += 1
            logger.info(
                "HandlerChainComposer: composed chain pred=%d succ=%d"
                " handlers=%s ninsns=%d",
                candidate.pred_serial,
                candidate.succ_serial,
                candidate.handler_serials,
                len(candidate.composed_instructions),
            )

        # Silence unused-builder lint until we route emission through it.
        _ = builder

        if not modifications:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=len(owned_blocks),
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["direct_handler_linearization"],
            expected_benefit=benefit,
            risk_score=0.5,
            metadata={
                "handler_chain_composer_emitted": emitted,
            },
        )

    # ------------------------------------------------------------------
    # Chain detection
    # ------------------------------------------------------------------

    def detect_chains(
        self, snapshot: "AnalysisSnapshot"
    ) -> list[HandlerChainCandidate]:
        """Detect sequential state-setter chains in the snapshot.

        A chain is a maximal sequence ``s0 -> s1 -> ... -> sn`` where:

        * each ``s_i`` (i>0) has exactly one predecessor (``s_{i-1}``)
        * each ``s_i`` has exactly one successor (which is ``s_{i+1}`` or
          the chain exit)
        * the entry handler ``s0`` has at least one predecessor (the
          chain anchor)
        * each handler's instruction stream is composable (whitelisted
          opcodes only)

        Returns a list of detected candidates with fully composed
        instruction tuples.
        """
        mba = snapshot.mba
        if mba is None:
            return []

        sm = snapshot.state_machine
        # ``DispatcherStateMachine.handlers`` is ``dict[int, StateHandler]``;
        # iterate VALUES, not keys (which would be state-value ints).
        handlers_attr = getattr(sm, "handlers", None) or {}
        if isinstance(handlers_attr, dict):
            handlers = list(handlers_attr.values())
        else:
            handlers = list(handlers_attr)
        if not handlers:
            return []

        # Build a set of handler-entry serials.  ``StateHandler`` exposes
        # ``check_block`` (the BST decision block) and ``handler_blocks``
        # (the handler-body block list).  Prefer ``handler_blocks[0]``
        # when available; fall back to ``check_block``.
        handler_entries: set[int] = set()
        for h in handlers:
            blocks = getattr(h, "handler_blocks", None) or ()
            if blocks:
                try:
                    handler_entries.add(int(blocks[0]))
                    continue
                except (ValueError, TypeError, IndexError):
                    pass
            check = getattr(h, "check_block", None)
            if isinstance(check, int):
                handler_entries.add(int(check))

        if not handler_entries:
            return []
        logger.info(
            "HandlerChainComposer: %d handler entries from state-machine",
            len(handler_entries),
        )

        # Walk handler entries; for each one whose predecessor is NOT a
        # handler entry, attempt to extend a chain forward.
        visited: set[int] = set()
        candidates: list[HandlerChainCandidate] = []

        for start in sorted(handler_entries):
            if start in visited:
                continue
            chain = self._walk_chain_forward(
                mba=mba,
                start=start,
                handler_entries=handler_entries,
            )
            if chain is None:
                continue
            for serial in chain.handler_serials:
                visited.add(serial)
            # Length-1 chains are still candidates: a single handler
            # whose body needs to be lifted onto the linearized path so
            # its def-use chain is preserved.  The benefit is use-def
            # preservation, not structural compaction.
            candidates.append(chain)

        return candidates

    def _walk_chain_forward(
        self,
        *,
        mba: object,
        start: int,
        handler_entries: set[int],
    ) -> HandlerChainCandidate | None:
        """Walk forward from ``start`` while the chain invariants hold."""
        try:
            start_blk = mba.get_mblock(start)  # type: ignore[attr-defined]
        except Exception:
            return None
        if start_blk is None:
            return None

        # Anchor predecessor: must have exactly one effective non-handler
        # predecessor.
        pred_candidates: list[int] = []
        try:
            for i in range(start_blk.npred()):
                pred = int(start_blk.pred(i))
                pred_candidates.append(pred)
        except Exception:
            return None
        if len(pred_candidates) != 1:
            return None
        anchor_pred = pred_candidates[0]
        if anchor_pred in handler_entries:
            return None  # not a chain start; some upstream handler feeds us

        chain_serials: list[int] = []
        composed: list[InsnSnapshot] = []
        state_values: list[int] = []
        cur_serial = start

        # Cap depth defensively so we never run forever on malformed CFGs.
        for _ in range(64):
            blk = mba.get_mblock(cur_serial)  # type: ignore[attr-defined]
            if blk is None:
                break

            # Composable opcode guard + capture.
            insns = self._capture_block_composable_instructions(blk)
            if insns is None:
                # Non-composable handler; stop here.
                break

            chain_serials.append(cur_serial)
            composed.extend(insns)
            state_values.append(0)  # state value annotation (unused MVP)

            # Single successor required to extend.
            try:
                if blk.nsucc() != 1:
                    break
                succ_serial = int(blk.succ(0))
            except Exception:
                break

            # Stop if successor is outside the handler set — we found the
            # chain exit (chain_serials[-1] -> succ_serial).
            if succ_serial not in handler_entries:
                return HandlerChainCandidate(
                    handler_serials=tuple(chain_serials),
                    pred_serial=int(anchor_pred),
                    succ_serial=int(succ_serial),
                    composed_instructions=tuple(composed),
                    state_values=tuple(state_values),
                )

            # Successor IS a handler entry. Continue only if it has exactly
            # one predecessor (us).
            try:
                succ_blk = mba.get_mblock(succ_serial)  # type: ignore[attr-defined]
            except Exception:
                break
            if succ_blk is None:
                break
            try:
                if succ_blk.npred() != 1 or int(succ_blk.pred(0)) != cur_serial:
                    # Joining branch; stop chain at current handler with
                    # succ as exit.
                    return HandlerChainCandidate(
                        handler_serials=tuple(chain_serials),
                        pred_serial=int(anchor_pred),
                        succ_serial=int(succ_serial),
                        composed_instructions=tuple(composed),
                        state_values=tuple(state_values),
                    )
            except Exception:
                break

            cur_serial = succ_serial

        # Fell out via depth-cap or break: emit only when we have a
        # clear single successor of the last block.  Length-1 is allowed
        # (single-handler chains preserve def-use just as well as multi-
        # handler chains; the goal is dominance, not compaction).
        if not chain_serials:
            return None
        last_blk = mba.get_mblock(chain_serials[-1])  # type: ignore[attr-defined]
        if last_blk is None or last_blk.nsucc() != 1:
            return None
        return HandlerChainCandidate(
            handler_serials=tuple(chain_serials),
            pred_serial=int(anchor_pred),
            succ_serial=int(last_blk.succ(0)),
            composed_instructions=tuple(composed),
            state_values=tuple(state_values),
        )

    @staticmethod
    def _capture_block_composable_instructions(
        blk: object,
    ) -> list[InsnSnapshot] | None:
        """Walk ``blk.head`` and capture composable instructions, or None.

        Returns None if any instruction has a non-whitelisted opcode (we
        can't safely compose unknown side-effects).  ``m_goto`` and
        ``m_nop`` tails are silently dropped from the composition output.
        """
        out: list[InsnSnapshot] = []
        try:
            insn = blk.head  # type: ignore[attr-defined]
        except Exception:
            return None
        while insn is not None:
            opcode = int(insn.opcode)
            # Drop trivial control-flow / no-op tails — they won't be
            # part of the composed body.
            if opcode in (ida_hexrays.m_goto, ida_hexrays.m_nop):
                insn = insn.next
                continue
            if opcode in _FORBIDDEN_COMPOSITION_OPCODES:
                return None  # abort composition for this handler
            try:
                snap = capture_insn_snapshot(insn)
            except Exception as exc:
                logger.warning(
                    "HandlerChainComposer: capture_insn_snapshot failed at"
                    " ea=0x%x opcode=%d: %s",
                    int(getattr(insn, "ea", 0)),
                    opcode,
                    exc,
                )
                return None
            out.append(snap)
            insn = insn.next
        return out
