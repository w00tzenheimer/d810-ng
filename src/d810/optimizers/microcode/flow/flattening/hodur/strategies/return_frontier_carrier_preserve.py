"""ReturnFrontierCarrierPreserve -- restore lvar carrier identity at
return-frontier writers classified POINTER_IDENTITY_PROPAGATED.

Default-off; opt-in via D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE=1.

Why
---
OLLVM-flattened functions that return a pointer derived from an arg
(e.g. ``(__int64)v49 = arg_20 + 0xD0``) lose carrier identity when
D810's upstream simplification produces a single-def single-use shape
that IDA's MMAT_GLBOPT1 copy-prop then attacks.  By the time
MMAT_LVARS reconstructs lvars, the return-slot write has become
``add %arg_20.8, #0xD0.8, %var_8.8`` instead of
``mov %var_178.8, %var_8.8``, and IDA renders ``return a5 + 0xD0``
instead of ``return v49``.

Scope (per user directive)
--------------------------
* Writer blocks classified POINTER_IDENTITY_PROPAGATED by
  :mod:`d810.recon.flow.return_frontier_carrier_audit`.
* The strategy fires at MMAT_GLBOPT1 (before IDA's copy-prop
  finalize) and operates on the live mba.

Hard exclusions
---------------
* Never touch writers classified STATE_GUARD_ARTIFACT
  (e.g. 0xC5FB34A1D9A6E315 case) -- pool-qword leakage, not a
  recoverable carrier.
* Never touch writers classified RETURN_CARRIER_LOST -- those are
  legitimate constant returns by design.
* Never modify CFG topology -- only mutate operand identity in an
  existing instruction.
"""
from __future__ import annotations

import os

import ida_hexrays

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)
from d810.recon.flow.return_frontier_carrier_audit import (
    audit_return_frontier_carriers,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.return_frontier_carrier_preserve",
    logging.DEBUG,
)

__all__ = ["ReturnFrontierCarrierPreserveStrategy"]

_GATE_ENV = "D810_HODUR_RETURN_FRONTIER_CARRIER_PRESERVE"


class ReturnFrontierCarrierPreserveStrategy:
    """Restore lvar carrier identity at POINTER_IDENTITY_PROPAGATED writers.

    Family: ``FAMILY_CLEANUP`` -- runs after CounterHoistStrategy,
    before D810's maturity boundary so the carrier-restoring
    mutation precedes IDA's MMAT_GLBOPT1 copy-prop sweep.
    """

    @property
    def name(self) -> str:
        return "return_frontier_carrier_preserve"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        # SUPERSEDED: per user directive (2026-05-03), downstream
        # carrier-rebranding is the wrong fix.  The correct fix is the
        # upstream HCC carrier-shred guard
        # (``HandlerChainComposerStrategy._filter_carrier_shredding_mods``),
        # which preserves the original carrier-def path before it can
        # be collapsed into a copy-prop-vulnerable shape.  This
        # strategy is retained as documentation/scaffold only and is
        # never applicable.
        if os.environ.get(_GATE_ENV, "").strip() == "1":
            logger.info(
                "RETURN_FRONTIER_CARRIER_PRESERVE: deprecated; superseded "
                "by HCC upstream carrier-shred guard "
                "(_filter_carrier_shredding_mods)"
            )
        return False

    def plan(self, snapshot: "AnalysisSnapshot") -> "PlanFragment | None":
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        dag = getattr(snapshot, "linearized_state_dag", None)
        corridors = (
            tuple(getattr(dag, "side_effect_corridors", ()) or ())
            if dag is not None
            else ()
        )

        # Run audit to obtain classifications.  Audit is read-only
        # and gated independently; we invoke its analysis function
        # directly so its env gate doesn't block us.  audit_return
        # _frontier_carriers honors its own gate; we set it here
        # transiently if not already on so we can read the
        # classification.
        prior_audit_gate = os.environ.get(
            "D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT", ""
        )
        os.environ["D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"] = "1"
        try:
            entries = audit_return_frontier_carriers(
                mba=mba,
                side_effect_corridors=corridors,
                label=self.name,
            )
        finally:
            if prior_audit_gate:
                os.environ[
                    "D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT"
                ] = prior_audit_gate
            else:
                os.environ.pop(
                    "D810_RECON_RETURN_FRONTIER_CARRIER_AUDIT", None
                )

        accepted_blocks: list[int] = []
        owned_blocks: set[int] = set()
        seen_writers: set[int] = set()

        for entry in entries:
            if entry.classification != "POINTER_IDENTITY_PROPAGATED":
                continue
            writer_serial = entry.writer_block
            if writer_serial is None:
                continue
            if int(writer_serial) in seen_writers:
                continue
            seen_writers.add(int(writer_serial))

            blk = mba.get_mblock(int(writer_serial))
            if blk is None:
                logger.info(
                    "RETURN_FRONTIER_CARRIER_PRESERVE_REJECTED "
                    "block=%d reason=writer_blk_not_in_mba",
                    int(writer_serial),
                )
                continue

            writer_insn = self._find_writer_insn(blk, entry)
            if writer_insn is None:
                logger.info(
                    "RETURN_FRONTIER_CARRIER_PRESERVE_REJECTED "
                    "block=%d reason=writer_insn_not_found "
                    "returned=%s",
                    int(writer_serial),
                    entry.returned_mop_repr,
                )
                continue

            # Search the writer block first; fall back to the audit's
            # walk_path predecessors (the cascade body where the
            # original lvar carrier instruction may still live).
            carrier_mop = self._find_sibling_carrier(blk, writer_insn)
            if carrier_mop is None:
                for path_blk_serial in entry.walk_path:
                    if int(path_blk_serial) == int(writer_serial):
                        continue
                    path_blk = mba.get_mblock(int(path_blk_serial))
                    if path_blk is None:
                        continue
                    carrier_mop = self._find_sibling_carrier(
                        path_blk, writer_insn
                    )
                    if carrier_mop is not None:
                        logger.info(
                            "RETURN_FRONTIER_CARRIER_PRESERVE: carrier "
                            "found in path_blk=%d (writer=%d)",
                            int(path_blk_serial), int(writer_serial),
                        )
                        break
            if carrier_mop is None:
                logger.info(
                    "RETURN_FRONTIER_CARRIER_PRESERVE_REJECTED "
                    "block=%d reason=no_sibling_carrier returned=%s",
                    int(writer_serial),
                    entry.returned_mop_repr,
                )
                continue

            if not self._restore_carrier(writer_insn, carrier_mop):
                logger.info(
                    "RETURN_FRONTIER_CARRIER_PRESERVE_REJECTED "
                    "block=%d reason=mutation_failed",
                    int(writer_serial),
                )
                continue

            try:
                blk.mark_lists_dirty()
            except Exception:
                pass

            carrier_idx = -1
            try:
                if carrier_mop.l is not None:
                    carrier_idx = int(carrier_mop.l.idx)
            except (AttributeError, TypeError):
                pass

            accepted_blocks.append(int(writer_serial))
            owned_blocks.add(int(writer_serial))
            logger.info(
                "RETURN_FRONTIER_CARRIER_PRESERVE_ACCEPTED "
                "block=%d writer_ea=%s carrier_lvar_idx=%d "
                "was=%s",
                int(writer_serial),
                hex(int(getattr(writer_insn, "ea", 0))),
                carrier_idx,
                entry.returned_mop_repr,
            )

        if not accepted_blocks:
            return None

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=0,
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=[],   # operand mutation, not a CFG edit
            ownership=ownership,
            prerequisites=["counter_hoist"],
            expected_benefit=benefit,
            risk_score=0.10,
            metadata={
                "safeguard_min_required": 1,
                "allow_prerequisite_block_overlap": True,
                "execution_policy": "return_frontier_carrier_preserve",
                "accepted_count": len(accepted_blocks),
                "accepted_blocks": tuple(accepted_blocks),
            },
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _find_writer_insn(blk, entry):
        """Find the writer instruction in ``blk``.  Audit gives us
        ``entry.returned_mop_repr`` (the dstr() of the writer); match
        by substring on each insn's dstr().  Last-match-wins because
        a block's terminal writer to the return slot is the audit's
        reported writer.
        """
        if blk is None:
            return None
        target_repr = getattr(entry, "returned_mop_repr", None)
        if not target_repr:
            return None
        match = None
        insn = blk.head
        while insn is not None:
            try:
                rendered = insn.dstr() if hasattr(insn, "dstr") else None
            except Exception:
                rendered = None
            if rendered and target_repr in rendered:
                match = insn
            insn = insn.next
        return match

    @staticmethod
    def _find_sibling_carrier(blk, writer_insn):
        """Find a sibling instruction in the same block whose source
        operand is a ``mop_l`` (lvar) carrying the same SSA value as
        the writer's source.

        Strategy:
          1. Try strict SSA value-num match.
          2. Fall back to first ``mop_l`` reference in the block --
             safe because the audit has already scoped us to a
             POINTER_IDENTITY_PROPAGATED writer; any sibling lvar in
             the same block is the cascade's carrier candidate.
        """
        if blk is None or writer_insn is None:
            return None
        try:
            mop_l = ida_hexrays.mop_l
        except AttributeError:
            return None

        writer_l = getattr(writer_insn, "l", None)
        writer_valnum = (
            int(getattr(writer_l, "valnum", 0)) if writer_l is not None else 0
        )

        def _is_lvar(cand) -> bool:
            try:
                return cand is not None and int(cand.t) == mop_l
            except (AttributeError, TypeError):
                return False

        # Pass 1: SSA value-num match.
        if writer_valnum:
            insn = blk.head
            while insn is not None:
                if insn is not writer_insn:
                    for side in ("l", "r", "d"):
                        cand = getattr(insn, side, None)
                        if _is_lvar(cand):
                            try:
                                if int(getattr(cand, "valnum", 0)) == writer_valnum:
                                    return cand
                            except (AttributeError, TypeError):
                                pass
                insn = insn.next

        # Pass 2: any mop_l in the block (best-effort).
        insn = blk.head
        while insn is not None:
            if insn is not writer_insn:
                for side in ("l", "r", "d"):
                    cand = getattr(insn, side, None)
                    if _is_lvar(cand):
                        return cand
            insn = insn.next
        return None

    @staticmethod
    def _restore_carrier(writer_insn, carrier_mop) -> bool:
        """Replace ``writer_insn``'s source operand with ``carrier_mop``
        and rewrite the opcode to ``m_mov`` if it was an arithmetic
        op.  Destination (``writer_insn.d``) is preserved.

        Returns True on successful mutation, False on failure.
        """
        if writer_insn is None or carrier_mop is None:
            return False
        try:
            m_mov = ida_hexrays.m_mov
        except AttributeError:
            return False

        try:
            # Snapshot the destination so we can restore it after the
            # opcode rewrite (some IDA SDK versions reset .d on
            # opcode change).
            saved_dest = ida_hexrays.mop_t()
            saved_dest.assign(writer_insn.d)

            # Build a fresh mop_t initialized from the carrier.
            new_l = ida_hexrays.mop_t()
            new_l.assign(carrier_mop)

            # Rewrite opcode to m_mov, swap in carrier as source,
            # erase the right operand (m_add had a constant there;
            # m_mov uses only .l → .d).
            writer_insn.opcode = m_mov
            writer_insn.l.assign(new_l)
            try:
                writer_insn.r.erase()
            except Exception:
                pass
            writer_insn.d.assign(saved_dest)
            return True
        except Exception as exc:
            logger.warning(
                "RETURN_FRONTIER_CARRIER_PRESERVE: mutation raised %s",
                exc,
            )
            return False
