"""CounterHoistStrategy -- promote fused load-add-store induction operands.

OLLVM-flattened byte loops express induction as a single fused instruction
where the load is embedded as a sub-instruction (mop_d) of an arithmetic op::

    add  [ds.2:v54.8].8, v62.8, v30.8   ; m_add l=mop_d(m_ldx ds, v54), r=v62
    stx  v30 -> [ds.2:v54.8]            ; m_stx storing back to the same addr

IDA's MMAT_LVARS DCE eliminates the load (and therefore the increment) because
the m_ldx only appears as a sub-operand. The pseudocode loses the
``*ptr += step`` semantic and the do-while body looks like a stuck counter.

This strategy detects the pattern at MMAT_GLBOPT1 and queues
:class:`PromoteOperandToScalar` modifications that hoist the embedded m_ldx
into its own instruction with a fresh kreg destination, restoring an
explicit def-use chain that survives DCE.

Family: ``FAMILY_CLEANUP`` -- runs after HCC, and after optional
trampoline-skip when that experiment is enabled.

Default behavior
----------------
Default-on. Disable for archaeology / regression isolation with
``D810_HODUR_DISABLE_COUNTER_HOIST=1`` or
``D810_HODUR_ENABLE_COUNTER_HOIST=0``.

Risk: LOW -- the rewrite is semantically equivalent (same value computed,
same memory write); only the def-use shape changes.
"""
from __future__ import annotations

import os

import ida_hexrays

from d810.core import logging
from d810.core.typing import TYPE_CHECKING
from d810.cfg.modification_builder import ModificationBuilder
from d810.optimizers.microcode.flow.flattening.engine.strategy import (
    FAMILY_CLEANUP,
    BenefitMetrics,
    OwnershipScope,
    PlanFragment,
)

if TYPE_CHECKING:
    from d810.optimizers.microcode.flow.flattening.engine.snapshot import (
        AnalysisSnapshot,
    )

logger = logging.getLogger(
    "D810.hodur.strategy.counter_hoist", logging.DEBUG
)

__all__ = ["CounterHoistStrategy"]

_GATE_ENV_ENABLE = "D810_HODUR_ENABLE_COUNTER_HOIST"
_GATE_ENV_DISABLE = "D810_HODUR_DISABLE_COUNTER_HOIST"

# Arithmetic opcodes whose ``l`` operand is RMW-eligible (i.e. semantically
# read-modify-write the value loaded from memory).
_RMW_ARITH_OPCODES: frozenset[int] = frozenset({
    ida_hexrays.m_add,
    ida_hexrays.m_sub,
    ida_hexrays.m_xor,
    ida_hexrays.m_or,
    ida_hexrays.m_and,
})


class CounterHoistStrategy:
    """Promote fused load-add-store induction operands to standalone insns.

    Family: ``FAMILY_CLEANUP``.
    """

    @property
    def name(self) -> str:
        return "counter_hoist"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: AnalysisSnapshot) -> bool:
        if os.environ.get(_GATE_ENV_DISABLE, "").strip() == "1":
            return False
        if os.environ.get(_GATE_ENV_ENABLE, "").strip() == "0":
            return False
        return snapshot.mba is not None

    def plan(self, snapshot: AnalysisSnapshot) -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        match_count = 0

        for i in range(mba.qty):
            blk = mba.get_mblock(i)
            if blk is None:
                continue

            insn = blk.head
            while insn is not None:
                hit = self._match_load_arith_store(insn)
                if hit is not None:
                    side, host_ea, host_opcode = hit
                    modifications.append(
                        builder.promote_operand_to_scalar(
                            source_block=int(blk.serial),
                            host_ea=host_ea,
                            host_opcode=host_opcode,
                            operand_side=side,
                        )
                    )
                    owned_blocks.add(int(blk.serial))
                    match_count += 1
                    logger.info(
                        "counter_hoist: queued promote at blk[%d]@0x%x "
                        "opcode=%d side=%s",
                        int(blk.serial),
                        host_ea,
                        host_opcode,
                        side,
                    )
                insn = insn.next

        logger.info(
            "CounterHoist: %d load-arith-store sites queued for promotion",
            match_count,
        )

        if not modifications:
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
            modifications=modifications,
            ownership=ownership,
            prerequisites=["handler_chain_composer"],
            expected_benefit=benefit,
            risk_score=0.10,
            metadata={
                "safeguard_min_required": 1,
                "allow_prerequisite_block_overlap": True,
                "execution_policy": "counter_hoist",
            },
        )

    # ------------------------------------------------------------------
    # Pattern detection
    # ------------------------------------------------------------------

    @staticmethod
    def _match_load_arith_store(
        host: object,
    ) -> tuple[str, int, int] | None:
        """Return (side, host_ea, host_opcode) if ``host`` is the arithmetic
        step of a load-arith-store induction triple, else ``None``.

        Pattern (operand-side ``l``, the common form)::

            host:  add  [ds:V].sz, step.sz, dst.sz   (l=mop_d(m_ldx ds, V))
            store: stx  dst -> [ds:V]                (in same block, after host)

        Pattern (operand-side ``r``, also legal but rarer)::

            host:  add  step.sz, [ds:V].sz, dst.sz   (r=mop_d(m_ldx ds, V))
            store: stx  dst -> [ds:V]
        """
        if host is None:
            return None
        if int(host.opcode) not in _RMW_ARITH_OPCODES:
            return None

        side, sub_mop = CounterHoistStrategy._embedded_load_side(host)
        if side is None:
            return None

        ldx = sub_mop.d
        # m_ldx layout: l = segment register, r = address operand, d = dest.
        if ldx is None or int(ldx.opcode) != ida_hexrays.m_ldx:
            return None

        # Find a same-block m_stx that consumes host.d and writes back to the
        # same address.  Bounded forward scan to avoid quadratic blowup.
        scan = host.next
        scan_budget = 16
        while scan is not None and scan_budget > 0:
            scan_budget -= 1
            if int(scan.opcode) == ida_hexrays.m_stx:
                # m_stx layout: l = value, r = segment, d = address operand.
                if (
                    CounterHoistStrategy._mops_equivalent(scan.l, host.d)
                    and CounterHoistStrategy._mops_equivalent(scan.r, ldx.l)
                    and CounterHoistStrategy._mops_equivalent(scan.d, ldx.r)
                ):
                    return side, int(host.ea), int(host.opcode)
            scan = scan.next

        return None

    @staticmethod
    def _embedded_load_side(host: object) -> tuple[str | None, object | None]:
        """Return ('l'|'r', mop) if one operand carries an m_ldx sub-insn.

        Prefers the ``l`` operand when both are mop_d carrying loads (the
        canonical OLLVM induction shape).
        """
        for side in ("l", "r"):
            mop = getattr(host, side)
            if mop is None:
                continue
            if mop.t != ida_hexrays.mop_d or mop.d is None:
                continue
            if int(mop.d.opcode) == ida_hexrays.m_ldx:
                return side, mop
        return None, None

    @staticmethod
    def _mops_equivalent(a: object, b: object) -> bool:
        """Best-effort mop_t comparison, tolerant to size mismatches.

        Uses the SDK's ``equal_mops`` when available, falls back to dstr().
        """
        if a is None or b is None:
            return False
        eq = getattr(a, "equal_mops", None)
        if eq is not None:
            try:
                # EQ_IGNSIZE = 0x01 in hexrays.hpp; tolerate int/flag drift.
                eq_ignsize = getattr(ida_hexrays, "EQ_IGNSIZE", 0x01)
                return bool(eq(b, eq_ignsize))
            except Exception:
                pass
        try:
            return a.dstr() == b.dstr()
        except Exception:
            return False
