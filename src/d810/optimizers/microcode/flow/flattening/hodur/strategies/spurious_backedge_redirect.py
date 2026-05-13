"""SpuriousBackedgeRedirectStrategy — smoke-test SCC normalization.

Composes Pieces 1 (live-CFG SCC analysis), 2 (back-edge classification)
and 3a (redirect planner) into a Hodur strategy that emits
``ConvertToGoto`` modifications for actionable SPURIOUS back-edges.

Status: **MEASUREMENT smoke test, not "the fix"**.

Scope is intentionally narrow: only ``BLT_2WAY``-source SPURIOUS
back-edges with two successors are redirected. ``BLT_1WAY`` SPURIOUS
edges and ``UNKNOWN`` classifications are left untouched — they need
register-token support and reaching-def-based forward-target resolution
that lives in future pieces of the SCC normalization plan.

Default-OFF. Opt-in via ``D810_HODUR_ENABLE_SPURIOUS_REDIRECT=1``. The
strategy logs topology metrics (SCC count/sizes, within-SCC back-edge
count) before AND after planning so the operator can see the effect
empirically without the strategy being on by default.
"""
from __future__ import annotations

import os

from d810.cfg.backedge_classifier import parse_var_tokens
from d810.cfg.modification_builder import ModificationBuilder
from d810.cfg.scc import compute_live_cfg_sccs, nontrivial_sccs
from d810.cfg.spurious_backedge_redirect import (
    SpuriousRedirectPlan,
    plan_spurious_backedge_redirects,
)
from d810.core import logging
from d810.core.typing import TYPE_CHECKING
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
    "D810.hodur.strategy.spurious_backedge_redirect", logging.INFO
)

__all__ = ["SpuriousBackedgeRedirectStrategy"]

_GATE_ENV = "D810_HODUR_ENABLE_SPURIOUS_REDIRECT"

# Map mblock_t.type integer to symbolic name. Defined once here to avoid
# pulling in ida_hexrays for a constant table.
_MBLOCK_TYPE_NAMES = {
    0: "BLT_NONE",
    1: "BLT_STOP",
    2: "BLT_0WAY",
    3: "BLT_1WAY",
    4: "BLT_2WAY",
    5: "BLT_NWAY",
    6: "BLT_XTRN",
}


class SpuriousBackedgeRedirectStrategy:
    """Convert spurious BLT_2WAY back-edges to forward gotos.

    Family: ``FAMILY_CLEANUP`` — runs after all other Hodur reconstruction
    passes when enabled.
    """

    @property
    def name(self) -> str:
        return "spurious_backedge_redirect"

    @property
    def family(self) -> str:
        return FAMILY_CLEANUP

    def is_applicable(self, snapshot: "AnalysisSnapshot") -> bool:
        if os.environ.get(_GATE_ENV, "").strip() != "1":
            return False
        if snapshot.mba is None:
            return False
        return True

    def plan(self, snapshot: "AnalysisSnapshot") -> PlanFragment | None:
        if not self.is_applicable(snapshot):
            return None

        mba = snapshot.mba
        block_succs, block_types = _build_succ_and_type_maps(mba)
        block_writes, block_predicate_reads = _build_write_and_read_maps(mba)

        # Pre-plan topology snapshot.
        sccs_before = compute_live_cfg_sccs(block_succs)
        cyclic_before = nontrivial_sccs(sccs_before)
        biggest_before = max((s.size for s in cyclic_before), default=0)
        backedges_before = sum(len(s.cyclic_edges) for s in cyclic_before)
        logger.info(
            "SpuriousBackedgeRedirect: pre-plan topology — sccs=%d "
            "biggest_size=%d backedges=%d",
            len(cyclic_before),
            biggest_before,
            backedges_before,
        )

        plans = plan_spurious_backedge_redirects(
            block_succs=block_succs,
            block_types=block_types,
            block_writes=block_writes,
            block_predicate_reads=block_predicate_reads,
        )

        if not plans:
            logger.info("SpuriousBackedgeRedirect: no actionable plans")
            return None

        builder = ModificationBuilder.from_snapshot(snapshot)
        modifications: list = []
        owned_blocks: set[int] = set()
        for plan in plans:
            modifications.append(
                builder.convert_to_goto(plan.src_serial, plan.new_target)
            )
            owned_blocks.add(plan.src_serial)
            logger.info(
                "SpuriousBackedgeRedirect: blk[%d] %d -> %d (was conditional "
                "back-edge to %d) — %s",
                plan.src_serial,
                plan.new_target,
                plan.new_target,
                plan.old_target,
                plan.reason,
            )

        # Simulated post-plan topology (succs map after applying redirects).
        simulated_succs = dict(block_succs)
        for plan in plans:
            simulated_succs[plan.src_serial] = (plan.new_target,)
        sccs_after = compute_live_cfg_sccs(simulated_succs)
        cyclic_after = nontrivial_sccs(sccs_after)
        biggest_after = max((s.size for s in cyclic_after), default=0)
        backedges_after = sum(len(s.cyclic_edges) for s in cyclic_after)
        logger.info(
            "SpuriousBackedgeRedirect: simulated post-plan topology — "
            "sccs=%d biggest_size=%d backedges=%d (delta sccs=%+d "
            "biggest=%+d backedges=%+d)",
            len(cyclic_after),
            biggest_after,
            backedges_after,
            len(cyclic_after) - len(cyclic_before),
            biggest_after - biggest_before,
            backedges_after - backedges_before,
        )

        ownership = OwnershipScope(
            blocks=frozenset(owned_blocks),
            edges=frozenset(),
            transitions=frozenset(),
        )
        benefit = BenefitMetrics(
            handlers_resolved=0,
            transitions_resolved=len(plans),
            blocks_freed=0,
            conflict_density=0.0,
        )
        return PlanFragment(
            strategy_name=self.name,
            family=self.family,
            modifications=modifications,
            ownership=ownership,
            prerequisites=["handler_chain_composer", "dispatcher_trampoline_skip"],
            expected_benefit=benefit,
            risk_score=0.30,
            metadata={
                "execution_policy": "spurious_backedge_redirect",
                "smoke_test": True,
            },
        )


def _build_succ_and_type_maps(mba) -> tuple[
    dict[int, tuple[int, ...]],
    dict[int, str],
]:
    """Walk live mba and extract (block_succs, block_types) maps."""
    succs: dict[int, tuple[int, ...]] = {}
    types: dict[int, str] = {}
    qty = int(getattr(mba, "qty", 0))
    for i in range(qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        nsucc = int(blk.nsucc())
        succs[i] = tuple(int(blk.succ(j)) for j in range(nsucc))
        types[i] = _MBLOCK_TYPE_NAMES.get(int(blk.type), f"type_{int(blk.type)}")
    return succs, types


_CONDITIONAL_JUMP_LEADING_WORDS = frozenset({
    "jcnd", "jnz", "jz", "jae", "jb", "ja", "jbe",
    "jg", "jge", "jl", "jle", "jtbl",
})

_UNCONDITIONAL_JUMP_LEADING_WORDS = frozenset({"goto", "ijmp", "ret"})

_JUMP_LEADING_WORDS = (
    _CONDITIONAL_JUMP_LEADING_WORDS | _UNCONDITIONAL_JUMP_LEADING_WORDS
)


def _leading_opcode(text: str) -> str:
    stripped = (text or "").lstrip()
    if not stripped:
        return ""
    end = 0
    while end < len(stripped) and not stripped[end].isspace():
        end += 1
    return stripped[:end].lower()


def _build_write_and_read_maps(mba) -> tuple[
    dict[int, frozenset[str]],
    dict[int, frozenset[str]],
]:
    """Extract per-block writes and tail-predicate reads as %var_HEX tokens.

    Writes: union of "destination" tokens across non-jump instructions.
    The dstr rendering convention is ``src..., dst`` so the last
    ``%var_HEX`` token in the line is the destination — except for jump
    instructions where there is no destination var (``@target`` is a
    label).

    Predicate reads: ALL ``%var_HEX`` tokens from the tail instruction
    when the tail is a conditional jump. For unconditional goto and
    non-jump tails the result is empty.
    """
    writes: dict[int, frozenset[str]] = {}
    reads: dict[int, frozenset[str]] = {}
    qty = int(getattr(mba, "qty", 0))
    for i in range(qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        block_writes: set[str] = set()
        tail_text: str | None = None
        insn = blk.head
        while insn is not None:
            try:
                text = insn._print()
            except Exception:
                text = ""
            opcode = _leading_opcode(text)
            tail_text = text
            if opcode in _JUMP_LEADING_WORDS:
                # Jumps don't write any var.
                insn = insn.next
                continue
            tokens = parse_var_tokens(text)
            if tokens:
                # Destination is the LAST %var token in dstr.
                dest = max(tokens, key=lambda t: text.rfind(t))
                block_writes.add(dest)
            insn = insn.next
        writes[i] = frozenset(block_writes)
        if tail_text is None:
            reads[i] = frozenset()
            continue
        tail_opcode = _leading_opcode(tail_text)
        if tail_opcode in _CONDITIONAL_JUMP_LEADING_WORDS:
            reads[i] = parse_var_tokens(tail_text)
        else:
            reads[i] = frozenset()
    return writes, reads
