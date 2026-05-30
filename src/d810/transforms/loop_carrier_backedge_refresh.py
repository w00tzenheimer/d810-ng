"""Fact-backed loop-carrier backedge refresh pass.

This transform repairs the compacted shape where a loop predicate has a
documented ``LoopCarrierFact`` with its carrier writer/reader outside the loop
SCC, while a shortcut backedge jumps directly to the predicate and refreshes
only a subset of predicate operands.

The pass is intentionally dormant unless explicitly enabled by
``D810_LOOP_CARRIER_BACKEDGE_REFRESH=1``.
"""
from __future__ import annotations

import os

from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnKind
from d810.transforms.graph_modification import GraphModification, RedirectBranch, RedirectGoto
from d810.transforms._base import FlowGraphTransform
from d810.core.logging import getLogger
from d810.core.typing import Callable

logger = getLogger(__name__)

def _as_int(value: object) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_int_set(value: object) -> set[int]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    out: set[int] = set()
    for item in value:
        parsed = _as_int(item)
        if parsed is not None:
            out.add(parsed)
    return out


def _env_enabled() -> bool:
    return os.environ.get("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "").strip() == "1"


def _insn_writes_stkoff(blk: BlockSnapshot, stkoff: int) -> bool:
    for insn in blk.insn_snapshots:
        dest = getattr(insn, "d", None)
        if dest is not None and getattr(dest, "stkoff", None) == stkoff:
            return True
    return False


def _insn_loads_stkoff(blk: BlockSnapshot, stkoff: int) -> bool:
    for insn in blk.insn_snapshots:
        dest = getattr(insn, "d", None)
        if (
            getattr(insn, "kind", InsnKind.UNKNOWN) == InsnKind.LOAD
            and dest is not None
            and getattr(dest, "stkoff", None) == stkoff
        ):
            return True
    return False


def _insn_reads_stkoff(blk: BlockSnapshot, stkoff: int) -> bool:
    for insn in blk.insn_snapshots:
        for operand in (getattr(insn, "l", None), getattr(insn, "r", None)):
            if operand is not None and getattr(operand, "stkoff", None) == stkoff:
                return True
    return False


def _direct_written_stkoffs(blk: BlockSnapshot) -> set[int]:
    out: set[int] = set()
    for insn in blk.insn_snapshots:
        dest = getattr(insn, "d", None)
        stkoff = getattr(dest, "stkoff", None) if dest is not None else None
        parsed = _as_int(stkoff)
        if parsed is not None:
            out.add(parsed)
    return out


def _select_refresh_entry(
    cfg: FlowGraph,
    *,
    writer_blocks: set[int],
    reader_blocks: set[int],
    carrier_stkoff: int,
) -> int | None:
    candidates: list[int] = []
    fallback: list[int] = []
    for serial in sorted(writer_blocks):
        blk = cfg.get_block(serial)
        if blk is None:
            continue
        if len(blk.succs) != 1 or blk.succs[0] not in reader_blocks:
            continue
        if _insn_loads_stkoff(blk, carrier_stkoff):
            candidates.append(serial)
            continue
        if _insn_writes_stkoff(blk, carrier_stkoff):
            fallback.append(serial)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        logger.info(
            "LOOP_CARRIER_BACKEDGE_REFRESH_ABSTAIN reason=multiple_load_refresh_entries "
            "candidates=%s",
            candidates,
        )
        return None
    if len(fallback) == 1:
        return fallback[0]
    if fallback:
        logger.info(
            "LOOP_CARRIER_BACKEDGE_REFRESH_ABSTAIN reason=multiple_write_refresh_entries "
            "candidates=%s",
            fallback,
        )
    return None


def _select_advance_refresh_entry(
    cfg: FlowGraph,
    *,
    writer_blocks: set[int],
    reader_blocks: set[int],
    carrier_stkoff: int,
) -> int | None:
    candidates: list[int] = []
    for serial in sorted(writer_blocks):
        blk = cfg.get_block(serial)
        if blk is None:
            continue
        if len(blk.succs) != 1 or blk.succs[0] not in reader_blocks:
            continue
        if _insn_loads_stkoff(blk, carrier_stkoff):
            continue
        if _insn_writes_stkoff(blk, carrier_stkoff):
            candidates.append(serial)
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        logger.info(
            "LOOP_CARRIER_BACKEDGE_REFRESH_ABSTAIN reason=multiple_advance_refresh_entries "
            "candidates=%s",
            candidates,
        )
    return None


def _tail_branch_stack_const(blk: BlockSnapshot) -> tuple[int, int] | None:
    tail = blk.tail
    if tail is None:
        return None
    l = getattr(tail, "l", None)
    r = getattr(tail, "r", None)
    stkoff = getattr(l, "stkoff", None)
    value = getattr(r, "value", None)
    if stkoff is None or value is None:
        return None
    try:
        return int(stkoff), int(value)
    except (TypeError, ValueError):
        return None


class LoopCarrierBackedgeRefreshPass(FlowGraphTransform):
    """Route shortcut loop backedges through the fact-backed carrier refresh path."""

    name = "loop_carrier_backedge_refresh"
    tags = frozenset({"loop-carrier", "fact-backed", "topology"})

    def __init__(
        self,
        fact_view_provider: Callable[[int, int | str], object | None] | None = None,
    ) -> None:
        self._fact_view_provider = fact_view_provider

    def is_applicable(self, cfg: FlowGraph) -> bool:
        return _env_enabled() and self._fact_view_provider is not None and bool(cfg.blocks)

    def _view_for(self, cfg: FlowGraph) -> object | None:
        if self._fact_view_provider is None:
            return None
        maturity = cfg.metadata.get(
            "producer_stage_id", cfg.metadata.get("maturity", "MMAT_GLBOPT2")
        )
        return self._fact_view_provider(int(cfg.func_ea), maturity)

    def transform(self, cfg: FlowGraph) -> list[GraphModification]:
        if not self.is_applicable(cfg):
            return []

        view = self._view_for(cfg)
        if view is None:
            return []

        mods: list[GraphModification] = []
        seen_edges: set[tuple[int, int, int]] = set()

        for predicate_serial in sorted(cfg.blocks):
            facts_getter = getattr(view, "loop_carriers_for_predicate_block", None)
            if facts_getter is None:
                return []
            facts = facts_getter(predicate_serial)
            if not facts:
                continue

            predicate_blk = cfg.get_block(predicate_serial)
            if predicate_blk is None:
                continue

            for obs in facts:
                payload = getattr(obs, "payload", None) or {}
                if payload.get("classification") != "LOOP_CARRIER_WRITER_OUTSIDE_SCC":
                    continue

                carrier_stkoff = _as_int(payload.get("carrier_stkoff"))
                if carrier_stkoff is None:
                    continue
                reader_blocks = _as_int_set(payload.get("carrier_reader_blocks"))
                writer_blocks = _as_int_set(payload.get("carrier_writer_blocks_outside_loop"))
                loop_scc = _as_int_set(payload.get("loop_scc_blocks"))
                if not reader_blocks or not writer_blocks or not loop_scc:
                    continue

                refresh_entry = _select_refresh_entry(
                    cfg,
                    writer_blocks=writer_blocks,
                    reader_blocks=reader_blocks,
                    carrier_stkoff=carrier_stkoff,
                )
                if refresh_entry is None:
                    continue

                for pred_serial in predicate_blk.preds:
                    pred_blk = cfg.get_block(pred_serial)
                    if pred_blk is None:
                        continue
                    if pred_serial in reader_blocks or pred_serial == refresh_entry:
                        continue
                    if pred_serial not in loop_scc:
                        continue
                    if predicate_serial not in pred_blk.succs:
                        continue

                    key = (pred_serial, predicate_serial, refresh_entry)
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)

                    if len(pred_blk.succs) == 2:
                        mods.append(
                            RedirectBranch(
                                from_serial=pred_serial,
                                old_target=predicate_serial,
                                new_target=refresh_entry,
                            )
                        )
                    else:
                        mods.append(
                            RedirectGoto(
                                from_serial=pred_serial,
                                old_target=predicate_serial,
                                new_target=refresh_entry,
                            )
                        )
                    logger.info(
                        "LOOP_CARRIER_BACKEDGE_REFRESH_REDIRECT "
                        "predicate=blk[%d] pred=blk[%d] refresh_entry=blk[%d] "
                        "reader_blocks=%s writer_blocks=%s carrier_stkoff=0x%X",
                        predicate_serial,
                        pred_serial,
                        refresh_entry,
                        sorted(reader_blocks),
                        sorted(writer_blocks),
                        carrier_stkoff,
                    )

                advance_entry = _select_advance_refresh_entry(
                    cfg,
                    writer_blocks=writer_blocks,
                    reader_blocks=reader_blocks,
                    carrier_stkoff=carrier_stkoff,
                )
                if advance_entry is not None:
                    self._add_initial_nonzero_advance_redirects(
                        cfg,
                        mods,
                        seen_edges,
                        predicate_serial=predicate_serial,
                        advance_entry=advance_entry,
                        carrier_stkoff=carrier_stkoff,
                    )

        self._add_structural_initial_nonzero_advance_redirects(cfg, mods, seen_edges)

        if mods:
            logger.info("LOOP_CARRIER_BACKEDGE_REFRESH_PLAN redirects=%d", len(mods))
        return mods

    def _add_initial_nonzero_advance_redirects(
        self,
        cfg: FlowGraph,
        mods: list[GraphModification],
        seen_edges: set[tuple[int, int, int]],
        *,
        predicate_serial: int,
        advance_entry: int,
        carrier_stkoff: int,
    ) -> None:
        for zero_test in cfg.blocks.values():
            if advance_entry not in zero_test.succs or len(zero_test.succs) != 2:
                continue
            selector = _tail_branch_stack_const(zero_test)
            if selector is None:
                continue
            selector_stkoff, selector_value = selector
            if selector_value != 0:
                continue

            for nonzero_serial in zero_test.succs:
                if nonzero_serial == advance_entry:
                    continue
                nonzero_blk = cfg.get_block(nonzero_serial)
                if nonzero_blk is None or len(nonzero_blk.succs) != 2:
                    continue
                nonzero_selector = _tail_branch_stack_const(nonzero_blk)
                if nonzero_selector != (selector_stkoff, 1):
                    continue

                stale_targets = [
                    succ
                    for succ in nonzero_blk.succs
                    if succ != advance_entry
                    and predicate_serial in cfg.successors(succ)
                ]
                if len(stale_targets) != 1:
                    continue
                old_target = int(stale_targets[0])
                key = (int(nonzero_serial), old_target, int(advance_entry))
                if key in seen_edges:
                    continue
                seen_edges.add(key)
                mods.append(
                    RedirectBranch(
                        from_serial=int(nonzero_serial),
                        old_target=old_target,
                        new_target=int(advance_entry),
                    )
                )
                logger.info(
                    "LOOP_CARRIER_INITIAL_NONZERO_ADVANCE_REDIRECT "
                    "predicate=blk[%d] zero_test=blk[%d] nonzero_test=blk[%d] "
                    "old_target=blk[%d] advance_entry=blk[%d] selector_stkoff=0x%X "
                    "carrier_stkoff=0x%X",
                    predicate_serial,
                    zero_test.serial,
                    nonzero_serial,
                    old_target,
                    advance_entry,
                    selector_stkoff,
                    carrier_stkoff,
                )

    def _add_structural_initial_nonzero_advance_redirects(
        self,
        cfg: FlowGraph,
        mods: list[GraphModification],
        seen_edges: set[tuple[int, int, int]],
    ) -> None:
        zero_value_tests = 0
        advance_reader_pairs = 0
        nonzero_value_tests = 0
        for zero_test in cfg.blocks.values():
            if len(zero_test.succs) != 2:
                continue
            selector = _tail_branch_stack_const(zero_test)
            if selector is None:
                continue
            selector_stkoff, selector_value = selector
            if selector_value != 0:
                continue
            zero_value_tests += 1

            for advance_entry in zero_test.succs:
                advance_blk = cfg.get_block(advance_entry)
                if advance_blk is None or len(advance_blk.succs) != 1:
                    continue
                written_stkoffs = _direct_written_stkoffs(advance_blk)
                if not written_stkoffs:
                    continue
                reader_serial = int(advance_blk.succs[0])
                reader_blk = cfg.get_block(reader_serial)
                if reader_blk is None or len(reader_blk.succs) != 1:
                    continue
                carrier_stkoffs = {
                    stkoff for stkoff in written_stkoffs
                    if _insn_reads_stkoff(reader_blk, stkoff)
                }
                if len(carrier_stkoffs) != 1:
                    continue
                advance_reader_pairs += 1
                carrier_stkoff = next(iter(carrier_stkoffs))
                predicate_serial = int(reader_blk.succs[0])

                for nonzero_serial in zero_test.succs:
                    if nonzero_serial == advance_entry:
                        continue
                    nonzero_blk = cfg.get_block(nonzero_serial)
                    if nonzero_blk is None or len(nonzero_blk.succs) != 2:
                        continue
                    nonzero_selector = _tail_branch_stack_const(nonzero_blk)
                    if nonzero_selector != (selector_stkoff, 1):
                        continue
                    nonzero_value_tests += 1

                    stale_targets = [
                        succ
                        for succ in nonzero_blk.succs
                        if succ != advance_entry
                        and predicate_serial in cfg.successors(succ)
                    ]
                    if len(stale_targets) != 1:
                        continue
                    old_target = int(stale_targets[0])
                    key = (int(nonzero_serial), old_target, int(advance_entry))
                    if key in seen_edges:
                        continue
                    seen_edges.add(key)
                    mods.append(
                        RedirectBranch(
                            from_serial=int(nonzero_serial),
                            old_target=old_target,
                            new_target=int(advance_entry),
                        )
                    )
                    logger.info(
                        "LOOP_CARRIER_INITIAL_NONZERO_ADVANCE_REDIRECT "
                        "mode=structural predicate=blk[%d] zero_test=blk[%d] "
                        "nonzero_test=blk[%d] old_target=blk[%d] "
                        "advance_entry=blk[%d] reader=blk[%d] "
                        "selector_stkoff=0x%X carrier_stkoff=0x%X",
                        predicate_serial,
                        zero_test.serial,
                        nonzero_serial,
                        old_target,
                        advance_entry,
                        reader_serial,
                        selector_stkoff,
                        carrier_stkoff,
                    )
        if zero_value_tests or advance_reader_pairs or nonzero_value_tests:
            logger.info(
                "LOOP_CARRIER_INITIAL_NONZERO_SCAN "
                "zero_value_tests=%d advance_reader_pairs=%d nonzero_value_tests=%d",
                zero_value_tests,
                advance_reader_pairs,
                nonzero_value_tests,
            )


__all__ = ["LoopCarrierBackedgeRefreshPass"]
