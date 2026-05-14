"""Snapshot-backed helpers for emitting GraphModification intents."""
from __future__ import annotations

import sys
from dataclasses import dataclass, field

from d810.core import logging
from d810.core.algorithm_metadata import algorithm_metadata

# Diagnostic logger for tracing every goto_redirect emission back to its
# caller (there are ~19 call sites across cfg/ and optimizers/; when Mode 1
# conflicts surface we need to know which specific site produced the
# override). Emits at INFO so it shows up in the live d810 log alongside
# the existing RECONSTRUCTION_REDIRECT_ATTEMPT entries.
_mod_builder_logger = logging.getLogger(
    "D810.cfg.modification_builder", logging.DEBUG
)
# Intra-fragment-ledger logger — fires when a single ModificationBuilder
# instance queues two RedirectGoto mods on the same source block with
# different new_targets. Catches Mode 1 bug (mod[26] vs mod[75]) that
# cross-fragment PLANNER_CTX_CONFLICT cannot reach.
logger = logging.getLogger(__name__)
from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringSite,
    DuplicateAndRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    NopInstructions,
    ZeroStateWrite,
    PromoteOperandToScalar,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectBranch,
    RedirectGoto,
)
from d810.cfg.state_write_cleanup import (
    StateWriteCleanupRequest,
    state_write_cleanup_to_graph_modification,
)


def snapshot_block_nsucc_map(snapshot: object) -> dict[int, int]:
    """Build serial->nsucc map from snapshot.flow_graph, fallback to live mba."""
    flow_graph = getattr(snapshot, "flow_graph", None)
    if flow_graph is not None:
        return {serial: block.nsucc for serial, block in flow_graph.blocks.items()}

    mba = getattr(snapshot, "mba", None)
    nsucc_map: dict[int, int] = {}
    if mba is None:
        return nsucc_map

    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        nsucc_map[blk.serial] = int(blk.nsucc())
    return nsucc_map


def snapshot_block_succ_map(snapshot: object) -> dict[int, tuple[int, ...]]:
    """Build serial->successor tuple map from snapshot.flow_graph, fallback to live mba."""
    flow_graph = getattr(snapshot, "flow_graph", None)
    if flow_graph is not None:
        return {serial: tuple(block.succs) for serial, block in flow_graph.blocks.items()}

    mba = getattr(snapshot, "mba", None)
    succ_map: dict[int, tuple[int, ...]] = {}
    if mba is None:
        return succ_map

    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        if blk is None:
            continue
        succ_map[blk.serial] = tuple(int(blk.succ(j)) for j in range(blk.nsucc()))
    return succ_map


def _infer_old_target(
    source_block: int,
    block_succ_map: dict[int, tuple[int, ...]],
    old_target: int | None = None,
) -> int | None:
    if old_target is not None:
        return int(old_target)

    succs = tuple(block_succ_map.get(source_block, ()))
    if len(succs) == 1:
        return int(succs[0])
    return None


from d810.cfg.lowering_scope import (  # noqa: E402
    LoweringScope,
    derive_edge_predecessor,
    requires_pred_scoped_lowering,
)


@dataclass(frozen=True)
@algorithm_metadata(
    algorithm_id="cfg.modification_builder",
    family="tail_block_duplication_and_redirect",
    summary="Builds snapshot-backed GraphModification intents for direct CFG rewrites.",
    use_cases=(
        "Translate semantic lowering decisions into redirect, duplicate, and suffix-isolation edits.",
        "Provide one consistent builder surface for direct, pred-split, and tail-duplication rewrites.",
    ),
    examples=(
        "Redirect a resolved exact-state handoff with goto_redirect(source_block=78, target_block=14).",
        "Privatize a shared tail with edge_redirect(..., via_pred=205) when a taken suffix must split from a terminal arm.",
    ),
    tags=("cfg", "redirect", "duplication", "pred-split", "lowering"),
    related_paths=(
        "src/d810/cfg/modification_builder.py",
        "src/d810/cfg/graph_modification.py",
    ),
)
class ModificationBuilder:
    """Construct GraphModification objects from strategy-local context.

    Intra-fragment ledger
    ---------------------
    Each builder tracks RedirectGoto emissions made through this instance in
    ``_redirect_ledger`` (source_block -> list of (new_target, old_target)).

    When two RedirectGoto mods are queued for the same ``source_block`` but
    with different ``new_target`` values via one builder, we log a WARNING at
    ``INTRA_FRAGMENT_REDIRECT_OVERRIDE``. This catches the Mode 1 bug pattern
    where a single strategy's ``plan()`` call produces conflicting redirects
    on the same source within one fragment (the engine-level
    ``PLANNER_CTX_CONFLICT`` diagnostic only catches cross-fragment
    conflicts). The ledger is builder-instance-scoped, so it naturally
    resets per strategy pass when a new builder is constructed via
    ``from_snapshot``.
    """

    block_nsucc_map: dict[int, int]
    block_succ_map: dict[int, tuple[int, ...]]
    _redirect_ledger: dict[int, list[tuple[int, int]]] = field(
        default_factory=dict, compare=False, repr=False
    )

    @classmethod
    def from_snapshot(cls, snapshot: object) -> "ModificationBuilder":
        return cls(
            block_nsucc_map=snapshot_block_nsucc_map(snapshot),
            block_succ_map=snapshot_block_succ_map(snapshot),
        )

    def _record_redirect_emission(
        self,
        source_block: int,
        new_target: int,
        old_target: int,
        *,
        origin: str,
    ) -> None:
        """Record a RedirectGoto emission and log if it overrides a prior one.

        An "override" is a prior emission for the same ``source_block`` with a
        different ``new_target``. Repeated emissions with the same new_target
        (regardless of old_target) are considered consistent and do not log.
        """
        prior_emissions = self._redirect_ledger.setdefault(source_block, [])
        for prior_new_target, prior_old_target in prior_emissions:
            if prior_new_target != new_target:
                logger.warning(
                    "INTRA_FRAGMENT_REDIRECT_OVERRIDE src=%d "
                    "prior=(new_target=%d, old_target=%d) "
                    "now=(new_target=%d, old_target=%d) origin=%s",
                    source_block,
                    prior_new_target,
                    prior_old_target,
                    new_target,
                    old_target,
                    origin,
                )
                break
        prior_emissions.append((new_target, old_target))

    def goto_redirect(
        self,
        source_block: int,
        target_block: int,
        *,
        old_target: int | None = None,
    ) -> GraphModification:
        # Caller-identifying trace: logs filename:function:line of the
        # immediate caller so diagnostic tooling can map each emitted
        # RedirectGoto (or ConvertToGoto) back to its emission site. This
        # is the missing half of reconstruction_redirect_log (which only
        # captures 4 of 19+ call sites). Grep the live d810 log for
        # "GOTO_REDIRECT_CALL src=76" to see which file emitted a
        # specific mod.
        _frame = sys._getframe(1)
        _caller = (
            f"{_frame.f_code.co_filename.rsplit('/', 1)[-1]}:"
            f"{_frame.f_code.co_name}:{_frame.f_lineno}"
        )
        _mod_builder_logger.info(
            "GOTO_REDIRECT_CALL src=%s tgt=%s old=%s caller=%s",
            source_block, target_block, old_target, _caller,
        )

        nsucc = self.block_nsucc_map.get(source_block, 1)
        if nsucc == 2:
            return ConvertToGoto(block_serial=source_block, goto_target=target_block)

        inferred_old_target = _infer_old_target(
            source_block,
            self.block_succ_map,
            old_target=old_target,
        )
        resolved_old_target = (
            inferred_old_target if inferred_old_target is not None else 0
        )
        self._record_redirect_emission(
            source_block,
            target_block,
            resolved_old_target,
            origin="goto_redirect",
        )
        return RedirectGoto(
            from_serial=source_block,
            old_target=resolved_old_target,
            new_target=target_block,
        )

    def convert_to_goto(self, source_block: int, target_block: int) -> ConvertToGoto:
        return ConvertToGoto(block_serial=source_block, goto_target=target_block)

    def nop_instruction(self, source_block: int, instruction_ea: int) -> NopInstructions:
        return NopInstructions(block_serial=source_block, insn_eas=(instruction_ea,))

    def zero_state_write(self, source_block: int, instruction_ea: int) -> ZeroStateWrite:
        return ZeroStateWrite(block_serial=source_block, insn_ea=instruction_ea)

    def state_write_cleanup(
        self,
        request: StateWriteCleanupRequest,
    ) -> GraphModification:
        return state_write_cleanup_to_graph_modification(request)

    def promote_operand_to_scalar(
        self,
        source_block: int,
        host_ea: int,
        host_opcode: int,
        operand_side: str,
    ) -> PromoteOperandToScalar:
        if operand_side not in ("l", "r"):
            raise ValueError(
                f"operand_side must be 'l' or 'r', got {operand_side!r}"
            )
        return PromoteOperandToScalar(
            block_serial=source_block,
            host_ea=host_ea,
            host_opcode=host_opcode,
            operand_side=operand_side,
        )

    def conditional_redirect(
        self,
        source_block: int,
        conditional_target: int,
        *,
        fallthrough_target: int,
        ref_block: int | None = None,
    ) -> CreateConditionalRedirect:
        return CreateConditionalRedirect(
            source_block=source_block,
            ref_block=source_block if ref_block is None else ref_block,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        )

    def edge_redirect(
        self,
        source_block: int,
        target_block: int,
        *,
        old_target: int | None = None,
        via_pred: int | None = None,
        clone_until: int | None = None,
        rule_priority: int = 550,
    ) -> GraphModification:
        inferred_old_target = _infer_old_target(
            source_block,
            self.block_succ_map,
            old_target=old_target,
        )
        resolved_old_target = (
            inferred_old_target if inferred_old_target is not None else 0
        )
        if via_pred is None:
            if self.block_nsucc_map.get(source_block, 1) == 2:
                return RedirectBranch(
                    from_serial=source_block,
                    old_target=resolved_old_target,
                    new_target=target_block,
                )
            self._record_redirect_emission(
                source_block,
                target_block,
                resolved_old_target,
                origin="edge_redirect",
            )
            return RedirectGoto(
                from_serial=source_block,
                old_target=resolved_old_target,
                new_target=target_block,
            )
        return EdgeRedirectViaPredSplit(
            src_block=source_block,
            old_target=resolved_old_target,
            new_target=target_block,
            via_pred=via_pred,
            clone_until=clone_until,
            rule_priority=rule_priority,
        )

    def duplicate_block(
        self,
        source_block: int,
        target_block: int | None,
        *,
        pred_serial: int | None = None,
        patch_kind: str = "",
        conditional_target: int | None = None,
        fallthrough_target: int | None = None,
    ) -> DuplicateBlock:
        return DuplicateBlock(
            source_block=source_block,
            target_block=target_block,
            pred_serial=pred_serial,
            patch_kind=patch_kind,
            conditional_target=conditional_target,
            fallthrough_target=fallthrough_target,
        )

    def duplicate_and_redirect(
        self,
        source_block: int,
        per_pred_targets: list[tuple[int, int]],
    ) -> DuplicateAndRedirect:
        """Emit a multi-pred duplication: one copy per (pred, target) pair.

        Args:
            source_block: Serial of the shared block to duplicate.
            per_pred_targets: List of ``(pred_serial, target_serial)`` pairs.
                The first entry keeps the original block; subsequent entries
                get freshly duplicated copies.

        Returns:
            A frozen :class:`DuplicateAndRedirect` modification intent.
        """
        return DuplicateAndRedirect(
            source_serial=source_block,
            per_pred_targets=tuple(per_pred_targets),
        )

    def private_terminal_suffix(
        self,
        anchor_serial: int,
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        *,
        reason: str = "terminal_return_shared_epilogue",
    ) -> PrivateTerminalSuffix:
        """Emit a PrivateTerminalSuffix modification for one anchor."""
        return PrivateTerminalSuffix(
            anchor_serial=anchor_serial,
            shared_entry_serial=shared_entry_serial,
            return_block_serial=return_block_serial,
            suffix_serials=suffix_serials,
            reason=reason,
        )

    def private_terminal_suffix_group(
        self,
        anchors: tuple[int, ...],
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        *,
        reason: str = "terminal_return_shared_epilogue",
    ) -> PrivateTerminalSuffixGroup:
        """Emit a grouped PrivateTerminalSuffixGroup for all anchors."""
        return PrivateTerminalSuffixGroup(
            anchors=anchors,
            shared_entry_serial=shared_entry_serial,
            return_block_serial=return_block_serial,
            suffix_serials=suffix_serials,
            reason=reason,
        )

    def direct_terminal_lowering(
        self,
        sites: list[DirectTerminalLoweringSite],
        shared_entry_serial: int,
        return_block_serial: int,
        suffix_serials: tuple[int, ...],
        *,
        reason: str = "terminal_return_direct_lowering",
    ) -> DirectTerminalLoweringGroup:
        """Emit a DirectTerminalLoweringGroup for multiple anchor sites."""
        return DirectTerminalLoweringGroup(
            shared_entry_serial=shared_entry_serial,
            return_block_serial=return_block_serial,
            suffix_serials=suffix_serials,
            sites=tuple(sites),
            reason=reason,
        )


__all__ = [
    "LoweringScope",
    "ModificationBuilder",
    "derive_edge_predecessor",
    "requires_pred_scoped_lowering",
    "snapshot_block_nsucc_map",
    "snapshot_block_succ_map",
]
