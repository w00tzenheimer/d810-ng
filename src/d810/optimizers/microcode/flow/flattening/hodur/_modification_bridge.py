"""Strategy-side helpers for emitting GraphModification intents."""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    GraphModification,
    NopInstructions,
    PrivateTerminalSuffix,
    PrivateTerminalSuffixGroup,
    RedirectBranch,
    RedirectGoto,
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


@dataclass(frozen=True)
class ModificationBuilder:
    """Construct GraphModification objects from strategy-local context."""

    block_nsucc_map: dict[int, int]
    block_succ_map: dict[int, tuple[int, ...]]

    @classmethod
    def from_snapshot(cls, snapshot: object) -> "ModificationBuilder":
        return cls(
            block_nsucc_map=snapshot_block_nsucc_map(snapshot),
            block_succ_map=snapshot_block_succ_map(snapshot),
        )

    def goto_redirect(
        self,
        source_block: int,
        target_block: int,
        *,
        old_target: int | None = None,
    ) -> GraphModification:
        nsucc = self.block_nsucc_map.get(source_block, 1)
        if nsucc == 2:
            return ConvertToGoto(block_serial=source_block, goto_target=target_block)

        inferred_old_target = _infer_old_target(
            source_block,
            self.block_succ_map,
            old_target=old_target,
        )
        return RedirectGoto(
            from_serial=source_block,
            old_target=inferred_old_target if inferred_old_target is not None else 0,
            new_target=target_block,
        )

    def convert_to_goto(self, source_block: int, target_block: int) -> ConvertToGoto:
        return ConvertToGoto(block_serial=source_block, goto_target=target_block)

    def nop_instruction(self, source_block: int, instruction_ea: int) -> NopInstructions:
        return NopInstructions(block_serial=source_block, insn_eas=(instruction_ea,))

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
        rule_priority: int = 550,
    ) -> GraphModification:
        inferred_old_target = _infer_old_target(
            source_block,
            self.block_succ_map,
            old_target=old_target,
        )
        if via_pred is None:
            if self.block_nsucc_map.get(source_block, 1) == 2:
                return RedirectBranch(
                    from_serial=source_block,
                    old_target=inferred_old_target if inferred_old_target is not None else 0,
                    new_target=target_block,
                )
            return RedirectGoto(
                from_serial=source_block,
                old_target=inferred_old_target if inferred_old_target is not None else 0,
                new_target=target_block,
            )
        return EdgeRedirectViaPredSplit(
            src_block=source_block,
            old_target=inferred_old_target if inferred_old_target is not None else 0,
            new_target=target_block,
            via_pred=via_pred,
            rule_priority=rule_priority,
        )

    def duplicate_block(
        self,
        source_block: int,
        target_block: int | None,
        *,
        pred_serial: int | None = None,
        patch_kind: str = "",
    ) -> DuplicateBlock:
        return DuplicateBlock(
            source_block=source_block,
            target_block=target_block,
            pred_serial=pred_serial,
            patch_kind=patch_kind,
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


__all__ = [
    "ModificationBuilder",
    "snapshot_block_nsucc_map",
    "snapshot_block_succ_map",
]
