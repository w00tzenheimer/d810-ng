"""Hodur-specific adapters for shared state-machine rule services."""
from __future__ import annotations

import traceback

from d810.backends.hexrays.evidence.datamodel import (
    DispatcherStateMachine,
    HandlerPathResult,
)
from d810.optimizers.microcode.flow.flattening.hodur.live_rule_services import (
    HodurLiveRuleServices,
    unflat_logger,
)

__all__ = ["HodurRuleServices"]


class HodurRuleServices(HodurLiveRuleServices):
    """Hodur adapter for services that are not profile-generic yet."""

    def _get_effective_state_var_stkoff(
        self,
        state_machine: DispatcherStateMachine | None = None,
    ) -> int | None:
        """Return the state-variable stack offset via the family adapter."""
        return self._family.get_effective_state_var_stkoff(state_machine)

    def _queue_handler_redirect(
        self,
        path: HandlerPathResult,
        target: int,
        reason: str,
        claimed_exits: dict[int, int],
        claimed_edges: dict[tuple[int, int], int],
        bst_node_blocks: set[int],
        deferred: object | None = None,
    ) -> bool:
        """Keep the retired direct-deferred redirect path visibly disabled."""
        del reason, claimed_exits, claimed_edges, bst_node_blocks, deferred
        unflat_logger.warning(
            "legacy _queue_handler_redirect DISABLED: direct deferred path"
            " bypasses PatchPlan\ncaller stack:\n%s",
            "".join(traceback.format_stack()[-40:]),
        )
        self._last_redirect_meta = {
            "kind": "disabled_legacy_queue_handler_redirect",
            "source_block": getattr(path, "exit_block", None),
            "via_pred": None,
            "target": target,
        }
        return False

    def _build_state_machine_from_cache(
        self,
        analysis: object,
    ) -> DispatcherStateMachine | None:
        """Backward-compatible wrapper for family-owned cache fallback."""
        return self._family.build_state_machine_from_cache(analysis)

    def _try_switch_table_detection(
        self,
        mba: object,
    ) -> DispatcherStateMachine | None:
        """Backward-compatible wrapper for family-owned switch-table fallback."""
        return self._family.try_switch_table_detection(mba)
