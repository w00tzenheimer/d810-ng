"""Hodur-specific adapters for shared state-machine rule services."""
from __future__ import annotations

import traceback

from d810.core import logging
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (
    DispatcherStateMachine,
    HandlerPathResult,
)
from d810.optimizers.microcode.flow.flattening.state_machine_rule_services import (
    StateMachineRuleServices,
)

__all__ = ["HodurRuleServices"]

unflat_logger = logging.getLogger("D810.unflat.hodur", logging.DEBUG)


class HodurRuleServices(StateMachineRuleServices):
    """Hodur adapter for services that are not profile-generic yet."""

    def _stabilize_sub7ffd_post_pipeline_bundle(self) -> int:
        """Disabled sample-specific repair kept as an explicit Hodur shim."""
        unflat_logger.warning(
            "sub7ffd bundle stabilize DISABLED: direct DeferredGraphModifier path"
            " bypasses PatchPlan; HodurRuleServices reached this compatibility"
            " shim after a non-empty pipeline before post_bundle_stabilize\n"
            "caller stack:\n%s",
            "".join(traceback.format_stack()[-40:]),
        )
        return 0

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
