"""Dispatcher-type-agnostic handler mapping.

Shared IR consumed by Hodur strategies. Produced by either BST analysis
(CONDITIONAL_CHAIN) or switch-table analysis (SWITCH_TABLE).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.recon.flow.dispatcher_detection import DispatcherType


@dataclass(frozen=True)
class DispatcherHandlerMap:
    """Dispatcher-type-agnostic handler mapping.

    ``handler_state_map`` keys are block serials where handler bodies begin.
    ``state_var_stkoff`` identifies which stack variable carries the dispatcher state.
    ``dispatcher_blocks`` includes the dispatcher entry and all routing blocks.
    ``source`` distinguishes origin for diagnostics; downstream ignores it.
    """

    handler_state_map: dict[int, int]  # handler_serial -> state_const
    dispatcher_serial: int
    dispatcher_blocks: frozenset[int]
    state_var_stkoff: int
    source: DispatcherType
    initial_state: int | None = None
    handler_range_map: dict[int, tuple[int | None, int | None]] = field(
        default_factory=dict
    )

    def resolve_target(self, state_value: int) -> int | None:
        """Resolve a concrete state value to a handler block serial.

        Mirrors ``resolve_target_via_bst`` logic: exact match first, then
        range fallback (skipping catch-all ranges and exact-match serials).
        """
        for handler_serial, state_const in self.handler_state_map.items():
            if state_const == state_value:
                return handler_serial

        exact_serials = set(self.handler_state_map.keys())
        for serial, (lo, hi) in self.handler_range_map.items():
            if serial in exact_serials:
                continue
            if (
                lo is not None
                and hi is not None
                and (hi - lo) >= 0xFFFF0000
            ):
                continue
            if lo is not None and state_value < lo:
                continue
            if hi is not None and state_value > hi:
                continue
            return serial

        return None

    @classmethod
    def from_bst_result(
        cls,
        bst_result: object,
        dispatcher_serial: int,
        state_var_stkoff: int,
    ) -> DispatcherHandlerMap:
        """Bridge from ``BSTAnalysisResult``.

        Extracts the dispatcher-agnostic subset of fields. BST-specific
        fields (``transitions``, ``exits``, ``dispatcher``) are not carried --
        Hodur's forward evaluator rebuilds them.
        """
        return cls(
            handler_state_map=dict(bst_result.handler_state_map),
            dispatcher_serial=dispatcher_serial,
            dispatcher_blocks=frozenset(bst_result.bst_node_blocks),
            state_var_stkoff=state_var_stkoff,
            source=DispatcherType.CONDITIONAL_CHAIN,
            initial_state=bst_result.initial_state,
            handler_range_map=dict(bst_result.handler_range_map),
        )

    def to_bst_result(self) -> object:
        """Synthesize a ``BSTAnalysisResult`` for downstream consumers.

        Downstream code (``resolve_target_via_bst``, ``_post_apply_bst_cleanup``)
        accesses ``handler_state_map``, ``bst_node_blocks``, and ``initial_state``.
        Transition-related fields are left empty (Hodur forward eval rebuilds them).
        """
        from d810.recon.flow.bst_model import BSTAnalysisResult, BSTNodeMap

        node_map = BSTNodeMap()
        for serial in self.dispatcher_blocks:
            node_map.add(serial)
        return BSTAnalysisResult(
            handler_state_map=dict(self.handler_state_map),
            handler_range_map=dict(self.handler_range_map),
            bst_node_blocks=node_map,
            initial_state=self.initial_state,
        )
