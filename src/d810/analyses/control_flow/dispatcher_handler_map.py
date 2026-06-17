"""Dispatcher-type-agnostic handler mapping.

Shared IR consumed by Hodur strategies. Produced by either condition-chain analysis
(CONDITION_CHAIN) or switch-table analysis (SWITCH).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from d810.capabilities.dispatcher import RouterKind


@dataclass(frozen=True)
class DispatcherHandlerMap:
    """Dispatcher-type-agnostic handler mapping.

    ``handler_state_map`` keys are block serials where handler bodies begin.
    ``state_var_stkoff`` identifies which stack variable carries the dispatcher state.
    ``dispatcher_blocks`` includes the dispatcher entry and all routing blocks.
    ``router_kind`` identifies the router shape; downstream ignores it unless it
    needs profile-specific routing.
    """

    handler_state_map: dict[int, int]  # handler_serial -> state_const
    dispatcher_serial: int
    dispatcher_blocks: frozenset[int]
    state_var_stkoff: int | None
    router_kind: RouterKind
    initial_state: int | None = None
    handler_range_map: dict[int, tuple[int | None, int | None]] = field(
        default_factory=dict
    )

    def resolve_target(self, state_value: int) -> int | None:
        """Resolve a concrete state value to a handler block serial.

        Mirrors ``resolve_target_via_condition_chain`` logic: exact match first, then
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
    def from_condition_chain_result(
        cls,
        condition_chain_result: object,
        dispatcher_serial: int,
        state_var_stkoff: int,
    ) -> DispatcherHandlerMap:
        """Bridge from ``ConditionChainAnalysisResult``.

        Extracts the dispatcher-agnostic subset of fields. Condition-chain-specific
        fields (``transitions``, ``exits``, ``dispatcher``) are not carried --
        Hodur's forward evaluator rebuilds them.
        """
        return cls(
            handler_state_map=dict(condition_chain_result.handler_state_map),
            dispatcher_serial=dispatcher_serial,
            dispatcher_blocks=frozenset(condition_chain_result.condition_chain_blocks),
            state_var_stkoff=state_var_stkoff,
            router_kind=RouterKind.CONDITION_CHAIN,
            initial_state=condition_chain_result.initial_state,
            handler_range_map=dict(condition_chain_result.handler_range_map),
        )

    @classmethod
    def from_state_dispatcher_map(
        cls,
        dispatch_map: object,
    ) -> DispatcherHandlerMap:
        """Bridge from exact ``StateDispatcherMap`` rows."""
        return cls(
            handler_state_map=dict(dispatch_map.handler_state_map()),
            dispatcher_serial=int(dispatch_map.dispatcher_entry_block),
            dispatcher_blocks=frozenset(dispatch_map.dispatcher_blocks),
            state_var_stkoff=dispatch_map.state_var_stkoff,
            router_kind=dispatch_map.router_kind,
            initial_state=dispatch_map.initial_state,
            handler_range_map={},
        )

    def to_condition_chain_result(self) -> object:
        """Synthesize a ``ConditionChainAnalysisResult`` for downstream consumers.

        Downstream code accesses ``handler_state_map``, ``condition_chain_blocks``,
        and ``initial_state``.
        Transition-related fields are left empty (Hodur forward eval rebuilds them).
        """
        from d810.analyses.control_flow.condition_chain_model import ConditionChainAnalysisResult, ConditionChainNodeMap

        node_map = ConditionChainNodeMap()
        for serial in self.dispatcher_blocks:
            node_map.add(serial)
        return ConditionChainAnalysisResult(
            handler_state_map=dict(self.handler_state_map),
            handler_range_map=dict(self.handler_range_map),
            condition_chain_blocks=node_map,
            initial_state=self.initial_state,
        )
