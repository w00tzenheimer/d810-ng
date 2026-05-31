from __future__ import annotations

from dataclasses import dataclass
from d810.core.typing import TYPE_CHECKING, Callable

import ida_hexrays

from d810.core import getLogger
from d810.hexrays.utils.hexrays_formatters import maturity_to_string
from d810.analyses.control_flow.analysis_stats import (
    FlowProfileStats,
    compute_flow_profile_stats,
)
from d810.backends.hexrays.evidence.dispatcher.dispatcher_history import (
    analyze_dispatcher_live,
)
from d810.hexrays.mutation.ir_translator import lift
from d810.analyses.control_flow.dispatcher_kind import DispatcherType
from d810.core.gate_modes import GateOperationMode
from d810.passes.flow_hints import FlowContextHintSummary
from d810.passes.function_priors import FunctionAnalysisPriors

if TYPE_CHECKING:
    from d810.analyses.value_flow.model import FactConsumerRecord, ValidatedFactView
    from d810.analyses.control_flow.dispatcher_analysis import DispatcherAnalysis
    from d810.analyses.control_flow.dispatcher_facts import BlockAnalysis
    from d810.optimizers.microcode.flow.handler import FlowOptimizationRule


logger = getLogger("D810.flow.context")


def _flowgraph_from_live_mba(
    mba: ida_hexrays.mba_t,
) -> tuple["FlowGraph", set[int]]:
    """Build a minimal FlowGraph + side-effect block set from the live mba.

    Returns (flow_graph, side_effect_blocks) where *side_effect_blocks*
    contains serials of blocks with at least one instruction that has
    side effects (calls, stores — via ``minsn_t.has_side_effects()``).
    """
    from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot

    blocks: dict[int, BlockSnapshot] = {}
    side_effect_blocks: set[int] = set()

    for i in range(mba.qty):
        blk = mba.get_mblock(i)
        succs = list(blk.succset)
        preds = list(blk.predset)

        # Check side effects across ALL instructions.
        insn = blk.head
        while insn is not None:
            if insn.has_side_effects():
                side_effect_blocks.add(i)
                break
            insn = insn.next

        # Capture only the tail instruction (for BST-walk opcode checks).
        insns: tuple[InsnSnapshot, ...] = ()
        tail = blk.tail
        if tail is not None:
            l_snap = r_snap = None
            if tail.l and tail.l.t != 0:
                stkoff = None
                if tail.l.t == 3 and hasattr(tail.l, "s") and tail.l.s:  # mop_S
                    stkoff = tail.l.s.off
                l_snap = MopSnapshot(t=tail.l.t, size=tail.l.size, stkoff=stkoff)
            if tail.r and tail.r.t != 0:
                val = None
                if tail.r.t == 2:  # mop_n
                    val = tail.r.nnn.value if hasattr(tail.r, "nnn") and tail.r.nnn else None
                r_snap = MopSnapshot(t=tail.r.t, size=tail.r.size, value=val)
            insns = (
                InsnSnapshot(
                    opcode=tail.opcode, ea=tail.ea, operands=(),
                    l=l_snap, r=r_snap,
                ),
            )

        blocks[i] = BlockSnapshot(
            serial=i,
            block_type=blk.type,
            succs=tuple(succs),
            preds=tuple(preds),
            flags=blk.flags,
            start_ea=blk.start,
            insn_snapshots=insns,
        )

    return FlowGraph(blocks=blocks, entry_serial=0, func_ea=mba.entry_ea), side_effect_blocks


@dataclass(frozen=True)
class FlowGateDecision:
    allowed: bool
    reason: str


class FlowMaturityContext:
    """Shared function+maturity analysis context for flow optimizers."""

    MIN_FIXPRED_DISPATCHER_PREDS = 3

    def __init__(
        self,
        mba: ida_hexrays.mba_t,
        func_ea: int,
        maturity: int,
        gate_mode: GateOperationMode = GateOperationMode.GATE_SELECT,
    ):
        self.mba = mba
        self.func_ea = int(func_ea)
        self.maturity = int(maturity)
        self.gate_mode = gate_mode
        self.phase_priority: int | None = None
        self.phase_index: int = 0
        self._dispatcher_analysis: DispatcherAnalysis | None = None
        self._dispatcher_analysis_error: Exception | None = None
        self._profile_stats: FlowProfileStats | None = None
        self._profile_stats_error: Exception | None = None
        self._active_rule_names: tuple[str, ...] = tuple()
        self._hint_summary: FlowContextHintSummary | None = None
        self._outcome_callback: Callable[[int, object, str], None] | None = None
        self._fact_view_provider: (
            Callable[[int, int | str], "ValidatedFactView"] | None
        ) = None
        self._fact_consumer_callback: (
            Callable[[int, tuple["FactConsumerRecord", ...]], int] | None
        ) = None
        self._function_priors_provider: (
            Callable[[int], FunctionAnalysisPriors] | None
        ) = None
        self._terminal_boundary_blocks: set[int] | None = None

    @property
    def hint_summary(self) -> FlowContextHintSummary | None:
        """Return the current flow-context hint summary, or ``None``."""
        return self._hint_summary

    def set_hint_summary(self, summary: FlowContextHintSummary) -> None:
        """Attach an analyzed hint summary from the recon lifecycle.

        The summary is used as an *additional* signal in gate evaluation
        methods. It does not replace existing dispatcher-analysis logic.

        In the live path, ``BlockOptimizerManager._attach_hint_summary``
        calls this automatically when a new ``FlowMaturityContext`` is
        created (including after invalidation). The summary is derived
        from persisted ``DeobfuscationHints`` via
        :func:`derive_flow_context_summary`.
        """
        self._hint_summary = summary

    def set_outcome_callback(
        self, callback: Callable[[int, object, str], None] | None,
    ) -> None:
        """Set a callback for recording consumer outcomes.

        The callback signature is ``(func_ea, outcome_object, consumer_type)``
        where *consumer_type* is ``"planner"`` or ``"flow_gate"``.
        """
        self._outcome_callback = callback

    def report_outcome(self, outcome_object: object, consumer_type: str) -> None:
        """Report a consumer outcome via the registered callback, if any."""
        if self._outcome_callback is not None:
            self._outcome_callback(self.func_ea, outcome_object, consumer_type)

    def set_fact_lifecycle_callbacks(
        self,
        *,
        view_provider: Callable[[int, int | str], "ValidatedFactView"] | None = None,
        consumer_callback: (
            Callable[[int, tuple["FactConsumerRecord", ...]], int] | None
        ) = None,
    ) -> None:
        """Attach fact-lifecycle accessors for observability-only consumers."""
        self._fact_view_provider = view_provider
        self._fact_consumer_callback = consumer_callback

    def validated_fact_view(
        self,
        maturity: int | str | None = None,
    ) -> "ValidatedFactView | None":
        """Return the validated fact view for this function, if available."""
        if self._fact_view_provider is None:
            return None
        maturity_value: int | str = self.maturity if maturity is None else maturity
        if isinstance(maturity_value, int):
            maturity_value = maturity_to_string(maturity_value)
        return self._fact_view_provider(
            self.func_ea,
            maturity_value,
        )

    def report_fact_consumers(
        self,
        records: tuple["FactConsumerRecord", ...],
    ) -> int:
        """Persist fact-consumer diagnostic rows, if a callback is available."""
        if not records or self._fact_consumer_callback is None:
            return 0
        return self._fact_consumer_callback(self.func_ea, records)

    def set_function_priors_provider(
        self,
        provider: Callable[[int], FunctionAnalysisPriors] | None,
    ) -> None:
        """Attach the project/test supplied function-priors provider."""
        self._function_priors_provider = provider

    def function_analysis_priors(
        self,
        func_ea: int | None = None,
    ) -> FunctionAnalysisPriors:
        """Return explicit project/test priors for this function."""
        if self._function_priors_provider is None:
            return FunctionAnalysisPriors()
        return self._function_priors_provider(
            self.func_ea if func_ea is None else int(func_ea)
        )

    def refresh_mba(self, mba: ida_hexrays.mba_t) -> None:
        self.mba = mba
        self._profile_stats = None
        self._profile_stats_error = None
        self._dispatcher_analysis = None
        self._dispatcher_analysis_error = None
        self._terminal_boundary_blocks = None

    def set_phase(
        self,
        *,
        priority: int,
        phase_index: int,
        active_rule_names: tuple[str, ...],
    ) -> None:
        self.phase_priority = int(priority)
        self.phase_index = int(phase_index)
        self._active_rule_names = active_rule_names

    @property
    def active_rule_names(self) -> tuple[str, ...]:
        return self._active_rule_names

    def prime_for_rules(self, rules: tuple[FlowOptimizationRule, ...]) -> None:
        if any(getattr(rule, "REQUIRES_DISPATCHER_ANALYSIS", False) for rule in rules):
            self.ensure_dispatcher_analysis()

    def ensure_dispatcher_analysis(self) -> DispatcherAnalysis | None:
        if self._dispatcher_analysis is not None:
            return self._dispatcher_analysis
        if self._dispatcher_analysis_error is not None:
            return None
        try:
            self._dispatcher_analysis = analyze_dispatcher_live(self.mba)
            return self._dispatcher_analysis
        except Exception as exc:  # pragma: no cover - defensive; IDA runtime edge
            self._dispatcher_analysis_error = exc
            maturity_name = maturity_to_string(self.maturity)
            logger.warning(
                "Dispatcher analysis failed for 0x%x at maturity %s: %s",
                self.func_ea,
                maturity_name,
                exc,
            )
            return None

    def get_terminal_cone_blocks(self) -> set[int]:
        """Return the terminal cone — dispatcher blocks that FixPred must skip.

        Lazily computed from the dispatcher analysis.  Identifies the
        reverse-predecessor cone of BST comparison blocks whose non-dispatcher
        arm reaches ``BLT_STOP``.  If the cone reaches a dispatcher root,
        it expands to cover that root's entire reachable component to avoid
        INTERR 50858 from partial resolution.
        """
        if self._terminal_boundary_blocks is not None:
            return self._terminal_boundary_blocks
        self._terminal_boundary_blocks = set()

        analysis = self.ensure_dispatcher_analysis()
        if analysis is None or analysis.dispatcher_type != DispatcherType.CONDITIONAL_CHAIN:
            return self._terminal_boundary_blocks

        from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, MopSnapshot
        from d810.analyses.control_flow.state_machine_analysis import (
            detect_terminal_state_families_snapshot,
        )

        try:
            flow_graph, side_effect_blocks = _flowgraph_from_live_mba(self.mba)
        except Exception:
            return self._terminal_boundary_blocks

        sm_blocks = set(analysis.dispatchers)
        self._terminal_boundary_blocks = detect_terminal_state_families_snapshot(
            flow_graph, sm_blocks, side_effect_blocks,
        )

        logger.info(
            "[TERM-GATE] result: terminal_boundary=%s",
            self._terminal_boundary_blocks,
        )
        return self._terminal_boundary_blocks

    def get_profile_stats(self) -> FlowProfileStats | None:
        if self._profile_stats is not None:
            return self._profile_stats
        if self._profile_stats_error is not None:
            return None

        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return None

        try:
            self._profile_stats = compute_flow_profile_stats(lift(self.mba), analysis)
            return self._profile_stats
        except Exception as exc:  # pragma: no cover - defensive; IDA runtime edge
            self._profile_stats_error = exc
            maturity_name = maturity_to_string(self.maturity)
            logger.warning(
                "Profile stats failed for 0x%x at maturity %s: %s",
                self.func_ea,
                maturity_name,
                exc,
            )
            return None

    def _dispatcher_blocks(self, analysis: DispatcherAnalysis) -> list[BlockAnalysis]:
        blocks: list[BlockAnalysis] = []
        for serial in analysis.dispatchers:
            info = analysis.blocks.get(serial)
            if info is not None:
                blocks.append(info)
        return blocks

    def _strong_dispatcher_count(self, analysis: DispatcherAnalysis) -> int:
        return sum(1 for info in self._dispatcher_blocks(analysis) if info.is_strong_dispatcher)

    def _max_dispatcher_predecessors(self, analysis: DispatcherAnalysis) -> int:
        max_preds = 0
        for info in self._dispatcher_blocks(analysis):
            if info.predecessor_count > max_preds:
                max_preds = info.predecessor_count
        return max_preds

    def evaluate_early_fcp_gate(self) -> FlowGateDecision:
        """Should FCP skip at early maturities (MMAT_CALLS)?

        Unlike :meth:`evaluate_unflattening_gate`, this is conservative:
        only returns ``allowed=True`` for UNKNOWN dispatcher types where
        the emulator cannot resolve state transitions and FCP would fold
        stale dispatcher constants into the return register.

        SWITCH_TABLE and CONDITIONAL_CHAIN dispatchers have resolvable
        structure — FCP is safe for those.
        """
        analysis = self.ensure_dispatcher_analysis()
        if analysis is None or len(analysis.dispatchers) == 0:
            return FlowGateDecision(False, "no dispatcher candidates")
        if analysis.dispatcher_type != DispatcherType.UNKNOWN:
            return FlowGateDecision(
                False,
                f"dispatcher type {analysis.dispatcher_type.value} is FCP-safe",
            )
        # UNKNOWN dispatcher — check if it has real structural signals
        strong = self._strong_dispatcher_count(analysis)
        if strong > 0:
            return FlowGateDecision(True, "unknown dispatcher with strong candidates")
        profile = self.get_profile_stats()
        if profile is not None:
            if profile.has_nested_dispatch:
                return FlowGateDecision(True, "unknown dispatcher with nested dispatch")
            if profile.dispatch_scc_n >= 2 and profile.flattening_score >= 0.35:
                return FlowGateDecision(
                    True,
                    f"unknown dispatcher with cyclic profile (scc={profile.dispatch_scc_n})",
                )
        return FlowGateDecision(False, "unknown dispatcher without strong signals")

    def evaluate_unflattening_gate(self) -> FlowGateDecision:
        """Evaluate whether unflattening should proceed.

        Gate operation mode
        -------------------
        - ``COLLECT_ONLY``: analysis still runs (for recon), but the gate
          always returns ``allowed=True``.
        - ``GATE_ONLY`` / ``GATE_SELECT``: analysis runs and the result
          is enforced (fail-closed).
        """
        decision = self._evaluate_unflattening_gate_inner()
        if not decision.allowed and not self.gate_mode.enforces_gate:
            return FlowGateDecision(
                True,
                f"collect-only bypass (underlying: {decision.reason})",
            )
        return decision

    def _evaluate_unflattening_gate_inner(self) -> FlowGateDecision:
        """Core unflattening gate logic (mode-independent).

        If a :class:`FlowContextHintSummary` is attached, its flattening
        signal is used as an additional rescue: when the dispatcher
        profile is too weak on its own but hints confirm flattening with
        sufficient confidence (>= 0.5), the gate allows the rule to
        proceed.  Existing positive decisions are never overridden.
        """
        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return FlowGateDecision(False, "dispatcher analysis unavailable")
        if analysis.dispatcher_type == DispatcherType.SWITCH_TABLE:
            return FlowGateDecision(True, "switch-table dispatcher")
        if len(analysis.dispatchers) == 0:
            return FlowGateDecision(False, "no dispatcher candidates")
        strong_dispatchers = self._strong_dispatcher_count(analysis)
        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            if strong_dispatchers == 0:
                return FlowGateDecision(False, "no strong dispatcher candidates")
            return FlowGateDecision(True, "conditional-chain dispatcher")
        if analysis.dispatcher_type == DispatcherType.UNKNOWN:
            if strong_dispatchers > 0:
                return FlowGateDecision(True, "unknown dispatcher with strong candidates")
            profile = self.get_profile_stats()
            if profile is None:
                return FlowGateDecision(False, "unknown dispatcher without profile stats")
            if profile.has_nested_dispatch:
                return FlowGateDecision(True, "unknown dispatcher with nested dispatch profile")
            if profile.dispatch_scc_n >= 2 and profile.flattening_score >= 0.35:
                return FlowGateDecision(
                    True,
                    (
                        "unknown dispatcher with cyclic dispatch profile "
                        f"(scc={profile.dispatch_scc_n}, score={profile.flattening_score:.2f})"
                    ),
                )
            # Hint-rescue: if recon hints confirm flattening, allow despite
            # weak profile.  This is additive — it never overrides a
            # positive decision above.
            if self._hint_summary is not None:
                if (
                    self._hint_summary.has_flattening_signal
                    and self._hint_summary.confidence >= 0.5
                ):
                    return FlowGateDecision(
                        True,
                        (
                            "unknown dispatcher rescued by recon hints "
                            f"(confidence={self._hint_summary.confidence:.2f})"
                        ),
                    )
            return FlowGateDecision(
                False,
                (
                    "unknown dispatcher profile too weak "
                    f"(scc={profile.dispatch_scc_n}, score={profile.flattening_score:.2f})"
                ),
            )
        return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")

    def evaluate_fix_predecessor_gate(self) -> FlowGateDecision:
        """Evaluate whether fix-predecessor optimization should proceed.

        Gate operation mode
        -------------------
        - ``COLLECT_ONLY``: analysis still runs (for recon), but the gate
          always returns ``allowed=True``.
        - ``GATE_ONLY`` / ``GATE_SELECT``: analysis runs and the result
          is enforced (fail-closed).
        """
        decision = self._evaluate_fix_predecessor_gate_inner()
        if not decision.allowed and not self.gate_mode.enforces_gate:
            return FlowGateDecision(
                True,
                f"collect-only bypass (underlying: {decision.reason})",
            )
        return decision

    def _evaluate_fix_predecessor_gate_inner(self) -> FlowGateDecision:
        """Core fix-predecessor gate logic (mode-independent)."""
        analysis = self.ensure_dispatcher_analysis()
        if analysis is None:
            return FlowGateDecision(False, "dispatcher analysis unavailable")
        if analysis.dispatcher_type == DispatcherType.SWITCH_TABLE:
            return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")
        if analysis.dispatcher_type not in (
            DispatcherType.CONDITIONAL_CHAIN,
            DispatcherType.UNKNOWN,
        ):
            return FlowGateDecision(False, f"dispatcher_type={analysis.dispatcher_type.name}")
        if len(analysis.dispatchers) == 0:
            return FlowGateDecision(False, "no dispatcher candidates")
        strong_dispatchers = self._strong_dispatcher_count(analysis)
        if strong_dispatchers == 0:
            return FlowGateDecision(False, "no strong dispatcher candidates")
        max_preds = self._max_dispatcher_predecessors(analysis)
        if max_preds < self.MIN_FIXPRED_DISPATCHER_PREDS:
            return FlowGateDecision(
                False,
                (
                    f"max dispatcher predecessors {max_preds} "
                    f"< {self.MIN_FIXPRED_DISPATCHER_PREDS}"
                ),
            )
        if analysis.dispatcher_type == DispatcherType.CONDITIONAL_CHAIN:
            return FlowGateDecision(True, "conditional-chain dispatcher with strong signals")
        return FlowGateDecision(True, "unknown dispatcher with strong signals")
