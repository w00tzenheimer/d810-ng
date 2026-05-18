"""Pure CFG contract orchestration."""

from __future__ import annotations

from d810.core.typing import Iterable, Protocol

from d810.cfg.contracts.invariants import (
    block_address_range,
    block_closing_opcode_at_tail,
    block_list_consistency,
    block_serial_range,
    block_type_vs_tail,
    block_unknown_flags,
    predecessor_uniqueness,
    pred_succ_symmetry,
    successor_set_matches_tail_semantics,
)
from d810.cfg.contracts.report import InvariantViolation
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.plan import PatchPlan

ContractScope = str
ContractPhase = str


class BackendContractOracle(Protocol):
    """Backend-specific live contract checks accepted by CFG orchestration."""

    def check_backend_contract(
        self,
        backend_graph,
        *,
        phase: str,
        focus_serials: Iterable[int] | None,
        include_insn_checks: bool = False,
    ) -> Iterable[InvariantViolation]:
        ...


def _summarize_violations(
    violations: Iterable[InvariantViolation],
    *,
    limit: int = 3,
) -> str:
    summaries: list[str] = []
    all_violations = tuple(violations)
    for violation in all_violations[:limit]:
        location = (
            f"blk[{violation.block_serial}]"
            if violation.block_serial is not None
            else "global"
        )
        summaries.append(f"{violation.code}@{location}")
    if len(all_violations) > limit:
        summaries.append(f"+{len(all_violations) - limit} more")
    return ", ".join(summaries)


class CfgContractViolationError(RuntimeError):
    """Raised when a CFG contract check finds violations."""

    def __init__(
        self,
        *,
        phase: str,
        violations: Iterable[InvariantViolation],
    ) -> None:
        self.phase = phase
        self.violations = tuple(violations)
        self.summary = _summarize_violations(self.violations)
        super().__init__(
            f"cfg contract {phase}-check failed: {self.summary or 'unknown violation'}"
        )


class CfgContract:
    """Backend-neutral contract checks for patch-plan validation."""

    def __init__(self, oracle: BackendContractOracle | None = None) -> None:
        self._oracle = oracle

    @staticmethod
    def summarize_violations(
        violations: Iterable[InvariantViolation],
        *,
        limit: int = 3,
    ) -> str:
        return _summarize_violations(violations, limit=limit)

    @staticmethod
    def _maybe_add_serial(serials: set[int], value) -> None:
        if isinstance(value, int):
            serials.add(int(value))

    def _collect_edge_serials(self, serials: set[int], edge) -> None:
        if edge is None:
            return
        self._maybe_add_serial(serials, getattr(edge, "source", None))
        self._maybe_add_serial(serials, getattr(edge, "target", None))

    def _collect_serials_from_object(self, serials: set[int], obj) -> None:
        if obj is None:
            return
        for attr_name in (
            "apply_old_target",
            "assigned_serial",
            "block_serial",
            "conditional_target",
            "fallthrough_serial",
            "fallthrough_target",
            "from_serial",
            "goto_target",
            "new_target",
            "old_target",
            "pred_serial",
            "ref_block",
            "source_block",
            "source_serial",
            "succ_serial",
            "target_block",
            "target_serial",
            "template_block",
            "to_serial",
            "via_pred",
        ):
            self._maybe_add_serial(serials, getattr(obj, attr_name, None))

        for successor in getattr(obj, "source_successors", ()) or ():
            self._maybe_add_serial(serials, successor)

        self._collect_edge_serials(serials, getattr(obj, "incoming_edge", None))
        for edge in getattr(obj, "outgoing_edges", ()) or ():
            self._collect_edge_serials(serials, edge)

        for _block_id, assigned_serial in getattr(obj, "assigned_serials", ()) or ():
            self._maybe_add_serial(serials, assigned_serial)
        for old_edge, new_edge in getattr(obj, "rewritten_edges", ()) or ():
            self._collect_edge_serials(serials, old_edge)
            self._collect_edge_serials(serials, new_edge)

        self._maybe_add_serial(serials, getattr(obj, "stop_serial_before", None))
        self._maybe_add_serial(serials, getattr(obj, "stop_serial_after", None))

    def _focus_serials(self, plan: PatchPlan) -> list[int]:
        serials: set[int] = set()
        for step in getattr(plan, "steps", ()):
            self._collect_serials_from_object(serials, step)
            self._collect_serials_from_object(serials, getattr(step, "modification", None))
        for block_spec in getattr(plan, "new_blocks", ()):
            self._collect_serials_from_object(serials, block_spec)
        self._collect_serials_from_object(serials, getattr(plan, "relocation_map", None))
        for op in getattr(plan, "ops", ()):
            self._collect_serials_from_object(serials, op)
        return sorted(serials)

    def verify_projected(
        self,
        pre_cfg: FlowGraph,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
    ) -> tuple[InvariantViolation, ...]:
        violations = tuple(self.check_projected(pre_cfg, plan, scope=scope))
        if violations:
            raise CfgContractViolationError(phase="projected", violations=violations)
        return violations

    def check_projected(
        self,
        pre_cfg: FlowGraph,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
    ) -> list[InvariantViolation]:
        from d810.cfg.flow.edit_simulator import project_post_state

        projected_cfg = project_post_state(pre_cfg, plan)
        focus = None if scope == "full" else (self._focus_serials(plan) or None)
        return self._check_projected(
            projected_cfg,
            phase="projected",
            focus_serials=focus,
        )

    def verify(
        self,
        graph,
        plan: PatchPlan | None = None,
        *,
        phase: ContractPhase = "post",
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> tuple[InvariantViolation, ...]:
        focus = None
        if plan is not None and scope != "full":
            focus = self._focus_serials(plan) or None
        violations = tuple(
            self._check(
                graph,
                phase=phase,
                focus_serials=focus,
                include_insn_checks=include_insn_checks,
            )
        )
        if violations:
            raise CfgContractViolationError(phase=phase, violations=violations)
        return violations

    def _check(
        self,
        graph,
        *,
        phase: str,
        focus_serials: Iterable[int] | None,
        include_insn_checks: bool = False,
    ) -> list[InvariantViolation]:
        if isinstance(graph, FlowGraph):
            return self._check_projected(graph, phase=phase, focus_serials=focus_serials)
        if self._oracle is None:
            return []
        return list(
            self._oracle.check_backend_contract(
                graph,
                phase=phase,
                focus_serials=focus_serials,
                include_insn_checks=include_insn_checks,
            )
        )

    def _check_projected(
        self,
        projected_cfg: FlowGraph,
        *,
        phase: str,
        focus_serials: Iterable[int] | None,
    ) -> list[InvariantViolation]:
        violations: list[InvariantViolation] = []
        violations.extend(
            block_list_consistency(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            pred_succ_symmetry(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            successor_set_matches_tail_semantics(
                projected_cfg,
                phase=phase,
                focus_serials=focus_serials,
            )
        )
        violations.extend(
            block_type_vs_tail(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            predecessor_uniqueness(
                projected_cfg,
                phase=phase,
                focus_serials=focus_serials,
            )
        )
        violations.extend(
            block_serial_range(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_closing_opcode_at_tail(
                projected_cfg,
                phase=phase,
                focus_serials=focus_serials,
            )
        )
        violations.extend(
            block_address_range(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_unknown_flags(projected_cfg, phase=phase, focus_serials=focus_serials)
        )
        return violations
