"""Portable CFG contract orchestration over plan-neutral projections.

The contract TYPES and orchestration here are backend-agnostic (portable
``transforms`` layer): :class:`CfgContract`, the structural ``FlowGraph``
invariants, and the violation records. Backend-SPECIFIC validation is injected
through the :class:`BackendContractOracle` Protocol below -- the Hex-Rays
implementation (``native_oracle`` + the verifier-parity invariant set) lives
under ``d810.hexrays.contracts``; a miasm/angr backend would supply its own
oracle with no change here.

This portability is enforced: unit tests and other portable consumers import
these types, so they must NOT sit in the ``hexrays`` namespace (the
"unit tests must not import hexrays" contract).
"""

from __future__ import annotations

from d810.core.typing import Iterable, Protocol

from d810.transforms.cfg_invariants import (
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
from d810.transforms.report import InvariantViolation
from d810.ir.flowgraph import FlowGraph
from d810.transforms.cfg_transaction import CfgProjection, PlanBlockRef

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
    ) -> Iterable[InvariantViolation]: ...


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
    """Backend-neutral invariant checks for projected CFG snapshots."""

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
    def _focus_serials(projection: CfgProjection) -> list[int]:
        """Return live source coordinates when the projection exposes any."""
        return []

    def verify_projection(
        self,
        projection: CfgProjection,
        *,
        scope: ContractScope = "focused",
    ) -> tuple[InvariantViolation, ...]:
        """Verify an already-projected portable graph without applying a plan."""
        violations = tuple(self.check_projection(projection, scope=scope))
        if violations:
            raise CfgContractViolationError(
                phase="projected",
                violations=violations,
            )
        return violations

    def check_projection(
        self,
        projection: CfgProjection,
        *,
        scope: ContractScope = "focused",
    ) -> list[InvariantViolation]:
        if not isinstance(projection, CfgProjection):
            raise TypeError("portable CFG contract requires a CfgProjection")
        focus = (
            None
            if scope == "full"
            or any(isinstance(ref, PlanBlockRef) for ref in projection.focus_refs)
            else None
        )
        return self._check_projected(
            projection.graph,
            phase="projected",
            focus_serials=focus,
        )

    def verify(
        self,
        graph,
        projection: CfgProjection | None = None,
        *,
        phase: ContractPhase = "post",
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> tuple[InvariantViolation, ...]:
        focus = (
            None
            if projection is None or scope == "full"
            else (self._focus_serials(projection) or None)
        )
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
            return self._check_projected(
                graph, phase=phase, focus_serials=focus_serials
            )
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
            block_list_consistency(
                projected_cfg, phase=phase, focus_serials=focus_serials
            )
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
