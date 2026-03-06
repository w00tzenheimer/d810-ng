"""IDA-backed CFG contract checker."""

from __future__ import annotations

from d810.core import logging, getLogger
from d810.core.typing import Literal
from d810.core.typing import Iterable

from d810.cfg.contracts.native_oracle import NATIVE_ORACLE_AVAILABLE, check_mba_native

logger = getLogger(__name__)

if NATIVE_ORACLE_AVAILABLE:
    logger.info("Native CFG oracle available — full parity mode")
else:
    logger.info("Native CFG oracle unavailable — Python-only parity mode")
from d810.cfg.contracts.insn_invariants import check_all_insn_invariants
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
from d810.cfg.plan import PatchPlan
from d810.cfg.contracts.report import InvariantViolation

ContractScope = Literal["focused", "full"]
ContractPhase = Literal["pre", "post", "rollback", "projected"]

# Native oracle violation code prefix — distinguishes oracle results from Python checks
_NATIVE_PREFIX = "CFG_NATIVE_"


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
        phase: ContractPhase,
        violations: Iterable[InvariantViolation],
    ) -> None:
        self.phase = phase
        self.violations = tuple(violations)
        self.summary = _summarize_violations(self.violations)
        super().__init__(
            f"cfg contract {phase}-check failed: {self.summary or 'unknown violation'}"
        )


class IDACfgContract:
    """Verifier-inspired contract checks for pre/post transaction validation."""

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

        source_successors = getattr(obj, "source_successors", ())
        for successor in source_successors or ():
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

    def check_pre(
        self,
        mba,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> list[InvariantViolation]:
        focus = None if scope == "full" else (self._focus_serials(plan) or None)
        return self._check(mba, phase="pre", focus_serials=focus, include_insn_checks=include_insn_checks)

    def check_post(
        self,
        mba,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> list[InvariantViolation]:
        focus = None if scope == "full" else (self._focus_serials(plan) or None)
        return self._check(mba, phase="post", focus_serials=focus, include_insn_checks=include_insn_checks)

    def check_rollback(
        self,
        mba,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> list[InvariantViolation]:
        focus = None if scope == "full" else (self._focus_serials(plan) or None)
        return self._check(mba, phase="rollback", focus_serials=focus, include_insn_checks=include_insn_checks)

    def check_projected(
        self,
        pre_cfg,
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

    def verify_projected(
        self,
        pre_cfg,
        plan: PatchPlan,
        *,
        scope: ContractScope = "focused",
    ) -> tuple[InvariantViolation, ...]:
        """Convenience wrapper: project + check + raise on violations.

        Mirrors :meth:`verify` behaviour for the ``"projected"`` phase:
        returns an empty tuple on success, raises
        :class:`CfgContractViolationError` with ``phase="projected"``
        when any invariant is violated.

        Projected-state construction is delegated to
        :func:`d810.cfg.flow.edit_simulator.project_post_state` (called
        internally by :meth:`check_projected`).
        """
        violations = tuple(self.check_projected(pre_cfg, plan, scope=scope))
        if violations:
            raise CfgContractViolationError(phase="projected", violations=violations)
        return violations

    def verify(
        self,
        mba,
        plan: PatchPlan | None = None,
        *,
        phase: ContractPhase = "post",
        scope: ContractScope = "focused",
        include_insn_checks: bool = False,
    ) -> tuple[InvariantViolation, ...]:
        if phase not in ("pre", "post", "rollback"):
            raise ValueError(f"Unknown cfg contract phase: {phase}")
        focus = None
        if plan is not None and scope != "full":
            focus = self._focus_serials(plan) or None
        violations = tuple(
            self._check(
                mba,
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
        mba,
        *,
        phase: str,
        focus_serials: Iterable[int] | None,
        include_insn_checks: bool = False,
    ) -> list[InvariantViolation]:
        violations: list[InvariantViolation] = []
        violations.extend(
            block_list_consistency(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            pred_succ_symmetry(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            successor_set_matches_tail_semantics(
                mba, phase=phase, focus_serials=focus_serials
            )
        )
        violations.extend(
            block_type_vs_tail(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            predecessor_uniqueness(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_serial_range(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_closing_opcode_at_tail(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_address_range(mba, phase=phase, focus_serials=focus_serials)
        )
        violations.extend(
            block_unknown_flags(mba, phase=phase, focus_serials=focus_serials)
        )
        if include_insn_checks:
            violations.extend(
                check_all_insn_invariants(
                    mba, phase=phase, focus_serials=focus_serials
                )
            )
        if NATIVE_ORACLE_AVAILABLE:
            for interr_code, block_serial, msg in check_mba_native(mba):
                violations.append(
                    InvariantViolation(
                        code=f"{_NATIVE_PREFIX}{interr_code}",
                        message=msg,
                        phase=phase,
                        block_serial=block_serial,
                    )
                )
        return violations

    def _check_projected(
        self,
        projected_cfg,
        *,
        phase: str,
        focus_serials: Iterable[int] | None,
    ) -> list[InvariantViolation]:
        violations: list[InvariantViolation] = []
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
        return violations
