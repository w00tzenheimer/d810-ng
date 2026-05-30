"""Reports for transactional CFG apply runs."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType


@dataclass(frozen=True)
class InvariantViolation:
    """One contract violation captured during pre/post checks."""

    code: str
    message: str
    phase: str
    block_serial: int | None = None
    insn_ea: int | None = None
    details: MappingProxyType | None = None  # type: ignore[type-arg]


@dataclass(frozen=True)
class ApplyReport:
    """Final outcome of one transactional apply run."""

    run_id: str
    func_ea: int
    maturity: int
    pass_id: str
    plan_hash: str
    op_count: int
    status: str
    verify_pre_ok: bool
    verify_post_ok: bool
    rollback_performed: bool
    quarantined: bool
    error_code: str | None
    error_message: str | None
    metrics: MappingProxyType  # type: ignore[type-arg]
    violations: tuple[InvariantViolation, ...] = ()
