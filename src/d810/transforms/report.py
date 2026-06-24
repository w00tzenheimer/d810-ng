"""Reports for transactional CFG apply runs."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType

from d810.ir.maturity import MaturityEnvelope


@dataclass(frozen=True)
class InvariantViolation:
    """One contract violation captured during pre/post checks."""

    code: str
    message: str
    phase: str
    block_serial: int | None = None
    insn_ea: int | None = None
    details: MappingProxyType | None = None  # type: ignore[type-arg]


@dataclass(frozen=True, init=False)
class ApplyReport:
    """Final outcome of one transactional apply run."""

    run_id: str
    func_ea: int
    provider_level: int | None
    maturity_envelope: MaturityEnvelope | None
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

    def __init__(
        self,
        *,
        run_id: str,
        func_ea: int,
        pass_id: str,
        plan_hash: str,
        op_count: int,
        status: str,
        verify_pre_ok: bool,
        verify_post_ok: bool,
        rollback_performed: bool,
        quarantined: bool,
        error_code: str | None,
        error_message: str | None,
        metrics: MappingProxyType,  # type: ignore[type-arg]
        violations: tuple[InvariantViolation, ...] = (),
        provider_level: int | None = None,
        maturity_envelope: MaturityEnvelope | None = None,
        **legacy_fields: object,
    ) -> None:
        legacy_provider_level = legacy_fields.pop("maturity", None)
        if legacy_fields:
            names = ", ".join(sorted(legacy_fields))
            raise TypeError(f"Unexpected ApplyReport field(s): {names}")
        if legacy_provider_level is not None:
            provider_level = int(legacy_provider_level)
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "func_ea", int(func_ea))
        object.__setattr__(self, "provider_level", provider_level)
        object.__setattr__(self, "maturity_envelope", maturity_envelope)
        object.__setattr__(self, "pass_id", pass_id)
        object.__setattr__(self, "plan_hash", plan_hash)
        object.__setattr__(self, "op_count", int(op_count))
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "verify_pre_ok", bool(verify_pre_ok))
        object.__setattr__(self, "verify_post_ok", bool(verify_post_ok))
        object.__setattr__(self, "rollback_performed", bool(rollback_performed))
        object.__setattr__(self, "quarantined", bool(quarantined))
        object.__setattr__(self, "error_code", error_code)
        object.__setattr__(self, "error_message", error_message)
        object.__setattr__(self, "metrics", metrics)
        object.__setattr__(self, "violations", violations)

    @property
    def maturity(self) -> int | None:
        if (
            self.maturity_envelope is not None
            and self.maturity_envelope.provider_id is not None
        ):
            return int(self.maturity_envelope.provider_id)
        if self.provider_level is None:
            return None
        return int(self.provider_level)
