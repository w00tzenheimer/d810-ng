"""Hodur-specific diagnostic helpers built from recon-store artifacts."""
from __future__ import annotations

from pathlib import Path

from d810.evaluator.hexrays_microcode.terminal_return_valranges import (
    TerminalReturnValrangeReport,
    build_terminal_return_valrange_report,
    build_terminal_return_valrange_report_from_mba,
)
from d810.optimizers.microcode.flow.flattening.hodur.recon_artifacts import (
    load_terminal_return_audit_from_store,
    load_transition_report_from_store,
)


def build_terminal_return_valrange_report_from_store(
    *,
    mba: object,
    func_ea: int,
    log_dir: Path | str | None,
    maturity: int | None = None,
    state_var_size: int = 4,
    carrier_mreg: int = 0,
    carrier_size: int = 8,
) -> TerminalReturnValrangeReport | None:
    """Load Hodur recon artifacts and build a terminal-return valrange report.

    This is the glue between recon/store and the live evaluator-side valrange
    comparison logic. It is intentionally Hodur-specific and therefore lives
    under ``optimizers/.../hodur`` rather than in evaluator.
    """
    audit = load_terminal_return_audit_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
    )
    if audit is None:
        return build_terminal_return_valrange_report_from_mba(
            mba,
            func_ea=func_ea,
            state_var_stkoff=None,
            state_var_size=state_var_size,
            carrier_mreg=carrier_mreg,
            carrier_size=carrier_size,
        )

    transition_report = load_transition_report_from_store(
        func_ea=func_ea,
        maturity=maturity,
        log_dir=log_dir,
    )
    state_var_stkoff = None
    if transition_report is not None:
        state_var_stkoff = transition_report.state_var_stkoff

    return build_terminal_return_valrange_report(
        mba,
        audit,
        state_var_stkoff=state_var_stkoff,
        state_var_size=state_var_size,
        carrier_mreg=carrier_mreg,
        carrier_size=carrier_size,
    )


__all__ = ["build_terminal_return_valrange_report_from_store"]
