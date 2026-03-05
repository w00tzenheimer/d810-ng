"""Handler transition recon collector.

Thin adapter over recon.flow.transition_report canonical transition API.
"""
from __future__ import annotations

import time
from types import MappingProxyType
from typing import Any

from d810.recon.models import CandidateFlag, ReconResult
from d810.recon.flow.transition_report import (
    TransitionKind,
    build_dispatcher_transition_report,
)


class HandlerTransitionsCollector:
    """Recon collector for handler transition coverage and quality."""

    name: str = "handler_transitions"
    maturities: frozenset[int] = frozenset()  # all maturities
    level: str = "microcode"

    def collect(self, target: Any, func_ea: int, maturity: int) -> ReconResult:
        dispatcher_entry_serial = getattr(target, "dispatcher_entry_serial", None)
        if dispatcher_entry_serial is None:
            return ReconResult(
                collector_name=self.name,
                func_ea=func_ea,
                maturity=maturity,
                timestamp=time.time(),
                metrics=MappingProxyType({}),
                candidates=(),
            )

        report = build_dispatcher_transition_report(
            mba=target,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=getattr(target, "state_var_stkoff", None),
            capture_diagnostics=False,
        )

        candidates: list[CandidateFlag] = []
        for row in report.rows:
            if row.kind == TransitionKind.UNKNOWN:
                candidates.append(
                    CandidateFlag(
                        kind="handler_transition_unknown",
                        block_serial=row.handler_serial,
                        confidence=0.9,
                        detail=row.transition_label,
                    )
                )

        return ReconResult(
            collector_name=self.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time(),
            metrics=MappingProxyType(
                {
                    "handlers_total": report.summary.handlers_total,
                    "handlers_known": report.summary.known_count,
                    "handlers_conditional": report.summary.conditional_count,
                    "handlers_exit": report.summary.exit_count,
                    "handlers_unknown": report.summary.unknown_count,
                }
            ),
            candidates=tuple(candidates),
        )
