"""Handler transition recon collector.

Thin adapter over the canonical transition report API. The collector accepts:

- a prebuilt report object or serialized report payload in target metadata
- graph-portable inputs (`flow_graph` + `transition_result`)
- live BST inputs (`mba` + dispatcher metadata) as a last resort
"""
from __future__ import annotations

import time
from types import MappingProxyType

from d810.core.logging import getLogger
from d810.core.typing import Any, Mapping, Optional
from d810.recon.flow.transition_report import (
    DispatcherTransitionReport,
    TransitionKind,
    build_dispatcher_transition_report,
    build_dispatcher_transition_report_from_graph,
    transition_report_from_dict,
    transition_report_to_dict,
)
from d810.recon.models import CandidateFlag, ReconResult
from d810.recon.phase import ALL_MATURITIES

logger = getLogger(__name__)


class HandlerTransitionsCollector:
    """Recon collector for handler transition coverage and quality."""

    name: str = "handler_transitions"
    maturities: frozenset[int] | None = ALL_MATURITIES
    level: str = "microcode"

    @staticmethod
    def _get_metadata(target: Any) -> Mapping[str, object]:
        metadata = getattr(target, "metadata", None)
        if isinstance(metadata, Mapping):
            return metadata
        return {}

    @staticmethod
    def _get_optional_int(value: object) -> Optional[int]:
        if value is None:
            return None
        return int(value)

    @classmethod
    def _get_field(
        cls,
        target: Any,
        metadata: Mapping[str, object],
        name: str,
    ) -> object:
        return metadata.get(name, getattr(target, name, None))

    @staticmethod
    def _report_from_payload(payload: object) -> DispatcherTransitionReport | None:
        if isinstance(payload, DispatcherTransitionReport):
            return payload
        if isinstance(payload, Mapping):
            try:
                return transition_report_from_dict(payload)
            except Exception:
                logger.warning(
                    "Failed to deserialize transition report payload",
                    exc_info=True,
                )
        return None

    @classmethod
    def _resolve_report(
        cls,
        target: Any,
    ) -> DispatcherTransitionReport | None:
        metadata = cls._get_metadata(target)
        for payload in (
            metadata.get("transition_report"),
            metadata.get("transition_report_payload"),
            getattr(target, "transition_report", None),
            getattr(target, "transition_report_payload", None),
        ):
            report = cls._report_from_payload(payload)
            if report is not None:
                return report

        dispatcher_entry_serial = cls._get_optional_int(
            cls._get_field(target, metadata, "dispatcher_entry_serial")
        )
        flow_graph = cls._get_field(target, metadata, "flow_graph")
        transition_result = cls._get_field(target, metadata, "transition_result")
        if (
            flow_graph is not None
            and transition_result is not None
            and dispatcher_entry_serial is not None
        ):
            return build_dispatcher_transition_report_from_graph(
                flow_graph=flow_graph,
                transition_result=transition_result,
                dispatcher_entry_serial=dispatcher_entry_serial,
                state_var_stkoff=cls._get_optional_int(
                    cls._get_field(target, metadata, "state_var_stkoff")
                ),
                state_var_lvar_idx=cls._get_optional_int(
                    cls._get_field(target, metadata, "state_var_lvar_idx")
                ),
                pre_header_serial=cls._get_optional_int(
                    cls._get_field(target, metadata, "pre_header_serial")
                ),
                initial_state=cls._get_optional_int(
                    cls._get_field(target, metadata, "initial_state")
                ),
                handler_range_map=metadata.get("handler_range_map"),
                bst_node_blocks=tuple(metadata.get("bst_node_blocks", ())),
                diagnostics=tuple(metadata.get("diagnostics", ())),
            )

        if dispatcher_entry_serial is None:
            return None

        mba = metadata.get("mba", target)
        return build_dispatcher_transition_report(
            mba=mba,
            dispatcher_entry_serial=dispatcher_entry_serial,
            state_var_stkoff=cls._get_optional_int(
                cls._get_field(target, metadata, "state_var_stkoff")
            ),
            state_var_lvar_idx=cls._get_optional_int(
                cls._get_field(target, metadata, "state_var_lvar_idx")
            ),
        )

    @classmethod
    def build_result_from_report(
        cls,
        report: DispatcherTransitionReport,
        *,
        func_ea: int,
        maturity: int,
        timestamp: float | None = None,
    ) -> ReconResult:
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
            collector_name=cls.name,
            func_ea=func_ea,
            maturity=maturity,
            timestamp=time.time() if timestamp is None else timestamp,
            metrics=MappingProxyType(
                {
                    "handlers_total": report.summary.handlers_total,
                    "handlers_known": report.summary.known_count,
                    "handlers_conditional": report.summary.conditional_count,
                    "handlers_exit": report.summary.exit_count,
                    "handlers_unknown": report.summary.unknown_count,
                    "dispatcher_entry_serial": report.dispatcher_entry_serial,
                    "pre_header_serial": report.pre_header_serial,
                    "transition_report": transition_report_to_dict(report),
                }
            ),
            candidates=tuple(candidates),
        )

    def collect(self, target: Any, func_ea: int, maturity: int) -> ReconResult:
        report = self._resolve_report(target)
        if report is None:
            return ReconResult(
                collector_name=self.name,
                func_ea=func_ea,
                maturity=maturity,
                timestamp=time.time(),
                metrics=MappingProxyType({}),
                candidates=(),
            )

        return self.build_result_from_report(
            report,
            func_ea=func_ea,
            maturity=maturity,
        )
