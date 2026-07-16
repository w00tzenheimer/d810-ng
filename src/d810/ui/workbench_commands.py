"""Thin adapters from a pseudocode action context to workbench commands."""

from __future__ import annotations

from d810.core.provider_phase import provider_phase_snapshot_from_level
from d810.manager.workbench_models import (
    OutcomeStatus,
    WorkbenchCommandRequest,
    WorkbenchCommandResult,
)


HEXRAYS_MICROCODE_PROVIDER = "hexrays_microcode"


def _failed_result(
    request: WorkbenchCommandRequest,
    message: str,
) -> WorkbenchCommandResult:
    return WorkbenchCommandResult(
        command=request.command,
        function_ea=request.function_ea,
        requested_generation=request.expected_generation,
        function_fingerprint=request.function_fingerprint,
        status=OutcomeStatus.FAILED,
        succeeded=False,
        accepted=True,
        refresh_requested=False,
        message=message,
    )


class WorkbenchCommandAdapter:
    """Translate one injected pseudocode context into manager commands."""

    def __init__(self, state: object, idaapi_shim: object, ctx: object) -> None:
        self._state = state
        self._idaapi = idaapi_shim
        self._ctx = ctx

    def analyze(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        widget = getattr(self._ctx, "widget", None)
        vdui = self._idaapi.get_widget_vdui(widget)
        cfunc = getattr(vdui, "cfunc", None) if vdui is not None else None
        target = getattr(cfunc, "mba", None) if cfunc is not None else None
        if target is None:
            return _failed_result(
                request,
                "Analyze requires a current pseudocode function with microcode",
            )
        provider_level = getattr(target, "maturity", None)
        if provider_level is None:
            return _failed_result(
                request,
                "Analyze requires a current microcode provider level",
            )
        provider_phase = provider_phase_snapshot_from_level(
            int(provider_level),
            provider_name=HEXRAYS_MICROCODE_PROVIDER,
        )
        return self._state.execute_workbench_analyze(
            request,
            target=target,
            provider_phase=provider_phase,
        )

    def deobfuscate(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        def lifecycle() -> bool:
            from d810.ui.actions.deobfuscate_this import DeobfuscateThisFunction

            action = DeobfuscateThisFunction(
                self._state,
                ida_modules={"idaapi": self._idaapi},
            )
            return action.execute(self._ctx) == 1

        return self._state.execute_workbench_deobfuscate(
            request,
            lifecycle=lifecycle,
        )

    def function_override(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        def lifecycle() -> bool:
            from d810.ui.actions.function_rules import FunctionRules

            action = FunctionRules(
                self._state,
                ida_modules={"idaapi": self._idaapi},
            )
            return action.execute(self._ctx) == 1

        return self._state.execute_workbench_function_override(
            request,
            lifecycle=lifecycle,
        )


__all__ = ["WorkbenchCommandAdapter"]
