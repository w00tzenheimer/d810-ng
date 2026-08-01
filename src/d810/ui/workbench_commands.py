"""Thin adapters from a pseudocode action context to workbench commands."""

from __future__ import annotations

from types import SimpleNamespace

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

    def __init__(
        self,
        state: object,
        idaapi_shim: object,
        ctx: object,
        *,
        comparison_adapter: object | None = None,
    ) -> None:
        self._state = state
        self._idaapi = idaapi_shim
        self._ctx = ctx
        original_widget = getattr(ctx, "widget", None)
        get_widget_vdui = getattr(idaapi_shim, "get_widget_vdui", None)
        vdui = get_widget_vdui(original_widget) if callable(get_widget_vdui) else None
        stable_widget = getattr(vdui, "ct", None) if vdui is not None else None
        self._widget = original_widget if stable_widget is None else stable_widget
        self._comparison_adapter = comparison_adapter

    def _current_vdui(self) -> object | None:
        get_widget_vdui = getattr(self._idaapi, "get_widget_vdui", None)
        if not callable(get_widget_vdui) or self._widget is None:
            return None
        return get_widget_vdui(self._widget)

    def _action_context(self) -> object:
        if self._widget is getattr(self._ctx, "widget", None):
            return self._ctx
        return SimpleNamespace(widget=self._widget)

    def analyze(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        vdui = self._current_vdui()
        cfunc = getattr(vdui, "cfunc", None) if vdui is not None else None
        target = getattr(cfunc, "mba", None) if cfunc is not None else None
        if target is None:
            return _failed_result(
                request,
                "Analyze requires a current pseudocode function with microcode",
            )
        entry_ea = getattr(cfunc, "entry_ea", None)
        if entry_ea is not None and int(entry_ea) != request.function_ea:
            return _failed_result(
                request,
                "Analyze pseudocode widget now shows a different function",
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

    def compare(self, snapshot: object) -> object:
        if self._comparison_adapter is None:
            raise RuntimeError("Native comparison is not configured")
        vdui = self._current_vdui()
        cfunc = getattr(vdui, "cfunc", None) if vdui is not None else None
        if cfunc is None:
            raise RuntimeError("Comparison requires current D810 pseudocode")
        function = getattr(snapshot, "function", None)
        function_ea = getattr(function, "ea", None)
        entry_ea = getattr(cfunc, "entry_ea", None)
        if entry_ea is not None and int(entry_ea) != int(function_ea):
            raise RuntimeError(
                "Comparison pseudocode widget now shows a different function"
            )
        return self._comparison_adapter.capture(
            snapshot,
            current_cfunc=cfunc,
        )

    def recipe(self, snapshot: object) -> object:
        from d810.ui.workbench_recipe_commands import WorkbenchRecipeAdapter

        return WorkbenchRecipeAdapter(
            self._state,
            self._idaapi,
            self._action_context(),
            snapshot,
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
            return action.execute(self._action_context()) == 1

        return self._state.execute_workbench_deobfuscate(
            request,
            lifecycle=lifecycle,
        )

    def build_deobfuscator(
        self,
        request: WorkbenchCommandRequest,
    ) -> WorkbenchCommandResult:
        """Collect a current strategy dossier without mutating the function."""
        vdui = self._current_vdui()
        cfunc = getattr(vdui, "cfunc", None) if vdui is not None else None
        target = getattr(cfunc, "mba", None) if cfunc is not None else None
        if target is None:
            return _failed_result(
                request,
                "Build Deobfuscator requires a current pseudocode function with microcode",
            )
        entry_ea = getattr(cfunc, "entry_ea", None)
        if entry_ea is not None and int(entry_ea) != request.function_ea:
            return _failed_result(
                request,
                "Build Deobfuscator pseudocode widget now shows a different function",
            )
        provider_level = getattr(target, "maturity", None)
        if provider_level is None:
            return _failed_result(
                request,
                "Build Deobfuscator requires a current microcode provider level",
            )
        provider_phase = provider_phase_snapshot_from_level(
            int(provider_level),
            provider_name=HEXRAYS_MICROCODE_PROVIDER,
        )
        return self._state.execute_workbench_build_deobfuscator(
            request,
            target=target,
            provider_phase=provider_phase,
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
            return action.execute(self._action_context()) == 1

        return self._state.execute_workbench_function_override(
            request,
            lifecycle=lifecycle,
        )


__all__ = ["WorkbenchCommandAdapter"]
