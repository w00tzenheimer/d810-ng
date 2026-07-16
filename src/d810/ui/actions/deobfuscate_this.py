"""Deobfuscate this function action.

Re-decompiles the current function with D810ng optimizations active.
"""

from __future__ import annotations

import contextlib

from d810.core import typing

from d810.core.logging import getLogger
from d810.core.provider_phase import provider_phase_snapshot_from_level
from d810.capabilities.detached_handler_snippets import (
    prepare_detached_handler_snippets,
)
from d810.ui.actions.base import D810ActionHandler

logger = getLogger("D810.ui")


def _get_current_func_ea(ctx: typing.Any, idaapi_shim: typing.Any) -> int | None:
    """Extract the entry-point EA of the function from the context.

    Args:
        ctx: IDA action context

    Returns:
        Function entry EA, or None if not in a function
    """
    vdui = idaapi_shim.get_widget_vdui(ctx.widget)
    if vdui is not None:
        return vdui.cfunc.entry_ea

    return None


class DeobfuscateThisFunction(D810ActionHandler):
    """Re-decompile the current function with d810-ng active."""

    ACTION_ID = "d810ng:deobfuscate_this"
    ACTION_TEXT = "Deobfuscate this function"
    ACTION_TOOLTIP = "Re-decompile the current function with d810-ng optimizations"
    SUPPORTED_VIEWS = frozenset({"pseudocode"})
    MENU_ORDER = 10
    REQUIRES_STARTED = True

    def execute(self, ctx: typing.Any) -> int:
        return self.execute_with_recipe(ctx, None)

    def _warning(self, idaapi_shim: typing.Any, message: str) -> None:
        logger.warning("DeobfuscateThisFunction: %s", message)
        warning = getattr(idaapi_shim, "warning", None)
        if callable(warning):
            warning(message)

    def _saved_recipe(
        self,
        idaapi_shim: typing.Any,
        func_ea: int,
    ) -> typing.Any | None:
        create = getattr(
            self._state,
            "create_saved_workbench_recipe_draft",
            None,
        )
        if not callable(create):
            return None
        fingerprint = None
        get_func = getattr(idaapi_shim, "get_func", None)
        func = get_func(func_ea) if callable(get_func) else None
        if func is not None:
            from d810.ui.workbench_comparison import (
                compute_ida_function_fingerprint,
            )

            fingerprint = compute_ida_function_fingerprint(func, idaapi_shim)
        return create(
            function_ea=func_ea,
            function_fingerprint=fingerprint,
        )

    def execute_with_recipe(
        self,
        ctx: typing.Any,
        recipe_draft: typing.Any | None,
    ) -> int:
        """Execute the deobfuscate action.

        Args:
            ctx: IDA action context

        Returns:
            1 on success, 0 on failure
        """
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None:
            return 0

        func_ea = _get_current_func_ea(ctx, idaapi_shim)
        if func_ea is None:
            logger.warning("DeobfuscateThisFunction: could not determine function EA")
            return 0

        vdui = idaapi_shim.get_widget_vdui(ctx.widget)
        try:
            draft = (
                recipe_draft
                if recipe_draft is not None
                else self._saved_recipe(idaapi_shim, int(func_ea))
            )
        except Exception as exc:
            self._warning(idaapi_shim, f"Saved function recipe is unavailable: {exc}")
            return 0

        activation = contextlib.nullcontext()
        if draft is not None:
            target = getattr(getattr(vdui, "cfunc", None), "mba", None)
            provider_level = getattr(target, "maturity", None)
            if target is None or provider_level is None:
                self._warning(
                    idaapi_shim,
                    "Function recipe requires current pseudocode microcode",
                )
                return 0
            provider_phase = provider_phase_snapshot_from_level(
                int(provider_level),
                provider_name="hexrays_microcode",
            )
            try:
                facts = self._state.analyze_workbench_recipe(
                    function_ea=int(func_ea),
                    target=target,
                    provider_phase=provider_phase,
                )
                validation = self._state.validate_workbench_recipe(
                    draft,
                    facts=facts,
                )
            except Exception as exc:
                self._warning(idaapi_shim, f"Function recipe analysis failed: {exc}")
                return 0
            if not validation.satisfied:
                detail = (
                    "; ".join(
                        str(diagnostic.message) for diagnostic in validation.diagnostics
                    )
                    or "contract preflight blocked"
                )
                self._warning(idaapi_shim, f"Function recipe is blocked: {detail}")
                return 0
            activation = self._state.activate_workbench_recipe(draft)

        logger.info("Triggering re-decompilation for function at %s", hex(func_ea))
        try:
            with activation:
                captured = prepare_detached_handler_snippets(
                    int(func_ea),
                    live_mba=vdui.cfunc.mba if vdui is not None else None,
                )
                if captured:
                    logger.info(
                        "Prepared %d detached microcode snippet(s) for %s",
                        int(captured),
                        hex(func_ea),
                    )

                # Force a refresh of the pseudocode view, which re-runs the
                # decompiler (and therefore all installed D-810 hooks).
                if vdui is not None:
                    vdui.refresh_view(True)
                else:
                    idaapi_shim.decompile(func_ea)
        except Exception as exc:
            self._warning(idaapi_shim, f"Function recipe execution failed: {exc}")
            return 0

        return 1

    def is_available(self, ctx: typing.Any) -> bool:
        """Check if action is available in current context.

        Args:
            ctx: IDA action context

        Returns:
            True if in pseudocode view, False otherwise
        """
        idaapi_shim = self.ida_module("idaapi")
        if idaapi_shim is None:
            return False

        return idaapi_shim.get_widget_vdui(ctx.widget) is not None
