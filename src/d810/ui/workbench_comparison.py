"""Thin, injected native-versus-D810 pseudocode capture boundary."""

from __future__ import annotations

import contextlib
from collections.abc import Callable

from d810.manager.workbench_comparison import ComparisonIdentity
from d810.manager.workbench_models import (
    DeobfuscationWorkbenchSnapshot,
    SnapshotFreshness,
    WorkbenchComparisonSnapshot,
)


class WorkbenchComparisonCaptureError(RuntimeError):
    """Raised when the current pseudocode context cannot supply both artifacts."""


def _default_hooks_suppressed(manager: object) -> contextlib.AbstractContextManager:
    from d810.manager import d810_hooks_suppressed

    return d810_hooks_suppressed(manager)


class WorkbenchComparisonAdapter:
    """Capture exactly one suppressed native decompilation and one current output."""

    def __init__(
        self,
        *,
        state: object,
        manager: object,
        decompile: Callable[[int], object | None],
        render_pseudocode: Callable[[object], str],
        idb_identity: Callable[[], str],
        type_generation: Callable[[], str],
        hexrays_version: Callable[[], str],
        hooks_suppressed: Callable[
            [object], contextlib.AbstractContextManager
        ] = _default_hooks_suppressed,
    ) -> None:
        self._state = state
        self._manager = manager
        self._hooks_suppressed = hooks_suppressed
        self._decompile = decompile
        self._render_pseudocode = render_pseudocode
        self._idb_identity = idb_identity
        self._type_generation = type_generation
        self._hexrays_version = hexrays_version

    def capture(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
        *,
        current_cfunc: object | None,
    ) -> WorkbenchComparisonSnapshot:
        if snapshot.freshness is not SnapshotFreshness.CURRENT:
            raise WorkbenchComparisonCaptureError(
                "Comparison requires a current workbench snapshot"
            )
        if not snapshot.engine_started:
            raise WorkbenchComparisonCaptureError(
                "Comparison requires a started D810 runtime"
            )
        if current_cfunc is None:
            raise WorkbenchComparisonCaptureError(
                "Comparison requires the current D810 pseudocode function"
            )

        identity = ComparisonIdentity(
            function_ea=snapshot.function.ea,
            function_fingerprint=snapshot.function.fingerprint,
            decompilation_generation=snapshot.generation,
            idb_identity=str(self._idb_identity()),
            type_generation=str(self._type_generation()),
            hexrays_version=str(self._hexrays_version()),
            runtime_path=snapshot.runtime.runtime_path,
            runtime_pass_ids=snapshot.runtime.pass_ids,
            runtime_generation=snapshot.generation,
        )

        with self._hooks_suppressed(self._manager):
            native_cfunc = self._decompile(snapshot.function.ea)
        if native_cfunc is None:
            raise WorkbenchComparisonCaptureError(
                "Native decompilation did not return pseudocode"
            )

        native_text = self._render_pseudocode(native_cfunc)
        d810_text = self._render_pseudocode(current_cfunc)
        self._state.capture_workbench_baseline(identity, native_text)
        self._state.capture_workbench_d810_output(identity, d810_text)
        return self._state.get_workbench_comparison(identity)


__all__ = ["WorkbenchComparisonAdapter", "WorkbenchComparisonCaptureError"]
