"""Thin, injected native-versus-D810 pseudocode capture boundary."""

from __future__ import annotations

import contextlib
from collections.abc import Callable

from d810.manager.workbench_comparison import (
    ComparisonIdentity,
    function_byte_fingerprint,
)
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

    def _identity(
        self,
        snapshot: DeobfuscationWorkbenchSnapshot,
    ) -> ComparisonIdentity:
        return ComparisonIdentity(
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

        identity = self._identity(snapshot)

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
        return self._state.get_workbench_comparison(self._identity(snapshot))


def _render_ida_pseudocode(cfunc: object, idaapi_shim: object) -> str:
    return "\n".join(
        str(idaapi_shim.tag_remove(str(line.line))) for line in cfunc.get_pseudocode()
    )


def compute_ida_function_fingerprint(
    function: object,
    idaapi_shim: object,
) -> str | None:
    """Read one function byte range and delegate stable hashing to manager logic."""
    start_ea = int(function.start_ea)
    end_ea = int(function.end_ea)
    if end_ea <= start_ea:
        return None
    content = idaapi_shim.get_bytes(start_ea, end_ea - start_ea)
    if content is None:
        return None
    return function_byte_fingerprint(bytes(content))


def _ida_idb_identity(idaapi_shim: object) -> str:
    path = str(idaapi_shim.get_path(idaapi_shim.PATH_TYPE_IDB))
    created_at = int(idaapi_shim.get_idb_ctime())
    input_sha256 = bytes(idaapi_shim.retrieve_input_file_sha256()).hex()
    return f"idb:{path};ctime:{created_at};input-sha256:{input_sha256}"


def _ida_type_generation(idaapi_shim: object) -> str:
    """Use conservative IDB mutation identity so changed types never look current."""
    database_change_count = int(idaapi_shim.inf_get_database_change_count())
    ordinal_count = int(idaapi_shim.get_ordinal_count())
    return f"db-change:{database_change_count};ordinals:{ordinal_count}"


def create_ida_comparison_adapter(
    *,
    state: object,
    idaapi_shim: object,
    hooks_suppressed: Callable[
        [object], contextlib.AbstractContextManager
    ] = _default_hooks_suppressed,
) -> WorkbenchComparisonAdapter:
    """Bind the pure comparison adapter to the live IDA API surface."""
    return WorkbenchComparisonAdapter(
        state=state,
        manager=state.manager,
        decompile=lambda function_ea: idaapi_shim.decompile(
            function_ea,
            flags=idaapi_shim.DECOMP_NO_CACHE,
        ),
        render_pseudocode=lambda cfunc: _render_ida_pseudocode(cfunc, idaapi_shim),
        idb_identity=lambda: _ida_idb_identity(idaapi_shim),
        type_generation=lambda: _ida_type_generation(idaapi_shim),
        hexrays_version=lambda: str(idaapi_shim.get_hexrays_version()),
        hooks_suppressed=hooks_suppressed,
    )


__all__ = [
    "WorkbenchComparisonAdapter",
    "WorkbenchComparisonCaptureError",
    "compute_ida_function_fingerprint",
    "create_ida_comparison_adapter",
]
