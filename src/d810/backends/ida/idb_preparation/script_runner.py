"""Main-thread execution boundary for source-attested trusted IDAPython."""

from __future__ import annotations

import hashlib
import runpy
import threading
from dataclasses import dataclass
from pathlib import Path

from d810.capabilities.idb_preparation import PreparationScriptDescriptor
from d810.core.typing import Callable

__all__ = [
    "PreparationScriptContext",
    "PreparationScriptSourceChanged",
    "PreparationScriptThreadError",
    "TrustedPreparationScriptRunner",
]


class PreparationScriptSourceChanged(RuntimeError):
    """The script no longer matches the source reviewed by the user."""


class PreparationScriptThreadError(RuntimeError):
    """A preparation script was requested outside Python's main thread."""


def _require_ea(value: object, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} must be an int")
    if value < 0:
        raise ValueError(f"{label} must be non-negative")


@dataclass(frozen=True, slots=True)
class PreparationScriptContext:
    """Managed convenience API made available to a trusted script."""

    function_ea: int
    patch_bytes_callback: Callable[[int, bytes], None]
    note_range_callback: Callable[[int, int], None]
    note_function_callback: Callable[[int], None]

    def __post_init__(self) -> None:
        _require_ea(self.function_ea, "function_ea")
        for callback, name in (
            (self.patch_bytes_callback, "patch_bytes_callback"),
            (self.note_range_callback, "note_range_callback"),
            (self.note_function_callback, "note_function_callback"),
        ):
            if not callable(callback):
                raise TypeError(f"{name} must be callable")

    def patch_bytes(self, ea: int, data: bytes) -> None:
        _require_ea(ea, "ea")
        if not isinstance(data, bytes):
            raise TypeError("data must be bytes")
        if not data:
            raise ValueError("data must be non-empty")
        self.patch_bytes_callback(ea, data)

    def note_range(self, start_ea: int, end_ea: int) -> None:
        _require_ea(start_ea, "start_ea")
        _require_ea(end_ea, "end_ea")
        if end_ea <= start_ea:
            raise ValueError("end_ea must be greater than start_ea")
        self.note_range_callback(start_ea, end_ea)

    def note_function(self, function_ea: int) -> None:
        _require_ea(function_ea, "function_ea")
        self.note_function_callback(function_ea)


class TrustedPreparationScriptRunner:
    """Run one attested script with a fresh, narrow feature namespace."""

    def run(
        self,
        descriptor: PreparationScriptDescriptor,
        context: PreparationScriptContext,
    ) -> None:
        if threading.current_thread() is not threading.main_thread():
            raise PreparationScriptThreadError(
                "preparation scripts must execute on the Python main thread"
            )
        if not isinstance(descriptor, PreparationScriptDescriptor):
            raise TypeError("descriptor must be a PreparationScriptDescriptor")
        if not isinstance(context, PreparationScriptContext):
            raise TypeError("context must be a PreparationScriptContext")
        if not descriptor.enabled:
            raise ValueError(f"preparation script {descriptor.script_id!r} is disabled")

        try:
            current_source = Path(descriptor.path).read_bytes()
        except OSError as error:
            raise PreparationScriptSourceChanged(
                f"could not read preparation script {descriptor.path}: {error}"
            ) from error
        current_hash = hashlib.sha256(current_source).hexdigest()
        if current_hash != descriptor.source_sha256:
            raise PreparationScriptSourceChanged(
                f"preparation script {descriptor.script_id!r} source SHA-256 changed; "
                "refresh the project before execution"
            )

        runpy.run_path(
            descriptor.path,
            init_globals={
                "function_ea": context.function_ea,
                "preparation": context,
            },
            run_name=f"d810_preparation_{descriptor.script_id}",
        )
