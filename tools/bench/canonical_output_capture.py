"""Opt-in pytest plugin capturing exact native decompiler output text."""

from __future__ import annotations

from contextlib import contextmanager
import functools
import hashlib
import json
import os
from pathlib import Path

import pytest


OUTPUT_ENV = "D810_CANONICAL_OUTPUT_CAPTURE_DIR"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class OutputCapture:
    def __init__(self, output_dir: Path, *, plugin_path: Path):
        self.output_dir = output_dir
        self.plugin_sha256 = _sha256(plugin_path)
        self._next_index = 0
        self._manifest = {
            "schema_version": 1,
            "plugin_sha256": self.plugin_sha256,
            "captures": [],
            "errors": [],
        }

    @classmethod
    def create(cls, output_dir: Path, *, plugin_path: Path) -> "OutputCapture":
        resolved = Path(output_dir).resolve()
        resolved.mkdir(parents=True, exist_ok=False)
        capture = cls(resolved, plugin_path=Path(plugin_path))
        capture._persist()
        return capture

    def _persist(self) -> None:
        temporary = self.output_dir / "manifest.json.tmp"
        temporary.write_text(
            json.dumps(
                self._manifest,
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        temporary.replace(self.output_dir / "manifest.json")

    def _error(self, *, index: int, exc: BaseException) -> None:
        self._manifest["errors"].append(
            {
                "index": index,
                "error_type": type(exc).__name__,
                "error": repr(exc),
            }
        )
        self._persist()

    def observe(
        self,
        result,
        *,
        nodeid: str,
        function_ea: int,
        function_name: str,
    ) -> None:
        index = self._next_index
        self._next_index += 1
        try:
            rendered = str(result)
            payload = rendered.encode("utf-8")
            filename = f"{index:03d}.c"
            with (self.output_dir / filename).open("xb") as stream:
                stream.write(payload)
            self._manifest["captures"].append(
                {
                    "index": index,
                    "filename": filename,
                    "nodeid": nodeid,
                    "function_ea": function_ea,
                    "function_ea_hex": hex(function_ea),
                    "function_name": function_name,
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                }
            )
            self._persist()
        except BaseException as exc:
            self._error(index=index, exc=exc)


def make_decompile_wrapper(original, observer):
    """Observe one returned object without changing decompile call semantics."""

    @functools.wraps(original)
    def observed(*args, **kwargs):
        result = original(*args, **kwargs)
        try:
            observer(result, args, kwargs)
        except BaseException:
            # Optional output capture cannot change a native decompile result.
            pass
        return result

    return observed


@contextmanager
def temporary_decompile_capture(owner, observer):
    original = owner.decompile
    owner.decompile = make_decompile_wrapper(original, observer)
    try:
        yield
    finally:
        owner.decompile = original


def _nodeid() -> str:
    current = os.environ.get("PYTEST_CURRENT_TEST", "")
    return current.rsplit(" (", 1)[0] if current else "unknown"


@pytest.fixture(scope="session", autouse=True)
def canonical_output_capture(canonical_dac_capture):
    """Wrap after the canonical probe and restore its exact wrapper at teardown."""
    del canonical_dac_capture
    configured = os.environ.get(OUTPUT_ENV)
    if configured is None:
        yield None
        return

    import ida_funcs
    import idaapi

    capture = OutputCapture.create(Path(configured), plugin_path=Path(__file__))

    def observe(result, args, kwargs):
        ea = kwargs.get("ea")
        if ea is None and args:
            ea = args[0]
        if type(ea) is not int:
            raise ValueError("native decompile call has no integer function EA")
        capture.observe(
            result,
            nodeid=_nodeid(),
            function_ea=ea,
            function_name=str(ida_funcs.get_func_name(ea)),
        )

    with temporary_decompile_capture(idaapi, observe):
        yield capture
