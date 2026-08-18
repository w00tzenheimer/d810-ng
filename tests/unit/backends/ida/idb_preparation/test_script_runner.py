from __future__ import annotations

import hashlib
import threading
from pathlib import Path

import pytest

from d810.backends.ida.idb_preparation.script_runner import (
    PreparationScriptContext,
    PreparationScriptSourceChanged,
    PreparationScriptThreadError,
    TrustedPreparationScriptRunner,
)
from d810.capabilities.idb_preparation import PreparationScriptDescriptor

pytestmark = pytest.mark.pure_python


def _descriptor(path: Path) -> PreparationScriptDescriptor:
    return PreparationScriptDescriptor(
        script_id="normalize",
        display_name="Normalize",
        path=str(path),
        source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        enabled=True,
        portable=True,
    )


def _context(
    *,
    patched: list[tuple[int, bytes]],
    ranges: list[tuple[int, int]],
    functions: list[int],
) -> PreparationScriptContext:
    return PreparationScriptContext(
        function_ea=0x401000,
        patch_bytes_callback=lambda ea, data: patched.append((ea, data)),
        note_range_callback=lambda start, end: ranges.append((start, end)),
        note_function_callback=functions.append,
    )


def test_runner_exposes_only_the_two_feature_globals(tmp_path: Path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text(
        """
visible = sorted(key for key in globals() if not key.startswith('__'))
assert visible == ['function_ea', 'preparation']
preparation.patch_bytes(function_ea, b'\\x90\\x90')
preparation.note_range(function_ea, function_ea + 2)
preparation.note_function(function_ea)
""".lstrip(),
        encoding="utf-8",
    )
    patched: list[tuple[int, bytes]] = []
    ranges: list[tuple[int, int]] = []
    functions: list[int] = []
    context = _context(patched=patched, ranges=ranges, functions=functions)

    TrustedPreparationScriptRunner().run(_descriptor(script), context)

    assert patched == [(0x401000, b"\x90\x90")]
    assert ranges == [(0x401000, 0x401002)]
    assert functions == [0x401000]


def test_source_hash_mismatch_rejects_before_script_execution(tmp_path: Path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("preparation.note_function(function_ea)\n", encoding="utf-8")
    descriptor = _descriptor(script)
    script.write_text("preparation.note_function(0xDEADBEEF)\n", encoding="utf-8")
    functions: list[int] = []
    context = _context(patched=[], ranges=[], functions=functions)

    with pytest.raises(PreparationScriptSourceChanged, match="source SHA-256"):
        TrustedPreparationScriptRunner().run(descriptor, context)

    assert functions == []


def test_runner_executes_the_exact_bytes_that_passed_source_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("preparation.note_function(0x1111)\n", encoding="utf-8")
    descriptor = _descriptor(script)
    original_read_bytes = Path.read_bytes
    replaced = False

    def _read_then_replace(path: Path) -> bytes:
        nonlocal replaced
        source = original_read_bytes(path)
        if path == script and not replaced:
            script.write_text(
                "preparation.note_function(0x2222)\n",
                encoding="utf-8",
            )
            replaced = True
        return source

    monkeypatch.setattr(Path, "read_bytes", _read_then_replace)
    functions: list[int] = []
    context = _context(patched=[], ranges=[], functions=functions)

    TrustedPreparationScriptRunner().run(descriptor, context)

    assert replaced
    assert functions == [0x1111]


def test_runner_rejects_execution_off_its_owner_thread(tmp_path: Path) -> None:
    script = tmp_path / "normalize.py"
    script.write_text("preparation.note_function(function_ea)\n", encoding="utf-8")
    runner = TrustedPreparationScriptRunner()
    context = _context(patched=[], ranges=[], functions=[])
    failures: list[BaseException] = []

    def _run() -> None:
        try:
            runner.run(_descriptor(script), context)
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=_run)
    thread.start()
    thread.join(timeout=5)

    assert len(failures) == 1
    assert isinstance(failures[0], PreparationScriptThreadError)


@pytest.mark.parametrize(
    ("call", "message"),
    [
        (lambda context: context.patch_bytes(-1, b"\x90"), "non-negative"),
        (lambda context: context.patch_bytes(0x10, b""), "non-empty"),
        (lambda context: context.note_range(0x20, 0x20), "end_ea"),
        (lambda context: context.note_function(-1), "non-negative"),
    ],
)
def test_context_rejects_malformed_script_requests(call, message: str) -> None:
    context = _context(patched=[], ranges=[], functions=[])

    with pytest.raises((TypeError, ValueError), match=message):
        call(context)
