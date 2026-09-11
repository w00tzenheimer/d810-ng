"""Pure contracts for the opt-in canonical pseudocode capture plugin."""

from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_plugin():
    path = ROOT / "tools/bench/canonical_output_capture.py"
    assert path.exists(), "canonical output capture plugin not implemented"
    spec = importlib.util.spec_from_file_location("canonical_output_capture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rendered:
    def __init__(self, text: str):
        self.text = text
        self.render_count = 0

    def __str__(self) -> str:
        self.render_count += 1
        return self.text


def test_capture_preserves_exact_utf8_and_sequential_nonoverwriting_outputs(tmp_path):
    module = load_plugin()
    plugin = tmp_path / "plugin.py"
    plugin.write_bytes(b"exact plugin source\n")
    output = tmp_path / "capture"
    capture = module.OutputCapture.create(output, plugin_path=plugin)
    first = Rendered("int café(void) {\n    return 1;\n}")
    second = Rendered("void λ(void) {}")

    capture.observe(
        first,
        nodeid="tests/system/test_original.py::test_node[value]",
        function_ea=0x18001AE24,
        function_name="_sub_7FF856533A20",
    )
    capture.observe(
        second,
        nodeid="tests/system/test_original.py::test_node[value]",
        function_ea=0x18001AE24,
        function_name="_sub_7FF856533A20",
    )

    first_bytes = first.text.encode("utf-8")
    second_bytes = second.text.encode("utf-8")
    assert (output / "000.c").read_bytes() == first_bytes
    assert (output / "001.c").read_bytes() == second_bytes
    assert first.render_count == second.render_count == 1
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["plugin_sha256"] == hashlib.sha256(plugin.read_bytes()).hexdigest()
    assert [row["sha256"] for row in manifest["captures"]] == [
        hashlib.sha256(first_bytes).hexdigest(),
        hashlib.sha256(second_bytes).hexdigest(),
    ]
    assert manifest["captures"][0] == {
        "bytes": len(first_bytes),
        "filename": "000.c",
        "function_ea": 0x18001AE24,
        "function_ea_hex": "0x18001ae24",
        "function_name": "_sub_7FF856533A20",
        "index": 0,
        "nodeid": "tests/system/test_original.py::test_node[value]",
        "sha256": hashlib.sha256(first_bytes).hexdigest(),
    }

    with pytest.raises(FileExistsError):
        module.OutputCapture.create(output, plugin_path=plugin)
    assert (output / "000.c").read_bytes() == first_bytes


def test_output_collision_is_reported_without_overwriting(tmp_path):
    module = load_plugin()
    plugin = tmp_path / "plugin.py"
    plugin.write_text("plugin\n")
    capture = module.OutputCapture.create(tmp_path / "capture", plugin_path=plugin)
    collision = capture.output_dir / "000.c"
    collision.write_bytes(b"owned")

    capture.observe(
        Rendered("replacement"),
        nodeid="node",
        function_ea=1,
        function_name="function",
    )

    assert collision.read_bytes() == b"owned"
    manifest = json.loads((capture.output_dir / "manifest.json").read_text())
    assert manifest["captures"] == []
    assert manifest["errors"][0]["error_type"] == "FileExistsError"


def test_decompile_wrapper_returns_identity_calls_once_and_propagates_exception():
    module = load_plugin()
    result = object()
    calls = []
    observations = []

    def original(*args, **kwargs):
        calls.append((args, kwargs))
        return result

    wrapped = module.make_decompile_wrapper(
        original,
        lambda value, args, kwargs: observations.append((value, args, kwargs)),
    )

    assert wrapped(0x1234, flags=7) is result
    assert calls == [((0x1234,), {"flags": 7})]
    assert observations == [(result, (0x1234,), {"flags": 7})]

    failure = RuntimeError("native decompile failed")

    def failing(*args, **kwargs):
        raise failure

    wrapped_failure = module.make_decompile_wrapper(
        failing,
        lambda *_args: pytest.fail("failed decompile must not be observed"),
    )
    with pytest.raises(RuntimeError) as raised:
        wrapped_failure(0x1234)
    assert raised.value is failure


def test_patch_restores_exact_callable_and_fixture_depends_on_probe(tmp_path):
    module = load_plugin()
    owner = SimpleNamespace()

    def original(ea):
        return ea

    owner.decompile = original
    observed = []
    with module.temporary_decompile_capture(
        owner,
        lambda value, args, kwargs: observed.append((value, args, kwargs)),
    ):
        wrapped = owner.decompile
        assert wrapped(0x401000) == 0x401000
        assert wrapped is not original
    assert owner.decompile is original
    assert observed == [(0x401000, (0x401000,), {})]
    assert (
        "canonical_dac_capture"
        in inspect.signature(module.canonical_output_capture).parameters
    )
