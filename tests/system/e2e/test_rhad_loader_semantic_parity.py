"""Two-round semantic regression for the real Rhadamanthys loader fixture."""

from __future__ import annotations

import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

idapro = pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_FUNCTION_EA = 0x40A560
_ZERO_ARG_CALLEE_EA = 0x40F830
_SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _clear_ida_sidecars(binary: pathlib.Path) -> None:
    for suffix in _SIDECAR_SUFFIXES:
        for stale in (
            binary.with_suffix(suffix),
            pathlib.Path(str(binary) + suffix),
        ):
            stale.unlink(missing_ok=True)


def _run_worker(binary: pathlib.Path, output_path: pathlib.Path) -> None:
    """Run the mutating idalib decompile in a process-local database."""
    assert idapro.open_database(str(binary), True) == 0
    recovered = "None"
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()

        # The fixture supplies the user-level type that the reference database
        # carries.  This is deliberately test-only; production recovery does
        # not match this sample EA or manufacture callee types.
        assert idc.SetType(
            _ZERO_ARG_CALLEE_EA,
            "int __cdecl sub_40F830(void)",
        )

        import d810.headless as headless

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

            cg.install()
            try:
                assert headless.prepare_native_preanalysis(_FUNCTION_EA) > 0
                ida_hexrays.clear_cached_cfuncs()
                first_failure = ida_hexrays.hexrays_failure_t()
                cfunc = ida_hexrays.decompile(_FUNCTION_EA, first_failure)
                assert cfunc is not None, (
                    "first decompile failed: "
                    f"code={int(first_failure.code)} "
                    f"ea=0x{int(first_failure.errea):X} "
                    f"description={first_failure.desc()!r}"
                )
                assert int(first_failure.code) == 0, (
                    "first decompile returned a cfunc with a failure: "
                    f"code={int(first_failure.code)} "
                    f"ea=0x{int(first_failure.errea):X} "
                    f"description={first_failure.desc()!r}"
                )
                recovered = str(cfunc) if cfunc is not None else "None"
            finally:
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        idapro.close_database(False)

    output_path.write_text(recovered, encoding="utf-8")


@pytest.mark.skipif(not _BINARY.exists(), reason="real loader fixture unavailable")
def test_real_loader_matches_reachable_semantic_oracle(tmp_path) -> None:
    """The reusable pipeline preserves every oracle-visible side effect."""
    binary = tmp_path / _BINARY.name
    output_path = tmp_path / "sub_40A560.c"
    shutil.copy2(_BINARY, binary)
    _clear_ida_sidecars(binary)

    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(_REPO / "src"),
            str(_REPO / "tests"),
            env.get("PYTHONPATH", ""),
        )
    )
    result = subprocess.run(
        [
            sys.executable,
            str(pathlib.Path(__file__).resolve()),
            "--worker",
            str(binary),
            str(output_path),
        ],
        capture_output=True,
        text=True,
        env=env,
        timeout=600,
        check=False,
    )
    assert result.returncode == 0, (
        f"real-loader worker failed ({result.returncode})\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    recovered = output_path.read_text(encoding="utf-8")

    assert recovered != "None"
    assert "while ( 1 )" not in recovered
    assert "HIBYTE(" not in recovered
    assert "sub_40F830()" in recovered
    assert "memset((void *)Param[1], 0, 0x40000u)" in recovered
    assert re.search(r"sub_4069C0\([^;\n]*&Param\[13\]\)", recovered)
    assert "return &off_48B8A4;" in recovered
    assert recovered.count("free(") == 6
    for call in (
        "CreateWindowExW(",
        "GetMessageA(",
        "TranslateMessage(",
        "DispatchMessageA(",
    ):
        assert recovered.count(call) == 1
    assert re.search(
        r"sub_40F830\(\)\s*&&\s*MessageBoxW\([\s\S]*?\)\s*==\s*7",
        recovered,
    )


if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "--worker":
        raise SystemExit(
            "usage: test_rhad_loader_semantic_parity.py --worker BINARY OUTPUT"
        )
    _run_worker(pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3]))
