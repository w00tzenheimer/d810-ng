"""End-to-end regression for portable computed-transfer normalization.

Codifies the win from spec §11.6: the ``rhad_indirect_dispatch`` fixture
(a cmov-pointer-select computed-goto CFF dispatcher, the Rhadamanthys
``sub_40A560`` shape) goes from an undecompilable ``__asm { jmp rax }`` to the
fully-unflattened original sequence, using only d810's own machinery:

  concolic resolve (EmulationOracle.trace_corridor)
  -> detached PREOPT source capture
  -> atomic condition-preserving frontend normalization
  -> CFF unflattener.

Runs via idalib (``idapro``) like the other headless e2e checks; skipped when
idalib or the lab fixture DLL is unavailable.
"""

from __future__ import annotations

import os
import pathlib
import re

import pytest

idapro = pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_FIXTURE = _REPO / "samples" / "bins" / "restructuring_lab.dll"
_SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _clear_ida_sidecars() -> None:
    """Force a fresh analysis: idalib reloads a stale unpacked db (``<name>.dll.id0``
    …) if present, which would mask the source bytes."""
    for suffix in _SIDECAR_SUFFIXES:
        for stale in (
            _FIXTURE.with_suffix(suffix),
            pathlib.Path(str(_FIXTURE) + suffix),
        ):
            stale.unlink(missing_ok=True)


@pytest.mark.skipif(not _FIXTURE.exists(), reason="restructuring_lab.dll not built")
def test_computed_goto_dispatcher_unflattens(monkeypatch) -> None:
    _clear_ida_sidecars()
    assert idapro.open_database(str(_FIXTURE), True) == 0
    try:
        import ida_hexrays
        import ida_name
        import idaapi

        idaapi.auto_wait()
        ida_hexrays.init_hexrays_plugin()
        func_ea = ida_name.get_name_ea(idaapi.BADADDR, "lab_rhad_indirect")
        assert func_ea != idaapi.BADADDR, "fixture export lab_rhad_indirect missing"

        # baseline: IDA cannot resolve the computed goto -> truncated decompile
        base = ida_hexrays.decompile(func_ea)
        baseline = str(base) if base else "None"
        assert (
            "jmp" in baseline.lower()
            or "jumpout" in baseline.lower()
            or baseline == "None"
        ), (
            f"fixture no longer reproduces the unresolved computed goto:\n{baseline}"
        )

        # start d810 with the unflattener config + install the computed-goto pass
        import d810.headless as headless

        # Under pytest, tests/system/conftest.py already scans+populates the
        # entire d810 package (Scanner.scan) at collection time. headless.configure()
        # normally re-triggers load_optimizer_registries() -> reload_package(),
        # which does a FULL importlib.reload() of every d810.* submodule. That
        # mints brand-new class objects (UnflatteningPlanner, etc.) while every
        # already-collected test module still holds the OLD class references
        # bound at collection time, causing `is`-identity assertions to fail
        # cascading through the rest of the system suite when it runs after
        # this test. Skip the redundant/destructive reload under pytest; it is
        # only needed for cold standalone idalib scripts (see __main__ below)
        # that never went through the system conftest's Scanner.scan().
        if "PYTEST_CURRENT_TEST" in os.environ:
            monkeypatch.setattr(headless, "load_optimizer_registries", lambda **_: None)

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

            cg.install()
            try:
                ida_hexrays.clear_cached_cfuncs()
                failure = ida_hexrays.hexrays_failure_t()
                recovered = str(headless.decompile(func_ea, failure=failure) or "None")
            finally:
                cg.uninstall()
        finally:
            headless.stop()
    finally:
        idapro.close_database(
            False
        )  # NEVER True: idalib writes patches through to the DLL

    # the flattened dispatcher is gone and each handler's side effect survives, in order
    assert (
        "__asm" not in recovered
        and "jmp" not in recovered.lower()
        and "jumpout" not in recovered.lower()
    ), (
        f"computed goto not materialised/unflattened:\n{recovered}\n"
        f"failure={int(failure.code)}@0x{int(failure.errea):X}: {failure.desc()}"
    )
    assert "__noreturn" not in recovered and re.search(
        r"\breturn\s+\w+\s*;", recovered
    ), (
        f"terminal return carrier was not recovered:\n{recovered}\n"
        f"failure={int(failure.code)}@0x{int(failure.errea):X}: {failure.desc()}"
    )
    # IDA's persisted radix setting may render these as hexadecimal or decimal.
    # Compare the ordered values, not their presentation.
    effects = tuple(
        int(literal, 0)
        for literal in re.findall(r"\+=\s+(0x[0-9A-Fa-f]+|[0-9]+)", recovered)
    )
    assert effects == (0x11, 0x22, 0x33), (
        f"handler effects/order not recovered: {effects}\n{recovered}\n"
        f"failure={int(failure.code)}@0x{int(failure.errea):X}: "
        f"{failure.desc()}"
    )


if __name__ == "__main__":
    # Local idalib runner (the docker system harness runs tests inside an already
    # open IDA; this file is idalib-style, so validate it directly here).
    patcher = pytest.MonkeyPatch()
    try:
        test_computed_goto_dispatcher_unflattens(patcher)
    finally:
        patcher.undo()
    print("PASS: computed-goto dispatcher unflattens end-to-end")
