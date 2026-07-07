"""End-to-end regression for the computed-goto resolver + CFF unflatten.

Codifies the win from spec §11.6: the ``rhad_indirect_dispatch`` fixture
(a cmov-pointer-select computed-goto CFF dispatcher, the Rhadamanthys
``sub_40A560`` shape) goes from an undecompilable ``__asm { jmp rax }`` to the
fully-unflattened original sequence, using only d810's own machinery:

  concolic resolve (EmulationOracle.trace_corridor)
  -> condition-preserving byte-patch delivery
  -> mark_indirect_dispatcher (route recovery to MMAT_CALLS)
  -> CFF unflattener.

Runs via idalib (``idapro``) like the other headless e2e checks; skipped when
idalib or the lab fixture DLL is unavailable.
"""
from __future__ import annotations

import pathlib

import pytest

idapro = pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_FIXTURE = _REPO / "samples" / "bins" / "restructuring_lab.dll"
_SIDECAR_SUFFIXES = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")


def _clear_ida_sidecars() -> None:
    """Force a fresh analysis: idalib reloads a stale unpacked db (``<name>.dll.id0``
    …) if present, which would mask the source bytes."""
    for suffix in _SIDECAR_SUFFIXES:
        for stale in (_FIXTURE.with_suffix(suffix), pathlib.Path(str(_FIXTURE) + suffix)):
            stale.unlink(missing_ok=True)


@pytest.mark.skipif(not _FIXTURE.exists(), reason="restructuring_lab.dll not built")
def test_computed_goto_dispatcher_unflattens() -> None:
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
        assert "jmp" in baseline.lower() or baseline == "None", (
            f"fixture no longer reproduces the unresolved computed goto:\n{baseline}"
        )

        # start d810 with the unflattener config + install the computed-goto pass
        import d810.headless as headless

        headless.configure(project="default_unflattening_ollvm.json")
        headless.start()
        try:
            import d810.optimizers.microcode.flow.jumps.computed_goto_resolver as cg

            cg.install()
            ida_hexrays.clear_cached_cfuncs()
            recovered = str(ida_hexrays.decompile(func_ea) or "None")
        finally:
            headless.stop()
    finally:
        idapro.close_database(False)  # NEVER True: idalib writes patches through to the DLL

    # the flattened dispatcher is gone and each handler's side effect survives, in order
    assert "__asm" not in recovered and "jmp" not in recovered.lower(), (
        f"computed goto not materialised/unflattened:\n{recovered}"
    )
    for literal in ("0x11", "0x22", "0x33"):
        assert literal in recovered, f"handler effect {literal} missing:\n{recovered}"
    # order: h_s1 (+0x11) before h_s2 (+0x22) before h_s3 (+0x33). (The final
    # return value may be typed away by Hex-Rays when unobserved -- not asserted.)
    assert recovered.index("0x11") < recovered.index("0x22") < recovered.index("0x33"), (
        f"handler order not recovered:\n{recovered}"
    )


if __name__ == "__main__":
    # Local idalib runner (the docker system harness runs tests inside an already
    # open IDA; this file is idalib-style, so validate it directly here).
    test_computed_goto_dispatcher_unflattens()
    print("PASS: computed-goto dispatcher unflattens end-to-end")
