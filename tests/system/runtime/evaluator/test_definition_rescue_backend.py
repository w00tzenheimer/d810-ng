from __future__ import annotations

from types import SimpleNamespace

import ida_hexrays

from d810.evaluator.hexrays_microcode import definition_rescue_backend as backend_module
from d810.evaluator.hexrays_microcode.definition_rescue_backend import (
    DefinitionSiteEvidence,
    HexRaysDefinitionRescueBackend,
)


def test_reaching_defs_for_stkvar_returns_neutral_sites(monkeypatch) -> None:
    backend = HexRaysDefinitionRescueBackend()
    mba = SimpleNamespace()
    captured = {}

    def fake_find_reaching_defs(_mba, block_serial, stkoff, size):
        captured["args"] = (_mba, block_serial, stkoff, size)
        return (
            SimpleNamespace(block_serial=12, insn_ea=0x4010),
            SimpleNamespace(block_serial=13, ins_ea=0x4020),
            SimpleNamespace(block_serial="bad"),
        )

    monkeypatch.setattr(
        backend_module,
        "find_reaching_defs_for_stkvar",
        fake_find_reaching_defs,
    )

    evidence = backend.reaching_defs_for_stkvar(mba, 15, 0x7BC, 4)

    assert evidence == (
        DefinitionSiteEvidence(block_serial=12, insn_ea=0x4010),
        DefinitionSiteEvidence(block_serial=13, insn_ea=0x4020),
    )
    assert captured["args"] == (mba, 15, 0x7BC, 4)


def test_run_sccp_overlay_delegates(monkeypatch) -> None:
    backend = HexRaysDefinitionRescueBackend()
    mba = SimpleNamespace()
    overlay = {}

    monkeypatch.setattr(backend_module, "run_sccp", lambda _mba: overlay)

    assert backend.run_sccp_overlay(mba) is overlay


def test_lookup_sccp_stkvar_uses_hexrays_stack_key() -> None:
    backend = HexRaysDefinitionRescueBackend()
    overlay = {
        (ida_hexrays.mop_S, 4, 0x7BC): 0x4C77464F,
    }

    assert (
        backend.lookup_sccp_stkvar(overlay, stkoff=0x7BC, size=4)
        == 0x4C77464F
    )
