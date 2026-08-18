"""Disposable-IDB proof for pre-Hex-Rays preparation and exact restore."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
    pytest.mark.hexrays,
    pytest.mark.e2e,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_gdl = pytest.importorskip("ida_gdl")
ida_hexrays = pytest.importorskip("ida_hexrays")
idaapi = pytest.importorskip("idaapi")
idautils = pytest.importorskip("idautils")
idc = pytest.importorskip("idc")

from d810.backends.ida.idb_preparation.patch_ledger import IdaPatchLedger  # noqa: E402
from d810.backends.ida.type_serialization import capture_serialized_tinfo  # noqa: E402
from d810.capabilities.idb_preparation import PreparationState  # noqa: E402
from d810.manager.manager import d810_hooks_suppressed  # noqa: E402
from d810.testing.runner import _resolve_test_project_index  # noqa: E402


_FUNCTION_NAME = "lab_pre_hex_dispatch_prepare"
_INHERITED_BYTE_NAME = "lab_pre_hex_inherited_patch_byte"
_EXPECTED_PREPARED_PSEUDOCODE = """\
__int64 __fastcall lab_pre_hex_dispatch_prepare(int a1)
{
  return 17;
}"""
_SCRIPT = (
    Path(__file__).parents[1] / "fixtures/preparation/normalize_dispatcher.py"
).resolve()


def _named_ea(name: str) -> int:
    ea = int(idc.get_name_ea_simple(name))
    if ea == int(idaapi.BADADDR):
        ea = int(idc.get_name_ea_simple("_" + name))
    return ea


def _function_bytes(function_ea: int) -> tuple[tuple[int, bytes], ...]:
    return tuple(
        (
            int(start_ea),
            bytes(ida_bytes.get_bytes(int(start_ea), int(end_ea - start_ea))),
        )
        for start_ea, end_ea in idautils.Chunks(function_ea)
    )


def _flowchart(function_ea: int) -> tuple[tuple[int, int, tuple[int, ...]], ...]:
    function = ida_funcs.get_func(function_ea)
    assert function is not None
    return tuple(
        sorted(
            (
                int(block.start_ea),
                int(block.end_ea),
                tuple(sorted(int(successor.start_ea) for successor in block.succs())),
            )
            for block in ida_gdl.FlowChart(function)
        )
    )


def _pseudocode(function_ea: int) -> str:
    cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
    assert cfunc is not None
    return "\n".join(
        idaapi.tag_remove(line.line).rstrip() for line in cfunc.get_pseudocode()
    ).strip()


def _type_fingerprint(function_ea: int) -> tuple[object, ...]:
    return tuple(
        capture_serialized_tinfo(ea)
        for ea in (
            function_ea,
            *(start_ea for start_ea, _content in _function_bytes(function_ea)),
        )
    )


def _first_conditional_ea(function_ea: int) -> int:
    return next(
        int(ea)
        for ea in idautils.FuncItems(function_ea)
        if idc.print_insn_mnem(int(ea)).lower() in {"jz", "je"}
    )


def _fingerprint(value: object) -> str:
    return hashlib.sha256(repr(value).encode("utf-8")).hexdigest()


def _chunk_hex(chunks: tuple[tuple[int, bytes], ...]) -> tuple[tuple[str, str], ...]:
    return tuple((f"0x{start_ea:X}", content.hex()) for start_ea, content in chunks)


class TestPreHexraysIdbPreparation:
    binary_name = "restructuring_lab.dll"

    def test_prepare_improves_fresh_pseudocode_and_restore_is_exact(
        self,
        copy_of_idb,
        d810_state,
    ) -> None:
        function_ea = _named_ea(_FUNCTION_NAME)
        inherited_ea = _named_ea(_INHERITED_BYTE_NAME)
        assert function_ea != int(idaapi.BADADDR)
        assert inherited_ea != int(idaapi.BADADDR)
        assert idaapi.init_hexrays_plugin()

        chunks = tuple(idautils.Chunks(function_ea))
        assert len(chunks) >= 2, chunks
        conditional_ea = _first_conditional_ea(function_ea)
        entry_chunk = next(
            (start_ea, end_ea)
            for start_ea, end_ea in chunks
            if int(start_ea) == function_ea
        )
        assert not int(entry_chunk[0]) <= conditional_ea < int(entry_chunk[1])
        assert int(ida_bytes.get_byte(conditional_ea)) == 0x74

        inherited_original = int(ida_bytes.get_original_byte(inherited_ea)) & 0xFF
        inherited_value = inherited_original ^ 0xFF
        ida_bytes.patch_byte(inherited_ea, inherited_value)
        before_patch_rows = IdaPatchLedger().capture()
        before_bytes = _function_bytes(function_ea)
        before_flowchart = _flowchart(function_ea)
        before_pseudocode = _pseudocode(function_ea)
        before_types = _type_fingerprint(function_ea)

        with d810_state() as state:
            project_index = _resolve_test_project_index(
                state, "default_instruction_only.json"
            )
            state.load_project(project_index)
            project = state.current_project
            assert project is not None
            prior_config = copy.deepcopy(project.additional_configuration)
            project.additional_configuration["pre_hexrays"] = {
                "scripts": [
                    {
                        "id": "normalize-dispatcher",
                        "display_name": "Normalize dispatcher",
                        "path": str(_SCRIPT),
                        "enabled": True,
                    }
                ]
            }
            state._activate_project(
                project_index=project_index,
                project=project,
            )
            state.start_d810()
            transaction_id = None
            try:
                receipt = state.manager.prepare_idb_for_hexrays(function_ea)
                assert receipt.ok, receipt
                assert len(receipt.run_receipts) == 1
                run_receipt = receipt.run_receipts[0]
                assert run_receipt.state is PreparationState.IDB_PREPARED
                assert len(run_receipt.byte_deltas) > 0
                assert len(run_receipt.refresh_receipts) == 1
                assert all(
                    refresh.refresh_deferred_to_requested_decompile
                    and not refresh.controlled_redo_function_eas
                    for refresh in run_receipt.refresh_receipts
                )
                transaction_id = run_receipt.transaction_id
                assert int(ida_bytes.get_byte(conditional_ea)) == 0xEB
                live_records = state.manager.pre_hex_preparation._prepared_records(
                    state.manager.pre_hex_preparation.database_identity
                )
                assert any(
                    record.transaction_id == transaction_id
                    and record.state is PreparationState.IDB_PREPARED
                    for record in live_records
                )

                prepared_bytes = _function_bytes(function_ea)
                prepared_patch_rows = IdaPatchLedger().capture()
                prepared_flowchart = _flowchart(function_ea)
                prepared_types = _type_fingerprint(function_ea)
                with d810_hooks_suppressed(state.manager):
                    prepared_pseudocode = _pseudocode(function_ea)

                assert prepared_bytes != before_bytes
                assert prepared_patch_rows != before_patch_rows
                assert prepared_flowchart != before_flowchart
                assert prepared_types == before_types
                assert prepared_pseudocode != before_pseudocode
                assert prepared_pseudocode == _EXPECTED_PREPARED_PSEUDOCODE
                assert "if (" in before_pseudocode

                snapshot = state.get_workbench_snapshot(
                    function_ea,
                    _FUNCTION_NAME,
                )
                transaction = next(
                    row
                    for row in snapshot.preparation.transactions
                    if row.transaction_id == transaction_id.value
                )
                assert transaction.restore_allowed
                assert transaction.live_after_image
                assert transaction.bytes_changed == len(run_receipt.byte_deltas)
                assert conditional_ea in {
                    ea
                    for start_ea, end_ea in transaction.byte_ranges
                    for ea in range(start_ea, end_ea)
                }

                restored = state.manager.restore_idb_preparation(transaction_id)
                assert restored.ok, restored
                restored_records = state.manager.pre_hex_preparation._prepared_records(
                    state.manager.pre_hex_preparation.database_identity
                )
                assert any(
                    record.transaction_id == transaction_id
                    and record.state is PreparationState.RESTORED
                    for record in restored_records
                )
                transaction_id = None

                assert _function_bytes(function_ea) == before_bytes
                assert IdaPatchLedger().capture() == before_patch_rows
                assert int(ida_bytes.get_byte(inherited_ea)) == inherited_value
                assert _flowchart(function_ea) == before_flowchart
                assert _type_fingerprint(function_ea) == before_types
                with d810_hooks_suppressed(state.manager):
                    restored_pseudocode = _pseudocode(function_ea)
                assert restored_pseudocode == before_pseudocode

                restored_bytes = _function_bytes(function_ea)
                restored_patch_rows = IdaPatchLedger().capture()
                restored_flowchart = _flowchart(function_ea)
                restored_types = _type_fingerprint(function_ea)
                print(
                    "PRE_HEXRAYS_EVIDENCE="
                    + json.dumps(
                        {
                            "function_ea": f"0x{function_ea:X}",
                            "conditional_ea": f"0x{conditional_ea:X}",
                            "before_bytes": _chunk_hex(before_bytes),
                            "prepared_bytes": _chunk_hex(prepared_bytes),
                            "restored_bytes": _chunk_hex(restored_bytes),
                            "before_patch_rows": repr(before_patch_rows),
                            "prepared_patch_rows": repr(prepared_patch_rows),
                            "restored_patch_rows": repr(restored_patch_rows),
                            "before_flowchart": before_flowchart,
                            "prepared_flowchart": prepared_flowchart,
                            "restored_flowchart": restored_flowchart,
                            "before_flowchart_sha256": _fingerprint(before_flowchart),
                            "prepared_flowchart_sha256": _fingerprint(
                                prepared_flowchart
                            ),
                            "before_types": repr(before_types),
                            "prepared_types": repr(prepared_types),
                            "restored_types": repr(restored_types),
                            "type_fingerprint_sha256": _fingerprint(before_types),
                            "before_pseudocode": before_pseudocode,
                            "prepared_pseudocode": prepared_pseudocode,
                            "restored_pseudocode": restored_pseudocode,
                        },
                        sort_keys=True,
                    )
                )
            finally:
                if transaction_id is not None:
                    state.manager.restore_idb_preparation(transaction_id)
                project.additional_configuration.clear()
                project.additional_configuration.update(prior_config)
                if int(ida_bytes.get_byte(inherited_ea)) == inherited_value:
                    ida_bytes.revert_byte(inherited_ea)
