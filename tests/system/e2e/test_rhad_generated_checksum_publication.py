"""Exact A560 GENERATED checksum canary through ctree generation."""

from __future__ import annotations

import hashlib
import faulthandler
import json
import os
import pathlib
import shutil
import sqlite3
import subprocess
import sys

import pytest


idapro = pytest.importorskip("idapro")

_REPO = pathlib.Path(__file__).resolve().parents[3]
_BINARY = _REPO / "samples" / "bins" / "rhad_loader_unpacked.bin"
_FUNCTION_EA = 0x40A560
_EXPECTED_SHA256 = "2449071691418114b0afbf290b0dae3bf52553c562b2c3aebc092a7f18335e4c"
_SIDECARS = (".id0", ".id1", ".id2", ".nam", ".til", ".i64")
_FAILURE_OUTPUT_LIMIT = 12_000
_REFERENCE_OPERATION_IDS = (
    "rhad:route@0x40A605",
    "route:rhad-direct@0x40A619",
    "route:rhad-direct@0x40A68A",
    "rhad:route@0x40A6A4",
    "route:rhad-direct@0x40A74A",
    "rhad:route@0x40A764",
    "rhad:route@0x40A77C",
)
_IMPORTED_BLOCK_IDS = (
    "native@0x40A607",
    "native@0x40A615",
    "native@0x40A619",
    "native@0x40A680",
    "native@0x40A68A",
    "native@0x40B6C0",
    "native@0x40B6CA",
    "native@0x40B6D0",
    "native@0x40B6D4",
    "native@0x40A61B",
    "native@0x40A62D",
    "native@0x40A631",
    "native@0x40A740",
    "native@0x40A74A",
    "native@0x40A68C",
    "native@0x40A69A",
    "native@0x40A6A0",
    "native@0x40A6A4",
    "native@0x40A6B4",
    "native@0x40A6BA",
    "native@0x40A800",
    "native@0x40A80E",
    "native@0x40A814",
    "native@0x40A818",
    "native@0x40A74C",
    "native@0x40A75A",
    "native@0x40A760",
    "native@0x40A764",
    "native@0x40A766",
    "native@0x40ABC6",
    "native@0x40ABD4",
    "native@0x40ABDA",
    "native@0x40ABDE",
    "native@0x40A77C",
    "native@0x40A9DE",
    "native@0x40A9EC",
    "native@0x40A9F2",
    "native@0x40A9F6",
    "native@0x40A77E",
    "native@0x40A792",
)


def _output_excerpt(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    lines = [line[:1_500] for line in (value or "").splitlines()]
    normalized = "\n".join(lines)
    if len(normalized) <= _FAILURE_OUTPUT_LIMIT:
        return normalized
    diagnostic = "\n".join(
        line
        for line in lines
        if any(
            marker in line
            for marker in (
                "Traceback",
                "Error",
                "Rejected",
                "failed",
                "Failure",
                "graph_closure",
                "native-body",
                "semantic validation",
                "GENERATED checksum",
                "rhad-generated",
            )
        )
    )
    head_limit = _FAILURE_OUTPUT_LIMIT // 2
    tail_limit = _FAILURE_OUTPUT_LIMIT - head_limit
    return (
        diagnostic[:head_limit]
        + "\n... failure output elided ...\n"
        + normalized[-tail_limit:]
    )


def _fixture() -> pathlib.Path:
    override = os.environ.get("D810_RHAD_LOADER_FIXTURE")
    return pathlib.Path(override).resolve() if override else _BINARY


def _instructions(block: object) -> tuple[object, ...]:
    rows = []
    instruction = block.head
    while instruction is not None:
        rows.append(instruction)
        if instruction is block.tail:
            break
        instruction = instruction.next
    return tuple(rows)


def _native_anchor(block: object, origins: dict[int, int]) -> int:
    return min(
        (
            int(origins.get(int(row.ea), int(row.ea)))
            for row in _instructions(block)
            if int(origins.get(int(row.ea), int(row.ea))) > 0
        ),
        default=int(block.start),
    )


def _route_snapshot(mba: object) -> dict[str, object]:
    import ida_hexrays

    from d810.hexrays.mutation.detached_handler_island import (
        imported_detached_snippet_instruction_origins,
    )

    origins = dict(imported_detached_snippet_instruction_origins(mba))
    blocks = {serial: mba.get_mblock(serial) for serial in range(int(mba.qty))}

    def exact_indirect(transfer_ea: int) -> bool:
        return any(
            int(row.opcode) == int(ida_hexrays.m_ijmp)
            and int(origins.get(int(row.ea), int(row.ea))) == int(transfer_ea)
            for block in blocks.values()
            for row in _instructions(block)
        )

    def source_at(anchor_ea: int) -> object | None:
        return next(
            (
                block
                for block in blocks.values()
                if any(
                    int(origins.get(int(row.ea), int(row.ea))) == int(anchor_ea)
                    for row in _instructions(block)
                )
            ),
            None,
        )

    def route_targets(
        source: object | None,
        corridor_anchor_eas: set[int],
    ) -> set[int]:
        if source is None:
            return set()
        targets: set[int] = set()
        source_successors = tuple(int(value) for value in source.succset)
        if source_successors:
            for successor_serial in source_successors:
                target = blocks[successor_serial]
                while (
                    _native_anchor(target, origins) in corridor_anchor_eas
                    and len(tuple(target.succset)) == 1
                ):
                    successor_serial = int(tuple(target.succset)[0])
                    target = blocks[successor_serial]
                targets.add(_native_anchor(target, origins))
            return targets
        corridor_blocks = [source]
        if source.nextb is not None:
            corridor_blocks.append(source.nextb)
            if source.nextb.nextb is not None:
                corridor_blocks.append(source.nextb.nextb)
        for block in corridor_blocks:
            if block.tail is None:
                continue
            opcode = int(block.tail.opcode)
            operand = (
                block.tail.l if opcode == int(ida_hexrays.m_goto) else block.tail.d
            )
            if int(operand.t) == int(ida_hexrays.mop_b):
                targets.add(_native_anchor(blocks[int(operand.b)], origins))
        return targets

    def reachable_anchors() -> tuple[int, ...]:
        reachable: set[int] = set()
        pending = [0]
        while pending:
            serial = pending.pop()
            if serial in reachable:
                continue
            reachable.add(serial)
            pending.extend(int(value) for value in blocks[serial].succset)
        return tuple(
            sorted({_native_anchor(blocks[serial], origins) for serial in reachable})
        )

    transfer_indirect = exact_indirect(0x40A605)
    source = source_at(0x40A5F0)
    selected_source = source_at(0x40A692)
    selected_targets = route_targets(selected_source, {0x40A69A, 0x40A6A0})
    selected_snapshot = {
        "selected_source_present": selected_source is not None,
        "selected_indirect": exact_indirect(0x40A6A4),
        "selected_target_eas": tuple(sorted(selected_targets)),
    }
    setcc_source = source_at(0x40A76E)
    setcc_live_targets = route_targets(setcc_source, set())

    def setcc_semantic_anchor(live_anchor_ea: int) -> int:
        if 0x40A77E <= int(live_anchor_ea) < 0x40A794:
            return 0x40A77E
        if 0x40ABC6 <= int(live_anchor_ea) < 0x40ABE0:
            return 0x40ABC6
        return int(live_anchor_ea)

    setcc_snapshot = {
        "setcc_source_present": setcc_source is not None,
        "setcc_indirect": exact_indirect(0x40A77C),
        "setcc_target_eas": tuple(
            sorted(setcc_semantic_anchor(ea) for ea in setcc_live_targets)
        ),
    }
    if source is None:
        return {
            "maturity": int(mba.maturity),
            "quantity": int(mba.qty),
            "source_present": False,
            "indirect": transfer_indirect,
            "target_eas": (),
            "reachable_eas": reachable_anchors(),
            **selected_snapshot,
            **setcc_snapshot,
        }
    target_eas: set[int] = set()
    indirect = False
    source_successors = tuple(int(value) for value in source.succset)
    if source_successors:
        route_serials = [int(source.serial)]
        for successor_serial in source_successors:
            target = blocks[successor_serial]
            route_serials.append(successor_serial)
            while (
                _native_anchor(target, origins) in {0x40A5FE, 0x40A601}
                and len(tuple(target.succset)) == 1
            ):
                successor_serial = int(tuple(target.succset)[0])
                target = blocks[successor_serial]
                route_serials.append(successor_serial)
            target_eas.add(_native_anchor(target, origins))
        indirect = any(
            block.tail is not None and int(block.tail.opcode) == int(ida_hexrays.m_ijmp)
            for block in (blocks[serial] for serial in route_serials)
        )
    else:
        route_rows = (
            *(_instructions(source)[-1:]),
            *(_instructions(source.nextb)[-1:]),
            *(_instructions(source.nextb.nextb)[-1:]),
        )
        for row in route_rows:
            opcode = int(row.opcode)
            if opcode == int(ida_hexrays.m_ijmp):
                indirect = True
            operand = row.l if opcode == int(ida_hexrays.m_goto) else row.d
            if int(operand.t) != int(ida_hexrays.mop_b):
                continue
            target = blocks[int(operand.b)]
            target_eas.add(_native_anchor(target, origins))
    return {
        "maturity": int(mba.maturity),
        "quantity": int(mba.qty),
        "source_present": True,
        "source_serial": int(source.serial),
        "route_blocks": tuple(
            (
                int(block.serial),
                _native_anchor(block, origins),
                int(block.type),
                tuple(int(value) for value in block.succset),
            )
            for block in (source, source.nextb, source.nextb.nextb)
        ),
        "indirect": indirect,
        "target_eas": tuple(sorted(target_eas)),
        "reachable_eas": reachable_anchors(),
        **selected_snapshot,
        **setcc_snapshot,
    }


def _run_worker(binary: pathlib.Path) -> None:
    faulthandler.dump_traceback_later(45, repeat=False)
    print("checksum-worker:open", flush=True)
    assert idapro.open_database(str(binary), True) == 0
    hook = None
    try:
        import ida_hexrays
        import idaapi
        import idc

        idaapi.auto_wait()
        assert ida_hexrays.init_hexrays_plugin()
        assert idc.SetType(0x40F830, "int __cdecl sub_40F830(void)")

        import d810.headless as headless

        headless.configure(
            project="default_unflattening_ollvm.json",
            ida_user_dir=binary.parent / "ida-user",
        )
        headless.start()

        class NoFlowRules:
            def get_active_rules(self, **_kwargs):
                return ()

        # The checksum isolates the GENERATED producer.  Retain the configured
        # instruction optimizer (its first callback owns the GENERATED seam),
        # while suppressing the older broad PREOPT flow publication entirely.
        headless._state.manager.block_optimizer._rule_scope_service = NoFlowRules()
        print("checksum-worker:started", flush=True)
        receipts = []
        from d810.hexrays.mutation.mba_mutation_events import MbaMutationCommitted

        headless._state.manager.event_emitter.on(
            MbaMutationCommitted,
            lambda event: receipts.append(event.receipt),
        )
        captures: dict[str, object] = {"calls_count": 0}

        class Probe(ida_hexrays.Hexrays_Hooks):
            def preoptimized(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["preopt"] = _route_snapshot(mba)
                return 0

            def locopt(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA and "first_cfg" not in captures:
                    captures["first_cfg"] = _route_snapshot(mba)
                return 0

            def calls_done(self, mba):
                if int(mba.entry_ea) == _FUNCTION_EA:
                    captures["calls_count"] = int(captures["calls_count"]) + 1
                    captures["calls"] = _route_snapshot(mba)
                return 0

        hook = Probe()
        assert hook.hook()
        ida_hexrays.mark_cfunc_dirty(_FUNCTION_EA)
        print("checksum-worker:decompile", flush=True)
        failure = ida_hexrays.hexrays_failure_t()
        cfunc = headless.decompile(_FUNCTION_EA, failure=failure)
        print("checksum-worker:decompiled", flush=True)
        assert cfunc is not None, (
            f"A560 ctree failed: code={int(failure.code)} "
            f"ea=0x{int(failure.errea):X} desc={failure.desc()}"
        )
        matching = tuple(
            receipt
            for receipt in receipts
            if str(receipt.fragment_plan_id).startswith(
                "rhad-reference-compiler:rhad-generated-reference@0x40A560:"
            )
        )
        assert len(matching) == 1, tuple(
            str(receipt.fragment_plan_id) for receipt in receipts
        )
        receipt = matching[0]
        assert receipt.operation_count == receipt.planned_operation_count == 55
        assert len(receipt.version_transitions) >= 10
        assert receipt.prepublication_validation.passed
        assert receipt.postpublication_validation.passed
        assert receipt.root_publication_confirmed
        assert captures["preopt"]["indirect"] is False
        assert set(captures["preopt"]["target_eas"]) == {0x40A607, 0x40B6C0}, captures[
            "preopt"
        ]
        assert captures["first_cfg"]["indirect"] is False
        assert set(captures["first_cfg"]["target_eas"]) == {
            0x40A607,
            0x40B6C0,
        }, captures["first_cfg"]
        assert 0x40B6C0 in captures["first_cfg"]["reachable_eas"], captures["first_cfg"]
        for capture_name in ("preopt", "first_cfg"):
            selected_capture = captures[capture_name]
            assert selected_capture["selected_source_present"] is True
            assert selected_capture["selected_indirect"] is False
            assert set(selected_capture["selected_target_eas"]) == {
                0x40A6B4,
                0x40A800,
            }, selected_capture
            assert selected_capture["setcc_source_present"] is True
            assert selected_capture["setcc_indirect"] is False
            assert set(selected_capture["setcc_target_eas"]) == {
                0x40A77E,
                0x40ABC6,
            }, selected_capture
        assert {0x40A6B4, 0x40A800}.issubset(
            captures["first_cfg"]["reachable_eas"]
        ), captures["first_cfg"]
        assert captures["calls_count"] == 1
        assert captures["calls"]["indirect"] is False, captures["calls"]
        assert captures["calls"]["selected_indirect"] is False, captures["calls"]
        assert captures["calls"]["selected_source_present"] is False, captures["calls"]
        assert captures["calls"]["setcc_indirect"] is False, captures["calls"]
        assert captures["calls"]["setcc_source_present"] is True, captures["calls"]
        assert set(captures["calls"]["setcc_target_eas"]) == {
            0x40A77E,
        }, captures["calls"]
        if captures["calls"]["source_present"]:
            assert set(captures["calls"]["target_eas"]) == {
                0x40A607,
                0x40B6C0,
            }, captures["calls"]
        assert 0x40B6C0 in captures["calls"]["reachable_eas"], captures["calls"]
        headless.stop()
        print("checksum-worker:stopped", flush=True)
    finally:
        if hook is not None:
            hook.unhook()
        try:
            import d810.headless as headless

            headless.stop()
        except Exception:
            pass
        from d810.core.observability import close_observability_session

        close_observability_session()
        diag_output = os.environ.get("D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT")
        if diag_output:
            from d810.core.diag import find_latest_diag_db_path

            diag_path = find_latest_diag_db_path(_FUNCTION_EA)
            if diag_path is not None:
                destination = pathlib.Path(diag_output).resolve()
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(diag_path, destination)
        idapro.close_database(False)


def test_a560_generated_checksum_commits_and_reaches_ctree(
    tmp_path: pathlib.Path,
) -> None:
    fixture = _fixture()
    if not fixture.is_file():
        pytest.skip("real Rhad loader fixture unavailable")
    assert hashlib.sha256(fixture.read_bytes()).hexdigest() == _EXPECTED_SHA256
    binary = tmp_path / fixture.name
    diag_path = tmp_path / "a560-generated-checksum.diag.sqlite3"
    shutil.copy2(fixture, binary)
    for suffix in _SIDECARS:
        binary.with_suffix(suffix).unlink(missing_ok=True)
        pathlib.Path(str(binary) + suffix).unlink(missing_ok=True)
    before = hashlib.sha256(binary.read_bytes()).hexdigest()
    env = dict(os.environ)
    env.pop("PYTEST_CURRENT_TEST", None)
    env["PYTHONPATH"] = os.pathsep.join(
        (str(_REPO / "src"), str(_REPO / "tests"), env.get("PYTHONPATH", ""))
    )
    env["D810_DIAG_SNAPSHOT"] = "1"
    env["D810_RHAD_GENERATED_CHECKSUM_DIAG_OUTPUT"] = str(diag_path)
    try:
        result = subprocess.run(
            [
                sys.executable,
                str(pathlib.Path(__file__).resolve()),
                "--worker",
                str(binary),
            ],
            capture_output=True,
            text=True,
            env=env,
            timeout=55,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        pytest.fail(
            "checksum worker timed out\n"
            f"stdout excerpt:\n{_output_excerpt(error.stdout)}\n"
            f"stderr excerpt:\n{_output_excerpt(error.stderr)}"
        )
    assert result.returncode == 0, (
        f"checksum worker failed ({result.returncode})\n"
        f"stdout excerpt:\n{_output_excerpt(result.stdout)}\n"
        f"stderr excerpt:\n{_output_excerpt(result.stderr)}"
    )
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == before
    assert diag_path.is_file()
    with sqlite3.connect(diag_path) as connection:
        lifecycle_rows = connection.execute(
            "SELECT event_kind, maturity, phase, payload_json "
            "FROM lifecycle_events "
            "WHERE event_kind LIKE 'rhad_generated_checksum%' "
            "ORDER BY event_id"
        ).fetchall()
        assert tuple(row[0] for row in lifecycle_rows[:3]) == (
            "rhad_generated_checksum_preparation",
            "rhad_generated_checksum_compiled",
            "rhad_generated_checksum_published",
        )
        maturity_rows = tuple(
            row
            for row in lifecycle_rows
            if row[0] == "rhad_generated_checksum_maturity"
        )
        assert tuple(row[1] for row in maturity_rows) == (
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_LOCOPT",
            "MMAT_CALLS",
        )
        assert all(bool(json.loads(row[3])["passed"]) for row in maturity_rows)
        compiled_payload = json.loads(lifecycle_rows[1][3])
        assert tuple(compiled_payload["operation_ids"]) == _REFERENCE_OPERATION_IDS
        assert tuple(compiled_payload["imported_block_ids"]) == _IMPORTED_BLOCK_IDS
        assert compiled_payload["imported_block_count"] == len(_IMPORTED_BLOCK_IDS)
        reference_payloads = {
            row["operation_id"]: json.loads(row["reference_ledger_json"])
            for row in compiled_payload["reference_operations"]
        }
        assert set(reference_payloads) == set(_REFERENCE_OPERATION_IDS)
        direct_reference = reference_payloads["route:rhad-direct@0x40A619"]
        assert direct_reference["operation_category"] == "direct_route"
        assert direct_reference["source_native_ea"] == 0x40A607
        assert direct_reference["source_block_anchor_ea"] == 0x40A615
        assert direct_reference["transfer_ea"] == 0x40A619
        assert direct_reference["direct_target_block_id"] == "native@0x40A61B"
        selected_reference = reference_payloads["rhad:route@0x40A6A4"]
        assert selected_reference["reference_order"] == 8
        assert selected_reference["reference_symbol"] == (
            "JumpInliner._fixup_jmp_and_possible_jcc"
        )
        assert selected_reference["operation_variant"] == (
            "existing_conditional_plus_indirect"
        )
        assert selected_reference["source_native_ea"] == 0x40A68C
        assert selected_reference["condition_producer_ea"] == 0x40A692
        assert selected_reference["transfer_ea"] == 0x40A6A4
        assert selected_reference["true_target_ea"] == 0x40A6A6
        assert selected_reference["false_target_ea"] == 0x40A800
        assert selected_reference["true_target_block_id"] == "native@0x40A6B4"
        assert selected_reference["false_target_block_id"] == "native@0x40A800"
        setcc_reference = reference_payloads["rhad:route@0x40A77C"]
        assert setcc_reference["reference_order"] == 16
        assert setcc_reference["reference_symbol"] == (
            "JumpInliner._fixup_index_access"
        )
        assert setcc_reference["operation_variant"] == "setcc_indexed_table"
        assert setcc_reference["source_native_ea"] == 0x40A766
        assert setcc_reference["condition_producer_ea"] == 0x40A768
        assert setcc_reference["transfer_ea"] == 0x40A77C
        assert setcc_reference["true_target_ea"] == 0x40A77E
        assert setcc_reference["false_target_ea"] == 0x40ABC6
        assert setcc_reference["true_target_block_id"] == "native@0x40A77E"
        assert setcc_reference["false_target_block_id"] == "native@0x40ABC6"
        assert setcc_reference["setcc_table"]["table_base_ea"] == 0x48B81C
        assert setcc_reference["setcc_table"]["stride_bytes"] == 0x20
        assert setcc_reference["setcc_table"]["true_index"] == 1
        assert setcc_reference["setcc_table"]["false_index"] == 0

        maturity_payloads = {row[1]: json.loads(row[3]) for row in maturity_rows}
        for maturity in ("MMAT_GENERATED", "MMAT_PREOPTIMIZED", "MMAT_LOCOPT"):
            observations = {
                row["operation_id"]: row
                for row in maturity_payloads[maturity]["operation_observations"]
            }
            direct = observations["route:rhad-direct@0x40A619"]
            assert direct["source_present"] is True
            assert direct["source_topology_reachable"] is True
            assert direct["source_topology_retired"] is False
            assert direct["indirect_transfer_present"] is False
            assert direct["target_eas"] == [0x40A61B]
            assert direct["passed"] is True
            selected = observations["rhad:route@0x40A6A4"]
            assert selected["source_present"] is True
            assert selected["source_topology_reachable"] is True
            assert selected["source_topology_retired"] is False
            assert selected["indirect_transfer_present"] is False
            assert selected["target_eas"] == [0x40A6B4, 0x40A800]
            assert selected["semantic_target_eas"] == [0x40A6A6, 0x40A800]
            assert selected["delivery_target_eas"] == [0x40A6B4, 0x40A800]
            assert selected["semantic_targets_survive"] is True
            assert selected["passed"] is True
            setcc = observations["rhad:route@0x40A77C"]
            assert setcc["source_present"] is True
            assert setcc["source_topology_reachable"] is True
            assert setcc["source_topology_retired"] is False
            assert setcc["indirect_transfer_present"] is False
            assert setcc["target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
            assert setcc["semantic_targets_survive"] is True
            assert setcc["passed"] is True
        calls_payload = maturity_payloads["MMAT_CALLS"]
        calls_observations = {
            row["operation_id"]: row for row in calls_payload["operation_observations"]
        }
        direct_calls = calls_observations["route:rhad-direct@0x40A619"]
        assert direct_calls["source_present"] is False
        assert direct_calls["source_topology_reachable"] is False
        assert direct_calls["source_topology_retired"] is True
        assert direct_calls["indirect_transfer_present"] is False
        assert direct_calls["target_eas"] == []
        assert direct_calls["passed"] is True
        accepted_calls = calls_observations["rhad:route@0x40A605"]
        assert accepted_calls["indirect_transfer_present"] is False
        assert accepted_calls["passed"] is True
        selected_calls = calls_observations["rhad:route@0x40A6A4"]
        assert selected_calls["source_present"] is False
        assert selected_calls["source_topology_reachable"] is False
        assert selected_calls["source_topology_retired"] is True
        assert selected_calls["indirect_transfer_present"] is False
        assert selected_calls["target_eas"] == []
        assert selected_calls["semantic_target_eas"] == [0x40A6A6, 0x40A800]
        assert selected_calls["delivery_target_eas"] == [0x40A6B4, 0x40A800]
        assert selected_calls["semantic_targets_survive"] is True
        assert selected_calls["passed"] is True
        setcc_calls = calls_observations["rhad:route@0x40A77C"]
        assert setcc_calls["source_present"] is True
        assert setcc_calls["source_topology_reachable"] is False
        assert setcc_calls["source_topology_retired"] is True
        assert setcc_calls["indirect_transfer_present"] is False
        assert setcc_calls["target_eas"] == [0x40A77E]
        assert setcc_calls["semantic_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["delivery_target_eas"] == [0x40A77E, 0x40ABC6]
        assert setcc_calls["semantic_targets_survive"] is True
        assert setcc_calls["passed"] is True
        assert 0x40B6C0 in calls_payload["reachable_eas"]
        assert connection.execute(
            "SELECT COUNT(*) FROM lifecycle_events "
            "WHERE event_kind='ctree_captured' AND maturity='CMAT_FINAL'"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT planned_operation_count, applied_operation_count, outcome "
            "FROM mutation_receipts"
        ).fetchall() == [(55, 55, "committed")]
        assert connection.execute(
            "SELECT current_phase, mutation_started, poisoned, interr_code "
            "FROM cfg_transaction_attempts"
        ).fetchall() == [("committed", 1, 0, None)]
        assert connection.execute(
            "SELECT outcome, fragment_staged, root_publication_attempted, "
            "root_publication_succeeded, rollback_attempted "
            "FROM semantic_fragment_transactions"
        ).fetchall() == [("committed", 1, 1, 1, 0)]
        assert connection.execute(
            "SELECT COUNT(*) FROM semantic_fragment_route_oracle_comparisons "
            "WHERE outcome='matched'"
        ).fetchone() == (7,)
        committed_witnesses = connection.execute(
            "SELECT local_block_id, provenance, logical_proxy_token, "
            "logical_version, logical_generation, insertion_quantity_before, "
            "insertion_quantity_after, requested_insertion_serial, "
            "returned_serial, invalidated "
            "FROM cfg_creation_witnesses WHERE state='committed' "
            "ORDER BY rowid"
        ).fetchall()
        assert tuple(row[0] for row in committed_witnesses) == _IMPORTED_BLOCK_IDS
        assert all(
            row[1] == "imported_native"
            and row[2]
            and row[3:5] == (0, 1)
            and row[6] == row[5] + 1
            and row[7] == row[8]
            and row[9] == 0
            for row in committed_witnesses
        )


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--worker":
        raise SystemExit(
            "usage: test_rhad_generated_checksum_publication.py --worker BINARY"
        )
    _run_worker(pathlib.Path(sys.argv[2]))
