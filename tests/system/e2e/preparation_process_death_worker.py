"""Two-process crash/recovery worker for pre-Hex-Rays preparation."""

from __future__ import annotations

import argparse
import json
import os
import shutil
from pathlib import Path

import idapro

import ida_auto
import ida_bytes
import ida_funcs
import ida_loader
import idaapi

from d810.backends.ida.idb_preparation.gateway import (
    IdaPreparationByteWriter,
    IdbPreparationGateway,
)
from d810.backends.ida.idb_preparation.journal import SQLitePreparationJournal
from d810.backends.ida.idb_preparation.patch_ledger import (
    IdaPatchLedger,
    derive_patch_delta,
)
from d810.capabilities.idb_preparation import (
    PreparationDeclaredByteBaseline,
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationState,
)
from d810.core.execution_journal import DecompilationSessionId, ExecutionAttemptId

DATABASE_IDENTITY = "preparation-process-death-idb"
UNMANAGED_CAPTURE_PENDING = "UNMANAGED_CAPTURE_PENDING"


class _UnusedRunner:
    def run(self, descriptor, context) -> None:
        raise AssertionError("startup recovery must not execute a script")


class _Reanalyzer:
    def reanalyze_function(self, function_ea: int) -> None:
        function = ida_funcs.get_func(function_ea)
        if function is not None:
            ida_funcs.reanalyze_function(function)

    def auto_wait(self) -> None:
        ida_auto.auto_wait()


class _Invalidator:
    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        return False


class _Callers:
    def callers_of(self, function_ea: int) -> frozenset[int]:
        return frozenset()


class _NoDecompiler:
    def decompile(self, function_ea: int):
        raise AssertionError("recovery without an erased cfunc must not decompile")


def _owner(ea: int) -> int | None:
    function = ida_funcs.get_func(ea)
    return None if function is None else int(function.start_ea)


def _gateway(journal: SQLitePreparationJournal) -> IdbPreparationGateway:
    return IdbPreparationGateway(
        journal=journal,
        patch_ledger=IdaPatchLedger(),
        script_runner=_UnusedRunner(),
        byte_writer=IdaPreparationByteWriter(),
        current_database_identity=DATABASE_IDENTITY,
        native_active_ranges=lambda identity: (),
        function_owner=_owner,
        reanalyzer=_Reanalyzer(),
        cache_invalidator=_Invalidator(),
        caller_discovery=_Callers(),
        redo_decompiler=_NoDecompiler(),
    )


def _open(path: Path) -> None:
    result = idapro.open_database(str(path), True)
    if result != 0:
        raise RuntimeError(f"failed to open {path}: {result}")
    ida_auto.auto_wait()


def _write(case_dir: Path, cut: str) -> None:
    source = Path("samples/bins/libobfuscated.dll").resolve()
    copied_binary = case_dir / source.name
    idb_path = case_dir / "crashed.i64"
    shutil.copy2(source, copied_binary)
    _open(copied_binary)
    try:
        pristine_ea = int(idaapi.inf_get_min_ea())
        inherited_ea = pristine_ea + 1
        pristine_original = int(ida_bytes.get_original_byte(pristine_ea)) & 0xFF
        inherited_original = int(ida_bytes.get_original_byte(inherited_ea)) & 0xFF
        inherited_before = inherited_original ^ 0x01
        ida_bytes.patch_byte(inherited_ea, inherited_before)
        pristine_before = pristine_original ^ 0x01
        ida_bytes.put_byte(pristine_ea, pristine_before)
        pristine_ledger_original = int(ida_bytes.get_original_byte(pristine_ea)) & 0xFF

        ledger = IdaPatchLedger()
        baseline = ledger.capture()
        request = PreparationRunRequest(
            database_identity=DATABASE_IDENTITY,
            anchor_function_ea=pristine_ea,
            script=PreparationScriptDescriptor(
                script_id="process-death",
                display_name="Process death",
                path="process_death.py",
                source_sha256="a" * 64,
                enabled=True,
                portable=True,
            ),
            authorizing_attempt_id=ExecutionAttemptId.new(
                session=DecompilationSessionId.new(), sequence=1
            ),
        )
        with SQLitePreparationJournal(case_dir / "journal.sqlite3") as journal:
            transaction = journal.prepare(request, baseline)
            transaction = journal.transition(
                transaction.transaction_id, PreparationState.SCRIPT_RUNNING
            )
            journal.record_declared_byte_baselines(
                transaction.transaction_id,
                (
                    PreparationDeclaredByteBaseline(
                        ea=pristine_ea,
                        ida_original=pristine_ledger_original,
                        before_is_patched=False,
                        before_value=pristine_before,
                    ),
                    PreparationDeclaredByteBaseline(
                        ea=inherited_ea,
                        ida_original=inherited_original,
                        before_is_patched=True,
                        before_value=inherited_before,
                    ),
                ),
            )

            if cut == UNMANAGED_CAPTURE_PENDING:
                ida_bytes.put_byte(pristine_ea, pristine_original ^ 0x02)
                ida_bytes.put_byte(inherited_ea, inherited_original ^ 0x03)
                journal.transition(
                    transaction.transaction_id, PreparationState.CAPTURE_PENDING
                )
            else:
                ida_bytes.patch_byte(pristine_ea, pristine_original ^ 0x02)
                ida_bytes.patch_byte(inherited_ea, inherited_original ^ 0x03)
            if cut == PreparationState.CAPTURE_PENDING.name:
                transaction = journal.transition(
                    transaction.transaction_id, PreparationState.CAPTURE_PENDING
                )
                journal.record_byte_deltas(
                    transaction.transaction_id,
                    derive_patch_delta(baseline, ledger.capture()),
                )

            metadata = {
                "pristine_ea": pristine_ea,
                "pristine_original": pristine_original,
                "pristine_before": pristine_before,
                "inherited_ea": inherited_ea,
                "inherited_original": inherited_original,
                "inherited_before": inherited_before,
                "baseline": [
                    {
                        "ea": row.ea,
                        "file_position": row.file_position,
                        "ida_original": row.ida_original,
                        "current_value": row.current_value,
                    }
                    for row in baseline
                ],
            }
            (case_dir / "metadata.json").write_text(
                json.dumps(metadata, indent=2), encoding="utf-8"
            )
            if not ida_loader.save_database(str(idb_path), 0):
                raise RuntimeError(f"failed to save crash IDB {idb_path}")
            print(f"saved crash cut {cut} to {idb_path}", flush=True)
            os._exit(91)
    finally:
        idapro.close_database(False)


def _recover(case_dir: Path) -> None:
    idb_path = case_dir / "crashed.i64"
    metadata = json.loads((case_dir / "metadata.json").read_text(encoding="utf-8"))
    _open(idb_path)
    try:
        with SQLitePreparationJournal(case_dir / "journal.sqlite3") as journal:
            receipts = _gateway(journal).recover_startup()
            if len(receipts) != 1 or not receipts[0].ok:
                raise AssertionError(f"unexpected recovery receipts: {receipts!r}")
            rows = IdaPatchLedger().capture()
            actual = [
                {
                    "ea": row.ea,
                    "file_position": row.file_position,
                    "ida_original": row.ida_original,
                    "current_value": row.current_value,
                }
                for row in rows
            ]
            if actual != metadata["baseline"]:
                raise AssertionError(
                    f"patch ledger did not restore exactly: {actual!r} != "
                    f"{metadata['baseline']!r}"
                )
            pristine_ea = int(metadata["pristine_ea"])
            inherited_ea = int(metadata["inherited_ea"])
            if int(ida_bytes.get_byte(pristine_ea)) & 0xFF != int(
                metadata["pristine_before"]
            ):
                raise AssertionError("pristine live before-value was not restored")
            if int(ida_bytes.get_byte(inherited_ea)) & 0xFF != int(
                metadata["inherited_before"]
            ):
                raise AssertionError("inherited patch value was not restored")
            print(
                f"recovered {receipts[0].transaction_id.value} exactly",
                flush=True,
            )
    finally:
        idapro.close_database(False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("write", "recover"), required=True)
    parser.add_argument(
        "--cut",
        choices=(
            PreparationState.SCRIPT_RUNNING.name,
            PreparationState.CAPTURE_PENDING.name,
            UNMANAGED_CAPTURE_PENDING,
        ),
        required=True,
    )
    parser.add_argument("--case-dir", type=Path, required=True)
    args = parser.parse_args()
    args.case_dir.mkdir(parents=True, exist_ok=True)
    if args.phase == "write":
        _write(args.case_dir, args.cut)
    else:
        _recover(args.case_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
