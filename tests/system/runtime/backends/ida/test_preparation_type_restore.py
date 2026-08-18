from __future__ import annotations

import hashlib

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_funcs = pytest.importorskip("ida_funcs")
ida_name = pytest.importorskip("ida_name")
ida_typeinf = pytest.importorskip("ida_typeinf")
idaapi = pytest.importorskip("idaapi")

from d810.backends.hexrays.global_const_annotation import (  # noqa: E402
    referenced_global_items,
)
from d810.backends.ida.idb_preparation.gateway import (  # noqa: E402
    IdaPreparationByteWriter,
    IdbPreparationGateway,
)
from d810.backends.ida.idb_preparation.journal import (  # noqa: E402
    SQLitePreparationJournal,
)
from d810.backends.ida.idb_preparation.patch_ledger import IdaPatchLedger  # noqa: E402
from d810.backends.ida.idb_preparation.script_runner import (  # noqa: E402
    TrustedPreparationScriptRunner,
)
from d810.backends.ida.idb_preparation.type_metadata import IdaTypeMetadata  # noqa: E402
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionReanalyzer,
)
from d810.backends.ida.type_serialization import (  # noqa: E402
    SerializedTinfoParts,
    deserialize_tinfo,
    serialize_tinfo,
)
from d810.capabilities.idb_preparation import (  # noqa: E402
    PreparationRunRequest,
    PreparationScriptDescriptor,
    PreparationTypeDelta,
    SerializedTypeSnapshot,
)
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)


class _Invalidator:
    def mark_cfunc_dirty(self, function_ea: int) -> bool:
        return False


class _Callers:
    def callers_of(self, function_ea: int) -> frozenset[int]:
        return frozenset()


class _NoDecompiler:
    def decompile(self, function_ea: int):
        raise AssertionError("no erased cfunc exists to refresh")


def _owner(ea: int) -> int | None:
    function = ida_funcs.get_func(ea)
    return None if function is None else int(function.start_ea)


def _const_snapshot(before: SerializedTypeSnapshot) -> SerializedTypeSnapshot:
    if before.present:
        assert before.type_bytes is not None
        tif = deserialize_tinfo(
            SerializedTinfoParts(
                before.type_bytes,
                before.field_bytes,
                before.field_comment_bytes,
            )
        )
    else:
        tif = ida_typeinf.tinfo_t()
        tif.create_simple_type(ida_typeinf.BTF_UINT64)
        assert not tif.empty()
    tif.set_const()
    parts = serialize_tinfo(tif)
    return SerializedTypeSnapshot.from_parts(
        parts.type_bytes,
        parts.field_bytes,
        parts.field_comment_bytes,
    )


def test_gateway_restores_exact_global_type_transaction(copy_of_idb, tmp_path) -> None:
    function_ea = int(ida_name.get_name_ea(idaapi.BADADDR, "global_const_rva_guard"))
    if function_ea == idaapi.BADADDR:
        pytest.skip("global_const_rva_guard not found")
    eligible = [
        item
        for item in referenced_global_items(function_ea)
        if item.decision.can_persist_const
    ]
    if not eligible:
        pytest.skip("fixture has no eligible referenced global item")
    item_ea = int(eligible[0].evidence.item_head)
    type_metadata = IdaTypeMetadata()
    before = type_metadata.capture(item_ea)
    after = _const_snapshot(before)
    if after == before:
        pytest.skip("fixture global is already const")

    script = tmp_path / "noop.py"
    script.write_text("# type-only preparation\n", encoding="utf-8")
    descriptor = PreparationScriptDescriptor(
        script_id="type-only",
        display_name="Type only",
        path=str(script),
        source_sha256=hashlib.sha256(script.read_bytes()).hexdigest(),
        enabled=True,
        portable=True,
    )
    request = PreparationRunRequest(
        database_identity="type-restore-idb",
        anchor_function_ea=function_ea,
        script=descriptor,
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )

    with SQLitePreparationJournal(tmp_path / "journal.sqlite3") as journal:
        gateway = IdbPreparationGateway(
            journal=journal,
            patch_ledger=IdaPatchLedger(),
            script_runner=TrustedPreparationScriptRunner(),
            byte_writer=IdaPreparationByteWriter(),
            current_database_identity="type-restore-idb",
            native_active_ranges=lambda identity: (),
            function_owner=_owner,
            reanalyzer=IdaFunctionReanalyzer(),
            cache_invalidator=_Invalidator(),
            caller_discovery=_Callers(),
            redo_decompiler=_NoDecompiler(),
            type_metadata=type_metadata,
        )
        applied = gateway.run(
            request,
            type_proposals=(PreparationTypeDelta(item_ea, before, after),),
        )
        assert applied.ok
        assert type_metadata.capture(item_ea) == after

        restored = gateway.restore(applied.transaction_id)
        assert restored.ok
        assert type_metadata.capture(item_ea) == before
