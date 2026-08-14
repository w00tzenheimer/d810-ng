"""Task 6 Step 1/2: the first tests in the whole plan permitted to mutate an
IDB, and only through ``NativePatchGateway``.

Every test here uses ``copy_of_idb`` (never combined with ``ida_database`` --
that fails loudly by design). It defaults to ``libobfuscated.dll``
specifically so the same disposable copy can, in a companion assertion, diff
d810's own deobfuscated output across the patch -- see
``tests/system/runtime/support/disposable_idb.py``'s module docstring.

Candidates are found by shape, not hardcoded, matching every other Task 5/6
system test in this directory (``test_native_patch_capture_preflight.py``,
``test_lifecycle_strategy_experiment.py``): scan every function for a
Mode-A-encodable branch via the already-committed, already-tested
``observation.observe_function``, rather than assuming a specific function
name survives a fixture recompile.
"""

from __future__ import annotations

import contextlib

import pytest

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime, pytest.mark.hexrays]

ida_auto = pytest.importorskip("ida_auto")
ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_gdl = pytest.importorskip("ida_gdl")
ida_hexrays = pytest.importorskip("ida_hexrays")
ida_ida = pytest.importorskip("ida_ida")
ida_nalt = pytest.importorskip("ida_nalt")
ida_typeinf = pytest.importorskip("ida_typeinf")
idaapi = pytest.importorskip("idaapi")
idautils = pytest.importorskip("idautils")

from d810.backends.hexrays.native_patch_lifecycle import (  # noqa: E402
    IdaCallerDiscovery,
    IdaCfuncCacheInvalidator,
    IdaControlledRedoDecompiler,
)
from d810.backends.ida.native_patch.capture import (  # noqa: E402
    IdaLiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder  # noqa: E402
from d810.backends.ida.native_patch.gateway import (  # noqa: E402
    IdaNativeByteWriter,
    NativePatchGateway,
)
from d810.backends.ida.native_patch.issuer import (  # noqa: E402
    NativePatchIssuerContract,
    NativePatchIssuerRegistry,
)
from d810.backends.ida.native_patch.observation import observe_function  # noqa: E402
from d810.backends.ida.native_patch.origin_mapper import (  # noqa: E402
    correlate_native_span,
    ida_decoded_range_reader,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionExtentRestorer,
    IdaFunctionFlowRestorer,
    IdaFunctionReanalyzer,
)
from d810.capabilities.native_patch import NativeJournalState  # noqa: E402
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)
from d810.core.persistence import SQLiteOptimizationStorage  # noqa: E402
from d810.ir.native_origin import NativeOriginCoverage  # noqa: E402
from d810.transforms.native_patch_lowering import lower_direct_edge  # noqa: E402
from d810.transforms.native_patch_plan import (  # noqa: E402
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
    NativePatchPlan,
)

# ---------------------------------------------------------------------------
# Shared discovery + construction helpers
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def fresh_journal(tmp_path):
    """One disposable SQLite write-ahead journal per test.

    A private, colocated helper -- not the production journal store itself
    (``d810.backends.ida.native_patch.journal.SQLiteNativePatchJournal``,
    used unmodified) -- just its open/close lifecycle for a test-scoped
    ``tmp_path``, mirroring ``tests/unit/backends/ida/native_patch/
    test_journal.py``'s ``store`` fixture for the system-test side.
    """
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    try:
        yield journal
    finally:
        journal.close()


def _bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else 32


def _issuer_registry() -> NativePatchIssuerRegistry:
    return NativePatchIssuerRegistry(
        (
            NativePatchIssuerContract(
                issuer_id="gateway-system-test-issuer",
                patch_class="lifting_normalization",
                proof_ids=frozenset({"gateway-system-test-proof"}),
                provenance=("gateway-system-test",),
            ),
        )
    )


def _encodable_candidates():
    for func_ea in idautils.Functions():
        observation = observe_function(func_ea)
        if observation is None:
            continue
        for branch in observation.branches:
            if branch.encodable:
                yield func_ea, branch


def _first_encodable_candidate():
    for func_ea, branch in _encodable_candidates():
        return func_ea, branch
    pytest.skip("no Mode-A-encodable branch found anywhere in this binary")


def _first_encodable_candidate_with_caller():
    for func_ea, branch in _encodable_candidates():
        callers = IdaCallerDiscovery().callers_of(func_ea)
        if callers:
            return func_ea, branch, callers
    pytest.skip("no Mode-A-encodable branch with a real caller found in this binary")


def _widest_encodable_candidate(min_size: int = 3):
    best = None
    for func_ea, branch in _encodable_candidates():
        if branch.size < min_size:
            continue
        if best is None or branch.size > best[1].size:
            best = (func_ea, branch)
    if best is None:
        pytest.skip(f"no Mode-A-encodable branch with size >= {min_size} found")
    return best


def _build_operation(function_ea: int, branch):
    start_ea, end_ea = branch.site_ea, branch.site_ea + branch.size
    origin_span = correlate_native_span(
        start_ea,
        end_ea,
        ida_decoded_range_reader(),
        expected_bytes_hash="gateway-system-test",
    )
    assert origin_span.coverage is NativeOriginCoverage.COMPLETE

    capture_outcome = capture_range_evidence(
        IdaLiveDatabaseReader(),
        NativeAddressRange(start_ea, end_ea),
        function_ea=function_ea,
    )
    assert capture_outcome.ok, capture_outcome.reason

    lowering = lower_direct_edge(
        operation_id="gateway-system-test-op",
        origin_span=origin_span,
        target_ea=branch.taken_target,
        known_instruction_heads=frozenset({branch.taken_target}),
        capture=capture_outcome.evidence,
        provider=MinimalX86BranchEncoder(),
        provider_id="minimal-x86",
        provider_version="1",
        bitness=_bitness(),
    )
    assert lowering.ok, lowering.reason
    return lowering.operation


def _build_plan(function_ea: int, operation) -> NativePatchPlan:
    ownership = IdaLiveDatabaseReader().read_function_ownership(function_ea)
    assert ownership is not None
    return NativePatchPlan(
        plan_id="gateway-system-test-plan",
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=NativeDatabaseIdentity(
            idb_uuid="gateway-system-test",
            input_file_hash="gateway-system-test",
            processor="metapc",
            bitness=_bitness(),
            image_base=idaapi.get_imagebase(),
            database_path_hash="gateway-system-test",
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=function_ea,
            chunk_ranges=ownership.chunk_ranges,
            inherited_bytes_hash="gateway-system-test",
        ),
        inherited_function_fingerprint="gateway-system-test-fp",
        target_cfg_fingerprint="gateway-system-test-cfg",
        native_origin_map_fingerprint="gateway-system-test-origin",
        architecture="x86",
        bitness=_bitness(),
        endianness="little",
        processor="metapc",
        issuer_id="gateway-system-test-issuer",
        proof_id="gateway-system-test-proof",
        proof_hash="gateway-system-test-proof-hash",
        provenance=("gateway-system-test",),
        operations=(operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


def _flowchart_signature(function_ea: int) -> tuple:
    func = ida_funcs.get_func(function_ea)
    chart = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
    edges = []
    for block in chart:
        succs = tuple(sorted(int(s.start_ea) for s in block.succs()))
        edges.append((int(block.start_ea), int(block.end_ea), succs))
    return tuple(sorted(edges))


def _function_metadata_signature(function_ea: int) -> tuple[int, tuple | None]:
    tif = ida_typeinf.tinfo_t()
    serialized = None
    if ida_nalt.get_tinfo(tif, function_ea):
        serialized = tuple(
            bytes(part) if part is not None else None for part in tif.serialize()
        )
    return int(ida_funcs.get_func_flags(function_ea)), serialized


def _capture_complete_native_state(function_ea: int, address_range: NativeAddressRange):
    reader = IdaLiveDatabaseReader()
    return {
        "current_bytes": reader.read_current_bytes(
            address_range.start_ea, address_range.end_ea
        ),
        "original_bytes": reader.read_original_bytes(
            address_range.start_ea, address_range.end_ea
        ),
        "patch_rows": reader.read_patch_rows(
            address_range.start_ea, address_range.end_ea
        ),
        "item_shape": reader.read_item_shape(
            address_range.start_ea, address_range.end_ea
        ),
        "incoming_refs": reader.read_incoming_refs(
            address_range.start_ea, address_range.end_ea
        ),
        "function_ownership": reader.read_function_ownership(function_ea),
        "function_metadata": _function_metadata_signature(function_ea),
        "flowchart": _flowchart_signature(function_ea),
    }


def _build_gateway(
    journal,
    *,
    reanalyzer=None,
    extent_restorer=None,
    cache_invalidator=None,
    redo=None,
):
    return NativePatchGateway(
        journal=journal,
        reader=IdaLiveDatabaseReader(),
        writer=IdaNativeByteWriter(),
        decode_replacement=MinimalX86BranchEncoder().decode,
        reanalyzer=reanalyzer or IdaFunctionReanalyzer(),
        extent_restorer=extent_restorer or IdaFunctionExtentRestorer(),
        flow_restorer=IdaFunctionFlowRestorer(),
        cache_invalidator=cache_invalidator or IdaCfuncCacheInvalidator(),
        caller_discovery=IdaCallerDiscovery(),
        redo_decompiler=redo or IdaControlledRedoDecompiler(),
        certificate_store=SQLiteOptimizationStorage(":memory:"),
        issuer_registry=_issuer_registry(),
        current_database_identity="gateway-system-test",
        d810_version="system-test",
    )


def _decompile_text(ea: int) -> str:
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")
    cfunc = ida_hexrays.decompile(ea)
    return str(cfunc) if cfunc is not None else "<decompile failed>"


# ---------------------------------------------------------------------------
# Step 1: exact apply/restore, plus the d810-output diff the disposable_idb
# fixture's default binary exists to make possible.
# ---------------------------------------------------------------------------


class TestGatewayApplyRestore:
    def test_restore_preserves_inherited_function_flags_and_type(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()
        assert ida_funcs.set_func_flags(
            function_ea,
            int(ida_funcs.get_func_flags(function_ea)) | ida_funcs.FUNC_NORET,
        )
        tif = ida_typeinf.tinfo_t()
        assert ida_typeinf.parse_decl(
            tif,
            None,
            "long long __fastcall native_patch_metadata_probe(long long value);",
            ida_typeinf.PT_SIL,
        )
        assert ida_typeinf.apply_tinfo(
            function_ea,
            tif,
            ida_typeinf.TINFO_DEFINITE,
        )
        before = _function_metadata_signature(function_ea)

        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)
            receipt = gateway.apply(plan)
            assert receipt.ok, receipt.rejection_reasons
            restored = gateway.restore(receipt.transaction_id)
            assert restored.ok, restored.failure_reason

        assert _function_metadata_signature(function_ea) == before

    def test_restore_reattaches_an_inherited_detached_tail(
        self, copy_of_idb, tmp_path
    ) -> None:
        selected = None
        for function_ea, branch in _encodable_candidates():
            func = ida_funcs.get_func(function_ea)
            heads = tuple(
                int(ea)
                for ea in idautils.Heads(branch.site_ea + branch.size, int(func.end_ea))
            )
            if len(heads) >= 3:
                selected = function_ea, branch, heads[-2], heads[-1], int(func.end_ea)
                break
        if selected is None:
            pytest.skip("no encodable branch leaves room to construct a tail")

        function_ea, branch, entry_end_ea, tail_start_ea, tail_end_ea = selected
        assert ida_funcs.set_func_end(function_ea, entry_end_ea)
        func = ida_funcs.get_func(function_ea)
        assert func is not None
        assert ida_funcs.append_func_tail(func, tail_start_ea, tail_end_ea)

        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = IdaLiveDatabaseReader().read_function_ownership(function_ea)
        assert before is not None
        assert len(before.chunk_ranges) == 2

        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)
            receipt = gateway.apply(plan)
            assert receipt.ok, receipt.rejection_reasons

            func = ida_funcs.get_func(function_ea)
            assert func is not None
            assert ida_funcs.remove_func_tail(func, tail_start_ea)

            restored = gateway.restore(receipt.transaction_id)
            assert restored.ok, restored.failure_reason

        assert IdaLiveDatabaseReader().read_function_ownership(function_ea) == before

    def test_gateway_restores_exact_owned_patch_on_disposable_idb(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()

        # A sentinel "user" patch elsewhere in the image -- proves the
        # gateway disturbs nothing outside its own authorized range, not
        # merely that the target range round-trips.
        sentinel_ea = copy_of_idb.min_ea
        original_sentinel = ida_bytes.get_byte(sentinel_ea)
        ida_bytes.patch_byte(sentinel_ea, (original_sentinel ^ 0xFF) & 0xFF)
        sentinel_value = ida_bytes.get_byte(sentinel_ea)

        # Normalize the baseline through the gateway's own reanalysis
        # primitive before capturing it (not a hand-rolled
        # reanalyze_function() call): apply() and restore() both drive
        # reanalysis through IdaFunctionReanalyzer, so the "before" baseline
        # must be captured under that exact same analysis regime or this
        # comparison is not measuring what it claims to. See
        # IdaFunctionReanalyzer.reanalyze_function's own docstring for the
        # measured reason a bare reanalyze_function() call is insufficient.
        IdaFunctionReanalyzer().reanalyze_function(function_ea)

        before_text = _decompile_text(function_ea)

        # Capture the authorizing plan only after the complete baseline
        # analysis/decompilation regime is established. Function-internal flow
        # refs are now part of exact ownership, so a plan captured before
        # either operation would correctly fail current-state preflight.
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        target_range = operation.range

        before = _capture_complete_native_state(function_ea, target_range)

        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)
            receipt = gateway.apply(plan)
            assert receipt.ok, receipt.rejection_reasons
            assert receipt.state is NativeJournalState.CERTIFIED
            assert receipt.certificate is not None

            after_apply = _capture_complete_native_state(function_ea, target_range)
            assert after_apply["current_bytes"] == operation.replacement_bytes
            assert after_apply != before, "the patch should have changed something"
            after_apply_text = _decompile_text(function_ea)

            restored = gateway.restore(receipt.transaction_id)
            assert restored.ok
            assert restored.state is NativeJournalState.RESTORED

        after_restore = _capture_complete_native_state(function_ea, target_range)

        # The core exact-restore guarantee: every field this task's
        # Non-negotiable behaviour 4 names as authorization/restore
        # evidence -- current bytes, original-layer bytes, patch rows, item
        # shape, incoming refs, and function ownership -- matches exactly.
        core_fields = (
            "current_bytes",
            "original_bytes",
            "patch_rows",
            "item_shape",
            "incoming_refs",
            "function_ownership",
            "function_metadata",
        )
        for field in core_fields:
            assert after_restore[field] == before[field], (
                f"restore must reproduce {field!r} byte-for-byte; it did not"
            )

        # Flowchart equality is a safety property, not a diagnostic. The
        # gateway now resets affected item boundaries before whole-function
        # reanalysis; retain this exact oracle so a stale successor regression
        # cannot be reported as a successful restore.
        assert after_restore["flowchart"] == before["flowchart"], (
            "restore changed IDA flowchart edges: "
            f"only_before={set(before['flowchart']) - set(after_restore['flowchart'])} "
            f"only_after={set(after_restore['flowchart']) - set(before['flowchart'])}"
        )

        after_restore_text = _decompile_text(function_ea)

        # The unrelated sentinel patch must have survived the whole
        # apply+restore cycle completely untouched.
        assert ida_bytes.get_byte(sentinel_ea) == sentinel_value

        # d810's deobfuscated output across the patch: recorded, not
        # asserted to go one way or the other (libobfuscated.dll's own
        # obfuscation may already resolve what Mode A also resolves
        # natively, in which case identical output is the expected,
        # interesting result -- see the module docstring).
        print(
            "[task6.gateway] d810 pseudocode identical before/after-apply: "
            f"{before_text == after_apply_text}"
        )
        print(
            "[task6.gateway] d810 pseudocode identical before/after-restore: "
            f"{before_text == after_restore_text}"
        )

    def test_caller_cfunc_is_invalidated_not_just_targets(
        self, copy_of_idb, tmp_path
    ) -> None:
        """Task 4 measured that ``mark_cfunc_dirty(target)`` leaves a
        caller's cached cfunc alone. Assert the gateway's own invalidation
        step does not repeat that gap."""
        function_ea, branch, callers = _first_encodable_candidate_with_caller()
        caller_ea = sorted(callers)[0]

        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        # Warm both caches.
        before_target_text = _decompile_text(function_ea)
        before_caller_text = _decompile_text(caller_ea)
        assert ida_hexrays.has_cached_cfunc(function_ea)
        assert ida_hexrays.has_cached_cfunc(caller_ea)

        # Decompilation may persist a guessed function type. Capture the plan
        # only after warming caches so exact function metadata remains an
        # authorization witness rather than a deliberately stale snapshot.
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)

        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)
            receipt = gateway.apply(plan)
            assert receipt.ok, receipt.rejection_reasons

        # THE ASSERTION: the caller's cfunc cache must be gone -- not merely
        # the target's. The target's own cache is expected to be warm again
        # by the time apply() returns (the gateway's own bounded controlled
        # redo re-decompiles the target after invalidating it, so it can
        # certify against fresh evidence) -- a target-only check here would
        # not distinguish "invalidated" from "never invalidated at all", so
        # the caller is the assertion that actually proves the point.
        assert not ida_hexrays.has_cached_cfunc(caller_ea), (
            "gateway.apply() invalidated the target but left the caller's "
            "cfunc cache intact -- this is precisely the gap Task 4 measured "
            "in mark_cfunc_dirty() alone"
        )
        # Recorded, not asserted to match: a fresh decompile of the caller
        # can legitimately differ from its pre-patch text even though the
        # caller's own bytes never changed -- Hex-Rays propagates type/
        # prototype inference for the patched callee into every caller it
        # re-decompiles, and Mode A's CFG simplification can change what it
        # infers. Measured on IDA 9.4 (Docker system-test run, Task 6): this
        # candidate's caller pseudocode did change (local variable
        # renumbering) after the callee's cache was correctly invalidated
        # and re-decompiled. The invariant this test proves is the
        # invalidation above, not representational stability of unrelated
        # callers.
        print(
            "[task6.gateway] caller pseudocode identical after invalidation: "
            f"{before_caller_text == _decompile_text(caller_ea)}"
        )

        # The target's cache, by contrast, is warm again and must reflect
        # the patch rather than serve stale pre-patch pseudocode.
        assert ida_hexrays.has_cached_cfunc(function_ea)
        after_target_text = _decompile_text(function_ea)
        assert after_target_text != before_target_text, (
            "the target's re-warmed cache should reflect the applied patch, "
            "not the pre-patch pseudocode"
        )


# ---------------------------------------------------------------------------
# Step 2: failure injection after each durable checkpoint.
# ---------------------------------------------------------------------------


class _FaultyDecodeReplacement:
    """Stands in for the decode step so a failure lands durably after
    PREPARED but strictly before any byte is written."""

    def __call__(self, ea, data):
        raise RuntimeError("injected: decode_replacement raised after PREPARED")


class _FaultyReanalyzer(IdaFunctionReanalyzer):
    """Performs the real reanalyze_function + auto_wait, then fails --
    'failure after the reanalysis request'."""

    def auto_wait(self) -> None:
        super().auto_wait()
        raise RuntimeError("injected: failure after reanalysis request")


class _FaultyRedoDecompiler(IdaControlledRedoDecompiler):
    """Performs the real cache-invalidation controlled redo, then fails --
    'failure after cache invalidation'."""

    def decompile(self, function_ea: int):
        result = super().decompile(function_ea)
        raise RuntimeError("injected: failure after cache invalidation")
        return result  # pragma: no cover - unreachable, kept for clarity


class _FaultyByteWriter(IdaNativeByteWriter):
    """Performs every real ``patch_byte`` call, but injects a failure (and,
    optionally, external interference on an untouched byte) partway through
    a multi-byte operation's write loop."""

    def __init__(self, *, raise_after_writes: int, corrupt_ea: int | None = None):
        self._raise_after = raise_after_writes
        self._corrupt_ea = corrupt_ea
        self.write_count = 0

    def patch_byte(self, ea: int, value: int) -> None:
        super().patch_byte(ea, value)
        self.write_count += 1
        if self.write_count == self._raise_after:
            if self._corrupt_ea is not None:
                import ida_bytes as _ida_bytes

                _ida_bytes.patch_byte(self._corrupt_ea, 0xCC)
            raise RuntimeError("injected: mid-write fault")


class TestGatewayFailureInjection:
    def test_failure_after_prepared_rolls_back_cleanly(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        with fresh_journal(tmp_path) as journal:
            gateway = NativePatchGateway(
                journal=journal,
                reader=IdaLiveDatabaseReader(),
                writer=IdaNativeByteWriter(),
                decode_replacement=_FaultyDecodeReplacement(),
                reanalyzer=IdaFunctionReanalyzer(),
                extent_restorer=IdaFunctionExtentRestorer(),
                flow_restorer=IdaFunctionFlowRestorer(),
                cache_invalidator=IdaCfuncCacheInvalidator(),
                caller_discovery=IdaCallerDiscovery(),
                redo_decompiler=IdaControlledRedoDecompiler(),
                certificate_store=SQLiteOptimizationStorage(":memory:"),
                issuer_registry=_issuer_registry(),
                current_database_identity="gateway-system-test",
            )
            with pytest.raises(RuntimeError, match="injected"):
                gateway.apply(plan)

            transaction_id = journal._conn.execute(  # noqa: SLF001
                "SELECT transaction_id FROM native_patch_transactions"
            ).fetchone()["transaction_id"]
            from d810.capabilities.native_patch import NativePatchTransactionId

            record = journal.get(NativePatchTransactionId(value=transaction_id))
            assert record.state is NativeJournalState.RESTORED

        after = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)
        assert after == before

    def test_failure_after_ida_write_rolls_back(self, copy_of_idb, tmp_path) -> None:
        function_ea, branch = _first_encodable_candidate()
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal, reanalyzer=_FaultyReanalyzer())
            with pytest.raises(
                RuntimeError, match="injected: failure after reanalysis"
            ):
                gateway.apply(plan)

            transaction_id = journal._conn.execute(  # noqa: SLF001
                "SELECT transaction_id FROM native_patch_transactions"
            ).fetchone()["transaction_id"]
            from d810.capabilities.native_patch import NativePatchTransactionId

            record = journal.get(NativePatchTransactionId(value=transaction_id))
            assert record.state is NativeJournalState.RECOVERY_REQUIRED

        after = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)
        assert after == before, (
            "bytes written before the injected failure must be rolled back"
        )

    def test_failure_after_cache_invalidation_rolls_back(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        with fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal, redo=_FaultyRedoDecompiler())
            with pytest.raises(
                RuntimeError, match="injected: failure after cache invalidation"
            ):
                gateway.apply(plan)

            transaction_id = journal._conn.execute(  # noqa: SLF001
                "SELECT transaction_id FROM native_patch_transactions"
            ).fetchone()["transaction_id"]
            from d810.capabilities.native_patch import NativePatchTransactionId

            record = journal.get(NativePatchTransactionId(value=transaction_id))
            assert record.state is NativeJournalState.RECOVERY_REQUIRED

        after = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)
        assert after == before

    def test_mid_write_failure_classifies_per_byte_and_rolls_back(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _widest_encodable_candidate(min_size=3)
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        with fresh_journal(tmp_path) as journal:
            writer = _FaultyByteWriter(raise_after_writes=2)
            gateway = NativePatchGateway(
                journal=journal,
                reader=IdaLiveDatabaseReader(),
                writer=writer,
                decode_replacement=MinimalX86BranchEncoder().decode,
                reanalyzer=IdaFunctionReanalyzer(),
                extent_restorer=IdaFunctionExtentRestorer(),
                flow_restorer=IdaFunctionFlowRestorer(),
                cache_invalidator=IdaCfuncCacheInvalidator(),
                caller_discovery=IdaCallerDiscovery(),
                redo_decompiler=IdaControlledRedoDecompiler(),
                certificate_store=SQLiteOptimizationStorage(":memory:"),
                issuer_registry=_issuer_registry(),
                current_database_identity="gateway-system-test",
            )
            with pytest.raises(RuntimeError, match="injected: mid-write fault"):
                gateway.apply(plan)

            transaction_id = journal._conn.execute(  # noqa: SLF001
                "SELECT transaction_id FROM native_patch_transactions"
            ).fetchone()["transaction_id"]
            from d810.capabilities.native_patch import NativePatchTransactionId

            record = journal.get(NativePatchTransactionId(value=transaction_id))
            assert record.state is NativeJournalState.RESTORED

        after = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)
        assert after == before, (
            "a fully disambiguated mid-write partial must roll back exactly"
        )

    def test_mid_write_external_interference_is_never_auto_overwritten(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _widest_encodable_candidate(min_size=3)
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        # A byte this operation does NOT govern, elsewhere in the image --
        # used as the "external interference" site so the corruption never
        # collides with a byte the operation itself would classify.
        interference_ea = copy_of_idb.min_ea
        original_interference_value = ida_bytes.get_byte(interference_ea)

        with fresh_journal(tmp_path) as journal:
            writer = _FaultyByteWriter(raise_after_writes=2, corrupt_ea=interference_ea)
            gateway = NativePatchGateway(
                journal=journal,
                reader=IdaLiveDatabaseReader(),
                writer=writer,
                decode_replacement=MinimalX86BranchEncoder().decode,
                reanalyzer=IdaFunctionReanalyzer(),
                extent_restorer=IdaFunctionExtentRestorer(),
                flow_restorer=IdaFunctionFlowRestorer(),
                cache_invalidator=IdaCfuncCacheInvalidator(),
                caller_discovery=IdaCallerDiscovery(),
                redo_decompiler=IdaControlledRedoDecompiler(),
                certificate_store=SQLiteOptimizationStorage(":memory:"),
                issuer_registry=_issuer_registry(),
                current_database_identity="gateway-system-test",
            )
            with pytest.raises(RuntimeError, match="injected: mid-write fault"):
                gateway.apply(plan)

            transaction_id = journal._conn.execute(  # noqa: SLF001
                "SELECT transaction_id FROM native_patch_transactions"
            ).fetchone()["transaction_id"]
            from d810.capabilities.native_patch import NativePatchTransactionId

            record = journal.get(NativePatchTransactionId(value=transaction_id))
            # The interference is on a byte outside this transaction's own
            # governed ranges, so classify_recovery does not itself see it --
            # what matters here is that automatic recovery never touched it.
            assert record.state in (
                NativeJournalState.RESTORED,
                NativeJournalState.RECOVERY_REQUIRED,
            )

        # The corrupted byte was never auto-overwritten by recovery.
        assert ida_bytes.get_byte(interference_ea) == 0xCC
        # Restore it manually so the disposable_idb teardown's SHA-256 check
        # of the *canonical* file is unaffected (it only ever inspects the
        # untouched original file on disk, but leaving the copy corrupted
        # would be a bad citizen for anyone inspecting the working copy).
        ida_bytes.patch_byte(interference_ea, original_interference_value)
