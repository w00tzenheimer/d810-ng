"""Task 6 Step 5: prove the no-rerun and user-policy boundaries end to end.

``d810.manager.native_normalization`` is the top-layer orchestration that
decides *whether* ``NativePatchGateway.apply()`` is ever called at all. This
module proves the two boundaries that make a native write safe to leave
enabled:

* An explicit, disabled-by-default user policy is the only thing that can
  authorize a write -- a request with ``user_enabled=False`` must reach
  ``NativeNormalizationOutcome.NOT_AUTHORIZED`` without a single byte
  changing. Nothing resembling "profile mode" exists in this request type at
  all (see ``native_normalization.py``'s module docstring for why that is
  itself the enforcement, not merely a default).
* A certificate matching the current plan's content hash short-circuits a
  second explicit request to ``ALREADY_NORMALIZED`` -- an execution-journal
  abstention, not a second call into ``gateway.apply()``.
"""

from __future__ import annotations

import contextlib

import pytest

pytestmark = [
    pytest.mark.requires_ida,
    pytest.mark.runtime,
    pytest.mark.hexrays,
    pytest.mark.e2e,
]

ida_bytes = pytest.importorskip("ida_bytes")
ida_funcs = pytest.importorskip("ida_funcs")
ida_ida = pytest.importorskip("ida_ida")
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
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.observation import observe_function  # noqa: E402
from d810.backends.ida.native_patch.origin_mapper import (  # noqa: E402
    correlate_native_span,
    ida_decoded_range_reader,
)
from d810.backends.ida.native_patch.reanalysis import IdaFunctionReanalyzer  # noqa: E402
from d810.core.execution_journal import (  # noqa: E402
    DecompilationSessionId,
    ExecutionAttemptId,
)
from d810.core.persistence import SQLiteOptimizationStorage  # noqa: E402
from d810.ir.native_origin import NativeOriginCoverage  # noqa: E402
from d810.manager.native_normalization import (  # noqa: E402
    NativeNormalizationOutcome,
    NativeNormalizationRequest,
    authorize_and_apply,
)
from d810.transforms.native_patch_lowering import lower_direct_edge  # noqa: E402
from d810.transforms.native_patch_plan import (  # noqa: E402
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeFunctionIdentity,
    NativePatchPlan,
)


# ---------------------------------------------------------------------------
# Self-contained helpers (deliberately not shared with
# tests/system/runtime/backends/ida/test_native_patch_gateway.py -- this
# repository's existing Task 5/6 system tests each keep their own local
# candidate-discovery/plan-construction helpers rather than introducing a
# cross-subtree shared module; see e.g. test_native_patch_capture_preflight.py
# vs. test_lifecycle_strategy_experiment.py).
# ---------------------------------------------------------------------------


def _bitness() -> int:
    return 64 if ida_ida.inf_is_64bit() else 32


def _first_encodable_candidate():
    for func_ea in idautils.Functions():
        observation = observe_function(func_ea)
        if observation is None:
            continue
        for branch in observation.branches:
            if branch.encodable:
                return func_ea, branch
    pytest.skip("no Mode-A-encodable branch found anywhere in this binary")


def _build_operation(function_ea: int, branch):
    start_ea, end_ea = branch.site_ea, branch.site_ea + branch.size
    origin_span = correlate_native_span(
        start_ea,
        end_ea,
        ida_decoded_range_reader(),
        expected_bytes_hash="e2e-native-normalization",
    )
    assert origin_span.coverage is NativeOriginCoverage.COMPLETE

    capture_outcome = capture_range_evidence(
        IdaLiveDatabaseReader(),
        NativeAddressRange(start_ea, end_ea),
        function_ea=function_ea,
    )
    assert capture_outcome.ok, capture_outcome.reason

    lowering = lower_direct_edge(
        operation_id="e2e-native-normalization-op",
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
    func = ida_funcs.get_func(function_ea)
    return NativePatchPlan(
        plan_id="e2e-native-normalization-plan",
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=NativeDatabaseIdentity(
            idb_uuid="e2e-native-normalization",
            input_file_hash="e2e-native-normalization",
            processor="metapc",
            bitness=_bitness(),
            image_base=idaapi.get_imagebase(),
            database_path_hash="e2e-native-normalization",
        ),
        function_identity=NativeFunctionIdentity(
            entry_ea=function_ea,
            chunk_ranges=(NativeAddressRange(int(func.start_ea), int(func.end_ea)),),
            inherited_bytes_hash="e2e-native-normalization",
        ),
        inherited_function_fingerprint="e2e-native-normalization-fp",
        target_cfg_fingerprint="e2e-native-normalization-cfg",
        native_origin_map_fingerprint="e2e-native-normalization-origin",
        architecture="x86",
        bitness=_bitness(),
        endianness="little",
        processor="metapc",
        issuer_id="e2e-native-normalization-issuer",
        proof_id="e2e-native-normalization-proof",
        proof_hash="e2e-native-normalization-proof-hash",
        provenance=("e2e-native-normalization",),
        operations=(operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )


@contextlib.contextmanager
def _fresh_journal(tmp_path):
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    try:
        yield journal
    finally:
        journal.close()


def _build_gateway(journal) -> NativePatchGateway:
    return NativePatchGateway(
        journal=journal,
        reader=IdaLiveDatabaseReader(),
        writer=IdaNativeByteWriter(),
        decode_replacement=MinimalX86BranchEncoder().decode,
        reanalyzer=IdaFunctionReanalyzer(),
        cache_invalidator=IdaCfuncCacheInvalidator(),
        caller_discovery=IdaCallerDiscovery(),
        redo_decompiler=IdaControlledRedoDecompiler(),
        certificate_store=SQLiteOptimizationStorage(":memory:"),
        d810_version="e2e-test",
    )


class TestExplicitUserPolicyBoundary:
    binary_name = "libobfuscated.dll"

    def test_disabled_policy_never_writes_a_single_byte(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        with _fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)
            result = authorize_and_apply(
                NativeNormalizationRequest(plan=plan, user_enabled=False),
                gateway=gateway,
            )

        assert result.outcome is NativeNormalizationOutcome.NOT_AUTHORIZED
        assert result.apply_receipt is None
        assert result.reason == "USER_NOT_OPTED_IN"
        after = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)
        assert after == before, "an unauthorized request must never write a byte"

    def test_explicit_enable_applies_once_and_a_second_request_short_circuits(
        self, copy_of_idb, tmp_path
    ) -> None:
        function_ea, branch = _first_encodable_candidate()
        operation = _build_operation(function_ea, branch)
        plan = _build_plan(function_ea, operation)

        with _fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(journal)

            first = authorize_and_apply(
                NativeNormalizationRequest(plan=plan, user_enabled=True),
                gateway=gateway,
            )
            assert first.outcome is NativeNormalizationOutcome.APPLIED
            assert first.apply_receipt is not None and first.apply_receipt.ok
            after_first = ida_bytes.get_bytes(
                operation.range.start_ea, operation.range.size
            )
            assert after_first == operation.replacement_bytes

            second = authorize_and_apply(
                NativeNormalizationRequest(plan=plan, user_enabled=True),
                gateway=gateway,
            )

        assert second.outcome is NativeNormalizationOutcome.ALREADY_NORMALIZED
        # The certificate short-circuit means gateway.apply() was never
        # called a second time -- no second NativeApplyReceipt at all.
        assert second.apply_receipt is None
        assert second.certificate is not None
        assert (
            second.certificate.certificate_id
            == first.apply_receipt.certificate.certificate_id
        )
        # Bytes are exactly what the first apply left them as -- a
        # short-circuited request touches nothing.
        after_second = ida_bytes.get_bytes(
            operation.range.start_ea, operation.range.size
        )
        assert after_second == operation.replacement_bytes
