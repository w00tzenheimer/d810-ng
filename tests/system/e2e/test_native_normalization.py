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
ida_ida = pytest.importorskip("ida_ida")
idaapi = pytest.importorskip("idaapi")
idc = pytest.importorskip("idc")

from d810.backends.hexrays.native_patch_lifecycle import (  # noqa: E402
    IdaCallerDiscovery,
    IdaCfuncCacheInvalidator,
    IdaControlledRedoDecompiler,
)
from d810.backends.ida.native_patch.capture import IdaLiveDatabaseReader  # noqa: E402
from d810.backends.ida.native_patch.dead_edge_oracle import (  # noqa: E402
    build_dead_edge_semantic_plan,
    find_dead_edges_for_function,
)
from d810.backends.ida.native_patch.encoder import MinimalX86BranchEncoder  # noqa: E402
from d810.backends.ida.native_patch.gateway import (  # noqa: E402
    IdaNativeByteWriter,
    NativePatchGateway,
)
from d810.backends.ida.native_patch.issuer import (  # noqa: E402
    NativePatchIssuerRegistry,
    dead_edge_semantic_issuers,
)
from d810.backends.ida.native_patch.journal import SQLiteNativePatchJournal  # noqa: E402
from d810.backends.ida.native_patch.reanalysis import (  # noqa: E402
    IdaFunctionExtentRestorer,
    IdaFunctionFlowRestorer,
    IdaFunctionReanalyzer,
)
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
from d810.transforms.native_patch_plan import NativePatchPlan  # noqa: E402


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


def _build_proven_plan() -> tuple[int, NativePatchPlan]:
    """Use a production proof, never a test-invented control-flow contract."""
    function_ea = idc.get_name_ea_simple("single_iteration_simple")
    assert function_ea != idaapi.BADADDR, "single_iteration_simple not found"
    candidates, _ = find_dead_edges_for_function(function_ea)
    assert candidates, "native dead-edge oracle found no proven candidate"
    plan = build_dead_edge_semantic_plan(
        function_ea,
        (candidates[0],),
        authorizing_attempt_id=ExecutionAttemptId.new(
            session=DecompilationSessionId.new(), sequence=1
        ),
    )
    assert len(plan.operations) == 1
    return function_ea, plan


@contextlib.contextmanager
def _fresh_journal(tmp_path):
    journal = SQLiteNativePatchJournal(tmp_path / "journal.db")
    try:
        yield journal
    finally:
        journal.close()


def _build_gateway(journal, *, database_identity: str) -> NativePatchGateway:
    return NativePatchGateway(
        journal=journal,
        reader=IdaLiveDatabaseReader(),
        writer=IdaNativeByteWriter(),
        decode_replacement=MinimalX86BranchEncoder().decode,
        reanalyzer=IdaFunctionReanalyzer(),
        extent_restorer=IdaFunctionExtentRestorer(),
        flow_restorer=IdaFunctionFlowRestorer(),
        cache_invalidator=IdaCfuncCacheInvalidator(),
        caller_discovery=IdaCallerDiscovery(),
        redo_decompiler=IdaControlledRedoDecompiler(),
        certificate_store=SQLiteOptimizationStorage(":memory:"),
        issuer_registry=NativePatchIssuerRegistry(dead_edge_semantic_issuers()),
        current_database_identity=database_identity,
        d810_version="e2e-test",
    )


class TestExplicitUserPolicyBoundary:
    binary_name = "libobfuscated.dll"

    def test_disabled_policy_never_writes_a_single_byte(
        self, copy_of_idb, tmp_path
    ) -> None:
        _, plan = _build_proven_plan()
        operation = plan.operations[0]
        before = ida_bytes.get_bytes(operation.range.start_ea, operation.range.size)

        with _fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(
                journal, database_identity=plan.database_identity.idb_uuid
            )
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
        _, plan = _build_proven_plan()
        operation = plan.operations[0]

        with _fresh_journal(tmp_path) as journal:
            gateway = _build_gateway(
                journal, database_identity=plan.database_identity.idb_uuid
            )

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
