"""Cross-repository native provider and SQLite discovery acceptance."""

from __future__ import annotations

import contextlib
import json
from collections import defaultdict
from pathlib import Path
from types import SimpleNamespace
import shutil
import subprocess
from uuid import UUID

import pytest

ida_hexrays = pytest.importorskip("ida_hexrays")

from d810.backends import _host_capability_registry, registry  # noqa: E402
from d810.capabilities.plugin_host import PluginHostCapabilityRegistry  # noqa: E402
from d810.core.config import D810Configuration, ProjectConfiguration  # noqa: E402
from d810.core.function_execution_identity import (  # noqa: E402
    FunctionExecutionIdentity,
    MbaObservationContext,
)
from d810.core.plugins import (  # noqa: E402
    BackendManifest,
    BackendRegistry,
    BackendSpec,
    BackendStatus,
    BackendUnavailable,
)
from d810.mba.discovery_store import MbaDiscoveryStore  # noqa: E402
from d810.mba.extension_api import (  # noqa: E402
    D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
    MbaResidualObservationSink,
)
from d810.mba.discovery_models import (  # noqa: E402
    ProviderAttemptSnapshot,
    ResidualGroupState,
)
from d810.mba.provider_outcome import ProviderOutcomeStatus  # noqa: E402
from d810.mba.provider_routing import MbaProviderKind  # noqa: E402
from d810.mba.typed_term import term_fingerprint  # noqa: E402
from d810.mba.residual_observation_sink import SqliteMbaResidualObservationSink  # noqa: E402
from d810.mba.native_callback_lease import native_mba_callback_scope  # noqa: E402
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer  # noqa: E402
from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager  # noqa: E402
from d810.passes.config_v2_hook_runtime import compile_config_v2_hook_schedule  # noqa: E402
from d810.ir.maturity import IRMaturity  # noqa: E402


_ROOT = Path(__file__).resolve().parents[4]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"


def _build_native_corpus_binary(output_path: Path) -> None:
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("MBA compiler-shape acceptance needs clang, gcc, or cc")
    flags = [
        "-shared",
        "-fPIC",
        "-O0",
        "-fno-inline",
        "-fno-builtin",
        "-fno-omit-frame-pointer",
    ]
    if Path(compiler).name.startswith("clang"):
        flags.extend(("-fno-vectorize", "-fno-slp-vectorize"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            compiler,
            *flags,
            "-I",
            str(_ROOT / "samples/include"),
            "-o",
            str(output_path),
            str(_SOURCE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def test_missing_requirement_is_reported_before_provides_resolution() -> None:
    host = PluginHostCapabilityRegistry()
    resolved = False

    def provides():
        nonlocal resolved
        resolved = True
        return object()

    def validate(requirements):
        missing = "d810.test.missing.v1"
        if missing in requirements:
            raise BackendUnavailable(f"missing capability: {missing}")

    registry = BackendRegistry(
        source=lambda: [
            BackendSpec(
                name="fake",
                origin="task11-fake",
                load_manifest=lambda: BackendManifest(
                    name="fake",
                    api_version=1,
                    provides=provides,
                    requires=("d810.test.missing.v1",),
                ),
            )
        ],
        host=host,
        requirement_validator=validate,
        host_view_factory=host.view_for,
    )

    info = registry.probe("fake")

    assert info.status is BackendStatus.UNAVAILABLE
    assert "d810.test.missing.v1" in (info.reason or "")
    assert resolved is False


def _native_instruction():
    from tests.system.runtime.backends.test_mba_extension_host import (
        _instruction,
        _residual_source_ast,
    )

    return _instruction(_residual_source_ast(), ea=0x401002)


def _accepted_native_instruction():
    """Use Egglog's real semantic acceptance fixture (x + y - 2 * (x & y))."""
    from tests.system.runtime.backends.test_mba_extension_host import (
        _constant,
        _instruction,
        _leaf,
        _node,
    )

    x = _leaf("x", 1)
    y = _leaf("y", 2)
    common_sum = _node(ida_hexrays.m_add, x, y)
    common_and = _node(ida_hexrays.m_and, _leaf("x", 1), _leaf("y", 2))
    coefficient = _node(ida_hexrays.m_mul, _constant(-2), common_and)
    return _instruction(
        _node(ida_hexrays.m_add, common_sum, coefficient),
        ea=0x401002,
    )


def _context(identity, block, instruction) -> MbaObservationContext:
    function_identity = FunctionExecutionIdentity(
        input_identity="sha256:" + "a" * 64,
        input_identity_provenance="verified_loader_sha256",
        external_evidence_allowed=True,
        database_uuid="12345678-1234-5678-1234-567812345678",
        database_identity="task11-native-idb",
        function_ea=0x401000,
        function_rva=0x1000,
        function_fingerprint="task11-native-function",
        decompilation_session_id="12345678-1234-5678-1234-567812345679",
        top_level_epoch=1,
        maturity=(
            IRMaturity.GLOBAL_OPTIMIZED.value
            if block.mba.maturity == ida_hexrays.MMAT_GLBOPT2
            else IRMaturity.CANONICAL.value
        ),
        evidence_generation=1,
    )
    return MbaObservationContext(
        function_identity=function_identity,
        plugin_identity=identity,
        instruction_ea=instruction.ea,
        block_serial=block.serial,
        block_ea=block.mba.entry_ea,
    )


class _Optimizer(InstructionOptimizer):
    RULE_CLASSES = [object]

    def add_rule(self, rule):
        self.rules.add(rule)
        return True


def _manager(optimizer, maturity):
    manager = InstructionOptimizerManager.__new__(InstructionOptimizerManager)
    manager.current_maturity = maturity
    manager._active_optimizers = [optimizer]
    manager._last_optimizer_tried = None
    manager._rewrite_seen = defaultdict(set)
    manager._cycle_quarantined_rule_names = defaultdict(set)
    manager._scheduled_implementation_names = frozenset()
    manager._resolve_active_instruction_rule_names = lambda _block: None
    manager._residual_admission_cache_key = None
    manager._residual_admission_cache_value = False
    manager.analyzer = SimpleNamespace(analyze=lambda _block, _instruction: None)
    manager.stats = None
    manager.generate_z3_code = False
    manager.mba_observation_context = lambda block, instruction, identity: _context(
        identity, block, instruction
    )
    return manager


def _activate_real_provider(
    pass_id: str,
    store: MbaDiscoveryStore,
    *,
    max_leaves: int = 8,
    time_budget_ms: int = 20,
):
    host_registry = _host_capability_registry()
    sink = SqliteMbaResidualObservationSink(store)
    lease = host_registry.register(
        D810_MBA_RESIDUAL_OBSERVATION_CAPABILITY,
        MbaResidualObservationSink,
        sink,
        activation_binder=sink.bind_activation,
        implementation_binder=sink.bind_implementation,
    )
    project = ProjectConfiguration(
        path=Path(f"task11-{pass_id}.runtime-config-v2.json"),
        additional_configuration={
            "pipeline_v2": [
                {
                    "pass_id": pass_id,
                    "options": (
                        {
                            "maturities": [
                                "GLOBAL_OPTIMIZED"
                                if pass_id == "mba-egraph"
                                else "CANONICAL"
                            ],
                            "require_proof": True,
                            "max_leaves": max_leaves,
                        }
                        if pass_id == "mba-solve"
                        else {
                            "maturities": [
                                "GLOBAL_OPTIMIZED"
                                if pass_id == "mba-egraph"
                                else "CANONICAL"
                            ],
                            "max_leaves": max_leaves,
                            "max_operator_nodes": 128,
                            "max_degree": 1,
                            "time_budget_ms": time_budget_ms,
                            "families": ["add", "and", "bnot", "mul", "or", "sub", "xor"],
                        }
                    ),
                }
            ]
        },
    )
    schedule = compile_config_v2_hook_schedule(project)
    binding = next(
        item for item in schedule.instruction_bindings if item.pass_id == pass_id
    )
    backends = registry()
    candidate = backends.require_unique_implementation(
        pass_id,
        install_hint=("d810-cobra" if pass_id == "mba-solve" else "d810-egglog"),
    )
    assert candidate.rule_name == binding.implementation_id
    implementation = backends.activate_implementation(candidate)
    implementation.bind_plugin_services(backends.plugin_rule_services(candidate))
    implementation.configure(dict(binding.config))
    return backends, implementation, lease, sink, schedule


@pytest.mark.usefixtures("libobfuscated_setup")
class TestRealProviderResidualDiscovery:
    binary_name = "libobfuscated.dll"

    @pytest.mark.parametrize(
        ("pass_id", "plugin_name", "distribution", "version", "provider", "status", "reason"),
        (
            ("mba-egraph", "egglog", "d810-egglog", "0.1.0", "egraph", "over_budget", "candidate_budget"),
            ("mba-solve", "cobra", "d810-cobra", "0.1.4", "coefficient_solver", "ineligible", "leaf_budget"),
        ),
    )
    def test_real_provider_attempt_is_attributed_through_outer_optimizer(
        self,
        tmp_path: Path,
        pass_id: str,
        plugin_name: str,
        distribution: str,
        version: str,
        provider: str,
        status: str,
        reason: str,
    ) -> None:
        db_path = tmp_path / f"{pass_id}.sqlite3"
        db_path.unlink(missing_ok=True)
        store = MbaDiscoveryStore(db_path)
        backends, rule, lease, sink, schedule = _activate_real_provider(
            pass_id, store, max_leaves=1
        )
        assert schedule.instruction_bindings
        runtime_maturity = (
            ida_hexrays.MMAT_GLBOPT2
            if pass_id == "mba-egraph"
            else ida_hexrays.MMAT_PREOPTIMIZED
        )
        assert rule.maturities == [runtime_maturity]
        block = SimpleNamespace(
            mba=SimpleNamespace(
                maturity=runtime_maturity,
                entry_ea=0x401000,
            ),
            serial=7,
        )
        instruction = _native_instruction()
        optimizer = _Optimizer([runtime_maturity], stats=None)
        optimizer.add_rule(rule)
        manager = _manager(optimizer, runtime_maturity)

        try:
            with native_mba_callback_scope():
                assert manager.optimize(block, instruction) is False
            pending = rule.pending_provider_observation()
            assert pending is None
            snapshots = store.provider_attempt_snapshots()
            assert len(snapshots) == 1
            snapshot = snapshots[0]
            assert isinstance(snapshot, ProviderAttemptSnapshot)
            attempt = snapshot.attempt
            assert attempt.context.plugin_identity.name == plugin_name
            assert attempt.context.plugin_identity.distribution == distribution
            assert attempt.context.plugin_identity.version == version
            assert attempt.context.plugin_identity.origin
            assert attempt.context.function_identity.database_uuid == "12345678-1234-5678-1234-567812345678"
            assert attempt.context.function_identity.function_ea == 0x401000
            assert attempt.context.function_identity.function_rva == 0x1000
            assert attempt.context.function_identity.function_fingerprint == "task11-native-function"
            assert attempt.context.instruction_ea == 0x401002
            assert attempt.context.block_serial == 7
            assert attempt.context.block_ea == 0x401000
            assert attempt.context.function_identity.maturity == (
                IRMaturity.GLOBAL_OPTIMIZED.value
                if pass_id == "mba-egraph"
                else IRMaturity.CANONICAL.value
            )
            assert term_fingerprint(attempt.canonical_term) == attempt.outcome.fingerprint
            assert snapshot.group.revision == 1
            assert snapshot.group.state.value in {"eligible", "observed"}
            assert snapshot.group.raw_terms == (attempt.raw_term,)
            assert attempt.outcome.status.value == status
            assert attempt.outcome.refusal_reason == reason
            assert attempt.outcome.input_cost is not None
            assert attempt.outcome.output_cost is None or attempt.outcome.output_cost < attempt.outcome.input_cost
            assert attempt.outcome.provider.value == provider
        finally:
            backends.close_activations()
            lease.release()
            sink.close()
            store.close()

    def test_real_accepted_rewrite_is_applied_without_residual_row(
        self, tmp_path: Path
    ) -> None:
        store = MbaDiscoveryStore(tmp_path / "accepted.sqlite3")
        backends, rule, lease, sink, schedule = _activate_real_provider(
            "mba-egraph", store, max_leaves=8, time_budget_ms=1000
        )
        assert schedule.instruction_bindings
        runtime_maturity = ida_hexrays.MMAT_GLBOPT2
        assert rule.maturities == [runtime_maturity]
        block = SimpleNamespace(
            mba=SimpleNamespace(
                maturity=runtime_maturity,
                entry_ea=0x401000,
            ),
            serial=7,
        )
        instruction = _accepted_native_instruction()
        optimizer = _Optimizer([runtime_maturity], stats=None)
        optimizer.add_rule(rule)
        manager = _manager(optimizer, runtime_maturity)
        rule.begin_provider_outcome_capture()

        try:
            with native_mba_callback_scope():
                assert manager.optimize(block, instruction) is True
            assert rule.pending_provider_observation() is None
            assert store.provider_attempt_snapshots() == ()
            assert rule.provider_outcomes()[-1].status.value == "applied"
        finally:
            rule.end_provider_outcome_capture()
            backends.close_activations()
            lease.release()
            sink.close()
            store.close()


@contextlib.contextmanager
def _live_provider_state(tmp_path: Path, pass_id: str):
    """Run one provider through production state, manager, and sink ownership."""
    from d810.manager import D810State
    from d810.manager.state import D810_LOG_DIR_NAME

    state = D810State()
    previous_config = state.d810_config
    was_loaded = state.is_loaded()
    was_started = state.manager.started
    if was_started:
        state.stop_d810()
    if was_loaded:
        state.unload(gui=False)

    config = D810Configuration(ida_user_dir=tmp_path / "ida-user")
    config["log_dir"] = str(tmp_path / "logs")
    config["erase_logs_on_reload"] = False
    db_path = (
        Path(config["log_dir"])
        / D810_LOG_DIR_NAME
        / "d810_mba_discovery.sqlite3"
    )
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db_path.unlink(missing_ok=True)
    project_path = config.config_dir / f"task12-live-{pass_id}.json"
    project_path.parent.mkdir(parents=True, exist_ok=True)
    options = {
        "maturities": ["GLOBAL_OPTIMIZED"],
        "max_leaves": 1,
    }
    if pass_id == "mba-solve":
        options["require_proof"] = True
    else:
        options.update(
            {
                "max_operator_nodes": 128,
                "max_degree": 1,
                "time_budget_ms": 20,
                "families": ["add", "and", "bnot", "mul", "or", "sub", "xor"],
            }
        )
    pipeline = []
    if pass_id == "mba-egraph":
        pipeline.append(
            {
                "pass_id": "mba-solve",
                "options": {
                    "maturities": ["GLOBAL_OPTIMIZED"],
                    "require_proof": True,
                    "max_leaves": 1,
                },
            }
        )
    pipeline.append({"pass_id": pass_id, "options": options})
    project_path.write_text(
        json.dumps(
            {
                "description": f"Task 12 live {pass_id} residual acceptance",
                "additional_configuration": {"pipeline_v2": pipeline},
            }
        ),
        encoding="utf-8",
    )

    try:
        state.load(gui=False, d810_config=config)
        activated = state.load_project(state.project_manager.index(project_path.name))
        assert activated is not None
        yield state, db_path
    finally:
        state.stop_d810()
        state.unload(gui=False)
        state.load(gui=False, d810_config=previous_config)
        if was_started:
            state.start_d810()
        elif not was_loaded:
            state.unload(gui=False)


@pytest.mark.usefixtures("configure_hexrays")
class TestLiveExactCProviderResidualDiscovery:
    binary_name = "mba_compiler_shapes.dylib"
    generated_binary_factory = staticmethod(_build_native_corpus_binary)

    @pytest.mark.parametrize(
        ("pass_id", "rule_name", "plugin_name", "distribution", "provider"),
        (
            (
                "mba-solve",
                "CobraSolveRule",
                "cobra",
                "d810-cobra",
                MbaProviderKind.COEFFICIENT_SOLVER,
            ),
            (
                "mba-egraph",
                "EgglogOptimizer",
                "egglog",
                "d810-egglog",
                MbaProviderKind.EGRAPH,
            ),
        ),
    )
    def test_live_provider_outcome_is_persisted_by_ordinary_decompilation(
        self,
        tmp_path: Path,
        ida_database,
        pass_id: str,
        rule_name: str,
        plugin_name: str,
        distribution: str,
        provider: MbaProviderKind,
    ) -> None:
        function = "mba_shape_coefficient_05"
        with _live_provider_state(tmp_path, pass_id) as (state, db_path):
            matching_rules = [
                rule
                for rule in state.current_ins_rules
                if rule.name == rule_name
            ]
            assert [rule.name for rule in matching_rules] == [rule_name]
            callback_calls = 0
            portable_capture_calls = 0
            portable_candidates = 0
            finalized_receipts = []
            provider_rule = matching_rules[0]
            original_check = provider_rule.check_and_replace
            host_attribute = (
                "_mba_host" if hasattr(provider_rule, "_mba_host") else "_host"
            )
            original_host = getattr(provider_rule, host_attribute)
            original_finalize = provider_rule.finalize_provider_observation

            class _CaptureCountingHost:
                def __getattr__(self, name):
                    return getattr(original_host, name)

                def capture_instruction(self, instruction):
                    nonlocal portable_capture_calls, portable_candidates
                    portable_capture_calls += 1
                    candidate = original_host.capture_instruction(instruction)
                    if candidate is not None:
                        portable_candidates += 1
                    return candidate

            def counted_check(block, instruction):
                nonlocal callback_calls
                callback_calls += 1
                return original_check(block, instruction)

            def counted_finalize(context, *, accepted, reason):
                receipt = original_finalize(
                    context,
                    accepted=accepted,
                    reason=reason,
                )
                if receipt is not None:
                    finalized_receipts.append(receipt)
                return receipt

            setattr(provider_rule, host_attribute, _CaptureCountingHost())
            provider_rule.check_and_replace = counted_check
            provider_rule.finalize_provider_observation = counted_finalize
            state.start_d810()
            import idaapi
            import idc

            function_ea = idc.get_name_ea_simple(function)
            if function_ea == idaapi.BADADDR:
                function_ea = idc.get_name_ea_simple("_" + function)
            assert function_ea != idaapi.BADADDR
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert cfunc is not None
            assert callback_calls > 0, "installed provider never received an optinsn callback"
            assert portable_capture_calls > 0
            assert portable_candidates > 0, (
                "installed callbacks never formed a portable MBA candidate"
            )
            assert finalized_receipts, (
                "portable provider observations were not accepted by the bound sink"
            )
            assert any(receipt.status == "stored" for receipt in finalized_receipts)

        store = MbaDiscoveryStore(db_path)
        try:
            snapshots = tuple(
                snapshot
                for snapshot in store.provider_attempt_snapshots()
                if snapshot.attempt.context.function_identity.function_ea
                == function_ea
                and snapshot.attempt.context.plugin_identity.name == plugin_name
            )
            assert snapshots, "ordinary decompilation did not publish a residual row"
            for snapshot in snapshots:
                attempt = snapshot.attempt
                context = attempt.context
                identity = context.function_identity
                outcome = attempt.outcome

                UUID(attempt.attempt_uuid)
                UUID(identity.database_uuid)
                assert identity.input_identity.startswith("sha256:")
                assert len(identity.input_identity.removeprefix("sha256:")) == 64
                assert identity.input_identity_provenance == "captured_from_ida"
                assert identity.external_evidence_allowed is True
                assert identity.database_identity == f"task12-live-{pass_id}.json"
                assert identity.function_ea == function_ea
                assert identity.function_rva >= 0
                assert identity.function_fingerprint.startswith("sha256:")
                assert (
                    len(identity.function_fingerprint.removeprefix("sha256:")) == 64
                )
                assert identity.decompilation_session_id
                assert identity.top_level_epoch == 1
                assert identity.maturity == "ir.global.optimized"
                assert identity.evidence_generation == 0

                assert context.plugin_identity.name == plugin_name
                assert context.plugin_identity.distribution == distribution
                assert context.plugin_identity.version
                assert context.plugin_identity.origin
                assert context.instruction_ea > 0
                assert context.block_serial >= 0
                assert context.block_ea > 0

                assert outcome.provider is provider
                assert outcome.status is not ProviderOutcomeStatus.APPLIED
                assert outcome.status is not ProviderOutcomeStatus.ERROR
                assert outcome.refusal_reason
                assert outcome.input_cost is not None
                assert outcome.fingerprint == term_fingerprint(
                    attempt.canonical_term
                )
                assert attempt.eligible_for_mining is True

                assert snapshot.group.state in {
                    ResidualGroupState.ELIGIBLE,
                    ResidualGroupState.OBSERVED,
                }
                assert snapshot.group.eligible_observation_count >= 1
                assert snapshot.group.revision >= 1
                assert snapshot.group.canonical_term == attempt.canonical_term
                assert attempt.raw_term in snapshot.group.raw_terms
                assert snapshot.group.materialized_at is None
                assert snapshot.group.admitted_at is None

            normalized = store._connection.execute(
                "SELECT DISTINCT plugin_distribution, plugin_origin "
                "FROM provider_attempts WHERE plugin_name = ?",
                (plugin_name,),
            ).fetchall()
            assert normalized
            assert all(row[0] == distribution and row[1] for row in normalized)
        finally:
            store.close()
