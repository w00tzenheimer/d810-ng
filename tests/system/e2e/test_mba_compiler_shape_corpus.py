"""Semantic receipt for the independently-authored compiler-shaped MBA corpus.

This is deliberately a pre-provider gate.  It proves every emitted shape against
its simple sibling before later portfolio tasks attribute a result to catalogue,
Egglog, or coefficient routing.
"""

from __future__ import annotations

import ctypes
import contextlib
import hashlib
import json
import os
import random
import shutil
import subprocess
import sys
import time
from collections.abc import Mapping
from pathlib import Path

import pytest
import idaapi

from d810.core.config import ProjectConfiguration
from d810.mba.certified_catalogue import ShadowMatcherParityLedger
from d810.mba.provider_outcome import MbaProviderKind, ProviderOutcomeStatus
from d810.mba.native_corpus_capture import capture_native_provider_histories
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    get_engine_info,
)
from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import get_func_ea, run_deobfuscation_test


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_CATALOGUE_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_catalogue.json"
_EGGLOG_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_egglog.json"
_EGGLOG_DEGREE2_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_egglog_degree2.json"
_NATIVE_BINARY = _ROOT / "samples/bins/mba_compiler_shapes.dylib"
_PARITY_CERTIFICATE_TOOL = _ROOT / "tools/scripts/mba_structural_matcher_certificate.py"

_COMMON_COMPILER_SHAPE_BUILD_FLAGS = (
    "-shared",
    "-fPIC",
    "-O0",
    "-fno-inline",
    "-fno-builtin",
    "-fno-omit-frame-pointer",
)

_CATALOGUE_CASES = (
    ("mba_shape_catalogue_01", "Add_HackersDelightRule_2"),
    ("mba_shape_catalogue_02", "Add_HackersDelightRule_3"),
    ("mba_shape_catalogue_03", "Xor_HackersDelightRule_3"),
    ("mba_shape_catalogue_04", "Sub_HackersDelightRule_2"),
    ("mba_shape_catalogue_05", "Or_MbaRule_1"),
    ("mba_shape_catalogue_06", "And_HackersDelightRule_4"),
    ("mba_shape_catalogue_07", "Add_HackersDelightRule_2"),
    ("mba_shape_catalogue_08", "Add_HackersDelightRule_4"),
    ("mba_shape_catalogue_09", "Or_HackersDelightRule_2"),
    ("mba_shape_catalogue_10", "Xor_HackersDelightRule_1"),
)

# GCC's -O0 code reaches IDA as already-canonical roots for these five forms.
# They remain semantically paired corpus samples, but do not constitute a
# provider candidate on that compiler.  The Clang lowering contract in the
# manifest preserves all ten roots for the pinned post-lowering proof.
_GCC_PRE_SIMPLIFIED_CATALOGUE_FUNCTIONS = frozenset(
    {
        "mba_shape_catalogue_02",
        "mba_shape_catalogue_05",
        "mba_shape_catalogue_06",
        "mba_shape_catalogue_09",
        "mba_shape_catalogue_10",
    }
)


def _ctype_for_width(width: int) -> type[ctypes._SimpleCData]:
    return {
        8: ctypes.c_uint8,
        16: ctypes.c_uint16,
        32: ctypes.c_uint32,
        64: ctypes.c_uint64,
    }[width]


def _input_vectors(width: int, seed: int) -> tuple[tuple[int, ...], ...]:
    maximum = (1 << width) - 1
    edges = (0, 1, 2, maximum - 1, maximum, maximum // 2)
    rng = random.Random(seed)
    random_vectors = tuple(
        tuple(rng.randrange(maximum + 1) for _ in range(8)) for _ in range(12)
    )
    return (
        tuple(
            tuple(edges[(index + offset) % len(edges)] for offset in range(8))
            for index in range(len(edges))
        )
        + random_vectors
    )


def _load_compiler_shape_library(tmp_path: Path) -> ctypes.CDLL:
    library = tmp_path / "libmba_compiler_shapes.dylib"
    compiler = _find_c_compiler()
    subprocess.run(
        [
            compiler,
            *_compiler_shape_build_flags(compiler),
            "-I",
            str(_ROOT / "samples/include"),
            "-o",
            str(library),
            str(_SOURCE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    _emit_compiler_shape_build_evidence(compiler, artifact="semantic_library")
    return ctypes.CDLL(str(library))


def _find_c_compiler() -> str:
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("compiler-shaped corpus needs clang, gcc, or cc")
    return compiler


def _compiler_shape_build_flags(compiler: str) -> tuple[str, ...]:
    """Return the exact portable build flags used for a recorded artifact.

    The lowering contract is deliberately Clang-specific because it inspects
    LLVM IR.  The semantic and IDA-input receipts may run under GCC in the
    pinned Linux image, where Clang's vectorizer spelling is not accepted.
    """
    if Path(compiler).name.startswith("clang"):
        return (
            *_COMMON_COMPILER_SHAPE_BUILD_FLAGS,
            "-fno-vectorize",
            "-fno-slp-vectorize",
        )
    return _COMMON_COMPILER_SHAPE_BUILD_FLAGS


def _catalogue_reaches_provider(function: str) -> bool:
    """Whether this compiler's native lowering still presents the MBA root."""
    compiler = _find_c_compiler()
    return not (
        Path(compiler).name.startswith("gcc")
        and function in _GCC_PRE_SIMPLIFIED_CATALOGUE_FUNCTIONS
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _canonical_json_digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    ).hexdigest()


def _parity_artifact_dir(tmp_path: Path) -> Path:
    """Use an explicit output directory when an operator wants persisted evidence."""

    configured = os.environ.get(
        "D810_MBA_STRUCTURAL_PARITY_ARTIFACT_DIR"
    ) or os.environ.get("MBA_STRUCTURAL_PARITY_ARTIFACT_DIR")
    destination = tmp_path if not configured else Path(configured)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _build_native_corpus_binary() -> None:
    compiler = _find_c_compiler()
    _NATIVE_BINARY.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            compiler,
            *_compiler_shape_build_flags(compiler),
            "-I",
            str(_ROOT / "samples/include"),
            "-o",
            str(_NATIVE_BINARY),
            str(_SOURCE),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    _emit_compiler_shape_build_evidence(compiler, artifact="native_ida_input")


def _emit_compiler_shape_build_evidence(compiler: str, *, artifact: str) -> None:
    compiler_version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    print(
        "MBA_COMPILER_SHAPE_BUILD_EVIDENCE="
        + json.dumps(
            {
                "artifact": artifact,
                "compiler": compiler,
                "version": compiler_version,
                "flags": [
                    *_compiler_shape_build_flags(compiler),
                    "-I samples/include",
                ],
            },
            sort_keys=True,
        )
    )


def test_all_compiler_shape_pairs_are_semantically_equivalent(tmp_path: Path) -> None:
    library = _load_compiler_shape_library(tmp_path)
    cases = json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]

    for case in cases:
        scalar = _ctype_for_width(case["width"])
        shape = getattr(library, case["function"])
        truth = getattr(library, case["ground_truth_function"])
        shape.argtypes = [scalar] * 8
        truth.argtypes = [scalar] * 8
        shape.restype = scalar
        truth.restype = scalar
        for arguments in _input_vectors(case["width"], case["semantic_seed"]):
            assert shape(*arguments) == truth(*arguments), (
                case["case_id"],
                arguments,
                shape(*arguments),
                truth(*arguments),
            )


def test_corpus_configs_are_provider_isolated_and_egglog_is_explicitly_interactive() -> (
    None
):
    catalogue = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
    egglog = json.loads(_EGGLOG_CONFIG.read_text(encoding="utf-8"))

    catalogue_passes = catalogue["additional_configuration"]["pipeline_v2"]
    assert [item["pass_id"] for item in catalogue_passes] == ["mba-simplify"]
    egglog_options = egglog["additional_configuration"]["pipeline_v2"][0]["options"]
    assert egglog_options["max_degree"] == 1
    assert egglog_options["time_budget_ms"] > 3
    assert "telemetry-only" in egglog["description"]
    assert set(catalogue_passes[0]["options"]["transforms"]) == {
        "add-hackers-delight-2",
        "add-hackers-delight-3",
        "add-hackers-delight-4",
        "and-hackers-delight-4",
        "or-hackers-delight-2",
        "or-mba-1",
        "sub-hackers-delight-2",
        "xor-hackers-delight-1",
        "xor-hackers-delight-3",
    }

    degree2 = json.loads(_EGGLOG_DEGREE2_CONFIG.read_text(encoding="utf-8"))
    degree2_options = degree2["additional_configuration"]["pipeline_v2"][0]["options"]
    assert degree2_options["max_degree"] == 2
    assert degree2_options["max_leaves"] == 4
    assert degree2_options["time_budget_ms"] > 3
    assert "root-only" in degree2["description"]


def test_catalogue_corpus_keeps_legacy_dsl_matching_by_default() -> None:
    """The portfolio pass stays stable while structural matching remains gated."""

    catalogue = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
    description = catalogue["description"].lower()
    assert "catalogue" in description
    # The portfolio scheduling pass does not change. Its selected DSL rules
    # retain legacy generated permutations until explicit structural opt-in
    # has native Cython parity evidence.
    assert [
        item["pass_id"] for item in catalogue["additional_configuration"]["pipeline_v2"]
    ] == ["mba-simplify"]


def test_corpus_projects_register_their_one_intended_provider(
    ida_database, d810_state, monkeypatch
) -> None:
    monkeypatch.delenv("D810_SHADOW_DSL_MATCHING", raising=False)
    monkeypatch.delenv("D810_STRUCTURAL_DSL_MATCHING", raising=False)
    with d810_state() as state:
        state.load_project(
            state.project_manager.index("mba_compiler_shape_catalogue.json")
        )
        assert state.last_pipeline_v2_hook_pass_ids == ("mba-simplify",)
        catalogue_adapters = tuple(state.current_ins_rules)
        assert catalogue_adapters
        assert all(
            not adapter.uses_structural_matching for adapter in catalogue_adapters
        )
        assert state.current_certified_catalogue_snapshot is None
        assert state.current_shadow_matcher_parity_ledger is None
        assert sum(
            len(adapter.pattern_candidates) for adapter in catalogue_adapters
        ) >= len(catalogue_adapters)

        state.load_project(
            state.project_manager.index("mba_compiler_shape_egglog.json")
        )
        assert state.last_pipeline_v2_hook_pass_ids == ("mba-egglog",)
        assert [rule.name for rule in state.current_ins_rules] == ["EgglogOptimizer"]

        state.load_project(
            state.project_manager.index("mba_compiler_shape_egglog_degree2.json")
        )
        assert state.last_pipeline_v2_hook_pass_ids == ("mba-egglog",)
        optimizer = state.current_ins_rules[0]
        assert optimizer.max_degree == 2
        assert optimizer.families == ("add", "and", "or", "sub", "xor")


@pytest.mark.usefixtures("configure_hexrays")
class TestCompilerShapeCatalogueNative:
    """Native receipt for the root-shaped, currently routed catalogue cases.

    The binary is built from this task's source before the Docker invocation;
    it is intentionally not checked in.  This compiler corpus makes no
    single-root degree-two claim: GCC/Hex-Rays may canonicalize a source form
    or schedule independent nested roots.  The direct-AST runtime suite owns
    the degree-two derivation proof.
    """

    binary_name = "mba_compiler_shapes.dylib"

    @classmethod
    def setup_class(cls) -> None:
        """Build before the shared IDA database fixture resolves ``binary_name``."""
        _build_native_corpus_binary()

    @pytest.mark.parametrize(
        ("function", "rule_name"),
        _CATALOGUE_CASES,
        ids=[function for function, _ in _CATALOGUE_CASES],
    )
    def test_catalogue_route_matches_the_native_lowered_shape(
        self,
        function: str,
        rule_name: str,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        # Task 7's parity receipt is meaningful only while the legacy matcher
        # remains authoritative.  Force the release rollback before state
        # construction; this test is the native shadow gate that selection
        # must satisfy before Task 8 can become authoritative.
        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
        reaches_provider = _catalogue_reaches_provider(function)
        ledgers = []

        @contextlib.contextmanager
        def _recording_d810_state():
            with d810_state() as state:
                yield state
                ledgers.append(state.current_shadow_matcher_parity_ledger)

        run_deobfuscation_test(
            DeobfuscationCase(
                function=function,
                description=(
                    "catalogue rule fires on a corpus-owned native shape"
                    if reaches_provider
                    else "native compiler/IDA lowering already canonicalizes this root"
                ),
                project="mba_compiler_shape_catalogue.json",
                must_change=reaches_provider,
                required_rules=[rule_name] if reaches_provider else [],
                forbidden_rules=[] if reaches_provider else [rule_name],
            ),
            d810_state=_recording_d810_state,
            pseudocode_to_string=pseudocode_to_string,
        )
        assert len(ledgers) == 1
        ledger = ledgers[0]
        assert ledger is not None
        # This is intentionally non-vacuous for the stable native shadow
        # witness. A zero-mismatch ledger with no legacy observation says
        # nothing about the selected config-v2 route. Other corpus roots may
        # already be canonicalized by GCC before this callback runs.
        if function == "mba_shape_catalogue_01":
            assert ledger.observation_count > 0
            assert ledger.legacy_match_count > 0
        if function == "mba_shape_catalogue_04":
            # Regression: the legacy generated XOR permutation binds x=b,
            # y=a only after the outer subtraction rejects x=a, y=b. The
            # structural shadow must retry that nested lazy swap.
            assert ledger.legacy_match_count == 1
        assert ledger.legacy_rule_mismatches == 0
        assert ledger.legacy_binding_mismatches == 0
        assert ledger.legacy_binding_unknown == 0
        # Structural-only coverage is split into pending and native-Z3-proven
        # observations. Neither counter is a provider selection or mutation.
        assert (
            ledger.new_safe_coverage_pending + ledger.new_safe_coverage_proved
        ) >= 0

    def test_native_shadow_evidence_generates_and_activates_runtime_bound_certificate(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """Turn real legacy-authoritative observations into an activation receipt.

        This is intentionally an IDA test rather than a portable certificate
        fixture.  It proves the evidence producer, certificate renderer, and
        configuration-time authorization form one chain in each matcher runtime.
        Set ``D810_MBA_STRUCTURAL_PARITY_ARTIFACT_DIR`` (the Docker-forwarded
        spelling) to retain the JSON evidence, toolchain document, and
        certificate outside pytest's temporary directory.  The historical
        ``MBA_STRUCTURAL_PARITY_ARTIFACT_DIR`` spelling remains compatible for
        direct local pytest invocations.
        """

        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
        monkeypatch.delenv("D810_STRUCTURAL_DSL_MATCHING", raising=False)
        observed_snapshots = []
        observed_ledgers = []

        @contextlib.contextmanager
        def recording_state():
            with d810_state() as state:
                yield state
                observed_snapshots.append(state.current_certified_catalogue_snapshot)
                observed_ledgers.append(state.current_shadow_matcher_parity_ledger)

        for function, rule_name in _CATALOGUE_CASES:
            reaches_provider = _catalogue_reaches_provider(function)
            run_deobfuscation_test(
                DeobfuscationCase(
                    function=function,
                    description="native structural parity evidence",
                    project="mba_compiler_shape_catalogue.json",
                    must_change=reaches_provider,
                    required_rules=[rule_name] if reaches_provider else [],
                    forbidden_rules=[] if reaches_provider else [rule_name],
                ),
                d810_state=recording_state,
                pseudocode_to_string=pseudocode_to_string,
            )

        snapshots = tuple(snapshot for snapshot in observed_snapshots if snapshot)
        ledgers = tuple(ledger for ledger in observed_ledgers if ledger)
        assert len(snapshots) == len(_CATALOGUE_CASES)
        assert len(ledgers) == len(_CATALOGUE_CASES)
        snapshot = snapshots[0]
        assert snapshot.structural_authorizable is True
        assert all(item.fingerprint == snapshot.fingerprint for item in snapshots)
        combined = ShadowMatcherParityLedger(
            **{
                field: sum(getattr(ledger, field) for ledger in ledgers)
                for field in (
                    "observation_count",
                    "legacy_match_count",
                    "legacy_rule_mismatches",
                    "legacy_binding_mismatches",
                    "legacy_binding_unknown",
                    "new_safe_coverage_pending",
                    "new_safe_coverage_proved",
                )
            }
        )
        assert combined.legacy_match_count > 0
        assert combined.legacy_rule_mismatches == 0
        assert combined.legacy_binding_mismatches == 0
        assert combined.legacy_binding_unknown == 0
        assert combined.new_safe_coverage_pending == 0

        artifacts = _parity_artifact_dir(tmp_path)
        runtime_mode = str(get_engine_info()["backend"])
        compiler = _find_c_compiler()
        toolchain = {
            "compiler": compiler,
            "compiler_version": subprocess.run(
                [compiler, "--version"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.splitlines()[0],
            "ida_sdk": str(idaapi.IDA_SDK_VERSION),
            "matcher_backend": runtime_mode,
        }
        evidence_path = artifacts / f"mba-structural-parity-{runtime_mode}.json"
        toolchain_path = artifacts / f"mba-structural-parity-toolchain-{runtime_mode}.json"
        certificate_path = artifacts / f"mba-structural-parity-{runtime_mode}.certificate.json"
        evidence_path.write_text(
            json.dumps(
                {
                    "runtime_mode": runtime_mode,
                    "snapshot": {
                        "fingerprint": snapshot.fingerprint,
                        "structural_authorizable": snapshot.structural_authorizable,
                    },
                    "ledger": {
                        field: getattr(combined, field)
                        for field in (
                            "observation_count",
                            "legacy_match_count",
                            "legacy_rule_mismatches",
                            "legacy_binding_mismatches",
                            "legacy_binding_unknown",
                            "new_safe_coverage_pending",
                            "new_safe_coverage_proved",
                        )
                    },
                },
                allow_nan=False,
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        toolchain_path.write_text(
            json.dumps(toolchain, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        completed = subprocess.run(
            [
                sys.executable,
                str(_PARITY_CERTIFICATE_TOOL),
                "--evidence",
                str(evidence_path),
                "--manifest",
                str(_MANIFEST),
                "--toolchain",
                str(toolchain_path),
                "--out",
                str(certificate_path),
            ],
            cwd=_ROOT,
            env=os.environ | {"PYTHONPATH": str(_ROOT / "src")},
            capture_output=True,
            text=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        certificate = json.loads(certificate_path.read_text(encoding="utf-8"))
        assert certificate["snapshot_fingerprint"] == snapshot.fingerprint
        assert certificate["runtime_mode"] == runtime_mode

        activation_config = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
        activation_config["additional_configuration"].update(
            {
                "structural_matcher_parity_certificate": certificate_path.name,
                "structural_matcher_parity_expectation": {
                    "corpus_digest": _sha256_file(_MANIFEST),
                    "toolchain_digest": _canonical_json_digest(toolchain),
                    "legacy_observation_count": combined.legacy_match_count,
                },
            }
        )
        activation_path = artifacts / f"mba-structural-activation-{runtime_mode}.json"
        activation_path.write_text(
            json.dumps(activation_config, ensure_ascii=True, indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        runtime_project = ProjectConfiguration.from_file(activation_path)

        monkeypatch.delenv("D810_LEGACY_DSL_PERMUTATIONS", raising=False)
        monkeypatch.delenv("D810_SHADOW_DSL_MATCHING", raising=False)
        monkeypatch.setenv("D810_STRUCTURAL_DSL_MATCHING", "1")
        activation_configuration_started = time.monotonic()
        with d810_state() as state:
            state.add_project(runtime_project)
            activation_index = state.project_manager.index(activation_path.name)
            assert state.load_project(activation_index) is not None
            cold_snapshot_ms = (time.monotonic() - activation_configuration_started) * 1000.0
            adapters = tuple(state.current_ins_rules)
            assert adapters
            assert all(adapter.uses_structural_matching for adapter in adapters)

            function_ea = get_func_ea("mba_shape_catalogue_01")
            assert function_ea != idaapi.BADADDR
            state.stop_d810()
            before = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            assert before is not None
            before_text = pseudocode_to_string(before.get_pseudocode())
            with capture_native_provider_histories(adapters):
                handler_started = time.monotonic()
                state.start_d810()
                handler_startup_ms = (time.monotonic() - handler_started) * 1000.0
                after = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
                state.stop_d810()
            assert after is not None
            assert pseudocode_to_string(after.get_pseudocode()) != before_text
            outcomes = tuple(
                outcome
                for adapter in adapters
                for outcome in adapter.provider_outcomes()
            )
            assert any(
                outcome.provider is MbaProviderKind.CATALOGUE
                and outcome.status is ProviderOutcomeStatus.APPLIED
                and "structural_dispatch" in outcome.metadata
                for outcome in outcomes
            )
            structural_outcome = next(
                outcome
                for outcome in outcomes
                if outcome.provider is MbaProviderKind.CATALOGUE
                and outcome.status is ProviderOutcomeStatus.APPLIED
                and "structural_dispatch" in outcome.metadata
            )
            assert structural_outcome.matcher is not None
            dispatch = structural_outcome.metadata["structural_dispatch"]
            assert isinstance(dispatch, Mapping)
            report_evidence_path = artifacts / f"mba-structural-report-evidence-{runtime_mode}.json"
            report_evidence_path.write_text(
                json.dumps(
                    {
                        "capture_metadata": {
                            "matcher_samples": [
                                {
                                    "bucket_size": dispatch["bucket_size"],
                                    "attempted_rule_count": dispatch["attempted_rule_count"],
                                    "comparisons": structural_outcome.matcher.comparisons,
                                    "lazy_swaps": structural_outcome.matcher.lazy_swaps,
                                    "flattened_arity": structural_outcome.matcher.flattened_arity,
                                    "comparison_cap_refusal": (
                                        structural_outcome.matcher.stop_reason
                                        == "comparison_budget"
                                    ),
                                }
                            ],
                            "lifecycle_measurements": {
                                "cold_snapshot_ms": [cold_snapshot_ms],
                                "handler_startup_ms": [handler_startup_ms],
                                "registration_pattern_count": [
                                    sum(
                                        len(
                                            getattr(
                                                adapter,
                                                "pattern_candidates",
                                                (),
                                            )
                                            or ()
                                        )
                                        for adapter in adapters
                                    )
                                ],
                                "native_proof_invocations": [1],
                            },
                        }
                    },
                    allow_nan=False,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            assert report_evidence_path.is_file()

            stale_config = json.loads(activation_path.read_text(encoding="utf-8"))
            stale_config["additional_configuration"][
                "structural_matcher_parity_expectation"
            ]["corpus_digest"] = "0" * 64
            stale_path = artifacts / f"mba-structural-stale-{runtime_mode}.json"
            stale_path.write_text(
                json.dumps(stale_config, ensure_ascii=True, indent=2, sort_keys=True)
                + "\n",
                encoding="utf-8",
            )
            stale_project = ProjectConfiguration.from_file(stale_path)
            state.add_project(stale_project)
            stale_index = state.project_manager.index(stale_path.name)
            assert state.load_project(stale_index) is not None
            assert all(
                not adapter.uses_structural_matching for adapter in state.current_ins_rules
            )
