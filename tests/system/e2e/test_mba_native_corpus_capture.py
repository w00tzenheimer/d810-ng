"""Native producer receipt for MBA differential-report input."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest
import idaapi

from d810.mba.native_corpus_capture import (
    ManifestNativeCaptureCase,
    NativeCaptureSelection,
    NativeMbaCorpusCapture,
    capture_manifest_native_cases,
    capture_native_provider_histories,
    native_profile_from_outcome,
    select_native_capture_profile,
    snapshot_native_provider_histories,
)
from d810.mba.provider_outcome import MbaProviderKind, ProviderOutcomeStatus
from d810.backends.mba.egglog_add_rule_compiler import (
    _compile_selected_rule_catalogue,
)
from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    get_engine_info,
)


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_BINARY = _ROOT / "samples/bins/mba_compiler_shapes.dylib"
_CLI = _ROOT / "tools/scripts/mba_differential_report.py"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_PORTFOLIO_PROJECT = "mba_portfolio_spike.json"
_TELEMETRY_PROJECT = "mba_portfolio_telemetry_3ms.json"
_PROVIDER_MATRIX = tuple(MbaProviderKind)
_TASK13_CASE_IDS = (
    "canonical_xor_negative_coefficient_32",
    "equivalent_xor_replay_32",
    "fixed_rotate_complementary_32",
    "fixed_shift_noncomplementary_32",
    "fixed_shift_arithmetic_right_32",
    "fixed_shift_variable_count_32",
)


def _manifest_capture_case(case_id: str) -> ManifestNativeCaptureCase:
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    raw_case = next(item for item in data["cases"] if item["case_id"] == case_id)
    return ManifestNativeCaptureCase(raw_case["case_id"], raw_case["stratum"])


def _manifest_capture_cases() -> tuple[ManifestNativeCaptureCase, ...]:
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return tuple(
        ManifestNativeCaptureCase(raw_case["case_id"], raw_case["stratum"])
        for raw_case in data["cases"]
    )


def _manifest_function(case_id: str) -> str:
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    raw_case = next(item for item in data["cases"] if item["case_id"] == case_id)
    return str(raw_case["function"])


def _preferred_manifest_providers(case_id: str) -> tuple[MbaProviderKind, ...]:
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    raw_case = next(item for item in data["cases"] if item["case_id"] == case_id)
    return tuple(MbaProviderKind(provider) for provider in raw_case["expected_route"])


def _task13_manifest_cases() -> dict[str, dict[str, object]]:
    data = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return {
        raw_case["case_id"]: raw_case
        for raw_case in data["cases"]
        if raw_case["case_id"] in _TASK13_CASE_IDS
    }


def _assert_task13_capture_rows(
    captured: tuple,
    report_cases: tuple[dict[str, object], ...] | None = None,
) -> dict[str, dict[str, object]]:
    """Check exact Task 13 rows without converting elision into provider yield."""

    manifest_cases = _task13_manifest_cases()
    captured_by_id = {case.case_id: case for case in captured}
    assert tuple(captured_by_id) == _TASK13_CASE_IDS
    assert set(captured_by_id) == set(manifest_cases)
    assert all(
        len(case.outcomes) == len(_PROVIDER_MATRIX) for case in captured_by_id.values()
    )

    for case_id in _TASK13_CASE_IDS:
        manifest_case = manifest_cases[case_id]
        case = captured_by_id[case_id]
        assert case.stratum == manifest_case["stratum"]
        assert tuple(outcome.provider for outcome in case.outcomes) == tuple(
            sorted(_PROVIDER_MATRIX, key=lambda provider: provider.value)
        )
        assert sum(
            outcome.status is ProviderOutcomeStatus.APPLIED
            for outcome in case.outcomes
        ) <= 1
        if case.profile is None:
            reasons = {
                outcome.refusal_reason
                for outcome in case.outcomes
            }
            assert reasons <= {
                "native_candidate_not_observed",
                "native_candidate_ambiguous",
            }
            assert reasons
            for outcome in case.outcomes:
                assert outcome.status is ProviderOutcomeStatus.UNAVAILABLE
                assert outcome.metadata == {
                    "native_capture": outcome.refusal_reason
                }
                assert not outcome.source_provenance
        else:
            assert all(
                outcome.fingerprint == case.profile.fingerprint
                for outcome in case.outcomes
            )
            for outcome in case.outcomes:
                if outcome.status is not ProviderOutcomeStatus.APPLIED:
                    continue
                assert outcome.source_provenance
                if outcome.provider is MbaProviderKind.EGGLOG:
                    metadata = outcome.metadata or {}
                    assert metadata["execution_path"] in {
                        "direct_catalogue",
                        "fresh_saturation",
                        "learned_replay",
                        "telemetry_only",
                    }
                    assert metadata["selected_family"] is not None
                    assert metadata["selected_source"] == outcome.source_provenance[0]
                    assert metadata["degree"] >= manifest_case["expected_minimum_degree"]
                    if case_id == "fixed_rotate_complementary_32":
                        assert metadata["selected_family"] == "fixed_rotate"
                        assert metadata["selected_source"] == "rol_32_7"

    if report_cases is None:
        return manifest_cases
    report_by_id = {case["case_id"]: case for case in report_cases}
    assert set(report_by_id) == set(manifest_cases)
    for case_id in _TASK13_CASE_IDS:
        report_case = report_by_id[case_id]
        captured_case = captured_by_id[case_id]
        assert report_case["stratum"] == captured_case.stratum
        assert len(report_case["outcomes"]) == len(_PROVIDER_MATRIX)
        assert sum(
            outcome["status"] == ProviderOutcomeStatus.APPLIED.value
            for outcome in report_case["outcomes"]
        ) <= 1
        if captured_case.profile is None:
            assert report_case["profile"] is None
            for outcome in report_case["outcomes"]:
                assert outcome["status"] == ProviderOutcomeStatus.UNAVAILABLE.value
                assert outcome["metadata"] == {
                    "native_capture": outcome["refusal_reason"]
                }
        else:
            assert report_case["profile"]["fingerprint"] == (
                captured_case.profile.fingerprint
            )
    return manifest_cases


def _native_compiler_details() -> tuple[str, tuple[str, ...], str, str]:
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("native MBA corpus capture needs a C compiler")
    compiler_path = str(Path(shutil.which(compiler) or compiler).resolve())
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
    include_path = str(_ROOT / "samples/include")
    version = subprocess.run(
        [compiler_path, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0].strip()
    return compiler_path, tuple(flags), include_path, version


def _compiler_toolchain_identity() -> dict[str, str]:
    compiler_path, flags, include_path, version = _native_compiler_details()
    return {
        "compiler_executable": compiler_path,
        "compiler_version": version,
        "compiler_flags": " ".join((*flags, "-I", include_path)),
    }


def _build_native_corpus_binary(output_path: Path) -> dict[str, str]:
    compiler_path, flags, include_path, _version = _native_compiler_details()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [compiler_path, *flags, "-I", include_path, "-o", str(output_path), str(_SOURCE)],
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        "compiler_executable": compiler_path,
        "compiler_version": _version,
        "compiler_flags": " ".join((*flags, "-I", include_path)),
    }


@pytest.mark.usefixtures("configure_hexrays")
class TestNativeMbaCorpusCapture:
    binary_name = "mba_compiler_shapes.dylib"
    generated_binary_factory = staticmethod(_build_native_corpus_binary)

    def test_generated_native_input_does_not_pollute_source_tree(
        self,
        ida_database,
    ) -> None:
        assert not _BINARY.exists()

    @classmethod
    def setup_class(cls) -> None:
        cls._compiler_toolchain_identity = _compiler_toolchain_identity()

    def test_elided_native_root_emits_complete_unavailable_provider_matrix(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        """No native candidate is explicit coverage, never a guessed island."""

        manifest_case = _manifest_capture_case("chain_01")
        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={"provider": "portfolio"},
        )
        with d810_state() as state:
            state.load_project(state.project_manager.index(_PORTFOLIO_PROJECT))
            selected_rules = tuple(state.current_ins_rules)

            @contextlib.contextmanager
            def selected_state():
                yield state

            def run_case(case, snapshot):
                run_deobfuscation_test(
                    DeobfuscationCase(
                        function="mba_shape_chain_01",
                        project="",
                        description="native no-candidate coverage",
                        # The selected-state context already owns this exact
                        # project and its capture-scoped adapters.  Supplying
                        # project here would rebuild them and orphan the
                        # history cursor captured above.
                        must_change=False,
                    ),
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )
                try:
                    return select_native_capture_profile(
                        selected_rules,
                        history_snapshot=snapshot,
                        preferred_providers=_preferred_manifest_providers(case.case_id),
                    )
                except ValueError as exc:
                    if str(exc) == "ambiguous native capture profile: none":
                        return None
                    if str(exc).startswith("ambiguous native capture profile:"):
                        return NativeCaptureSelection(
                            profile=None,
                            unavailable_reason="native_candidate_ambiguous",
                        )
                    raise

            captured = capture_manifest_native_cases(
                capture=capture,
                cases=(manifest_case,),
                rules=selected_rules,
                expected_providers=_PROVIDER_MATRIX,
                run_case=run_case,
            )

        assert captured[0].profile is None
        assert len(captured[0].outcomes) == len(_PROVIDER_MATRIX)
        assert all(
            outcome.status is ProviderOutcomeStatus.UNAVAILABLE
            and outcome.refusal_reason == "native_candidate_not_observed"
            for outcome in captured[0].outcomes
        )

    def _capture_manifest_wide_native_provider_matrix(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
        *,
        project_name: str = _PORTFOLIO_PROJECT,
        egglog_mode: str = "interactive",
    ) -> None:
        """Capture every manifest function through the real provider histories."""

        manifest_cases = _manifest_capture_cases()
        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={
                **self._compiler_toolchain_identity,
                "ida_sdk": str(idaapi.IDA_SDK_VERSION),
                "matcher_backend": str(get_engine_info()["backend"]),
                "profile": f"portfolio-{egglog_mode}",
            },
        )
        with d810_state() as state:
            catalogue_cache_before = _compile_selected_rule_catalogue.cache_info()
            configured_started = time.monotonic()
            state.load_project(state.project_manager.index(project_name))
            configuration_elapsed_ms = (time.monotonic() - configured_started) * 1000.0
            catalogue_cache_after = _compile_selected_rule_catalogue.cache_info()
            selected_rules = tuple(state.current_ins_rules)
            registration_pattern_count = sum(
                len(getattr(rule, "pattern_candidates", ()) or ())
                for rule in selected_rules
            )
            whole_function_elapsed_ms: dict[str, float] = {}

            @contextlib.contextmanager
            def selected_state():
                yield state

            def run_case(case, snapshot):
                started = time.monotonic()
                run_deobfuscation_test(
                    DeobfuscationCase(
                        function=_manifest_function(case.case_id),
                        description="manifest native provider capture",
                        # Keep the preloaded project's live provider objects;
                        # see the stale-adapter contract above.
                        project="",
                        must_change=False,
                    ),
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )
                whole_function_elapsed_ms[case.case_id] = (
                    time.monotonic() - started
                ) * 1000.0
                try:
                    return select_native_capture_profile(
                        selected_rules,
                        history_snapshot=snapshot,
                        preferred_providers=_preferred_manifest_providers(case.case_id),
                    )
                except ValueError as exc:
                    if str(exc) == "ambiguous native capture profile: none":
                        return None
                    if str(exc).startswith("ambiguous native capture profile:"):
                        return NativeCaptureSelection(
                            profile=None,
                            unavailable_reason="native_candidate_ambiguous",
                        )
                    raise

            captured = capture_manifest_native_cases(
                capture=capture,
                cases=manifest_cases,
                rules=selected_rules,
                expected_providers=_PROVIDER_MATRIX,
                run_case=run_case,
            )

        task13_captured = tuple(
            case for case in captured if case.case_id in _TASK13_CASE_IDS
        )
        task13_manifest_cases = _assert_task13_capture_rows(task13_captured)
        task13_native_case_evidence: dict[str, dict[str, object]] = {}
        for case_id in _TASK13_CASE_IDS:
            case = next(item for item in task13_captured if item.case_id == case_id)
            if case.profile is None:
                evidence: dict[str, object] = {
                    "capture_status": "unavailable",
                    "unavailable_reasons": sorted(
                        {
                            str(outcome.refusal_reason)
                            for outcome in case.outcomes
                        }
                    ),
                }
            else:
                evidence = {
                    "capture_status": "observed",
                    "profile_fingerprint": case.profile.fingerprint,
                    "applied_providers": [
                        outcome.provider.value
                        for outcome in case.outcomes
                        if outcome.status is ProviderOutcomeStatus.APPLIED
                    ],
                }
            expected_blocker = task13_manifest_cases[case_id].get("expected_blocker")
            if expected_blocker is not None:
                evidence["expected_blocker"] = expected_blocker
            task13_native_case_evidence[case_id] = evidence

        capture.set_capture_metadata(
            {
                "provider_execution_modes": {
                    MbaProviderKind.STRUCTURAL_CHAIN.value: "interactive",
                    MbaProviderKind.CATALOGUE.value: "interactive",
                    MbaProviderKind.EGGLOG.value: egglog_mode,
                    MbaProviderKind.COEFFICIENT_SOLVER.value: "extension_unavailable",
                },
                "whole_function_elapsed_ms_by_case": whole_function_elapsed_ms,
                "lifecycle_measurements": {
                    "project_configuration_ms": [configuration_elapsed_ms],
                    "cold_snapshot_ms": [configuration_elapsed_ms],
                    "registration_pattern_count": registration_pattern_count,
                    "catalogue_compiler_invocations": [
                        catalogue_cache_after.misses - catalogue_cache_before.misses
                    ],
                    "catalogue_cache_hits": [
                        catalogue_cache_after.hits - catalogue_cache_before.hits
                    ],
                },
                "task13_native_case_evidence": task13_native_case_evidence,
            }
        )

        expected_case_ids = {case.case_id for case in manifest_cases}
        assert len(captured) == len(expected_case_ids)
        assert {case.case_id for case in captured} == expected_case_ids
        assert all(len(case.outcomes) == len(_PROVIDER_MATRIX) for case in captured)
        # Refusal rows are safety evidence, not provider yield.  If the
        # compiler/IDA preserves one of these roots, every provider must still
        # abstain; if it elides the root, capture_native_provider_case has
        # already emitted the complete explicit unavailable matrix.
        refusal_case_ids = {
            case.case_id
            for case in manifest_cases
            if case.case_id
            in {
                "fixed_shift_noncomplementary_32",
                "fixed_shift_arithmetic_right_32",
                "fixed_shift_variable_count_32",
            }
        }
        for case in captured:
            if case.case_id in refusal_case_ids:
                assert not any(
                    outcome.status is ProviderOutcomeStatus.APPLIED
                    for outcome in case.outcomes
                )

        configured_artifacts = os.environ.get(
            "D810_MBA_NATIVE_CAPTURE_ARTIFACT_DIR"
        ) or os.environ.get("MBA_NATIVE_CAPTURE_ARTIFACT_DIR")
        artifacts = Path(configured_artifacts) if configured_artifacts else tmp_path
        artifacts.mkdir(parents=True, exist_ok=True)
        runtime_mode = str(get_engine_info()["backend"])
        capture_path = artifacts / f"mba-native-capture-{egglog_mode}-{runtime_mode}.json"
        report_path = artifacts / f"mba-native-report-{egglog_mode}-{runtime_mode}.json"
        capture.write_json(capture_path)
        telemetry_sidecar_path = (
            artifacts / f"mba-native-telemetry-sidecar-{egglog_mode}-{runtime_mode}.json"
        )
        telemetry_sidecar_path.write_text(
            json.dumps(
                {
                    "capture_metadata": {
                        "latency_lanes": [
                            {
                                "population": "candidate",
                                "mode": egglog_mode,
                                "provider": MbaProviderKind.EGGLOG.value,
                            }
                        ],
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
        assert telemetry_sidecar_path.is_file()
        completed = subprocess.run(
            [
                sys.executable,
                str(_CLI),
                "--out",
                str(report_path),
                "--manifest",
                str(_MANIFEST),
                "--providers",
                ",".join(provider.value for provider in _PROVIDER_MATRIX),
                "--rollout-evidence",
                str(telemetry_sidecar_path),
                str(capture_path),
            ],
            cwd=_ROOT,
            env={"PYTHONPATH": str(_ROOT / "src")},
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        report = json.loads(report_path.read_text(encoding="utf-8"))
        toolchain = report["toolchain_identity"]
        assert toolchain["compiler_executable"] == self._compiler_toolchain_identity[
            "compiler_executable"
        ]
        assert toolchain["compiler_version"] == self._compiler_toolchain_identity[
            "compiler_version"
        ]
        assert toolchain["compiler_flags"] == self._compiler_toolchain_identity[
            "compiler_flags"
        ]
        assert toolchain["ida_sdk"] == str(idaapi.IDA_SDK_VERSION)
        assert toolchain["matcher_backend"] == runtime_mode
        assert toolchain["profile"] == f"portfolio-{egglog_mode}"
        assert toolchain["reporter"] == "mba_differential_report"
        assert len(report["cases"]) == len(expected_case_ids)
        assert all(len(case["outcomes"]) == len(_PROVIDER_MATRIX) for case in report["cases"])
        capture_metadata = capture.report().to_dict()["capture_metadata"]
        for key, value in capture_metadata.items():
            assert report["capture_metadata"][key] == value
        assert report["capture_metadata"]["latency_lanes"] == [
            {
                "population": "candidate",
                "mode": egglog_mode,
                "provider": MbaProviderKind.EGGLOG.value,
            },
        ]
        _assert_task13_capture_rows(
            task13_captured,
            tuple(case for case in report["cases"] if case["case_id"] in _TASK13_CASE_IDS),
        )
        assert report["capture_metadata"]["task13_native_case_evidence"] == (
            task13_native_case_evidence
        )
        evidence = report["summary"]["rollout_evidence"]
        assert egglog_mode in evidence["whole_function_latency_by_mode"], evidence
        whole_function_lane = evidence["whole_function_latency_by_mode"][egglog_mode][
            MbaProviderKind.EGGLOG.value
        ]
        assert whole_function_lane["count"] == len(whole_function_elapsed_ms)
        assert whole_function_lane["p50_ms"] is not None
        assert whole_function_lane["p95_ms"] is not None
        assert whole_function_lane["p95_ms"] <= max(whole_function_elapsed_ms.values())
        assert evidence["lifecycle_measurements"]["project_configuration_ms"]["count"] == 1
        if egglog_mode == "interactive":
            assert "interactive" in evidence["candidate_latency_by_mode"], evidence
        else:
            zero_sample_lane = evidence["candidate_latency_by_mode"][egglog_mode][
                MbaProviderKind.EGGLOG.value
            ]
            assert zero_sample_lane == {
                "count": 0,
                "p50_ms": None,
                "p95_ms": None,
            }
            egglog_rows = tuple(
                outcome
                for case in report["cases"]
                for outcome in case["outcomes"]
                if outcome["provider"] == MbaProviderKind.EGGLOG.value
            )
            assert all(row["status"] != ProviderOutcomeStatus.APPLIED.value for row in egglog_rows)

    def test_real_provider_histories_produce_cli_input(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """Capture an actual accepted catalogue mutation; no synthetic rows."""

        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        native_case = DeobfuscationCase(
            function="mba_shape_catalogue_01",
            description="native provider history capture",
            # The surrounding selected-state context already owns the exact
            # catalogue project and the history-bearing rule instances.
            project="",
            must_change=True,
        )
        with d810_state() as state:
            state.load_project(
                state.project_manager.index("mba_compiler_shape_catalogue.json")
            )
            captured_rules = tuple(state.current_ins_rules)

            @contextlib.contextmanager
            def selected_state():
                yield state

            with capture_native_provider_histories(captured_rules):
                run_deobfuscation_test(
                    native_case,
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )

            applied = tuple(
                outcome
                for rule in captured_rules
                for outcome in rule.provider_outcomes()
                if outcome.provider is MbaProviderKind.CATALOGUE
                and outcome.status is ProviderOutcomeStatus.APPLIED
            )
        assert applied, "native corpus did not record an accepted catalogue outcome"
        profile = native_profile_from_outcome(applied[-1])
        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={
                "ida_sdk": str(idaapi.IDA_SDK_VERSION),
                "matcher_backend": str(get_engine_info()["backend"]),
                "provider": "catalogue",
            },
        )
        case = capture.add_case(
            case_id="catalogue_01",
            stratum="catalogue",
            profile=profile,
            rules=captured_rules,
        )
        assert [outcome.provider for outcome in case.outcomes] == [
            MbaProviderKind.CATALOGUE
        ]
        assert case.outcomes[0].status is ProviderOutcomeStatus.APPLIED

        capture_path = tmp_path / "native-capture.json"
        report_path = tmp_path / "report.json"
        capture.write_json(capture_path)
        completed = subprocess.run(
            [
                sys.executable,
                str(_CLI),
                "--out",
                str(report_path),
                "--providers",
                "catalogue",
                str(capture_path),
            ],
            cwd=_ROOT,
            env={"PYTHONPATH": str(_ROOT / "src")},
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        assert report_path.exists()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert [case["case_id"] for case in report["cases"]] == ["catalogue_01"]
        captured_case = report["cases"][0]
        assert captured_case["profile"]["fingerprint"] == profile.fingerprint
        assert len(captured_case["outcomes"]) == 1
        captured_outcome = captured_case["outcomes"][0]
        assert captured_outcome["provider"] == MbaProviderKind.CATALOGUE.value
        assert captured_outcome["status"] == ProviderOutcomeStatus.APPLIED.value
        assert captured_outcome == case.outcomes[0].to_dict()

    def test_history_snapshot_retains_real_post_snapshot_outcome(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """A snapshot-backed capture keeps the actual later applied outcome."""

        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        native_case = DeobfuscationCase(
            function="mba_shape_catalogue_01",
            description="capture a real post-snapshot catalogue outcome",
            project="",
            must_change=True,
        )

        with d810_state() as state:
            state.load_project(
                state.project_manager.index("mba_compiler_shape_catalogue.json")
            )
            selected_rules = tuple(state.current_ins_rules)

            @contextlib.contextmanager
            def selected_state():
                yield state

            with capture_native_provider_histories(selected_rules):
                history_snapshot = snapshot_native_provider_histories(selected_rules)
                run_deobfuscation_test(
                    native_case,
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )
                post_snapshot_applied = tuple(
                    outcome
                    for rule in selected_rules
                    for outcome in rule.provider_outcomes_since(
                        history_snapshot.outcome_counts_by_rule_id[id(rule)]
                    )
                    if outcome.provider is MbaProviderKind.CATALOGUE
                    and outcome.status is ProviderOutcomeStatus.APPLIED
                )
            assert post_snapshot_applied, "native snapshot delta has no applied outcome"
            profile = native_profile_from_outcome(post_snapshot_applied[-1])

        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={"provider": "catalogue"},
        )
        case = capture.add_case(
            case_id="catalogue-post-snapshot",
            stratum="catalogue",
            profile=profile,
            rules=selected_rules,
            history_snapshot=history_snapshot,
        )
        assert case.outcomes == (post_snapshot_applied[-1],)

        capture_path = tmp_path / "snapshot-capture.json"
        report_path = tmp_path / "snapshot-report.json"
        capture.write_json(capture_path)
        completed = subprocess.run(
            [
                sys.executable,
                str(_CLI),
                "--out",
                str(report_path),
                "--providers",
                "catalogue",
                str(capture_path),
            ],
            cwd=_ROOT,
            env={"PYTHONPATH": str(_ROOT / "src")},
            text=True,
            capture_output=True,
            check=False,
        )
        assert completed.returncode == 0, completed.stderr
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert [item["case_id"] for item in report["cases"]] == [
            "catalogue-post-snapshot"
        ]
        report_case = report["cases"][0]
        assert report_case["profile"]["fingerprint"] == profile.fingerprint
        assert report_case["outcomes"] == [post_snapshot_applied[-1].to_dict()]

    def test_history_snapshot_excludes_prior_real_profile(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """A later decompilation cannot recapture an earlier profile's outcome."""

        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        first_case = DeobfuscationCase(
            function="mba_shape_catalogue_01",
            description="seed a real catalogue history outcome",
            project="",
            must_change=True,
        )
        second_case = DeobfuscationCase(
            function="mba_shape_chain_01",
            description="produce a distinct real native profile",
            project="",
            must_change=False,
        )

        with d810_state() as state:
            state.load_project(
                state.project_manager.index("mba_compiler_shape_catalogue.json")
            )
            selected_rules = tuple(state.current_ins_rules)

            @contextlib.contextmanager
            def selected_state():
                yield state

            with capture_native_provider_histories(selected_rules):
                run_deobfuscation_test(
                    first_case,
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )
                prior_applied = tuple(
                    outcome
                    for rule in selected_rules
                    for outcome in rule.provider_outcomes()
                    if outcome.provider is MbaProviderKind.CATALOGUE
                    and outcome.status is ProviderOutcomeStatus.APPLIED
                )
                assert prior_applied, "first native run did not retain an applied outcome"
                first_profile = native_profile_from_outcome(prior_applied[-1])

                history_snapshot = snapshot_native_provider_histories(selected_rules)
                run_deobfuscation_test(
                    second_case,
                    d810_state=selected_state,
                    pseudocode_to_string=pseudocode_to_string,
                )

        capture = NativeMbaCorpusCapture(
            corpus_identity="mba-compiler-shapes-native",
            toolchain_identity={"provider": "catalogue"},
        )
        without_snapshot = capture.add_case(
            case_id="prior-profile-without-snapshot",
            stratum="catalogue",
            profile=first_profile,
            rules=selected_rules,
        )
        assert without_snapshot.outcomes == (prior_applied[-1],)

        with_snapshot = capture.add_case(
            case_id="prior-profile-with-snapshot",
            stratum="catalogue",
            profile=first_profile,
            rules=selected_rules,
            history_snapshot=history_snapshot,
        )
        assert with_snapshot.outcomes == ()

    def test_manifest_wide_native_capture_has_one_explicit_row_per_provider_case(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        """Run the mutating manifest-wide corpus capture after pristine-state tests.

        The IDA fixture retains decompiler state for this class.  This must run
        after the single-function history-delta witnesses so their baseline is
        a pristine native lowering, not a prior portfolio mutation.
        """

        self._capture_manifest_wide_native_provider_matrix(
            tmp_path,
            ida_database,
            d810_state,
            pseudocode_to_string,
        )

    def test_manifest_wide_native_capture_records_default_3ms_telemetry_separately(
        self,
        tmp_path: Path,
        ida_database,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        """The default 3 ms lane reports telemetry and never credits Egglog wins."""

        self._capture_manifest_wide_native_provider_matrix(
            tmp_path,
            ida_database,
            d810_state,
            pseudocode_to_string,
            project_name=_TELEMETRY_PROJECT,
            egglog_mode="telemetry_3ms",
        )
