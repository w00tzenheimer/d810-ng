"""Native producer receipt for MBA differential-report input."""

from __future__ import annotations

import contextlib
import json
import shutil
import subprocess
import sys
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
_PORTFOLIO_PROJECT = "mba_compiler_shape_catalogue.json"
_PROVIDER_MATRIX = tuple(MbaProviderKind)


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
