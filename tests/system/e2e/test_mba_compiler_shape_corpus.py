"""Semantic receipt for the independently-authored compiler-shaped MBA corpus.

This is deliberately a pre-provider gate.  It proves every emitted shape against
its simple sibling before later portfolio tasks attribute a result to catalogue,
the e-graph provider, or coefficient routing.
"""

from __future__ import annotations

import ctypes
import cProfile
import contextlib
import gc
import hashlib
import io
import json
import os
import pstats
import random
import shutil
import statistics
import subprocess
import sys
import time
import tracemalloc
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import idapro
import idaapi
import pytest

from d810.core.config import ProjectConfiguration
from d810.backends.mba import ida as ida_backend
from d810.mba.certified_catalogue import (
    make_structural_matcher_parity_certificate,
    ShadowMatcherParityLedger,
    StructuralMatcherParityExpectation,
    load_structural_matcher_parity_certificate,
)
from d810.mba.native_corpus_capture import (
    ManifestNativeCaptureCase,
    NativeCaptureSelection,
    NativeMbaCorpusCapture,
    NativeProviderHistorySnapshot,
    capture_manifest_native_cases,
    native_profile_from_outcome,
    select_native_capture_profile,
)
from d810.mba.provider_outcome import (
    MatcherSelection,
    MbaProviderKind,
    ProviderOutcomeStatus,
)
from d810.mba.native_corpus_capture import (
    capture_native_provider_histories,
    observe_native_provider_histories,
    native_provider_outcomes,
)
from d810.optimizers.microcode.instructions.pattern_matching.engine import (
    get_engine_info,
)
from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import get_func_ea, run_deobfuscation_test


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_CATALOGUE_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_catalogue.json"
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
# One receipt row is pinned to the intended catalogue rule for each native
# function.  The rows are deliberately independent of the other rule attempts
# emitted by the live handler, so Python and Cython runs exercise this same
# contract table rather than accepting an arbitrary non-empty receipt.
_CATALOGUE_RECEIPT_CONTRACT = {
    "mba_shape_catalogue_01": (
        "Add_HackersDelightRule_2",
        MatcherSelection.CANONICAL_FALLBACK,
        "matched",
        True,
        ProviderOutcomeStatus.APPLIED,
    ),
    "mba_shape_catalogue_02": (
        "Add_HackersDelightRule_3",
        MatcherSelection.NONE,
        "miss",
        None,
        ProviderOutcomeStatus.UNCHANGED,
    ),
    "mba_shape_catalogue_03": (
        "Xor_HackersDelightRule_3",
        MatcherSelection.RAW,
        "matched",
        None,
        ProviderOutcomeStatus.APPLIED,
    ),
    "mba_shape_catalogue_05": (
        "Or_MbaRule_1",
        MatcherSelection.NONE,
        "not_observed",
        None,
        None,
    ),
    "mba_shape_catalogue_06": (
        "And_HackersDelightRule_4",
        MatcherSelection.NONE,
        "not_observed",
        None,
        None,
    ),
    "mba_shape_catalogue_07": (
        "Add_HackersDelightRule_2",
        MatcherSelection.CANONICAL_FALLBACK,
        "matched",
        True,
        ProviderOutcomeStatus.APPLIED,
    ),
    "mba_shape_catalogue_08": (
        "Add_HackersDelightRule_4",
        MatcherSelection.RAW,
        "matched",
        None,
        ProviderOutcomeStatus.APPLIED,
    ),
    "mba_shape_catalogue_09": (
        "Or_HackersDelightRule_2",
        MatcherSelection.NONE,
        "not_observed",
        None,
        None,
    ),
    "mba_shape_catalogue_10": (
        "Xor_HackersDelightRule_1",
        MatcherSelection.NONE,
        "not_observed",
        None,
        None,
    ),
}

_CATALOGUE_ROW04_ALLOWED_RECEIPTS = frozenset(
    {
        (
            MatcherSelection.NONE,
            "miss",
            None,
            ProviderOutcomeStatus.UNCHANGED,
            None,
        ),
        (
            MatcherSelection.NONE,
            "clean_miss",
            None,
            ProviderOutcomeStatus.UNCHANGED,
            None,
        ),
        (
            MatcherSelection.CANONICAL_FALLBACK,
            "matched",
            False,
            ProviderOutcomeStatus.UNCHANGED,
            None,
        ),
        (
            MatcherSelection.CANONICAL_FALLBACK,
            "matched",
            True,
            ProviderOutcomeStatus.APPLIED,
            "accepted",
        ),
    }
)


def _assert_row04_invariant_contract(
    function: str, expected_rule: str, outcomes: tuple[object, ...]
) -> None:
    """Accept only the backend-observed closed receipt set for subtraction."""

    assert outcomes, f"{function} must record at least one provider receipt"
    target_outcomes = tuple(
        outcome for outcome in outcomes if outcome.metadata.get("rule_name") == expected_rule
    )
    assert target_outcomes, f"{function} did not record its contract rule {expected_rule}"
    for outcome in target_outcomes:
        matcher = outcome.matcher
        assert matcher is not None
        receipt = (
            matcher.selection,
            matcher.terminal_stop_reason,
            matcher.native_equivalence_verdict,
            outcome.status,
            matcher.mutation_outcome,
        )
        assert receipt in _CATALOGUE_ROW04_ALLOWED_RECEIPTS, (
            f"{function} receipt outside closed allowed set: {outcome!r}"
        )
        assert outcome.source_provenance, f"{function} receipt lacks source provenance"
        if outcome.status is ProviderOutcomeStatus.APPLIED:
            assert matcher.selection is MatcherSelection.CANONICAL_FALLBACK
            assert matcher.terminal_stop_reason == "matched"
            assert matcher.native_equivalence_verdict is True
            assert matcher.mutation_outcome == "accepted"
            assert outcome.metadata.get("mutation_outcome") == "accepted"
        else:
            assert outcome.metadata.get("mutation_outcome") != "accepted"


def _assert_adapter_callback_context_cleared(adapter) -> None:
    """Require all borrowed adapter and rule callback state to be released."""

    for field in (
        "_attempt_input_ast",
        "_attempt_instruction",
        "_shadow_lowering",
        "_shadow_structural_lowering",
        "_shadow_source_ast",
        "_shadow_match_report",
        "_shadow_structural_native_paths",
        "_legacy_binding_paths",
        "_shadow_native_equivalence_verdict",
    ):
        assert getattr(adapter, field, None) is None
    assert getattr(adapter, "_shadow_native_path_unavailable", False) is False
    assert getattr(adapter, "_structural_selection_active", False) is False
    rule = adapter.rule
    assert getattr(rule, "_current_blk", None) is None
    assert getattr(rule, "_current_ins", None) is None
    assert getattr(rule, "_runtime_constant_evaluator", None) is None




def _assert_exact_catalogue_contract(function: str, outcomes: tuple[object, ...]) -> None:
    expected_rule = next(
        rule_name for case_name, rule_name in _CATALOGUE_CASES if case_name == function
    )
    if function == "mba_shape_catalogue_04":
        _assert_row04_invariant_contract(function, expected_rule, outcomes)
        return
    configured = _CATALOGUE_RECEIPT_CONTRACT[function]
    if not outcomes:
        assert not _catalogue_reaches_provider(function)
        assert configured == (
            expected_rule,
            MatcherSelection.NONE,
            "not_observed",
            None,
            None,
        )
        return
    target_outcomes = tuple(
        outcome for outcome in outcomes if outcome.metadata.get("rule_name") == expected_rule
    )
    if not target_outcomes and configured[2] == "not_observed":
        # A canonicalized compiler root may still produce terminal receipts
        # for other catalogue candidates.  The not-observed contract applies
        # to its pinned rule, not to the entire provider receipt stream.
        assert not _catalogue_reaches_provider(function)
        return
    assert target_outcomes, f"{function} did not record its contract rule {expected_rule}"
    expected_selection, expected_stop, expected_proof, expected_status = configured[1:]
    secondary_receipts = frozenset(
        {
            (
                MatcherSelection.NONE,
                "miss",
                None,
                ProviderOutcomeStatus.UNCHANGED,
                None,
            ),
            (
                MatcherSelection.NONE,
                "clean_miss",
                None,
                ProviderOutcomeStatus.UNCHANGED,
                None,
            ),
            (
                MatcherSelection.CANONICAL_FALLBACK,
                "fallback_unavailable",
                None,
                ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                None,
            ),
            (
                MatcherSelection.CANONICAL_FALLBACK,
                "reconstruction_failed",
                None,
                ProviderOutcomeStatus.RECONSTRUCTION_FAILED,
                None,
            ),
        }
    )
    decisive = tuple(
        outcome.matcher is not None
        and outcome.matcher.selection == expected_selection
        and outcome.matcher.terminal_stop_reason == expected_stop
        and outcome.matcher.native_equivalence_verdict == expected_proof
        and outcome.status == expected_status
        for outcome in target_outcomes
    )
    if expected_status is ProviderOutcomeStatus.APPLIED:
        assert sum(decisive) == 1, f"{function} receipt contract mismatch: {target_outcomes!r}"
        decisive_outcome = target_outcomes[decisive.index(True)]
        assert decisive_outcome.matcher is not None
        assert decisive_outcome.matcher.mutation_outcome == "accepted"
        assert decisive_outcome.metadata.get("mutation_outcome") == "accepted"
        assert all(
            (
                outcome.matcher.selection,
                outcome.matcher.terminal_stop_reason,
                outcome.matcher.native_equivalence_verdict,
                outcome.status,
                outcome.matcher.mutation_outcome,
            )
            in secondary_receipts
            for outcome, matches in zip(target_outcomes, decisive, strict=True)
            if not matches
        ), f"{function} incoherent extra receipts: {target_outcomes!r}"
    else:
        assert target_outcomes and all(decisive), (
            f"{function} receipt contract mismatch: {target_outcomes!r}"
        )
_PORTFOLIO_PROJECT = "mba_compiler_shape_catalogue.json"
_EXPECTED_NATIVE_PROVIDERS = tuple(MbaProviderKind)

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

_DOMAIN_LIFTED_CASE_IDS = frozenset(
    {
        "canonical_xor_negative_coefficient_32",
        "equivalent_xor_replay_32",
        "fixed_rotate_complementary_32",
        "fixed_shift_noncomplementary_32",
        "fixed_shift_arithmetic_right_32",
        "fixed_shift_variable_count_32",
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


def _p95_seconds(values: list[float]) -> float:
    return statistics.quantiles(values, n=20, method="inclusive")[18]


def _parity_artifact_dir(tmp_path: Path) -> Path:
    """Use an explicit output directory when an operator wants persisted evidence."""

    configured = os.environ.get(
        "D810_MBA_STRUCTURAL_PARITY_ARTIFACT_DIR"
    ) or os.environ.get("MBA_STRUCTURAL_PARITY_ARTIFACT_DIR")
    destination = tmp_path if not configured else Path(configured)
    destination.mkdir(parents=True, exist_ok=True)
    return destination


def _manifest_capture_cases() -> tuple[ManifestNativeCaptureCase, ...]:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return tuple(
        ManifestNativeCaptureCase(case["case_id"], case["stratum"])
        for case in manifest["cases"]
    )


def _manifest_function(case_id: str) -> str:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    return next(case["function"] for case in manifest["cases"] if case["case_id"] == case_id)


def _preferred_manifest_providers(case_id: str) -> tuple[MbaProviderKind, ...]:
    manifest = json.loads(_MANIFEST.read_text(encoding="utf-8"))
    case = next(case for case in manifest["cases"] if case["case_id"] == case_id)
    return tuple(MbaProviderKind(provider) for provider in case["expected_route"])


def _task13_capture_toolchain_identity(runtime_mode: str) -> dict[str, str]:
    compiler = _find_c_compiler()
    compiler_version = subprocess.run(
        [compiler, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()[0]
    return {
        "compiler_executable": compiler,
        "compiler_version": compiler_version,
        "compiler_flags": " ".join(
            (*_compiler_shape_build_flags(compiler), "-I", str(_ROOT / "samples/include"))
        ),
        "ida_sdk": str(idaapi.IDA_SDK_VERSION),
        "matcher_backend": runtime_mode,
        "profile": "portfolio-interactive",
    }


def build_real_shadow_activation(
    *,
    snapshot,
    ledger: ShadowMatcherParityLedger,
    runtime_mode: str,
    output_path: Path,
) -> tuple[Path, StructuralMatcherParityExpectation]:
    """Build activation evidence from an observed native shadow run.

    This is shared by the corpus gate and the bounded callback benchmark.  The
    caller must provide the snapshot and ledger produced by a real
    ``run_deobfuscation_test``; this helper does not synthesize observations or
    accept caller-provided digests/counts.
    """

    corpus_digest = _sha256_file(_MANIFEST)
    toolchain_digest = _canonical_json_digest(
        _task13_capture_toolchain_identity(runtime_mode)
    )
    certificate = make_structural_matcher_parity_certificate(
        snapshot=snapshot,
        ledger=ledger,
        runtime_mode=runtime_mode,
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(certificate, allow_nan=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    expectation = StructuralMatcherParityExpectation(
        corpus_digest=corpus_digest,
        toolchain_digest=toolchain_digest,
        runtime_semantics_digest=snapshot.runtime_semantics_digest,
        legacy_observation_count=ledger.legacy_match_count,
        observation_count=ledger.observation_count,
    )
    activation = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
    activation.setdefault("additional_configuration", {}).update(
        {
            "structural_matcher_parity_certificate": output_path.name,
            "structural_matcher_parity_expectation": {
                "corpus_digest": expectation.corpus_digest,
                "toolchain_digest": expectation.toolchain_digest,
                "runtime_semantics_digest": expectation.runtime_semantics_digest,
                "legacy_observation_count": expectation.legacy_observation_count,
                "observation_count": expectation.observation_count,
            },
        }
    )
    activation_path = output_path.with_name(
        output_path.stem.replace(".certificate", "") + ".activation.json"
    )
    activation_path.write_text(
        json.dumps(activation, allow_nan=False, ensure_ascii=True, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    return activation_path, expectation


def _persist_task13_native_capture(
    capture_path: Path,
    *,
    d810_state,
    pseudocode_to_string,
    shadow_evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    """Persist the real Task 13 NativeMbaCorpusCapture wire shape."""

    runtime_mode = str(get_engine_info()["backend"])
    capture = NativeMbaCorpusCapture(
        corpus_identity="mba-compiler-shapes-native",
        toolchain_identity=_task13_capture_toolchain_identity(runtime_mode),
    )
    manifest_cases = _manifest_capture_cases()
    whole_function_elapsed_ms: dict[str, float] = {}
    with d810_state() as state:
        assert state.load_project(state.project_manager.index(_PORTFOLIO_PROJECT)) is not None
        selected_rules = tuple(state.current_ins_rules)

        @contextlib.contextmanager
        def selected_state():
            yield state

        def run_case(case: ManifestNativeCaptureCase, snapshot):
            started = time.monotonic()
            run_deobfuscation_test(
                DeobfuscationCase(
                    function=_manifest_function(case.case_id),
                    description="Task 13 native provider capture",
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
            expected_providers=_EXPECTED_NATIVE_PROVIDERS,
            run_case=run_case,
        )
        if shadow_evidence is not None:
            # The state owns one cumulative ledger for the complete capture.
            # Record it once; retaining the same mutable object per case would
            # make a later consumer multiply the final totals.
            shadow_evidence["snapshot"] = state.current_certified_catalogue_snapshot
            shadow_evidence["ledger"] = state.current_shadow_matcher_parity_ledger

    expected_case_ids = {case.case_id for case in manifest_cases}
    assert len(captured) == len(expected_case_ids)
    assert {case.case_id for case in captured} == expected_case_ids
    assert all(len(case.outcomes) == len(_EXPECTED_NATIVE_PROVIDERS) for case in captured)
    capture.set_capture_metadata(
        {
            "corpus_digest": _sha256_file(_MANIFEST),
            "whole_function_elapsed_ms_by_case": whole_function_elapsed_ms,
        }
    )
    capture_path.parent.mkdir(parents=True, exist_ok=True)
    capture.write_json(capture_path)
    return json.loads(capture_path.read_text(encoding="utf-8"))


def _build_native_corpus_binary(output_path: Path) -> None:
    compiler = _find_c_compiler()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        [
            compiler,
            *_compiler_shape_build_flags(compiler),
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
    assert {
        case["case_id"]
        for case in cases
        if case["stratum"] in {"semantic_canonicalization", "fixed_shift"}
    } == _DOMAIN_LIFTED_CASE_IDS

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


def test_domain_lifted_provider_routes_are_evidence_bounded() -> None:
    """Routes describe admissible evidence, never a guaranteed native yield."""

    cases = {
        case["case_id"]: case
        for case in json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]
        if case["case_id"] in _DOMAIN_LIFTED_CASE_IDS
    }
    assert cases["canonical_xor_negative_coefficient_32"]["expected_route"] == [
        "catalogue",
        "egraph",
    ]
    assert cases["equivalent_xor_replay_32"]["expected_route"] == [
        "catalogue",
        "egraph",
    ]
    assert cases["fixed_rotate_complementary_32"]["expected_route"] == ["egraph"]
    for case_id in (
        "fixed_shift_noncomplementary_32",
        "fixed_shift_arithmetic_right_32",
        "fixed_shift_variable_count_32",
    ):
        assert cases[case_id]["expected_route"] == []
        assert isinstance(cases[case_id]["expected_blocker"], str)


def test_catalogue_config_is_provider_isolated() -> None:
    catalogue = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))

    catalogue_passes = catalogue["additional_configuration"]["pipeline_v2"]
    assert [item["pass_id"] for item in catalogue_passes] == ["mba-simplify"]
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


@pytest.mark.usefixtures("configure_hexrays")
class TestCompilerShapeCatalogueNative:
    """Native receipt for the root-shaped, currently routed catalogue cases.

    The binary is built from this task's source in a fixture-owned temporary
    directory; it is intentionally not checked in.  This compiler corpus makes
    no single-root degree-two claim: GCC/Hex-Rays may canonicalize a source form
    or schedule independent nested roots.  The direct-AST runtime suite owns the
    degree-two derivation proof.
    """

    binary_name = "mba_compiler_shapes.dylib"
    generated_binary_factory = staticmethod(_build_native_corpus_binary)

    def test_generated_native_input_does_not_pollute_source_tree(
        self,
        ida_database,
    ) -> None:
        assert not _NATIVE_BINARY.exists()

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

    def test_nomut_catalogue_route_matches_the_native_lowered_shape(
        self,
        ida_database,
        d810_state,
        pseudocode_to_string,
        monkeypatch,
    ) -> None:
        """The explicit nomut opt-in must still apply the catalogue rule."""

        from d810.core.settings import get_settings, reset_settings

        monkeypatch.setenv("D810_NOMUT_MATCHING", "1")
        monkeypatch.delenv("D810_LEGACY_STORAGE", raising=False)
        monkeypatch.setenv("D810_LEGACY_DSL_PERMUTATIONS", "1")
        monkeypatch.setenv("D810_SHADOW_DSL_MATCHING", "1")
        reset_settings()

        try:
            @contextlib.contextmanager
            def nomut_state():
                with d810_state() as state:
                    state.load_project(
                        state.project_manager.index("mba_compiler_shape_catalogue.json")
                    )
                    assert state.current_ins_rules
                    instruction_optimizers = state.manager.instruction_optimizer
                    pattern_optimizers = tuple(
                        optimizer
                        for optimizer in instruction_optimizers.instruction_optimizers
                        if hasattr(optimizer, "_use_nomut_matching")
                    )
                    assert pattern_optimizers
                    assert all(
                        optimizer._use_nomut_matching
                        and not optimizer._use_legacy_storage
                        for optimizer in pattern_optimizers
                    )
                    yield state

            run_deobfuscation_test(
                DeobfuscationCase(
                    function="mba_shape_catalogue_01",
                    description="catalogue rule fires through explicit nomut matching",
                    project="mba_compiler_shape_catalogue.json",
                    must_change=True,
                    required_rules=["Add_HackersDelightRule_2"],
                    forbidden_rules=[],
                ),
                d810_state=nomut_state,
                pseudocode_to_string=pseudocode_to_string,
            )
        finally:
            monkeypatch.undo()
            reset_settings()

        assert get_settings().nomut_matching is False

    def test_native_shadow_evidence_certificate_and_activation(
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

        # This is one certificate over one matcher/runtime configuration, not
        # ten independent before/after deobfuscation tests.  Keep one live D810
        # state and perform one D810-enabled decompilation per function.  The
        # parameterized test above owns native before/after text parity; this
        # receipt requires or forbids the exact rule for every corpus member.
        with d810_state() as shared_state:
            shared_state.load_project(
                shared_state.project_manager.index(
                    "mba_compiler_shape_catalogue.json"
                )
            )

            @contextlib.contextmanager
            def recording_state():
                shared_state.stats.reset()
                yield shared_state
                observed_snapshots.append(
                    shared_state.current_certified_catalogue_snapshot
                )
                observed_ledgers.append(
                    shared_state.current_shadow_matcher_parity_ledger
                )

            for function, rule_name in _CATALOGUE_CASES:
                reaches_provider = _catalogue_reaches_provider(function)
                run_deobfuscation_test(
                    DeobfuscationCase(
                        function=function,
                        description="native structural parity evidence",
                        project="",
                        must_change=False,
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
                    "unsafe_mutations",
                    "unproved_structural_replacements",
                )
            }
        )
        assert combined.legacy_match_count > 0
        assert combined.legacy_rule_mismatches == 0
        assert combined.legacy_binding_mismatches == 0
        assert combined.legacy_binding_unknown == 0
        assert combined.new_safe_coverage_pending == 0
        manifest_case_ids_by_function = {
            case["function"]: case["case_id"]
            for case in json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"]
        }
        catalogue_case_coverage = {
            manifest_case_ids_by_function[function]: {
                "observation_count": ledger.observation_count,
                "legacy_match_count": ledger.legacy_match_count,
            }
            for (function, _), ledger in zip(_CATALOGUE_CASES, ledgers, strict=True)
        }
        assert len(catalogue_case_coverage) == len(_CATALOGUE_CASES)

        artifacts = _parity_artifact_dir(tmp_path)
        runtime_mode = str(get_engine_info()["backend"])
        ledger_path = artifacts / f"mba-structural-parity-{runtime_mode}.json"
        capture_path = artifacts / f"mba-native-capture-interactive-{runtime_mode}.json"
        certificate_path = artifacts / f"mba-structural-parity-{runtime_mode}.certificate.json"
        capture_document = _persist_task13_native_capture(
            capture_path,
            d810_state=d810_state,
            pseudocode_to_string=pseudocode_to_string,
        )
        capture_cases = capture_document["cases"]
        assert isinstance(capture_cases, list)
        expected_capture_case_count = len(capture_cases)
        assert expected_capture_case_count == len(json.loads(_MANIFEST.read_text(encoding="utf-8"))["cases"])
        capture_case_ids = {
            case["case_id"] for case in capture_cases if isinstance(case, Mapping)
        }
        assert {
            f"catalogue_{index:02d}" for index in range(1, len(_CATALOGUE_CASES) + 1)
        } <= capture_case_ids
        capture_provider_row_count = sum(
            len(case["outcomes"])
            for case in capture_cases
            if isinstance(case, Mapping) and isinstance(case.get("outcomes"), list)
        )
        assert capture_provider_row_count == expected_capture_case_count * len(
            _EXPECTED_NATIVE_PROVIDERS
        )
        toolchain_identity = capture_document["toolchain_identity"]
        assert isinstance(toolchain_identity, Mapping)
        toolchain_digest = _canonical_json_digest(toolchain_identity)
        ledger_path.write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "runtime_mode": runtime_mode,
                    "snapshot": {
                        "fingerprint": snapshot.fingerprint,
                        "structural_authorizable": snapshot.structural_authorizable,
                        "canonicalizer_schema_version": snapshot.canonicalizer_schema_version,
                        "runtime_semantics_digest": snapshot.runtime_semantics_digest,
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
                            "unsafe_mutations",
                            "unproved_structural_replacements",
                        )
                    },
                    "coverage": {
                        "case_count": len(capture_cases),
                        "provider_row_count": capture_provider_row_count,
                        "catalogue_cases": catalogue_case_coverage,
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
        completed = subprocess.run(
            [
                sys.executable,
                str(_PARITY_CERTIFICATE_TOOL),
                "--ledger",
                str(ledger_path),
                "--capture",
                str(capture_path),
                "--runtime",
                runtime_mode,
                "--output",
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
        assert certificate["canonicalizer_schema_version"] == (
            snapshot.canonicalizer_schema_version
        )
        assert certificate["corpus_digest"] == _sha256_file(_MANIFEST)
        assert certificate["toolchain_digest"] == toolchain_digest
        assert certificate["runtime_semantics_digest"] == snapshot.runtime_semantics_digest
        assert certificate["legacy_observation_count"] > 0
        assert certificate["observation_count"] == combined.observation_count
        assert certificate["observation_count"] > 0
        assert certificate["legacy_rule_mismatches"] == 0
        assert certificate["legacy_binding_mismatches"] == 0
        assert certificate["legacy_binding_unknown"] == 0
        assert certificate["new_safe_coverage_pending"] == 0
        assert certificate["unsafe_mutations"] == 0
        assert certificate["unproved_structural_replacements"] == 0

        # Earlier tests in this class intentionally mutate the class-scoped
        # database. Reopen the fixture-owned input before activation so the
        # raw/fallback partition is measured from one clean native snapshot.
        database_path = ida_database.get("temp_path")
        if database_path is not None:
            idapro.close_database(False)
            assert idapro.open_database(str(database_path), True) == 0
            idaapi.auto_wait()

        # Capture the exact legacy registration shape before the certificate
        # request.  A stale certificate must restore this cache shape rather
        # than merely expose a non-structural adapter.
        monkeypatch.delenv("D810_SHADOW_DSL_MATCHING", raising=False)
        monkeypatch.delenv("D810_STRUCTURAL_DSL_MATCHING", raising=False)
        with d810_state() as legacy_state:
            assert legacy_state.load_project(
                legacy_state.project_manager.index("mba_compiler_shape_catalogue.json")
            ) is not None
            legacy_adapters = tuple(legacy_state.current_ins_rules)
            assert legacy_adapters
            assert legacy_state.current_certified_catalogue_snapshot is None
            legacy_candidate_counts = tuple(
                len(adapter.pattern_candidates) for adapter in legacy_adapters
            )

        activation_config = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
        activation_config["additional_configuration"].update(
            {
                "structural_matcher_parity_certificate": certificate_path.name,
                "structural_matcher_parity_expectation": {
                    "corpus_digest": _sha256_file(_MANIFEST),
                    "toolchain_digest": toolchain_digest,
                    "runtime_semantics_digest": snapshot.runtime_semantics_digest,
                    "legacy_observation_count": combined.legacy_match_count,
                    "observation_count": combined.observation_count,
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
        monkeypatch.setenv("D810_CANONICAL_MATCH_FALLBACK", "1")
        activation_configuration_started = time.monotonic()
        with d810_state() as state:
            state.add_project(runtime_project)
            activation_index = state.project_manager.index(activation_path.name)
            assert state.load_project(activation_index) is not None
            cold_snapshot_ms = (time.monotonic() - activation_configuration_started) * 1000.0
            adapters = tuple(state.current_ins_rules)
            assert adapters
            assert all(adapter.uses_structural_matching for adapter in adapters)
            assert all(len(adapter.pattern_candidates) == 1 for adapter in adapters)

            function_eas = {
                function: get_func_ea(function) for function, _ in _CATALOGUE_CASES
            }
            assert all(ea != idaapi.BADADDR for ea in function_eas.values())
            state.stop_d810()
            for function, _ in _CATALOGUE_CASES:
                before = idaapi.decompile(
                    function_eas[function], flags=idaapi.DECOMP_NO_CACHE
                )
                assert before is not None
            native_proof_results: list[bool] = []
            real_fallback_callback_active = False
            real_bound_proof_count = 0
            original_native_proof = ida_backend.prove_native_ast_equivalence

            def record_native_proof(*args, **kwargs):
                nonlocal real_profiled_proof_count
                nonlocal real_bound_proof_count
                result = original_native_proof(*args, **kwargs)
                native_proof_results.append(result)
                if real_fallback_callback_active:
                    real_bound_proof_count += 1
                if active_root_record is not None:
                    active_root_record["proofs"] += 1
                if real_profile_active:
                    real_profiled_proof_count += 1
                return result

            monkeypatch.setattr(
                ida_backend,
                "prove_native_ast_equivalence",
                record_native_proof,
            )
            # The GCC/IDA lowering may be raw-match-complete in the Cython
            # runtime, so force one admitted rule's raw legacy comparison to
            # miss. This is a controlled live fallback witness; the primary
            # rollout flag and certificate authorization remain unchanged.
            forced_fallback_rule = next(
                adapter
                for adapter in adapters
                if adapter.name == "Add_HackersDelightRule_2"
            )
            monkeypatch.setattr(
                forced_fallback_rule,
                "check_pattern_and_replace",
                lambda _pattern, _candidate: None,
            )
            real_lowering_count = 0
            real_fallback_callback_count = 0
            real_profile = cProfile.Profile()
            real_profile_stream = io.StringIO()
            real_first_current = None
            real_second_current = None
            real_first_peak = 0
            real_second_peak = 0
            real_allocation_before = 0
            real_profile_active = False
            real_profile_completed = False
            real_profiled_proof_count = 0
            real_replacement_count = 0
            real_success_callback_count = 0
            real_callback_allocation_count = 0
            real_root_records: list[dict[str, object]] = []
            active_root_record: dict[str, object] | None = None
            real_clear_events: list[str] = []
            original_prepare = forced_fallback_rule.prepare_structural_candidate
            original_match = forced_fallback_rule.match_structural_and_replace
            from d810.backends.mba import hexrays_island
            from d810.backends.mba import native_z3
            from d810.mba import ac_matching
            from d810.optimizers.microcode.instructions.pattern_matching.handler import (
                PatternOptimizer,
            )
            original_try_matches = PatternOptimizer._try_matches

            real_island_lowering_count = 0
            real_proof_lowering_count = 0
            real_canonical_match_count = 0
            original_island_lowering = hexrays_island.lower_hexrays_island
            original_proof_lowering = native_z3.lower_hexrays_island
            original_canonical_match = ac_matching.match_canonical_term_pattern

            def record_island_lowering(*args, **kwargs):
                nonlocal real_island_lowering_count
                real_island_lowering_count += 1
                if active_root_record is not None:
                    active_root_record["island_lowerings"] += 1
                return original_island_lowering(*args, **kwargs)

            def record_proof_lowering(*args, **kwargs):
                nonlocal real_proof_lowering_count
                real_proof_lowering_count += 1
                if active_root_record is not None:
                    active_root_record["proof_lowerings"] += 1
                return original_proof_lowering(*args, **kwargs)

            def record_canonical_match(*args, **kwargs):
                nonlocal real_canonical_match_count
                real_canonical_match_count += 1
                if active_root_record is not None:
                    active_root_record["canonical_matches"] += 1
                return original_canonical_match(*args, **kwargs)

            monkeypatch.setattr(
                hexrays_island,
                "lower_hexrays_island",
                record_island_lowering,
            )
            monkeypatch.setattr(
                native_z3,
                "lower_hexrays_island",
                record_proof_lowering,
            )
            monkeypatch.setattr(
                ac_matching,
                "match_canonical_term_pattern",
                record_canonical_match,
            )

            def record_real_lowering(*args, **kwargs):
                nonlocal real_lowering_count, real_profile_active
                nonlocal real_profile_completed, real_allocation_before
                if not real_profile_active and not real_profile_completed:
                    gc.collect()
                    real_profile.enable()
                    real_profile_active = True
                real_lowering_count += 1
                if active_root_record is not None:
                    active_root_record["prepares"] += 1
                return original_prepare(*args, **kwargs)

            def record_real_fallback(*args, **kwargs):
                nonlocal real_fallback_callback_count
                nonlocal real_first_current, real_second_current
                nonlocal real_first_peak, real_second_peak, real_allocation_before
                nonlocal real_profile_active, real_profile_completed
                nonlocal real_replacement_count
                nonlocal real_fallback_callback_active, real_success_callback_count
                nonlocal real_callback_allocation_count
                real_fallback_callback_count += 1
                real_fallback_callback_active = True
                if active_root_record is not None:
                    active_root_record["callbacks"] += 1
                gc.collect()
                tracemalloc.start()
                allocation_before = tracemalloc.get_traced_memory()[0]
                result = original_match(*args, **kwargs)
                gc.collect()
                allocation_after, allocation_peak = tracemalloc.get_traced_memory()
                tracemalloc.stop()
                retained = allocation_after - allocation_before
                real_callback_allocation_count += 1
                if real_callback_allocation_count == 1:
                    real_allocation_before = allocation_before
                    real_first_current = retained
                    real_first_peak = allocation_peak
                elif real_callback_allocation_count == 2:
                    real_second_current = retained
                    real_second_peak = allocation_peak
                real_replacement_count += result is not None
                if result is not None:
                    real_success_callback_count += 1
                    if active_root_record is not None:
                        active_root_record["successful_callbacks"] += 1
                        outcome = forced_fallback_rule._last_provider_outcome
                        matcher = getattr(outcome, "matcher", None)
                        if matcher is not None:
                            active_root_record["fallback_comparisons"] = (
                                matcher.fallback_comparisons
                            )
                            active_root_record["selection"] = matcher.selection.value
                if result is not None and not real_profile_completed:
                    real_profile.disable()
                    real_profile_active = False
                    real_profile_completed = True
                return result

            def record_try_matches(self, *args, **kwargs):
                nonlocal active_root_record
                previous = active_root_record
                active_root_record = {
                    "prepares": 0,
                    "island_lowerings": 0,
                    "proof_lowerings": 0,
                    "canonical_matches": 0,
                    "proofs": 0,
                    "emitters": 0,
                    "callbacks": 0,
                    "successful_callbacks": 0,
                    "fallback_comparisons": 0,
                    "selection": None,
                }
                try:
                    result = original_try_matches(self, *args, **kwargs)
                    active_root_record["result"] = result is not None
                    return result
                finally:
                    record = active_root_record
                    active_root_record = previous
                    if record is not None and record["callbacks"]:
                        real_root_records.append(record)

            monkeypatch.setattr(PatternOptimizer, "_try_matches", record_try_matches)

            original_emitter = forced_fallback_rule._create_replacement_from_candidate

            def record_emitter(*args, **kwargs):
                if active_root_record is not None:
                    active_root_record["emitters"] += 1
                return original_emitter(*args, **kwargs)

            monkeypatch.setattr(
                forced_fallback_rule,
                "_create_replacement_from_candidate",
                record_emitter,
            )

            # Verify callback-owned state immediately after every adapter's
            # cleanup call, including the exception path.
            for callback_adapter in adapters:
                original_clear = callback_adapter.clear_match_context

                def clear_callback_context(
                    *args,
                    _adapter=callback_adapter,
                    _original_clear=original_clear,
                    **kwargs,
                ):
                    nonlocal real_fallback_callback_active
                    try:
                        return _original_clear(*args, **kwargs)
                    finally:
                        _assert_adapter_callback_context_cleared(_adapter)
                        real_clear_events.append(_adapter.name)
                        if _adapter is forced_fallback_rule:
                            real_fallback_callback_active = False

                monkeypatch.setattr(
                    callback_adapter,
                    "clear_match_context",
                    clear_callback_context,
                )

            monkeypatch.setattr(
                forced_fallback_rule,
                "prepare_structural_candidate",
                record_real_lowering,
            )
            monkeypatch.setattr(
                forced_fallback_rule,
                "match_structural_and_replace",
                record_real_fallback,
            )
            from d810.mba import canonical_pattern

            catalogue_compile_count = 0
            original_catalogue_compile = canonical_pattern.compile_canonical_pattern

            def record_catalogue_compile(*args, **kwargs):
                nonlocal catalogue_compile_count
                catalogue_compile_count += 1
                return original_catalogue_compile(*args, **kwargs)

            monkeypatch.setattr(
                canonical_pattern,
                "compile_canonical_pattern",
                record_catalogue_compile,
            )
            compile_count_before_callbacks = catalogue_compile_count
            accepted_catalogue_by_function: dict[str, tuple[object, ...]] = {}
            observed_catalogue_by_function: dict[str, tuple[object, ...]] = {}
            fallback_capture_outcomes: list[object] = []
            with capture_native_provider_histories(adapters):
                handler_started = time.monotonic()
                state.start_d810()
                handler_startup_ms = (time.monotonic() - handler_started) * 1000.0
                for function, _ in _CATALOGUE_CASES:
                    with observe_native_provider_histories(adapters) as observation:
                        after = idaapi.decompile(
                            function_eas[function], flags=idaapi.DECOMP_NO_CACHE
                        )
                        assert after is not None
                        new_outcomes = native_provider_outcomes(adapters, observation)
                    observed_catalogue_by_function[function] = tuple(
                        outcome
                        for outcome in new_outcomes
                        if outcome.provider is MbaProviderKind.CATALOGUE
                    )
                    accepted = tuple(
                        outcome
                        for outcome in new_outcomes
                        if outcome.provider is MbaProviderKind.CATALOGUE
                        and outcome.status is ProviderOutcomeStatus.APPLIED
                    )
                    accepted_catalogue_by_function[function] = accepted
                    fallback_capture_outcomes.extend(
                        outcome
                        for outcome in accepted
                        if outcome.matcher is not None
                        and outcome.matcher.selection is MatcherSelection.CANONICAL_FALLBACK
                    )
                state.stop_d810()
            assert real_fallback_callback_count >= 2
            # The per-root records are authoritative.  Global counters are
            # retained only as diagnostic totals because unrelated roots and
            # provider callbacks share the same decompilation.
            assert real_root_records
            successful_root_records = [
                record
                for record in real_root_records
                if record.get("successful_callbacks")
            ]
            assert successful_root_records
            assert all(
                record["prepares"] == 1
                and record["island_lowerings"] == 1
                and record["callbacks"] == 1
                and record["canonical_matches"] >= 1
                and record["proofs"] == 1
                and record["emitters"] == 1
                and 1 <= record["fallback_comparisons"] <= 64
                for record in successful_root_records
            ), successful_root_records
            assert all(
                record["prepares"] == 1
                and record["callbacks"] == 1
                and record["successful_callbacks"] == 0
                for record in real_root_records
                if not record.get("successful_callbacks")
            )
            assert len(real_clear_events) >= len(adapters)
            assert real_profiled_proof_count >= 1
            assert real_replacement_count >= 2
            assert real_profile_active is False
            assert real_first_current is not None
            assert real_second_current is not None
            assert abs(real_second_current - real_first_current) < 128 * 1024
            assert max(real_first_peak, real_second_peak) < 10 * 1024 * 1024
            assert catalogue_compile_count == compile_count_before_callbacks
            real_profile_stats = pstats.Stats(
                real_profile, stream=real_profile_stream
            ).strip_dirs().sort_stats("cumulative")
            # Keep enough of the bounded real-callback profile to retain the
            # complete lowerer -> matcher -> proof -> emitter path.  The
            # callback deliberately performs collection around its allocation
            # probes, so a top-12 report can hide these short-lived functions
            # behind ``gc.collect``.
            real_profile_stats.print_stats()
            real_profile_text = real_profile_stream.getvalue()
            assert "lower_hexrays_island" in real_profile_text
            assert "match_canonical_term_pattern" in real_profile_text
            assert "prove_native_ast_equivalence" in real_profile_text
            assert "_create_replacement_from_candidate" in real_profile_text
            real_profile_path = _ROOT / ".tmp" / (
                f"canonical-fallback-production-profile-{runtime_mode}.json"
            )
            real_profile_path.parent.mkdir(parents=True, exist_ok=True)
            real_profile_path.write_text(
                json.dumps(
                    {
                        "runtime_mode": runtime_mode,
                        "function": "mba_shape_catalogue_01",
                        "fallback_callbacks": real_fallback_callback_count,
                        "lowerings": real_lowering_count,
                        "island_lowerings": real_island_lowering_count,
                        "proof_lowerings": real_proof_lowering_count,
                        "canonical_match_calls": real_canonical_match_count,
                        "replacement_count": real_replacement_count,
                        "root_callback_records": real_root_records,
                        "clear_context_checks": len(real_clear_events),
                        "catalogue_compilations_during_callbacks": 0,
                        "allocation_before": real_allocation_before,
                        "allocation_first_current": real_first_current,
                        "allocation_second_current": real_second_current,
                        "allocation_first_peak": real_first_peak,
                        "allocation_second_peak": real_second_peak,
                        "allocation_window_growth": real_second_current - real_first_current,
                        "profile": real_profile_text,
                    },
                    allow_nan=False,
                    ensure_ascii=True,
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            assert fallback_capture_outcomes
            fallback_capture_outcome = fallback_capture_outcomes[-1]
            fallback_profile = native_profile_from_outcome(fallback_capture_outcome)
            fallback_adapter = next(
                adapter
                for adapter in adapters
                if adapter.name == fallback_capture_outcome.metadata["rule_name"]
            )
            fallback_history = fallback_adapter.provider_outcomes()
            fallback_outcome_index = next(
                index
                for index, outcome in enumerate(fallback_history)
                if outcome is fallback_capture_outcome
            )
            fallback_capture_snapshot = NativeProviderHistorySnapshot(
                {id(fallback_adapter): fallback_outcome_index}
            )
            semantic_capture = NativeMbaCorpusCapture(
                corpus_identity="mba-compiler-shapes-native",
                toolchain_identity={
                    "ida_sdk": str(idaapi.IDA_SDK_VERSION),
                    "matcher_backend": str(get_engine_info()["backend"]),
                    "provider": "catalogue",
                },
            )
            semantic_case = semantic_capture.add_case(
                case_id="catalogue-controlled-fallback",
                stratum="catalogue",
                profile=fallback_profile,
                rules=(fallback_adapter,),
                history_snapshot=fallback_capture_snapshot,
                expected_providers=(MbaProviderKind.CATALOGUE,),
            )
            assert semantic_case.outcomes == (fallback_capture_outcome,)
            semantic_capture_path = artifacts / f"mba-native-capture-controlled-fallback-{runtime_mode}.json"
            semantic_capture.write_json(semantic_capture_path)
            semantic_capture_document = json.loads(
                semantic_capture_path.read_text(encoding="utf-8")
            )
            assert semantic_capture_document["cases"][0]["profile"]["fingerprint"] == (
                fallback_profile.fingerprint
            )
            assert semantic_capture_document["cases"][0]["outcomes"] == [
                fallback_capture_outcome.to_dict()
            ]

            for function, outcomes in observed_catalogue_by_function.items():
                for outcome in outcomes:
                    assert outcome.source_provenance
                    assert outcome.metadata.get("rule_name")
                    matcher = outcome.matcher
                    assert matcher is not None
                    # Raw and fallback work are separate budgets.  A raw hit
                    # must not pay semantic comparison work, while any
                    # fallback callback remains bounded by the shared cap.
                    assert matcher.raw_comparisons >= 0
                    assert matcher.fallback_comparisons >= 0
                    assert matcher.fallback_comparisons <= 64
                    assert matcher.selection in {
                        MatcherSelection.RAW,
                        MatcherSelection.CANONICAL_FALLBACK,
                        MatcherSelection.NONE,
                    }
                    assert matcher.terminal_stop_reason
                    if matcher.selection is MatcherSelection.RAW:
                        assert matcher.fallback_comparisons == 0
                        assert matcher.native_equivalence_verdict is None
                        assert outcome.proof_verdict is None
                        assert outcome.metadata.get("raw_native_identity")
                    elif matcher.selection is MatcherSelection.CANONICAL_FALLBACK:
                        if matcher.terminal_stop_reason in {
                            "fallback_unavailable",
                            "reconstruction_failed",
                        }:
                            # A terminal structural-selection refusal may be
                            # emitted before either comparison phase runs.
                            # Keep the receipt visible and require that it
                            # cannot claim equivalence or a mutation.
                            assert matcher.raw_comparisons >= 0
                            assert matcher.fallback_comparisons >= 0
                            assert matcher.native_equivalence_verdict is None
                            assert matcher.mutation_outcome in {None, "rejected"}
                            assert outcome.status is not ProviderOutcomeStatus.APPLIED
                            assert outcome.proof_verdict in {None, False}
                        elif outcome.status is ProviderOutcomeStatus.APPLIED:
                            assert matcher.raw_comparisons > 0
                            assert matcher.fallback_comparisons > 0
                            assert matcher.native_equivalence_verdict is True
                            assert matcher.mutation_outcome == "accepted"
                            assert outcome.proof_verdict is None
                        else:
                            assert matcher.raw_comparisons > 0
                            assert matcher.fallback_comparisons > 0
                            assert matcher.native_equivalence_verdict in {None, False}
                            assert matcher.mutation_outcome in {None, "rejected"}
                            assert outcome.proof_verdict in {None, False}
                    else:
                        assert matcher.terminal_stop_reason in {"miss", "clean_miss"}
                        assert outcome.status is not ProviderOutcomeStatus.APPLIED
                        assert outcome.proof_verdict in {None, False}
                _assert_exact_catalogue_contract(function, outcomes)
                # Callback-local canonical candidate/binding state is cleared
                # before the next instruction.  Registration candidates are
                # intentionally long-lived; these borrowed objects are not.
                for adapter in adapters:
                    _assert_adapter_callback_context_cleared(adapter)
            applied_catalogue_outcomes = tuple(
                outcome
                for function_outcomes in accepted_catalogue_by_function.values()
                for outcome in function_outcomes
                if outcome.provider is MbaProviderKind.CATALOGUE
                and outcome.status is ProviderOutcomeStatus.APPLIED
            )
            raw_outcomes = tuple(
                outcome
                for outcome in applied_catalogue_outcomes
                if outcome.matcher is not None
                and outcome.matcher.selection is MatcherSelection.RAW
            )
            fallback_outcomes = tuple(
                outcome
                for outcome in applied_catalogue_outcomes
                if outcome.matcher is not None
                and outcome.matcher.selection is MatcherSelection.CANONICAL_FALLBACK
            )
            assert fallback_outcomes, (
                "activation must observe a canonical fallback: "
                + repr(
                    [
                        (
                            outcome.matcher.selection.value
                            if outcome.matcher is not None
                            else None,
                            outcome.matcher.raw_comparisons
                            if outcome.matcher is not None
                            else None,
                            outcome.matcher.fallback_comparisons
                            if outcome.matcher is not None
                            else None,
                        )
                        for outcome in applied_catalogue_outcomes
                    ]
                )
            )
            assert raw_outcomes, "activation must observe a raw catalogue selection"
            assert len(applied_catalogue_outcomes) == len(raw_outcomes) + len(
                fallback_outcomes
            )
            assert all(
                outcome.matcher is not None
                and outcome.matcher.raw_comparisons > 0
                and outcome.matcher.fallback_comparisons == 0
                and outcome.matcher.backend == "legacy_ast"
                and outcome.matcher.native_equivalence_verdict is None
                and "structural_dispatch" not in outcome.metadata
                and outcome.metadata.get("mutation_outcome") == "accepted"
                for outcome in raw_outcomes
            )
            assert all(
                outcome.matcher is not None
                and outcome.matcher.raw_comparisons > 0
                and outcome.matcher.fallback_comparisons > 0
                and outcome.matcher.selection is MatcherSelection.CANONICAL_FALLBACK
                and outcome.matcher.native_equivalence_verdict is True
                and outcome.metadata.get("structural_dispatch") is not None
                and outcome.metadata["mutation_outcome"] == "accepted"
                for outcome in fallback_outcomes
            )
            assert native_proof_results
            assert any(native_proof_results)
            report_evidence_path = artifacts / f"mba-structural-report-evidence-{runtime_mode}.json"
            report_evidence_path.write_text(
                json.dumps(
                    {
                        "capture_metadata": {
                            "matcher_samples": [
                                {
                                    "bucket_size": outcome.metadata["structural_dispatch"][
                                        "bucket_size"
                                    ],
                                    "attempted_rule_count": outcome.metadata[
                                        "structural_dispatch"
                                    ]["attempted_rule_count"],
                                    "raw_comparisons": outcome.matcher.raw_comparisons,
                                    "fallback_comparisons": outcome.matcher.fallback_comparisons,
                                    "fallback_comparison_budget": 64,
                                    "comparisons": outcome.matcher.comparisons,
                                    "lazy_swaps": outcome.matcher.lazy_swaps,
                                    "flattened_arity": outcome.matcher.flattened_arity,
                                    "comparison_cap_refusal": (
                                        outcome.matcher.stop_reason
                                        == "comparison_budget"
                                    ),
                                }
                                for outcome in fallback_outcomes
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
                                "native_proof_invocations": [len(native_proof_results)],
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

            loaded_certificate = load_structural_matcher_parity_certificate(
                certificate_path
            )
            expectation = StructuralMatcherParityExpectation(
                corpus_digest=_sha256_file(_MANIFEST),
                toolchain_digest=toolchain_digest,
                runtime_semantics_digest=loaded_certificate.runtime_semantics_digest,
                legacy_observation_count=combined.legacy_match_count,
                observation_count=combined.observation_count,
            )
            stale_mutations = (
                (
                    "wrong_runtime",
                    loaded_certificate,
                    expectation,
                    "cython" if runtime_mode == "python" else "python",
                ),
                (
                    "wrong_canonicalizer_version",
                    replace(
                        loaded_certificate,
                        canonicalizer_schema_version=(
                            loaded_certificate.canonicalizer_schema_version + 1
                        ),
                    ),
                    expectation,
                    runtime_mode,
                ),
                (
                    "wrong_catalogue_digest",
                    replace(loaded_certificate, snapshot_fingerprint="0" * 64),
                    expectation,
                    runtime_mode,
                ),
                (
                    "wrong_corpus_digest",
                    loaded_certificate,
                    replace(expectation, corpus_digest="0" * 64),
                    runtime_mode,
                ),
                (
                    "wrong_toolchain_digest",
                    loaded_certificate,
                    replace(expectation, toolchain_digest="0" * 64),
                    runtime_mode,
                ),
                (
                    "wrong_runtime_semantics_digest",
                    replace(
                        loaded_certificate,
                        runtime_semantics_digest="0" * 64,
                    ),
                    expectation,
                    runtime_mode,
                ),
                (
                    "wrong_observation_count",
                    loaded_certificate,
                    replace(
                        expectation,
                        observation_count=expectation.observation_count + 1,
                    ),
                    runtime_mode,
                ),
            )
            for (
                _mutation_name,
                stale_certificate,
                stale_expectation,
                stale_runtime,
            ) in stale_mutations:
                for adapter in adapters:
                    rule_id = getattr(adapter, "_certified_catalogue_rule_id", 0)
                    adapter.attach_certified_catalogue_snapshot(
                        snapshot,
                        rule_id,
                        state.current_shadow_matcher_parity_ledger,
                        loaded_certificate,
                        expectation,
                        runtime_mode,
                    )
                    assert adapter.uses_structural_matching is True
                    adapter.pattern_candidates
                for adapter in adapters:
                    rule_id = getattr(adapter, "_certified_catalogue_rule_id", 0)
                    adapter.attach_certified_catalogue_snapshot(
                        snapshot,
                        rule_id,
                        state.current_shadow_matcher_parity_ledger,
                        stale_certificate,
                        stale_expectation,
                        stale_runtime,
                    )
                assert all(not adapter.uses_structural_matching for adapter in adapters)
                assert all(
                    adapter._pattern_candidates_cache is None for adapter in adapters
                )

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
            assert tuple(
                len(adapter.pattern_candidates) for adapter in state.current_ins_rules
            ) == legacy_candidate_counts
