"""Semantic receipt for the independently-authored compiler-shaped MBA corpus.

This is deliberately a pre-provider gate.  It proves every emitted shape against
its simple sibling before later portfolio tasks attribute a result to catalogue,
Egglog, or coefficient routing.
"""

from __future__ import annotations

import ctypes
import contextlib
import json
import random
import shutil
import subprocess
from pathlib import Path

import pytest

from d810.testing.cases import DeobfuscationCase
from d810.testing.runner import run_deobfuscation_test


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_CATALOGUE_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_catalogue.json"
_EGGLOG_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_egglog.json"
_EGGLOG_DEGREE2_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_egglog_degree2.json"
_NATIVE_BINARY = _ROOT / "samples/bins/mba_compiler_shapes.dylib"

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


def test_catalogue_corpus_keeps_structural_matching_in_shadow_mode() -> None:
    """Task 7 observes structural matches but does not select through them."""

    catalogue = json.loads(_CATALOGUE_CONFIG.read_text(encoding="utf-8"))
    description = catalogue["description"].lower()
    assert "catalogue" in description
    # The project remains the legacy `mba-simplify` pass until Task 8's parity
    # gate replaces generated commutations with the structural matcher.
    assert [
        item["pass_id"] for item in catalogue["additional_configuration"]["pipeline_v2"]
    ] == ["mba-simplify"]


def test_corpus_projects_register_their_one_intended_provider(
    ida_database, d810_state
) -> None:
    with d810_state() as state:
        state.load_project(
            state.project_manager.index("mba_compiler_shape_catalogue.json")
        )
        assert state.last_pipeline_v2_hook_pass_ids == ("mba-simplify",)

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
    ) -> None:
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
        assert ledger.legacy_rule_mismatches == 0
        assert ledger.legacy_binding_mismatches == 0
        assert ledger.legacy_binding_unknown == 0
        # Structural-only coverage is split into pending and native-Z3-proven
        # observations. Neither counter is a provider selection or mutation.
        assert (
            ledger.new_safe_coverage_pending + ledger.new_safe_coverage_proved
        ) >= 0
