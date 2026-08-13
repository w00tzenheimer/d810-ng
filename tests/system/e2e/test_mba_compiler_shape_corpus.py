"""Semantic receipt for the independently-authored compiler-shaped MBA corpus.

This is deliberately a pre-provider gate.  It proves every emitted shape against
its simple sibling before later portfolio tasks attribute a result to catalogue,
Egglog, or coefficient routing.
"""

from __future__ import annotations

import ctypes
import json
import random
import shutil
import subprocess
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[3]
_SOURCE = _ROOT / "samples/src/c/mba_compiler_shapes.c"
_MANIFEST = _ROOT / "tests/fixtures/mba_portfolio/compiler_shapes.json"
_CATALOGUE_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_catalogue.json"
_EGGLOG_CONFIG = _ROOT / "src/d810/conf/mba_compiler_shape_egglog.json"


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
    compiler = next(
        (candidate for candidate in ("clang", "gcc", "cc") if shutil.which(candidate)),
        None,
    )
    if compiler is None:
        raise RuntimeError("compiler-shaped corpus needs clang, gcc, or cc")
    subprocess.run(
        [
            compiler,
            "-shared",
            "-fPIC",
            "-O0",
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
    return ctypes.CDLL(str(library))


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
