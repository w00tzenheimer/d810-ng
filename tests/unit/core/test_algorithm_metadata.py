from __future__ import annotations

from d810.core.algorithm_metadata import (
    algorithm_metadata,
    find_algorithm_metadata,
    get_algorithm_metadata,
    get_algorithm_metadata_for_object,
)
from d810.transforms.modification_builder import ModificationBuilder
from d810.transforms.plan import compile_patch_plan
from d810.analyses.control_flow.compare_chain import CompareChainResolver


@algorithm_metadata(
    algorithm_id="tests.unit.synthetic_algorithm",
    family="unit_test_family",
    summary="Synthetic metadata entry for registry testing.",
    use_cases=("Unit-test lookup coverage.",),
    examples=("Decorate a local function and recover its metadata.",),
    tags=("synthetic", "test"),
    related_paths=("tests/unit/core/test_algorithm_metadata.py",),
)
def _synthetic_algorithm():
    return None


def test_get_algorithm_metadata_for_decorated_function():
    metadata = get_algorithm_metadata_for_object(_synthetic_algorithm)

    assert metadata is not None
    assert metadata.algorithm_id == "tests.unit.synthetic_algorithm"
    assert metadata.family == "unit_test_family"


def test_known_algorithm_metadata_entries_are_queryable():
    builder_meta = get_algorithm_metadata_for_object(ModificationBuilder)
    plan_meta = get_algorithm_metadata_for_object(compile_patch_plan)
    compare_meta = get_algorithm_metadata_for_object(CompareChainResolver)

    assert builder_meta is not None
    assert builder_meta.family == "tail_block_duplication_and_redirect"
    assert plan_meta is not None
    assert plan_meta.algorithm_id == "cfg.compile_patch_plan"
    assert compare_meta is not None
    assert compare_meta.family == "compare_chain_interval_dispatch_reconstruction"


def test_find_algorithm_metadata_filters_by_family_and_search():
    family_matches = find_algorithm_metadata(
        family="tail_block_duplication_and_redirect",
    )
    search_matches = find_algorithm_metadata(search="dispatch table")

    assert {item.algorithm_id for item in family_matches} >= {
        "cfg.modification_builder",
        "cfg.compile_patch_plan",
    }
    assert any(item.algorithm_id == "cfg.compare_chain_resolver" for item in search_matches)
    assert get_algorithm_metadata("cfg.modification_builder") is not None
