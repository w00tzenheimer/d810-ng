from __future__ import annotations

import pytest

from d810.passes.mba_simplify import build_mba_simplify_pass, mba_simplify_pass_registry
from d810.passes.mba_transform_options import (
    MbaSimplifyOptions,
    parse_mba_simplify_options,
)
from d810.passes.pass_pipeline import PipelineConfig, PipelineConfigError


def _config(
    transforms: object,
    transform_options: object | None = None,
) -> PipelineConfig:
    options: dict[str, object] = {"transforms": transforms}
    if transform_options is not None:
        options["transform_options"] = transform_options
    return PipelineConfig(pass_id="mba-simplify", options=options)


def test_typed_mba_options_preserve_order_and_resolve_private_bindings() -> None:
    registry = mba_simplify_pass_registry()
    config = _config(
        ["add-xor-1", "example-guessing"],
        {
            "example-guessing": {
                "min_nb_var": 1,
                "max_nb_var": 3,
                "min_nb_diff_opcodes": 3,
                "max_nb_diff_opcodes": 6,
            }
        },
    )

    parsed = parse_mba_simplify_options(config, registry)
    adapter = build_mba_simplify_pass(config, registry)

    assert parsed == MbaSimplifyOptions(
        transform_ids=("add-xor-1", "example-guessing"),
        transform_options={
            "example-guessing": {
                "min_nb_var": 1,
                "max_nb_var": 3,
                "min_nb_diff_opcodes": 3,
                "max_nb_diff_opcodes": 6,
            }
        },
    )
    assert adapter.transform_ids == ("add-xor-1", "example-guessing")
    assert adapter.implementation_names == ("AddXor_Rule_1", "ExampleGuessingRule")


def test_typed_mba_options_reject_an_undeclared_transform_option() -> None:
    config = _config(
        ["example-guessing"],
        {"example-guessing": {"json_only": True}},
    )

    with pytest.raises(PipelineConfigError, match="editor-visible"):
        parse_mba_simplify_options(config, mba_simplify_pass_registry())


def test_typed_mba_options_can_disable_legacy_fuzzy_permutations() -> None:
    config = PipelineConfig(
        pass_id="mba-simplify",
        options={
            "transforms": ["add-xor-1"],
            "generate_commutative_permutations": False,
        },
    )

    parsed = parse_mba_simplify_options(config, mba_simplify_pass_registry())
    adapter = build_mba_simplify_pass(config, mba_simplify_pass_registry())

    assert parsed.generate_commutative_permutations is False
    assert adapter.generate_commutative_permutations is False


@pytest.mark.parametrize(
    ("config", "message"),
    (
        (_config(["not-registered"]), "unknown transform"),
        (_config(["add-xor-1", "add-xor-1"]), "duplicate"),
        (
            _config(
                ["add-xor-1"],
                {"add-ollvm-1": {"max_depth": 6}},
            ),
            "unselected transform",
        ),
        (_config(["AddXor_Rule_1"]), "unknown transform"),
    ),
)
def test_typed_mba_options_reject_unknown_duplicate_or_private_names(
    config: PipelineConfig,
    message: str,
) -> None:
    with pytest.raises(PipelineConfigError, match=message):
        parse_mba_simplify_options(config, mba_simplify_pass_registry())


@pytest.mark.parametrize(
    "transform_id",
    ("z-3-setz-generic", "z-3-setnz-generic", "z-3-lnot-generic"),
)
def test_generic_z3_transform_options_accept_explicit_bounded_policy(
    transform_id: str,
) -> None:
    parsed = parse_mba_simplify_options(
        _config(
            [transform_id],
            {
                transform_id: {
                    "max_expression_nodes": 1024,
                    "proof_timeout_ms": 250,
                }
            },
        ),
        mba_simplify_pass_registry(),
    )

    assert parsed.transform_options == {
        transform_id: {
            "max_expression_nodes": 1024,
            "proof_timeout_ms": 250,
        }
    }


@pytest.mark.parametrize(
    ("transform_id", "field", "value"),
    (
        ("z-3-setz-generic", "max_expression_nodes", 0),
        ("z-3-setnz-generic", "max_expression_nodes", 4097),
        ("z-3-lnot-generic", "proof_timeout_ms", 0),
        ("z-3-setz-generic", "proof_timeout_ms", 5001),
        ("z-3-setnz-generic", "max_expression_nodes", True),
        ("z-3-lnot-generic", "proof_timeout_ms", "50"),
    ),
)
def test_generic_z3_transform_options_reject_invalid_policy_values(
    transform_id: str,
    field: str,
    value: object,
) -> None:
    with pytest.raises(PipelineConfigError, match=transform_id):
        parse_mba_simplify_options(
            _config([transform_id], {transform_id: {field: value}}),
            mba_simplify_pass_registry(),
        )


@pytest.mark.parametrize(
    "transform_id",
    ("z-3-setz-generic", "z-3-setnz-generic", "z-3-lnot-generic"),
)
def test_generic_z3_transform_options_reject_unknown_keys(transform_id: str) -> None:
    with pytest.raises(PipelineConfigError, match="editor-visible"):
        parse_mba_simplify_options(
            _config([transform_id], {transform_id: {"unknown": 1}}),
            mba_simplify_pass_registry(),
        )


def test_generic_z3_transform_options_are_omittable_per_transform() -> None:
    parsed = parse_mba_simplify_options(
        _config(
            ["z-3-setz-generic", "z-3-setnz-generic", "z-3-lnot-generic"],
            {"z-3-setz-generic": {"max_expression_nodes": 7}},
        ),
        mba_simplify_pass_registry(),
    )

    # Parsing preserves only explicit values. The live bridge supplies defaults
    # separately to each selected rule, so one transform cannot inherit another's
    # partial policy.
    assert parsed.transform_options == {
        "z-3-setz-generic": {"max_expression_nodes": 7}
    }
