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
