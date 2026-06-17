from __future__ import annotations

from d810.passes.pass_pipeline_factory import (
    PASS_ID_GOTO_CHAIN_REMOVAL,
    PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH,
    PASS_ID_SIMPLIFY_IDENTICAL_BRANCH,
    build_pass_pipeline_spec,
    pass_pipeline_spec_from_config,
)


def test_default_cleanup_spec_selects_two_safe_cleanup_passes() -> None:
    spec = build_pass_pipeline_spec(include_default_cleanup=True)

    assert spec.pass_ids == (
        PASS_ID_SIMPLIFY_IDENTICAL_BRANCH,
        PASS_ID_GOTO_CHAIN_REMOVAL,
    )
    assert spec.enabled is True


def test_loop_carrier_refresh_can_be_selected_without_default_cleanup() -> None:
    spec = build_pass_pipeline_spec(
        include_default_cleanup=False,
        enable_loop_carrier_backedge_refresh=True,
    )

    assert spec.pass_ids == (PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH,)


def test_spec_from_config_returns_none_when_all_flags_disabled() -> None:
    assert pass_pipeline_spec_from_config({}, environ={}) is None


def test_spec_from_config_uses_project_flag_and_env_flag() -> None:
    spec = pass_pipeline_spec_from_config(
        {"enable_pass_pipeline": True},
        environ={"D810_LOOP_CARRIER_BACKEDGE_REFRESH": "1"},
    )

    assert spec is not None
    assert spec.pass_ids == (
        PASS_ID_SIMPLIFY_IDENTICAL_BRANCH,
        PASS_ID_GOTO_CHAIN_REMOVAL,
        PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH,
    )
