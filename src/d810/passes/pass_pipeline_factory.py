"""Portable pass-pipeline specification helpers."""
from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

PASS_ID_SIMPLIFY_IDENTICAL_BRANCH = "simplify_identical_branch"
PASS_ID_GOTO_CHAIN_REMOVAL = "goto_chain_removal"
PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH = "loop_carrier_backedge_refresh"


@dataclass(frozen=True, slots=True)
class PassPipelineSpec:
    """Target-neutral ordered pass IDs selected for one pipeline run."""

    pass_ids: tuple[str, ...]

    @property
    def enabled(self) -> bool:
        return bool(self.pass_ids)


def build_pass_pipeline_spec(
    *,
    include_default_cleanup: bool = True,
    enable_loop_carrier_backedge_refresh: bool = False,
) -> PassPipelineSpec:
    """Build the target-neutral pass ordering.

    The spec deliberately stores pass IDs rather than concrete classes. Some
    concrete implementations still live in backend-oriented packages, while the
    ordering and feature selection are D810 compiler-pipeline concerns.
    """
    pass_ids: list[str] = []
    if include_default_cleanup:
        pass_ids.extend(
            (
                PASS_ID_SIMPLIFY_IDENTICAL_BRANCH,
                PASS_ID_GOTO_CHAIN_REMOVAL,
            )
        )
    if enable_loop_carrier_backedge_refresh:
        pass_ids.append(PASS_ID_LOOP_CARRIER_BACKEDGE_REFRESH)
    return PassPipelineSpec(pass_ids=tuple(pass_ids))


def pass_pipeline_spec_from_config(
    config: Mapping[str, object],
    *,
    environ: Mapping[str, str] | None = None,
) -> PassPipelineSpec | None:
    """Return a pass-pipeline spec for project config/environment, if enabled."""
    if environ is None:
        environ = os.environ
    enable_default_cleanup = bool(config.get("enable_pass_pipeline", False))
    enable_loop_carrier_backedge_refresh = (
        str(environ.get("D810_LOOP_CARRIER_BACKEDGE_REFRESH", "")).strip() == "1"
    )
    if not enable_default_cleanup and not enable_loop_carrier_backedge_refresh:
        return None
    return build_pass_pipeline_spec(
        include_default_cleanup=enable_default_cleanup,
        enable_loop_carrier_backedge_refresh=enable_loop_carrier_backedge_refresh,
    )
