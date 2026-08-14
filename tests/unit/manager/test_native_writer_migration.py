"""Policy tests for the manager-owned native writer bridge."""

from __future__ import annotations

from d810.manager.native_patch_policy import (
    NATIVE_PATCH_FUNCTION_OPT_IN_TAG,
    native_patch_function_is_authorized,
)


def test_native_patch_requires_persisted_opt_in_for_the_exact_function() -> None:
    assert not native_patch_function_is_authorized(
        globally_available=True,
        function_tags=set(),
    )
    assert not native_patch_function_is_authorized(
        globally_available=False,
        function_tags={NATIVE_PATCH_FUNCTION_OPT_IN_TAG},
    )
    assert native_patch_function_is_authorized(
        globally_available=True,
        function_tags={NATIVE_PATCH_FUNCTION_OPT_IN_TAG},
    )
