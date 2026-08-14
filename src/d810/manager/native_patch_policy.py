"""Portable, persisted authorization policy for native normalization."""

from __future__ import annotations

__all__ = ["NATIVE_PATCH_FUNCTION_OPT_IN_TAG", "native_patch_function_is_authorized"]


# This is deliberately a persisted per-function tag, not a profile-derived
# eligibility signal.  A global configuration value can disable the feature,
# but can never opt every function into a native mutation.
NATIVE_PATCH_FUNCTION_OPT_IN_TAG = "native_patch:enabled"


def native_patch_function_is_authorized(
    *, globally_available: bool, function_tags: set[str]
) -> bool:
    """Return whether the user explicitly authorized this exact function."""
    return bool(globally_available) and NATIVE_PATCH_FUNCTION_OPT_IN_TAG in {
        str(tag).strip() for tag in function_tags
    }
