"""Smoke test: def_search module is importable without IDA."""
import pytest


def test_def_search_importable():
    """Module should be importable (will fail at IDA import in non-IDA env, which is expected)."""
    try:
        from d810.recon.flow import def_search
    except ImportError as e:
        if "ida_hexrays" in str(e):
            pytest.skip("IDA not available")
        raise
