from __future__ import annotations

import pytest

from d810.hexrays.ir import block_helpers


class _BlockDouble:
    serial = 7

    def npred(self) -> int:
        return 1

    def pred(self, _idx: int) -> int:
        return 3

    def nsucc(self) -> int:
        return 1

    def succ(self, _idx: int) -> int:
        return 11


class _SwigLikeBlock(_BlockDouble):
    this = object()


def test_cython_block_helper_dispatch_uses_python_fallback_for_block_doubles():
    helper = block_helpers._make_block_helper(
        lambda _blk: pytest.fail("non-SWIG block doubles must not hit Cython"),
        block_helpers._py_get_succ_serials,
    )

    assert helper(_BlockDouble()) == (11,)


def test_cython_block_helper_dispatch_uses_cython_for_swig_blocks():
    helper = block_helpers._make_block_helper(
        lambda _blk: ("fast",),
        lambda _blk: pytest.fail("SWIG blocks must keep the Cython fast path"),
    )

    assert helper(_SwigLikeBlock()) == ("fast",)
