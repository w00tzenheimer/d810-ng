from __future__ import annotations

from d810.expr import p_ast


class _MappedLeaf:
    def __init__(self, mop):
        self.mop = mop


class _Source:
    def __init__(self):
        self.leafs_by_name = {
            "x_0": _MappedLeaf(mop="mop_x"),
            "c_1": _MappedLeaf(mop="mop_c"),
        }


class _Leaf:
    def __init__(self, name: str, should_succeed: bool):
        self.name = name
        self.mop = None
        self._should_succeed = should_succeed
        self.calls = 0

    def update_leafs_mop(self, other, other2=None):
        self.calls += 1
        if self.name in other.leafs_by_name:
            self.mop = other.leafs_by_name[self.name].mop
        return self._should_succeed


class _NodeLike:
    def __init__(self, leaves):
        self._leaves = leaves
        self.leafs = []

    def get_leaf_list(self):
        return self._leaves


def test_update_leafs_mop_delegates_to_leaf_specific_update():
    ok_leaf = _Leaf("x_0", should_succeed=True)
    failing_leaf = _Leaf("c_1", should_succeed=False)
    node_like = _NodeLike([ok_leaf, failing_leaf])
    source = _Source()

    result = p_ast.AstNode.update_leafs_mop(node_like, source)

    assert result is False
    assert ok_leaf.calls == 1
    assert failing_leaf.calls == 1
    assert ok_leaf.mop == "mop_x"
    assert failing_leaf.mop == "mop_c"
