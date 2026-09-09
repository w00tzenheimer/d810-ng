"""Fast visitor admission retains the structural Protocol contract."""

from types import SimpleNamespace

import pytest

from d810.ir.expr.dsl import (
    SymbolicExpression, SymbolicExpressionProtocol, is_symbolic_expression,
)


@pytest.mark.parametrize("missing", [None, "operation", "left", "right", "name", "value"])
def test_missing_instance_fields_preserve_protocol_verdict(missing):
    node = SymbolicExpression("add")
    if missing is not None:
        delattr(node, missing)
    assert is_symbolic_expression(node) == isinstance(node, SymbolicExpressionProtocol)


def test_null_leaf_method_is_rejected():
    node = SymbolicExpression("add")
    node.is_leaf = None
    assert not is_symbolic_expression(node)


def test_foreign_and_subclass_instances_use_structural_contract():
    class Derived(SymbolicExpression):
        pass

    for node in (Derived("add"), SimpleNamespace(**vars(SymbolicExpression("add")), is_leaf=lambda: False), object()):
        assert is_symbolic_expression(node) == isinstance(node, SymbolicExpressionProtocol)


def test_dict_subclass_cannot_hide_null_method():
    class Misleading(dict):
        def get(self, key, default=None):
            return default

    node = SymbolicExpression("add")
    node.__dict__ = Misleading(vars(node), is_leaf=None)
    assert not is_symbolic_expression(node)


def test_ordinary_node_avoids_protocol_check(monkeypatch):
    import d810.ir.expr.dsl as dsl

    node = SymbolicExpression("add")

    def unexpected(*_args):
        raise AssertionError("ordinary nodes must not invoke the Protocol")

    monkeypatch.setattr(dsl, "isinstance", unexpected, raising=False)
    assert is_symbolic_expression(node)
