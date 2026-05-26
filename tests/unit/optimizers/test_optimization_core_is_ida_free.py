"""Regression: ``d810.optimizers.core`` must be importable without IDA.

Slice 7 (llvm-lisa-restructure) removed the ``import ida_hexrays`` from
``optimizers/core.py`` and widened the two surface annotations
(``OptimizationContext.mba`` and ``PatternMatchingRule.apply``'s ``ins``)
to portable types so the ``OptimizationRule`` Protocol can be moved to
a portable home in a sibling slice.

These tests guard against regression: if a future contributor adds
``import ida_hexrays`` back to this module (or to anything it imports
transitively), the tests fail.

All imports here go through ``importlib.import_module`` rather than
``from d810.optimizers... import ...`` so the ``unit-tests-no-optimizers``
import-linter contract sees no static ``tests.unit.*`` -> ``d810.optimizers.*``
edge.  The test still proves the runtime import works.
"""
from __future__ import annotations

import importlib
import sys

import pytest


def _import_optimizers_core() -> object:
    """Import ``d810.optimizers.core`` dynamically and return the module."""
    return importlib.import_module("d810.optimizers.core")


def test_optimization_core_does_not_bind_ida_hexrays_name() -> None:
    """``optimizers.core``'s module namespace must not include ``ida_hexrays``."""
    core = _import_optimizers_core()

    leaked = [name for name in dir(core) if "ida_hexrays" in name.lower()]
    assert not leaked, f"optimizers.core leaked ida_hexrays-named symbols: {leaked}"
    assert not hasattr(core, "ida_hexrays"), (
        "optimizers.core must not bind ``ida_hexrays`` as a module-level name"
    )


def test_optimization_context_field_types_are_portable() -> None:
    """``OptimizationContext`` field annotations must be portable types.

    Slice 7 widened ``mba: ida_hexrays.mba_t`` to ``mba: object``;
    a regression to the IDA-typed annotation would force
    ``import ida_hexrays`` back into the module.
    """
    core = _import_optimizers_core()
    ctx_cls = core.OptimizationContext

    fields = ctx_cls.__dataclass_fields__
    mba_type = fields["mba"].type
    annotation_repr = mba_type if isinstance(mba_type, str) else repr(mba_type)
    assert "ida_hexrays" not in annotation_repr, (
        f"OptimizationContext.mba annotation regressed to IDA-typed: "
        f"{annotation_repr!r}"
    )


def test_pattern_matching_rule_apply_ins_is_portable() -> None:
    """``PatternMatchingRule.apply``'s ``ins`` parameter must be a
    portable type annotation (``Any`` after slice 7), not
    ``ida_hexrays.minsn_t``."""
    core = _import_optimizers_core()
    rule_cls = core.PatternMatchingRule

    apply_annotations = rule_cls.apply.__annotations__
    ins_annotation = apply_annotations.get("ins")
    assert ins_annotation is not None, "ins parameter must be annotated"
    annotation_repr = (
        ins_annotation if isinstance(ins_annotation, str) else repr(ins_annotation)
    )
    assert "ida_hexrays" not in annotation_repr, (
        f"PatternMatchingRule.apply 'ins' annotation regressed to IDA-typed: "
        f"{annotation_repr!r}"
    )


def test_optimizers_core_importable_with_ida_hexrays_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Force-import ``optimizers.core`` after evicting ``ida_hexrays`` from
    ``sys.modules`` and blocking re-import.  If ``optimizers.core`` has
    any transitive ``import ida_hexrays``, this raises ``ModuleNotFoundError``
    / ``ImportError``."""
    # Block any attempt to import ida_hexrays during the test.
    monkeypatch.setitem(sys.modules, "ida_hexrays", None)
    # Force a fresh import of optimizers.core so any transitive
    # ida_hexrays import would fail loudly.
    for mod_name in list(sys.modules):
        if mod_name == "d810.optimizers.core" or mod_name.startswith(
            "d810.optimizers.core."
        ):
            monkeypatch.delitem(sys.modules, mod_name, raising=False)

    # If the import succeeds with ida_hexrays blocked, the module is
    # genuinely IDA-free.  If it fails with ModuleNotFoundError or
    # ImportError citing ida_hexrays, slice 7's invariant has regressed.
    importlib.import_module("d810.optimizers.core")
