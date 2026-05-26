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


def test_optimizers_core_importable_in_clean_subprocess() -> None:
    """Import ``optimizers.core`` in a fresh subprocess with no project
    modules cached and ``ida_hexrays`` blocked.

    Running in a subprocess avoids the cached-state hole an
    in-process monkeypatch has: if an earlier test in this process
    has already imported a transitive dependency that pulled in
    ``ida_hexrays``, evicting only the ``d810.optimizers.core``
    subtree from ``sys.modules`` would NOT re-exercise that
    dependency under the blocked condition, and the assertion would
    pass even after a regression.  A clean subprocess re-runs every
    transitive import from scratch.
    """
    import os
    import subprocess

    repo_src = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "..",
        "src",
    )
    repo_src = os.path.normpath(repo_src)

    script = (
        "import sys\n"
        # Block any attempt to import ida_hexrays (or its parent if
        # imported indirectly).  Setting sys.modules[name] = None
        # makes any subsequent `import ida_hexrays` raise
        # ModuleNotFoundError.
        "sys.modules['ida_hexrays'] = None\n"
        "sys.modules['idaapi'] = None\n"
        "import importlib\n"
        "core = importlib.import_module('d810.optimizers.core')\n"
        # Sanity check: the module must define the symbols this slice
        # cares about.
        "assert hasattr(core, 'OptimizationContext')\n"
        "assert hasattr(core, 'OptimizationRule')\n"
        "assert hasattr(core, 'PatternMatchingRule')\n"
        # And no ida_hexrays leakage in the module namespace.
        "assert not hasattr(core, 'ida_hexrays')\n"
        "print('OK')\n"
    )

    env = os.environ.copy()
    # Prepend the project src/ to PYTHONPATH so `import d810...` resolves.
    existing_pp = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        repo_src if not existing_pp else f"{repo_src}{os.pathsep}{existing_pp}"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )

    assert completed.returncode == 0, (
        f"clean-subprocess import of d810.optimizers.core failed "
        f"(returncode={completed.returncode}). Indicates a transitive "
        f"ida_hexrays import was re-introduced.\n"
        f"stdout: {completed.stdout!r}\n"
        f"stderr: {completed.stderr!r}"
    )
    assert "OK" in completed.stdout, (
        f"subprocess did not reach the OK marker.\n"
        f"stdout: {completed.stdout!r}\n"
        f"stderr: {completed.stderr!r}"
    )
