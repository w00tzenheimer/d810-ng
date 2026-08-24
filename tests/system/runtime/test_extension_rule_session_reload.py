"""Exercise extension rule registration across production package reloads."""

from __future__ import annotations

import importlib
import os
import sys

import pytest

_RELOAD_GATE_ENV = "D810_RELOAD_GATE"
_EGGLOG_RULE_MODULE = "d810_egglog.rules.egglog_optimizer"
_EGGLOG_RULE_NAME = "EgglogOptimizer"


def test_installed_extension_reregisters_after_production_package_reload() -> None:
    """A cached out-of-tree rule must attach to the rebuilt core registry."""
    if os.environ.get(_RELOAD_GATE_ENV) != "1":
        pytest.skip(
            "package reload is standalone-only; set D810_RELOAD_GATE=1 in a "
            "dedicated runner process"
        )
    pytest.importorskip("d810_egglog")

    import d810
    from d810._vendor.ida_reloader import reload_package
    from d810.backends import (
        load_extension_rules,
        prepare_extension_rules_for_core_reload,
    )
    from d810.optimizers.microcode.instructions.handler import (
        InstructionOptimizationRule,
    )

    load_extension_rules()
    assert InstructionOptimizationRule.find(_EGGLOG_RULE_NAME) is not None
    extension_module = sys.modules[_EGGLOG_RULE_MODULE]
    extension_runtime = importlib.import_module("d810_egglog.saturation")
    original_rule_base = InstructionOptimizationRule

    evicted = prepare_extension_rules_for_core_reload()
    assert _EGGLOG_RULE_MODULE in evicted
    assert "d810_egglog.saturation" in evicted
    assert not any(
        name == "d810_egglog" or name.startswith("d810_egglog.")
        for name in sys.modules
    )
    reload_package(
        d810,
        skip=["d810.core.registry", "d810._vendor"],
        suppress_errors=False,
    )

    reloaded_backends = importlib.import_module("d810.backends")
    reloaded_handler = importlib.import_module(
        "d810.optimizers.microcode.instructions.handler"
    )
    reloaded_backends.load_extension_rules()
    reloaded_extension_runtime = importlib.import_module(
        "d810_egglog.saturation"
    )

    assert reloaded_handler.InstructionOptimizationRule is not original_rule_base
    assert sys.modules[_EGGLOG_RULE_MODULE] is not extension_module
    assert reloaded_extension_runtime is not extension_runtime
    reloaded_extension_runtime.assert_current_typed_term_type(
        reloaded_extension_runtime.TypedBvTerm
    )
    rule_class = reloaded_handler.InstructionOptimizationRule.find(
        _EGGLOG_RULE_NAME
    )
    assert rule_class is not None
    assert rule_class().name == _EGGLOG_RULE_NAME
