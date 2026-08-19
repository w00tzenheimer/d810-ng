"""An extension's rules must register BEFORE the known-rule catalogue is built.

``D810State.load()`` snapshots ``InstructionOptimizationRule.registry`` into
``known_ins_rules``, and ``load_project`` activates a rule only when a
configured rule name matches an entry in that snapshot.  Rules contributed by
an installed extension are imported by ``load_extension_rules()``, which used
to run only from ``manager.start()`` -- 88 ms *after* the snapshot, measured on
a live dump::

    45,037  Instruction rules configured                     <- snapshot + match
    45,041  Starting manager...
    45,125  extension rule module loaded: d810_cobra...      <- too late

So ``CobraSolveRule`` never reached the catalogue, never matched its config,
and never had ``configure()`` called.  The pass was configured, routed and
silently inert -- indistinguishable from a solver that ran and found nothing.

Deliberately independent of any real extension: the fixture below contributes
its own rule module, so this measures the ordering rather than whether
d810-cobra happens to be installed.

IDA-dependent (``D810State`` pulls in the live manager) -> system/runtime.
"""

from __future__ import annotations

import sys
import textwrap

import pytest

RULE_NAME = "FakeExtensionOrderingRule"
MODULE_NAME = "d810_fake_ext_ordering_rule"

SOURCE = textwrap.dedent(
    '''
    """Stand-in for a rule shipped inside an installed extension."""

    from d810.optimizers.microcode.instructions.peephole.handler import (
        PeepholeSimplificationRule,
    )


    class FakeExtensionOrderingRule(PeepholeSimplificationRule):
        DESCRIPTION = "Test-only rule contributed by a fake extension"
        CATEGORY = "Testing"

        def check_and_replace(self, blk, ins):
            return None
    '''
)


@pytest.fixture
def contributed_rule_module(tmp_path, monkeypatch):
    """Make one rule module reachable only through ``rule_modules()``.

    The module lives outside ``d810.optimizers.__path__`` on purpose: that is
    precisely the reach the package scan does not have, which is why extensions
    need ``load_extension_rules()`` at all.
    """
    (tmp_path / f"{MODULE_NAME}.py").write_text(SOURCE, encoding="utf-8")
    monkeypatch.syspath_prepend(str(tmp_path))

    import d810.backends as backends

    real_registry = backends.registry()

    class _Contributing:
        def __getattr__(self, item):
            return getattr(real_registry, item)

        def rule_modules(self):
            return (*real_registry.rule_modules(), MODULE_NAME)

    monkeypatch.setattr(backends, "registry", lambda: _Contributing())
    yield MODULE_NAME

    sys.modules.pop(MODULE_NAME, None)
    from d810.optimizers.microcode.instructions.handler import (
        InstructionOptimizationRule,
    )

    InstructionOptimizationRule.registry.pop(RULE_NAME.lower(), None)


def test_the_catalogue_includes_a_rule_only_an_extension_contributes(
    d810_state, contributed_rule_module
) -> None:
    """The regression: the rule exists, but the catalogue was built too early."""
    with d810_state() as state:
        catalogue = state._build_known_instruction_rules()

    assert RULE_NAME in {rule.name for rule in catalogue}


def test_building_the_catalogue_imports_extension_rule_modules(
    d810_state, contributed_rule_module
) -> None:
    """Building the catalogue is what pulls the extension's module in."""
    sys.modules.pop(contributed_rule_module, None)

    with d810_state() as state:
        state._build_known_instruction_rules()

    assert contributed_rule_module in sys.modules


def test_the_catalogue_still_contains_in_tree_rules(d810_state) -> None:
    """Loading extension rules must not replace the in-tree catalogue."""
    with d810_state() as state:
        names = {rule.name for rule in state._build_known_instruction_rules()}

    assert "FoldReadonlyDataRule" in names
    assert len(names) > 10


def test_the_contributed_rule_is_registered_exactly_once(
    d810_state, contributed_rule_module
) -> None:
    """Both catalogue builders load extension rules; neither may double-register.

    ``load()`` builds the instruction and block catalogues, and each ensures
    extension rules are present.  Were that import not idempotent, the rule
    would appear twice and the activation loop would append two instances --
    running it twice per instruction.

    Deliberately not asserting global name uniqueness: 7 names are already
    contributed by BOTH ``InstructionOptimizationRule.registry`` and
    ``adapt_rules(VerifiableRule.instantiate_all())`` (Add_SpecialConstantRule_1
    through _3, Add_OllvmRule_1, _2, AddXor_Rule_1, _2), which predates this
    change and is tracked separately.
    """
    with d810_state() as state:
        state._build_known_block_rules()
        names = [rule.name for rule in state._build_known_instruction_rules()]

    assert names.count(RULE_NAME) == 1
