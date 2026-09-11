"""Runtime rollback restores cleanup participants with the ordered rule store."""

from d810.hexrays.hooks.optinsn_adapter import InstructionOptimizerManager
from d810.optimizers.microcode.instructions.handler import InstructionOptimizer


def test_restored_child_cleans_original_providers_and_excludes_replacement():
    calls = []

    class Provider:
        def __init__(self, name):
            self.name = name

        def finalize_provider_observation(self, context, *, accepted, reason):
            calls.append((self.name, accepted, reason))

    optimizer = InstructionOptimizer([], None)
    original_store = optimizer.rules
    first, plain, second = Provider("first"), object(), Provider("second")
    for rule in (first, plain, second):
        optimizer.rules.add(rule)
    snapshot = InstructionOptimizerManager._capture_child_runtime_state(optimizer)
    optimizer.reset_rules()
    optimizer.rules.add(Provider("replacement"))

    InstructionOptimizerManager._restore_child_runtime_state(snapshot)
    optimizer.clear_pending_provider_observation()

    assert calls == [
        ("first", False, "callback_cleanup"),
        ("second", False, "callback_cleanup"),
    ]
    assert optimizer.rules is original_store
    assert tuple(optimizer.rules) == (first, plain, second)
