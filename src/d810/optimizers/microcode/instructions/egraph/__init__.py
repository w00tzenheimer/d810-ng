"""E-Graph based optimizers for IDA microcode.

This package provides two approaches to e-graph style optimization:

1. **Canonical E-Graph** (handler.py): Uses AST canonicalization to achieve
   similar effects to e-graphs. Flattens commutative operators and sorts
   operands to get a canonical form. Class: PatternOptimizer2

2. **Egglog E-Graph** (egglog_handler.py): Uses actual equality saturation
   via the egglog library. More powerful but requires egglog to be installed.
   Class: EgglogOptimizer

The canonical approach is always available. The egglog approach requires:
    pip install egglog cloudpickle
"""

# Deferred imports: PatternOptimizer2 and EgglogOptimizer depend on
# ida_hexrays which is only available inside IDA Pro.  Importing them at
# package level would cause ImportError in headless / testing environments.
# Consumers should import directly from the submodules instead:
#
#   from d810.optimizers.microcode.instructions.egraph.handler import PatternOptimizer2
#   from d810.optimizers.microcode.instructions.egraph.egglog_handler import EgglogOptimizer
