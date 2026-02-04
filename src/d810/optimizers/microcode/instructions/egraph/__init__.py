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

# from d810.optimizers.microcode.instructions.egraph.handler import (
#     PatternOptimizer2,
# )

# Alias for clarity
# CanonicalPatternOptimizer = PatternOptimizer2

# __all__ = ["PatternOptimizer2", "CanonicalPatternOptimizer"]
