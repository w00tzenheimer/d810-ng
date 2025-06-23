from d810.utils import get_all_subclasses  # isort: skip
from d810.optimizers.instructions.peephole.handler import (  # isort: skip
    PeepholeOptimizer,
    PeepholeSimplificationRule,
)
from d810.optimizers.instructions.peephole.fold_const import *

PEEPHOLE_RULES = [x() for x in get_all_subclasses(PeepholeSimplificationRule)]
