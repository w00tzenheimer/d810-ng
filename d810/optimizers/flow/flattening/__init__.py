from d810.optimizers.flow.flattening.unflattener import Unflattener  # isort:skip
from d810.optimizers.flow.flattening.fix_pred_cond_jump_block import (
    FixPredecessorOfConditionalJumpBlock,
)
from d810.optimizers.flow.flattening.unflattener_badwhile_loop import BadWhileLoop
from d810.optimizers.flow.flattening.unflattener_cf import UnflattenControlFlowRule
from d810.optimizers.flow.flattening.unflattener_fake_jump import UnflattenerFakeJump
from d810.optimizers.flow.flattening.unflattener_indirect import (
    UnflattenerTigressIndirect,
)
from d810.optimizers.flow.flattening.unflattener_switch_case import (
    UnflattenerSwitchCase,
)

UNFLATTENING_BLK_RULES = [
    Unflattener(),
    UnflattenerSwitchCase(),
    UnflattenerTigressIndirect(),
    UnflattenerFakeJump(),
    FixPredecessorOfConditionalJumpBlock(),
    BadWhileLoop(),
    UnflattenControlFlowRule(),
]
