"""Backward-compatibility shim — re-exports from hodur package."""
from d810.optimizers.microcode.flow.flattening.hodur.datamodel import (  # noqa: F401
    HandlerPathResult,
    HodurStateMachine,
    Pass0RedirectRecord,
)
try:
    from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (  # noqa: F401
        HodurUnflattener,
    )
except ImportError:
    # IDA runtime not available.
    pass
