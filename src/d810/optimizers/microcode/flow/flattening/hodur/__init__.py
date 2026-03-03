"""Hodur while-loop state machine unflattener — strategy-based pipeline."""
try:
    from d810.optimizers.microcode.flow.flattening.hodur.unflattener import (  # noqa: F401
        HodurUnflattener,
    )
except ImportError:
    # IDA runtime not available (unit-test environment); skip re-export.
    pass
