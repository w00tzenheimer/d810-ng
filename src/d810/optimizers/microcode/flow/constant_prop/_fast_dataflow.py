"""Dataflow module dispatcher - uses Cython speedups if available, otherwise pure Python."""

# Try to import Cython-optimized version first
try:
    from d810.speedups.optimizers.microcode.flow.constant_prop.c_dataflow import (
        cy_extract_assignment,
        cy_get_written_var_name,
        cy_is_constant_stack_assignment,
        cy_rewrite_instruction,
        cy_run_full_pass,
        run_dataflow_cython,
    )
    _USING_CYTHON = True
except ImportError:
    # TODO: Fall back to pure Python implementation if needed
    # For now, raise the import error so we know if Cython is unavailable
    _USING_CYTHON = False
    raise

__all__ = [
    "cy_extract_assignment",
    "cy_get_written_var_name",
    "cy_is_constant_stack_assignment",
    "cy_rewrite_instruction",
    "cy_run_full_pass",
    "run_dataflow_cython",
]
