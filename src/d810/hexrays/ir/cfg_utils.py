"""Backward-compatible re-exports from split cfg_utils modules.

This module has been split into:
- cfg_queries: Read-only CFG topology queries
- mop_utils: Operand/variable helpers
- cfg_verify: Verification and diagnostics
- cfg_mutations: Edge/block mutation functions

All functions remain importable from this module for backward compatibility.
"""
from d810.hexrays.ir.cfg_queries import *  # noqa: F401,F403
from d810.hexrays.ir.mop_utils import *    # noqa: F401,F403
from d810.hexrays.mutation.cfg_verify import *   # noqa: F401,F403
from d810.hexrays.mutation.cfg_mutations import *  # noqa: F401,F403
