"""Pattern engine dispatcher — gates between Cython and Python backends.

Follows CythonMode Pattern 1 (module-level gate) established in ast.py.
Exports normalized names so consumers don't care which backend is active.

Environment variables:
    D810_NO_CYTHON=1  — Force Python backend even if Cython is available.

Usage:
    from d810.optimizers.microcode.instructions.pattern_matching.engine import (
        OpcodeIndexedStorage,
        match_pattern_nomut,
        MatchBindings,
        compute_fingerprint,
        PatternFingerprint,
        RulePatternEntry,
    )
"""
from __future__ import annotations

import logging

from d810.core.cymode import CythonMode

logger = logging.getLogger(__name__)

# Always import Python data containers (no perf benefit from Cython for these)
from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
    PatternFingerprint,
    RulePatternEntry,
    compute_fingerprint,
)

# Gate Cython vs Python for performance-critical implementations
if CythonMode().is_enabled():
    try:
        from d810.speedups.optimizers.c_pattern_match import (
            COpcodeIndexedStorage as OpcodeIndexedStorage,
            match_pattern_nomut,
            CMatchBindings as MatchBindings,
        )
        _USING_CYTHON = True
        logger.debug("Pattern engine: using Cython backend")
    except (ModuleNotFoundError, ImportError):
        from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
            OpcodeIndexedStorage,
            match_pattern_nomut,
            MatchBindings,
        )
        _USING_CYTHON = False
        logger.debug("Pattern engine: Cython unavailable, using Python backend")
else:
    from d810.optimizers.microcode.instructions.pattern_matching.pattern_speedups import (
        OpcodeIndexedStorage,
        match_pattern_nomut,
        MatchBindings,
    )
    _USING_CYTHON = False
    logger.debug("Pattern engine: CythonMode disabled, using Python backend")


def get_engine_info() -> dict:
    """Return diagnostic info about the active pattern engine backend."""
    return {
        "backend": "cython" if _USING_CYTHON else "python",
        "cython_mode_enabled": CythonMode().is_enabled(),
        "storage_class": OpcodeIndexedStorage.__qualname__,
        "match_function": match_pattern_nomut.__module__,
    }


# A/B validation mode (D810_PATTERN_ENGINE_VALIDATE) is implemented in PR2
# when the hot-path switchover happens in handler.py. PR1 only provides
# the dispatcher; handler.py continues using legacy PatternStorage.

__all__ = [
    "OpcodeIndexedStorage",
    "match_pattern_nomut",
    "MatchBindings",
    "compute_fingerprint",
    "PatternFingerprint",
    "RulePatternEntry",
    "_USING_CYTHON",
    "get_engine_info",
]
