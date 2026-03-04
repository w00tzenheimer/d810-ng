"""CFG pass package.

Import pass classes from their concrete modules to avoid package-level
import cycles (e.g. `d810.cfg.transform.dead_block_elimination`).
"""

__all__: list[str] = []
