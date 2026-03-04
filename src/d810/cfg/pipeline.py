"""PassPipeline orchestrator for running FlowGraphTransform transforms through a CFGBackend.

The pipeline lifts backend state to FlowGraph, runs each pass's transform,
lowers the resulting modifications, verifies, and re-lifts if changes occurred.
"""
from __future__ import annotations

from d810.core.logging import getLogger
from d810.core.typing import Any

from d810.cfg.passes._base import FlowGraphTransform
from d810.cfg.protocol import IRTranslator
from d810.cfg.flowgraph import FlowGraph

logger = getLogger(__name__, default_level=0)  # NOTSET: inherit from parent


class PassPipeline:
    """Run a sequence of FlowGraphTransform transforms through a CFGBackend.

    Usage:
        pipeline = PassPipeline(backend, [pass1, pass2, pass3])
        total_changes = pipeline.run(backend_state)
    """

    def __init__(self, backend: IRTranslator, passes: list[FlowGraphTransform]) -> None:
        self.backend = backend
        self.passes = list(passes)  # defensive copy

    def run(self, backend_state: Any) -> int:
        """Execute all passes against backend_state.

        Returns total count of applied modifications across all passes.
        """
        total = 0
        cfg = self.backend.lift(backend_state)

        for pass_ in self.passes:
            if not pass_.is_applicable(cfg):
                logger.debug("Pass %s not applicable, skipping", pass_.name)
                continue

            mods = pass_.transform(cfg)
            if not mods:
                logger.debug("Pass %s produced no modifications", pass_.name)
                continue

            count = self.backend.lower(mods, backend_state)
            if count <= 0:
                logger.debug("Pass %s: lower returned %d, skipping verify", pass_.name, count)
                continue

            if not self.backend.verify(backend_state):
                logger.warning("Pass %s failed verification, aborting pipeline", pass_.name)
                break  # Stop all further passes - MBA may be corrupted

            # Re-lift only when changes were applied successfully
            cfg = self.backend.lift(backend_state)
            total += count
            logger.debug("Pass %s applied %d modifications (total: %d)", pass_.name, count, total)

        return total

    def __repr__(self) -> str:
        pass_names = [p.name for p in self.passes]
        return f"PassPipeline(backend={self.backend.name!r}, passes={pass_names})"


__all__ = ["PassPipeline"]
