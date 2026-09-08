from __future__ import annotations

import abc

from d810.hexrays.mutation.block_instruction_commit import (
    BlockInstructionBatchCandidate,
)
from d810.hexrays.mutation.instruction_commit import NativeEpoch
from d810.optimizers.microcode.flow.handler import FlowOptimizationRule


class HostedBlockInstructionRule(FlowOptimizationRule, abc.ABC):
    """Flow rule whose instruction writes are owned by the optblock adapter."""

    _d810_hosted_block_instruction_rule = True

    @abc.abstractmethod
    def propose_instruction_batch(
        self,
        block: object,
        *,
        epoch: NativeEpoch,
    ) -> BlockInstructionBatchCandidate | None:
        """Propose a detached instruction batch for one live block callback."""
        raise NotImplementedError

    def optimize(self, block: object) -> int:
        raise RuntimeError(
            "hosted block instruction rules require optblock-owned commit"
        )


__all__ = ["HostedBlockInstructionRule"]
