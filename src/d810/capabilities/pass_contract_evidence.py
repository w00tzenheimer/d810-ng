"""Optional observation sink for published native pass-contract evidence.

The pipeline owns publication; this capability only reports an already-accepted
output to an external observability boundary.  A missing or failed observer
must never change a pass result, scheduling decision, or mutation route.
"""

from __future__ import annotations

from d810.core.typing import Any, Protocol, runtime_checkable

__all__ = ["PassContractEvidenceObserver"]


@runtime_checkable
class PassContractEvidenceObserver(Protocol):
    """Observe one declared contract-evidence output after publication."""

    def observe_contract_evidence(
        self,
        *,
        pass_id: str,
        evidence_token: str,
        function_ea: int,
        producer_stage_id: str,
        publication: Any,
    ) -> None:
        """Persist or forward one already-published, anchored evidence receipt."""
        ...
