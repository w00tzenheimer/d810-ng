"""Manager adapter that publishes safe pass-contract evidence receipts."""

from __future__ import annotations

from d810.core.observability import emit as emit_diagnostic
from d810.core.observability_events import PassContractEvidencePublished
from d810.passes.pass_pipeline import ContractEvidencePublication

__all__ = ["SessionPassContractEvidenceObserver"]


class SessionPassContractEvidenceObserver:
    """Bind pass publications to one manager-owned diagnostic session."""

    def __init__(
        self,
        *,
        session_id: str,
        function_ea: int,
        evidence_generation: int,
    ) -> None:
        if not isinstance(session_id, str) or not session_id.strip():
            raise ValueError("pass contract evidence observer requires a session id")
        if int(function_ea) < 0 or int(evidence_generation) < 0:
            raise ValueError("pass contract evidence observer requires non-negative ids")
        self._session_id = session_id
        self._function_ea = int(function_ea)
        self._evidence_generation = int(evidence_generation)

    def observe_contract_evidence(
        self,
        *,
        pass_id: str,
        evidence_token: str,
        function_ea: int,
        producer_stage_id: str,
        publication: object,
    ) -> None:
        """Emit one typed event after the driver has accepted the output."""
        if int(function_ea) != self._function_ea:
            raise ValueError("pass evidence publication belongs to another function")
        if not isinstance(producer_stage_id, str) or not producer_stage_id.strip():
            raise TypeError("pass evidence publication requires a producer stage id")
        if not isinstance(publication, ContractEvidencePublication):
            raise TypeError("pass evidence publication has an invalid receipt")
        emit_diagnostic(
            PassContractEvidencePublished(
                session_id=self._session_id,
                func_ea=self._function_ea,
                evidence_generation=self._evidence_generation,
                maturity=producer_stage_id,
                pass_id=pass_id,
                evidence_token=evidence_token,
                native_anchor_eas=publication.native_anchor_eas,
                summary=publication.summary,
            )
        )
