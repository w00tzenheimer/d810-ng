from __future__ import annotations

import pytest

from d810.analyses.value_flow.dead_store import (
    DeadStoreCandidate,
    DeadStoreEvidence,
    DeadStoreRejection,
    DeadStoreRejectionReason,
)
from d810.ir.storage_identity import StorageIdentity, StorageIdentityKind


def _candidate(*, width: int = 8) -> DeadStoreCandidate:
    return DeadStoreCandidate(
        block_serial=3,
        block_start_ea=0x401000,
        insn_ea=0x401020,
        ordinal=2,
        opcode=0x55,
        destination=StorageIdentity(StorageIdentityKind.REGISTER, 7),
        destination_width=width,
    )


def test_dead_store_candidate_requires_positive_width() -> None:
    with pytest.raises(ValueError, match="destination_width"):
        _candidate(width=0)


def test_dead_store_candidate_rejects_non_scalar_storage() -> None:
    with pytest.raises(ValueError, match="register or stack"):
        DeadStoreCandidate(
            block_serial=3,
            block_start_ea=0x401000,
            insn_ea=0x401020,
            ordinal=2,
            opcode=0x55,
            destination=StorageIdentity(StorageIdentityKind.GLOBAL, 0x500000),
            destination_width=8,
        )


def test_dead_store_evidence_preserves_stable_rejection_codes() -> None:
    rejection = DeadStoreRejection(
        block_serial=3,
        block_start_ea=0x401000,
        insn_ea=0x401020,
        reason=DeadStoreRejectionReason.REACHED_USE,
        detail="blk4@0x401100",
    )

    evidence = DeadStoreEvidence(
        candidates=(_candidate(),),
        rejections=(rejection,),
        authoritative=True,
    )

    assert evidence.rejections[0].reason.value == "reached_use"
    assert evidence.candidates[0].destination.key == "r7"
    assert evidence.authoritative is True
