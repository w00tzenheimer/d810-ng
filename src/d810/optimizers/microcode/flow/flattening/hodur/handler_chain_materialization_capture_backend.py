"""Materialization-capture backend for Hodur handler-chain composition."""
from __future__ import annotations

from dataclasses import dataclass

from d810.cfg.flowgraph import InsnSnapshot
from d810.cfg.materialization_payload import CapturedBlockBody
from d810.core.typing import Protocol
from d810.evaluator.hexrays_microcode.instruction_capture_backend import (
    HexRaysInstructionCaptureBackend,
)
from d810.cfg.state_write_evidence import StateConstantWriteEvidence


@dataclass(frozen=True, slots=True)
class HandlerChainBlockCaptureResult:
    """Typed capture result for one live HCC block body."""

    kind: str
    snapshots: tuple[InsnSnapshot, ...] | None = None
    body: CapturedBlockBody | None = None
    abort_reason: str | None = None
    call_ea: int | None = None
    is_indirect: bool | None = None
    pre_call_count: int | None = None
    post_call_count: int | None = None


class HandlerChainMaterializationCaptureBackend(Protocol):
    """Backend boundary for HCC instruction-body materialization probes."""

    def capture_block_composable_instructions(
        self,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None = None,
        byte_evidence_eas: frozenset[int] = frozenset(),
    ) -> HandlerChainBlockCaptureResult:
        """Capture a composable block body, or classify why capture stops."""

    def block_contains_byte_evidence(
        self,
        mba: object,
        block_serial: int,
        *,
        byte_evidence_eas: frozenset[int],
    ) -> bool:
        """Return whether ``block_serial`` contains any required source EA."""

    def collect_stkvar_reads_in_block(
        self,
        mba: object,
        block_serial: int,
        *,
        skip_jcond_tail: bool = True,
    ) -> frozenset[tuple[int, int]] | None:
        """Collect stack-variable reads for a live block body."""

    def block_mentions_text(
        self,
        mba: object,
        block_serial: int,
        *,
        needle: str,
    ) -> bool:
        """Return whether any live instruction text contains ``needle``."""

    def collect_state_constant_writes(
        self,
        mba: object,
        *,
        state_variable: object | None,
    ) -> tuple[StateConstantWriteEvidence, ...]:
        """Collect constant writes to the dispatcher state variable."""


class HexRaysHandlerChainMaterializationCaptureBackend:
    """Default Hex-Rays materialization-capture backend for HCC."""

    def __init__(
        self,
        capture_backend: HexRaysInstructionCaptureBackend | None = None,
    ) -> None:
        self._capture_backend = (
            capture_backend
            if capture_backend is not None
            else HexRaysInstructionCaptureBackend()
        )

    def _block(self, mba: object, serial: int) -> object | None:
        try:
            return mba.get_mblock(int(serial))  # type: ignore[attr-defined]
        except Exception:
            return None

    def capture_block_composable_instructions(
        self,
        mba: object,
        block_serial: int,
        *,
        state_var_stkoff: int | None = None,
        byte_evidence_eas: frozenset[int] = frozenset(),
    ) -> HandlerChainBlockCaptureResult:
        block = self._block(mba, int(block_serial))
        if block is None:
            return HandlerChainBlockCaptureResult(
                kind="missing_block",
                abort_reason="block_dead",
            )
        backend_result = (
            self._capture_backend.capture_block_composable_instructions_v2(
                block,
                state_var_stkoff=state_var_stkoff,
                byte_evidence_eas=byte_evidence_eas,
            )
        )
        snapshots = (
            self._capture_backend.snapshots_from_body(backend_result.body)
            if backend_result.body is not None
            else None
        )
        return HandlerChainBlockCaptureResult(
            kind=backend_result.kind,
            snapshots=snapshots,
            body=backend_result.body,
            abort_reason=backend_result.abort_reason,
            call_ea=backend_result.call_ea,
            is_indirect=backend_result.is_indirect,
            pre_call_count=backend_result.pre_call_count,
            post_call_count=backend_result.post_call_count,
        )

    def block_contains_byte_evidence(
        self,
        mba: object,
        block_serial: int,
        *,
        byte_evidence_eas: frozenset[int],
    ) -> bool:
        if not byte_evidence_eas:
            return False
        block = self._block(mba, int(block_serial))
        if block is None:
            return False
        insn = getattr(block, "head", None)
        while insn is not None:
            try:
                ea = int(getattr(insn, "ea", 0) or 0)
            except Exception:
                ea = 0
            if ea and ea in byte_evidence_eas:
                return True
            insn = getattr(insn, "next", None)
        return False

    def collect_stkvar_reads_in_block(
        self,
        mba: object,
        block_serial: int,
        *,
        skip_jcond_tail: bool = True,
    ) -> frozenset[tuple[int, int]] | None:
        block = self._block(mba, int(block_serial))
        if block is None:
            return None
        return frozenset(
            self._capture_backend.collect_stkvar_reads_in_block(
                block,
                skip_jcond_tail=skip_jcond_tail,
            )
        )

    def block_mentions_text(
        self,
        mba: object,
        block_serial: int,
        *,
        needle: str,
    ) -> bool:
        if not needle:
            return False
        block = self._block(mba, int(block_serial))
        if block is None:
            return False
        insn = getattr(block, "head", None)
        while insn is not None:
            dstr = getattr(insn, "dstr", None)
            text: str | None = None
            if callable(dstr):
                try:
                    text = dstr()
                except Exception:
                    text = None
            elif isinstance(dstr, str):
                text = dstr
            if text and needle in text:
                return True
            insn = getattr(insn, "next", None)
        return False

    def collect_state_constant_writes(
        self,
        mba: object,
        *,
        state_variable: object | None,
    ) -> tuple[StateConstantWriteEvidence, ...]:
        return self._capture_backend.collect_state_constant_writes(
            mba,
            state_variable=state_variable,
        )


DEFAULT_HODUR_HANDLER_CHAIN_MATERIALIZATION_CAPTURE_BACKEND: HandlerChainMaterializationCaptureBackend = (
    HexRaysHandlerChainMaterializationCaptureBackend()
)


__all__ = [
    "DEFAULT_HODUR_HANDLER_CHAIN_MATERIALIZATION_CAPTURE_BACKEND",
    "HandlerChainBlockCaptureResult",
    "HandlerChainMaterializationCaptureBackend",
    "HexRaysHandlerChainMaterializationCaptureBackend",
]
