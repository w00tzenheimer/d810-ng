"""IDA-independent native versus D810 comparison evidence service."""

from __future__ import annotations

import dataclasses
import hashlib
import time
from collections.abc import Callable

from d810.manager.workbench_models import (
    ArtifactFreshness,
    BaselineRef,
    ComparisonMetric,
    D810OutputRef,
    WorkbenchComparisonSnapshot,
)


@dataclasses.dataclass(frozen=True, slots=True)
class ComparisonIdentity:
    """Complete identity required before two pseudocode artifacts are comparable."""

    function_ea: int
    function_fingerprint: str | None
    decompilation_generation: int
    idb_identity: str
    type_generation: str
    hexrays_version: str
    runtime_path: str
    runtime_pass_ids: tuple[str, ...]
    runtime_generation: int


def _normalize_pseudocode(pseudocode: str) -> str:
    normalized = str(pseudocode).replace("\r\n", "\n").replace("\r", "\n")
    if not normalized:
        return ""
    return normalized.rstrip("\n") + "\n"


def _content_sha256(pseudocode: str) -> str:
    digest = hashlib.sha256(pseudocode.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def function_byte_fingerprint(content: bytes) -> str:
    """Return the stable fingerprint format used by workbench function identity."""
    digest = hashlib.sha256(bytes(content)).hexdigest()
    return f"sha256:{digest}"


def _missing_baseline(function_ea: int) -> BaselineRef:
    return BaselineRef(
        available=False,
        fingerprint=None,
        path=None,
        generation=None,
        function_ea=int(function_ea),
    )


def _missing_output(function_ea: int) -> D810OutputRef:
    return D810OutputRef(
        available=False,
        fingerprint=None,
        path=None,
        generation=None,
        function_ea=int(function_ea),
    )


def _common_stale_reasons(
    artifact: BaselineRef | D810OutputRef,
    current: ComparisonIdentity,
) -> tuple[str, ...]:
    checks = (
        (artifact.function_ea != current.function_ea, "Function address changed"),
        (
            artifact.fingerprint != current.function_fingerprint,
            "Function fingerprint changed",
        ),
        (
            artifact.generation != current.decompilation_generation,
            "Decompilation generation changed",
        ),
        (artifact.idb_identity != current.idb_identity, "IDB identity changed"),
        (
            artifact.type_generation != current.type_generation,
            "Type generation changed",
        ),
        (
            artifact.hexrays_version != current.hexrays_version,
            "Hex-Rays version changed",
        ),
    )
    return tuple(reason for changed, reason in checks if changed)


class WorkbenchComparisonService:
    """Store and compare immutable per-function pseudocode evidence."""

    def __init__(self, *, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._baselines: dict[int, BaselineRef] = {}
        self._outputs: dict[int, D810OutputRef] = {}

    def capture_baseline(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> BaselineRef:
        normalized = _normalize_pseudocode(pseudocode)
        baseline = BaselineRef(
            available=True,
            fingerprint=identity.function_fingerprint,
            path=None,
            generation=identity.decompilation_generation,
            function_ea=identity.function_ea,
            idb_identity=identity.idb_identity,
            type_generation=identity.type_generation,
            hexrays_version=identity.hexrays_version,
            captured_at=float(self._clock()),
            pseudocode=normalized,
            line_count=len(normalized.splitlines()),
            character_count=len(normalized),
            content_sha256=_content_sha256(normalized),
        )
        self._baselines[int(identity.function_ea)] = baseline
        return baseline

    def capture_d810_output(
        self,
        identity: ComparisonIdentity,
        pseudocode: str,
    ) -> D810OutputRef:
        normalized = _normalize_pseudocode(pseudocode)
        output = D810OutputRef(
            available=True,
            fingerprint=identity.function_fingerprint,
            path=None,
            generation=identity.decompilation_generation,
            function_ea=identity.function_ea,
            idb_identity=identity.idb_identity,
            type_generation=identity.type_generation,
            hexrays_version=identity.hexrays_version,
            captured_at=float(self._clock()),
            pseudocode=normalized,
            line_count=len(normalized.splitlines()),
            character_count=len(normalized),
            content_sha256=_content_sha256(normalized),
            runtime_path=identity.runtime_path,
            runtime_pass_ids=identity.runtime_pass_ids,
            runtime_generation=identity.runtime_generation,
        )
        self._outputs[int(identity.function_ea)] = output
        return output

    def refs(self, function_ea: int) -> tuple[BaselineRef, D810OutputRef]:
        function_ea = int(function_ea)
        return (
            self._baselines.get(function_ea, _missing_baseline(function_ea)),
            self._outputs.get(function_ea, _missing_output(function_ea)),
        )

    def compare(self, current: ComparisonIdentity) -> WorkbenchComparisonSnapshot:
        baseline, output = self.refs(current.function_ea)
        if baseline.available:
            baseline_reasons = _common_stale_reasons(baseline, current)
            baseline_freshness = (
                ArtifactFreshness.STALE
                if baseline_reasons
                else ArtifactFreshness.CURRENT
            )
        else:
            baseline_reasons = ("Native baseline has not been captured",)
            baseline_freshness = ArtifactFreshness.MISSING

        if output.available:
            output_reasons = _common_stale_reasons(output, current)
            runtime_checks = (
                (output.runtime_path != current.runtime_path, "Runtime path changed"),
                (
                    output.runtime_pass_ids != current.runtime_pass_ids,
                    "Runtime pass IDs changed",
                ),
                (
                    output.runtime_generation != current.runtime_generation,
                    "Runtime generation changed",
                ),
            )
            output_reasons += tuple(
                reason for changed, reason in runtime_checks if changed
            )
            output_freshness = (
                ArtifactFreshness.STALE if output_reasons else ArtifactFreshness.CURRENT
            )
        else:
            output_reasons = ("D810 output has not been captured",)
            output_freshness = ArtifactFreshness.MISSING

        both_current = (
            baseline_freshness is ArtifactFreshness.CURRENT
            and output_freshness is ArtifactFreshness.CURRENT
        )
        if both_current:
            text_changed: bool | None = baseline.pseudocode != output.pseudocode
            metrics = (
                ComparisonMetric(
                    name="Lines",
                    native_value=baseline.line_count,
                    d810_value=output.line_count,
                    delta=output.line_count - baseline.line_count,
                ),
                ComparisonMetric(
                    name="Characters",
                    native_value=baseline.character_count,
                    d810_value=output.character_count,
                    delta=output.character_count - baseline.character_count,
                ),
            )
        else:
            text_changed = None
            metrics = ()

        return WorkbenchComparisonSnapshot(
            function_ea=current.function_ea,
            baseline=baseline,
            d810_output=output,
            baseline_freshness=baseline_freshness,
            d810_freshness=output_freshness,
            baseline_stale_reasons=baseline_reasons,
            d810_stale_reasons=output_reasons,
            text_changed=text_changed,
            metrics=metrics,
        )


__all__ = [
    "ComparisonIdentity",
    "WorkbenchComparisonService",
    "function_byte_fingerprint",
]
