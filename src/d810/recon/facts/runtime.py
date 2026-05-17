"""Runtime coordinator for maturity fact collection.

Phase 2 intentionally starts with an empty collector registry.  The important
contract is that D810 can invoke this runtime at several maturities without
changing behavior; later collectors plug into the same API.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.core.logging import getLogger
from d810.core.settings import get_settings
from d810.core.typing import Any, Callable, Protocol, runtime_checkable
from d810.recon.facts.model import (
    FactConflict,
    FactMapping,
    FactObservation,
    FactStatus,
    ValidatedFactView,
)

logger = getLogger("D810.recon.facts.runtime")

_GENERIC_LIFECYCLE_FACT_KINDS = frozenset({
    "ByteEmitCorridorFact",
    "CallAnchorFact",
    "ReturnFrontierFact",
    "ZeroBlobFact",
})

FactPersistenceCallback = Callable[
    [
        # SnapshotRef | None (forward-typed; see d810.core.observability)
        Any,
        int,
        tuple[FactObservation, ...],
        tuple[FactMapping, ...],
        tuple[FactConflict, ...],
    ],
    None,
]


@runtime_checkable
class FactCollector(Protocol):
    """Protocol for maturity fact collectors."""

    name: str
    fact_kinds: frozenset[str]
    maturities: frozenset[int] | None

    def collect(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str,
    ) -> "FactCollectionResult | tuple[FactObservation, ...]":
        """Collect observations from the current maturity."""
        ...


@dataclass(frozen=True)
class FactCollectionResult:
    """Collector result containing observations and lifecycle mappings."""

    observations: tuple[FactObservation, ...] = ()
    mappings: tuple[FactMapping, ...] = ()
    conflicts: tuple[FactConflict, ...] = ()


@dataclass(frozen=True)
class FactCaptureSummary:
    """One invocation result for the fact lifecycle runtime."""

    func_ea: int
    maturity: int
    phase: str
    enabled: bool
    invoked: bool
    collector_count: int = 0
    observation_count: int = 0
    mapping_count: int = 0
    conflict_count: int = 0
    reason: str = ""


class FactLifecycleRuntime:
    """Empty-registry maturity fact runtime."""

    def __init__(
        self,
        *,
        persistence_callback: FactPersistenceCallback | None = None,
    ) -> None:
        self._collectors: list[FactCollector] = []
        self._fired: set[tuple[int, int, str]] = set()
        self._persistence_callback = persistence_callback
        self._observations_by_func: dict[int, list[FactObservation]] = {}
        self._mappings_by_func: dict[int, list[FactMapping]] = {}
        self._last_observations_by_func: dict[int, dict[str, FactObservation]] = {}

    @property
    def collector_count(self) -> int:
        return len(self._collectors)

    def reset_for_func(self, func_ea: int) -> None:
        self._fired = {key for key in self._fired if key[0] != func_ea}
        self._observations_by_func.pop(func_ea, None)
        self._mappings_by_func.pop(func_ea, None)
        self._last_observations_by_func.pop(func_ea, None)

    def register(self, collector: FactCollector) -> None:
        for existing in self._collectors:
            if existing.name == collector.name:
                raise ValueError(f"FactCollector '{collector.name}' already registered")
        self._collectors.append(collector)
        logger.debug("Registered fact collector: %s", collector.name)

    @staticmethod
    def _collector_runs_at_maturity(
        collector: FactCollector,
        maturity: int,
    ) -> bool:
        return collector.maturities is None or maturity in collector.maturities

    @staticmethod
    def _normalize_result(
        result: FactCollectionResult | tuple[FactObservation, ...],
    ) -> FactCollectionResult:
        if isinstance(result, FactCollectionResult):
            return result
        return FactCollectionResult(observations=tuple(result))

    @staticmethod
    def _maturity_text(maturity: int) -> str:
        try:
            import ida_hexrays  # type: ignore

            names = (
                "MMAT_GENERATED",
                "MMAT_PREOPTIMIZED",
                "MMAT_LOCOPT",
                "MMAT_CALLS",
                "MMAT_GLBOPT1",
                "MMAT_GLBOPT2",
                "MMAT_GLBOPT3",
                "MMAT_LVARS",
            )
            for name in names:
                if int(getattr(ida_hexrays, name)) == int(maturity):
                    return name
        except Exception:
            pass
        return f"MMAT_{int(maturity)}"

    @staticmethod
    def _maturity_rank(maturity: int | str) -> int:
        names = (
            "MMAT_GENERATED",
            "MMAT_PREOPTIMIZED",
            "MMAT_LOCOPT",
            "MMAT_CALLS",
            "MMAT_GLBOPT1",
            "MMAT_GLBOPT2",
            "MMAT_GLBOPT3",
            "MMAT_LVARS",
        )
        if isinstance(maturity, int):
            maturity_text = FactLifecycleRuntime._maturity_text(maturity)
        else:
            maturity_text = str(maturity)
        if maturity_text in names:
            return names.index(maturity_text)
        if maturity_text.startswith("MMAT_"):
            suffix = maturity_text.removeprefix("MMAT_")
            if suffix.isdigit():
                resolved = FactLifecycleRuntime._maturity_text(int(suffix))
                if resolved != maturity_text:
                    return FactLifecycleRuntime._maturity_rank(resolved)
                return int(suffix)
        return len(names)

    def validated_view(self, func_ea: int, maturity: int | str) -> ValidatedFactView:
        """Return the validated fact view for one function as of ``maturity``.

        Earlier facts carry forward into later maturities, but later mappings do
        not contaminate historical views.  Consumers should use
        ``active_observations`` rather than raw observations so stale,
        contradicted, superseded, and identity-lost facts are filtered.
        """
        maturity_text = (
            maturity if isinstance(maturity, str) else self._maturity_text(maturity)
        )
        rank = self._maturity_rank(maturity_text)
        observations = tuple(
            observation
            for observation in self._observations_by_func.get(func_ea, ())
            if self._maturity_rank(observation.maturity) <= rank
        )
        mappings = tuple(
            mapping
            for mapping in self._mappings_by_func.get(func_ea, ())
            if self._maturity_rank(mapping.target_maturity) <= rank
        )
        return ValidatedFactView(
            maturity=maturity_text,
            observations=observations,
            mappings=mappings,
        )

    @staticmethod
    def _stale_mapping_count(view: ValidatedFactView) -> int:
        stale_statuses = {
            FactStatus.REMAPPED,
            FactStatus.STALE,
            FactStatus.CONTRADICTED,
            FactStatus.SUPERSEDED,
            FactStatus.IDENTITY_LOST,
        }
        return sum(1 for mapping in view.mappings if mapping.status in stale_statuses)

    @staticmethod
    def _induction_continuity_key(
        observation: FactObservation,
    ) -> tuple[int, str] | None:
        if observation.kind != "InductionCarrierFact":
            return None
        if observation.source_block is None or not observation.mop_signature:
            return None
        return (int(observation.source_block), str(observation.mop_signature))

    @staticmethod
    def _induction_source_ea_key(
        observation: FactObservation,
    ) -> tuple[int, str] | None:
        if observation.kind != "InductionCarrierFact":
            return None
        if observation.source_ea is None or not observation.mop_signature:
            return None
        return (int(observation.source_ea), str(observation.mop_signature))

    def _derive_induction_lifecycle(
        self,
        func_ea: int,
        *,
        maturity: int,
        current_observations: tuple[FactObservation, ...],
        current_mappings: tuple[FactMapping, ...],
    ) -> tuple[tuple[FactMapping, ...], tuple[FactConflict, ...]]:
        current_induction = tuple(
            observation
            for observation in current_observations
            if observation.kind == "InductionCarrierFact"
        )
        current_induction_fact_ids = {
            observation.fact_id
            for observation in current_induction
        }
        current_by_continuity: dict[tuple[int, str], list[FactObservation]] = {}
        current_by_source_ea: dict[tuple[int, str], list[FactObservation]] = {}
        for observation in current_induction:
            key = self._induction_continuity_key(observation)
            if key is not None:
                current_by_continuity.setdefault(key, []).append(observation)
            source_ea_key = self._induction_source_ea_key(observation)
            if source_ea_key is not None:
                current_by_source_ea.setdefault(source_ea_key, []).append(observation)

        mappings: list[FactMapping] = []
        conflicts: list[FactConflict] = []
        maturity_text = self._maturity_text(maturity)
        maturity_rank = self._maturity_rank(maturity_text)
        existing_mapping_keys = {
            (
                mapping.source_fact_id,
                self._maturity_rank(mapping.target_maturity),
            )
            for mapping in (*self._mappings_by_func.get(func_ea, ()), *current_mappings)
        }

        seen_conflict_ids: set[str] = set()

        def _add_conflict(
            left: FactObservation,
            right: FactObservation,
            *,
            continuity_key: tuple[int, str],
            reason: str,
        ) -> None:
            first, second = sorted((left.fact_id, right.fact_id))
            conflict_id = (
                f"induction-identity:{maturity_text}:"
                f"blk={continuity_key[0]}:mop={continuity_key[1]}:"
                f"{first}:{second}"
            )
            if conflict_id in seen_conflict_ids:
                return
            seen_conflict_ids.add(conflict_id)
            conflicts.append(
                FactConflict(
                    conflict_id=conflict_id,
                    fact_id=first,
                    other_fact_id=second,
                    maturity=maturity_text,
                    conflict_kind="INCOMPATIBLE_INDUCTION_IDENTITY",
                    reason=reason,
                    payload={
                        "continuity_block": continuity_key[0],
                        "continuity_mop_signature": continuity_key[1],
                        "left_semantic_key": left.semantic_key,
                        "right_semantic_key": right.semantic_key,
                    },
                )
            )

        def _add_source_ea_conflict(
            left: FactObservation,
            right: FactObservation,
            *,
            source_ea_key: tuple[int, str],
            reason: str,
        ) -> None:
            first, second = sorted((left.fact_id, right.fact_id))
            conflict_id = (
                f"induction-identity:{maturity_text}:"
                f"ea=0x{source_ea_key[0]:x}:mop={source_ea_key[1]}:"
                f"{first}:{second}"
            )
            if conflict_id in seen_conflict_ids:
                return
            seen_conflict_ids.add(conflict_id)
            conflicts.append(
                FactConflict(
                    conflict_id=conflict_id,
                    fact_id=first,
                    other_fact_id=second,
                    maturity=maturity_text,
                    conflict_kind="INCOMPATIBLE_INDUCTION_IDENTITY",
                    reason=reason,
                    payload={
                        "continuity_source_ea": source_ea_key[0],
                        "continuity_mop_signature": source_ea_key[1],
                        "left_semantic_key": left.semantic_key,
                        "right_semantic_key": right.semantic_key,
                    },
                )
            )

        for continuity_key, observations in current_by_continuity.items():
            by_semantic: dict[str, list[FactObservation]] = {}
            for observation in observations:
                by_semantic.setdefault(observation.semantic_key, []).append(observation)
            if len(by_semantic) <= 1:
                continue
            for index, left in enumerate(observations):
                for right in observations[index + 1:]:
                    if left.semantic_key == right.semantic_key:
                        continue
                    _add_conflict(
                        left,
                        right,
                        continuity_key=continuity_key,
                        reason=(
                            "InductionCarrierFact observations share block/mop "
                            "continuity but claim different semantic keys"
                        ),
                    )

        for observation in self._observations_by_func.get(func_ea, ()):
            if observation.kind != "InductionCarrierFact":
                continue
            if self._maturity_rank(observation.maturity) >= maturity_rank:
                continue
            if observation.fact_id in current_induction_fact_ids:
                continue
            mapping_key = (observation.fact_id, self._maturity_rank(maturity_text))
            if mapping_key in existing_mapping_keys:
                continue

            continuity_key = self._induction_continuity_key(observation)
            remap_target: FactObservation | None = None
            remap_reason = (
                "InductionCarrierFact identity remapped by stable "
                "block/mop continuity"
            )
            contradicted_by: list[FactObservation] = []
            if continuity_key is not None:
                continuity_candidates = list(
                    current_by_continuity.get(continuity_key, ())
                )
                candidates = [
                    candidate
                    for candidate in continuity_candidates
                    if candidate.semantic_key == observation.semantic_key
                ]
                contradicted_by = [
                    candidate
                    for candidate in continuity_candidates
                    if candidate.semantic_key != observation.semantic_key
                ]
                for candidate in contradicted_by:
                    _add_conflict(
                        observation,
                        candidate,
                        continuity_key=continuity_key,
                        reason=(
                            "Prior InductionCarrierFact block/mop continuity "
                            "survived under a different semantic key"
                        ),
                    )
                if len(candidates) == 1:
                    remap_target = candidates[0]
                elif len(candidates) > 1:
                    for candidate in candidates:
                        _add_conflict(
                            observation,
                            candidate,
                            continuity_key=continuity_key,
                            reason=(
                                "Multiple current InductionCarrierFact observations "
                                "match one prior block/mop continuity key"
                            ),
                        )

            if remap_target is None and not contradicted_by:
                source_ea_key = self._induction_source_ea_key(observation)
                if source_ea_key is not None:
                    source_ea_all_candidates = tuple(
                        current_by_source_ea.get(source_ea_key, ())
                    )
                    source_ea_contradicted_by = [
                        candidate
                        for candidate in source_ea_all_candidates
                        if candidate.semantic_key != observation.semantic_key
                    ]
                    for candidate in source_ea_contradicted_by:
                        _add_source_ea_conflict(
                            observation,
                            candidate,
                            source_ea_key=source_ea_key,
                            reason=(
                                "Prior InductionCarrierFact source-EA/mop continuity "
                                "survived under a different semantic key"
                            ),
                        )
                    contradicted_by = source_ea_contradicted_by
                    source_ea_candidates = [
                        candidate
                        for candidate in source_ea_all_candidates
                        if candidate.semantic_key == observation.semantic_key
                    ]
                    if len(source_ea_candidates) == 1:
                        remap_target = source_ea_candidates[0]
                        remap_reason = (
                            "InductionCarrierFact identity remapped by stable "
                            "source-EA/mop continuity"
                        )
                    elif len(source_ea_candidates) > 1 and continuity_key is not None:
                        for candidate in source_ea_candidates:
                            _add_conflict(
                                observation,
                                candidate,
                                continuity_key=continuity_key,
                                reason=(
                                    "Multiple current InductionCarrierFact observations "
                                    "match one prior source-EA/mop continuity key"
                                ),
                            )

            if remap_target is not None:
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.REMAPPED,
                        confidence=min(0.9, observation.confidence, remap_target.confidence),
                        target_fact_id=remap_target.fact_id,
                        target_block=remap_target.source_block,
                        target_ea=remap_target.source_ea,
                        target_mop_signature=remap_target.mop_signature,
                        reason=remap_reason,
                        payload={
                            "kind": observation.kind,
                            "semantic_key": observation.semantic_key,
                            "source_fact_id": observation.fact_id,
                            "source_block": observation.source_block,
                            "source_ea": observation.source_ea,
                            "source_mop_signature": observation.mop_signature,
                            "target_fact_id": remap_target.fact_id,
                            "target_block": remap_target.source_block,
                            "target_ea": remap_target.source_ea,
                            "target_mop_signature": remap_target.mop_signature,
                        },
                    )
                )
                continue

            if contradicted_by:
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.CONTRADICTED,
                        confidence=min(
                            0.85,
                            observation.confidence,
                            max(candidate.confidence for candidate in contradicted_by),
                        ),
                        reason=(
                            "InductionCarrierFact block/mop continuity survived "
                            "with an incompatible semantic key"
                        ),
                        payload={
                            "kind": observation.kind,
                            "semantic_key": observation.semantic_key,
                            "source_fact_id": observation.fact_id,
                            "source_block": observation.source_block,
                            "source_ea": observation.source_ea,
                            "source_mop_signature": observation.mop_signature,
                            "conflicting_fact_ids": [
                                candidate.fact_id for candidate in contradicted_by
                            ],
                            "conflicting_semantic_keys": sorted({
                                candidate.semantic_key
                                for candidate in contradicted_by
                            }),
                        },
                    )
                )
                continue

            mappings.append(
                FactMapping(
                    source_fact_id=observation.fact_id,
                    source_maturity=observation.maturity,
                    target_maturity=maturity_text,
                    status=FactStatus.IDENTITY_LOST,
                    confidence=0.75,
                    reason=(
                        "InductionCarrierFact observation observed at an earlier "
                        "maturity but absent from this maturity's collection"
                    ),
                    payload={
                        "kind": observation.kind,
                        "semantic_key": observation.semantic_key,
                        "source_fact_id": observation.fact_id,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "source_mop_signature": observation.mop_signature,
                    },
                )
            )
        return tuple(mappings), tuple(conflicts)

    def _derive_return_carrier_lifecycle(
        self,
        func_ea: int,
        *,
        target: Any,
        maturity: int,
        current_observations: tuple[FactObservation, ...],
        current_mappings: tuple[FactMapping, ...],
    ) -> tuple[FactMapping, ...]:
        current_fact_ids = {
            observation.fact_id
            for observation in current_observations
            if observation.kind == "ReturnCarrierFact"
        }
        maturity_text = self._maturity_text(maturity)
        maturity_rank = self._maturity_rank(maturity_text)
        existing_mapping_keys = {
            (
                mapping.source_fact_id,
                self._maturity_rank(mapping.target_maturity),
            )
            for mapping in (*self._mappings_by_func.get(func_ea, ()), *current_mappings)
        }

        mappings: list[FactMapping] = []
        for observation in self._observations_by_func.get(func_ea, ()):
            if observation.kind != "ReturnCarrierFact":
                continue
            if self._maturity_rank(observation.maturity) >= maturity_rank:
                continue
            if observation.fact_id in current_fact_ids:
                continue
            mapping_key = (observation.fact_id, maturity_rank)
            if mapping_key in existing_mapping_keys:
                continue
            target_block = self._find_block_for_ea(target, observation.source_ea)
            mappings.append(
                FactMapping(
                    source_fact_id=observation.fact_id,
                    source_maturity=observation.maturity,
                    target_maturity=maturity_text,
                    status=FactStatus.IDENTITY_LOST,
                    confidence=0.72,
                    target_block=target_block,
                    target_ea=observation.source_ea if target_block is not None else None,
                    reason=(
                        "ReturnCarrierFact observation observed at an earlier "
                        "maturity but absent from this maturity's collection"
                    ),
                    payload={
                        "kind": observation.kind,
                        "semantic_key": observation.semantic_key,
                        "source_fact_id": observation.fact_id,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "source_mop_signature": observation.mop_signature,
                        "source_payload": dict(observation.payload or {}),
                    },
                )
            )
        return tuple(mappings)

    @staticmethod
    def _find_block_for_ea(target: Any, ea: int | None) -> int | None:
        if ea is None:
            return None
        try:
            wanted = int(ea)
            qty = int(getattr(target, "qty", 0))
        except (TypeError, ValueError):
            return None
        if qty <= 0:
            return None
        for serial in range(qty):
            try:
                blk = target.get_mblock(serial)
            except Exception:
                continue
            if blk is None:
                continue
            insn = getattr(blk, "head", None)
            seen = 0
            while insn is not None and seen < 10000:
                seen += 1
                try:
                    if int(getattr(insn, "ea", -1)) == wanted:
                        return serial
                except (TypeError, ValueError):
                    pass
                insn = getattr(insn, "next", None)
        return None

    @staticmethod
    def _terminal_byte_emitter_continuity_key(
        observation: FactObservation,
    ) -> tuple[str, int, str] | None:
        if observation.kind != "TerminalByteEmitterFact":
            return None
        if observation.source_ea is None or not observation.mop_signature:
            return None
        return (
            observation.semantic_key,
            int(observation.source_ea),
            str(observation.mop_signature),
        )

    def _derive_terminal_byte_emitter_lifecycle(
        self,
        func_ea: int,
        *,
        maturity: int,
        current_observations: tuple[FactObservation, ...],
        current_mappings: tuple[FactMapping, ...],
    ) -> tuple[FactMapping, ...]:
        current_facts = tuple(
            observation
            for observation in current_observations
            if observation.kind == "TerminalByteEmitterFact"
        )
        current_fact_ids = {observation.fact_id for observation in current_facts}
        current_by_continuity: dict[tuple[str, int, str], list[FactObservation]] = {}
        for observation in current_facts:
            key = self._terminal_byte_emitter_continuity_key(observation)
            if key is not None:
                current_by_continuity.setdefault(key, []).append(observation)

        maturity_text = self._maturity_text(maturity)
        maturity_rank = self._maturity_rank(maturity_text)
        existing_mapping_keys = {
            (
                mapping.source_fact_id,
                self._maturity_rank(mapping.target_maturity),
            )
            for mapping in (*self._mappings_by_func.get(func_ea, ()), *current_mappings)
        }

        mappings: list[FactMapping] = []
        for observation in self._observations_by_func.get(func_ea, ()):
            if observation.kind != "TerminalByteEmitterFact":
                continue
            if self._maturity_rank(observation.maturity) >= maturity_rank:
                continue
            if observation.fact_id in current_fact_ids:
                continue
            mapping_key = (observation.fact_id, maturity_rank)
            if mapping_key in existing_mapping_keys:
                continue

            remap_target: FactObservation | None = None
            continuity_key = self._terminal_byte_emitter_continuity_key(observation)
            if continuity_key is not None:
                candidates = current_by_continuity.get(continuity_key, ())
                if len(candidates) == 1:
                    remap_target = candidates[0]

            if remap_target is not None:
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.REMAPPED,
                        confidence=min(0.82, observation.confidence, remap_target.confidence),
                        target_fact_id=remap_target.fact_id,
                        target_block=remap_target.source_block,
                        target_ea=remap_target.source_ea,
                        target_mop_signature=remap_target.mop_signature,
                        reason=(
                            "TerminalByteEmitterFact remapped by stable "
                            "semantic/source-EA/mop continuity"
                        ),
                        payload={
                            "kind": observation.kind,
                            "semantic_key": observation.semantic_key,
                            "source_fact_id": observation.fact_id,
                            "source_block": observation.source_block,
                            "source_ea": observation.source_ea,
                            "source_mop_signature": observation.mop_signature,
                            "target_fact_id": remap_target.fact_id,
                            "target_block": remap_target.source_block,
                            "target_ea": remap_target.source_ea,
                            "target_mop_signature": remap_target.mop_signature,
                        },
                    )
                )
                continue

            mappings.append(
                FactMapping(
                    source_fact_id=observation.fact_id,
                    source_maturity=observation.maturity,
                    target_maturity=maturity_text,
                    status=FactStatus.IDENTITY_LOST,
                    confidence=0.7,
                    reason=(
                        "TerminalByteEmitterFact observation observed at an "
                        "earlier maturity but absent from this maturity's collection"
                    ),
                    payload={
                        "kind": observation.kind,
                        "semantic_key": observation.semantic_key,
                        "source_fact_id": observation.fact_id,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "source_mop_signature": observation.mop_signature,
                        "byte_index": observation.payload.get("byte_index"),
                    },
                )
            )
        return tuple(mappings)

    @staticmethod
    def _generic_continuity_key(
        observation: FactObservation,
    ) -> tuple[str, str, int, str] | None:
        if observation.kind not in _GENERIC_LIFECYCLE_FACT_KINDS:
            return None
        if observation.source_ea is None or not observation.mop_signature:
            return None
        return (
            observation.kind,
            observation.semantic_key,
            int(observation.source_ea),
            str(observation.mop_signature),
        )

    def _derive_generic_lifecycle(
        self,
        func_ea: int,
        *,
        maturity: int,
        current_observations: tuple[FactObservation, ...],
        current_mappings: tuple[FactMapping, ...],
        ran_fact_kinds: frozenset[str],
    ) -> tuple[FactMapping, ...]:
        active_kinds = _GENERIC_LIFECYCLE_FACT_KINDS & ran_fact_kinds
        if not active_kinds:
            return ()

        current_facts = tuple(
            observation
            for observation in current_observations
            if observation.kind in active_kinds
        )
        current_fact_ids = {observation.fact_id for observation in current_facts}
        current_by_continuity: dict[tuple[str, str, int, str], list[FactObservation]] = {}
        for observation in current_facts:
            key = self._generic_continuity_key(observation)
            if key is not None:
                current_by_continuity.setdefault(key, []).append(observation)

        maturity_text = self._maturity_text(maturity)
        maturity_rank = self._maturity_rank(maturity_text)
        existing_mapping_keys = {
            (
                mapping.source_fact_id,
                self._maturity_rank(mapping.target_maturity),
            )
            for mapping in (*self._mappings_by_func.get(func_ea, ()), *current_mappings)
        }

        mappings: list[FactMapping] = []
        for observation in self._observations_by_func.get(func_ea, ()):
            if observation.kind not in active_kinds:
                continue
            if self._maturity_rank(observation.maturity) >= maturity_rank:
                continue
            if observation.fact_id in current_fact_ids:
                continue
            mapping_key = (observation.fact_id, maturity_rank)
            if mapping_key in existing_mapping_keys:
                continue

            remap_target: FactObservation | None = None
            continuity_key = self._generic_continuity_key(observation)
            if continuity_key is not None:
                candidates = current_by_continuity.get(continuity_key, ())
                if len(candidates) == 1:
                    remap_target = candidates[0]

            if remap_target is not None:
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.REMAPPED,
                        confidence=min(0.8, observation.confidence, remap_target.confidence),
                        target_fact_id=remap_target.fact_id,
                        target_block=remap_target.source_block,
                        target_ea=remap_target.source_ea,
                        target_mop_signature=remap_target.mop_signature,
                        reason=(
                            f"{observation.kind} remapped by stable "
                            "semantic/source-EA/mop continuity"
                        ),
                        payload={
                            "kind": observation.kind,
                            "semantic_key": observation.semantic_key,
                            "source_fact_id": observation.fact_id,
                            "source_block": observation.source_block,
                            "source_ea": observation.source_ea,
                            "source_mop_signature": observation.mop_signature,
                            "target_fact_id": remap_target.fact_id,
                            "target_block": remap_target.source_block,
                            "target_ea": remap_target.source_ea,
                            "target_mop_signature": remap_target.mop_signature,
                        },
                    )
                )
                continue

            mappings.append(
                FactMapping(
                    source_fact_id=observation.fact_id,
                    source_maturity=observation.maturity,
                    target_maturity=maturity_text,
                    status=FactStatus.IDENTITY_LOST,
                    confidence=0.68,
                    reason=(
                        f"{observation.kind} observation observed at an earlier "
                        "maturity but absent from this maturity's collection"
                    ),
                    payload={
                        "kind": observation.kind,
                        "semantic_key": observation.semantic_key,
                        "source_fact_id": observation.fact_id,
                        "source_block": observation.source_block,
                        "source_ea": observation.source_ea,
                        "source_mop_signature": observation.mop_signature,
                    },
                )
            )
        return tuple(mappings)

    @staticmethod
    def _state_write_anchor_continuity_key(
        observation: FactObservation,
    ) -> tuple[int, int, int] | None:
        """Return ``(instruction_ea, block_serial, state_var_stkoff)``
        for a ``StateWriteAnchorFact`` observation, or ``None`` if any
        component is missing.

        This is the cross-maturity correlation key: two observations of
        the same write site at different maturities will share this
        triple but may carry DIFFERENT ``state_const`` payload values
        (which is exactly the rewrite signal we want to surface).
        """
        if observation.kind != "StateWriteAnchorFact":
            return None
        payload = observation.payload or {}
        ea = payload.get("instruction_ea")
        block = payload.get("block_serial")
        stkoff = payload.get("state_var_stkoff")
        if ea is None or block is None or stkoff is None:
            return None
        try:
            return (int(ea), int(block), int(stkoff))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _state_write_anchor_fallback_key(
        observation: FactObservation,
    ) -> tuple[int, int] | None:
        """Return ``(block_serial, state_var_stkoff)`` for fallback
        cross-maturity correlation.

        IDA's MMAT_LOCOPT/MMAT_CALLS pass can REPLACE a state-write
        instruction at a NEW EA (rather than mutating the const in
        place), so the primary EA-based continuity key fails to match.
        For canonical state-var writes (single dispatcher state var
        slot per function), ``(block_serial, state_var_stkoff)`` is
        still a stable identity since the state-var slot itself does
        not move.
        """
        if observation.kind != "StateWriteAnchorFact":
            return None
        payload = observation.payload or {}
        block = payload.get("block_serial")
        stkoff = payload.get("state_var_stkoff")
        if block is None or stkoff is None:
            return None
        try:
            return (int(block), int(stkoff))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _state_write_anchor_const(observation: FactObservation) -> int | None:
        """Return the ``state_const`` (u64) recorded in this observation."""
        if observation.kind != "StateWriteAnchorFact":
            return None
        payload = observation.payload or {}
        raw = payload.get("state_const_u64")
        if raw is None:
            raw = payload.get("state_const")
        if raw is None:
            return None
        try:
            return int(raw) & 0xFFFFFFFFFFFFFFFF
        except (TypeError, ValueError):
            return None

    def _canonical_state_var_stkoff(
        self,
        func_ea: int,
        current_observations: tuple[FactObservation, ...],
    ) -> int | None:
        """Return the canonical state-var stkoff for ``func_ea`` based
        on the mode (most-frequent stkoff) across ALL recorded
        ``StateWriteAnchorFact`` observations.

        Rationale: the dispatcher state variable resides at a single
        stack slot per function and is the most-written stkvar across
        the whole CFG (every handler writes a successor state into
        it). Byte-table writes target many different stkoffs and never
        approach the dominance of the canonical state slot. A simple
        mode is therefore reliable in practice and avoids plumbing a
        dispatcher-detection dependency into the fact runtime.
        """
        counts: dict[int, int] = {}
        observed: tuple[FactObservation, ...] = (
            *self._observations_by_func.get(func_ea, ()),
            *current_observations,
        )
        for obs in observed:
            if obs.kind != "StateWriteAnchorFact":
                continue
            payload = obs.payload or {}
            raw = payload.get("state_var_stkoff")
            if raw is None:
                continue
            try:
                stkoff = int(raw)
            except (TypeError, ValueError):
                continue
            counts[stkoff] = counts.get(stkoff, 0) + 1
        if not counts:
            return None
        # Mode: highest count wins. Tie-breaker: smallest stkoff (more
        # likely the canonical state slot since it tends to be a small
        # 4-byte field rather than an array offset).
        return max(counts.items(), key=lambda kv: (kv[1], -kv[0]))[0]

    def _derive_state_write_anchor_lifecycle(
        self,
        func_ea: int,
        *,
        maturity: int,
        current_observations: tuple[FactObservation, ...],
        current_mappings: tuple[FactMapping, ...],
    ) -> tuple[FactMapping, ...]:
        """Emit ``STATE_CONST_REWRITTEN`` mappings when the same write
        site carries a DIFFERENT ``state_const`` at a later maturity
        than the earliest recorded observation.

        Continuity keys (in priority order):

        1. **Primary**: ``(instruction_ea, block_serial, state_var_stkoff)``
           — applies whenever the EA is stable across maturities (true
           in-place mutation).
        2. **Fallback**: ``(block_serial, state_var_stkoff)`` —
           applies ONLY for the canonical dispatcher state-var slot
           when the primary key did not match. IDA's
           MMAT_LOCOPT/MMAT_CALLS pass can REPLACE the state-write
           instruction at a NEW EA, so EA-based continuity drops the
           rewrite signal. The fallback is gated on
           ``stkoff == canonical_state_var_stkoff`` to avoid mistakenly
           correlating arbitrary stack writes (byte tables, locals)
           between maturities.

        Also emits ``IDENTITY_LOST`` mappings when an earlier write
        site is absent from the current maturity's collection AND
        neither key matched (the write was folded away entirely
        rather than rewritten in place).
        """
        current_facts = tuple(
            observation
            for observation in current_observations
            if observation.kind == "StateWriteAnchorFact"
        )
        current_fact_ids = {observation.fact_id for observation in current_facts}
        current_by_continuity: dict[
            tuple[int, int, int], list[FactObservation]
        ] = {}
        current_by_fallback: dict[
            tuple[int, int], list[FactObservation]
        ] = {}
        for observation in current_facts:
            key = self._state_write_anchor_continuity_key(observation)
            if key is not None:
                current_by_continuity.setdefault(key, []).append(observation)
            fallback = self._state_write_anchor_fallback_key(observation)
            if fallback is not None:
                current_by_fallback.setdefault(fallback, []).append(observation)

        canonical_stkoff = self._canonical_state_var_stkoff(
            func_ea, current_observations
        )

        maturity_text = self._maturity_text(maturity)
        maturity_rank = self._maturity_rank(maturity_text)
        existing_mapping_keys = {
            (
                mapping.source_fact_id,
                self._maturity_rank(mapping.target_maturity),
            )
            for mapping in (*self._mappings_by_func.get(func_ea, ()), *current_mappings)
        }

        mappings: list[FactMapping] = []
        for observation in self._observations_by_func.get(func_ea, ()):
            if observation.kind != "StateWriteAnchorFact":
                continue
            if self._maturity_rank(observation.maturity) >= maturity_rank:
                continue
            mapping_key = (observation.fact_id, maturity_rank)
            if mapping_key in existing_mapping_keys:
                continue

            continuity_key = self._state_write_anchor_continuity_key(observation)
            if continuity_key is None:
                continue
            candidates = current_by_continuity.get(continuity_key, ())
            primary_matched = bool(candidates)

            # Primary key failed -- try fallback for canonical state-var.
            fallback_used = False
            if not primary_matched:
                fallback_key = self._state_write_anchor_fallback_key(observation)
                if (
                    fallback_key is not None
                    and canonical_stkoff is not None
                    and fallback_key[1] == canonical_stkoff
                ):
                    candidates = current_by_fallback.get(fallback_key, ())
                    fallback_used = bool(candidates)

            if not candidates:
                if observation.fact_id in current_fact_ids:
                    # Same fact_id surfaced again -- nothing to record.
                    continue
                # Site absent at this maturity (and fallback did not
                # rescue) -- IDA folded it entirely.
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.IDENTITY_LOST,
                        confidence=0.7,
                        reason=(
                            "StateWriteAnchorFact observation observed at an "
                            "earlier maturity but the (block, ea, stkoff) "
                            "triple is absent from this maturity's collection"
                        ),
                        payload={
                            "kind": observation.kind,
                            "semantic_key": observation.semantic_key,
                            "source_fact_id": observation.fact_id,
                            "source_block": observation.source_block,
                            "source_ea": observation.source_ea,
                            "source_mop_signature": observation.mop_signature,
                            "instruction_ea": continuity_key[0],
                            "block_serial": continuity_key[1],
                            "state_var_stkoff": continuity_key[2],
                            "original_state_const": (
                                self._state_write_anchor_const(observation)
                            ),
                        },
                    )
                )
                continue

            original_const = self._state_write_anchor_const(observation)
            if original_const is None:
                continue

            for candidate in candidates:
                candidate_const = self._state_write_anchor_const(candidate)
                if candidate_const is None:
                    continue
                if candidate_const == original_const:
                    # Same value at later maturity -- not a rewrite.
                    continue
                candidate_payload = candidate.payload or {}
                rewritten_ea_raw = candidate_payload.get("instruction_ea")
                try:
                    rewritten_ea = (
                        int(rewritten_ea_raw)
                        if rewritten_ea_raw is not None
                        else None
                    )
                except (TypeError, ValueError):
                    rewritten_ea = None
                original_ea = continuity_key[0]
                ea_changed = (
                    rewritten_ea is not None and rewritten_ea != original_ea
                )
                if fallback_used:
                    reason = (
                        f"state_const rewritten via canonical-state-var "
                        f"fallback (EA changed): "
                        f"0x{original_const:016x} -> "
                        f"0x{candidate_const:016x} "
                        f"blk={continuity_key[1]} "
                        f"stkoff=0x{continuity_key[2]:x} "
                        f"original_ea=0x{original_ea & 0xFFFFFFFFFFFFFFFF:016x} "
                        + (
                            f"rewritten_ea=0x{rewritten_ea & 0xFFFFFFFFFFFFFFFF:016x}"
                            if rewritten_ea is not None
                            else "rewritten_ea=?"
                        )
                    )
                else:
                    reason = (
                        f"state_const rewritten in place: "
                        f"0x{original_const:016x} -> "
                        f"0x{candidate_const:016x} "
                        f"at ea=0x{original_ea & 0xFFFFFFFFFFFFFFFF:016x} "
                        f"blk={continuity_key[1]} "
                        f"stkoff=0x{continuity_key[2]:x}"
                    )
                payload: dict[str, Any] = {
                    "kind": observation.kind,
                    "instruction_ea": original_ea,
                    "instruction_ea_hex": (
                        f"0x{original_ea & 0xFFFFFFFFFFFFFFFF:016x}"
                    ),
                    "block_serial": continuity_key[1],
                    "state_var_stkoff": continuity_key[2],
                    "state_var_stkoff_hex": f"0x{continuity_key[2]:x}",
                    "original_state_const": original_const,
                    "original_state_const_hex": f"0x{original_const:016x}",
                    "original_const_hex": f"0x{original_const:016x}",
                    "original_const_u64": original_const,
                    "rewritten_state_const": candidate_const,
                    "rewritten_state_const_hex": (
                        f"0x{candidate_const:016x}"
                    ),
                    "rewritten_const_hex": f"0x{candidate_const:016x}",
                    "rewritten_const_u64": candidate_const,
                    "original_ea_hex": (
                        f"0x{original_ea & 0xFFFFFFFFFFFFFFFF:016x}"
                    ),
                    "rewritten_ea_hex": (
                        f"0x{rewritten_ea & 0xFFFFFFFFFFFFFFFF:016x}"
                        if rewritten_ea is not None
                        else None
                    ),
                    "ea_changed": ea_changed,
                    "continuity_kind": (
                        "fallback_canonical_state_var"
                        if fallback_used
                        else "primary_ea_block_stkoff"
                    ),
                    "from_maturity": observation.maturity,
                    "to_maturity": maturity_text,
                    "source_fact_id": observation.fact_id,
                    "target_fact_id": candidate.fact_id,
                    "source_maturity": observation.maturity,
                    "target_maturity": maturity_text,
                }
                mappings.append(
                    FactMapping(
                        source_fact_id=observation.fact_id,
                        source_maturity=observation.maturity,
                        target_maturity=maturity_text,
                        status=FactStatus.STATE_CONST_REWRITTEN,
                        confidence=min(
                            0.92,
                            observation.confidence,
                            candidate.confidence,
                        ),
                        target_fact_id=candidate.fact_id,
                        target_block=candidate.source_block,
                        target_ea=candidate.source_ea,
                        target_mop_signature=candidate.mop_signature,
                        reason=reason,
                        payload=payload,
                    )
                )
                # Only record one mapping per source fact per target
                # maturity even if multiple candidates remap.
                break
        return tuple(mappings)

    def _update_latest_observations(
        self,
        func_ea: int,
        current_observations: tuple[FactObservation, ...],
    ) -> None:
        latest = dict(self._last_observations_by_func.get(func_ea, {}))
        for observation in current_observations:
            if observation.kind == "InductionCarrierFact":
                latest[observation.fact_id] = observation
        self._last_observations_by_func[func_ea] = latest

    def capture(
        self,
        target: Any,
        *,
        func_ea: int,
        maturity: int,
        phase: str = "pre_d810",
        snapshot: Any = None,
    ) -> FactCaptureSummary:
        settings = get_settings()
        if not settings.fact_lifecycle:
            return FactCaptureSummary(
                func_ea=func_ea,
                maturity=maturity,
                phase=phase,
                enabled=False,
                invoked=False,
                reason="disabled",
            )

        dedupe_key = (func_ea, maturity, phase)
        if dedupe_key in self._fired:
            return FactCaptureSummary(
                func_ea=func_ea,
                maturity=maturity,
                phase=phase,
                enabled=True,
                invoked=False,
                collector_count=len(self._collectors),
                reason="already-fired",
            )
        self._fired.add(dedupe_key)
        maturity_text = self._maturity_text(maturity)

        observations: list[FactObservation] = []
        mappings: list[FactMapping] = []
        conflicts: list[FactConflict] = []
        ran_fact_kinds: set[str] = set()
        for collector in self._collectors:
            if not self._collector_runs_at_maturity(collector, maturity):
                continue
            try:
                result = self._normalize_result(
                    collector.collect(
                        target,
                        func_ea=func_ea,
                        maturity=maturity,
                        phase=phase,
                    )
                )
                observations.extend(result.observations)
                mappings.extend(result.mappings)
                conflicts.extend(result.conflicts)
                ran_fact_kinds.update(getattr(collector, "fact_kinds", frozenset()))
                ran_fact_kinds.update(
                    observation.kind for observation in result.observations
                )
            except Exception:
                logger.exception(
                    "FactCollector '%s' failed at func=0x%x maturity=%s",
                    collector.name,
                    func_ea,
                    maturity_text,
                )

        derived_mappings: tuple[FactMapping, ...] = ()
        derived_conflicts: tuple[FactConflict, ...] = ()
        if "InductionCarrierFact" in ran_fact_kinds:
            derived_mappings, derived_conflicts = self._derive_induction_lifecycle(
                func_ea,
                maturity=maturity,
                current_observations=tuple(observations),
                current_mappings=tuple(mappings),
            )
        return_carrier_mappings: tuple[FactMapping, ...] = ()
        if "ReturnCarrierFact" in ran_fact_kinds:
            return_carrier_mappings = self._derive_return_carrier_lifecycle(
                func_ea,
                target=target,
                maturity=maturity,
                current_observations=tuple(observations),
                current_mappings=(*tuple(mappings), *derived_mappings),
            )
        terminal_byte_mappings: tuple[FactMapping, ...] = ()
        if "TerminalByteEmitterFact" in ran_fact_kinds:
            terminal_byte_mappings = self._derive_terminal_byte_emitter_lifecycle(
                func_ea,
                maturity=maturity,
                current_observations=tuple(observations),
                current_mappings=(
                    *tuple(mappings),
                    *derived_mappings,
                    *return_carrier_mappings,
                ),
            )
        generic_mappings = self._derive_generic_lifecycle(
            func_ea,
            maturity=maturity,
            current_observations=tuple(observations),
            current_mappings=(
                *tuple(mappings),
                *derived_mappings,
                *return_carrier_mappings,
                *terminal_byte_mappings,
            ),
            ran_fact_kinds=frozenset(ran_fact_kinds),
        )
        state_write_mappings: tuple[FactMapping, ...] = ()
        if "StateWriteAnchorFact" in ran_fact_kinds:
            state_write_mappings = self._derive_state_write_anchor_lifecycle(
                func_ea,
                maturity=maturity,
                current_observations=tuple(observations),
                current_mappings=(
                    *tuple(mappings),
                    *derived_mappings,
                    *return_carrier_mappings,
                    *terminal_byte_mappings,
                    *generic_mappings,
                ),
            )
        mappings.extend(derived_mappings)
        mappings.extend(return_carrier_mappings)
        mappings.extend(terminal_byte_mappings)
        mappings.extend(generic_mappings)
        mappings.extend(state_write_mappings)
        conflicts.extend(derived_conflicts)

        if observations or mappings or conflicts:
            self._observations_by_func.setdefault(func_ea, []).extend(observations)
            self._mappings_by_func.setdefault(func_ea, []).extend(mappings)
            self._update_latest_observations(func_ea, tuple(observations))
            if (
                self._persistence_callback is not None
                and snapshot is not None
            ):
                self._persistence_callback(
                    snapshot,
                    func_ea,
                    tuple(observations),
                    tuple(mappings),
                    tuple(conflicts),
                )
            else:
                logger.warning(
                    "FACT_LIFECYCLE_DROPPED func=0x%x maturity=%s phase=%s "
                    "observations=%d mappings=%d conflicts=%d snapshot=%s callback=%s",
                    func_ea,
                    maturity_text,
                    phase,
                    len(observations),
                    len(mappings),
                    len(conflicts),
                    snapshot,
                    self._persistence_callback is not None,
                )

        view = self.validated_view(func_ea, maturity)
        logger.info(
            "FACT_VIEW func=0x%x maturity=%s phase=%s observations=%d "
            "active=%d mappings=%d stale=%d",
            func_ea,
            view.maturity,
            phase,
            len(view.observations),
            len(view.active_observations),
            len(view.mappings),
            self._stale_mapping_count(view),
        )

        summary = FactCaptureSummary(
            func_ea=func_ea,
            maturity=maturity,
            phase=phase,
            enabled=True,
            invoked=True,
            collector_count=len(self._collectors),
            observation_count=len(observations),
            mapping_count=len(mappings),
            conflict_count=len(conflicts),
        )
        logger.info(
            "FACT_LIFECYCLE_CAPTURE func=0x%x maturity=%s phase=%s "
            "collectors=%d observations=%d mappings=%d conflicts=%d",
            func_ea,
            maturity_text,
            phase,
            summary.collector_count,
            summary.observation_count,
            summary.mapping_count,
            summary.conflict_count,
        )
        return summary
