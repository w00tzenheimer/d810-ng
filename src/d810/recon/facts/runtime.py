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

FactPersistenceCallback = Callable[
    [
        Any,
        int,
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
        snapshot_id: int | None = None,
        diag_conn: Any = None,
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
                    "FactCollector '%s' failed at func=0x%x maturity=%d",
                    collector.name,
                    func_ea,
                    maturity,
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
        mappings.extend(derived_mappings)
        mappings.extend(return_carrier_mappings)
        mappings.extend(terminal_byte_mappings)
        conflicts.extend(derived_conflicts)

        if observations or mappings or conflicts:
            self._observations_by_func.setdefault(func_ea, []).extend(observations)
            self._mappings_by_func.setdefault(func_ea, []).extend(mappings)
            self._update_latest_observations(func_ea, tuple(observations))
            if (
                self._persistence_callback is not None
                and snapshot_id is not None
                and diag_conn is not None
            ):
                self._persistence_callback(
                    diag_conn,
                    snapshot_id,
                    func_ea,
                    tuple(observations),
                    tuple(mappings),
                    tuple(conflicts),
                )
            else:
                logger.warning(
                    "FACT_LIFECYCLE_DROPPED func=0x%x maturity=%d phase=%s "
                    "observations=%d mappings=%d conflicts=%d snapshot_id=%s callback=%s",
                    func_ea,
                    maturity,
                    phase,
                    len(observations),
                    len(mappings),
                    len(conflicts),
                    snapshot_id,
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
            "FACT_LIFECYCLE_CAPTURE func=0x%x maturity=%d phase=%s "
            "collectors=%d observations=%d mappings=%d conflicts=%d",
            func_ea,
            maturity,
            phase,
            summary.collector_count,
            summary.observation_count,
            summary.mapping_count,
            summary.conflict_count,
        )
        return summary
