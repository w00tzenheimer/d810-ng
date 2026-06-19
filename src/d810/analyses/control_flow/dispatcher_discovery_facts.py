"""Generic state-dispatcher discovery facts.

These facts describe reusable dispatcher evidence without naming the first
obfuscator family that consumed it.  They are intentionally IDA-free: live
microcode adapters must pass plain serials, state values, and dispatcher maps.
"""
from __future__ import annotations

from dataclasses import dataclass

from d810.analyses.value_flow.observation import FactObservation
from d810.analyses.control_flow.dispatcher_resolution import StateDispatcherMap, StateDispatcherRow
from d810.analyses.control_flow.predecessor_dispatcher_target import (
    PredecessorDispatcherTargetFact,
)
from d810.analyses.value_flow.contract_evidence import contract_evidence_payload

STATE_DISPATCHER_TOPOLOGY_FACT_TYPE = "state_dispatcher_topology"
STATE_VARIABLE_IDENTITY_FACT_TYPE = "state_variable_identity"
DISPATCHER_INITIAL_STATE_FACT_TYPE = "dispatcher_initial_state"
DISPATCHER_ARTIFACT_STATE_FACT_TYPE = "dispatcher_artifact_state"
DISPATCHER_DISCOVERY_GAP_FACT_TYPE = "dispatcher_discovery_gap"
PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE = "predecessor_dispatcher_target"


@dataclass(frozen=True, slots=True)
class DispatcherTopologyFact:
    """One recovered dispatcher topology relation."""

    fact_id: str
    dispatcher_entry_serial: int
    dispatcher_blocks: tuple[int, ...]
    predecessor_serials: tuple[int, ...]
    handler_targets: tuple[int, ...]
    row_count: int
    dispatcher_source: str
    profile_name: str | None = None

    def to_observation(
        self,
        *,
        maturity: str,
        phase: str,
    ) -> FactObservation:
        return FactObservation(
            fact_id=self.fact_id,
            kind=STATE_DISPATCHER_TOPOLOGY_FACT_TYPE,
            semantic_key=_dispatcher_semantic_key(
                self.dispatcher_entry_serial,
                self.profile_name,
            ),
            maturity=maturity,
            phase=phase,
            confidence=1.0,
            source_block=self.dispatcher_entry_serial,
            payload={
                "dispatcher_entry_serial": self.dispatcher_entry_serial,
                "dispatcher_blocks": list(self.dispatcher_blocks),
                "predecessor_serials": list(self.predecessor_serials),
                "handler_targets": list(self.handler_targets),
                "row_count": self.row_count,
                "dispatcher_source": self.dispatcher_source,
                "profile_name": self.profile_name,
                **(
                    contract_evidence_payload("branch_targets")
                    if self.handler_targets
                    else {}
                ),
            },
            evidence=("state_dispatcher_map",),
        )


@dataclass(frozen=True, slots=True)
class StateVariableIdentityFact:
    """Storage identity for the dispatcher state variable."""

    fact_id: str
    dispatcher_entry_serial: int
    storage_kind: str
    state_var_stkoff: int | None = None
    state_var_lvar_idx: int | None = None
    profile_name: str | None = None

    def to_observation(
        self,
        *,
        maturity: str,
        phase: str,
    ) -> FactObservation:
        return FactObservation(
            fact_id=self.fact_id,
            kind=STATE_VARIABLE_IDENTITY_FACT_TYPE,
            semantic_key=_dispatcher_semantic_key(
                self.dispatcher_entry_serial,
                self.profile_name,
            ),
            maturity=maturity,
            phase=phase,
            confidence=1.0,
            source_block=self.dispatcher_entry_serial,
            payload={
                "dispatcher_entry_serial": self.dispatcher_entry_serial,
                "storage_kind": self.storage_kind,
                "state_var_stkoff": self.state_var_stkoff,
                "state_var_lvar_idx": self.state_var_lvar_idx,
                "profile_name": self.profile_name,
            },
            evidence=("state_dispatcher_map",),
        )


@dataclass(frozen=True, slots=True)
class DispatcherInitialStateFact:
    """Initial state evidence for a state-dispatcher family."""

    fact_id: str
    dispatcher_entry_serial: int
    initial_state: int
    target_block_serial: int | None
    pre_header_serial: int | None = None
    profile_name: str | None = None

    @property
    def initial_state_hex(self) -> str:
        return _hex_u64(self.initial_state)

    def to_observation(
        self,
        *,
        maturity: str,
        phase: str,
    ) -> FactObservation:
        return FactObservation(
            fact_id=self.fact_id,
            kind=DISPATCHER_INITIAL_STATE_FACT_TYPE,
            semantic_key=_dispatcher_semantic_key(
                self.dispatcher_entry_serial,
                self.profile_name,
            ),
            maturity=maturity,
            phase=phase,
            confidence=1.0,
            source_block=self.pre_header_serial or self.dispatcher_entry_serial,
            payload={
                "dispatcher_entry_serial": self.dispatcher_entry_serial,
                "initial_state": self.initial_state,
                "initial_state_hex": self.initial_state_hex,
                "target_block_serial": self.target_block_serial,
                "pre_header_serial": self.pre_header_serial,
                "profile_name": self.profile_name,
            },
            evidence=("initial_state_recovery", "state_dispatcher_map"),
        )


@dataclass(frozen=True, slots=True)
class DispatcherArtifactStateFact:
    """State row classified as dispatcher artifact or neutralizer state."""

    fact_id: str
    dispatcher_entry_serial: int
    classification: str
    target_block_serial: int | None
    state_const: int | None = None
    row_kind: str | None = None
    dispatcher_block_serial: int | None = None
    profile_name: str | None = None

    @property
    def state_const_hex(self) -> str | None:
        if self.state_const is None:
            return None
        return _hex_u64(self.state_const)

    def to_observation(
        self,
        *,
        maturity: str,
        phase: str,
    ) -> FactObservation:
        return FactObservation(
            fact_id=self.fact_id,
            kind=DISPATCHER_ARTIFACT_STATE_FACT_TYPE,
            semantic_key=_dispatcher_semantic_key(
                self.dispatcher_entry_serial,
                self.profile_name,
            ),
            maturity=maturity,
            phase=phase,
            confidence=1.0,
            source_block=self.dispatcher_block_serial or self.dispatcher_entry_serial,
            payload={
                "dispatcher_entry_serial": self.dispatcher_entry_serial,
                "classification": self.classification,
                "state_const": self.state_const,
                "state_const_hex": self.state_const_hex,
                "target_block_serial": self.target_block_serial,
                "row_kind": self.row_kind,
                "dispatcher_block_serial": self.dispatcher_block_serial,
                "profile_name": self.profile_name,
            },
            evidence=("state_dispatcher_map",),
        )


@dataclass(frozen=True, slots=True)
class DispatcherDiscoveryGapFact:
    """Read-only diagnostic for missing dispatcher proof evidence."""

    fact_id: str
    dispatcher_entry_serial: int | None
    reason: str
    detail: str | None = None
    profile_name: str | None = None

    def to_observation(
        self,
        *,
        maturity: str,
        phase: str,
    ) -> FactObservation:
        return FactObservation(
            fact_id=self.fact_id,
            kind=DISPATCHER_DISCOVERY_GAP_FACT_TYPE,
            semantic_key=_dispatcher_semantic_key(
                self.dispatcher_entry_serial,
                self.profile_name,
            ),
            maturity=maturity,
            phase=phase,
            confidence=1.0,
            source_block=self.dispatcher_entry_serial,
            payload={
                "dispatcher_entry_serial": self.dispatcher_entry_serial,
                "reason": self.reason,
                "detail": self.detail,
                "profile_name": self.profile_name,
            },
            evidence=("dispatcher_discovery",),
        )


DispatcherDiscoveryFact = (
    DispatcherTopologyFact
    | StateVariableIdentityFact
    | DispatcherInitialStateFact
    | DispatcherArtifactStateFact
    | DispatcherDiscoveryGapFact
)


def collect_state_dispatcher_discovery_facts(
    *,
    state_dispatcher_map: StateDispatcherMap | None,
    profile_name: str | None = None,
    predecessor_serials: tuple[int, ...] = (),
    initial_state: int | None = None,
    pre_header_serial: int | None = None,
) -> tuple[DispatcherDiscoveryFact, ...]:
    """Project a dispatcher map into generic recon facts."""

    if state_dispatcher_map is None:
        return (
            _gap_fact(
                dispatcher_entry_serial=None,
                profile_name=profile_name,
                reason="state_dispatcher_map_missing",
                detail="No state dispatcher map was available",
            ),
        )

    entry = int(state_dispatcher_map.dispatcher_entry_block)
    source = _source_name(state_dispatcher_map.router_kind)
    dispatcher_blocks = tuple(sorted(int(block) for block in state_dispatcher_map.dispatcher_blocks))
    handler_targets = tuple(
        sorted(
            {
                int(row.target_block)
                for row in state_dispatcher_map.rows
                if row.is_handler_row
            }
        )
    )

    facts: list[DispatcherDiscoveryFact] = [
        DispatcherTopologyFact(
            fact_id=_fact_id(
                STATE_DISPATCHER_TOPOLOGY_FACT_TYPE,
                profile_name,
                entry,
            ),
            dispatcher_entry_serial=entry,
            dispatcher_blocks=dispatcher_blocks,
            predecessor_serials=tuple(sorted(int(pred) for pred in predecessor_serials)),
            handler_targets=handler_targets,
            row_count=len(state_dispatcher_map.rows),
            dispatcher_source=source,
            profile_name=profile_name,
        )
    ]

    storage_kind = _state_storage_kind(
        state_dispatcher_map.state_var_stkoff,
        state_dispatcher_map.state_var_lvar_idx,
    )
    if storage_kind == "unknown":
        facts.append(
            _gap_fact(
                dispatcher_entry_serial=entry,
                profile_name=profile_name,
                reason="state_variable_identity_missing",
                detail="Dispatcher map did not identify state-variable storage",
            )
        )
    else:
        facts.append(
            StateVariableIdentityFact(
                fact_id=_fact_id(
                    STATE_VARIABLE_IDENTITY_FACT_TYPE,
                    profile_name,
                    entry,
                ),
                dispatcher_entry_serial=entry,
                storage_kind=storage_kind,
                state_var_stkoff=state_dispatcher_map.state_var_stkoff,
                state_var_lvar_idx=state_dispatcher_map.state_var_lvar_idx,
                profile_name=profile_name,
            )
        )

    effective_initial_state = (
        int(initial_state)
        if initial_state is not None
        else (
            int(state_dispatcher_map.initial_state)
            if state_dispatcher_map.initial_state is not None
            else None
        )
    )
    if effective_initial_state is None:
        facts.append(
            _gap_fact(
                dispatcher_entry_serial=entry,
                profile_name=profile_name,
                reason="initial_state_missing",
                detail="No initial state value was recovered",
            )
        )
    else:
        facts.append(
            DispatcherInitialStateFact(
                fact_id=_fact_id(
                    DISPATCHER_INITIAL_STATE_FACT_TYPE,
                    profile_name,
                    entry,
                    _hex_u64(effective_initial_state),
                ),
                dispatcher_entry_serial=entry,
                initial_state=effective_initial_state,
                target_block_serial=state_dispatcher_map.resolve_target(
                    effective_initial_state
                ),
                pre_header_serial=pre_header_serial,
                profile_name=profile_name,
            )
        )

    facts.extend(
        _artifact_facts_from_dispatcher_map(
            state_dispatcher_map,
            profile_name=profile_name,
        )
    )
    if not handler_targets:
        facts.append(
            _gap_fact(
                dispatcher_entry_serial=entry,
                profile_name=profile_name,
                reason="handler_rows_missing",
                detail="Dispatcher map did not contain handler rows",
            )
        )
    return tuple(facts)


def collect_state_dispatcher_discovery_fact_observations(
    *,
    state_dispatcher_map: StateDispatcherMap | None,
    maturity: str,
    phase: str,
    profile_name: str | None = None,
    predecessor_serials: tuple[int, ...] = (),
    initial_state: int | None = None,
    pre_header_serial: int | None = None,
    predecessor_target_facts: tuple[PredecessorDispatcherTargetFact, ...] = (),
) -> tuple[FactObservation, ...]:
    """Return generic dispatcher discovery rows as fact observations."""

    observations = [
        fact.to_observation(maturity=maturity, phase=phase)
        for fact in collect_state_dispatcher_discovery_facts(
            state_dispatcher_map=state_dispatcher_map,
            profile_name=profile_name,
            predecessor_serials=predecessor_serials,
            initial_state=initial_state,
            pre_header_serial=pre_header_serial,
        )
    ]
    observations.extend(
        predecessor_dispatcher_target_observation(
            fact,
            maturity=maturity,
            phase=phase,
            profile_name=profile_name,
        )
        for fact in predecessor_target_facts
    )
    return tuple(observations)


def predecessor_dispatcher_target_observation(
    fact: PredecessorDispatcherTargetFact,
    *,
    maturity: str,
    phase: str,
    profile_name: str | None = None,
) -> FactObservation:
    """Mirror a predecessor-target proof as a durable generic fact row."""

    return FactObservation(
        fact_id=fact.fact_id,
        kind=PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE,
        semantic_key=_dispatcher_semantic_key(
            fact.dispatcher_entry_serial,
            profile_name,
        ),
        maturity=maturity,
        phase=phase,
        confidence=fact.confidence,
        source_block=fact.predecessor_block_serial,
        payload={
            **fact.to_dict(),
            "profile_name": profile_name,
            **_predecessor_dispatcher_target_contract_evidence(fact),
        },
        evidence=(fact.resolver_kind,),
    )


def _predecessor_dispatcher_target_contract_evidence(
    fact: PredecessorDispatcherTargetFact,
) -> dict[str, list[str]]:
    tokens = ["branch_targets"]
    if (
        fact.branch_kind is not None
        or fact.compare_block_serial is not None
        or fact.condition_block_serial is not None
    ):
        tokens.append("dispatcher_predicates")
    return contract_evidence_payload(*tokens)


def _artifact_facts_from_dispatcher_map(
    state_dispatcher_map: StateDispatcherMap,
    *,
    profile_name: str | None,
) -> tuple[DispatcherArtifactStateFact, ...]:
    facts: list[DispatcherArtifactStateFact] = []
    entry = int(state_dispatcher_map.dispatcher_entry_block)
    for row in state_dispatcher_map.rows:
        classification = _artifact_classification(row, state_dispatcher_map)
        if classification is None:
            continue
        state_const = int(row.state_const)
        facts.append(
            DispatcherArtifactStateFact(
                fact_id=_fact_id(
                    DISPATCHER_ARTIFACT_STATE_FACT_TYPE,
                    profile_name,
                    entry,
                    _hex_u64(state_const),
                    classification,
                ),
                dispatcher_entry_serial=entry,
                classification=classification,
                target_block_serial=int(row.target_block),
                state_const=state_const,
                row_kind=str(row.row_kind),
                dispatcher_block_serial=int(row.dispatcher_block),
                profile_name=profile_name,
            )
        )

    if state_dispatcher_map.default_target_block is not None:
        classification = state_dispatcher_map.default_row_kind or "default_target"
        facts.append(
            DispatcherArtifactStateFact(
                fact_id=_fact_id(
                    DISPATCHER_ARTIFACT_STATE_FACT_TYPE,
                    profile_name,
                    entry,
                    "default",
                    classification,
                ),
                dispatcher_entry_serial=entry,
                classification=classification,
                target_block_serial=int(state_dispatcher_map.default_target_block),
                row_kind=state_dispatcher_map.default_row_kind,
                profile_name=profile_name,
            )
        )
    return tuple(facts)


def _artifact_classification(
    row: StateDispatcherRow,
    state_dispatcher_map: StateDispatcherMap,
) -> str | None:
    if row.is_dispatcher_self_loop:
        return "dispatcher_self_loop"
    if row.row_kind not in {"handler", "handler_alias"}:
        return str(row.row_kind)
    if int(row.target_block) in state_dispatcher_map.dispatcher_blocks:
        return "dispatcher_block_target"
    return None


def _gap_fact(
    *,
    dispatcher_entry_serial: int | None,
    profile_name: str | None,
    reason: str,
    detail: str | None,
) -> DispatcherDiscoveryGapFact:
    return DispatcherDiscoveryGapFact(
        fact_id=_fact_id(
            DISPATCHER_DISCOVERY_GAP_FACT_TYPE,
            profile_name,
            dispatcher_entry_serial,
            reason,
        ),
        dispatcher_entry_serial=dispatcher_entry_serial,
        profile_name=profile_name,
        reason=reason,
        detail=detail,
    )


def _source_name(value: object) -> str:
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def _state_storage_kind(
    state_var_stkoff: int | None,
    state_var_lvar_idx: int | None,
) -> str:
    if state_var_stkoff is not None:
        return "stack_slot"
    if state_var_lvar_idx is not None:
        return "local_variable"
    return "unknown"


def _dispatcher_semantic_key(
    dispatcher_entry_serial: int | None,
    profile_name: str | None,
) -> str:
    entry = "unknown" if dispatcher_entry_serial is None else str(int(dispatcher_entry_serial))
    if profile_name:
        return f"state_dispatcher:{profile_name}:entry={entry}"
    return f"state_dispatcher:entry={entry}"


def _fact_id(
    fact_type: str,
    profile_name: str | None,
    dispatcher_entry_serial: int | None,
    *suffixes: object,
) -> str:
    entry = "unknown" if dispatcher_entry_serial is None else str(int(dispatcher_entry_serial))
    profile = profile_name or "generic"
    suffix = "".join(f":{item}" for item in suffixes)
    return f"{fact_type}:profile={profile}:entry={entry}{suffix}"


def _hex_u64(value: int) -> str:
    return f"0x{int(value) & 0xFFFFFFFFFFFFFFFF:016x}"


__all__ = [
    "DISPATCHER_ARTIFACT_STATE_FACT_TYPE",
    "DISPATCHER_DISCOVERY_GAP_FACT_TYPE",
    "DISPATCHER_INITIAL_STATE_FACT_TYPE",
    "PREDECESSOR_DISPATCHER_TARGET_FACT_TYPE",
    "STATE_DISPATCHER_TOPOLOGY_FACT_TYPE",
    "STATE_VARIABLE_IDENTITY_FACT_TYPE",
    "DispatcherArtifactStateFact",
    "DispatcherDiscoveryFact",
    "DispatcherDiscoveryGapFact",
    "DispatcherInitialStateFact",
    "DispatcherTopologyFact",
    "StateVariableIdentityFact",
    "collect_state_dispatcher_discovery_fact_observations",
    "collect_state_dispatcher_discovery_facts",
    "predecessor_dispatcher_target_observation",
]
