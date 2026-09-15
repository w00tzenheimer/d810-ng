"""Fail-closed route-semantic comparison for the seven hash-bound MASM fixtures.

Reference facts belong to test support.  This module compares recovery evidence;
it must not become production unflattening policy.  The live seven-fixture gate
certifies exact dispatcher transitions.  The generic effect/exit fields support
stricter fixture oracles, but empty traces are not whole-function equivalence.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from d810.core.typing import Iterable


@dataclass(frozen=True, slots=True)
class Transition:
    partition: str
    predecessor_eas: tuple[int, ...]
    constraints: tuple[str, ...]
    target_rvas: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class Effect:
    order: int
    kind: str
    ea: int
    width: int | None = None
    target: str | None = None
    value: str | None = None


@dataclass(frozen=True, slots=True)
class Exit:
    kind: str
    ea: int
    value: str | None = None


@dataclass(frozen=True, slots=True)
class FixtureReference:
    function: str
    entry_rva: int
    extent: int
    linked_sha256: str
    transitions: tuple[Transition, ...]
    effects: tuple[Effect, ...]
    exits: tuple[Exit, ...]
    assumptions: tuple[str, ...] = ()
    unresolved: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RecoveredSemantics:
    function: str
    entry_rva: int
    extent: int
    linked_sha256: str
    transitions: tuple[Transition, ...]
    effects: tuple[Effect, ...]
    exits: tuple[Exit, ...]
    unresolved: tuple[str, ...] = ()
    raw_computed_dispatcher_jump: bool = False
    pseudocode: str = ""


@dataclass(frozen=True, slots=True)
class SemanticBlocker:
    code: str
    detail: str


@dataclass(frozen=True, slots=True)
class SemanticDiff:
    key: str
    expected: object
    observed: object

    @property
    def matches(self) -> bool:
        return self.expected == self.observed


@dataclass(frozen=True, slots=True)
class SemanticOracleResult:
    passed: bool
    blockers: tuple[SemanticBlocker, ...]
    transition_diffs: tuple[SemanticDiff, ...]
    effect_diffs: tuple[SemanticDiff, ...]


def _route_transition(
    proof: object,
    *,
    function_ea: int,
    entry_rva: int,
) -> Transition:
    destinations = tuple(getattr(proof, "destinations", ()))
    if not destinations:
        raise ValueError("published route proof has no destination")
    state_constants = {
        int(value)
        for destination in destinations
        if (value := getattr(destination, "state_constant", None)) is not None
    }
    if len(state_constants) != 1:
        raise ValueError("published route proof has ambiguous selector state")
    state_constant = next(iter(state_constants)) & 0xFFFFFFFFFFFFFFFF
    source_rva = entry_rva + int(getattr(proof, "source_anchor_ea")) - function_ea
    target_rvas = tuple(
        sorted(
            {
                entry_rva + int(getattr(destination, "target_anchor_ea")) - function_ea
                for destination in destinations
            }
        )
    )
    width = max(8, ((state_constant.bit_length() + 3) // 4))
    state_text = f"0x{state_constant:0{width}X}"
    return Transition(
        # Proof kind is a recovery strategy, not semantic partition identity.
        # Bootstrap and assignment witnesses can describe the same transition.
        partition=f"src=0x{source_rva:X}:state={state_text}",
        predecessor_eas=(source_rva,),
        constraints=(f"selector_state == {state_text}",),
        target_rvas=target_rvas,
    )


def recovered_semantics_from_proposals(
    *,
    function: str,
    function_ea: int,
    entry_rva: int,
    extent: int,
    linked_sha256: str,
    proposals: Iterable[object],
    pseudocode: str = "",
    raw_computed_dispatcher_jump: bool = False,
) -> RecoveredSemantics:
    """Project committed authority into stable, comparable route semantics.

    Only route proofs named by a published claim are output semantics.  Proofs
    merely available in the evidence bundle (for example a duplicate bootstrap
    witness) are not silently promoted into recovered transitions.
    """

    available: dict[str, object] = {}
    claimed: set[str] = set()
    unresolved: list[str] = []
    for proposal in proposals:
        evidence = getattr(proposal, "route_evidence", None)
        for proof in tuple(getattr(evidence, "route_proofs", ())):
            proof_id = str(getattr(proof, "proof_id"))
            previous = available.get(proof_id)
            if previous is not None and previous != proof:
                unresolved.append(f"conflicting canonical proof {proof_id}")
            available[proof_id] = proof
        for claim in tuple(getattr(proposal, "claims", ())):
            claimed.update(
                str(value) for value in getattr(claim, "route_proof_ids", ())
            )

    if not claimed:
        unresolved.append("no published semantic route proofs")
    foreign = claimed - available.keys()
    if foreign:
        unresolved.append("published claims reference unavailable route proofs")

    by_partition: dict[str, Transition] = {}
    conflicting_partitions: set[str] = set()
    for proof_id in sorted(claimed & available.keys()):
        try:
            transition = _route_transition(
                available[proof_id],
                function_ea=function_ea,
                entry_rva=entry_rva,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            unresolved.append(f"invalid published route proof {proof_id}: {exc}")
            continue
        previous = by_partition.get(transition.partition)
        if previous is not None and previous != transition:
            conflicting_partitions.add(transition.partition)
            continue
        by_partition[transition.partition] = transition
    for partition in sorted(conflicting_partitions):
        by_partition.pop(partition, None)
        unresolved.append(f"conflicting route partition {partition}")

    return RecoveredSemantics(
        function=function,
        entry_rva=entry_rva,
        extent=extent,
        linked_sha256=linked_sha256,
        transitions=tuple(by_partition[key] for key in sorted(by_partition)),
        effects=(),
        exits=(),
        unresolved=tuple(sorted(set(unresolved))),
        raw_computed_dispatcher_jump=raw_computed_dispatcher_jump,
        pseudocode=pseudocode,
    )


def recovered_semantics_from_diagnostics(
    *,
    reference: FixtureReference,
    function_ea: int,
    diagnostics_db: Path,
    pseudocode: str = "",
    raw_computed_dispatcher_jump: bool = False,
) -> RecoveredSemantics:
    """Project committed diagnostic authority for one exact fixture."""

    from tests.system.e2e.hash_bound_fixture_receipts import (
        load_committed_unflatten_proposals,
    )

    connection = sqlite3.connect(diagnostics_db)
    try:
        row = connection.execute(
            "SELECT session_id FROM diagnostic_sessions "
            "ORDER BY started_at DESC LIMIT 1"
        ).fetchone()
        if row is None:
            raise ValueError("diagnostics DB has no session for semantic recovery")
        proposals = load_committed_unflatten_proposals(
            connection, session_id=str(row[0])
        )
    finally:
        connection.close()
    return recovered_semantics_from_proposals(
        function=reference.function,
        function_ea=function_ea,
        entry_rva=reference.entry_rva,
        extent=reference.extent,
        linked_sha256=reference.linked_sha256,
        proposals=proposals,
        pseudocode=pseudocode,
        raw_computed_dispatcher_jump=raw_computed_dispatcher_jump,
    )


def transition_from_native_receipt(
    image_slice: object,
    receipt: object,
) -> Transition:
    """Project one independently executed native slice into route semantics."""

    from tests.system.e2e.hash_bound.native_transition_oracle import (
        NativeTransitionStatus,
    )

    if getattr(receipt, "status", None) is not NativeTransitionStatus.RESOLVED:
        raise ValueError(f"native transition is not resolved: {receipt!r}")
    selector_value = getattr(receipt, "selector_value", None)
    target_name = getattr(receipt, "target", None)
    if selector_value is None or target_name is None:
        raise ValueError("native transition lacks selector or target evidence")
    request = getattr(image_slice, "request")
    image_base = int(getattr(image_slice, "image_base"))
    matching_targets = tuple(
        tuple(int(ea) - image_base for ea in eas)
        for name, eas in getattr(request, "target_partitions")
        if str(name) == str(target_name)
    )
    if len(matching_targets) != 1 or not matching_targets[0]:
        raise ValueError("native transition target partition is not unique")
    source_rva = int(getattr(request, "entry_ea")) - image_base
    state_constant = int(selector_value) & 0xFFFFFFFFFFFFFFFF
    width = max(8, ((state_constant.bit_length() + 3) // 4))
    state_text = f"0x{state_constant:0{width}X}"
    return Transition(
        partition=f"src=0x{source_rva:X}:state={state_text}",
        predecessor_eas=(source_rva,),
        constraints=(f"selector_state == {state_text}",),
        target_rvas=tuple(sorted(set(matching_targets[0]))),
    )


def _by_partition(transitions: tuple[Transition, ...]) -> dict[str, Transition]:
    result: dict[str, Transition] = {}
    for transition in transitions:
        if transition.partition in result:
            raise ValueError(f"duplicate transition partition: {transition.partition}")
        result[transition.partition] = transition
    return result


def _add_blocker(blockers: list[SemanticBlocker], code: str, detail: str) -> None:
    blockers.append(SemanticBlocker(code=code, detail=detail))


def evaluate_fixture_semantics(
    reference: FixtureReference,
    recovered: RecoveredSemantics,
) -> SemanticOracleResult:
    blockers: list[SemanticBlocker] = []
    transition_diffs: list[SemanticDiff] = []
    effect_diffs: list[SemanticDiff] = []

    expected_identity = (
        reference.function,
        reference.entry_rva,
        reference.extent,
        reference.linked_sha256,
    )
    observed_identity = (
        recovered.function,
        recovered.entry_rva,
        recovered.extent,
        recovered.linked_sha256,
    )
    if expected_identity != observed_identity:
        _add_blocker(
            blockers,
            "fixture_identity_mismatch",
            f"expected {expected_identity!r}, observed {observed_identity!r}",
        )

    if reference.unresolved:
        _add_blocker(
            blockers,
            "reference_unresolved",
            "; ".join(reference.unresolved),
        )
    if recovered.unresolved:
        _add_blocker(
            blockers,
            "recovered_unresolved",
            "; ".join(recovered.unresolved),
        )
    if recovered.raw_computed_dispatcher_jump:
        _add_blocker(
            blockers,
            "raw_computed_dispatcher_jump",
            "recovered output still contains a computed dispatcher transfer",
        )

    expected_transitions = _by_partition(reference.transitions)
    observed_transitions = _by_partition(recovered.transitions)
    for partition in sorted(expected_transitions.keys() | observed_transitions.keys()):
        expected = expected_transitions.get(partition)
        observed = observed_transitions.get(partition)
        transition_diffs.append(
            SemanticDiff(key=partition, expected=expected, observed=observed)
        )
        if expected is None:
            _add_blocker(
                blockers,
                "extra_transition_partition",
                f"unexpected partition {partition!r}",
            )
            continue
        if observed is None:
            _add_blocker(
                blockers,
                "missing_transition_partition",
                f"missing feasible partition {partition!r}",
            )
            continue
        if (
            expected.predecessor_eas != observed.predecessor_eas
            or expected.constraints != observed.constraints
        ):
            _add_blocker(
                blockers,
                "transition_partition_mismatch",
                f"partition {partition!r} has different predecessor/path evidence",
            )
        if expected.target_rvas != observed.target_rvas:
            _add_blocker(
                blockers,
                "transition_target_mismatch",
                f"partition {partition!r}: expected {expected.target_rvas!r}, "
                f"observed {observed.target_rvas!r}",
            )

    extent_start = reference.entry_rva
    extent_end = extent_start + reference.extent
    for transition in recovered.transitions:
        invalid = tuple(
            target
            for target in transition.target_rvas
            if not extent_start <= target < extent_end
        )
        if invalid:
            _add_blocker(
                blockers,
                "out_of_extent_transfer",
                f"partition {transition.partition!r} targets {invalid!r} outside "
                f"[0x{extent_start:X}, 0x{extent_end:X})",
            )

    effect_diffs.append(
        SemanticDiff(
            key="ordered_effects",
            expected=reference.effects,
            observed=recovered.effects,
        )
    )
    if reference.effects != recovered.effects:
        _add_blocker(
            blockers,
            "effect_trace_mismatch",
            "ordered call/memory-write trace differs from the native reference",
        )

    effect_diffs.append(
        SemanticDiff(
            key="terminal_exits", expected=reference.exits, observed=recovered.exits
        )
    )
    if reference.exits != recovered.exits:
        _add_blocker(
            blockers,
            "exit_trace_mismatch",
            "terminal return/exception trace differs from the native reference",
        )

    blocker_tuple = tuple(blockers)
    return SemanticOracleResult(
        passed=not blocker_tuple,
        blockers=blocker_tuple,
        transition_diffs=tuple(transition_diffs),
        effect_diffs=tuple(effect_diffs),
    )


def _parse_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise ValueError(f"{field} must be an integer or base-prefixed string")


def _parse_transition(raw: dict[str, object]) -> Transition:
    return Transition(
        partition=str(raw["partition"]),
        predecessor_eas=tuple(
            _parse_int(value, field="predecessor_eas")
            for value in raw.get("predecessor_eas", ())
        ),
        constraints=tuple(str(value) for value in raw.get("constraints", ())),
        target_rvas=tuple(
            _parse_int(value, field="target_rvas")
            for value in raw.get("target_rvas", ())
        ),
    )


def _parse_effect(raw: dict[str, object]) -> Effect:
    width = raw.get("width")
    return Effect(
        order=_parse_int(raw["order"], field="effect.order"),
        kind=str(raw["kind"]),
        ea=_parse_int(raw["ea"], field="effect.ea"),
        width=None if width is None else _parse_int(width, field="effect.width"),
        target=None if raw.get("target") is None else str(raw["target"]),
        value=None if raw.get("value") is None else str(raw["value"]),
    )


def _parse_exit(raw: dict[str, object]) -> Exit:
    return Exit(
        kind=str(raw["kind"]),
        ea=_parse_int(raw["ea"], field="exit.ea"),
        value=None if raw.get("value") is None else str(raw["value"]),
    )


def load_fixture_references(path: Path) -> dict[str, FixtureReference]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema") != "d810.hash-bound-seven-semantics.v1":
        raise ValueError("unsupported hash-bound semantic reference schema")
    source = payload.get("source")
    if not isinstance(source, dict) or source.get("reference_policy") != (
        "exact_bytes_dispatcher_routes_only"
    ):
        raise ValueError("hash-bound references must declare route-only scope")
    references: dict[str, FixtureReference] = {}
    for raw_fixture in payload.get("fixtures", ()):
        raw = dict(raw_fixture)
        reference = FixtureReference(
            function=str(raw["function"]),
            entry_rva=_parse_int(raw["entry_rva"], field="entry_rva"),
            extent=_parse_int(raw["extent"], field="extent"),
            linked_sha256=str(raw["linked_sha256"]),
            transitions=tuple(
                _parse_transition(dict(value)) for value in raw.get("transitions", ())
            ),
            effects=tuple(
                _parse_effect(dict(value)) for value in raw.get("effects", ())
            ),
            exits=tuple(_parse_exit(dict(value)) for value in raw.get("exits", ())),
            assumptions=tuple(str(value) for value in raw.get("assumptions", ())),
            unresolved=tuple(str(value) for value in raw.get("unresolved", ())),
        )
        if reference.function in references:
            raise ValueError(f"duplicate fixture reference: {reference.function}")
        if reference.extent <= 0:
            raise ValueError(f"non-positive extent for {reference.function}")
        if len(reference.linked_sha256) != 64:
            raise ValueError(f"invalid linked SHA-256 for {reference.function}")
        _by_partition(reference.transitions)
        if tuple(effect.order for effect in reference.effects) != tuple(
            range(len(reference.effects))
        ):
            raise ValueError(f"non-contiguous effect order for {reference.function}")
        references[reference.function] = reference
    return references
