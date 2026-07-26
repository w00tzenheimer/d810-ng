"""Portable semantic-route shapes for detached/reference differential oracles.

This module never retains a live Hex-Rays object or a maturity-local block
serial.  A live adapter may use serials while projecting one MBA snapshot, but
the resulting shape is expressed only through stable native EAs and semantic
transfer properties.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
import json

from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.core.observability_models import BlockSnapshot, InstructionSnapshot
from d810.core.typing import Mapping, Sequence


_MANIFEST_SCHEMA_VERSION = 2


class RouteCaptureLane(str, Enum):
    REFERENCE = "reference"
    CANDIDATE = "candidate"


class SemanticTransferKind(str, Enum):
    DIRECT = "direct"
    CONDITIONAL = "conditional"
    INDIRECT = "indirect"
    RETURN = "return"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReferenceRouteRewrite:
    route_id: str
    function_ea: int
    owner_ea: int
    rewrite_anchor_ea: int
    corridor: tuple[tuple[int, int], ...]
    reference_phase: str
    original_transfer_kind: SemanticTransferKind
    final_transfer_kind: SemanticTransferKind
    direct_target_ea: int | None = None
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    predicate_kind: str | None = None
    reference_ledger_identity: str = ""
    reference_ledger_json: str = "{}"

    def __post_init__(self) -> None:
        if not self.route_id:
            raise ValueError("reference route requires a stable route_id")
        if min(self.function_ea, self.owner_ea, self.rewrite_anchor_ea) < 0:
            raise ValueError("reference route EAs must be non-negative")
        if not self.corridor:
            raise ValueError("reference route requires an owned native corridor")
        if any(start >= end for start, end in self.corridor):
            raise ValueError("reference route corridor ranges must be non-empty")
        if not any(
            start <= self.owner_ea < end and start <= self.rewrite_anchor_ea < end
            for start, end in self.corridor
        ):
            raise ValueError(
                "reference route owner and rewrite anchor must share an owned range"
            )
        if not self.reference_ledger_identity:
            raise ValueError("reference route requires a ledger identity")
        if not self.reference_phase:
            raise ValueError("reference route requires the reference phase")
        parsed_ledger = json.loads(self.reference_ledger_json)
        if not isinstance(parsed_ledger, dict):
            raise ValueError("reference route ledger payload must be a JSON object")

        if self.final_transfer_kind is SemanticTransferKind.DIRECT:
            if self.direct_target_ea is None:
                raise ValueError("direct reference route requires one direct target")
            if any(
                value is not None
                for value in (
                    self.true_target_ea,
                    self.false_target_ea,
                    self.predicate_kind,
                )
            ):
                raise ValueError(
                    "direct reference route cannot carry conditional semantics"
                )
        elif self.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
            if (
                self.true_target_ea is None
                or self.false_target_ea is None
                or self.predicate_kind is None
            ):
                raise ValueError(
                    "conditional reference route requires predicate and both targets"
                )
            if self.direct_target_ea is not None:
                raise ValueError(
                    "conditional reference route cannot carry a direct target"
                )


@dataclass(frozen=True)
class SemanticRouteShape:
    route_id: str
    lane: RouteCaptureLane
    maturity: str
    owner_ea: int
    rewrite_anchor_ea: int
    owner_block_start_ea: int
    instruction_eas: tuple[int, ...]
    terminator_ea: int
    terminator_opcode: str
    transfer_kind: SemanticTransferKind
    direct_target_ea: int | None
    true_target_ea: int | None
    false_target_ea: int | None
    predicate_kind: str | None
    successor_eas: tuple[int, ...]
    physical_fallthrough_ea: int | None
    reachable_from_entry: bool

    def to_json(self) -> str:
        return json.dumps(
            {
                "direct_target_ea": _hex_or_none(self.direct_target_ea),
                "false_target_ea": _hex_or_none(self.false_target_ea),
                "instruction_eas": [_hex(ea) for ea in self.instruction_eas],
                "lane": self.lane.value,
                "maturity": self.maturity,
                "owner_block_start_ea": _hex(self.owner_block_start_ea),
                "owner_ea": _hex(self.owner_ea),
                "physical_fallthrough_ea": _hex_or_none(self.physical_fallthrough_ea),
                "predicate_kind": self.predicate_kind,
                "reachable_from_entry": self.reachable_from_entry,
                "rewrite_anchor_ea": _hex(self.rewrite_anchor_ea),
                "route_id": self.route_id,
                "successor_eas": [_hex(ea) for ea in self.successor_eas],
                "terminator_ea": _hex(self.terminator_ea),
                "terminator_opcode": self.terminator_opcode,
                "transfer_kind": self.transfer_kind.value,
                "true_target_ea": _hex_or_none(self.true_target_ea),
            },
            sort_keys=True,
            separators=(",", ":"),
        )


@dataclass(frozen=True)
class SemanticRouteObservation:
    route_id: str
    lane: RouteCaptureLane
    maturity: str
    outcome: str
    shape: SemanticRouteShape | None
    reason: str
    failed_invariant: str | None = None


@dataclass(frozen=True)
class RouteOracleComparison:
    route_id: str
    maturity: str
    candidate_variant: str
    outcome: str
    first_divergence: bool
    failed_invariant: str | None
    owner_ea: int
    rewrite_anchor_ea: int
    oracle_shape: SemanticRouteShape | None
    candidate_shape: SemanticRouteShape | None
    reason: str


@dataclass(frozen=True)
class RouteOracleRun:
    run_id: str
    function_ea: int
    fixture_sha256: str
    reference_binary_sha256: str
    candidate_binary_sha256: str
    reference_commit: str
    runtime_image: str
    runtime_image_id: str
    cache_disabled: bool
    metadata_json: str = "{}"

    def __post_init__(self) -> None:
        if not self.run_id:
            raise ValueError("route oracle run requires a run_id")
        for label, digest in (
            ("fixture", self.fixture_sha256),
            ("reference binary", self.reference_binary_sha256),
            ("candidate binary", self.candidate_binary_sha256),
        ):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest.lower()
            ):
                raise ValueError(f"{label} SHA-256 must contain 64 hexadecimal digits")
        if not self.reference_commit:
            raise ValueError("route oracle run requires the reference commit")
        if not self.runtime_image or not self.runtime_image_id:
            raise ValueError("route oracle run requires pinned runtime image identity")
        metadata = json.loads(self.metadata_json)
        if not isinstance(metadata, dict):
            raise ValueError("route oracle metadata must be a JSON object")


@dataclass(frozen=True, slots=True)
class ReferenceRouteOracleSelection:
    """Pinned reference authority selected for one fragment plan."""

    run: RouteOracleRun
    publication_root_ea: int
    routes: tuple[ReferenceRouteRewrite, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.run, RouteOracleRun):
            raise TypeError("reference route selection requires one oracle run")
        if not self.run.cache_disabled:
            raise ValueError("reference route selection requires a cache-disabled run")
        publication_root_ea = int(self.publication_root_ea)
        if publication_root_ea < 0:
            raise ValueError("reference route selection requires a publication root")
        routes = tuple(self.routes)
        if not routes or any(
            not isinstance(route, ReferenceRouteRewrite) for route in routes
        ):
            raise ValueError("reference route selection requires portable routes")
        if any(route.function_ea != self.run.function_ea for route in routes):
            raise ValueError("reference route selection has a function mismatch")
        _require_unique_reference_fields(routes)
        object.__setattr__(self, "publication_root_ea", publication_root_ea)
        object.__setattr__(self, "routes", routes)


@dataclass(frozen=True, slots=True)
class ReferenceRouteOracleCatalog:
    """Exact-input manifest authority exposed through a portable capability."""

    run: RouteOracleRun
    publication_root_ea: int
    routes: tuple[ReferenceRouteRewrite, ...]

    def __post_init__(self) -> None:
        selection = ReferenceRouteOracleSelection(
            run=self.run,
            publication_root_ea=self.publication_root_ea,
            routes=self.routes,
        )
        object.__setattr__(
            self,
            "publication_root_ea",
            selection.publication_root_ea,
        )
        object.__setattr__(self, "routes", selection.routes)

    @classmethod
    def from_manifest(
        cls,
        manifest: Mapping[str, object],
    ) -> ReferenceRouteOracleCatalog:
        """Parse the single supported manifest schema without aliases."""

        if not isinstance(manifest, Mapping):
            raise TypeError("semantic route oracle manifest must be an object")
        observed_version = manifest.get("schema_version")
        if observed_version != _MANIFEST_SCHEMA_VERSION:
            raise ValueError(
                "semantic route oracle manifest schema version mismatch: "
                f"expected={_MANIFEST_SCHEMA_VERSION} "
                f"observed={observed_version!r}"
            )
        raw_run = manifest.get("run")
        if not isinstance(raw_run, Mapping):
            raise ValueError("semantic route oracle manifest has no run object")
        raw_routes = manifest.get("routes")
        if not isinstance(raw_routes, list) or not raw_routes:
            raise ValueError("semantic route oracle manifest has no routes")
        if "publication_root_ea" not in manifest:
            raise ValueError(
                "semantic route oracle manifest lacks required field "
                "'publication_root_ea'"
            )
        run = _run_from_manifest(raw_run)
        routes = tuple(_route_from_manifest(raw) for raw in raw_routes)
        return cls(
            run=run,
            publication_root_ea=_manifest_int(
                manifest["publication_root_ea"],
                field="publication root",
            ),
            routes=routes,
        )

    def reference_oracle_scope_for(
        self,
        function_ea: int,
        native_key: NativePreanalysisKey,
    ) -> ReferenceRouteOracleSelection | None:
        """Return the complete configured fragment scope for one exact input."""

        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("reference route selection requires a native key")
        expected_input_identity = f"sha256:{self.run.candidate_binary_sha256.lower()}"
        if (
            int(function_ea) != self.run.function_ea
            or native_key.input_identity.lower() != expected_input_identity
        ):
            return None
        return ReferenceRouteOracleSelection(
            run=self.run,
            publication_root_ea=self.publication_root_ea,
            routes=self.routes,
        )

    def reference_oracle_for(
        self,
        function_ea: int,
        native_key: NativePreanalysisKey,
        rewrite_anchor_eas: Sequence[int],
    ) -> ReferenceRouteOracleSelection | None:
        """Return authority only for an exact input, function, and anchor set."""

        if not isinstance(native_key, NativePreanalysisKey):
            raise TypeError("reference route selection requires a native key")
        requested = tuple(int(anchor_ea) for anchor_ea in rewrite_anchor_eas)
        if not requested or len(set(requested)) != len(requested):
            return None
        expected_input_identity = f"sha256:{self.run.candidate_binary_sha256.lower()}"
        if (
            int(function_ea) != self.run.function_ea
            or native_key.input_identity.lower() != expected_input_identity
        ):
            return None
        by_anchor = {route.rewrite_anchor_ea: route for route in self.routes}
        if any(anchor_ea not in by_anchor for anchor_ea in requested):
            return None
        return ReferenceRouteOracleSelection(
            run=self.run,
            publication_root_ea=self.publication_root_ea,
            routes=tuple(by_anchor[anchor_ea] for anchor_ea in requested),
        )


@dataclass(frozen=True, slots=True)
class ReferenceRouteOracleRegistry:
    """Exact-input catalog registry for multiple configured functions."""

    catalogs: tuple[ReferenceRouteOracleCatalog, ...]

    def __post_init__(self) -> None:
        catalogs = tuple(self.catalogs)
        if not catalogs or any(
            not isinstance(catalog, ReferenceRouteOracleCatalog) for catalog in catalogs
        ):
            raise ValueError("reference route registry requires portable catalogs")
        authority_keys = tuple(
            (
                catalog.run.candidate_binary_sha256.lower(),
                int(catalog.run.function_ea),
            )
            for catalog in catalogs
        )
        if len(set(authority_keys)) != len(authority_keys):
            raise ValueError(
                "reference route registry requires unique input/function authority"
            )
        object.__setattr__(self, "catalogs", catalogs)

    @classmethod
    def from_manifests(
        cls,
        manifests: Sequence[Mapping[str, object]],
    ) -> ReferenceRouteOracleRegistry:
        """Parse the sole manifest schema for every configured authority."""

        return cls(
            catalogs=tuple(
                ReferenceRouteOracleCatalog.from_manifest(manifest)
                for manifest in manifests
            )
        )

    def reference_oracle_for(
        self,
        function_ea: int,
        native_key: NativePreanalysisKey,
        rewrite_anchor_eas: Sequence[int],
    ) -> ReferenceRouteOracleSelection | None:
        """Select one exact input/function catalog, then its requested routes."""

        for catalog in self.catalogs:
            selection = catalog.reference_oracle_for(
                function_ea,
                native_key,
                rewrite_anchor_eas,
            )
            if selection is not None:
                return selection
        return None

    def reference_oracle_scope_for(
        self,
        function_ea: int,
        native_key: NativePreanalysisKey,
    ) -> ReferenceRouteOracleSelection | None:
        """Select the complete configured fragment scope for one exact input."""

        for catalog in self.catalogs:
            selection = catalog.reference_oracle_scope_for(
                function_ea,
                native_key,
            )
            if selection is not None:
                return selection
        return None


def _require_unique_reference_fields(
    routes: Sequence[ReferenceRouteRewrite],
) -> None:
    fields = (
        ("route ids", tuple(route.route_id for route in routes)),
        (
            "rewrite anchors",
            tuple(route.rewrite_anchor_ea for route in routes),
        ),
        (
            "ledger identities",
            tuple(route.reference_ledger_identity for route in routes),
        ),
    )
    for label, values in fields:
        if len(set(values)) != len(values):
            raise ValueError(f"reference route catalog requires unique {label}")


def _manifest_int(value: object, *, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer or numeric string")
    if isinstance(value, int):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError as exc:
            raise ValueError(f"{field} must be an integer or numeric string") from exc
    raise ValueError(f"{field} must be an integer or numeric string")


def _run_from_manifest(raw: Mapping[str, object]) -> RouteOracleRun:
    try:
        cache_disabled = raw["cache_disabled"]
        if not isinstance(cache_disabled, bool):
            raise ValueError("route oracle cache_disabled must be a boolean")
        return RouteOracleRun(
            run_id=str(raw["run_id"]),
            function_ea=_manifest_int(raw["function_ea"], field="run function_ea"),
            fixture_sha256=str(raw["fixture_sha256"]),
            reference_binary_sha256=str(raw["reference_binary_sha256"]),
            candidate_binary_sha256=str(raw["candidate_binary_sha256"]),
            reference_commit=str(raw["reference_commit"]),
            runtime_image=str(raw["runtime_image"]),
            runtime_image_id=str(raw["runtime_image_id"]),
            cache_disabled=cache_disabled,
            metadata_json=json.dumps(raw.get("metadata", {}), sort_keys=True),
        )
    except KeyError as exc:
        raise ValueError(
            f"semantic route oracle run lacks required field {exc.args[0]!r}"
        ) from exc


def _optional_manifest_ea(
    raw: Mapping[str, object],
    field: str,
) -> int | None:
    value = raw.get(field)
    return None if value is None else _manifest_int(value, field=field)


def _route_from_manifest(raw: object) -> ReferenceRouteRewrite:
    if not isinstance(raw, Mapping):
        raise ValueError("semantic route oracle route is not an object")
    corridor = raw.get("corridor")
    if not isinstance(corridor, list) or not corridor:
        raise ValueError("semantic route oracle route has no corridor")
    parsed_corridor: list[tuple[int, int]] = []
    for item in corridor:
        if not isinstance(item, list) or len(item) != 2:
            raise ValueError("semantic route oracle corridor range is malformed")
        parsed_corridor.append(
            (
                _manifest_int(item[0], field="corridor start"),
                _manifest_int(item[1], field="corridor end"),
            )
        )
    try:
        return ReferenceRouteRewrite(
            route_id=str(raw["route_id"]),
            function_ea=_manifest_int(raw["function_ea"], field="function_ea"),
            owner_ea=_manifest_int(raw["owner_ea"], field="owner_ea"),
            rewrite_anchor_ea=_manifest_int(
                raw["rewrite_anchor_ea"], field="rewrite_anchor_ea"
            ),
            corridor=tuple(parsed_corridor),
            reference_phase=str(raw["reference_phase"]),
            original_transfer_kind=SemanticTransferKind(
                str(raw["original_transfer_kind"])
            ),
            final_transfer_kind=SemanticTransferKind(str(raw["final_transfer_kind"])),
            direct_target_ea=_optional_manifest_ea(raw, "direct_target_ea"),
            true_target_ea=_optional_manifest_ea(raw, "true_target_ea"),
            false_target_ea=_optional_manifest_ea(raw, "false_target_ea"),
            predicate_kind=(
                None
                if raw.get("predicate_kind") is None
                else str(raw["predicate_kind"])
            ),
            reference_ledger_identity=str(raw["reference_ledger_identity"]),
            reference_ledger_json=json.dumps(raw["reference_ledger"], sort_keys=True),
        )
    except KeyError as exc:
        raise ValueError(
            f"semantic route oracle route lacks required field {exc.args[0]!r}"
        ) from exc


@dataclass(frozen=True)
class RouteOracleCapture:
    run_id: str
    lane: RouteCaptureLane
    candidate_variant: str
    maturity: str
    snapshot_id: int
    binary_sha256: str
    d810_enabled: bool
    cache_disabled: bool
    metadata_json: str = "{}"

    def __post_init__(self) -> None:
        if not self.run_id or not self.candidate_variant or not self.maturity:
            raise ValueError("route oracle capture identity must be complete")
        if self.snapshot_id <= 0:
            raise ValueError("route oracle capture requires a persisted snapshot")
        if len(self.binary_sha256) != 64:
            raise ValueError("route oracle capture requires a SHA-256 digest")
        metadata = json.loads(self.metadata_json)
        if not isinstance(metadata, dict):
            raise ValueError("route oracle capture metadata must be a JSON object")


def _hex(value: int) -> str:
    return f"0x{int(value):X}"


def _hex_or_none(value: int | None) -> str | None:
    return None if value is None else _hex(value)


def _instruction_eas(block: BlockSnapshot) -> tuple[int, ...]:
    return tuple(int(instruction.ea) for instruction in block.instructions)


def _transfer_kind(opcode_name: str) -> SemanticTransferKind:
    if opcode_name == "m_goto":
        return SemanticTransferKind.DIRECT
    if opcode_name in {"m_ijmp", "m_jtbl"}:
        return SemanticTransferKind.INDIRECT
    if opcode_name == "m_ret":
        return SemanticTransferKind.RETURN
    if opcode_name.startswith("m_j"):
        return SemanticTransferKind.CONDITIONAL
    return SemanticTransferKind.UNKNOWN


def _predicate_kind(opcode_name: str) -> str | None:
    if not opcode_name.startswith("m_j") or opcode_name in {"m_ijmp", "m_jtbl"}:
        return None
    return opcode_name.removeprefix("m_j")


def _branch_target_serial(instruction: InstructionSnapshot) -> int | None:
    if instruction.meta is None:
        return None
    try:
        payload = json.loads(instruction.meta)
    except (TypeError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    candidates: list[int] = []
    for slot in ("l", "d", "r"):
        operand = payload.get(slot)
        if not isinstance(operand, dict) or operand.get("type") != "mop_b":
            continue
        block_num = operand.get("block_num")
        if isinstance(block_num, int):
            candidates.append(int(block_num))
    unique = tuple(dict.fromkeys(candidates))
    return unique[0] if len(unique) == 1 else None


def _reachable_serials(
    blocks: Sequence[BlockSnapshot],
    *,
    function_ea: int,
) -> frozenset[int]:
    by_serial = {int(block.serial): block for block in blocks}
    root_blocks = tuple(
        block
        for block in blocks
        if int(block.start_ea or -1) == int(function_ea)
        or int(function_ea) in _instruction_eas(block)
    )
    if not root_blocks:
        return frozenset()
    if len(root_blocks) == 1:
        root_serial = int(root_blocks[0].serial)
    else:
        predecessor_free_roots = tuple(
            block for block in root_blocks if int(block.npred) == 0 and not block.preds
        )
        if len(predecessor_free_roots) != 1:
            return frozenset()
        root_serial = int(predecessor_free_roots[0].serial)
    pending = [root_serial]
    reached: set[int] = set()
    while pending:
        serial = pending.pop()
        if serial in reached:
            continue
        reached.add(serial)
        block = by_serial.get(serial)
        if block is not None:
            pending.extend(
                int(successor)
                for successor in block.succs
                if int(successor) in by_serial
            )
    return frozenset(reached)


def _observation_failure(
    route: ReferenceRouteRewrite,
    *,
    lane: RouteCaptureLane,
    maturity: str,
    outcome: str,
    reason: str,
) -> SemanticRouteObservation:
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=lane,
        maturity=maturity,
        outcome=outcome,
        shape=None,
        reason=reason,
    )


def observe_route_shape(
    route: ReferenceRouteRewrite,
    blocks: Sequence[BlockSnapshot],
    *,
    lane: RouteCaptureLane,
    maturity: str,
) -> SemanticRouteObservation:
    """Project one route from a snapshot into a serial-free semantic shape."""

    by_serial = {int(block.serial): block for block in blocks}
    owner_blocks = tuple(
        block for block in blocks if int(block.start_ea or -1) == route.owner_ea
    )
    if not owner_blocks:
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="missing",
            reason=(f"route {route.route_id} has no owner at {_hex(route.owner_ea)}"),
        )
    if len(owner_blocks) != 1:
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="ambiguous",
            reason=(
                f"route {route.route_id} has {len(owner_blocks)} owners at "
                f"{_hex(route.owner_ea)}"
            ),
        )

    block = owner_blocks[0]
    instructions = tuple(block.instructions)
    if not any(
        int(instruction.ea) == route.rewrite_anchor_ea for instruction in instructions
    ):
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="missing",
            reason=(
                f"route {route.route_id} owner {_hex(route.owner_ea)} does not "
                f"contain rewrite anchor {_hex(route.rewrite_anchor_ea)}"
            ),
        )
    if not instructions or int(instructions[-1].ea) != route.rewrite_anchor_ea:
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="invalid",
            reason=(
                f"route {route.route_id} rewrite anchor "
                f"{_hex(route.rewrite_anchor_ea)} is not the block terminator"
            ),
        )
    instruction = instructions[-1]

    kind = _transfer_kind(instruction.opcode_name)
    target_serial = _branch_target_serial(instruction)
    successor_serials = tuple(int(successor) for successor in block.succs)
    missing_successors = tuple(
        successor for successor in successor_serials if successor not in by_serial
    )
    if missing_successors:
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="invalid",
            reason=(
                f"route {route.route_id} rewrite anchor "
                f"{_hex(route.rewrite_anchor_ea)} has unresolved successor owners"
            ),
        )
    successor_eas = tuple(
        sorted(
            int(by_serial[successor].start_ea or 0) for successor in successor_serials
        )
    )
    if any(successor_ea <= 0 for successor_ea in successor_eas):
        return _observation_failure(
            route,
            lane=lane,
            maturity=maturity,
            outcome="invalid",
            reason=(
                f"route {route.route_id} rewrite anchor "
                f"{_hex(route.rewrite_anchor_ea)} has successor without a native EA"
            ),
        )

    direct_target_ea: int | None = None
    true_target_ea: int | None = None
    false_target_ea: int | None = None
    physical_fallthrough_ea: int | None = None
    if kind is SemanticTransferKind.DIRECT:
        if len(successor_serials) != 1 or target_serial != successor_serials[0]:
            return _observation_failure(
                route,
                lane=lane,
                maturity=maturity,
                outcome="invalid",
                reason=(
                    f"direct route {route.route_id} at "
                    f"{_hex(route.rewrite_anchor_ea)} does not own exactly one "
                    "matching successor"
                ),
            )
        direct_target_ea = int(by_serial[target_serial].start_ea or 0)
    elif kind is SemanticTransferKind.CONDITIONAL:
        if (
            len(successor_serials) != 2
            or target_serial is None
            or target_serial not in successor_serials
        ):
            return _observation_failure(
                route,
                lane=lane,
                maturity=maturity,
                outcome="invalid",
                reason=(
                    f"conditional route {route.route_id} at "
                    f"{_hex(route.rewrite_anchor_ea)} does not own a complete pair"
                ),
            )
        fallthrough_serials = tuple(
            successor for successor in successor_serials if successor != target_serial
        )
        if (
            len(fallthrough_serials) != 1
            or int(block.serial) + 1 != fallthrough_serials[0]
        ):
            return _observation_failure(
                route,
                lane=lane,
                maturity=maturity,
                outcome="invalid",
                reason=(
                    f"conditional route {route.route_id} at "
                    f"{_hex(route.rewrite_anchor_ea)} has no exact physical fallthrough"
                ),
            )
        true_target_ea = int(by_serial[target_serial].start_ea or 0)
        false_target_ea = int(by_serial[fallthrough_serials[0]].start_ea or 0)
        physical_fallthrough_ea = false_target_ea

    reachable = int(block.serial) in _reachable_serials(
        blocks,
        function_ea=route.function_ea,
    )
    shape = SemanticRouteShape(
        route_id=route.route_id,
        lane=lane,
        maturity=maturity,
        owner_ea=route.owner_ea,
        rewrite_anchor_ea=route.rewrite_anchor_ea,
        owner_block_start_ea=int(block.start_ea or 0),
        instruction_eas=_instruction_eas(block),
        terminator_ea=int(instruction.ea),
        terminator_opcode=instruction.opcode_name,
        transfer_kind=kind,
        direct_target_ea=direct_target_ea,
        true_target_ea=true_target_ea,
        false_target_ea=false_target_ea,
        predicate_kind=_predicate_kind(instruction.opcode_name),
        successor_eas=successor_eas,
        physical_fallthrough_ea=physical_fallthrough_ea,
        reachable_from_entry=reachable,
    )
    return SemanticRouteObservation(
        route_id=route.route_id,
        lane=lane,
        maturity=maturity,
        outcome="observed",
        shape=shape,
        reason="",
    )


def _reference_shape_failure(
    route: ReferenceRouteRewrite,
    shape: SemanticRouteShape,
) -> tuple[str, str] | None:
    if shape.transfer_kind is not route.final_transfer_kind:
        return (
            "reference_transfer_kind",
            f"reference route {route.route_id} expected "
            f"{route.final_transfer_kind.value}, observed {shape.transfer_kind.value}",
        )
    if route.final_transfer_kind is SemanticTransferKind.DIRECT:
        if shape.direct_target_ea != route.direct_target_ea:
            return (
                "reference_direct_target",
                f"reference route {route.route_id} expected target "
                f"{_hex_or_none(route.direct_target_ea)}, observed "
                f"{_hex_or_none(shape.direct_target_ea)}",
            )
    elif route.final_transfer_kind is SemanticTransferKind.CONDITIONAL:
        if shape.predicate_kind != route.predicate_kind:
            return (
                "reference_predicate",
                f"reference route {route.route_id} predicate mismatch",
            )
        if (
            shape.true_target_ea != route.true_target_ea
            or shape.false_target_ea != route.false_target_ea
        ):
            return (
                "reference_conditional_targets",
                f"reference route {route.route_id} target pair mismatch",
            )
    return None


def _compare_one(
    route: ReferenceRouteRewrite,
    reference: SemanticRouteObservation,
    candidate: SemanticRouteObservation,
    *,
    candidate_variant: str,
) -> RouteOracleComparison:
    base = {
        "route_id": route.route_id,
        "maturity": reference.maturity,
        "candidate_variant": candidate_variant,
        "first_divergence": False,
        "owner_ea": route.owner_ea,
        "rewrite_anchor_ea": route.rewrite_anchor_ea,
        "oracle_shape": reference.shape,
        "candidate_shape": candidate.shape,
    }
    if reference.outcome != "observed" or reference.shape is None:
        return RouteOracleComparison(
            **base,
            outcome="rejected",
            failed_invariant="reference_observation",
            reason=reference.reason,
        )
    reference_failure = _reference_shape_failure(route, reference.shape)
    if reference_failure is not None:
        invariant, reason = reference_failure
        return RouteOracleComparison(
            **base,
            outcome="rejected",
            failed_invariant=invariant,
            reason=reason,
        )
    if candidate.outcome != "observed" or candidate.shape is None:
        return RouteOracleComparison(
            **base,
            outcome="diverged",
            failed_invariant=(candidate.failed_invariant or "candidate_observation"),
            reason=candidate.reason,
        )

    stable_fields = (
        "owner_ea",
        "rewrite_anchor_ea",
        "transfer_kind",
        "predicate_kind",
        "direct_target_ea",
        "true_target_ea",
        "false_target_ea",
        "successor_eas",
        "physical_fallthrough_ea",
        "reachable_from_entry",
    )
    for field_name in stable_fields:
        oracle_value = getattr(reference.shape, field_name)
        candidate_value = getattr(candidate.shape, field_name)
        if oracle_value != candidate_value:
            return RouteOracleComparison(
                **base,
                outcome="diverged",
                failed_invariant=field_name,
                reason=(
                    f"route {route.route_id} differs at {reference.maturity}: "
                    f"{field_name} oracle={oracle_value!r} "
                    f"candidate={candidate_value!r}"
                ),
            )
    return RouteOracleComparison(
        **base,
        outcome="matched",
        failed_invariant=None,
        reason="",
    )


def compare_route_maturities(
    route: ReferenceRouteRewrite,
    reference_by_maturity: Mapping[str, SemanticRouteObservation],
    candidate_by_maturity: Mapping[str, SemanticRouteObservation],
    *,
    maturity_order: Sequence[str],
    candidate_variant: str,
) -> tuple[RouteOracleComparison, ...]:
    """Compare one stable route and mark its earliest non-matching maturity."""

    if not candidate_variant:
        raise ValueError("route comparison requires a candidate variant")
    comparisons: list[RouteOracleComparison] = []
    first_divergence_marked = False
    for maturity in maturity_order:
        if (
            maturity not in reference_by_maturity
            or maturity not in candidate_by_maturity
        ):
            raise ValueError(f"route comparison lacks maturity {maturity}")
        reference = reference_by_maturity[maturity]
        candidate = candidate_by_maturity[maturity]
        if reference.maturity != maturity or candidate.maturity != maturity:
            raise ValueError(f"route observation maturity mismatch for {maturity}")
        comparison = _compare_one(
            route,
            reference,
            candidate,
            candidate_variant=candidate_variant,
        )
        if comparison.outcome != "matched" and not first_divergence_marked:
            comparison = replace(comparison, first_divergence=True)
            first_divergence_marked = True
        comparisons.append(comparison)
    return tuple(comparisons)


__all__ = [
    "ReferenceRouteRewrite",
    "ReferenceRouteOracleCatalog",
    "ReferenceRouteOracleRegistry",
    "ReferenceRouteOracleSelection",
    "RouteCaptureLane",
    "RouteOracleCapture",
    "RouteOracleComparison",
    "RouteOracleRun",
    "SemanticRouteObservation",
    "SemanticRouteShape",
    "SemanticTransferKind",
    "compare_route_maturities",
    "observe_route_shape",
]
