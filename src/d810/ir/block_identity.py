"""Stable block labels for diagnostics.

Block serials are local to a single MBA snapshot/maturity.  Diagnostics that
compare across maturities or after block creation must include at least the
serial-local snapshot context plus a physical/code identity.  These helpers are
pure ``d810.ir`` utilities for logs that only have a :class:`FlowGraph`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

from d810.core.maturity_labels import MaturityNumbering, mmat_label
from d810.core.native_preanalysis_key import NativePreanalysisKey
from d810.ir.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot, OperandKind
from d810.ir.storage_identity import (
    StorageIdentityKind,
    storage_identity_from_mop_snapshot,
)

_MASK64 = 0xFFFFFFFFFFFFFFFF
_SIGNED64_MAX = 0x7FFFFFFFFFFFFFFF
_BADADDR = _MASK64


@dataclass(frozen=True, slots=True)
class NativeEaInterval:
    """A native code-address interval used to identify a lifted block."""

    start_ea: int
    end_ea: int

    def __post_init__(self) -> None:
        start_ea = int(self.start_ea)
        end_ea = int(self.end_ea)
        if start_ea < 0 or end_ea <= start_ea:
            raise ValueError(
                "native EA intervals must be non-empty, non-negative half-open ranges"
            )
        object.__setattr__(self, "start_ea", start_ea)
        object.__setattr__(self, "end_ea", end_ea)


@dataclass(frozen=True, slots=True)
class NativeEaIntervalSet:
    """Canonical native intervals that survive MBA reconstruction."""

    intervals: tuple[NativeEaInterval, ...]

    def __post_init__(self) -> None:
        canonical = self._canonicalize(self.intervals)
        object.__setattr__(self, "intervals", canonical)

    @staticmethod
    def _canonicalize(
        intervals: Iterable[NativeEaInterval],
    ) -> tuple[NativeEaInterval, ...]:
        ordered = sorted(
            (
                (
                    interval
                    if isinstance(interval, NativeEaInterval)
                    else NativeEaInterval(*interval)
                )
                for interval in intervals
            ),
            key=lambda interval: (interval.start_ea, interval.end_ea),
        )
        merged: list[NativeEaInterval] = []
        for interval in ordered:
            if merged and interval.start_ea <= merged[-1].end_ea:
                previous = merged[-1]
                merged[-1] = NativeEaInterval(
                    previous.start_ea,
                    max(previous.end_ea, interval.end_ea),
                )
            else:
                merged.append(interval)
        return tuple(merged)

    @classmethod
    def from_intervals(
        cls,
        intervals: Iterable[NativeEaInterval],
    ) -> NativeEaIntervalSet:
        return cls(tuple(intervals))

    @property
    def is_empty(self) -> bool:
        return not self.intervals

    def contains(self, ea: int) -> bool:
        """Return whether an exact native-EA anchor belongs to this identity."""
        ea = int(ea)
        return any(
            interval.start_ea <= ea < interval.end_ea for interval in self.intervals
        )

    def diagnostic_label(self) -> str:
        if self.is_empty:
            return "native-ea=[]"
        return (
            "native-ea=["
            + ",".join(
                f"0x{interval.start_ea:X}-0x{interval.end_ea:X}"
                for interval in self.intervals
            )
            + "]"
        )


@dataclass(frozen=True, slots=True)
class StableBlockIdentity:
    """Serial-free cross-maturity block identity."""

    native_key: NativePreanalysisKey
    exact_instruction_eas: frozenset[int]
    native_ranges: NativeEaIntervalSet

    def __post_init__(self) -> None:
        if not isinstance(self.native_key, NativePreanalysisKey):
            raise TypeError("stable block identity requires a native key")
        exact_instruction_eas = frozenset(int(ea) for ea in self.exact_instruction_eas)
        if any(ea < 0 or ea >= _BADADDR for ea in exact_instruction_eas):
            raise ValueError("exact instruction EAs must be native addresses")
        if self.native_ranges.is_empty:
            raise ValueError("stable block identity requires native ranges")
        if any(not self.native_ranges.contains(ea) for ea in exact_instruction_eas):
            raise ValueError("exact instruction EAs must belong to native ranges")
        object.__setattr__(self, "exact_instruction_eas", exact_instruction_eas)

    @classmethod
    def from_intervals(
        cls,
        intervals: Iterable[NativeEaInterval],
        *,
        native_key: NativePreanalysisKey,
        exact_instruction_eas: Iterable[int] | None = None,
    ) -> StableBlockIdentity:
        native_ranges = NativeEaIntervalSet.from_intervals(intervals)
        if exact_instruction_eas is None:
            exact_instruction_eas = (
                interval.start_ea
                for interval in native_ranges.intervals
                if interval.end_ea == interval.start_ea + 1
            )
        return cls(
            native_key=native_key,
            exact_instruction_eas=frozenset(exact_instruction_eas),
            native_ranges=native_ranges,
        )

    @classmethod
    def from_instruction_eas(
        cls,
        instruction_eas: Iterable[int],
        *,
        native_key: NativePreanalysisKey,
    ) -> StableBlockIdentity:
        exact_instruction_eas = frozenset(int(ea) for ea in instruction_eas)
        return cls.from_intervals(
            (
                NativeEaInterval(ea, ea + 1)
                for ea in sorted(exact_instruction_eas)
                if 0 <= ea < _BADADDR
            ),
            native_key=native_key,
            exact_instruction_eas=exact_instruction_eas,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "native_key": self.native_key.to_dict(),
            "exact_instruction_eas": sorted(self.exact_instruction_eas),
            "native_ranges": [
                {"start_ea": interval.start_ea, "end_ea": interval.end_ea}
                for interval in self.native_ranges.intervals
            ],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> StableBlockIdentity:
        if set(payload) != {
            "native_key",
            "exact_instruction_eas",
            "native_ranges",
        }:
            raise ValueError("stable block identity fields mismatch")
        native_key_payload = payload["native_key"]
        exact_eas_payload = payload["exact_instruction_eas"]
        native_ranges_payload = payload["native_ranges"]
        if not isinstance(native_key_payload, dict):
            raise TypeError("stable block native_key must be an object")
        if not isinstance(exact_eas_payload, list):
            raise TypeError("stable block exact_instruction_eas must be a list")
        if not isinstance(native_ranges_payload, list):
            raise TypeError("stable block native_ranges must be a list")
        intervals: list[NativeEaInterval] = []
        for item in native_ranges_payload:
            if not isinstance(item, dict) or set(item) != {"start_ea", "end_ea"}:
                raise ValueError("stable block native range fields mismatch")
            intervals.append(NativeEaInterval(item["start_ea"], item["end_ea"]))
        return cls.from_intervals(
            intervals,
            native_key=NativePreanalysisKey.from_dict(native_key_payload),
            exact_instruction_eas=exact_eas_payload,
        )

    def diagnostic_label(self) -> str:
        return (
            f"input={self.native_key.input_identity} "
            f"function-rva=0x{self.native_key.function_rva:X} "
            f"exact-ea=[{','.join(f'0x{ea:X}' for ea in sorted(self.exact_instruction_eas))}] "
            f"{self.native_ranges.diagnostic_label()}"
        )


def stable_block_identity_semantic_anchor(
    identity: StableBlockIdentity,
) -> int:
    """Select one deterministic native EA for a portable block identity."""
    if not isinstance(identity, StableBlockIdentity):
        raise TypeError("semantic anchor requires a stable block identity")
    if identity.exact_instruction_eas:
        return min(identity.exact_instruction_eas)
    return identity.native_ranges.intervals[0].start_ea


def _stable_identity_ranges_contain(
    owner: StableBlockIdentity,
    candidate: StableBlockIdentity,
) -> bool:
    return all(
        any(
            int(owner_interval.start_ea) <= int(candidate_interval.start_ea)
            and int(candidate_interval.end_ea) <= int(owner_interval.end_ea)
            for owner_interval in owner.native_ranges.intervals
        )
        for candidate_interval in candidate.native_ranges.intervals
    )


def stable_block_identity_covers(
    owner: StableBlockIdentity,
    candidate: StableBlockIdentity,
) -> bool:
    """Return whether one physical identity fully realizes portable authority."""
    if not isinstance(owner, StableBlockIdentity) or not isinstance(
        candidate,
        StableBlockIdentity,
    ):
        raise TypeError("identity coverage requires stable block identities")
    return bool(
        owner.native_key == candidate.native_key
        and candidate.exact_instruction_eas.issubset(owner.exact_instruction_eas)
        and _stable_identity_ranges_contain(owner, candidate)
    )


def stable_block_identities_overlap(
    first: StableBlockIdentity,
    second: StableBlockIdentity,
) -> bool:
    """Return whether two portable identities own intersecting native code."""
    if not isinstance(first, StableBlockIdentity) or not isinstance(
        second,
        StableBlockIdentity,
    ):
        raise TypeError("identity overlap requires stable block identities")
    if first.native_key != second.native_key:
        return False
    return any(
        int(first_interval.start_ea) < int(second_interval.end_ea)
        and int(second_interval.start_ea) < int(first_interval.end_ea)
        for first_interval in first.native_ranges.intervals
        for second_interval in second.native_ranges.intervals
    )


def stable_block_identities_refine_at_anchor(
    first: StableBlockIdentity,
    second: StableBlockIdentity,
    anchor_ea: int,
) -> bool:
    """Match one logical block across a native/live range refinement."""
    if not isinstance(first, StableBlockIdentity) or not isinstance(
        second,
        StableBlockIdentity,
    ):
        raise TypeError("identity refinement requires stable block identities")
    anchor_ea = int(anchor_ea)
    return bool(
        first.native_key == second.native_key
        and anchor_ea in first.exact_instruction_eas
        and anchor_ea in second.exact_instruction_eas
        and (
            _stable_identity_ranges_contain(first, second)
            or _stable_identity_ranges_contain(second, first)
        )
    )


def stable_block_identity_token(identity: StableBlockIdentity) -> str:
    """Encode a serial-free plan-local token from complete native ownership."""
    if not isinstance(identity, StableBlockIdentity):
        raise TypeError("identity token requires a stable block identity")
    native_ranges = ",".join(
        f"0x{interval.start_ea:X}-0x{interval.end_ea:X}"
        for interval in identity.native_ranges.intervals
    )
    exact_instruction_eas = ",".join(
        f"0x{ea:X}" for ea in sorted(identity.exact_instruction_eas)
    )
    return f"{native_ranges};exact={exact_instruction_eas or 'none'}"


@dataclass(frozen=True, slots=True)
class CurrentMbaBlockIdentityBinding:
    """Tie one full stable identity to surviving current-MBA instruction EAs."""

    stable_identity: StableBlockIdentity
    live_instruction_eas: frozenset[int]

    def __post_init__(self) -> None:
        if not isinstance(self.stable_identity, StableBlockIdentity):
            raise TypeError("current-MBA block binding requires stable identity")
        live_instruction_eas = frozenset(int(ea) for ea in self.live_instruction_eas)
        if not live_instruction_eas or any(
            ea <= 0 or ea >= _BADADDR for ea in live_instruction_eas
        ):
            raise ValueError(
                "current-MBA block binding requires valid live instruction EAs"
            )
        object.__setattr__(
            self,
            "live_instruction_eas",
            live_instruction_eas,
        )


@dataclass(frozen=True, slots=True)
class CurrentMbaIdentityBindingSnapshot:
    """One receipt-scoped live/native binding with no physical block serials."""

    instruction_origins: tuple[tuple[int, int], ...]
    block_bindings: tuple[CurrentMbaBlockIdentityBinding, ...]

    def __post_init__(self) -> None:
        native_by_live: dict[int, int] = {}
        for row in tuple(self.instruction_origins):
            if not isinstance(row, tuple) or len(row) != 2:
                raise TypeError(
                    "current-MBA identity snapshot requires live/native EA pairs"
                )
            live_ea, native_ea = (int(value) for value in row)
            if (
                live_ea <= 0
                or native_ea <= 0
                or live_ea >= _BADADDR
                or native_ea >= _BADADDR
            ):
                raise ValueError(
                    "current-MBA identity snapshot requires valid positive EAs"
                )
            previous = native_by_live.get(live_ea)
            if previous is not None and previous != native_ea:
                raise ValueError(
                    "one current-MBA instruction cannot have multiple native origins"
                )
            native_by_live[live_ea] = native_ea

        block_bindings = tuple(self.block_bindings)
        if any(
            not isinstance(binding, CurrentMbaBlockIdentityBinding)
            for binding in block_bindings
        ):
            raise TypeError(
                "current-MBA identity snapshot contains an invalid block binding"
            )
        if len(set(block_bindings)) != len(block_bindings):
            raise ValueError(
                "current-MBA identity snapshot contains duplicate block bindings"
            )
        native_keys = {binding.stable_identity.native_key for binding in block_bindings}
        if len(native_keys) > 1:
            raise ValueError(
                "current-MBA identity snapshot spans multiple native identities"
            )

        binding_by_live: dict[int, CurrentMbaBlockIdentityBinding] = {}
        for binding in block_bindings:
            for live_ea in binding.live_instruction_eas:
                if live_ea in binding_by_live:
                    raise ValueError(
                        "one current-MBA instruction cannot anchor multiple blocks"
                    )
                native_ea = native_by_live.get(live_ea)
                if native_ea is None or not (
                    binding.stable_identity.native_ranges.contains(native_ea)
                ):
                    raise ValueError(
                        "current-MBA block anchor lacks matching native ownership"
                    )
                binding_by_live[live_ea] = binding
        if set(binding_by_live) != set(native_by_live):
            raise ValueError(
                "current-MBA instruction origins and block anchors must be complete"
            )

        object.__setattr__(
            self,
            "instruction_origins",
            tuple(sorted(native_by_live.items())),
        )
        object.__setattr__(
            self,
            "block_bindings",
            tuple(
                sorted(
                    block_bindings,
                    key=lambda binding: (
                        min(binding.live_instruction_eas),
                        binding.stable_identity.diagnostic_label(),
                    ),
                )
            ),
        )


def stable_block_identity_from_snapshot(
    block: BlockSnapshot,
    *,
    native_key: NativePreanalysisKey,
) -> StableBlockIdentity | None:
    """Derive portable identity from a lifted block's native EA anchors.

    Hex-Rays uses ``BADADDR`` for inserted/synthetic microcode.  Such a block
    intentionally has no cross-generation identity: a caller can still use a
    generation-local handle, but it must not survive a rebuild.  Every native
    instruction EA, plus the block start, contributes a unit interval so the
    resulting identity is independent of the current block serial.
    """
    instruction_eas = frozenset(
        native_ea
        for insn in block.insn_snapshots
        for native_ea in (
            int(insn.ea) if insn.native_ea is None else int(insn.native_ea),
        )
        if 0 <= native_ea < _BADADDR
    )
    native_anchors = set(instruction_eas)
    start_ea = (
        int(block.start_ea)
        if block.native_start_ea is None
        else int(block.native_start_ea)
    )
    if 0 <= start_ea < _BADADDR:
        native_anchors.add(start_ea)
    if not native_anchors:
        return None
    return StableBlockIdentity.from_intervals(
        (NativeEaInterval(ea, ea + 1) for ea in sorted(native_anchors)),
        native_key=native_key,
        exact_instruction_eas=instruction_eas,
    )


def refine_stable_block_identity_for_graph_block(
    graph: FlowGraph,
    block: BlockSnapshot,
    identity: StableBlockIdentity,
) -> StableBlockIdentity | None:
    """Remove a shared block-start coordinate contradicted by exact origins.

    Hex-Rays may assign the function entry EA as the physical ``start`` of an
    imported block whose instructions originate elsewhere.  A start shared by
    another current block is not portable ownership when this block has exact
    instruction origins and none of them owns that coordinate.
    """
    if not isinstance(graph, FlowGraph) or not isinstance(block, BlockSnapshot):
        raise TypeError("graph identity refinement requires a graph block")
    if not isinstance(identity, StableBlockIdentity):
        raise TypeError("graph identity refinement requires stable identity")

    start_ea = int(
        block.start_ea if block.native_start_ea is None else block.native_start_ea
    )
    if (
        not 0 <= start_ea < _BADADDR
        or start_ea in identity.exact_instruction_eas
        or not identity.exact_instruction_eas
        or not identity.native_ranges.contains(start_ea)
    ):
        return identity
    shared_start_count = sum(
        1
        for candidate in graph.blocks.values()
        if int(
            candidate.start_ea
            if candidate.native_start_ea is None
            else candidate.native_start_ea
        )
        == start_ea
    )
    if shared_start_count < 2:
        return identity

    retained_intervals: list[NativeEaInterval] = []
    for interval in identity.native_ranges.intervals:
        if not interval.start_ea <= start_ea < interval.end_ea:
            retained_intervals.append(interval)
            continue
        if interval.start_ea < start_ea:
            retained_intervals.append(NativeEaInterval(interval.start_ea, start_ea))
        if start_ea + 1 < interval.end_ea:
            retained_intervals.append(NativeEaInterval(start_ea + 1, interval.end_ea))
    if not retained_intervals:
        return None
    return StableBlockIdentity.from_intervals(
        retained_intervals,
        native_key=identity.native_key,
        exact_instruction_eas=identity.exact_instruction_eas,
    )


class BlockHandleProvenance(Enum):
    """Whether a generation-local block handle has native identity."""

    NATIVE = "native"
    IMPORTED_NATIVE = "imported_native"
    CREATED_SYNTHETIC = "created_synthetic"
    OBSERVED_EPHEMERAL = "observed_ephemeral"


@dataclass(frozen=True, slots=True)
class MbaBlockHandle:
    """A session-local logical block handle with no serial identity.

    The current serial belongs to :class:`BoundBlock`, returned only by the
    live index.  Keeping it out of this durable handle prevents an old MBA
    coordinate from silently crossing a maturity change or ``MERR_REDO``.
    """

    session_id: str
    token: str
    stable_identity: StableBlockIdentity | None
    provenance: BlockHandleProvenance

    def __post_init__(self) -> None:
        session_id = str(self.session_id)
        token = str(self.token)
        if not session_id or not token:
            raise ValueError("MBA handle requires non-empty session and token")
        if (
            self.provenance
            in {
                BlockHandleProvenance.NATIVE,
                BlockHandleProvenance.IMPORTED_NATIVE,
            }
            and self.stable_identity is None
        ):
            raise ValueError("native MBA handle requires stable identity")
        if (
            self.provenance
            in {
                BlockHandleProvenance.CREATED_SYNTHETIC,
                BlockHandleProvenance.OBSERVED_EPHEMERAL,
            }
            and self.stable_identity is not None
        ):
            raise ValueError("synthetic MBA handle must not claim stable identity")
        object.__setattr__(self, "session_id", session_id)
        object.__setattr__(self, "token", token)

    @classmethod
    def native(
        cls,
        identity: StableBlockIdentity,
        *,
        session_id: str,
        token: str,
    ) -> MbaBlockHandle:
        return cls(
            session_id=session_id,
            token=token,
            stable_identity=identity,
            provenance=BlockHandleProvenance.NATIVE,
        )

    @classmethod
    def created_synthetic(
        cls,
        *,
        session_id: str,
        token: str,
    ) -> MbaBlockHandle:
        return cls(
            session_id=session_id,
            token=token,
            stable_identity=None,
            provenance=BlockHandleProvenance.CREATED_SYNTHETIC,
        )

    @classmethod
    def observed_ephemeral(
        cls,
        *,
        session_id: str,
        token: str,
    ) -> MbaBlockHandle:
        """Create a generation-local handle for an anonymously observed block."""
        return cls(
            session_id=session_id,
            token=token,
            stable_identity=None,
            provenance=BlockHandleProvenance.OBSERVED_EPHEMERAL,
        )

    @classmethod
    def imported_native(
        cls,
        identity: StableBlockIdentity,
        *,
        session_id: str,
        token: str,
    ) -> MbaBlockHandle:
        """Create a live handle for an imported translation of native code."""
        return cls(
            session_id=session_id,
            token=token,
            stable_identity=identity,
            provenance=BlockHandleProvenance.IMPORTED_NATIVE,
        )


class RebindStatus(Enum):
    """The result of rebinding stable identity into the current MBA."""

    BOUND = "bound"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    STALE_GENERATION = "stale_generation"


@dataclass(frozen=True, slots=True)
class BoundBlock:
    """A current, uniquely rebound block handle."""

    handle: MbaBlockHandle
    serial: int
    generation: int
    anchor_ea: int | None

    def __post_init__(self) -> None:
        serial = int(self.serial)
        generation = int(self.generation)
        if serial < 0 or generation < 0:
            raise ValueError("bound block serial and generation must be non-negative")
        anchor_ea = self.anchor_ea
        if anchor_ea is not None:
            anchor_ea = int(anchor_ea)
            identity = self.handle.stable_identity
            if identity is not None and not identity.native_ranges.contains(anchor_ea):
                raise ValueError("bound block anchor must belong to native identity")
        object.__setattr__(self, "serial", serial)
        object.__setattr__(self, "generation", generation)
        object.__setattr__(self, "anchor_ea", anchor_ea)


@dataclass(frozen=True, slots=True)
class RebindResult:
    """A total rebinding result; only BOUND carries a block."""

    status: RebindStatus
    block: BoundBlock | None

    def __post_init__(self) -> None:
        if (self.status is RebindStatus.BOUND) is not (self.block is not None):
            raise ValueError("only a bound rebinding result may carry a block")

    @classmethod
    def bound(cls, block: BoundBlock) -> RebindResult:
        return cls(status=RebindStatus.BOUND, block=block)

    @classmethod
    def missing(cls) -> RebindResult:
        return cls(status=RebindStatus.MISSING, block=None)

    @classmethod
    def ambiguous(cls) -> RebindResult:
        return cls(status=RebindStatus.AMBIGUOUS, block=None)

    @classmethod
    def stale_generation(cls) -> RebindResult:
        return cls(status=RebindStatus.STALE_GENERATION, block=None)


def hex64(value: object | None) -> str | None:
    """Return the fixed-width EA/state text used by diagnostic tables."""
    if value is None:
        return None
    try:
        return f"0x{int(value) & _MASK64:016x}"
    except Exception:
        return None


def _safe_i64(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        value_int = int(value)
    except Exception:
        return None
    if value_int > _SIGNED64_MAX:
        return value_int - (1 << 64)
    return value_int


def _fnv1a_64(text: str) -> int:
    value = 0xCBF29CE484222325
    for byte in text.encode("utf-8", errors="surrogatepass"):
        value ^= byte
        value = (value * 0x100000001B3) & _MASK64
    return value


def maturity_label(value: object | None) -> str:
    """Return a stable maturity label for a metadata value."""
    if value is None:
        return "maturity=?"
    if isinstance(value, str):
        return f"maturity={value}"
    try:
        value_int = int(value)
    except Exception:
        return f"maturity={value}"
    return mmat_label(value_int, numbering=MaturityNumbering.WITH_ZERO)


def flow_graph_context_label(flow_graph: FlowGraph | None) -> str:
    """Return snapshot/maturity context carried by a FlowGraph."""
    if flow_graph is None:
        return "maturity=? snapshot=?"
    parts = [
        maturity_label(
            flow_graph.metadata.get(
                "producer_stage_id", flow_graph.metadata.get("maturity")
            )
        )
    ]
    snapshot_id = flow_graph.metadata.get("snapshot_id")
    if snapshot_id is not None:
        parts.append(f"snapshot={snapshot_id}")
    phase = flow_graph.metadata.get("phase")
    if phase is not None:
        parts.append(f"phase={phase}")
    return " ".join(parts)


def block_label(flow_graph: FlowGraph | None, serial: int | None) -> str:
    """Format ``blk[N]@0xEA`` using a FlowGraph snapshot."""
    if serial is None:
        return "blk[?]@?"
    serial_int = int(serial)
    if flow_graph is None:
        return f"blk[{serial_int}]@?"
    block = flow_graph.get_block(serial_int)
    if block is None:
        return f"blk[{serial_int}]@?"
    return f"blk[{serial_int}]@0x{int(block.start_ea):x}"


def edge_label(flow_graph: FlowGraph | None, source: int, target: int) -> str:
    """Format a source-to-target edge with EA labels on both ends."""
    return f"{block_label(flow_graph, source)} -> {block_label(flow_graph, target)}"


def instruction_fingerprint(
    instructions: Iterable[InsnSnapshot],
    *,
    limit: int = 4,
) -> str:
    """Return a compact instruction EA/opcode fingerprint."""
    parts: list[str] = []
    for idx, insn in enumerate(instructions):
        if idx >= limit:
            parts.append("...")
            break
        raw_opcode = getattr(insn, "raw_opcode", getattr(insn, "opcode", None))
        parts.append(f"0x{int(insn.ea):x}:op{int(raw_opcode)}")
    return "[" + ",".join(parts) + "]"


def block_fingerprint(
    flow_graph: FlowGraph | None,
    serial: int | None,
    *,
    limit: int = 4,
) -> str:
    """Return a compact fingerprint for a block's current body."""
    if serial is None or flow_graph is None:
        return "fp=[]"
    block = flow_graph.get_block(int(serial))
    if block is None:
        return "fp=[]"
    return "fp=" + instruction_fingerprint(block.insn_snapshots, limit=limit)


def _mop_type_name(value: object | None) -> str | None:
    if not isinstance(value, OperandKind) or value is OperandKind.UNKNOWN:
        return None
    return value.value


def _mop_row(mop: object | None) -> dict[str, object | None]:
    identity = storage_identity_from_mop_snapshot(mop)
    stack_offset = (
        identity.offset
        if identity is not None and identity.kind is StorageIdentityKind.STACK
        else None
    )
    return {
        "t": _mop_type_name(getattr(mop, "kind", None)),
        "o": _safe_i64(stack_offset),
        "s": _safe_i64(getattr(mop, "size", None)) if mop is not None else None,
        "v": hex64(getattr(mop, "value", None)),
    }


def block_body_observation_fingerprint(
    flow_graph: FlowGraph | None,
    serial: int | None,
) -> str | None:
    """Return the canonical body hash used by ``block_observations``.

    This is the join key for block lineage.  ``block_fingerprint`` is a compact
    human label; this hash mirrors the observation table's EA/opcode/operand
    shape so cloned blocks with duplicate EAs can still be correlated.
    """
    if serial is None or flow_graph is None:
        return None
    block = flow_graph.get_block(int(serial))
    if block is None:
        return None
    ea_fp = json.dumps(
        [hex64(insn.ea) for insn in block.insn_snapshots],
        separators=(",", ":"),
    )
    op_fp = json.dumps(
        [
            int(getattr(insn, "raw_opcode", getattr(insn, "opcode", 0)))
            for insn in block.insn_snapshots
        ],
        separators=(",", ":"),
    )
    operand_rows: list[dict[str, object | None]] = []
    for insn in block.insn_snapshots:
        d = _mop_row(getattr(insn, "d", None))
        left = _mop_row(getattr(insn, "l", None))
        r = _mop_row(getattr(insn, "r", None))
        operand_rows.append(
            {
                "d_t": d["t"],
                "d_o": d["o"],
                "d_s": d["s"],
                "l_t": left["t"],
                "l_o": left["o"],
                "l_v": left["v"],
                "r_t": r["t"],
                "r_o": r["o"],
                "r_v": r["v"],
            }
        )
    operand_fp = json.dumps(operand_rows, sort_keys=True, separators=(",", ":"))
    payload = json.dumps(
        {"ea": ea_fp, "op": op_fp, "operand": operand_fp},
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"fnv1a64:0x{_fnv1a_64(payload):016x}"


def block_origin_label(
    flow_graph: FlowGraph | None,
    *,
    assigned_serial: int,
    origin_serial: int | None,
    reason: str,
) -> str:
    """Format clone/insert origin context for diagnostics."""
    assigned = block_label(flow_graph, assigned_serial)
    origin = (
        block_label(flow_graph, origin_serial)
        if origin_serial is not None
        else "synthetic"
    )
    return f"{assigned} origin={origin} clone_reason={reason}"


__all__ = [
    "BlockHandleProvenance",
    "BoundBlock",
    "MbaBlockHandle",
    "NativeEaInterval",
    "NativeEaIntervalSet",
    "RebindResult",
    "RebindStatus",
    "StableBlockIdentity",
    "block_fingerprint",
    "block_body_observation_fingerprint",
    "block_label",
    "block_origin_label",
    "edge_label",
    "flow_graph_context_label",
    "hex64",
    "instruction_fingerprint",
    "maturity_label",
    "refine_stable_block_identity_for_graph_block",
    "stable_block_identities_overlap",
    "stable_block_identities_refine_at_anchor",
    "stable_block_identity_covers",
    "stable_block_identity_semantic_anchor",
    "stable_block_identity_from_snapshot",
    "stable_block_identity_token",
]
