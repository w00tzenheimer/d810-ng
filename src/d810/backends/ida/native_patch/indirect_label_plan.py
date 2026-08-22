"""Lower one discovered indirect-label request to a metadata-only patch plan.

This backend is the live-IDA half of the Task 7 migration.  It may *read*
IDA to capture a proposal, but every mutation remains in ``NativePatchGateway``
through ``IdaMetadataActionExecutor``.  The module deliberately accepts only
primitive request fields, never an object from ``d810.hexrays``: backends sit
below Hex-Rays in the import contract.
"""

from __future__ import annotations

import hashlib
import enum
import json
from dataclasses import dataclass
from collections.abc import Callable

from d810.backends.ida.native_patch.capture import (
    IdaLiveDatabaseReader,
    capture_range_evidence,
)
from d810.backends.ida.native_patch.metadata import (
    IdaMetadataActionExecutor,
    _parse_reversible_data_item_state,
    _parse_scoped_item_state,
    _scoped_item_token,
    reversible_data_item_head,
    is_reversible_data_item_state,
)
from d810.backends.ida.native_patch.phase_schema import (
    PhaseWitnessError,
    canonical_phase_item_state,
)
from d810.capabilities.native_patch import (
    NativeInstructionHead,
    NativeInstructionSequenceShape,
)
from d810.core.execution_journal import ExecutionAttemptId
from d810.transforms.native_patch_plan import (
    NativeAddressRange,
    NativeDatabaseIdentity,
    NativeEncodingEvidence,
    NativeFunctionIdentity,
    NativeMetadataAction,
    NativeMetadataActionKind,
    NativePatchOperation,
    NativePatchPlan,
)

__all__ = [
    "DecodedClosureBoundaryStop",
    "DecodedClosureInstruction",
    "DecodedClosureResult",
    "DecodedClosureTransfer",
    "DecodedClosureTransferKind",
    "IndirectLabelPlanBuildError",
    "IndirectLabelPlanFailureReason",
    "IndirectLabelPlanRequest",
    "build_indirect_label_metadata_plan",
]


@dataclass(frozen=True, slots=True)
class DecodedClosureInstruction:
    """Provider-neutral decoded instruction used by the closure oracle.

    ``effects`` is already the mutation-free, authorized decoded effect for
    this instruction.  The closure does not inspect live IDA xrefs: it only
    follows code rows whose source is this instruction and whose target is in
    the bounded group range.
    """

    ea: int
    size: int
    effects: tuple[tuple[int, int, int, bool, bool], ...]
    control_edges: tuple["DecodedClosureTransfer | tuple[int, str, bool]", ...] = ()
    # A transient instruction may consume the exact loaded UNKNOWN suffix of
    # its enclosing origin item.  The bounded closure remains rooted in the
    # origin extent, while this explicit proof records the larger destruction
    # extent that the inverse must clear back to UNKNOWN.
    destruction_extent: tuple[int, int] | None = None


class DecodedClosureTransferKind(str, enum.Enum):
    """Semantic class of a statically proven decoded control transfer."""

    FALLTHROUGH = "fallthrough"
    DIRECT_NEAR = "direct_near"
    CONDITIONAL_NEAR = "conditional_near"
    CALL = "call"
    FAR = "far"
    INDIRECT = "indirect"


@dataclass(frozen=True, slots=True)
class DecodedClosureTransfer:
    """Provider-neutral transfer evidence with explicit semantic provenance."""

    target: int
    kind: DecodedClosureTransferKind
    loaded: bool
    provenance: str

    def as_tuple(self) -> tuple[int, str, bool]:
        return (self.target, self.kind.value, self.loaded)


@dataclass(frozen=True, slots=True)
class DecodedClosureBoundaryStop:
    """A decoded start whose extent reaches preserved bytes at the boundary.

    The bytes are intentionally not admitted to the derived item partition;
    IDA cannot recreate them without consuming the neighboring original item.
    This is distinct from an undecodable instruction, which remains a hard
    planner failure.
    """

    ea: int
    effects: tuple[tuple[int, int, int, bool, bool], ...] = ()
    control_edges: tuple["DecodedClosureTransfer | tuple[int, str, bool]", ...] = ()


@dataclass(frozen=True, slots=True)
class DecodedClosureResult:
    """Exact derived item partition and xref witness for one group."""

    roots: tuple[int, ...]
    items: tuple[tuple[int, int], ...]
    xrefs: tuple[tuple[int, int, int, bool, bool], ...]


def _extent_is_fully_covered(
    start: int, end: int, extents: tuple[tuple[int, int], ...]
) -> bool:
    """Return whether every byte in ``[start,end)`` is planned for clearing."""

    cursor = int(start)
    for low, high in sorted(extents):
        if int(high) <= cursor:
            continue
        if int(low) > cursor:
            return False
        cursor = max(cursor, int(high))
        if cursor >= int(end):
            return True
    return cursor >= int(end)


def _transfer_parts(
    transfer: DecodedClosureTransfer | tuple[int, str, bool],
) -> tuple[int, str, bool]:
    """Validate and normalize one transfer record at the closure boundary."""
    if isinstance(transfer, DecodedClosureTransfer):
        if not transfer.provenance or not isinstance(transfer.loaded, bool):
            raise IndirectLabelPlanBuildError("closure transfer provenance is invalid")
        return transfer.as_tuple()
    # Keep provider-neutral unit fixtures written against the pre-v4 tuple
    # shape readable, but still validate the semantic class rather than
    # accepting arbitrary labels or truthy loadability values.
    if (
        not isinstance(transfer, tuple)
        or len(transfer) != 3
        or not isinstance(transfer[0], int)
        or not isinstance(transfer[1], str)
        or transfer[1] not in {item.value for item in DecodedClosureTransferKind}
        or not isinstance(transfer[2], bool)
    ):
        raise IndirectLabelPlanBuildError("closure transfer provenance is invalid")
    return (int(transfer[0]), transfer[1], bool(transfer[2]))


def _bounded_decoded_cfg_closure(
    *,
    group_low: int,
    group_high: int,
    roots: tuple[int, ...],
    decode: Callable[
        [int], DecodedClosureInstruction | DecodedClosureBoundaryStop | None
    ],
    seed_effects: tuple[tuple[int, int, int, bool, bool], ...] = (),
) -> DecodedClosureResult:
    """Compute a finite, mutation-free decoded CFG closure.

    Roots are supplied by already-authorized immediate effects.  Every
    decoded extent must be wholly inside ``[group_low, group_high)`` and all
    in-range code successors must be statically represented by the decoded
    effect.  An outgoing row is retained but never traversed.  Any malformed
    decoder result, overlap, target-to-interior edge, or missing decode is a
    hard planner abstention.
    """

    low, high = int(group_low), int(group_high)
    if low < 0 or high <= low:
        raise IndirectLabelPlanBuildError("invalid decoded closure range")
    seed_rows = tuple(sorted(set(seed_effects)))
    if any(
        not isinstance(row, tuple)
        or len(row) != 5
        or not all(isinstance(value, int) for value in row[:3])
        or any(value < 0 for value in row[:3])
        or not isinstance(row[3], bool)
        or not isinstance(row[4], bool)
        for row in seed_rows
    ):
        raise IndirectLabelPlanBuildError("closure seed provenance is invalid")
    ordered_roots = tuple(
        sorted(
            {
                *map(int, roots),
                *(int(target) for _source, target, _type, _user, is_code in seed_rows if is_code and low <= int(target) < high),
            }
        )
    )
    if any(root < low or root >= high for root in ordered_roots):
        raise IndirectLabelPlanBuildError("closure root escapes its group range")

    queue = list(ordered_roots)
    decoded: dict[int, DecodedClosureInstruction] = {}
    boundary_rows: set[tuple[int, int, int, bool, bool]] = set()
    while queue:
        ea = int(queue.pop(0))
        prior = decoded.get(ea)
        if prior is not None:
            continue
        try:
            record = decode(ea)
        except Exception as error:
            raise IndirectLabelPlanBuildError(
                f"closure decode failed at {ea:#x}"
            ) from error
        if isinstance(record, DecodedClosureBoundaryStop):
            if int(record.ea) != ea:
                raise IndirectLabelPlanBuildError(
                    f"closure boundary stop is inconsistent at {ea:#x}"
                )
            effects = tuple(record.effects)
            if effects != tuple(sorted(set(effects))):
                raise IndirectLabelPlanBuildError(
                    f"closure boundary effects are not canonical at {ea:#x}"
                )
            normalized_edges = tuple(_transfer_parts(edge) for edge in record.control_edges)
            edge_map = {(target, kind): loaded for target, kind, loaded in normalized_edges}
            if len(edge_map) != len(record.control_edges):
                raise IndirectLabelPlanBuildError(
                    f"closure boundary edges are not canonical at {ea:#x}"
                )
            for source, target, _type, _user, is_code in effects:
                if source != ea or not is_code:
                    continue
                matching = [
                    loaded
                    for (edge_target, edge_kind), loaded in edge_map.items()
                    if edge_target == int(target) and edge_kind == "fallthrough"
                ]
                if len(matching) != 1 or not matching[0]:
                    raise IndirectLabelPlanBuildError(
                        f"closure boundary lacks a proven preserved fallthrough at {ea:#x}"
                    )
            boundary_rows.update(effects)
            continue
        if record is None or not isinstance(record, DecodedClosureInstruction):
            raise IndirectLabelPlanBuildError(
                f"closure decode failed at {ea:#x}"
            )
        if int(record.ea) != ea or int(record.size) <= 0:
            raise IndirectLabelPlanBuildError(
                f"closure decoder returned an inconsistent record at {ea:#x}"
            )
        end = ea + int(record.size)
        if end > high:
            destruction_extent = record.destruction_extent
            if destruction_extent != (ea, end) or end <= high:
                raise IndirectLabelPlanBuildError(
                    f"closure instruction escapes group at {ea:#x}"
                )
        elif record.destruction_extent is not None:
            raise IndirectLabelPlanBuildError(
                f"closure destruction extent is not a boundary crossing at {ea:#x}"
            )
        for other_ea, other in decoded.items():
            if ea < other_ea + int(other.size) and other_ea < end:
                raise IndirectLabelPlanBuildError(
                    f"closure instruction extents overlap at {ea:#x}"
                )
            if other_ea < ea < other_ea + int(other.size):
                raise IndirectLabelPlanBuildError(
                    f"closure target enters instruction interior at {ea:#x}"
                )
        effects = tuple(record.effects)
        if effects != tuple(sorted(set(effects))):
            raise IndirectLabelPlanBuildError(
                f"closure effects are not canonical at {ea:#x}"
            )
        if any(
            not isinstance(row, tuple)
            or len(row) != 5
            or not all(isinstance(value, int) for value in row[:3])
            or any(value < 0 for value in row[:3])
            or not isinstance(row[3], bool)
            or not isinstance(row[4], bool)
            or row[0] != ea
            for row in effects
        ):
            raise IndirectLabelPlanBuildError(
                f"closure effect provenance is invalid at {ea:#x}"
            )
        normalized_edges = tuple(_transfer_parts(edge) for edge in record.control_edges)
        edge_map = {(target, kind): loaded for target, kind, loaded in normalized_edges}
        if len(edge_map) != len(record.control_edges):
            raise IndirectLabelPlanBuildError(
                f"closure control edges are not canonical at {ea:#x}"
            )
        for source, target, _xref_type, _user_owned, is_code in effects:
            if not is_code or source != ea:
                continue
            matching = [
                loaded
                for (edge_target, edge_kind), loaded in edge_map.items()
                if edge_target == int(target)
                and edge_kind in {"fallthrough", "direct_near"}
            ]
            if len(matching) != 1 or not matching[0]:
                raise IndirectLabelPlanBuildError(
                    f"closure code edge lacks a loaded direct provenance at {ea:#x}"
                )
            edge_kind = next(
                edge_kind
                for edge_target, edge_kind in edge_map
                if edge_target == int(target)
            )
            if not (low <= int(target) < high) and edge_kind != "direct_near":
                if not (
                    record.destruction_extent == (ea, end)
                    and edge_kind == "fallthrough"
                    and int(target) == end
                ):
                    raise IndirectLabelPlanBuildError(
                        f"closure fallthrough escapes group at {ea:#x}"
                    )
        decoded[ea] = DecodedClosureInstruction(
            ea, int(record.size), effects, tuple(normalized_edges),
            record.destruction_extent,
        )
        for source, target, _xref_type, _user_owned, is_code in effects:
            if not is_code or source != ea:
                continue
            if low <= target < high:
                queue.append(int(target))

    starts = tuple(sorted(decoded))
    for ea, record in decoded.items():
        end = ea + int(record.size)
        for target in starts:
            if ea < target < end:
                raise IndirectLabelPlanBuildError(
                    f"closure target enters instruction interior at {target:#x}"
                )
    effects = tuple(
        sorted(
            set(seed_rows)
            | boundary_rows
            | {
                row
                for record in decoded.values()
                for row in record.effects
            }
        )
    )
    return DecodedClosureResult(
        roots=ordered_roots,
        items=tuple((ea, int(decoded[ea].size)) for ea in starts),
        xrefs=effects,
    )

class IndirectLabelPlanFailureReason(str, enum.Enum):
    """Stable machine-readable reasons for planner abstention receipts."""

    UNCLASSIFIED = "unclassified"
    FUNCTION_TAIL_ADOPTION_UNSUPPORTED = "function_tail_adoption_unsupported"
    LOSSLESS_ITEM_RECREATION_UNSUPPORTED = "lossless_item_recreation_unsupported"


class IndirectLabelPlanBuildError(ValueError):
    """Live evidence cannot honestly lower the requested materialization."""

    def __init__(
        self,
        message: str,
        *,
        reason: IndirectLabelPlanFailureReason = (
            IndirectLabelPlanFailureReason.UNCLASSIFIED
        ),
        ea: int | None = None,
        before_shape: str | None = None,
        after_shape: str | None = None,
    ) -> None:
        super().__init__(message)
        if not isinstance(reason, IndirectLabelPlanFailureReason):
            raise TypeError("reason must be an IndirectLabelPlanFailureReason")
        if (
            reason
            is IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED
        ):
            if ea is None or not before_shape or not after_shape:
                raise ValueError(
                    "lossless item recreation errors require EA and both shapes"
                )
        self.reason = reason
        self.ea = None if ea is None else int(ea)
        self.before_shape = before_shape
        self.after_shape = after_shape


@dataclass(frozen=True, slots=True)
class IndirectLabelPlanRequest:
    function_ea: int
    label_start: int
    label_end: int
    table_address: int
    table_count: int
    target_eas: tuple[int, ...]
    dispatch_jump_ea: int | None
    switch_start_ea: int | None
    install_switch_info: bool
    state_base: int
    state_var_stkoff: int | None


def _instruction_shape(ea: int) -> NativeInstructionSequenceShape:
    import ida_ua
    import idc

    instruction = ida_ua.insn_t()
    size = int(ida_ua.decode_insn(instruction, int(ea)))
    if size <= 0:
        raise IndirectLabelPlanBuildError(f"cannot decode instruction at {ea:#x}")
    return NativeInstructionSequenceShape(
        heads=(
            NativeInstructionHead(
                ea=int(ea),
                length=size,
                mnemonic=str(idc.print_insn_mnem(int(ea)) or "unknown"),
                operand_shapes=(),
                successors=(),
            ),
        )
    )


def _instruction_size(ea: int) -> int:
    return _instruction_shape(int(ea)).heads[0].length


def _matches_rsp_state_write(ea: int, state_var_stkoff: int) -> int | None:
    import ida_bytes

    if int(ida_bytes.get_byte(ea)) != 0xC7:
        return None
    if int(ida_bytes.get_byte(ea + 1)) != 0x44:
        return None
    if int(ida_bytes.get_byte(ea + 2)) != 0x24:
        return None
    if int(ida_bytes.get_byte(ea + 3)) != (int(state_var_stkoff) & 0xFF):
        return None
    return int(ida_bytes.get_dword(ea + 4)) & 0xFFFFFFFF


def _following_jump_ea(start_ea: int, stop_ea: int) -> int | None:
    import ida_bytes
    import idaapi
    import idc

    badaddr = int(getattr(idaapi, "BADADDR", -1))
    ea = int(ida_bytes.next_head(int(start_ea), int(stop_ea)))
    local_stop = min(int(stop_ea), int(start_ea) + 0x80)
    while ea != badaddr and ea < local_stop:
        if str(idc.print_insn_mnem(ea) or "").lower() == "jmp":
            return int(ea)
        next_ea = int(ida_bytes.next_head(ea, int(stop_ea)))
        if next_ea == badaddr or next_ea <= ea:
            break
        ea = next_ea
    return None


def _parse_cref_state(token: str) -> set[tuple[int, int, bool]]:
    if not token.startswith("cref3:"):
        raise IndirectLabelPlanBuildError(f"unsupported xref state {token!r}")
    rows: set[tuple[int, int, bool]] = set()
    for row in token.removeprefix("cref3:").split(","):
        if not row:
            continue
        target_text, separator, remainder = row.partition("@")
        type_text, separator2, owner_text = remainder.partition("@")
        if not separator or not separator2 or owner_text not in {"a", "u"}:
            raise IndirectLabelPlanBuildError(f"unsupported xref state {token!r}")
        rows.add((int(target_text, 16), int(type_text, 16), owner_text == "u"))
    return rows


def _cref_state(rows: set[tuple[int, int, bool]]) -> str:
    return "cref3:" + ",".join(
        f"{target:#x}@{xref_type:#x}@{'u' if user_owned else 'a'}"
        for target, xref_type, user_owned in sorted(rows)
    )


def _missing_cref_targets(token: str, targets: set[int]) -> tuple[int, ...]:
    """Return targets not already delivered by any code-xref representation.

    IDA permits a source-target relation to be represented as an automatic
    flow edge, a jump edge, or a user-owned edge.  Adding a user jump edge over
    an existing automatic flow edge is not stable: reanalysis canonicalizes it
    back to the flow edge.  The planner therefore treats any existing edge to
    the target as already materialized and emits no redundant write.
    """
    existing_targets = {
        target for target, _xref_type, _user in _parse_cref_state(token)
    }
    return tuple(sorted(set(int(target) for target in targets) - existing_targets))


def _bundle_cref_targets(
    before: str, targets: set[int], *, xref_type: int
) -> tuple[str, tuple[int, ...]]:
    """Build one exact after-token for all missing targets at one source."""

    missing = _missing_cref_targets(before, targets)
    if not missing:
        return before, ()
    wanted = _parse_cref_state(before)
    wanted.update((target, int(xref_type), True) for target in missing)
    return _cref_state(wanted), missing


def _group_item_transition_before(
    before: str,
    *,
    target_ea: int,
    seen_data_heads: set[int],
) -> str:
    """Plan one shared data item as a reversible first-plus-unknown sequence.

    IDA's label table can place several instruction targets inside one scalar
    data item. The first target removes that item and retains its snapshot;
    later targets are genuinely ``unknown`` after that removal. Reverse
    journal order restores the later unknowns first, then the first action
    recreates the enclosing item.
    """

    head_ea = reversible_data_item_head(before, expected_ea=int(target_ea))
    if head_ea is None:
        return before
    if head_ea in seen_data_heads:
        return "unknown"
    seen_data_heads.add(head_ea)
    return before


def _item_transition_order(target_eas: tuple[int, ...]) -> tuple[int, ...]:
    """Order item promotions high-to-low to avoid adjacent-item overlap.

    IDA can decode an instruction at a lower target across the boundary of a
    following data item.  If that lower promotion runs first, IDA clears the
    following item before its own action can verify the recorded snapshot.
    Promoting the highest target first removes its enclosing item explicitly;
    lower targets then observe the intentional ``unknown`` grouped state.
    Reverse journal order restores the lower instruction before recreating the
    enclosing data item, so the transition remains lossless.
    """

    return tuple(sorted((int(ea) for ea in target_eas), reverse=True))


def _validate_grouped_item_actions(actions: list[NativeMetadataAction]) -> None:
    """Validate v2 sequencing and provenance before a plan is emitted."""
    groups: dict[tuple[int, tuple[int, ...]], dict[str, object]] = {}
    for action in actions:
        if action.kind is not NativeMetadataActionKind.RECREATE_ITEM:
            continue
        for token in (action.expected_before, action.expected_after):
            if not token.startswith("item-xrefs:v2:"):
                continue
            parsed = _parse_scoped_item_state(token, expected_ea=action.ea)
            if parsed is None:
                raise IndirectLabelPlanBuildError(
                    f"malformed grouped item action at {action.ea:#x}"
                )
            key = (int(parsed["head_ea"]), tuple(parsed["group_targets"]))
            group = groups.setdefault(
                key,
                {"origin": parsed["origin_data_state"], "seen_first": False},
            )
            if parsed["origin_data_state"] != group["origin"]:
                raise IndirectLabelPlanBuildError("group origin provenance drift")
            item_state = str(parsed["item_state"])
            if item_state.startswith("data:v2:"):
                if group["seen_first"]:
                    raise IndirectLabelPlanBuildError(
                        "group contains more than one first data transition"
                    )
                group["seen_first"] = True
            elif item_state == "unknown" and not group["seen_first"]:
                raise IndirectLabelPlanBuildError(
                    "standalone grouped unknown is not an authorized transition"
                )
    for group in groups.values():
        if not group["seen_first"]:
            raise IndirectLabelPlanBuildError(
                "group has no first data:v2 transition"
            )


def _touching_xrefs(
    rows: tuple[tuple[int, int, int, bool, bool], ...],
    *,
    low: int,
    high: int,
) -> set[tuple[int, int, int, bool, bool]]:
    return {
        row
        for row in rows
        if low <= int(row[0]) < high or low <= int(row[1]) < high
    }


def _project_group_witnesses(
    actions: list[NativeMetadataAction],
    effects: dict[int, tuple[tuple[int, int, int, bool, bool], ...]],
    groups: dict[
        int,
        tuple[int, int, tuple[tuple[int, int, int, bool, bool], ...]],
    ],
) -> dict[
    int,
    dict[int, tuple[
        tuple[tuple[int, int, int, bool, bool], ...],
        tuple[tuple[int, int, int, bool, bool], ...],
    ]],
]:
    """Replay every authorized action into every touching grouped witness.

    ``effects`` is the mutation-free, action-owned effect set: decoded rows
    for item actions and exact after-minus-before rows for xref actions.  This
    projection only routes rows into scopes; it never invents a row from an
    address relationship.
    """

    current = {
        head: set(origin)
        for head, (_low, _high, origin) in groups.items()
    }
    projected: dict[int, dict[int, tuple[tuple, tuple]]] = {}
    for index, _action in enumerate(actions):
        if index not in effects:
            raise IndirectLabelPlanBuildError(
                f"missing exact effect provenance for action {index}"
            )
        event = tuple(effects[index])
        projected[index] = {}
        for head, (low, high, _origin) in groups.items():
            before = set(current[head])
            touching = _touching_xrefs(event, low=low, high=high)
            if before.intersection(touching):
                raise IndirectLabelPlanBuildError(
                    f"predicted grouped xref already exists before action {index}"
                )
            after = before | touching
            projected[index][head] = (
                tuple(sorted(before)),
                tuple(sorted(after)),
            )
            current[head] = after
    return projected


def _reverse_group_witnesses(
    actions: list[NativeMetadataAction],
    effects: dict[int, tuple[tuple[int, int, int, bool, bool], ...]],
    groups: dict[
        int,
        tuple[int, int, tuple[tuple[int, int, int, bool, bool], ...]],
    ],
) -> dict[
    int,
    dict[int, tuple[
        tuple[tuple[int, int, int, bool, bool], ...],
        tuple[tuple[int, int, int, bool, bool], ...],
    ]],
]:
    """Replay exact event removal in reverse action order."""

    forward = _project_group_witnesses(actions, effects, groups)
    final = {
        head: set(forward[len(actions) - 1][head][1])
        for head in groups
    }
    reversed_projection: dict[int, dict[int, tuple[tuple, tuple]]] = {}
    for index in reversed(range(len(actions))):
        if index not in effects:
            raise IndirectLabelPlanBuildError(
                f"missing exact effect provenance for action {index}"
            )
        event = tuple(effects[index])
        reversed_projection[index] = {}
        for head, (low, high, _origin) in groups.items():
            present = set(final[head])
            touching = _touching_xrefs(event, low=low, high=high)
            if not touching.issubset(present):
                raise IndirectLabelPlanBuildError(
                    f"predicted grouped xref is absent before reverse action {index}"
                )
            before = present - touching
            reversed_projection[index][head] = (
                tuple(sorted(before)),
                tuple(sorted(present)),
            )
            final[head] = before
    return reversed_projection


def _analysis_phase_token(
    *,
    origin_data_state: str,
    group_targets: tuple[int, ...],
    before_items: tuple[tuple[int, int, str], ...],
    after_items: tuple[tuple[int, int, str], ...],
    before_xrefs: tuple[tuple[int, int, int, bool, bool], ...],
    after_xrefs: tuple[tuple[int, int, int, bool, bool], ...],
    postconditions: tuple[tuple[int, str], ...],
    origin_extent: tuple[int, int],
    destruction_extent: tuple[int, int],
) -> str:
    """Serialize one exact phase-A/phase-B analysis witness."""

    payload = {
        "version": 4,
        "origin_data_state": origin_data_state,
        "origin_extent": list(origin_extent),
        "destruction_extent": list(destruction_extent),
        "group_targets": list(group_targets),
        "before_items": [list(row) for row in before_items],
        "after_items": [list(row) for row in after_items],
        "before_xrefs": [
            {
                "source_ea": source,
                "target_ea": target,
                "xref_type": xref_type,
                "user_owned": user_owned,
                "is_code": is_code,
            }
            for source, target, xref_type, user_owned, is_code in before_xrefs
        ],
        "after_xrefs": [
            {
                "source_ea": source,
                "target_ea": target,
                "xref_type": xref_type,
                "user_owned": user_owned,
                "is_code": is_code,
            }
            for source, target, xref_type, user_owned, is_code in after_xrefs
        ],
        "postconditions": [
            {"ea": ea, "state": state} for ea, state in postconditions
        ],
    }
    return "analysis-phase:v4:" + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


def _with_user_cref(
    executor: IdaMetadataActionExecutor,
    *,
    source_ea: int,
    target_ea: int,
) -> NativeMetadataAction | None:
    import ida_xref

    before = executor.read_state(NativeMetadataActionKind.UPDATE_XREF, source_ea)
    wanted = _parse_cref_state(before)
    wanted.add((int(target_ea), int(ida_xref.fl_JN), True))
    after = _cref_state(wanted)
    if after == before:
        return None
    return NativeMetadataAction(
        kind=NativeMetadataActionKind.UPDATE_XREF,
        ea=int(source_ea),
        expected_before=before,
        expected_after=after,
    )


def _function_identity(
    reader: IdaLiveDatabaseReader,
    *,
    ownership,
) -> NativeFunctionIdentity:
    image = b"".join(
        reader.read_current_bytes(chunk.start_ea, chunk.end_ea) or b""
        for chunk in ownership.chunk_ranges
    )
    if not image:
        raise IndirectLabelPlanBuildError("cannot capture owning function bytes")
    return NativeFunctionIdentity(
        entry_ea=ownership.owning_function_entry_ea,
        chunk_ranges=ownership.chunk_ranges,
        inherited_bytes_hash=hashlib.sha256(image).hexdigest(),
    )


def _database_identity(function_ea: int) -> NativeDatabaseIdentity:
    """Use the attested loader SHA and durable IDB UUID, never a path hash.

    The input path remains a locator only, so it is retained solely as the
    non-authoritative ``database_path_hash`` field.  A missing loader SHA or
    durable attestation is an abstention boundary: manufacturing an identity
    from path/processor/image-base would make certificates portable across
    distinct inputs.
    """
    import ida_nalt
    import idaapi

    from d810.backends.hexrays.native_preanalysis_key import (
        resolve_native_preanalysis_identity,
    )

    resolution = resolve_native_preanalysis_identity(
        int(function_ea), profile_config={}
    )
    native_key = resolution.native_key
    database_uuid = resolution.identity_resolution.database_uuid
    if (
        native_key is None
        or database_uuid is None
        or not resolution.external_evidence_allowed
    ):
        raise IndirectLabelPlanBuildError(
            "missing attested loader identity or durable database UUID: "
            + resolution.identity_resolution.reason
        )
    path = str(ida_nalt.get_input_file_path() or "<unnamed-idb>")
    image_base = int(idaapi.get_imagebase())
    path_hash = hashlib.sha256(path.encode("utf-8")).hexdigest()
    return NativeDatabaseIdentity(
        idb_uuid=database_uuid,
        input_file_hash=native_key.input_identity.removeprefix("sha256:"),
        processor=native_key.processor,
        bitness=native_key.bitness,
        image_base=image_base,
        database_path_hash=path_hash,
    )


def build_indirect_label_metadata_plan(
    request: IndirectLabelPlanRequest,
    *,
    authorizing_attempt_id: ExecutionAttemptId,
) -> NativePatchPlan:
    """Capture one fully evidenced, zero-byte materialization plan.

    Any missing decode, ownership, or metadata state raises
    :class:`IndirectLabelPlanBuildError`; callers must turn that into a
    read-only abstention rather than approximating an IDA mutation.
    """
    if not isinstance(authorizing_attempt_id, ExecutionAttemptId):
        raise TypeError("authorizing_attempt_id must be an ExecutionAttemptId")
    dispatch_jump_ea = request.dispatch_jump_ea
    if dispatch_jump_ea is None:
        raise IndirectLabelPlanBuildError("indirect dispatch jump was not found")
    reader = IdaLiveDatabaseReader()
    executor = IdaMetadataActionExecutor()
    shape = _instruction_shape(int(dispatch_jump_ea))
    anchor = NativeAddressRange(
        int(dispatch_jump_ea), int(dispatch_jump_ea) + shape.heads[0].length
    )
    captured = capture_range_evidence(
        reader,
        anchor,
        function_ea=int(request.function_ea),
    )
    if not captured.ok or captured.evidence is None:
        raise IndirectLabelPlanBuildError(str(captured.reason))
    evidence = captured.evidence

    actions: list[NativeMetadataAction] = []
    import ida_bytes
    import ida_funcs

    requires_tail = any(
        (owner := ida_funcs.get_func(int(target_ea))) is None
        or int(owner.start_ea) != int(request.function_ea)
        for target_ea in request.target_eas
    )
    if requires_tail:
        # A detached tail requires a positive live-IDB adoption oracle before
        # it can become an authorized writer route.  The bundled fixture has
        # no detached creatable code span, so this transition is intentionally
        # unavailable rather than carrying an unproven append/remove inverse.
        raise IndirectLabelPlanBuildError(
            "function-tail adoption is not yet proven losslessly reversible",
            reason=(
                IndirectLabelPlanFailureReason.FUNCTION_TAIL_ADOPTION_UNSUPPORTED
            ),
        )

    ordered_targets = _item_transition_order(request.target_eas)
    decoded_sizes: dict[int, int] = {}
    for target_ea in ordered_targets:
        try:
            decoded_sizes[int(target_ea)] = _instruction_size(int(target_ea))
        except IndirectLabelPlanBuildError:
            raise
    for first_ea, first_size in sorted(decoded_sizes.items()):
        for second_ea, second_size in sorted(decoded_sizes.items()):
            if first_ea >= second_ea:
                continue
            if first_ea + first_size > second_ea:
                raise IndirectLabelPlanBuildError(
                    f"decoded target extents overlap at {first_ea:#x} and {second_ea:#x}"
                )
    captured_before = {
        int(target_ea): executor.read_state(
            NativeMetadataActionKind.RECREATE_ITEM, int(target_ea)
        )
        for target_ea in ordered_targets
    }
    grouped_targets: dict[int, tuple[int, ...]] = {}
    for target_ea, before in captured_before.items():
        head_ea = reversible_data_item_head(before, expected_ea=target_ea)
        if head_ea is None or not before.startswith("data:v2:"):
            continue
        group = tuple(
            sorted(
                candidate
                for candidate, candidate_before in captured_before.items()
                if candidate_before.startswith("data:v2:")
                and reversible_data_item_head(candidate_before, expected_ea=candidate)
                == head_ea
            )
        )
        grouped_targets[head_ea] = group
    group_progress: dict[int, tuple[tuple[int, int, int, bool, bool], ...]] = {}
    group_origins: dict[int, str] = {}
    group_sizes: dict[int, int] = {}
    group_code_sizes: dict[int, dict[int, int]] = {}
    seen_data_heads: set[int] = set()
    for target_ea in ordered_targets:
        before = captured_before[target_ea]
        after = f"code:{decoded_sizes[target_ea]}"
        if before == "unknown":
            flags = ida_bytes.get_flags(int(target_ea))
            if not (
                ida_bytes.is_unknown(flags)
                and int(ida_bytes.get_item_head(int(target_ea))) == int(target_ea)
            ):
                raise IndirectLabelPlanBuildError(
                    f"target is not an explicit unknown item head at {target_ea:#x}"
                )
            # Required function reanalysis/redo reclaims such an item as code
            # during restore, so UNKNOWN -> CODE has no lossless inverse yet.
            # Its head witness is intentionally checked above to make the
            # refusal diagnostic precise rather than conflating it with tails.
            raise IndirectLabelPlanBuildError(
                "unknown-item recreation is not yet proven reversible after "
                f"required reanalysis at {target_ea:#x}"
            )
        elif before == after:
            # Keep the target's final item witness stable across a rerun.  The
            # gateway recognizes this as a no-op and never calls IDA's item
            # writer, but the certificate still proves the same target set.
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(target_ea),
                    expected_before=before,
                    expected_after=after,
                )
            )
        elif is_reversible_data_item_state(before, expected_ea=int(target_ea)):
            # A narrow scalar-data snapshot preserves the exact IDA flags,
            # per-byte flags, and bytes needed to reverse the data->code
            # promotion.  Generic ``data:<size>`` remains fail-closed.
            if before.startswith("data:v2:"):
                data = _parse_reversible_data_item_state(
                    before, expected_ea=int(target_ea)
                )
                assert data is not None
                head_ea = int(data["head_ea"])
                group = grouped_targets.get(head_ea, ())
                cumulative = group_progress.get(head_ea, tuple(data["xrefs"]))
                if head_ea not in group_origins:
                    inner_before = before
                    group_origins[head_ea] = before
                else:
                    inner_before = "unknown"
                expected_before = _scoped_item_token(
                    ea=int(target_ea),
                    head_ea=head_ea,
                    size=int(data["size"]),
                    item_state=inner_before,
                    xrefs=cumulative,
                    origin_data_state=group_origins[head_ea],
                    group_targets=group,
                )
                derived = executor._predict_code_xrefs(int(target_ea))[1]
                cumulative = tuple(sorted(set(cumulative) | set(derived)))
                group_progress[head_ea] = cumulative
                group_sizes[head_ea] = int(data["size"])
                group_code_sizes.setdefault(head_ea, {})[int(target_ea)] = decoded_sizes[
                    int(target_ea)
                ]
                expected_after = _scoped_item_token(
                    ea=int(target_ea),
                    head_ea=head_ea,
                    size=int(data["size"]),
                    item_state=after,
                    xrefs=cumulative,
                    origin_data_state=group_origins[head_ea],
                    group_targets=group,
                )
            else:
                expected_before = _group_item_transition_before(
                    before,
                    target_ea=int(target_ea),
                    seen_data_heads=seen_data_heads,
                )
                expected_after = after
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(target_ea),
                    expected_before=expected_before,
                    expected_after=expected_after,
                )
            )
        elif before != after:
            raise IndirectLabelPlanBuildError(
                f"cannot losslessly recreate {before!r} as {after!r} at {target_ea:#x}",
                reason=(
                    IndirectLabelPlanFailureReason.LOSSLESS_ITEM_RECREATION_UNSUPPORTED
                ),
                ea=int(target_ea),
                before_shape=before,
                after_shape=after,
            )

    import idaapi

    badaddr = int(getattr(idaapi, "BADADDR", -1))
    fallthrough_ea = int(ida_bytes.next_head(int(dispatch_jump_ea), badaddr))
    alternate_source = int(ida_bytes.prev_head(int(dispatch_jump_ea), 0))
    targets_by_source: dict[int, set[int]] = {}
    for target_ea in request.target_eas:
        source_ea = int(dispatch_jump_ea)
        if (
            int(target_ea) == fallthrough_ea
            and alternate_source != badaddr
            and alternate_source < int(dispatch_jump_ea)
        ):
            source_ea = alternate_source
        targets_by_source.setdefault(source_ea, set()).add(int(target_ea))
    import idc

    # A table label physically adjacent to a no-fallthrough jump needs an
    # explicit flow boundary for Hex-Rays to retain the separate handler body.
    # IDA removes every synthetic representation we measured during required
    # reanalysis, so the gateway cannot create or certify one. Accept an
    # already-normalized boundary, otherwise abstain before journal prepare.
    for target_ea in request.target_eas:
        previous_ea = int(ida_bytes.prev_head(int(target_ea), int(request.function_ea)))
        if previous_ea == badaddr or previous_ea >= int(target_ea):
            continue
        if int(ida_bytes.next_head(previous_ea, int(target_ea) + 16)) != int(target_ea):
            continue
        if str(idc.print_insn_mnem(previous_ea) or "").lower() != "jmp":
            continue
        boundary_state = executor.read_state(
            NativeMetadataActionKind.UPDATE_XREF,
            previous_ea,
        )
        if int(target_ea) in _missing_cref_targets(
            boundary_state, {int(target_ea)}
        ):
            # This edge is an analysis-only block-boundary hint, not a
            # requested semantic mutation. Do not manufacture a user xref
            # merely to satisfy a planner witness; actual requested xrefs
            # below remain transactional and fail closed.
            continue
        actions.append(
            NativeMetadataAction(
                kind=NativeMetadataActionKind.UPDATE_XREF,
                ea=previous_ea,
                expected_before=boundary_state,
                expected_after=boundary_state,
            )
        )
    if request.state_var_stkoff is not None:
        target_by_state = {
            int(request.state_base) + index: int(target_ea)
            for index, target_ea in enumerate(request.target_eas)
        }
        for ea in range(int(request.function_ea), int(request.label_end) - 7):
            state_value = _matches_rsp_state_write(ea, int(request.state_var_stkoff))
            if state_value is None:
                continue
            target_ea = target_by_state.get(state_value)
            if target_ea is None:
                continue
            source_ea = _following_jump_ea(ea, int(request.label_end)) or ea
            # These resolved-state crefs are optional analysis hints.  The
            # legacy writer also tolerates their initial rejection and only
            # refreshes them after handler-body reanalysis.  A native plan
            # cannot promise an exact reversible after-state from an undefined
            # source, so include only sources that are already instruction
            # heads; the required dispatcher fan-out above is unaffected.
            if not ida_bytes.is_code(ida_bytes.get_flags(int(source_ea))):
                continue
            targets_by_source.setdefault(source_ea, set()).add(target_ea)
    for source_ea, targets in sorted(targets_by_source.items()):
        before = executor.read_state(NativeMetadataActionKind.UPDATE_XREF, source_ea)
        import ida_xref

        # One action owns the complete source fan-out.  The executor applies
        # the user-edge additions as a local failure-atomic batch, so the
        # journal can reverse the entire source transition as one state move.
        after, missing_targets = _bundle_cref_targets(
            before, targets, xref_type=int(ida_xref.fl_JN)
        )
        if not missing_targets:
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=source_ea,
                    expected_before=before,
                    expected_after=before,
                )
            )
        else:
            # Keep all additions for one source in one failure-atomic action.
            # IDA can drop an earlier user edge while the same source is being
            # revisited, so sequential expected-before witnesses are not
            # stable on the live database.
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.UPDATE_XREF,
                    ea=source_ea,
                    expected_before=before,
                    expected_after=after,
                )
            )

    # Read-only composite seals are the final scoped metadata proof for each
    # grouped target.  They are deliberately appended after explicit user
    # cref actions so their witness includes every planned edge touching the
    # former data range; the gateway therefore never journals or mutates them.
    for head_ea, group in sorted(grouped_targets.items()):
        if head_ea not in group_progress or head_ea not in group_origins:
            continue
        low, high = head_ea, head_ea + group_sizes[head_ea]
        witness = set(group_progress[head_ea])
        for action in actions:
            if action.kind is not NativeMetadataActionKind.UPDATE_XREF:
                continue
            for target, xref_type, user_owned in _parse_cref_state(
                action.expected_after
            ):
                if user_owned and (low <= action.ea < high or low <= target < high):
                    witness.add((int(action.ea), int(target), int(xref_type), True, True))
        for target_ea in group:
            code_size = group_code_sizes[head_ea].get(int(target_ea))
            if code_size is None:
                continue
            seal = _scoped_item_token(
                ea=int(target_ea),
                head_ea=head_ea,
                size=group_sizes[head_ea],
                item_state=f"code:{code_size}",
                xrefs=tuple(sorted(witness)),
                origin_data_state=group_origins[head_ea],
                group_targets=group,
            )
            actions.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(target_ea),
                    expected_before=seal,
                    expected_after=seal,
                )
            )

    # Singleton v2 scopes also need a final synchronous seal when a planned
    # user edge touches their retained range.  Without this read-only seal,
    # the last action for the item would describe the pre-user-edge witness
    # and phase-A verification would quite correctly reject the transaction.
    singleton_seals: list[NativeMetadataAction] = []
    for action in tuple(actions):
        parsed = _parse_scoped_item_state(
            action.expected_after, expected_ea=action.ea
        )
        if parsed is None or parsed.get("origin_data_state") is not None:
            continue
        item_state = str(parsed["item_state"])
        if not item_state.startswith("code:"):
            continue
        low = int(parsed["head_ea"])
        high = low + int(parsed["size"])
        witness = set(parsed["xrefs"])
        for edge_action in actions:
            if edge_action.kind is not NativeMetadataActionKind.UPDATE_XREF:
                continue
            for target, xref_type, user_owned in _parse_cref_state(
                edge_action.expected_after
            ):
                if user_owned and (
                    low <= int(edge_action.ea) < high or low <= int(target) < high
                ):
                    witness.add(
                        (
                            int(edge_action.ea),
                            int(target),
                            int(xref_type),
                            True,
                            True,
                        )
                    )
        sealed = _scoped_item_token(
            ea=int(parsed["ea"]),
            head_ea=low,
            size=int(parsed["size"]),
            item_state=item_state,
            xrefs=tuple(sorted(witness)),
        )
        if sealed != action.expected_after:
            singleton_seals.append(
                NativeMetadataAction(
                    kind=NativeMetadataActionKind.RECREATE_ITEM,
                    ea=int(parsed["ea"]),
                    expected_before=sealed,
                    expected_after=sealed,
                )
            )
    actions.extend(singleton_seals)

    # Re-project every authorized effect in global action order.  A decoded
    # effect from an adjacent item can touch this group's read surface, even
    # though that item is not a member of the group.  The local group
    # accumulator above remains useful for constructing the action sequence;
    # this replay is the final exact witness authority for every scoped token.
    group_specs: dict[
        int, tuple[int, int, tuple[tuple[int, int, int, bool, bool], ...]]
    ] = {}
    for head_ea in group_origins:
        origin = _parse_reversible_data_item_state(group_origins[head_ea])
        if origin is None:
            raise IndirectLabelPlanBuildError(
                f"group origin is not a reversible data snapshot at {head_ea:#x}"
            )
        group_specs[head_ea] = (
            int(head_ea),
            int(head_ea) + int(group_sizes[head_ea]),
            tuple(origin["xrefs"]),
        )
    action_effects: dict[
        int, tuple[tuple[int, int, int, bool, bool], ...]
    ] = {}
    for index, action in enumerate(actions):
        if action.kind is NativeMetadataActionKind.RECREATE_ITEM:
            if action.expected_before == action.expected_after:
                action_effects[index] = ()
            else:
                action_effects[index] = executor._predict_code_xrefs(action.ea)[1]
        elif action.kind is NativeMetadataActionKind.UPDATE_XREF:
            before_rows = _parse_cref_state(action.expected_before)
            after_rows = _parse_cref_state(action.expected_after)
            action_effects[index] = tuple(
                sorted(
                    (
                        int(action.ea),
                        int(target),
                        int(xref_type),
                        bool(user_owned),
                        True,
                    )
                    for target, xref_type, user_owned in after_rows - before_rows
                )
            )
        else:
            action_effects[index] = ()
    projected = _project_group_witnesses(actions, action_effects, group_specs)
    _reverse_group_witnesses(actions, action_effects, group_specs)
    projected_actions: list[NativeMetadataAction] = []
    for index, action in enumerate(actions):
        before = _parse_scoped_item_state(
            action.expected_before, expected_ea=action.ea
        )
        after = _parse_scoped_item_state(
            action.expected_after, expected_ea=action.ea
        )
        if before is None and after is None:
            projected_actions.append(action)
            continue
        scope = before if before is not None else after
        assert scope is not None
        head_ea = int(scope["head_ea"])
        if head_ea not in group_specs:
            projected_actions.append(action)
            continue
        if head_ea not in projected[index]:
            raise IndirectLabelPlanBuildError(
                f"group action {index} has no replayed witness scope"
            )
        before_xrefs, after_xrefs = projected[index][head_ea]

        def _projected_token(
            parsed: dict[str, object] | None,
            xrefs: tuple[tuple[int, int, int, bool, bool], ...],
        ) -> str:
            if parsed is None:
                return action.expected_before
            return _scoped_item_token(
                ea=int(parsed["ea"]),
                head_ea=int(parsed["head_ea"]),
                size=int(parsed["size"]),
                item_state=str(parsed["item_state"]),
                xrefs=xrefs,
                origin_data_state=parsed.get("origin_data_state"),
                group_targets=tuple(parsed.get("group_targets", ())),
            )

        projected_actions.append(
            NativeMetadataAction(
                kind=action.kind,
                ea=action.ea,
                expected_before=_projected_token(before, before_xrefs),
                expected_after=_projected_token(after, after_xrefs),
            )
        )
    actions = projected_actions
    analysis_phase_witness: str | None = None
    if group_specs:
        phase_groups: list[dict[str, object]] = []
        phase_extent_high: dict[int, int] = {}
        import ida_ua
        active_high = 0
        active_low = 0
        active_head = 0
        planned_cleared_extents: tuple[tuple[int, int], ...] = ()
        cleared_extent_set = {
            (
                int(origin["head_ea"]),
                int(origin["head_ea"]) + int(origin["size"]),
            )
            for token in group_origins.values()
            if (origin := _parse_reversible_data_item_state(token)) is not None
        }
        for action in actions:
            for token in (action.expected_before, action.expected_after):
                scoped = _parse_scoped_item_state(token, expected_ea=action.ea)
                candidate = (
                    str(scoped["item_state"])
                    if scoped is not None
                    else token
                )
                origin = _parse_reversible_data_item_state(candidate)
                if origin is not None:
                    cleared_extent_set.add(
                        (
                            int(origin["head_ea"]),
                            int(origin["head_ea"]) + int(origin["size"]),
                        )
                    )
                if scoped is not None and str(scoped["item_state"]).startswith("code:"):
                    try:
                        code_size = int(str(scoped["item_state"]).removeprefix("code:"))
                    except ValueError:
                        continue
                    cleared_extent_set.add((int(action.ea), int(action.ea) + code_size))
        planned_cleared_extents = tuple(sorted(cleared_extent_set))

        def _decode_closure(
            ea: int,
        ) -> DecodedClosureInstruction | DecodedClosureBoundaryStop | None:
            import ida_bytes

            instruction = ida_ua.insn_t()
            try:
                size = int(ida_ua.decode_insn(instruction, int(ea)))
                if size <= 0:
                    return None
                _predicted_size, predicted_effects = executor._predict_code_xrefs(int(ea))
                predicted_effects = tuple(
                    effect
                    for effect in predicted_effects
                    if not effect[4]
                    or active_low <= int(effect[1]) < active_high
                    or bool(ida_bytes.is_loaded(int(effect[1])))
                )
                if int(ea) + size > active_high:
                    # A decoded instruction may begin in the authorized
                    # origin range and consume a suffix that is still exact
                    # loaded UNKNOWN bytes.  This is a destruction extent,
                    # not a preserved-neighbor boundary, and is therefore
                    # admitted before checking the original item envelope.
                    crossed_start, crossed_end = active_high, int(ea) + size
                    import ida_xref
                    import idaapi
                    suffix_without_item = all(
                        bool(ida_bytes.is_loaded(offset))
                        and not bool(ida_bytes.is_code(ida_bytes.get_flags(offset)))
                        and not bool(ida_bytes.is_data(ida_bytes.get_flags(offset)))
                        and int(ida_xref.get_first_cref_to(offset))
                        == int(getattr(idaapi, "BADADDR", -1))
                        and int(ida_xref.get_first_dref_to(offset))
                        == int(getattr(idaapi, "BADADDR", -1))
                        for offset in range(crossed_start, crossed_end)
                    )
                    suffix_data_item = (
                        bool(ida_bytes.is_data(ida_bytes.get_flags(crossed_start)))
                        and int(ida_bytes.get_item_head(crossed_start)) == crossed_start
                        and int(ida_bytes.get_item_end(crossed_start)) >= crossed_end
                        and all(
                            bool(ida_bytes.is_loaded(offset))
                            and not bool(ida_bytes.is_code(ida_bytes.get_flags(offset)))
                            and int(ida_xref.get_first_cref_to(offset))
                            == int(getattr(idaapi, "BADADDR", -1))
                            and int(ida_xref.get_first_dref_to(offset))
                            == int(getattr(idaapi, "BADADDR", -1))
                            for offset in range(crossed_start, crossed_end)
                        )
                    )
                    unknown_suffix = suffix_without_item or suffix_data_item
                    if unknown_suffix and any(
                        bool(is_code) and int(source) == int(ea)
                        and int(target) == crossed_end
                        for source, target, _type, _user, is_code in predicted_effects
                    ):
                        return DecodedClosureInstruction(
                            int(ea),
                            int(size),
                            predicted_effects,
                            (DecodedClosureTransfer(
                                crossed_end,
                                DecodedClosureTransferKind.FALLTHROUGH,
                                True,
                                "ida-loaded-unknown-suffix",
                            ),),
                            (int(ea), int(ea) + int(size)),
                        )
                    # A decoder can interpret the tail bytes of the original
                    # enclosing data item as an instruction even though the
                    # planned materialization cannot create an item crossing
                    # into the preserved neighboring item.  Stop only when
                    # IDA proves that exact original data boundary; arbitrary
                    # crossing instructions remain a hard abstention.
                    if (
                        int(ida_bytes.get_item_head(int(ea))) == active_head
                        and int(ida_bytes.get_item_end(int(ea))) == active_high
                    ):
                        crossed_start, crossed_end = active_high, int(ea) + size
                        planned = _extent_is_fully_covered(
                            crossed_start, crossed_end, planned_cleared_extents
                        )
                        preserved_target = crossed_end
                        import ida_xref
                        import idaapi
                        unknown_suffix = (
                            all(
                                bool(ida_bytes.is_loaded(offset))
                                and bool(ida_bytes.is_unknown(ida_bytes.get_flags(offset)))
                                and int(ida_xref.get_first_cref_to(offset))
                                == int(getattr(idaapi, "BADADDR", -1))
                                and int(ida_xref.get_first_dref_to(offset))
                                == int(getattr(idaapi, "BADADDR", -1))
                                for offset in range(crossed_start, crossed_end)
                            )
                        )
                        if unknown_suffix and any(
                            bool(is_code) and int(source) == int(ea)
                            and int(target) == preserved_target
                            for source, target, _type, _user, is_code in predicted_effects
                        ):
                            return DecodedClosureInstruction(
                                int(ea),
                                int(size),
                                predicted_effects,
                                (DecodedClosureTransfer(
                                    preserved_target,
                                    DecodedClosureTransferKind.FALLTHROUGH,
                                    True,
                                    "ida-loaded-unknown-suffix",
                                ),),
                                (int(ea), int(ea) + int(size)),
                            )
                        preserved = (
                            not planned
                            and bool(ida_bytes.is_loaded(preserved_target))
                            and not bool(ida_bytes.is_data(ida_bytes.get_flags(crossed_start)))
                            and int(ida_bytes.get_item_head(crossed_start)) != active_head
                            and int(ida_bytes.get_item_end(crossed_start)) >= crossed_end
                            and not any(
                                low <= crossed_start < high
                                or low < crossed_end <= high
                                for low, high in planned_cleared_extents
                            )
                        )
                        if planned and any(
                            bool(is_code) and int(source) == int(ea)
                            and int(target) == preserved_target
                            for source, target, _type, _user, is_code in predicted_effects
                        ):
                            boundary_edges = (DecodedClosureTransfer(
                                preserved_target,
                                DecodedClosureTransferKind.FALLTHROUGH,
                                True,
                                "ida-preserved-boundary",
                            ),)
                            return DecodedClosureBoundaryStop(
                                int(ea), predicted_effects, boundary_edges
                            )
                        if preserved:
                            return DecodedClosureBoundaryStop(int(ea))
                        return None
                # A promoted instruction may end exactly at the original
                # data boundary while its fallthrough points at the next
                # item.  That edge is still outside this closure: retain it
                # only when the next item is a complete, loaded neighboring
                # item whose extent is either explicitly planned or proven
                # preserved.  A gap or unknown extent remains fail-closed.
                exact_boundary_targets = tuple(
                    sorted(
                        {
                            int(target)
                            for source, target, _type, _user, is_code in predicted_effects
                            if is_code
                            and int(source) == int(ea)
                            and int(target) == int(ea) + size
                            and int(target) >= active_high
                        }
                    )
                )
                if exact_boundary_targets:
                    import idaapi

                    badaddr = int(getattr(idaapi, "BADADDR", -1))
                    for target in exact_boundary_targets:
                        if not bool(ida_bytes.is_loaded(target)):
                            continue
                        target_flags = ida_bytes.get_flags(target)
                        target_head = int(ida_bytes.get_item_head(target))
                        target_end = int(ida_bytes.get_item_end(target))
                        if (
                            target_head != target
                            or target_end <= target
                            or bool(ida_bytes.is_unknown(target_flags))
                            or target == badaddr
                        ):
                            continue
                        target_planned = _extent_is_fully_covered(
                            target, target_end, planned_cleared_extents
                        )
                        if target_planned or (
                            not any(
                                low < target_end and target < high
                                for low, high in planned_cleared_extents
                            )
                            and (
                                bool(ida_bytes.is_data(target_flags))
                                or bool(ida_bytes.is_code(target_flags))
                            )
                        ):
                            return DecodedClosureBoundaryStop(
                                int(ea),
                                predicted_effects,
                                (DecodedClosureTransfer(
                                    target,
                                    DecodedClosureTransferKind.FALLTHROUGH,
                                    True,
                                    "ida-preserved-boundary",
                                ),),
                            )
                    return None
                effects = predicted_effects
            except Exception:
                return None
            effects = tuple(
                effect
                for effect in effects
                if not effect[4]
                or active_low <= int(effect[1]) < active_high
                or bool(ida_bytes.is_loaded(int(effect[1])))
            )
            control_edges = tuple(
                DecodedClosureTransfer(
                    target=int(target),
                    kind=(
                        DecodedClosureTransferKind.FALLTHROUGH
                        if int(target) == int(ea) + size
                        else DecodedClosureTransferKind.DIRECT_NEAR
                    ),
                    loaded=bool(
                        ida_bytes.is_loaded(int(target))
                        or (
                            active_low <= int(target) < active_high
                            and int(ida_bytes.get_item_head(int(target))) == active_head
                        )
                    ),
                    provenance="ida-static-code-xref",
                )
                for source, target, _type, _user, is_code in effects
                if is_code and int(source) == int(ea)
            )
            return DecodedClosureInstruction(
                ea=int(ea),
                size=size,
                effects=tuple(effects),
                control_edges=control_edges,
            )

        for head_ea, (low, high, origin_rows) in sorted(group_specs.items()):
            active_low = low
            active_high = high
            active_head = head_ea
            immediate_after = set(projected[len(actions) - 1][head_ea][1])
            immediate_rows = tuple(
                sorted(
                    set(origin_rows)
                    | immediate_after
                    | {
                        row
                        for effect in action_effects.values()
                        for row in effect
                        if row[4] and low <= int(row[1]) < high
                    }
                )
            )
            roots = tuple(
                sorted(
                    {
                        int(row[1])
                        for row in immediate_rows
                        if low <= int(row[1]) < high
                    }
                )
            )
            closure = _bounded_decoded_cfg_closure(
                group_low=low,
                group_high=high,
                roots=roots,
                decode=_decode_closure,
                seed_effects=immediate_rows,
            )
            closure_rows = tuple(
                row for row in closure.xrefs if row not in immediate_after
            )
            after_rows = tuple(sorted(immediate_after | set(closure_rows)))
            origin = _parse_reversible_data_item_state(group_origins[head_ea])
            assert origin is not None
            group = grouped_targets[head_ea]
            item_records: dict[int, tuple[int, str]] = {}
            for target_ea in grouped_targets[head_ea]:
                size = group_code_sizes[head_ea].get(int(target_ea))
                if size is None:
                    raise IndirectLabelPlanBuildError(
                        f"missing grouped target decode at {target_ea:#x}"
                    )
                item_records[int(target_ea)] = (int(size), f"code:{int(size)}")
            for item_ea, item_size in closure.items:
                item_records.setdefault(int(item_ea), (int(item_size), f"code:{int(item_size)}"))
            carrier_high = max(
                int(head_ea) + int(group_sizes[head_ea]),
                *(int(item_ea) + int(item_size) for item_ea, (item_size, _state) in item_records.items()),
            )
            phase_extent_high[int(head_ea)] = carrier_high

            def _complete_items(records, high=carrier_high):
                rows = []
                cursor = int(head_ea)
                for item_ea, (item_size, item_state) in sorted(records.items()):
                    if item_ea < cursor:
                        raise IndirectLabelPlanBuildError(
                            f"overlapping phase items at {item_ea:#x}"
                        )
                    if item_ea > cursor:
                        rows.append((cursor, item_ea - cursor, "unknown"))
                    rows.append((item_ea, item_size, item_state))
                    cursor = item_ea + item_size
                if cursor < high:
                    rows.append((cursor, high - cursor, "unknown"))
                if cursor > high:
                    raise IndirectLabelPlanBuildError(
                        f"phase item escapes carrier extent at {cursor:#x}"
                    )
                return tuple(rows)

            after_items = _complete_items(item_records)
            phase_a_records = {
                int(target_ea): (
                    int(group_code_sizes[head_ea][int(target_ea)]),
                    f"code:{int(group_code_sizes[head_ea][int(target_ea)])}",
                )
                for target_ea in group
            }
            phase_a_items = _complete_items(phase_a_records)
            postconditions: list[tuple[int, str]] = []
            for target_ea in group:
                code_size, _state = item_records[int(target_ea)]
                postconditions.append(
                    (
                        int(target_ea),
                        _scoped_item_token(
                            ea=int(target_ea),
                            head_ea=int(head_ea),
                            size=int(group_sizes[head_ea]),
                            item_state=f"code:{code_size}",
                            xrefs=after_rows,
                            origin_data_state=group_origins[head_ea],
                            group_targets=group,
                        ),
                    )
                )
            group_token = _analysis_phase_token(
                origin_data_state=group_origins[head_ea],
                group_targets=group,
                before_items=phase_a_items,
                after_items=after_items,
                before_xrefs=tuple(sorted(immediate_after)),
                after_xrefs=after_rows,
                postconditions=tuple(sorted(postconditions)),
                origin_extent=(
                    int(head_ea),
                    int(head_ea)
                    + int(_parse_reversible_data_item_state(group_origins[head_ea])["size"]),
                ),
                destruction_extent=(int(head_ea), int(carrier_high)),
            )
            phase_groups.append(
                json.loads(group_token.removeprefix("analysis-phase:v4:"))
            )
        # Persist the exact carrier-reversal state machine.  Start from the
        # sealed P graph with only the user-owned additions removed (those
        # UPDATE_XREF actions are reversed before any carrier recreation),
        # then remove each carrier's auto code rows in dependency order.
        phase_group_by_head = {
            int(_parse_reversible_data_item_state(group["origin_data_state"])["head_ea"]): group
            for group in phase_groups
        }
        group_ranges = {
            int(head): (int(head), int(phase_extent_high[int(head)]))
            for head in phase_group_by_head
        }
        all_phase_rows = {
            tuple(
                (
                    int(row["source_ea"]), int(row["target_ea"]),
                    int(row["xref_type"]), bool(row["user_owned"]),
                    bool(row["is_code"]),
                )
            )
            for group in phase_groups
            for row in group["after_xrefs"]
        }
        user_added_rows = {
            tuple(row)
            for effect in action_effects.values()
            for row in effect
            if bool(row[3])
        }
        reverse_rows = set(all_phase_rows - user_added_rows)
        dependency_edges = {int(head): set() for head in group_ranges}
        for source, target, _xref_type, _user, is_code in all_phase_rows:
            if not is_code:
                continue
            source_head = next(
                (head for head, (low, high) in group_ranges.items() if low <= source < high),
                None,
            )
            target_head = next(
                (head for head, (low, high) in group_ranges.items() if low <= target < high),
                None,
            )
            if source_head is not None and target_head is not None and source_head != target_head:
                dependency_edges[source_head].add(target_head)
        reverse_heads: list[int] = []
        pending = {head: set(edges) for head, edges in dependency_edges.items()}
        while pending:
            # dependency_edges stores source -> destination.  A source must
            # be recreated before its destination so the destination's R_i
            # witness reflects the removed incoming edge.
            ready = sorted(
                head
                for head in pending
                if not any(head in edges for edges in pending.values())
            )
            if not ready:
                raise IndirectLabelPlanBuildError(
                    "carrier reverse dependency graph contains a cycle"
                )
            reverse_heads.extend(ready)
            for head in ready:
                pending.pop(head)
            for edges in pending.values():
                edges.difference_update(ready)

        def _phase_rows(rows: set[tuple[int, int, int, bool, bool]]) -> list[dict[str, object]]:
            return [
                {
                    "source_ea": source,
                    "target_ea": target,
                    "xref_type": xref_type,
                    "user_owned": user_owned,
                    "is_code": is_code,
                }
                for source, target, xref_type, user_owned, is_code in sorted(rows)
            ]

        for head in reverse_heads:
            low, high = group_ranges[head]
            current = {
                row for row in reverse_rows
                if low <= row[0] < high or low <= row[1] < high
            }
            removed = {
                row for row in current
                if low <= row[0] < high
            }
            phase_group_by_head[head]["reverse_before_xrefs"] = _phase_rows(current)
            phase_group_by_head[head]["reverse_after_xrefs"] = _phase_rows(current - removed)
            reverse_rows.difference_update(removed)
        phase_extents = tuple(
            (int(head), int(phase_extent_high[int(head)]))
            for head in sorted(phase_extent_high)
        )
        preserved_global_items: set[tuple[int, int, str]] = set()
        enumerate_partition = getattr(executor, "enumerate_item_partition", None)
        if callable(enumerate_partition):
            for head_ea, origin_token in group_origins.items():
                origin = _parse_reversible_data_item_state(origin_token)
                if origin is None:
                    raise IndirectLabelPlanBuildError(
                        f"group {head_ea:#x} has no reversible origin"
                    )
                origin_head = int(origin["head_ea"])
                origin_end = int(phase_extent_high[origin_head])
                try:
                    partition = enumerate_partition(origin_head, origin_end)
                except Exception as error:
                    raise IndirectLabelPlanBuildError(
                        f"preserved item partition failed at {origin_head:#x}"
                    ) from error
                for item_ea, item_size, item_state in partition:
                    if (
                        not isinstance(item_ea, int) or isinstance(item_ea, bool)
                        or not isinstance(item_size, int) or isinstance(item_size, bool)
                        or item_size <= 0 or not isinstance(item_state, str)
                    ):
                        raise IndirectLabelPlanBuildError(
                            f"preserved item partition is malformed at {origin_head:#x}"
                        )
                    # The carrier origin itself is replaced by the promoted
                    # code item.  Preserve every other concrete item in the
                    # original range as an explicit global item rather than
                    # mislabeling it as an UNKNOWN gap.
                    if item_ea != origin_head and item_state != "unknown":
                        preserved_global_items.add((item_ea, item_size, item_state))

        def _canonical_global_items(rows):
            """Build one disjoint partition from overlapping carrier views.

            Each group carries its own complete view, so an UNKNOWN gap in one
            carrier can overlap a decoded item discovered by a neighboring
            carrier.  Global state is a partition, not the concatenation of
            those views: concrete decoded items win and UNKNOWN rows are
            regenerated only for uncovered bytes.
            """
            by_range = {}
            for raw in rows:
                ea, size, raw_state = (int(raw[0]), int(raw[1]), str(raw[2]))
                try:
                    state = canonical_phase_item_state(raw_state, head_ea=ea)
                except PhaseWitnessError as error:
                    raise IndirectLabelPlanBuildError(
                        f"global phase item state is not canonical at {ea:#x}"
                    ) from error
                if size <= 0:
                    raise IndirectLabelPlanBuildError("global phase item has non-positive size")
                key = (ea, size)
                prior = by_range.get(key)
                if prior is not None and prior[2] != state:
                    raise IndirectLabelPlanBuildError(
                        f"conflicting global phase items at {ea:#x}"
                    )
                by_range[key] = (ea, size, state)
            concrete = sorted(
                row for row in by_range.values() if row[2] != "unknown"
            )
            previous_end = -1
            previous_row = None
            for ea, size, _state in concrete:
                if ea < previous_end:
                    raise IndirectLabelPlanBuildError(
                        f"overlapping concrete global phase items at {ea:#x} "
                        f"with {previous_row!r}; current={(ea, size, _state)!r}"
                    )
                previous_end = ea + size
                previous_row = (ea, size, _state)
            merged_extents = []
            for low, high in phase_extents:
                if merged_extents and low <= merged_extents[-1][1]:
                    merged_extents[-1] = (
                        merged_extents[-1][0], max(merged_extents[-1][1], high)
                    )
                else:
                    merged_extents.append((low, high))
            result = []
            for low, high in merged_extents:
                cursor = low
                for ea, size, state in concrete:
                    end = ea + size
                    if end <= low:
                        continue
                    if ea >= high:
                        break
                    if ea < cursor or end > high:
                        raise IndirectLabelPlanBuildError(
                            f"concrete global phase item escapes extent at {ea:#x}"
                        )
                    if ea > cursor:
                        result.append((cursor, ea - cursor, "unknown"))
                    result.append((ea, size, state))
                    cursor = end
                if cursor < high:
                    result.append((cursor, high - cursor, "unknown"))
            return tuple(result)

        def _global_state(items, xrefs, extents=phase_extents):
            return {
                "items": [list(row) for row in _canonical_global_items(items)],
                "xrefs": [
                    {
                        "source_ea": source,
                        "target_ea": target,
                        "xref_type": xref_type,
                        "user_owned": user_owned,
                        "is_code": is_code,
                    }
                    for source, target, xref_type, user_owned, is_code in sorted(xrefs)
                ],
                "extents": [list(extent) for extent in extents],
            }

        sealed_items = {
            tuple(row)
            for group in phase_groups
            for row in group["after_items"]
        }
        concrete_phase_items = [
            row for row in sealed_items if row[2] != "unknown"
        ]
        preserved_global_items = {
            row for row in preserved_global_items
            if not any(
                row[0] < other[0] + other[1]
                and other[0] < row[0] + row[1]
                for other in concrete_phase_items
            )
        }
        sealed_items.update(preserved_global_items)
        sealed_xrefs = {
            (
                int(row["source_ea"]), int(row["target_ea"]), int(row["xref_type"]),
                bool(row["user_owned"]), bool(row["is_code"]),
            )
            for group in phase_groups
            for row in group["after_xrefs"]
        }
        origin_items = set()
        origin_xrefs = set()
        for group in phase_groups:
            origin = _parse_reversible_data_item_state(group["origin_data_state"])
            assert origin is not None
            origin_items.add((int(origin["head_ea"]), int(origin["size"]), group["origin_data_state"]))
            origin_end = int(origin["head_ea"]) + int(origin["size"])
            tail_high = int(phase_extent_high[int(origin["head_ea"])])
            if origin_end < tail_high:
                origin_items.add((origin_end, tail_high - origin_end, "unknown"))
            origin_xrefs.update(tuple(row) for row in origin["xrefs"])
        origin_items.update(preserved_global_items)
        global_items = set(_canonical_global_items(sealed_items))
        global_xrefs = set(sealed_xrefs)
        reverse_schedule = []
        for index, action in reversed(tuple(enumerate(actions))):
            before_global = _global_state(global_items, global_xrefs)
            after_global_xrefs = set(global_xrefs)
            if action.kind is NativeMetadataActionKind.UPDATE_XREF:
                after_global_xrefs.difference_update(action_effects.get(index, ()))
            after_global = _global_state(global_items, after_global_xrefs)
            reverse_schedule.append(
                {
                    "action_kind": action.kind.value,
                    "after_state": action.expected_after,
                    "before_state": action.expected_before,
                    "ea": int(action.ea),
                    "expected_after": action.expected_after,
                    "global_after": after_global,
                    "global_before": before_global,
                    "index": index,
                    "kind": "action",
                }
            )
            global_xrefs = after_global_xrefs
        for head_ea in reverse_heads:
            group = phase_group_by_head[int(head_ea)]
            before_global = _global_state(global_items, global_xrefs)
            removed_items = {tuple(row) for row in group["after_items"]}
            global_items.difference_update(removed_items)
            origin = _parse_reversible_data_item_state(group["origin_data_state"])
            assert origin is not None
            global_items.add((int(origin["head_ea"]), int(origin["size"]), group["origin_data_state"]))
            origin_end = int(origin["head_ea"]) + int(origin["size"])
            tail_high = int(phase_extent_high[int(head_ea)])
            if origin_end < tail_high:
                global_items.add((origin_end, tail_high - origin_end, "unknown"))
            global_items = set(_canonical_global_items(global_items))
            removed_xrefs = {
                tuple(
                    (
                        int(row["source_ea"]), int(row["target_ea"]), int(row["xref_type"]),
                        bool(row["user_owned"]), bool(row["is_code"]),
                    )
                )
                for row in group["reverse_before_xrefs"]
            } - {
                tuple(
                    (
                        int(row["source_ea"]), int(row["target_ea"]), int(row["xref_type"]),
                        bool(row["user_owned"]), bool(row["is_code"]),
                    )
                )
                for row in group["reverse_after_xrefs"]
            }
            preserved_incoming_data_xrefs = {
                row
                for row in removed_xrefs
                if not row[4]
                and not (int(head_ea) <= row[0] < int(phase_extent_high[int(head_ea)]))
            }
            effective_removed_xrefs = removed_xrefs - preserved_incoming_data_xrefs
            cleared_items = {
                row for row in global_items
                if row[0] + row[1] <= int(head_ea)
                or row[0] >= int(phase_extent_high[int(head_ea)])
            }
            cleared_global = _global_state(
                cleared_items
                | {
                    (
                        int(head_ea),
                        int(phase_extent_high[int(head_ea)]) - int(head_ea),
                        "unknown",
                    )
                },
                global_xrefs - effective_removed_xrefs,
            )
            global_xrefs.difference_update(effective_removed_xrefs)
            global_items = set(_canonical_global_items(global_items))
            after_global = _global_state(global_items, global_xrefs)
            reverse_schedule.append(
                {
                    "after_items": group["after_items"],
                    "after_xrefs": group["after_xrefs"],
                    "before_items": group["before_items"],
                    "before_xrefs": group["before_xrefs"],
                    "global_after": after_global,
                    "global_before": before_global,
                    "cleared_state": cleared_global,
                    "origin_extent": group["origin_extent"],
                    "destruction_extent": group["destruction_extent"],
                    "head_ea": int(head_ea),
                    "kind": "group",
                }
            )
        analysis_phase_witness = "analysis-phase:v4:" + json.dumps(
            {
                "version": 4,
                "groups": phase_groups,
                "sealed_state": _global_state(sealed_items, sealed_xrefs),
                "origin_state": _global_state(origin_items, origin_xrefs),
                "reverse_schedule": reverse_schedule,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    if request.install_switch_info:
        # IDA canonicalizes a persisted switch record (including flags,
        # version, and expression EA) only after ``set_switch_info``.  A
        # read-only planner cannot capture that exact post-state without
        # first mutating the database, so this route remains fail-closed
        # until the SDK supplies a pure canonicalization API.
        raise IndirectLabelPlanBuildError(
            "switch-info installation has no read-only exact after-state witness"
        )

    if not actions:
        raise IndirectLabelPlanBuildError(
            "label request has no required metadata change"
        )

    _validate_grouped_item_actions(actions)

    operation = NativePatchOperation(
        operation_id="indirect-label-metadata",
        range=anchor,
        expected_current_bytes=evidence.expected_current_bytes,
        expected_original_bytes=evidence.expected_original_bytes,
        expected_patch_rows=evidence.expected_patch_rows,
        expected_before_shape=shape,
        expected_item_shape=evidence.expected_item_shape,
        expected_incoming_refs=evidence.expected_incoming_refs,
        expected_function_ownership=evidence.expected_function_ownership,
        replacement_bytes=evidence.expected_current_bytes,
        expected_after_shape=shape,
        expected_after_successors=(),
        encoding_evidence=NativeEncodingEvidence(
            provider_id="ida-metadata-only",
            provider_version="1",
            final_ea=int(dispatch_jump_ea),
            opcode_intent="metadata_only",
            emitted_hash=hashlib.sha256(evidence.expected_current_bytes).hexdigest(),
            independent_decode_hash=hashlib.sha256(
                repr(shape).encode("utf-8")
            ).hexdigest(),
        ),
        relocation_evidence=(),
        metadata_actions=tuple(actions),
        restore_snapshot=evidence.restore_snapshot,
        writes_bytes=False,
    )
    database_identity = _database_identity(int(request.function_ea))
    function_identity = _function_identity(
        reader,
        ownership=evidence.expected_function_ownership,
    )
    request_fingerprint = hashlib.sha256(repr(request).encode("utf-8")).hexdigest()
    return NativePatchPlan(
        plan_id=f"indirect-label:{request_fingerprint[:16]}",
        schema_version=1,
        patch_class="lifting_normalization",
        database_identity=database_identity,
        function_identity=function_identity,
        inherited_function_fingerprint=function_identity.inherited_bytes_hash,
        target_cfg_fingerprint=request_fingerprint,
        native_origin_map_fingerprint=request_fingerprint,
        architecture="x86",
        bitness=database_identity.bitness,
        endianness="little",
        processor=database_identity.processor,
        issuer_id="indirect-label-materializer",
        proof_id="indirect-label-discovery",
        proof_hash=request_fingerprint,
        provenance=("indirect_jump_labels",),
        operations=(operation,),
        fallback_policy="no_patch",
        authorizing_attempt_id=authorizing_attempt_id,
        analysis_phase_witness=analysis_phase_witness,
    )
