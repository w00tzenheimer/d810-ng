"""Pending buffer for planner-created block lineage rows.

The executor records lineage after a PatchPlan is successfully applied, before
the post-apply diagnostic snapshot is captured.  ``snapshot_mba`` can later
drain this process-local buffer and persist the rows under its new snapshot_id.
"""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass

from d810.cfg.block_identity import (
    block_body_observation_fingerprint,
    block_fingerprint,
    block_label,
    flow_graph_context_label,
    hex64,
)
from d810.cfg.flowgraph import FlowGraph
from d810.cfg.plan import LegacyBlockOperation, PatchPlan, VirtualBlockId
from d810.core.typing import Any


@dataclass(frozen=True)
class BlockLineageEntry:
    """In-memory lineage row for one block created by a PatchPlan."""

    serial: int
    origin_snapshot_id: int | None
    origin_serial: int | None
    origin_start_ea_hex: str | None
    origin_body_fingerprint: str | None
    creation_kind: str
    creation_reason: str | None
    planner_block_id: str | None
    source_mod_type: str | None
    extra_json: str | None

    def as_db_tuple(self, snapshot_id: int) -> tuple[Any, ...]:
        """Return values in ``block_lineage`` schema order."""
        return (
            int(snapshot_id),
            self.serial,
            self.origin_snapshot_id,
            self.origin_serial,
            self.origin_start_ea_hex,
            self.origin_body_fingerprint,
            self.creation_kind,
            self.creation_reason,
            self.planner_block_id,
            self.source_mod_type,
            self.extra_json,
        )


_pending_lock = threading.Lock()
_pending: list[BlockLineageEntry] = []


def build_patch_plan_block_lineage(
    patch_plan: PatchPlan,
    pre_cfg: FlowGraph | None,
    post_cfg: FlowGraph | None,
    *,
    creation_reason_prefix: str = "patch_plan",
) -> list[BlockLineageEntry]:
    """Build lineage entries for every assigned ``patch_plan.new_blocks`` spec."""
    new_blocks = tuple(getattr(patch_plan, "new_blocks", ()) or ())
    if not new_blocks:
        return []

    source_mod_types = _source_mod_types_by_block_id(patch_plan)
    origin_snapshot_id = _snapshot_id(pre_cfg)
    entries: list[BlockLineageEntry] = []
    for spec in new_blocks:
        block_id = getattr(spec, "block_id", None)
        assigned_serial = _assigned_serial_for(patch_plan, block_id)
        if assigned_serial is None:
            continue

        origin_serial = _infer_origin_serial(
            spec,
            pre_cfg=pre_cfg,
            post_cfg=post_cfg,
            assigned_serial=assigned_serial,
        )
        origin_block = (
            pre_cfg.get_block(origin_serial)
            if pre_cfg is not None and origin_serial is not None
            else None
        )
        origin_start_ea_hex = (
            hex64(origin_block.start_ea) if origin_block is not None else None
        )
        origin_fingerprint = (
            block_body_observation_fingerprint(pre_cfg, origin_serial)
            if origin_block is not None
            else None
        )
        creation_kind = str(getattr(spec, "kind", "unknown"))
        source_mod_type = source_mod_types.get(block_id) or _infer_source_mod_type(spec)
        extra = _entry_extra(
            spec=spec,
            assigned_serial=assigned_serial,
            origin_serial=origin_serial,
            pre_cfg=pre_cfg,
            post_cfg=post_cfg,
        )
        entries.append(
            BlockLineageEntry(
                serial=int(assigned_serial),
                origin_snapshot_id=origin_snapshot_id,
                origin_serial=(int(origin_serial) if origin_serial is not None else None),
                origin_start_ea_hex=origin_start_ea_hex,
                origin_body_fingerprint=origin_fingerprint,
                creation_kind=creation_kind,
                creation_reason=f"{creation_reason_prefix}:{creation_kind}",
                planner_block_id=(str(block_id) if block_id is not None else None),
                source_mod_type=source_mod_type,
                extra_json=_json_or_none(extra),
            )
        )
    return entries


def buffer_block_lineage(entries: list[BlockLineageEntry]) -> None:
    """Append already-built lineage entries to the pending snapshot buffer."""
    if not entries:
        return
    with _pending_lock:
        _pending.extend(entries)
    # Re-subscribe in case the test fixture reset the bus between
    # cases. A no-op if the subscriber is already registered.
    _ensure_subscribed()


def buffer_patch_plan_block_lineage(
    patch_plan: PatchPlan,
    pre_cfg: FlowGraph | None,
    post_cfg: FlowGraph | None,
    *,
    creation_reason_prefix: str = "patch_plan",
) -> list[BlockLineageEntry]:
    """Build and buffer PatchPlan-created block lineage entries."""
    entries = build_patch_plan_block_lineage(
        patch_plan,
        pre_cfg,
        post_cfg,
        creation_reason_prefix=creation_reason_prefix,
    )
    buffer_block_lineage(entries)
    return entries


def drain_pending_block_lineage() -> list[BlockLineageEntry]:
    """Atomically drain and return lineage entries pending snapshot flush."""
    with _pending_lock:
        out = list(_pending)
        _pending.clear()
    return out


def reset_pending_block_lineage() -> None:
    """Clear pending lineage rows without flushing.  Test harness use."""
    with _pending_lock:
        _pending.clear()


def _drain_into_snapshot(conn: object, snapshot_id: int) -> int:
    entries = drain_pending_block_lineage()
    if not entries:
        return 0
    executemany = getattr(conn, "executemany")
    executemany(
        "INSERT INTO block_lineage VALUES (?,?,?,?,?,?,?,?,?,?,?)",
        [entry.as_db_tuple(snapshot_id) for entry in entries],
    )
    return len(entries)


def _assigned_serial_for(patch_plan: PatchPlan, block_id: object | None) -> int | None:
    if block_id is None:
        return None
    relocation_map = getattr(patch_plan, "relocation_map", None)
    assigned_serial_for = getattr(relocation_map, "assigned_serial_for", None)
    if assigned_serial_for is None:
        return None
    try:
        assigned = assigned_serial_for(block_id)
    except Exception:
        return None
    return _safe_int(assigned)


def _infer_origin_serial(
    spec: object,
    *,
    pre_cfg: FlowGraph | None,
    post_cfg: FlowGraph | None,
    assigned_serial: int,
) -> int | None:
    origin = _safe_int(getattr(spec, "template_block", None))
    if origin is not None:
        return origin
    if str(getattr(spec, "kind", "")) == "insert_block":
        return _infer_insert_block_origin_serial(
            spec,
            pre_cfg=pre_cfg,
            post_cfg=post_cfg,
            assigned_serial=assigned_serial,
        )
    incoming_edge = getattr(spec, "incoming_edge", None)
    if incoming_edge is None:
        return None
    return _safe_int(getattr(incoming_edge, "source", None))


def _infer_insert_block_origin_serial(
    spec: object,
    *,
    pre_cfg: FlowGraph | None,
    post_cfg: FlowGraph | None,
    assigned_serial: int,
) -> int | None:
    """Infer copied-body origin for an InsertBlock without using routing edges.

    InsertBlock.incoming_edge describes the predecessor edge being replaced; it
    is not the source of the inserted body.  Prefer a unique pre-CFG block that
    matches the concrete assigned block's EA/opcode shape.  If that fails, fall
    back to the instruction list carried by the spec.  Ambiguous/no match stays
    synthetic rather than recording a false origin.
    """
    assigned_block = (
        post_cfg.get_block(assigned_serial)
        if post_cfg is not None
        else None
    )
    if pre_cfg is not None and assigned_block is not None:
        assigned_opcodes = _opcode_tuple(assigned_block.insn_snapshots)
        assigned_start_ea = int(assigned_block.start_ea)
        candidates = [
            block.serial
            for block in pre_cfg.blocks.values()
            if int(block.start_ea) == assigned_start_ea
            and _opcode_tuple(block.insn_snapshots) == assigned_opcodes
        ]
        if len(candidates) == 1:
            return int(candidates[0])

    spec_instructions = tuple(getattr(spec, "instructions", ()) or ())
    if pre_cfg is None or not spec_instructions:
        return None
    spec_opcodes = _opcode_tuple(spec_instructions)
    candidates = [
        block.serial
        for block in pre_cfg.blocks.values()
        if _opcode_tuple(block.insn_snapshots) == spec_opcodes
    ]
    if len(candidates) == 1:
        return int(candidates[0])
    return None


def _opcode_tuple(instructions: tuple[object, ...]) -> tuple[int, ...]:
    return tuple(int(getattr(insn, "opcode")) for insn in instructions)


def _snapshot_id(flow_graph: FlowGraph | None) -> int | None:
    if flow_graph is None:
        return None
    return _safe_int(flow_graph.metadata.get("snapshot_id"))


def _source_mod_types_by_block_id(patch_plan: PatchPlan) -> dict[object, str]:
    out: dict[object, str] = {}
    for step in tuple(getattr(patch_plan, "steps", ()) or ()):
        source_mod_type = _source_mod_type_for_step(step)
        if source_mod_type is None:
            continue
        for block_id in _iter_step_block_ids(step):
            out.setdefault(block_id, source_mod_type)
    return out


def _source_mod_type_for_step(step: object) -> str | None:
    if isinstance(step, LegacyBlockOperation):
        return type(step.modification).__name__
    name = type(step).__name__
    return {
        "PatchEdgeSplitTrampoline": "EdgeRedirectViaPredSplit",
        "PatchConditionalRedirect": "CreateConditionalRedirect",
        "PatchInsertBlock": "InsertBlock",
        "PatchDuplicateBlock": "DuplicateBlock",
        "PatchPrivateTerminalSuffix": "PrivateTerminalSuffix",
        "PatchPrivateTerminalSuffixGroup": "PrivateTerminalSuffixGroup",
        "PatchDirectTerminalLoweringGroup": "DirectTerminalLoweringGroup",
        "PatchReorderBlocks": "ReorderBlocks",
    }.get(name)


def _iter_step_block_ids(step: object) -> list[object]:
    block_ids: list[object] = []
    _append_block_id(block_ids, getattr(step, "block_id", None))
    _append_block_id(block_ids, getattr(step, "fallthrough_block_id", None))
    for block_id in tuple(getattr(step, "clone_block_ids", ()) or ()):
        _append_block_id(block_ids, block_id)
    for block_ids_for_anchor in tuple(
        getattr(step, "per_anchor_clone_block_ids", ()) or ()
    ):
        for block_id in tuple(block_ids_for_anchor or ()):
            _append_block_id(block_ids, block_id)
    per_site = getattr(step, "per_site_clone_assigned_serials", None)
    if isinstance(per_site, dict):
        for block_ids_for_site in per_site.values():
            for block_id in tuple(block_ids_for_site or ()):
                _append_block_id(block_ids, block_id)
    return block_ids


def _append_block_id(out: list[object], value: object | None) -> None:
    if value is None:
        return
    if isinstance(value, VirtualBlockId):
        out.append(value)


def _infer_source_mod_type(spec: object) -> str | None:
    kind = str(getattr(spec, "kind", ""))
    if kind.startswith("edge_split"):
        return "EdgeRedirectViaPredSplit"
    if kind.startswith("conditional_redirect"):
        return "CreateConditionalRedirect"
    if kind.startswith("insert_block"):
        return "InsertBlock"
    if kind.startswith("duplicate_block"):
        return "DuplicateBlock"
    if kind.startswith("private_terminal_suffix"):
        return "PrivateTerminalSuffix"
    if kind.startswith("direct_terminal"):
        return "DirectTerminalLoweringGroup"
    if kind.startswith("reorder_block"):
        return "ReorderBlocks"
    return None


def _entry_extra(
    *,
    spec: object,
    assigned_serial: int,
    origin_serial: int | None,
    pre_cfg: FlowGraph | None,
    post_cfg: FlowGraph | None,
) -> dict[str, Any]:
    assigned_block = post_cfg.get_block(assigned_serial) if post_cfg is not None else None
    return {
        "assigned_label": block_label(post_cfg, assigned_serial),
        "assigned_start_ea_hex": (
            hex64(assigned_block.start_ea) if assigned_block is not None else None
        ),
        "assigned_body_fingerprint": block_body_observation_fingerprint(
            post_cfg,
            assigned_serial,
        ),
        "assigned_display_fingerprint": block_fingerprint(post_cfg, assigned_serial),
        "origin_label": (
            block_label(pre_cfg, origin_serial)
            if origin_serial is not None
            else "synthetic"
        ),
        "origin_display_fingerprint": block_fingerprint(pre_cfg, origin_serial),
        "incoming_edge": _edge_payload(getattr(spec, "incoming_edge", None)),
        "outgoing_edges": [
            _edge_payload(edge)
            for edge in tuple(getattr(spec, "outgoing_edges", ()) or ())
        ],
        "pre_context": flow_graph_context_label(pre_cfg),
        "post_context": flow_graph_context_label(post_cfg),
    }


def _edge_payload(edge: object | None) -> dict[str, Any] | None:
    if edge is None:
        return None
    return {
        "source": _ref_payload(getattr(edge, "source", None)),
        "target": _ref_payload(getattr(edge, "target", None)),
    }


def _ref_payload(value: object | None) -> int | str | None:
    int_value = _safe_int(value)
    if int_value is not None:
        return int_value
    if value is None:
        return None
    return str(value)


def _json_or_none(payload: dict[str, Any]) -> str | None:
    if not payload:
        return None
    try:
        return json.dumps(payload, default=str, sort_keys=True)
    except Exception:
        return None


def _safe_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


__all__ = [
    "BlockLineageEntry",
    "build_patch_plan_block_lineage",
    "buffer_block_lineage",
    "buffer_patch_plan_block_lineage",
    "drain_pending_block_lineage",
    "reset_pending_block_lineage",
]


# Subscribe to BlockLineageDrainRequested so the planner-owned
# lineage buffer flushes under the just-captured snapshot_id when
# ``snapshot_mba`` lands. The event carries the live conn + snap_id
# so the subscriber writes rows immediately without round-tripping
# through the global session lookup. The producer side never imports
# ``d810.core.diag``.
def _ensure_subscribed() -> None:
    """Re-subscribe to BlockLineageDrainRequested if absent.

    Tests call ``reset_diagnostic_bus()`` between cases (autouse
    fixtures), which clears module-load subscriptions.
    ``buffer_block_lineage`` calls this so the subscriber is always
    present when there are lineage rows to drain.
    """
    try:
        from d810.core.observability import has_subscribers, subscribe
        from d810.core.observability_events import BlockLineageDrainRequested

        if has_subscribers(BlockLineageDrainRequested):
            return

        def _on_block_lineage_drain_requested(ev) -> None:
            try:
                _drain_into_snapshot(ev.conn, int(ev.snapshot_id))
            except Exception:
                pass

        subscribe(BlockLineageDrainRequested, _on_block_lineage_drain_requested)
    except Exception:
        pass


# Subscribe at module load so the subscriber is in place for normal
# decompilation flows (no test-side bus reset).
_ensure_subscribed()
