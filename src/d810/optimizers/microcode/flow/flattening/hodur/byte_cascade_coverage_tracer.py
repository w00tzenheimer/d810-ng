"""Read-only HandlerChainComposer byte-cascade coverage tracer.

Per-byte trajectory through HCC for terminal-byte facts (bytes 0-6 of the
``%var_190`` cascade). For each byte the tracer records whether the byte's
DAG node is present, whether a raw candidate was generated, which execution
or filter stage accepted or dropped it, and what kind of modification (if any)
finally preserves the byte's behaviour.

The tracer is **read-only**: it never mutates HCC inputs, never imports
``ida_hexrays``, and emits diagnostic output via the provided logger only.
It activates on env gate ``D810_HCC_BYTE_CASCADE_TRACE=1`` and is a no-op
otherwise.

Two output channels:

- Grep-able row logs (one ``HCC_BYTE_CASCADE_TRACE_ROW`` line per byte) for
  later reconciliation against the diag DB.
- Summary markdown table at the end of HCC ``plan()`` for human review.

Byte evidence is keyed by **block EA** and **instruction EAs** because block
serials drift across snapshots. Facts label byte index; EAs anchor the
comparison.

Preservation predicate at any given stage's modifications snapshot:

- the byte's source instructions appear (matched by EA) inside any
  ``InsertBlock`` body, OR
- the byte's block is the explicit ``new_target`` of a redirect-shaped mod,
  OR
- nothing has redirected away from the byte's block (passive preservation).

A byte is reported lost when it was present in ``dag`` or ``corrected_dag``
but did not survive the final fragment under that predicate.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from enum import Enum

from d810.core.typing import Iterable, Sequence


ENV_GATE = "D810_HCC_BYTE_CASCADE_TRACE"
ROW_LOG_PREFIX = "HCC_BYTE_CASCADE_TRACE_ROW"
TABLE_LOG_PREFIX = "HCC_BYTE_CASCADE_TRACE_TABLE"


class ByteCascadeStage(str, Enum):
    """Discrete observation points inside HCC ``plan()``."""

    SEED_DAG = "seed_dag"
    SEED_CORRECTED_DAG = "seed_corrected_dag"
    RAW_REGION_TABLE = "raw_region_table"
    CANDIDATE_BUILD = "candidate_build"
    PRIMARY_EXECUTION = "primary_execution"
    FALLBACK_EXECUTION = "fallback_execution"
    FRONTIER_OVERRIDES = "frontier_overrides"
    POSTPROCESS = "postprocess"
    LATE_SHARED_FALLBACK = "late_shared_fallback"
    REGION_FILTER = "region_filter"
    CALL_BARRIER_COLLISION = "call_barrier_collision"
    PAYLOAD_INTERMEDIATE_FILTER = "payload_intermediate_filter"
    CORRIDOR_FILTER = "corridor_filter"
    CARRIER_FILTER = "carrier_filter"
    FINALIZE_ARBITER = "finalize_arbiter"
    FINAL = "final"


@dataclass(frozen=True, slots=True)
class ModSig:
    """Canonical signature for a modification, used to diff before/after filters."""

    kind: str
    src: int
    old: int | None
    new: int | None
    fingerprint: str = ""


@dataclass(frozen=True, slots=True)
class ByteEvidence:
    """Per-byte evidence drawn from ``TerminalByteEmitterFact`` payloads.

    Block serial is best-effort (may drift across snapshots); EAs are the
    stable bridge for matching against InsertBlock bodies.
    """

    byte_index: int
    block_serial: int | None
    block_ea_hex: str | None
    source_ea_hex: str | None
    destination: str
    source_expression: str
    fact_id: str
    confidence: float


@dataclass
class StageObservation:
    """Single-stage snapshot for one byte."""

    preserved: bool = False
    mechanism: str = ""
    note: str = ""


@dataclass
class ByteRecord:
    """Accumulated trajectory for one byte across all stages."""

    byte: ByteEvidence
    entry_anchor: int | None = None
    dag_node_key: str | None = None
    in_dag: bool = False
    in_corrected_dag: bool = False
    in_region_table: bool = False
    raw_candidate: bool = False
    candidate_rejection: str | None = None
    accepted_stage: str | None = None
    emitted_mod_kind: str | None = None
    preserved_in_insertblock: bool = False
    stages: dict[str, StageObservation] = field(default_factory=dict)
    first_dropped_stage: str | None = None
    final_status: str = "unknown"

    @property
    def block_ea_hex(self) -> str:
        return self.byte.block_ea_hex or ""

    def render_row_log(self) -> str:
        parts = [
            f"byte={self.byte.byte_index}",
            f"block_ea={self.byte.block_ea_hex or '?'}",
            f"block_serial={self.byte.block_serial if self.byte.block_serial is not None else '?'}",
            f"entry_anchor={self.entry_anchor if self.entry_anchor is not None else '?'}",
            f"dag_node={self.dag_node_key or '?'}",
            f"in_dag={1 if self.in_dag else 0}",
            f"in_corrected_dag={1 if self.in_corrected_dag else 0}",
            f"in_region_table={1 if self.in_region_table else 0}",
            f"raw_candidate={1 if self.raw_candidate else 0}",
            f"candidate_rejection={(self.candidate_rejection or '-')!r}",
            f"accepted_stage={self.accepted_stage or '-'}",
            f"emitted_mod={self.emitted_mod_kind or '-'}",
            f"preserved_in_insertblock={1 if self.preserved_in_insertblock else 0}",
            f"first_dropped_stage={self.first_dropped_stage or '-'}",
            f"final_status={self.final_status}",
        ]
        return f"{ROW_LOG_PREFIX} " + " ".join(parts)


# ---------------------------------------------------------------------------
# Helpers (pure, no IDA imports)
# ---------------------------------------------------------------------------


def _format_ea_hex(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        try:
            return f"0x{int(value, 0):016X}"
        except ValueError:
            return value
    try:
        return f"0x{int(value):016X}"
    except (TypeError, ValueError):
        return None


def _int_or_none(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _canonical_mod_sig(mod: object) -> ModSig:
    """Return a stable signature for a modification.

    Compares mods by structural identity rather than object identity, so the
    same mod can be tracked across filter stages even when wrapped/rebuilt.
    """
    cls_name = type(mod).__name__
    if cls_name == "RedirectGoto":
        return ModSig(
            kind="redirect_goto",
            src=int(getattr(mod, "from_serial", -1)),
            old=int(getattr(mod, "old_target", -1)),
            new=int(getattr(mod, "new_target", -1)),
        )
    if cls_name == "RedirectBranch":
        return ModSig(
            kind="redirect_branch",
            src=int(getattr(mod, "from_serial", -1)),
            old=int(getattr(mod, "old_target", -1)),
            new=int(getattr(mod, "new_target", -1)),
        )
    if cls_name == "ConvertToGoto":
        return ModSig(
            kind="convert_to_goto",
            src=int(getattr(mod, "block_serial", -1)),
            old=None,
            new=int(getattr(mod, "goto_target", -1)),
        )
    if cls_name == "EdgeRedirectViaPredSplit":
        return ModSig(
            kind="edge_redirect_via_pred_split",
            src=int(getattr(mod, "src_block", -1)),
            old=int(getattr(mod, "old_target", -1)),
            new=int(getattr(mod, "new_target", -1)),
            fingerprint=f"via_pred={int(getattr(mod, 'via_pred', -1))}",
        )
    if cls_name == "DuplicateBlock":
        return ModSig(
            kind="duplicate_block",
            src=int(getattr(mod, "source_block", -1)),
            old=_int_or_none(getattr(mod, "target_block", None)),
            new=_int_or_none(getattr(mod, "pred_serial", None)),
            fingerprint=str(getattr(mod, "patch_kind", "") or ""),
        )
    if cls_name == "InsertBlock":
        instructions = getattr(mod, "instructions", ()) or ()
        ea_hexes: list[str] = []
        for ins in instructions:
            ea_hex = _format_ea_hex(getattr(ins, "ea", None))
            if ea_hex is not None:
                ea_hexes.append(ea_hex)
        fp = ",".join(sorted(set(ea_hexes)))[:120]
        succ = int(getattr(mod, "succ_serial", -1))
        old_target_serial = getattr(mod, "old_target_serial", None)
        return ModSig(
            kind="insert_block",
            src=int(getattr(mod, "pred_serial", -1)),
            old=int(old_target_serial) if old_target_serial is not None else succ,
            new=succ,
            fingerprint=fp,
        )
    if cls_name == "CreateConditionalRedirect":
        return ModSig(
            kind="create_conditional_redirect",
            src=int(getattr(mod, "source_block", -1)),
            old=int(getattr(mod, "ref_block", -1)),
            new=int(getattr(mod, "conditional_target", -1)),
            fingerprint=f"fallthrough={int(getattr(mod, 'fallthrough_target', -1))}",
        )
    return ModSig(
        kind=cls_name.lower(),
        src=_int_or_none(getattr(mod, "from_serial", None))
        or _int_or_none(getattr(mod, "pred_serial", None))
        or -1,
        old=_int_or_none(getattr(mod, "old_target", None))
        or _int_or_none(getattr(mod, "old_target_serial", None)),
        new=_int_or_none(getattr(mod, "new_target", None))
        or _int_or_none(getattr(mod, "succ_serial", None)),
    )


def _insertblock_contains_evidence(
    mod: object,
    byte_source_ea_hex_set: frozenset[str],
) -> bool:
    if type(mod).__name__ != "InsertBlock":
        return False
    instructions = getattr(mod, "instructions", ()) or ()
    for ins in instructions:
        ea_hex = _format_ea_hex(getattr(ins, "ea", None))
        if ea_hex is None:
            continue
        if ea_hex in byte_source_ea_hex_set:
            return True
    return False


def _byte_block_redirected_away(mod: object, block_serial: int | None) -> bool:
    if block_serial is None:
        return False
    cls_name = type(mod).__name__
    if cls_name in ("RedirectGoto", "RedirectBranch"):
        return int(getattr(mod, "from_serial", -1)) == int(block_serial)
    if cls_name == "ConvertToGoto":
        return int(getattr(mod, "block_serial", -1)) == int(block_serial)
    if cls_name == "EdgeRedirectViaPredSplit":
        return int(getattr(mod, "src_block", -1)) == int(block_serial)
    if cls_name == "InsertBlock":
        return int(getattr(mod, "pred_serial", -1)) == int(block_serial)
    return False


def _byte_block_redirect_target(mod: object, block_serial: int | None) -> bool:
    if block_serial is None:
        return False
    cls_name = type(mod).__name__
    if cls_name in ("RedirectGoto", "RedirectBranch"):
        return int(getattr(mod, "new_target", -1)) == int(block_serial)
    if cls_name == "ConvertToGoto":
        return int(getattr(mod, "goto_target", -1)) == int(block_serial)
    if cls_name == "EdgeRedirectViaPredSplit":
        return int(getattr(mod, "new_target", -1)) == int(block_serial)
    if cls_name == "InsertBlock":
        return int(getattr(mod, "succ_serial", -1)) == int(block_serial)
    return False


def _classify_preservation(
    byte: ByteEvidence,
    mods: Sequence[object],
) -> tuple[bool, str]:
    """Apply the preservation predicate against a set of modifications.

    Returns ``(preserved, mechanism)`` where ``mechanism`` is one of:

    - ``insertblock_evidence`` -- byte's source EAs appear in an InsertBlock body
    - ``redirect_target`` -- byte's block is the explicit new target of a redirect
    - ``passive`` -- nothing rewired away from the byte's block (default-preserved)
    - ``redirected_away`` -- the byte's block was rewired away with no replacement
    """
    if byte.source_ea_hex is not None:
        evidence_set = frozenset({byte.source_ea_hex})
    else:
        evidence_set = frozenset()

    if evidence_set:
        for mod in mods:
            if _insertblock_contains_evidence(mod, evidence_set):
                return True, "insertblock_evidence"

    for mod in mods:
        if _byte_block_redirect_target(mod, byte.block_serial):
            return True, "redirect_target"

    for mod in mods:
        if _byte_block_redirected_away(mod, byte.block_serial):
            return False, "redirected_away"

    return True, "passive"


# ---------------------------------------------------------------------------
# Tracer
# ---------------------------------------------------------------------------


def is_enabled() -> bool:
    return os.environ.get(ENV_GATE, "").strip() == "1"


@dataclass
class ByteCascadeCoverageTracer:
    """Threaded through HCC's ``plan()`` and ``_run_swr_orchestration``.

    All hook methods are no-ops if the tracer was constructed with no byte
    evidence (e.g. no ``TerminalByteEmitterFact`` rows in the snapshot).
    """

    records: dict[int, ByteRecord]
    logger: object | None = None
    func_ea_hex: str = ""
    target_bytes: tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6)

    @classmethod
    def from_snapshot(
        cls,
        snapshot: object,
        *,
        logger: object | None = None,
    ) -> "ByteCascadeCoverageTracer | None":
        if not is_enabled():
            return None
        fact_view = (
            getattr(snapshot, "diagnostic_fact_view", None)
            or getattr(snapshot, "validated_fact_view", None)
        )
        if fact_view is None:
            return None
        records = _seed_records_from_fact_view(fact_view)
        if not records:
            return None
        mba = getattr(snapshot, "mba", None)
        func_ea = _format_ea_hex(getattr(mba, "entry_ea", None)) or ""
        return cls(records=records, logger=logger, func_ea_hex=func_ea)

    # ------------------------------------------------------------------
    # Hook methods (all guarded against missing evidence)
    # ------------------------------------------------------------------

    def seed_dag(self, dag: object) -> None:
        if not self.records or dag is None:
            return
        self._mark_dag_membership(dag, attr="in_dag")
        self._record_stage_event(ByteCascadeStage.SEED_DAG, present_fn=lambda r: r.in_dag)

    def seed_corrected_dag(self, corrected_dag: object) -> None:
        if not self.records or corrected_dag is None:
            return
        self._mark_dag_membership(corrected_dag, attr="in_corrected_dag")
        self._record_stage_event(
            ByteCascadeStage.SEED_CORRECTED_DAG,
            present_fn=lambda r: r.in_corrected_dag,
        )

    def seed_raw_region_table(self, raw_region_table: object) -> None:
        if not self.records:
            return
        region_block_serials = _collect_region_block_serials(raw_region_table)
        for record in self.records.values():
            if record.byte.block_serial in region_block_serials:
                record.in_region_table = True
        self._record_stage_event(
            ByteCascadeStage.RAW_REGION_TABLE,
            present_fn=lambda r: r.in_region_table,
        )

    def record_candidate_build(
        self,
        edge: object,
        candidate: object | None,
        rejection: object | None,
    ) -> None:
        if not self.records:
            return
        serial = _edge_source_block_serial(edge)
        if serial is None:
            return
        for record in self.records.values():
            if record.byte.block_serial != serial:
                continue
            if candidate is not None:
                record.raw_candidate = True
            if rejection is not None and record.candidate_rejection is None:
                record.candidate_rejection = _stringify_rejection(rejection)

    def record_stage_modifications(
        self,
        stage: ByteCascadeStage,
        modifications: Sequence[object],
    ) -> None:
        """Snapshot the predicate at a given stage.

        For each byte, records preserved-or-not + the mechanism, and assigns
        accepted_stage / first_dropped_stage on the first transition.
        """
        if not self.records:
            return
        for record in self.records.values():
            preserved, mechanism = _classify_preservation(record.byte, modifications)
            record.stages[stage.value] = StageObservation(
                preserved=preserved,
                mechanism=mechanism,
            )
            if preserved:
                if record.accepted_stage is None and mechanism != "passive":
                    record.accepted_stage = stage.value
                if mechanism == "insertblock_evidence":
                    record.preserved_in_insertblock = True
                    if record.emitted_mod_kind is None:
                        record.emitted_mod_kind = "InsertBlock"
                elif mechanism == "redirect_target" and record.emitted_mod_kind is None:
                    record.emitted_mod_kind = _redirect_kind_for_target(
                        record.byte.block_serial, modifications
                    )
            else:
                if record.first_dropped_stage is None:
                    record.first_dropped_stage = stage.value

    def record_finalize(self, final_modifications: Sequence[object]) -> None:
        if not self.records:
            return
        self.record_stage_modifications(ByteCascadeStage.FINAL, final_modifications)
        for record in self.records.values():
            stage = record.stages.get(ByteCascadeStage.FINAL.value)
            if stage is None:
                record.final_status = "no_final_observation"
                continue
            if stage.preserved:
                record.final_status = (
                    "preserved_insertblock"
                    if stage.mechanism == "insertblock_evidence"
                    else "preserved_passive"
                    if stage.mechanism == "passive"
                    else "preserved_redirect"
                )
            else:
                record.final_status = "lost"

    def emit_log(self) -> None:
        if not self.records or self.logger is None:
            return
        logger = self.logger
        info = getattr(logger, "info", None)
        if not callable(info):
            return
        for byte_index in sorted(self.records.keys()):
            info("%s", self.records[byte_index].render_row_log())
        info("%s\n%s", TABLE_LOG_PREFIX, self.render_markdown_table())

    def render_markdown_table(self) -> str:
        header = (
            "| byte | block_ea | block_serial | entry_anchor | in_dag |"
            " in_corrected_dag | in_region | raw_candidate | rejection |"
            " accepted_stage | emitted_mod | preserved_in_insertblock |"
            " first_dropped_stage | final_status |"
        )
        sep = "|-|-|-|-|-|-|-|-|-|-|-|-|-|-|"
        rows: list[str] = []
        for byte_index in sorted(self.records.keys()):
            r = self.records[byte_index]
            rows.append(
                "| "
                + " | ".join(
                    [
                        str(r.byte.byte_index),
                        r.byte.block_ea_hex or "?",
                        (str(r.byte.block_serial) if r.byte.block_serial is not None else "?"),
                        (str(r.entry_anchor) if r.entry_anchor is not None else "?"),
                        "1" if r.in_dag else "0",
                        "1" if r.in_corrected_dag else "0",
                        "1" if r.in_region_table else "0",
                        "1" if r.raw_candidate else "0",
                        r.candidate_rejection or "-",
                        r.accepted_stage or "-",
                        r.emitted_mod_kind or "-",
                        "1" if r.preserved_in_insertblock else "0",
                        r.first_dropped_stage or "-",
                        r.final_status,
                    ]
                )
                + " |"
            )
        title = (
            f"### HCC byte-cascade coverage for func {self.func_ea_hex or '?'}"
        )
        return "\n".join([title, "", header, sep, *rows])

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _mark_dag_membership(self, dag: object, *, attr: str) -> None:
        nodes = getattr(dag, "nodes", None)
        if not nodes:
            return
        for node in nodes:
            anchor = _int_or_none(getattr(node, "entry_anchor", None))
            if anchor is None:
                continue
            for record in self.records.values():
                if record.byte.block_serial is None:
                    continue
                owned = getattr(node, "owned_blocks", ()) or ()
                owned_ints = {_int_or_none(b) for b in owned if _int_or_none(b) is not None}
                if (
                    anchor == record.byte.block_serial
                    or record.byte.block_serial in owned_ints
                ):
                    setattr(record, attr, True)
                    if record.entry_anchor is None:
                        record.entry_anchor = anchor
                    if record.dag_node_key is None:
                        key_obj = getattr(node, "key", None)
                        record.dag_node_key = (
                            str(key_obj) if key_obj is not None else None
                        )

    def _record_stage_event(
        self,
        stage: ByteCascadeStage,
        *,
        present_fn,
    ) -> None:
        for record in self.records.values():
            record.stages[stage.value] = StageObservation(
                preserved=present_fn(record),
                mechanism="dag_membership",
            )


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------


_VAR_190_BYTE_RE = re.compile(r"%var_190\.8\+#(?P<byte>[0-9]+)\.8")


def _seed_records_from_fact_view(fact_view: object) -> dict[int, ByteRecord]:
    """Collect bytes 0-6 from ``TerminalByteEmitterFact`` observations.

    Falls back to parsing ``source_byte_expression`` when the payload lacks an
    explicit ``byte_index`` field.
    """
    records: dict[int, ByteRecord] = {}
    active = getattr(fact_view, "active_observations", ())
    for obs in active or ():
        if getattr(obs, "kind", None) != "TerminalByteEmitterFact":
            continue
        payload = getattr(obs, "payload", None) or {}
        if payload.get("corridor_role") != "terminal_tail":
            continue
        byte_index = _int_or_none(payload.get("byte_index"))
        if byte_index is None:
            text = str(payload.get("source_byte_expression") or "")
            match = _VAR_190_BYTE_RE.search(text)
            if match is not None:
                byte_index = int(match.group("byte"))
        if byte_index is None:
            continue
        confidence = float(getattr(obs, "confidence", 0.0) or 0.0)
        existing = records.get(byte_index)
        candidate = ByteEvidence(
            byte_index=byte_index,
            block_serial=_int_or_none(
                payload.get("destination_block")
                or payload.get("block_serial")
                or payload.get("source_block")
            ),
            block_ea_hex=_format_ea_hex(payload.get("block_ea")),
            source_ea_hex=_format_ea_hex(payload.get("source_ea")),
            destination=str(payload.get("destination_buffer_expression") or ""),
            source_expression=str(payload.get("source_byte_expression") or ""),
            fact_id=str(getattr(obs, "fact_id", "") or ""),
            confidence=confidence,
        )
        if existing is None or _evidence_better(candidate, existing.byte):
            records[byte_index] = ByteRecord(byte=candidate)
    return records


def _evidence_better(new: ByteEvidence, old: ByteEvidence) -> bool:
    """Prefer evidence with stronger anchoring (EAs available, real store)."""
    score_new = (
        (1 if new.source_ea_hex else 0)
        + (1 if new.block_ea_hex else 0)
        + (2 if "%var_190" in new.source_expression else 0)
        + new.confidence
    )
    score_old = (
        (1 if old.source_ea_hex else 0)
        + (1 if old.block_ea_hex else 0)
        + (2 if "%var_190" in old.source_expression else 0)
        + old.confidence
    )
    return score_new > score_old


def _collect_region_block_serials(raw_region_table: object) -> set[int]:
    """Best-effort extraction of block serials from HCC's raw_region_table."""
    out: set[int] = set()
    if raw_region_table is None:
        return out
    iterable: Iterable[object]
    if isinstance(raw_region_table, dict):
        iterable = raw_region_table.values()
    else:
        try:
            iterable = list(raw_region_table)  # type: ignore[arg-type]
        except TypeError:
            return out
    for entry in iterable:
        for attr in ("handler_serials", "block_serials", "owned_blocks", "members"):
            value = getattr(entry, attr, None)
            if value is None:
                continue
            for item in value:
                parsed = _int_or_none(item)
                if parsed is not None:
                    out.add(parsed)
    return out


def _edge_source_block_serial(edge: object) -> int | None:
    """Best-effort source block for a state-DAG edge.

    Tries the ``source_anchor.block_serial`` path first, then walks
    ``ordered_path`` for the first integer entry.
    """
    anchor = getattr(edge, "source_anchor", None)
    if anchor is not None:
        serial = _int_or_none(getattr(anchor, "block_serial", None))
        if serial is not None:
            return serial
    ordered_path = getattr(edge, "ordered_path", ()) or ()
    for item in ordered_path:
        parsed = _int_or_none(item)
        if parsed is not None:
            return parsed
    return None


def _stringify_rejection(rejection: object) -> str:
    if rejection is None:
        return ""
    if isinstance(rejection, dict):
        for key in ("rejection_reason", "reason", "kind"):
            value = rejection.get(key)
            if value:
                return str(value)
        return str(sorted(rejection.items()))[:160]
    return str(rejection)[:160]


def _redirect_kind_for_target(
    block_serial: int | None,
    mods: Sequence[object],
) -> str:
    if block_serial is None:
        return ""
    for mod in mods:
        if _byte_block_redirect_target(mod, block_serial):
            return type(mod).__name__
    return ""
