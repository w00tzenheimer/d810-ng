"""Read-only terminal-tail cascade egress planner.

The structuring lab showed that Hex-Rays renders terminal byte tails
cleanly when the CFG is an acyclic per-byte emit/guard cascade. This
module answers the next question without mutating CFGs: given existing
``TerminalByteEmitterFact`` payloads and a target microcode snapshot,
can the current D810 graph be rewired into that cascade shape?
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from d810.cfg.scc import compute_live_cfg_sccs
from d810.core.typing import Iterable, Mapping

SAFE_STATE_ALREADY_SET = "SAFE_STATE_ALREADY_SET"
SAFE_TARGET_POST_GUARD = "SAFE_TARGET_POST_GUARD"
NEEDS_STATE_WRITE = "NEEDS_STATE_WRITE"
AMBIGUOUS_STATE_UPDATE = "AMBIGUOUS_STATE_UPDATE"

_GUARD_COMPARE_RE = re.compile(
    r"\b(?:jnz|jz|jcnd)\s+"
    r"(?P<var>%var_[0-9A-Fa-f]+)\.\d+\s*,\s*"
    r"#(?P<value>[-+]?(?:0x[0-9A-Fa-f]+|\d+))\.\d+",
)
_MOV_CONST_RE = re.compile(
    r"\bmov\s+#(?P<value>[-+]?(?:0x[0-9A-Fa-f]+|\d+))\.\d+\s*,\s*"
    r"(?P<var>%var_[0-9A-Fa-f]+)\.\d+",
)
_BRANCH_TARGET_RE = re.compile(r"@(?P<target>\d+)\b")


@dataclass(frozen=True, slots=True)
class TerminalTailBlock:
    """Minimal block shape needed by the planner."""

    serial: int
    succs: tuple[int, ...]
    preds: tuple[int, ...] = ()
    type_name: str = ""
    start_ea_hex: str | None = None
    insn_opcodes: tuple[str, ...] = ()
    insn_text: tuple[str, ...] = ()

    @property
    def has_explicit_store(self) -> bool:
        return any(
            opcode in {"m_stx", "op_1"} or text.lstrip().startswith("stx")
            for opcode, text in zip(self.insn_opcodes, self.insn_text)
        )


@dataclass(frozen=True, slots=True)
class TerminalByteEmitSite:
    """One terminal-byte fact resolved into planner input."""

    byte_index: int
    block_serial: int
    fact_id: str = ""
    source_ea_hex: str | None = None
    block_ea_hex: str | None = None
    opcode: str = ""
    emitter_role: str = ""
    corridor_role: str = ""
    destination: str = ""
    source_expression: str = ""
    return_edge: int | None = None
    continuation_edge: int | None = None
    successor_blocks: tuple[int, ...] = ()
    confidence: float = 0.0

    @property
    def explicit_store(self) -> bool:
        return self.opcode == "m_stx"

    @property
    def is_guard_only(self) -> bool:
        return self.emitter_role == "guard_only"

    @property
    def is_terminal_tail(self) -> bool:
        return self.corridor_role == "terminal_tail"


@dataclass(frozen=True, slots=True)
class TerminalTailCascadeEgressRow:
    """Per-byte candidate rewrite plan."""

    byte_index: int
    source_block: int | None
    current_continuation_target: int | None
    intended_target: int | None
    early_return_target: int | None
    current_convergence_target: int | None
    state_variable: str | None
    state_required_value: int | None
    state_write_block: int | None
    state_write_path: tuple[int, ...]
    state_write_bypassed: bool
    state_update_verdict: str
    confidence: float
    reason: str
    explicit_store: bool = False
    preserves_early_return: bool = False
    removes_from_scc: bool = False
    source_scc_size_before: int | None = None
    source_scc_size_after: int | None = None
    largest_scc_size_before: int | None = None
    largest_scc_size_after: int | None = None


@dataclass(frozen=True, slots=True)
class TerminalTailCascadeEgressPlan:
    """Planner output for the full byte tail."""

    rows: tuple[TerminalTailCascadeEgressRow, ...]
    largest_scc_size_before: int
    largest_scc_size_after: int

    @property
    def complete_bytes(self) -> tuple[int, ...]:
        return tuple(
            row.byte_index
            for row in self.rows
            if row.source_block is not None and row.intended_target is not None
        )

    @property
    def gap_bytes(self) -> tuple[int, ...]:
        return tuple(
            row.byte_index
            for row in self.rows
            if row.source_block is None or row.intended_target is None
        )


def _int_or_none(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _string_or_none(value: object) -> str | None:
    if value is None:
        return None
    text = str(value)
    return text or None


def _int_tuple(value: object) -> tuple[int, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    out: list[int] = []
    for item in value:
        converted = _int_or_none(item)
        if converted is not None:
            out.append(converted)
    return tuple(out)


def terminal_byte_emit_site_from_payload(
    fact_id: str,
    payload: Mapping[str, object],
    *,
    source_ea_hex: str | None = None,
    confidence: float = 0.0,
) -> TerminalByteEmitSite | None:
    """Build a planner site from a ``TerminalByteEmitterFact`` payload."""
    byte_index = _int_or_none(payload.get("byte_index"))
    block_serial = _int_or_none(
        payload.get("destination_block")
        or payload.get("block_serial")
        or payload.get("source_block")
    )
    if byte_index is None or block_serial is None:
        return None
    block_ea = _int_or_none(payload.get("block_ea"))
    return TerminalByteEmitSite(
        byte_index=byte_index,
        block_serial=block_serial,
        fact_id=fact_id,
        source_ea_hex=source_ea_hex,
        block_ea_hex=f"0x{block_ea:016X}" if block_ea is not None else None,
        opcode=str(payload.get("opcode") or ""),
        emitter_role=str(payload.get("emitter_role") or ""),
        corridor_role=str(payload.get("corridor_role") or ""),
        destination=str(payload.get("destination_buffer_expression") or ""),
        source_expression=str(payload.get("source_byte_expression") or ""),
        return_edge=_int_or_none(payload.get("return_edge")),
        continuation_edge=_int_or_none(payload.get("continuation_edge")),
        successor_blocks=_int_tuple(payload.get("successor_blocks")),
        confidence=float(confidence or 0.0),
    )


def _site_mentions_exact_source_byte(site: TerminalByteEmitSite) -> bool:
    if site.byte_index == 0:
        return "%var_190" in site.source_expression
    needles = (
        f"%var_190.8+#{site.byte_index}.8",
        f"%var_190+#{site.byte_index}",
        f"%var_190.8 + #{site.byte_index}.8",
    )
    return any(needle in site.source_expression for needle in needles)


def _site_score(site: TerminalByteEmitSite) -> tuple[int, float, int]:
    """Prefer the site most likely to represent the real byte emit."""
    score = 0
    if _site_mentions_exact_source_byte(site):
        score += 60
    if site.is_terminal_tail:
        score += 40
    if site.explicit_store:
        score += 20
    if site.emitter_role == "memory_store":
        score += 12
    if site.return_edge is not None:
        score += 8
    if site.continuation_edge is not None:
        score += 8
    if "%var_188" in site.destination or "%var_190" in site.source_expression:
        score += 8
    if site.destination == "%var_178.8":
        score -= 4
    if site.is_guard_only:
        score -= 18
    return (score, site.confidence, -site.block_serial)


def _select_sites_by_byte(
    sites: Iterable[TerminalByteEmitSite],
) -> dict[int, TerminalByteEmitSite]:
    selected: dict[int, TerminalByteEmitSite] = {}
    for site in sites:
        if not site.is_terminal_tail and not _site_mentions_exact_source_byte(site):
            continue
        current = selected.get(site.byte_index)
        if current is None or _site_score(site) > _site_score(current):
            selected[site.byte_index] = site
    return selected


def _block_has_call(block: TerminalTailBlock) -> bool:
    return any(
        opcode in {"m_call", "op_56"} or text.lstrip().startswith("call")
        for opcode, text in zip(block.insn_opcodes, block.insn_text)
    )


def _block_has_guard(block: TerminalTailBlock) -> bool:
    return any(_GUARD_COMPARE_RE.search(text) for text in block.insn_text)


def _entry_predecessor_score(
    *,
    candidate: TerminalTailBlock,
    first_byte_block: int,
) -> tuple[int, int, int]:
    score = 0
    if tuple(candidate.succs) == (int(first_byte_block),):
        score += 80
    if candidate.type_name == "BLT_1WAY":
        score += 30
    if _block_has_call(candidate):
        score += 20
    if not _block_has_guard(candidate):
        score += 10
    if not candidate.has_explicit_store:
        score += 5
    # Prefer the closest predecessor when scores tie.
    return (score, -abs(int(candidate.serial) - int(first_byte_block)), -int(candidate.serial))


def select_effective_terminal_tail_entry_block(
    blocks: Mapping[int, TerminalTailBlock],
    sites: Iterable[TerminalByteEmitSite],
) -> int | None:
    """Return the materialized terminal-tail entry block in snapshot space.

    The DAG's nominal target entry can point at a dispatcher/state block that
    later materializes as a byte-tail island.  For CFG lowering we want the
    first preserved block of that island, including the prep/helper-call block
    immediately before the first byte body when it exists:

    ``prep -> first_byte`` rather than the literal DAG ``target_entry``.

    The choice is fact-backed: find the earliest usable terminal byte emitter,
    then prefer a single-successor, non-guard predecessor that flows directly
    into that byte block.  If no prep block exists, fall back to the byte block
    itself.  Callers bridge the returned snapshot serial to the live MBA by EA.
    """
    by_byte = _select_sites_by_byte(sites)
    ordered_sites = [
        site
        for byte_index, site in sorted(by_byte.items())
        if byte_index >= 1 and site.block_serial in blocks
    ]
    if not ordered_sites:
        ordered_sites = [
            site for _, site in sorted(by_byte.items()) if site.block_serial in blocks
        ]
    if not ordered_sites:
        return None

    first_site = ordered_sites[0]
    first_block = blocks.get(int(first_site.block_serial))
    if first_block is None:
        return None

    candidates: list[TerminalTailBlock] = []
    for pred in first_block.preds:
        pred_block = blocks.get(int(pred))
        if pred_block is None:
            continue
        if int(first_block.serial) not in tuple(int(s) for s in pred_block.succs):
            continue
        candidates.append(pred_block)

    if not candidates:
        return int(first_block.serial)
    candidates.sort(
        key=lambda block: _entry_predecessor_score(
            candidate=block,
            first_byte_block=int(first_block.serial),
        ),
        reverse=True,
    )
    best = candidates[0]
    if _entry_predecessor_score(candidate=best, first_byte_block=int(first_block.serial))[0] <= 0:
        return int(first_block.serial)
    return int(best.serial)


def _largest_cyclic_scc_size(block_succs: Mapping[int, tuple[int, ...]]) -> int:
    sizes = [scc.size for scc in compute_live_cfg_sccs(block_succs) if scc.is_cyclic]
    return max(sizes, default=1)


def _scc_size_for_block(
    block_succs: Mapping[int, tuple[int, ...]], block_serial: int | None,
) -> int | None:
    if block_serial is None:
        return None
    for scc in compute_live_cfg_sccs(block_succs):
        if block_serial in scc.blocks:
            return scc.size
    return None


def _mutated_succs(
    block_succs: Mapping[int, tuple[int, ...]],
    source: int,
    old_target: int,
    new_target: int,
) -> dict[int, tuple[int, ...]]:
    out = {int(src): tuple(int(s) for s in succs) for src, succs in block_succs.items()}
    current = out.get(source, ())
    rewritten = tuple(new_target if succ == old_target else succ for succ in current)
    out[source] = rewritten
    out.setdefault(new_target, ())
    return out


def _parse_int_literal(text: str) -> int | None:
    try:
        return int(text, 0)
    except ValueError:
        return None


def _guard_state_requirement(
    block: TerminalTailBlock | None,
) -> tuple[str | None, int | None]:
    if block is None:
        return (None, None)
    for index in range(len(block.insn_text) - 1, -1, -1):
        text = block.insn_text[index]
        match = _GUARD_COMPARE_RE.search(text)
        if match is None:
            continue
        has_prior_store = any(
            opcode in {"m_stx", "op_1"} or prior_text.lstrip().startswith("stx")
            for opcode, prior_text in zip(
                block.insn_opcodes[:index],
                block.insn_text[:index],
            )
        )
        if has_prior_store:
            # This is the byte block's own post-emit early-return guard,
            # not a precondition that the predecessor must synthesize.
            continue
        return (match.group("var"), _parse_int_literal(match.group("value")))
    return (None, None)


def _tail_branch_target(block: TerminalTailBlock) -> int | None:
    for text in reversed(block.insn_text):
        if not _GUARD_COMPARE_RE.search(text):
            continue
        match = _BRANCH_TARGET_RE.search(text)
        if match is None:
            continue
        return _parse_int_literal(match.group("target"))
    return None


def _state_write_in_block(
    block: TerminalTailBlock | None,
    variable: str | None,
    required_value: int | None,
) -> bool:
    if block is None or variable is None or required_value is None:
        return False
    for text in block.insn_text:
        match = _MOV_CONST_RE.search(text)
        if match is None or match.group("var") != variable:
            continue
        if _parse_int_literal(match.group("value")) == required_value:
            return True
    return False


def _shortest_path(
    block_succs: Mapping[int, tuple[int, ...]],
    start: int | None,
    target: int | None,
    *,
    max_depth: int = 64,
) -> tuple[int, ...]:
    if start is None or target is None:
        return ()
    if start == target:
        return (start,)
    queue: list[tuple[int, tuple[int, ...]]] = [(start, (start,))]
    seen = {start}
    while queue:
        node, path = queue.pop(0)
        if len(path) > max_depth:
            continue
        for succ in block_succs.get(node, ()):
            if succ in seen:
                continue
            next_path = path + (succ,)
            if succ == target:
                return next_path
            seen.add(succ)
            queue.append((succ, next_path))
    return ()


def _state_update_proof(
    *,
    blocks: Mapping[int, TerminalTailBlock],
    block_succs: Mapping[int, tuple[int, ...]],
    source_block: int | None,
    continuation: int | None,
    intended_target: int | None,
) -> tuple[str | None, int | None, int | None, tuple[int, ...], bool, str]:
    target_block = blocks.get(intended_target) if intended_target is not None else None
    variable, required_value = _guard_state_requirement(target_block)
    if variable is None or required_value is None:
        return (None, None, None, (), False, SAFE_TARGET_POST_GUARD)

    source = blocks.get(source_block) if source_block is not None else None
    if _state_write_in_block(source, variable, required_value):
        return (
            variable,
            required_value,
            source_block,
            (source_block,) if source_block is not None else (),
            False,
            SAFE_STATE_ALREADY_SET,
        )

    path = _shortest_path(block_succs, continuation, intended_target)
    for serial in path[:-1]:
        if _state_write_in_block(blocks.get(serial), variable, required_value):
            return (variable, required_value, serial, path, True, NEEDS_STATE_WRITE)

    return (variable, required_value, None, path, False, AMBIGUOUS_STATE_UPDATE)


def _current_continuation(
    block: TerminalTailBlock,
    site: TerminalByteEmitSite,
    early_return: int | None,
) -> int | None:
    branch_target = _tail_branch_target(block)
    if branch_target in block.succs and len(block.succs) == 2:
        return branch_target
    if site.continuation_edge in block.succs:
        return site.continuation_edge
    for succ in block.succs:
        if succ != early_return:
            return succ
    return block.succs[0] if block.succs else None


def _early_return_target(
    block: TerminalTailBlock,
    site: TerminalByteEmitSite,
) -> int | None:
    branch_target = _tail_branch_target(block)
    if branch_target in block.succs and len(block.succs) == 2:
        for succ in block.succs:
            if succ != branch_target:
                return succ
    if site.return_edge in block.succs:
        return site.return_edge
    if site.return_edge is not None:
        return site.return_edge
    if site.continuation_edge in block.succs:
        for succ in block.succs:
            if succ != site.continuation_edge:
                return succ
    return None


def _reason(
    *,
    site: TerminalByteEmitSite | None,
    block: TerminalTailBlock | None,
    intended_target: int | None,
    preserves_early_return: bool,
    removes_from_scc: bool,
) -> str:
    if site is None:
        return "missing_terminal_byte_emitter_fact"
    if site.is_guard_only:
        return "guard_only_byte0_collector_gap"
    if block is None:
        return "fact_block_not_present_in_target_snapshot"
    if not site.explicit_store and not block.has_explicit_store:
        return "no_explicit_m_stx_in_resolved_block"
    if intended_target is None:
        return "terminal_byte_has_no_next_emit_target"
    if site is not None and intended_target == site.block_serial:
        return "next_byte_emit_resolves_to_same_block_split_required"
    if not preserves_early_return:
        return "rewrite_would_not_preserve_distinct_early_return_edge"
    if removes_from_scc:
        return "complete_cascade_egress_candidate_reduces_source_scc"
    return "complete_cascade_egress_candidate"


class TerminalTailCascadeEgressPlanner:
    """Read-only planner for REF-like terminal-tail cascade rewiring."""

    def __init__(
        self,
        blocks: Mapping[int, TerminalTailBlock],
        sites: Iterable[TerminalByteEmitSite],
    ) -> None:
        self._blocks = {int(serial): block for serial, block in blocks.items()}
        self._sites_by_byte = _select_sites_by_byte(sites)

    def build_plan(self) -> TerminalTailCascadeEgressPlan:
        block_succs = {
            serial: tuple(block.succs) for serial, block in self._blocks.items()
        }
        largest_before = _largest_cyclic_scc_size(block_succs)
        projected = dict(block_succs)
        rows: list[TerminalTailCascadeEgressRow] = []
        for byte_index in range(7):
            row, projected = self._build_row(byte_index, projected, largest_before)
            rows.append(row)
        return TerminalTailCascadeEgressPlan(
            rows=tuple(rows),
            largest_scc_size_before=largest_before,
            largest_scc_size_after=_largest_cyclic_scc_size(projected),
        )

    def _build_row(
        self,
        byte_index: int,
        projected_succs: Mapping[int, tuple[int, ...]],
        largest_before: int,
    ) -> tuple[TerminalTailCascadeEgressRow, dict[int, tuple[int, ...]]]:
        site = self._sites_by_byte.get(byte_index)
        next_site = self._sites_by_byte.get(byte_index + 1)
        source_block = site.block_serial if site is not None else None
        block = self._blocks.get(source_block) if source_block is not None else None
        intended_target = next_site.block_serial if next_site is not None else None

        if block is None or site is None:
            (
                state_variable,
                state_required_value,
                state_write_block,
                state_write_path,
                state_write_bypassed,
                state_update_verdict,
            ) = _state_update_proof(
                blocks=self._blocks,
                block_succs=projected_succs,
                source_block=source_block,
                continuation=None,
                intended_target=intended_target,
            )
            return (
                TerminalTailCascadeEgressRow(
                    byte_index=byte_index,
                    source_block=source_block,
                    current_continuation_target=None,
                    intended_target=intended_target,
                    early_return_target=None,
                    current_convergence_target=None,
                    state_variable=state_variable,
                    state_required_value=state_required_value,
                    state_write_block=state_write_block,
                    state_write_path=state_write_path,
                    state_write_bypassed=state_write_bypassed,
                    state_update_verdict=state_update_verdict,
                    confidence=0.0,
                    reason=_reason(
                        site=site,
                        block=block,
                        intended_target=intended_target,
                        preserves_early_return=False,
                        removes_from_scc=False,
                    ),
                ),
                dict(projected_succs),
            )

        early_return = _early_return_target(block, site)
        continuation = _current_continuation(block, site, early_return)
        (
            state_variable,
            state_required_value,
            state_write_block,
            state_write_path,
            state_write_bypassed,
            state_update_verdict,
        ) = _state_update_proof(
            blocks=self._blocks,
            block_succs=projected_succs,
            source_block=source_block,
            continuation=continuation,
            intended_target=intended_target,
        )
        preserves_early_return = (
            early_return is None
            or early_return != continuation
            or len(block.succs) == 1
        )
        source_scc_before = _scc_size_for_block(projected_succs, source_block)
        projected_after = dict(projected_succs)
        source_scc_after = source_scc_before
        largest_after = largest_before
        removes_from_scc = False
        if (
            source_block is not None
            and continuation is not None
            and intended_target is not None
            and continuation != intended_target
            and intended_target != source_block
        ):
            projected_after = _mutated_succs(
                projected_succs,
                source_block,
                continuation,
                intended_target,
            )
            source_scc_after = _scc_size_for_block(projected_after, source_block)
            largest_after = _largest_cyclic_scc_size(projected_after)
            removes_from_scc = (
                source_scc_before is not None
                and source_scc_after is not None
                and source_scc_after < source_scc_before
            )
        confidence = min(1.0, max(0.0, site.confidence + (0.12 if removes_from_scc else 0.0)))
        return (
            TerminalTailCascadeEgressRow(
                byte_index=byte_index,
                source_block=source_block,
                current_continuation_target=continuation,
                intended_target=intended_target,
                early_return_target=early_return,
                current_convergence_target=continuation,
                state_variable=state_variable,
                state_required_value=state_required_value,
                state_write_block=state_write_block,
                state_write_path=state_write_path,
                state_write_bypassed=state_write_bypassed,
                state_update_verdict=state_update_verdict,
                confidence=confidence,
                reason=_reason(
                    site=site,
                    block=block,
                    intended_target=intended_target,
                    preserves_early_return=preserves_early_return,
                    removes_from_scc=removes_from_scc,
                ),
                explicit_store=site.explicit_store or block.has_explicit_store,
                preserves_early_return=preserves_early_return,
                removes_from_scc=removes_from_scc,
                source_scc_size_before=source_scc_before,
                source_scc_size_after=source_scc_after,
                largest_scc_size_before=largest_before,
                largest_scc_size_after=largest_after,
            ),
            projected_after,
        )


def format_cascade_egress_plan(plan: TerminalTailCascadeEgressPlan) -> str:
    """Render the planner output as a compact markdown table."""
    lines: list[str] = []
    lines.append("## Terminal tail cascade egress plan")
    lines.append(
        f"- largest cyclic SCC before: {plan.largest_scc_size_before}; "
        f"projected after: {plan.largest_scc_size_after}"
    )
    lines.append("")
    lines.append(
        "| byte | source block | current continuation | intended target | "
        "early return | state requirement | state write | state verdict | "
        "confidence | reason |"
    )
    lines.append("|-|-|-|-|-|-|-|-|-|-|")
    for row in plan.rows:
        source = row.source_block if row.source_block is not None else "?"
        current = (
            row.current_continuation_target
            if row.current_continuation_target is not None
            else "?"
        )
        intended = row.intended_target if row.intended_target is not None else "?"
        early = row.early_return_target if row.early_return_target is not None else "?"
        state_req = (
            f"{row.state_variable}={row.state_required_value}"
            if row.state_variable is not None and row.state_required_value is not None
            else "none"
        )
        state_write = row.state_write_block if row.state_write_block is not None else "?"
        lines.append(
            f"| {row.byte_index} | {source} | {current} | {intended} | "
            f"{early} | {state_req} | {state_write} | "
            f"{row.state_update_verdict} | {row.confidence:.2f} | {row.reason} |"
        )
    return "\n".join(lines)


__all__ = [
    "TerminalByteEmitSite",
    "TerminalTailBlock",
    "TerminalTailCascadeEgressPlan",
    "TerminalTailCascadeEgressPlanner",
    "TerminalTailCascadeEgressRow",
    "format_cascade_egress_plan",
    "select_effective_terminal_tail_entry_block",
    "terminal_byte_emit_site_from_payload",
]
