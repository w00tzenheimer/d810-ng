"""Backend-neutral semantic-reference label indexing helpers."""
from __future__ import annotations

import re


_STATE_LABEL_RE = re.compile(r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?$")
_RAW_STATE_LABEL_RE = re.compile(r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?$")
_STATE_LABEL_PREFIX_RE = re.compile(
    r"^STATE_([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)
_RAW_STATE_LABEL_PREFIX_RE = re.compile(
    r"^0x([0-9A-Fa-f]{8})(?:(_fallback))?(?:__.+)?$"
)

__all__ = [
    "collect_semantic_entry_by_label",
    "collect_semantic_successors_by_state",
    "normalize_semantic_target_label",
    "semantic_state_value_from_label",
]


def normalize_semantic_target_label(label_text: str | None) -> str | None:
    """Return the canonical ``STATE_XXXXXXXX`` form for a semantic label."""
    text = str(label_text or "").strip()
    if not text:
        return None
    state_match = _STATE_LABEL_PREFIX_RE.match(text)
    if state_match is not None:
        state_hex = state_match.group(1).upper()
        fallback_suffix = "_fallback" if state_match.group(2) else ""
        return f"STATE_{state_hex}{fallback_suffix}"
    raw_match = _RAW_STATE_LABEL_PREFIX_RE.match(text)
    if raw_match is not None:
        state_hex = raw_match.group(1).upper()
        fallback_suffix = "_fallback" if raw_match.group(2) else ""
        return f"STATE_{state_hex}{fallback_suffix}"
    return None


def semantic_state_value_from_label(label_text: str | None) -> int | None:
    """Return the 32-bit state value encoded by a semantic label."""
    normalized = normalize_semantic_target_label(label_text)
    if normalized is None:
        return None
    match = _STATE_LABEL_RE.match(normalized)
    if match is None:
        return None
    return int(match.group(1), 16) & 0xFFFFFFFF


def collect_semantic_entry_by_label(
    semantic_reference_program: object | None,
) -> dict[str, int]:
    """Index semantic-reference nodes by original and canonical label forms."""
    if semantic_reference_program is None:
        return {}
    entries: dict[str, int] = {}
    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        entry_anchor = getattr(node, "entry_anchor", None)
        if not label_text or entry_anchor is None:
            continue
        entry_value = int(entry_anchor)
        entries[label_text] = entry_value
        normalized_label = normalize_semantic_target_label(label_text)
        if normalized_label is not None:
            entries.setdefault(normalized_label, entry_value)
        raw_match = _RAW_STATE_LABEL_RE.match(label_text)
        if raw_match is not None:
            suffix = raw_match.group(2) or ""
            entries[f"STATE_{raw_match.group(1).upper()}{suffix}"] = entry_value
            continue
        state_match = _STATE_LABEL_RE.match(label_text)
        if state_match is not None:
            suffix = state_match.group(2) or ""
            entries[f"0x{state_match.group(1).upper()}{suffix}"] = entry_value
    return entries


def collect_semantic_successors_by_state(
    semantic_reference_program: object | None,
) -> dict[int, tuple[str, ...]]:
    """Index semantic-reference outgoing target labels by source state."""
    if semantic_reference_program is None:
        return {}
    lines = tuple(getattr(semantic_reference_program, "lines", ()) or ())
    by_state: dict[int, list[str]] = {}
    for node in getattr(semantic_reference_program, "nodes", ()) or ():
        label_text = str(getattr(node, "label_text", "") or "")
        match = _STATE_LABEL_PREFIX_RE.match(label_text)
        if match is None:
            match = _RAW_STATE_LABEL_PREFIX_RE.match(label_text)
        if match is None:
            continue
        source_state = int(match.group(1), 16) & 0xFFFFFFFF
        line_start = int(getattr(node, "line_start", 0) or 0)
        line_end = int(getattr(node, "line_end", 0) or 0)
        targets: list[str] = []
        for line in lines:
            line_no = int(getattr(line, "line_no", 0) or 0)
            if line_no < line_start or line_no > line_end:
                continue
            target_label = getattr(line, "target_label", None)
            if target_label is None:
                continue
            targets.append(str(target_label))
        if targets:
            existing = by_state.setdefault(source_state, [])
            for target in targets:
                if target not in existing:
                    existing.append(target)
    return {
        int(source_state) & 0xFFFFFFFF: tuple(targets)
        for source_state, targets in by_state.items()
        if targets
    }
