"""Return-frontier site derivation from reconstruction evidence."""
from __future__ import annotations

import hashlib

from d810.cfg.flow.return_frontier import ReturnSite

__all__ = [
    "compute_legacy_return_site_guard_hash",
    "compute_transition_row_guard_hash",
    "legacy_handler_path_return_sites",
    "transition_report_return_sites",
]


def compute_transition_row_guard_hash(row: object) -> str:
    """Compute a stable guard hash for a transition-report row."""
    digest = hashlib.sha256()
    digest.update(str(getattr(row, "handler_serial", "")).encode())
    state_const = getattr(row, "state_const", None)
    if state_const is not None:
        digest.update(str(state_const).encode())
    for block_serial in getattr(row, "chain_preview", ()) or ():
        digest.update(str(block_serial).encode())
    return digest.hexdigest()[:16]


def _transition_kind_name(row: object) -> str:
    kind = getattr(row, "kind", None)
    return str(getattr(kind, "name", "") or kind or "")


def _state_tag_for_row(row: object) -> str:
    state_const = getattr(row, "state_const", None)
    if state_const is not None:
        return f"{int(state_const):08x}"
    state_range_lo = getattr(row, "state_range_lo", None)
    state_range_hi = getattr(row, "state_range_hi", None)
    if state_range_lo is not None and state_range_hi is not None:
        return f"range_{int(state_range_lo):08x}_{int(state_range_hi):08x}"
    return "unknown"


def _normalise_site_id_prefix(site_id_prefix: str) -> str:
    prefix = str(site_id_prefix).strip("_")
    return prefix or "return"


def transition_report_return_sites(
    report: object,
    *,
    site_id_prefix: str = "return",
) -> tuple[ReturnSite, ...]:
    """Build one ReturnSite per EXIT handler in a transition report.

    The derivation is intentionally strict: a row must be classified EXIT and
    its path must confirm exit-block reachability.  Sites are keyed by handler
    origin and state identity, not by the shared physical return block.

    ``site_id_prefix`` names the consuming strategy family.  The generic recon
    helper defaults to a neutral prefix; family adapters can pass a stable
    family-specific prefix when compatibility matters.
    """
    prefix = _normalise_site_id_prefix(site_id_prefix)
    sites: list[ReturnSite] = []
    seen_ids: set[str] = set()

    for row in getattr(report, "rows", ()) or ():
        if _transition_kind_name(row) != "EXIT":
            continue
        path = row.path
        if not path.reaches_exit_block:
            continue

        handler_serial = int(getattr(row, "handler_serial"))
        site_id = f"{prefix}_handler_{handler_serial}_state_{_state_tag_for_row(row)}"
        if site_id in seen_ids:
            continue
        seen_ids.add(site_id)

        metadata = {
            "dispatcher_entry": getattr(report, "dispatcher_entry_serial", None),
            "state_const": getattr(row, "state_const", None),
            "state_range_lo": getattr(row, "state_range_lo", None),
            "state_range_hi": getattr(row, "state_range_hi", None),
            "transition_kind": _transition_kind_name(row),
            "transition_label": getattr(row, "transition_label", None),
            "path_chain": list(path.chain),
            "path_back_edge": path.back_edge,
            "path_reaches_exit_block": path.reaches_exit_block,
            "path_classified_exit": path.classified_exit,
            "path_unresolved": path.unresolved,
        }
        sites.append(
            ReturnSite(
                site_id=site_id,
                origin_block=handler_serial,
                expected_terminal_kind="return",
                metadata=metadata,
            )
        )

    sites.sort(key=lambda site: (site.origin_block, site.site_id))
    return tuple(sites)


def compute_legacy_return_site_guard_hash(entry_serial: int, path: object) -> str:
    """Compute the legacy handler-path guard hash."""
    parts = [str(entry_serial), str(getattr(path, "exit_block"))]
    for write in getattr(path, "state_writes", ()) or ():
        parts.append(str(write))
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def legacy_handler_path_return_sites(
    handler_paths: dict[int, list[object]],
    *,
    site_id_prefix: str = "return",
) -> tuple[ReturnSite, ...]:
    """Extract legacy return sites from handler path analysis results."""
    prefix = _normalise_site_id_prefix(site_id_prefix)
    sites: list[ReturnSite] = []
    seen_blocks: set[int] = set()

    for entry_serial, paths in handler_paths.items():
        for index, path in enumerate(paths):
            if getattr(path, "final_state", None) is not None:
                continue
            exit_block = int(getattr(path, "exit_block"))
            if exit_block in seen_blocks:
                continue
            seen_blocks.add(exit_block)
            sites.append(
                ReturnSite(
                    site_id=f"{prefix}_ret_{entry_serial}_{exit_block}",
                    origin_block=exit_block,
                    guard_hash=compute_legacy_return_site_guard_hash(entry_serial, path),
                    expected_terminal_kind="return",
                    provenance=f"handler_{entry_serial}_path_{index}",
                )
            )

    return tuple(sites)
