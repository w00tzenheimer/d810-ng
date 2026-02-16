"""Edge-count safeguard for deflattening CFG modifications."""
from __future__ import annotations

from d810.core import getLogger

logger = getLogger("D810.unflat.safeguard")

MIN_ABSOLUTE_EDGES = 3
MIN_EDGE_RATIO = 3  # Denominator: require at least 1/3 of case blocks


def should_apply_cfg_modifications(
    num_redirected_edges: int,
    total_case_blocks: int,
    context: str = "",
    min_required_override: int | None = None,
) -> bool:
    """Check if enough edges were redirected to justify CFG modification.

    Prevents destructive partial CFG rewrites by requiring a minimum
    number of resolved transitions before applying modifications.

    Args:
        num_redirected_edges: Number of edges successfully resolved.
        total_case_blocks: Total case/exit blocks in the dispatcher.
        context: Description for log messages.

    Returns:
        True if modifications should proceed, False to skip.
    """
    if min_required_override is not None and int(min_required_override) > 0:
        min_required = int(min_required_override)
    elif total_case_blocks > 0:
        min_required = max(MIN_ABSOLUTE_EDGES, total_case_blocks // MIN_EDGE_RATIO)
    else:
        min_required = MIN_ABSOLUTE_EDGES

    if num_redirected_edges >= min_required:
        return True

    if min_required_override is not None and int(min_required_override) > 0:
        logger.warning(
            "SAFEGUARD%s: Only %d edges redirected but %d required "
            "(case_blocks=%d, override threshold=%d); "
            "skipping CFG reconstruction to avoid breaking function",
            f" [{context}]" if context else "",
            num_redirected_edges,
            min_required,
            total_case_blocks,
            min_required,
        )
    else:
        logger.warning(
            "SAFEGUARD%s: Only %d edges redirected but %d required "
            "(case_blocks=%d, threshold=max(%d, %d/%d)); "
            "skipping CFG reconstruction to avoid breaking function",
            f" [{context}]" if context else "",
            num_redirected_edges,
            min_required,
            total_case_blocks,
            MIN_ABSOLUTE_EDGES,
            total_case_blocks,
            MIN_EDGE_RATIO,
        )
    return False
