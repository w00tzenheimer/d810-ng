"""Fail-closed statistics adapter for the pinned Egglog 13.2.0 runtime.

Egglog exposes e-graph cardinalities only through ``EGraph._serialize``.  This
module is the sole private-API boundary: callers get counts only when both the
runtime version and the complete serialized shape match the audited contract.
"""

from __future__ import annotations

import importlib.metadata
import json
from collections.abc import Mapping

from d810.core.typing import Any


SUPPORTED_EGGLOG_VERSION = "13.2.0"


def _installed_egglog_version() -> str | None:
    try:
        return importlib.metadata.version("egglog")
    except importlib.metadata.PackageNotFoundError:
        return None


def read_egraph_statistics(
    egraph: Any,
    *,
    egglog_version: str | None = None,
) -> tuple[int, int] | None:
    """Return exact ``(eclasses, enodes)`` counts, or fail closed."""

    version = _installed_egglog_version() if egglog_version is None else egglog_version
    if version != SUPPORTED_EGGLOG_VERSION:
        return None
    try:
        serialized = egraph._serialize()
        if type(serialized.truncated_functions) is not list:
            return None
        if type(serialized.discarded_functions) is not list:
            return None
        if serialized.truncated_functions or serialized.discarded_functions:
            return None
        payload = json.loads(serialized.to_json())
    except Exception:
        return None
    if type(payload) is not dict:
        return None
    nodes = payload.get("nodes")
    class_data = payload.get("class_data")
    root_eclasses = payload.get("root_eclasses")
    if type(nodes) is not dict or type(class_data) is not dict:
        return None
    if type(root_eclasses) is not list:
        return None
    for node in nodes.values():
        if type(node) is not dict or type(node.get("eclass")) is not str:
            return None
        if node["eclass"] not in class_data:
            return None
    if any(type(name) is not str for name in class_data):
        return None
    return (len(class_data), len(nodes))


def read_rule_firing_count(report: Any) -> int | None:
    """Return exact aggregate ground-rewrite matches from a run report."""

    matches = getattr(report, "num_matches_per_rule", None)
    if not isinstance(matches, Mapping):
        return None
    values = tuple(matches.values())
    if any(type(value) is not int or value < 0 for value in values):
        return None
    return sum(values)


def release_egraph_on_owner_thread(
    egraph: Any,
    *,
    egglog_version: str | None = None,
) -> bool:
    """Detach Egglog's thread-affine native graph before callback return.

    Egglog 13.2.0 has no public close API, yet its native ``EGraph`` binding is
    intentionally unsendable.  A Hex-Rays callback must therefore release the
    private state on its creating thread rather than leave Python finalization
    to an arbitrary teardown thread.  Any shape or version drift fails closed.
    """

    version = _installed_egglog_version() if egglog_version is None else egglog_version
    if version != SUPPORTED_EGGLOG_VERSION:
        return False
    try:
        state = egraph._state
        state_stack = egraph._state_stack
        token_stack = egraph._token_stack
        if state is None or not hasattr(state, "egraph"):
            return False
        if type(state_stack) is not list or type(token_stack) is not list:
            return False
        state_stack.clear()
        token_stack.clear()
        egraph._state = None
        del state
    except Exception:
        return False
    return True


__all__ = [
    "SUPPORTED_EGGLOG_VERSION",
    "release_egraph_on_owner_thread",
    "read_egraph_statistics",
    "read_rule_firing_count",
]
