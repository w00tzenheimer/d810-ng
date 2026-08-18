"""Session-local progress accounting for layered dispatcher recovery."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from enum import Enum
import hashlib

from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherCandidateIdentity,
)
from d810.ir.maturity import IRMaturity


_AttemptKey = tuple[int, IRMaturity, str, DispatcherCandidateIdentity]
_GraphKey = tuple[int, IRMaturity, str]


def _stable_value(value: object) -> object:
    if value is None or isinstance(value, (bool, int, float, str, bytes)):
        return value
    if isinstance(value, Enum):
        return (type(value).__qualname__, value.value)
    if isinstance(value, Mapping):
        return tuple(
            sorted(
                (
                    (_stable_value(key), _stable_value(item))
                    for key, item in value.items()
                ),
                key=repr,
            )
        )
    if isinstance(value, (tuple, list)):
        return tuple(_stable_value(item) for item in value)
    if isinstance(value, (set, frozenset)):
        return tuple(sorted((_stable_value(item) for item in value), key=repr))
    if is_dataclass(value) and not isinstance(value, type):
        return (
            type(value).__qualname__,
            tuple(
                (item.name, _stable_value(getattr(value, item.name)))
                for item in fields(value)
                if item.compare
            ),
        )
    return repr(value)


def flowgraph_content_fingerprint(graph: object) -> str:
    """Hash topology and portable instructions for exact no-progress comparison."""
    blocks = getattr(graph, "blocks")
    content = tuple(
        (
            int(serial),
            int(getattr(block, "start_ea", 0)),
            int(getattr(block, "native_start_ea", 0) or 0),
            int(getattr(block, "block_type", 0)),
            int(getattr(block, "flags", 0)),
            tuple(int(succ) for succ in getattr(block, "succs", ())),
            tuple(int(pred) for pred in getattr(block, "preds", ())),
            _stable_value(getattr(block, "insn_snapshots", ())),
        )
        for serial, block in sorted(blocks.items())
    )
    digest = hashlib.sha256(repr(content).encode("utf-8")).hexdigest()
    return f"flowgraph-content-v1:{digest}"


@dataclass(slots=True)
class DispatcherProgressLedger:
    """Exclude an exact candidate only after repeated no-op attempts.

    The graph fingerprint is part of the attempt key.  A Hex-Rays rewrite or
    optimizer change therefore makes the candidate eligible again instead of
    turning one local stall into a function-wide veto.
    """

    stall_threshold: int = 2
    _no_progress_counts: dict[_AttemptKey, int] = field(default_factory=dict)
    _exhausted_graphs: set[_GraphKey] = field(default_factory=set)

    def __post_init__(self) -> None:
        if self.stall_threshold < 1:
            raise ValueError("stall_threshold must be positive")

    def record_no_progress(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
        identity: DispatcherCandidateIdentity,
    ) -> None:
        key = (
            int(func_ea),
            maturity,
            str(graph_fingerprint),
            identity,
        )
        self._no_progress_counts[key] = self._no_progress_counts.get(key, 0) + 1

    def record_progress(
        self,
        func_ea: int,
        maturity: IRMaturity,
        identity: DispatcherCandidateIdentity,
    ) -> None:
        self._no_progress_counts = {
            key: count
            for key, count in self._no_progress_counts.items()
            if not (
                key[0] == int(func_ea)
                and key[1] is maturity
                and key[3] == identity
            )
        }

    def excluded_identities(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
    ) -> frozenset[DispatcherCandidateIdentity]:
        return frozenset(
            identity
            for (candidate_func, candidate_maturity, fingerprint, identity), count
            in self._no_progress_counts.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and fingerprint == str(graph_fingerprint)
            and count >= self.stall_threshold
        )

    def record_exhausted(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
    ) -> None:
        self._exhausted_graphs.add(
            (int(func_ea), maturity, str(graph_fingerprint))
        )

    def is_exhausted(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
    ) -> bool:
        return (
            int(func_ea),
            maturity,
            str(graph_fingerprint),
        ) in self._exhausted_graphs

    def reset_function(self, func_ea: int) -> None:
        self._no_progress_counts = {
            key: count
            for key, count in self._no_progress_counts.items()
            if key[0] != int(func_ea)
        }
        self._exhausted_graphs = {
            key for key in self._exhausted_graphs if key[0] != int(func_ea)
        }

    def reset_all(self) -> None:
        self._no_progress_counts.clear()
        self._exhausted_graphs.clear()


__all__ = ["DispatcherProgressLedger", "flowgraph_content_fingerprint"]
