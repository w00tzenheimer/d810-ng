"""Session-local progress accounting for layered dispatcher recovery."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib

from d810.analyses.control_flow.dispatcher_resolution import (
    DispatcherCandidateIdentity,
)
from d810.ir.maturity import IRMaturity


_AttemptKey = tuple[int, IRMaturity, str, DispatcherCandidateIdentity]
_PreflightFailureKey = tuple[int, IRMaturity, DispatcherCandidateIdentity, str]
_CandidateKey = tuple[int, IRMaturity, DispatcherCandidateIdentity]
_GraphKey = tuple[int, IRMaturity, str]
_MaturityKey = tuple[int, IRMaturity]


def flowgraph_content_fingerprint(graph: object) -> str:
    """Hash the topology epoch used for candidate progress accounting.

    Instruction optimizers may rewrite unrelated handler expressions between
    optblock callbacks without changing whether a dispatcher candidate is
    actionable.  Hashing every instruction turns that ordinary churn into a
    fresh recovery opportunity and defeats the no-progress bound on large
    functions.  Dispatcher fallback is reopened when block identity, type, or
    edges change; tail rendering and block flags are intentionally excluded.
    """
    blocks = getattr(graph, "blocks")
    content = tuple(
        (
            int(serial),
            int(getattr(block, "start_ea", 0)),
            int(getattr(block, "native_start_ea", 0) or 0),
            int(getattr(block, "block_type", 0)),
            tuple(int(succ) for succ in getattr(block, "succs", ())),
            tuple(int(pred) for pred in getattr(block, "preds", ())),
        )
        for serial, block in sorted(blocks.items())
    )
    digest = hashlib.sha256(repr(content).encode("utf-8")).hexdigest()
    return f"flowgraph-topology-epoch-v1:{digest}"


@dataclass(slots=True)
class DispatcherProgressLedger:
    """Exclude a stalled candidate only after repeated no-op attempts.

    Ordinary no-progress attempts remain graph-scoped: a Hex-Rays rewrite or
    optimizer change therefore makes the candidate eligible again.  Clean
    no-ops additionally use a bounded distinct-fingerprint fence, while
    preflight failures use their stable failure fingerprint so repeated
    rejection cannot evade the fence through graph churn.
    """

    stall_threshold: int = 2
    clean_noop_graph_threshold: int = 3
    _no_progress_counts: dict[_AttemptKey, int] = field(default_factory=dict)
    _preflight_failure_counts: dict[_PreflightFailureKey, int] = field(
        default_factory=dict
    )
    _clean_noop_graphs: dict[_CandidateKey, set[str]] = field(default_factory=dict)
    _exhausted_graphs: set[_GraphKey] = field(default_factory=set)
    _stable_preflight_exhausted: set[_MaturityKey] = field(default_factory=set)
    _cross_graph_clean_noop_exhausted: set[_MaturityKey] = field(
        default_factory=set
    )

    def __post_init__(self) -> None:
        if self.stall_threshold < 1:
            raise ValueError("stall_threshold must be positive")
        if self.clean_noop_graph_threshold < 1:
            raise ValueError("clean_noop_graph_threshold must be positive")

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

    def record_clean_noop(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
        identity: DispatcherCandidateIdentity,
    ) -> None:
        """Record a no-op and fence it after bounded graph revision churn.

        A clean no-op means recovery selected a stable candidate but published
        no mutation and raised no preflight failure.  The exact-graph counter
        still provides the original two-attempt fence.  The separate bounded
        fingerprint set handles Hex-Rays repeatedly relifting the same
        candidate with unrelated instruction changes; repeated observations of
        one fingerprint do not consume the cross-graph budget.
        """
        graph_fingerprint = str(graph_fingerprint)
        self.record_no_progress(func_ea, maturity, graph_fingerprint, identity)
        key = (int(func_ea), maturity, identity)
        fingerprints = self._clean_noop_graphs.setdefault(key, set())
        if len(fingerprints) < self.clean_noop_graph_threshold:
            fingerprints.add(graph_fingerprint)

    def record_preflight_failure(
        self,
        func_ea: int,
        maturity: IRMaturity,
        identity: DispatcherCandidateIdentity,
        failure_fingerprint: str,
    ) -> None:
        """Fence a stable clean rejection independently of graph churn."""
        key = (
            int(func_ea),
            maturity,
            identity,
            str(failure_fingerprint),
        )
        self._preflight_failure_counts[key] = (
            self._preflight_failure_counts.get(key, 0) + 1
        )

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
        self._preflight_failure_counts = {
            key: count
            for key, count in self._preflight_failure_counts.items()
            if not (
                key[0] == int(func_ea)
                and key[1] is maturity
                and key[2] == identity
            )
        }
        self._clean_noop_graphs.pop((int(func_ea), maturity, identity), None)
        self._stable_preflight_exhausted.discard((int(func_ea), maturity))
        self._cross_graph_clean_noop_exhausted.discard((int(func_ea), maturity))

    def excluded_identities(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
    ) -> frozenset[DispatcherCandidateIdentity]:
        excluded = {
            identity
            for (candidate_func, candidate_maturity, fingerprint, identity), count
            in self._no_progress_counts.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and fingerprint == str(graph_fingerprint)
            and count >= self.stall_threshold
        }
        excluded.update(
            identity
            for (candidate_func, candidate_maturity, identity, _failure), count
            in self._preflight_failure_counts.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and count >= self.stall_threshold
        )
        excluded.update(
            identity
            for (candidate_func, candidate_maturity, identity), fingerprints
            in self._clean_noop_graphs.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and len(fingerprints) >= self.clean_noop_graph_threshold
        )
        return frozenset(excluded)

    def all_excluded_by_cross_graph_clean_noop(
        self,
        func_ea: int,
        maturity: IRMaturity,
        identities: frozenset[DispatcherCandidateIdentity],
    ) -> bool:
        """Return whether every filtered candidate hit the clean-noop fence."""
        if not identities:
            return False
        return identities <= {
            identity
            for (candidate_func, candidate_maturity, identity), fingerprints
            in self._clean_noop_graphs.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and len(fingerprints) >= self.clean_noop_graph_threshold
        }

    def all_excluded_by_stable_preflight_failure(
        self,
        func_ea: int,
        maturity: IRMaturity,
        identities: frozenset[DispatcherCandidateIdentity],
    ) -> bool:
        """Return whether every filtered candidate has a stable clean fence.

        A function/maturity can be considered exhausted across graph churn only
        when filtered recovery has no candidate left and every candidate it
        filtered was independently fenced by the same stable failure policy.
        Exact-graph no-progress exclusions deliberately do not qualify.
        """
        if not identities:
            return False
        stable_excluded = {
            identity
            for (candidate_func, candidate_maturity, identity, _failure), count
            in self._preflight_failure_counts.items()
            if candidate_func == int(func_ea)
            and candidate_maturity is maturity
            and count >= self.stall_threshold
        }
        return identities <= stable_excluded

    def record_exhausted(
        self,
        func_ea: int,
        maturity: IRMaturity,
        graph_fingerprint: str,
        *,
        stable_preflight_failure: bool = False,
        cross_graph_clean_noop: bool = False,
    ) -> None:
        if stable_preflight_failure:
            self._stable_preflight_exhausted.add((int(func_ea), maturity))
        if cross_graph_clean_noop:
            self._cross_graph_clean_noop_exhausted.add((int(func_ea), maturity))
        if not stable_preflight_failure and not cross_graph_clean_noop:
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
            (int(func_ea), maturity) in self._stable_preflight_exhausted
            or (int(func_ea), maturity) in self._cross_graph_clean_noop_exhausted
            or (
                int(func_ea),
                maturity,
                str(graph_fingerprint),
            ) in self._exhausted_graphs
        )

    def is_maturity_exhausted(self, func_ea: int, maturity: IRMaturity) -> bool:
        """Return whether a graph-independent fence exhausted this maturity.

        This graph-independent query lets the live callback exit before it
        rebuilds another portable graph snapshot.  Exact-graph exhaustion is
        intentionally omitted because a changed graph may make that candidate
        eligible again.
        """
        return (
            (int(func_ea), maturity) in self._stable_preflight_exhausted
            or (int(func_ea), maturity) in self._cross_graph_clean_noop_exhausted
        )

    def reset_function(self, func_ea: int) -> None:
        self._no_progress_counts = {
            key: count
            for key, count in self._no_progress_counts.items()
            if key[0] != int(func_ea)
        }
        self._preflight_failure_counts = {
            key: count
            for key, count in self._preflight_failure_counts.items()
            if key[0] != int(func_ea)
        }
        self._clean_noop_graphs = {
            key: fingerprints
            for key, fingerprints in self._clean_noop_graphs.items()
            if key[0] != int(func_ea)
        }
        self._exhausted_graphs = {
            key for key in self._exhausted_graphs if key[0] != int(func_ea)
        }
        self._stable_preflight_exhausted = {
            key for key in self._stable_preflight_exhausted if key[0] != int(func_ea)
        }
        self._cross_graph_clean_noop_exhausted = {
            key
            for key in self._cross_graph_clean_noop_exhausted
            if key[0] != int(func_ea)
        }

    def reset_all(self) -> None:
        self._no_progress_counts.clear()
        self._preflight_failure_counts.clear()
        self._clean_noop_graphs.clear()
        self._exhausted_graphs.clear()
        self._stable_preflight_exhausted.clear()
        self._cross_graph_clean_noop_exhausted.clear()


__all__ = ["DispatcherProgressLedger", "flowgraph_content_fingerprint"]
