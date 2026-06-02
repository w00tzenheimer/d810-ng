"""Dispatch region detection using Tarjan's SCC algorithm.

This module provides a clean service API for identifying dispatch regions in
control-flow flattened code. The dispatch region is the Strongly Connected
Component (SCC) containing the dispatcher entry block.

Key insight from cadecff integration plan:
    The SCC containing the dispatcher entry block defines the dispatch region.
    Blocks in the SCC are dispatch/glue blocks; blocks outside are case blocks.

Usage:
    adj = {0: (1, 2), 1: (0,), 2: (0,)}
    dispatcher_serial = 0
    region = DispatchRegionDetector.detect(adj, dispatcher_serial)
    # region = frozenset({0, 1, 2})

    dispatch_blocks, case_blocks = DispatchRegionDetector.classify_blocks(adj, region)
"""

from __future__ import annotations

from d810.ir.directed_graph import tarjan_scc as _canonical_tarjan_scc

__all__ = ["DispatchRegionDetector"]


class DispatchRegionDetector:
    """Detect dispatch regions using Tarjan's SCC algorithm.

    Given a CFG (as an adjacency dict) and a candidate dispatcher serial,
    identifies all blocks belonging to the dispatch region (the SCC
    containing the dispatcher).
    """

    @staticmethod
    def detect(adj: dict[int, tuple[int, ...]], dispatcher_serial: int) -> frozenset[int]:
        """Return the set of block serials in the dispatch region.

        The dispatch region is the Strongly Connected Component containing
        the dispatcher_serial. Blocks in this SCC are dispatcher/glue blocks;
        blocks outside are case blocks (useful blocks).

        Parameters
        ----------
        adj : dict mapping serial -> tuple of successor serials
        dispatcher_serial : the known/suspected dispatcher block serial

        Returns
        -------
        frozenset of block serials in the dispatch SCC. Empty if dispatcher
        is not in any SCC (degenerate case).

        Examples
        --------
        >>> adj = {0: (1, 2), 1: (0,), 2: (0,)}
        >>> DispatchRegionDetector.detect(adj, 0)
        frozenset({0, 1, 2})

        >>> adj = {0: (1,), 1: (2,), 2: ()}
        >>> DispatchRegionDetector.detect(adj, 0)
        frozenset({0})
        """
        if dispatcher_serial not in adj:
            return frozenset()

        sccs = DispatchRegionDetector.tarjan_scc(adj)

        for scc in sccs:
            if dispatcher_serial in scc:
                return scc

        return frozenset()

    @staticmethod
    def tarjan_scc(adj: dict[int, tuple[int, ...]]) -> list[frozenset[int]]:
        """Compute all SCCs using Tarjan's algorithm.

        Returns list of frozensets, one per SCC, ordered by reverse
        topological order (standard Tarjan output).

        Parameters
        ----------
        adj : dict mapping serial -> tuple of successor serials

        Returns
        -------
        list of frozensets, one per SCC

        Notes
        -----
        This is a pure implementation extracted from analysis_stats.py.
        It operates on adjacency dicts with no IDA dependencies.

        References
        ----------
        Tarjan, R. (1972). "Depth-first search and linear graph algorithms."
        SIAM Journal on Computing.

        Examples
        --------
        >>> adj = {0: (1,), 1: (0,)}
        >>> DispatchRegionDetector.tarjan_scc(adj)
        [frozenset({0, 1})]

        >>> adj = {0: (1,), 1: (2,), 2: ()}
        >>> DispatchRegionDetector.tarjan_scc(adj)
        [frozenset({2}), frozenset({1}), frozenset({0})]
        """
        # Delegates to the canonical lowest-layer implementation
        # (``d810.ir.directed_graph.tarjan_scc``) — same contract
        # (``list[frozenset]``, reverse-topological order). Kept as a static
        # method for the existing ``DispatchRegionDetector.tarjan_scc`` API.
        return _canonical_tarjan_scc(adj)

    @staticmethod
    def classify_blocks(
        adj: dict[int, tuple[int, ...]],
        dispatch_region: frozenset[int],
    ) -> tuple[frozenset[int], frozenset[int]]:
        """Classify blocks as dispatch (in SCC) or case (outside SCC).

        Returns (dispatch_blocks, case_blocks).

        Parameters
        ----------
        adj : dict mapping serial -> tuple of successor serials
        dispatch_region : the SCC containing the dispatcher

        Returns
        -------
        tuple of (dispatch_blocks, case_blocks)

        Examples
        --------
        >>> adj = {0: (1, 2), 1: (0,), 2: (0,), 3: (4,), 4: ()}
        >>> region = frozenset({0, 1, 2})
        >>> dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)
        >>> dispatch
        frozenset({0, 1, 2})
        >>> case
        frozenset({3, 4})
        """
        all_nodes = set(adj.keys())
        for succs in adj.values():
            all_nodes.update(succs)

        dispatch_blocks = dispatch_region
        case_blocks = frozenset(all_nodes - dispatch_blocks)

        return dispatch_blocks, case_blocks
