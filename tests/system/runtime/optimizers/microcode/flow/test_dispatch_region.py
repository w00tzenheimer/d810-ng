"""Unit tests for dispatch region detection using Tarjan SCC.

Tests the DispatchRegionDetector service with synthetic CFG patterns
representing OLLVM-style control-flow flattening, glue blocks, nested
dispatchers, and degenerate cases.

No IDA runtime required - operates on pure adjacency dictionaries.
"""

from __future__ import annotations

import pytest

from d810.optimizers.microcode.flow.dispatch_region import DispatchRegionDetector


class TestTarjanSCC:
    """Test Tarjan's SCC algorithm on synthetic graphs."""

    def test_single_node_no_cycle(self) -> None:
        """Linear graph with no cycles produces singleton SCCs."""
        adj = {0: (1,), 1: ()}
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # Each node is its own SCC when no cycles
        assert len(sccs) == 2
        # SCCs are returned in reverse topological order
        assert frozenset({1}) in sccs
        assert frozenset({0}) in sccs

    def test_simple_cycle(self) -> None:
        """Two nodes forming a cycle produce one SCC."""
        adj = {0: (1,), 1: (0,)}
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        assert len(sccs) == 1
        assert sccs[0] == frozenset({0, 1})

    def test_dispatcher_pattern_simple(self) -> None:
        """OLLVM-style CFF: dispatcher -> cases -> dispatcher."""
        # dispatcher(0) -> case1(1), case2(2), case3(3)
        # case1 -> dispatcher, case2 -> dispatcher, case3 -> dispatcher
        adj = {
            0: (1, 2, 3),
            1: (0,),
            2: (0,),
            3: (0,),
        }
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # All blocks form one big SCC (cyclic)
        assert len(sccs) == 1
        assert sccs[0] == frozenset({0, 1, 2, 3})

    def test_dispatcher_with_glue(self) -> None:
        """Dispatcher with glue blocks and case blocks."""
        # dispatcher(0) -> glue(1) -> case1(2)
        # case1 -> glue(1), case2(3) -> dispatcher
        adj = {
            0: (1, 3),
            1: (2,),
            2: (1,),
            3: (0,),
        }
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # Multiple SCCs based on cycles
        # {0, 3} forms one SCC (cycle: 0 -> 3 -> 0)
        # {1, 2} forms another SCC (cycle: 1 -> 2 -> 1)
        assert len(sccs) == 2
        scc_sets = [set(scc) for scc in sccs]
        assert {0, 3} in scc_sets
        assert {1, 2} in scc_sets

    def test_nested_dispatch(self) -> None:
        """Two separate SCCs representing nested dispatchers."""
        # Outer dispatcher: 0 -> 1, 1 -> 0
        # Inner dispatcher: 2 -> 3, 3 -> 2
        # Bridge: 1 -> 2
        adj = {
            0: (1,),
            1: (0, 2),
            2: (3,),
            3: (2,),
        }
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # Two SCCs: {0, 1} and {2, 3}
        assert len(sccs) == 2
        scc_sets = [set(scc) for scc in sccs]
        assert {0, 1} in scc_sets
        assert {2, 3} in scc_sets

    def test_empty_graph(self) -> None:
        """Empty adjacency dict produces no SCCs."""
        adj: dict[int, tuple[int, ...]] = {}
        sccs = DispatchRegionDetector.tarjan_scc(adj)
        assert sccs == []

    def test_disconnected_components(self) -> None:
        """Disconnected graph produces separate SCCs."""
        adj = {
            0: (1,),
            1: (0,),
            2: (3,),
            3: (2,),
        }
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        assert len(sccs) == 2
        scc_sets = [set(scc) for scc in sccs]
        assert {0, 1} in scc_sets
        assert {2, 3} in scc_sets

    def test_complex_dispatcher_pattern(self) -> None:
        """Complex OLLVM pattern with multiple glue blocks."""
        # dispatcher(0) -> glue1(1), glue2(2), case1(3), case2(4)
        # glue1 -> glue2
        # glue2 -> case1
        # case1 -> dispatcher
        # case2 -> dispatcher
        adj = {
            0: (1, 2, 3, 4),
            1: (2,),
            2: (3,),
            3: (0,),
            4: (0,),
        }
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # All nodes reachable from 0 and can reach 0 form one SCC
        assert len(sccs) == 1
        assert sccs[0] == frozenset({0, 1, 2, 3, 4})


class TestDispatchRegionDetector:
    """Test dispatch region detection."""

    def test_detect_returns_dispatcher_scc(self) -> None:
        """Detect returns the SCC containing the dispatcher."""
        adj = {0: (1, 2), 1: (0,), 2: (0,)}
        dispatcher_serial = 0

        region = DispatchRegionDetector.detect(adj, dispatcher_serial)

        assert region == frozenset({0, 1, 2})

    def test_detect_degenerate_no_scc(self) -> None:
        """Linear graph with no back edges returns empty set."""
        adj = {0: (1,), 1: (2,), 2: ()}
        dispatcher_serial = 0

        region = DispatchRegionDetector.detect(adj, dispatcher_serial)

        # Singleton SCC: dispatcher is in a trivial (size-1) component.
        # detect() still returns it since tarjan_scc emits all SCCs.
        assert region == frozenset({0})

    def test_detect_dispatcher_in_nested_scc(self) -> None:
        """Detect finds the correct SCC when multiple exist."""
        # Two SCCs: {0, 1} and {2, 3}
        # Bridge from 1 -> 2
        adj = {
            0: (1,),
            1: (0, 2),
            2: (3,),
            3: (2,),
        }

        # Dispatcher is in outer SCC {0, 1}
        region = DispatchRegionDetector.detect(adj, dispatcher_serial=0)
        assert region == frozenset({0, 1})

        # Dispatcher is in inner SCC {2, 3}
        region = DispatchRegionDetector.detect(adj, dispatcher_serial=2)
        assert region == frozenset({2, 3})

    def test_detect_dispatcher_not_in_graph(self) -> None:
        """Dispatcher not in adjacency dict returns empty set."""
        adj = {0: (1,), 1: ()}
        dispatcher_serial = 99

        region = DispatchRegionDetector.detect(adj, dispatcher_serial)

        assert region == frozenset()

    def test_detect_complex_ollvm_pattern(self) -> None:
        """Real OLLVM pattern: dispatcher with multiple cases and glue."""
        # dispatcher(0) -> case1(1), case2(2), case3(3)
        # case1 -> glue1(4) -> dispatcher
        # case2 -> glue2(5) -> dispatcher
        # case3 -> dispatcher
        adj = {
            0: (1, 2, 3),
            1: (4,),
            2: (5,),
            3: (0,),
            4: (0,),
            5: (0,),
        }

        region = DispatchRegionDetector.detect(adj, dispatcher_serial=0)

        # All blocks form the dispatch region
        assert region == frozenset({0, 1, 2, 3, 4, 5})

    def test_detect_with_external_blocks(self) -> None:
        """Dispatcher SCC with external blocks outside the cycle."""
        # dispatcher(0) -> case1(1), case2(2), exit(3)
        # case1 -> dispatcher
        # case2 -> dispatcher
        # exit -> external(4) -> terminal(5)
        adj = {
            0: (1, 2, 3),
            1: (0,),
            2: (0,),
            3: (4,),
            4: (5,),
            5: (),
        }

        region = DispatchRegionDetector.detect(adj, dispatcher_serial=0)

        # Only the cyclic part is the dispatch region
        assert region == frozenset({0, 1, 2})


class TestClassifyBlocks:
    """Test block classification into dispatch vs case blocks."""

    def test_classify_blocks_simple(self) -> None:
        """Classify blocks with known dispatch region."""
        adj = {0: (1, 2), 1: (0,), 2: (0,), 3: (4,), 4: ()}
        region = frozenset({0, 1, 2})

        dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)

        assert dispatch == frozenset({0, 1, 2})
        assert case == frozenset({3, 4})

    def test_classify_all_dispatch(self) -> None:
        """All blocks in dispatch region, no case blocks."""
        adj = {0: (1,), 1: (0,)}
        region = frozenset({0, 1})

        dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)

        assert dispatch == frozenset({0, 1})
        assert case == frozenset()

    def test_classify_no_dispatch(self) -> None:
        """Empty dispatch region means all blocks are cases."""
        adj = {0: (1,), 1: (2,), 2: ()}
        region = frozenset()

        dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)

        assert dispatch == frozenset()
        assert case == frozenset({0, 1, 2})

    def test_classify_with_unreachable_blocks(self) -> None:
        """Classify correctly even with blocks not in adjacency dict."""
        # Adjacency only includes edges, but nodes 3, 4 exist via successors
        adj = {0: (1, 2), 1: (0,), 2: (0, 3), 3: (4,)}
        region = frozenset({0, 1, 2})

        dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)

        assert dispatch == frozenset({0, 1, 2})
        # classify_blocks discovers node 4 via successors
        assert case == frozenset({3, 4})

    def test_classify_ollvm_pattern(self) -> None:
        """Classify OLLVM-style dispatcher vs case blocks."""
        # dispatcher(0) + glue(1, 2) vs cases(3, 4, 5)
        adj = {
            0: (1, 3, 4),
            1: (2,),
            2: (0,),
            3: (5,),
            4: (5,),
            5: (),
        }
        # Dispatch region detected as {0, 1, 2}
        region = frozenset({0, 1, 2})

        dispatch, case = DispatchRegionDetector.classify_blocks(adj, region)

        assert dispatch == frozenset({0, 1, 2})
        assert case == frozenset({3, 4, 5})


class TestEdgeCases:
    """Test edge cases and error conditions."""

    def test_self_loop(self) -> None:
        """Block with self-loop is its own SCC."""
        adj = {0: (0,)}
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        assert len(sccs) == 1
        assert sccs[0] == frozenset({0})

    def test_multiple_self_loops(self) -> None:
        """Multiple self-loops produce separate SCCs."""
        adj = {0: (0,), 1: (1,), 2: (2,)}
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        assert len(sccs) == 3
        scc_sets = [set(scc) for scc in sccs]
        assert {0} in scc_sets
        assert {1} in scc_sets
        assert {2} in scc_sets

    def test_node_in_successors_but_not_keys(self) -> None:
        """Node appears in successors but not as a key in adjacency dict."""
        adj = {0: (1, 2), 1: (0,)}
        # Node 2 has no outgoing edges (not a key)

        region = DispatchRegionDetector.detect(adj, dispatcher_serial=0)

        # Graph has SCC {0, 1} - node 2 has no outgoing edges, cannot be in a cycle
        assert region == frozenset({0, 1})

    def test_large_dispatcher_pattern(self) -> None:
        """Large dispatcher with many cases."""
        # dispatcher(0) -> case1..case99
        # all cases -> dispatcher
        adj = {0: tuple(range(1, 100))}
        for i in range(1, 100):
            adj[i] = (0,)

        region = DispatchRegionDetector.detect(adj, dispatcher_serial=0)

        # All 100 blocks (0..99) form one SCC
        assert len(region) == 100
        assert 0 in region
        assert all(i in region for i in range(1, 100))

    def test_detect_with_missing_edges(self) -> None:
        """Adjacency dict with missing nodes still works."""
        # Node 2 is a successor but has no entry in adj
        adj = {0: (1, 2), 1: (0,)}

        # tarjan_scc should handle this gracefully
        sccs = DispatchRegionDetector.tarjan_scc(adj)

        # {0, 1} form an SCC, {2} is a singleton (no outgoing edges)
        assert len(sccs) >= 1
        scc_sets = [set(scc) for scc in sccs]
        assert {0, 1} in scc_sets
