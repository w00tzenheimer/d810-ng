"""Unit tests for the reaching-definitions dataflow domain.

Tests exercise VarKey, DefSite, meet semantics, and integration with the
generic forward fixpoint engine. No IDA dependency required.
"""
from __future__ import annotations

import pytest

from d810.cfg.lattice import BOTTOM, TOP
from d810.evaluator.hexrays_microcode.forward_dataflow import (
    DefSite,
    ReachingDefEnv,
    VarKey,
    _MAX_DEF_SET_SIZE,
    build_reaching_defs_entry_state,
    reaching_defs_meet,
)
from d810.evaluator.hexrays_microcode.forward_dataflow import (
    run_forward_fixpoint,
)


# ---------------------------------------------------------------------------
# VarKey and DefSite basic properties
# ---------------------------------------------------------------------------


class TestVarKeyFrozenAndHashable:
    """VarKey must be usable as a dict key and set member."""

    def test_hashable_as_dict_key(self) -> None:
        vk = VarKey(kind="reg", identifier=0, size=8)
        d: dict[VarKey, int] = {vk: 42}
        assert d[vk] == 42

    def test_frozen(self) -> None:
        vk = VarKey(kind="reg", identifier=0, size=8)
        with pytest.raises(AttributeError):
            vk.kind = "stkvar"  # type: ignore[misc]

    def test_equality(self) -> None:
        a = VarKey(kind="stkvar", identifier=16, size=4)
        b = VarKey(kind="stkvar", identifier=16, size=4)
        assert a == b
        assert hash(a) == hash(b)

    def test_inequality(self) -> None:
        a = VarKey(kind="reg", identifier=0, size=8)
        b = VarKey(kind="reg", identifier=1, size=8)
        assert a != b

    def test_in_set(self) -> None:
        s = {VarKey("reg", 0, 8), VarKey("reg", 0, 8)}
        assert len(s) == 1


class TestDefSiteFrozen:
    """DefSite must be frozen and hashable."""

    def test_frozen(self) -> None:
        ds = DefSite(block_serial=0, ins_ea=0x1000, opcode=7)
        with pytest.raises(AttributeError):
            ds.block_serial = 1  # type: ignore[misc]

    def test_hashable(self) -> None:
        ds = DefSite(0, 0x1000, 7)
        s = {ds, ds}
        assert len(s) == 1

    def test_optional_opcode(self) -> None:
        ds = DefSite(block_serial=0, ins_ea=0x1000)
        assert ds.opcode is None


# ---------------------------------------------------------------------------
# Meet function tests
# ---------------------------------------------------------------------------


class TestMeetEmptyReturnsEmpty:
    """meet([]) should return an empty environment."""

    def test_empty(self) -> None:
        result = reaching_defs_meet([])
        assert result == {}


class TestMeetSinglePassthrough:
    """meet([env]) should return a copy of env."""

    def test_passthrough(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env: ReachingDefEnv = {vk: frozenset({ds})}
        result = reaching_defs_meet([env])
        assert result == env
        # Must be a separate dict instance
        assert result is not env


class TestMeetUnionDefSets:
    """Two envs with different defs for the same VarKey -> union."""

    def test_union(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds1 = DefSite(0, 0x1000)
        ds2 = DefSite(1, 0x2000)
        env1: ReachingDefEnv = {vk: frozenset({ds1})}
        env2: ReachingDefEnv = {vk: frozenset({ds2})}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] == frozenset({ds1, ds2})

    def test_union_disjoint_keys(self) -> None:
        vk1 = VarKey("reg", 0, 8)
        vk2 = VarKey("stkvar", 16, 4)
        ds1 = DefSite(0, 0x1000)
        ds2 = DefSite(1, 0x2000)
        env1: ReachingDefEnv = {vk1: frozenset({ds1})}
        env2: ReachingDefEnv = {vk2: frozenset({ds2})}
        result = reaching_defs_meet([env1, env2])
        assert result[vk1] == frozenset({ds1})
        assert result[vk2] == frozenset({ds2})


class TestMeetBottomIsIdentity:
    """BOTTOM + frozenset -> frozenset."""

    def test_bottom_left(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env1: ReachingDefEnv = {vk: BOTTOM}
        env2: ReachingDefEnv = {vk: frozenset({ds})}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] == frozenset({ds})

    def test_bottom_right(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env1: ReachingDefEnv = {vk: frozenset({ds})}
        env2: ReachingDefEnv = {vk: BOTTOM}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] == frozenset({ds})

    def test_bottom_missing_key_is_identity(self) -> None:
        """A key present in only one env should survive (BOTTOM is identity)."""
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env1: ReachingDefEnv = {vk: frozenset({ds})}
        env2: ReachingDefEnv = {}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] == frozenset({ds})


class TestMeetTopAbsorbs:
    """TOP + anything -> TOP."""

    def test_top_left(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env1: ReachingDefEnv = {vk: TOP}
        env2: ReachingDefEnv = {vk: frozenset({ds})}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] is TOP

    def test_top_right(self) -> None:
        vk = VarKey("reg", 0, 8)
        ds = DefSite(0, 0x1000)
        env1: ReachingDefEnv = {vk: frozenset({ds})}
        env2: ReachingDefEnv = {vk: TOP}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] is TOP

    def test_top_both(self) -> None:
        vk = VarKey("reg", 0, 8)
        env1: ReachingDefEnv = {vk: TOP}
        env2: ReachingDefEnv = {vk: TOP}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] is TOP


class TestMeetLargeSetCollapsesToTop:
    """Union exceeding _MAX_DEF_SET_SIZE -> TOP."""

    def test_collapse(self) -> None:
        vk = VarKey("reg", 0, 8)
        # Create two sets whose union exceeds the threshold
        half = _MAX_DEF_SET_SIZE // 2 + 1
        defs_a = frozenset(DefSite(i, 0x1000 + i) for i in range(half))
        defs_b = frozenset(
            DefSite(i + half, 0x2000 + i) for i in range(half)
        )
        # Sanity: union would exceed threshold
        assert len(defs_a | defs_b) > _MAX_DEF_SET_SIZE

        env1: ReachingDefEnv = {vk: defs_a}
        env2: ReachingDefEnv = {vk: defs_b}
        result = reaching_defs_meet([env1, env2])
        assert result[vk] is TOP


# ---------------------------------------------------------------------------
# Entry state builder
# ---------------------------------------------------------------------------


class TestBuildEntryState:
    """Entry state maps every VarKey to BOTTOM."""

    def test_entry_state(self) -> None:
        universe = {
            VarKey("reg", 0, 8),
            VarKey("stkvar", 16, 4),
        }
        entry = build_reaching_defs_entry_state(universe)
        assert len(entry) == 2
        for v in entry.values():
            assert v is BOTTOM

    def test_empty_universe(self) -> None:
        entry = build_reaching_defs_entry_state(set())
        assert entry == {}


# ---------------------------------------------------------------------------
# Integration with forward fixpoint engine
# ---------------------------------------------------------------------------


class TestWithForwardFixpoint:
    """Run reaching_defs_meet with a synthetic graph and simple transfer."""

    @staticmethod
    def _build_graph(
        edges: list[tuple[int, int]],
    ) -> tuple[set[int], dict[int, list[int]], dict[int, list[int]]]:
        nodes: set[int] = set()
        pred_map: dict[int, list[int]] = {}
        succ_map: dict[int, list[int]] = {}
        for src, dst in edges:
            nodes.add(src)
            nodes.add(dst)
            succ_map.setdefault(src, []).append(dst)
            pred_map.setdefault(dst, []).append(src)
        for n in nodes:
            pred_map.setdefault(n, [])
            succ_map.setdefault(n, [])
        return nodes, pred_map, succ_map

    def test_diamond_reaching_defs(self) -> None:
        """Diamond graph: 0->{1,2}->3.

        Block 0: DEF vk at ea=0x100
        Block 1: DEF vk at ea=0x200
        Block 2: (no def)
        Block 3: meet -> should see defs from block 1 AND block 0 (via block 2)
        """
        vk = VarKey("reg", 0, 8)

        # Per-block GEN maps
        block_defs: dict[int, DefSite] = {
            0: DefSite(0, 0x100, opcode=1),
            1: DefSite(1, 0x200, opcode=1),
        }

        def transfer(node_id: int, in_state: ReachingDefEnv) -> ReachingDefEnv:
            out = dict(in_state)
            if node_id in block_defs:
                # KILL + GEN
                out[vk] = frozenset({block_defs[node_id]})
            return out

        edges = [(0, 1), (0, 2), (1, 3), (2, 3)]
        nodes, pred_map, succ_map = self._build_graph(edges)

        entry_state: ReachingDefEnv = {vk: BOTTOM}
        bottom: ReachingDefEnv = {vk: BOTTOM}

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state=entry_state,
            bottom=bottom,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=reaching_defs_meet,
            transfer=transfer,
        )

        # Block 0 OUT: {vk: {DefSite(0, 0x100)}}
        assert result.out_states[0][vk] == frozenset({DefSite(0, 0x100, 1)})

        # Block 1 OUT: {vk: {DefSite(1, 0x200)}}  (KILL + GEN)
        assert result.out_states[1][vk] == frozenset({DefSite(1, 0x200, 1)})

        # Block 2 OUT: {vk: {DefSite(0, 0x100)}}  (passthrough from block 0)
        assert result.out_states[2][vk] == frozenset({DefSite(0, 0x100, 1)})

        # Block 3 IN: meet([OUT[1], OUT[2]]) = union of both defs
        expected_in_3 = frozenset({DefSite(0, 0x100, 1), DefSite(1, 0x200, 1)})
        assert result.in_states[3][vk] == expected_in_3

    def test_linear_kill_gen(self) -> None:
        """Linear: 0->1->2. Each block defines the same variable.

        Only the last def should reach the OUT of each block.
        """
        vk = VarKey("stkvar", 16, 4)

        def transfer(node_id: int, in_state: ReachingDefEnv) -> ReachingDefEnv:
            out = dict(in_state)
            # Every block defines vk (KILL + GEN)
            out[vk] = frozenset({DefSite(node_id, 0x1000 + node_id * 0x100)})
            return out

        edges = [(0, 1), (1, 2)]
        nodes, pred_map, succ_map = self._build_graph(edges)

        entry_state: ReachingDefEnv = {vk: BOTTOM}
        bottom: ReachingDefEnv = {vk: BOTTOM}

        result = run_forward_fixpoint(
            nodes=nodes,
            entry_node=0,
            entry_state=entry_state,
            bottom=bottom,
            predecessors_of=lambda n: pred_map[n],
            successors_of=lambda n: succ_map[n],
            meet=reaching_defs_meet,
            transfer=transfer,
        )

        # Each block's OUT should only contain its own def (KILL + GEN)
        assert result.out_states[0][vk] == frozenset({DefSite(0, 0x1000)})
        assert result.out_states[1][vk] == frozenset({DefSite(1, 0x1100)})
        assert result.out_states[2][vk] == frozenset({DefSite(2, 0x1200)})
