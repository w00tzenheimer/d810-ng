"""Unit tests for edit simulator (no IDA dependency)."""

import pytest

from d810.cfg.contracts.contract import CfgContract
from d810.transforms.edit_simulator import (
    SimulatedEdit,
    SimulationResult,
    graph_modifications_to_simulated_edits,
    patch_plan_to_simulated_edits,
    project_cumulative_state,
    project_post_state,
    simulate_edits,
)
from d810.analyses.control_flow.graph_checks import prove_terminal_sink
from d810.cfg.flowgraph import (
    BlockKind,
    BlockSnapshot,
    FlowGraph,
    InsnKind,
    InsnSnapshot,
)
from d810.transforms.graph_modification import (
    ConvertToGoto,
    CreateConditionalRedirect,
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringKind,
    DirectTerminalLoweringSite,
    DuplicateBlock,
    EdgeRedirectViaPredSplit,
    InsertBlock,
    PrivateTerminalSuffixGroup,
    RedirectGoto,
    RemoveEdge,
)
from d810.transforms.plan import compile_patch_plan


def _block(
    serial: int, succs: tuple[int, ...], preds: tuple[int, ...]
) -> BlockSnapshot:
    return BlockSnapshot(
        serial=serial,
        block_type=1 if succs else 0,
        succs=succs,
        preds=preds,
        flags=0,
        start_ea=0,
        insn_snapshots=(),
    )


class TestSimulateEdits:
    def test_goto_redirect(self):
        """Single edge replacement via goto_redirect."""
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)
        ]
        sim = simulate_edits(adj, edits)
        assert isinstance(sim, SimulationResult)
        assert sim.adj[0] == [2]
        assert sim.adj[1] == [2]  # unchanged

    def test_conditional_redirect(self):
        """One of two edges replaced via conditional_redirect."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(
                kind="conditional_redirect", source=0, old_target=2, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [1, 3]

    def test_convert_to_goto(self):
        """Both edges become single target via convert_to_goto."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(kind="convert_to_goto", source=0, old_target=1, new_target=3)
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [3]

    def test_no_mutation(self):
        """Original adj unchanged after simulate."""
        adj = {0: [1], 1: [2], 2: []}
        original_copy = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2)
        ]
        simulate_edits(adj, edits)
        assert adj == original_copy

    def test_chained_edits(self):
        """Two edits applied sequentially."""
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [
            SimulatedEdit(kind="goto_redirect", source=0, old_target=1, new_target=2),
            SimulatedEdit(kind="goto_redirect", source=1, old_target=2, new_target=3),
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0] == [2]
        assert sim.adj[1] == [3]

    def test_edge_split_redirect_no_via_pred(self):
        """edge_split_redirect without via_pred uses conservative fallback (append)."""
        adj = {0: [1, 2], 1: [], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect", source=0, old_target=1, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert 3 in sim.adj[0]
        # Original successors preserved, new_target appended
        assert 1 in sim.adj[0]
        assert len(sim.created_clones) == 0

    def test_edge_split_redirect_no_via_pred_dedup(self):
        """edge_split_redirect fallback does not duplicate existing target."""
        adj = {0: [1, 3], 1: [], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect", source=0, old_target=1, new_target=3
            )
        ]
        sim = simulate_edits(adj, edits)
        assert sim.adj[0].count(3) == 1  # no duplicate

    def test_edge_split_with_clone(self):
        """Edge split creates virtual clone node."""
        # Original: 0->1->2, via_pred=0
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        sim = simulate_edits(adj, edits)
        # Clone node created (serial 3 = max(2)+1)
        clone = max(sim.adj.keys())
        assert clone > 2  # new node
        assert sim.adj[clone] == [5]  # clone -> new_target
        assert clone in sim.adj[0]  # via_pred rewired to clone
        assert sim.adj[1] == [2]  # original source unchanged
        assert clone in sim.created_clones

    def test_edge_split_clone_via_pred_partial_rewire(self):
        """Edge split only rewires the source edge in via_pred, not others."""
        # via_pred 0 has two successors: [1, 3]
        adj = {0: [1, 3], 1: [2], 2: [], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=1,
                old_target=2,
                new_target=5,
                via_pred=0,
            )
        ]
        sim = simulate_edits(adj, edits)
        clone = max(sim.adj.keys())
        # via_pred[0] should have [clone, 3] — only source=1 replaced
        assert clone in sim.adj[0]
        assert 3 in sim.adj[0]
        assert 1 not in sim.adj[0]

    def test_edge_split_clone_cycle_detection(self):
        """Edge split clone that creates cycle is detectable."""
        # 0(disp)->1(handler)->2(exit)->3(stop, nsucc=0)
        # Edge split: src=2, via_pred=1, old=3, new=1 (back to handler!)
        adj = {0: [1], 1: [2], 2: [3], 3: []}
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=2,
                old_target=3,
                new_target=1,
                via_pred=1,
            )
        ]
        sim = simulate_edits(adj, edits)
        clone = next(iter(sim.created_clones))
        # Clone -> 1 (handler), creating cycle
        assert sim.adj[clone] == [1]
        # detect_terminal_cycles should find this
        from d810.analyses.control_flow.graph_checks import detect_terminal_cycles

        cycle_result = detect_terminal_cycles(
            sim.adj, terminal_exits={clone}, handler_entries={1}, dispatcher=0
        )
        assert not cycle_result.passed

    def test_edge_split_clone_detected_as_cycle_seed(self):
        """Clone node from edge-split must be a cycle seed for detect_terminal_cycles.

        Repro of blk[219]->blk[180] bug:
        - blk[219] is terminal (nsucc=0)
        - Edge split on blk[45] via_pred=122 creates clone (e.g. 220)
        - Clone 220 -> 180 (handler entry)
        - detect_terminal_cycles from {219} misses it
        - detect_terminal_cycles from {219, 220} catches it
        """
        adj = {
            0: [45],  # dispatcher
            45: [2],  # source block
            122: [45],  # via_pred -> source
            2: [219],  # path to terminal
            219: [],  # terminal (nsucc=0)
            180: [181],  # handler entry
            181: [],  # handler body
        }
        edits = [
            SimulatedEdit(
                kind="edge_split_redirect",
                source=45,
                old_target=2,
                new_target=180,
                via_pred=122,
            )
        ]
        sim_result = simulate_edits(adj, edits)

        # Clone was created
        assert len(sim_result.created_clones) == 1
        clone = next(iter(sim_result.created_clones))

        # Clone -> 180 (handler entry)
        assert sim_result.adj[clone] == [180]

        # Without clone as seed: MISS
        from d810.analyses.control_flow.graph_checks import detect_terminal_cycles

        miss = detect_terminal_cycles(sim_result.adj, {219}, {180}, dispatcher=0)
        assert miss.passed  # wrongly passes - 219 has no succs

        # With clone as seed: CATCH
        catch = detect_terminal_cycles(
            sim_result.adj, {219, clone}, {180}, dispatcher=0
        )
        assert not catch.passed
        assert any(c.reentry_target == 180 for c in catch.cycles)

    def test_create_conditional_redirect_creates_virtual_conditional_clone(self):
        adj = {0: [1], 1: [2], 2: []}
        edits = [
            SimulatedEdit(
                kind="create_conditional_redirect",
                source=0,
                old_target=1,
                new_target=10,
                fallthrough_target=11,
            )
        ]
        sim = simulate_edits(adj, edits)
        assert len(sim.created_clones) == 2
        clone = min(sim.created_clones)
        nop_blk = max(sim.created_clones)
        assert sim.adj[0] == [clone]
        assert sim.adj[clone] == [nop_blk, 10]
        assert sim.adj[nop_blk] == [11]

    def test_duplicate_block_creates_clone_and_redirects_predecessor(self):
        cfg = FlowGraph(
            blocks={
                9: _block(9, (10,), ()),
                10: _block(10, (11,), (9,)),
                11: _block(11, (), (10,)),
            },
            entry_serial=9,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=10,
                    target_block=11,
                    pred_serial=9,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(),
            patch_plan_to_simulated_edits(patch_plan),
        )

        assert sim.adj[9] == [11]
        assert sim.adj[10] == [12]
        assert sim.adj[11] == [12]
        assert sim.adj[12] == []

    def test_duplicate_block_private_target_split_redirects_1way_predecessor(self):
        cfg = FlowGraph(
            blocks={
                9: _block(9, (10,), ()),
                10: _block(10, (11,), (9,)),
                11: _block(11, (), (10,)),
            },
            entry_serial=9,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DuplicateBlock(
                    source_block=10,
                    target_block=None,
                    pred_serial=9,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(),
            patch_plan_to_simulated_edits(patch_plan),
        )

        assert sim.adj[9] == [11]
        assert sim.adj[10] == [12]
        assert sim.adj[11] == [12]
        assert sim.adj[12] == []

    def test_duplicate_block_preserves_conditional_shape(self):
        edits = [
            SimulatedEdit(
                kind="duplicate_block",
                source=10,
                old_target=-1,
                new_target=None,
                via_pred=9,
                source_successors=(12, 11),
                conditional_target=12,
                fallthrough_target=11,
                created_serial=14,
                secondary_created_serial=15,
                stop_serial_before=14,
                stop_serial_after=16,
            )
        ]

        sim = simulate_edits(
            {9: [10], 10: [11, 12], 11: [], 12: [], 14: []},
            edits,
        )

        assert sim.adj[9] == [14]
        assert sim.adj[10] == [11, 12]
        assert sim.adj[14] == [15, 12]
        assert sim.adj[15] == [11]
        assert sim.adj[16] == []


class TestProjectPostState:
    def test_project_post_state_normalizes_one_way_redirect_tail_to_goto(self):
        cfg = FlowGraph(
            blocks={
                1: BlockSnapshot(
                    serial=1,
                    block_type=3,
                    succs=(2,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=4,
                ),
                2: BlockSnapshot(
                    serial=2,
                    block_type=2,
                    succs=(),
                    preds=(1,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                    tail_opcode=0,
                ),
            },
            entry_serial=1,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=9)],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[1].succs == (9,)
        assert projected.blocks[1].tail_kind == InsnKind.GOTO

    def test_project_post_state_rebuilds_created_block_preds(self):
        cfg = FlowGraph(
            blocks={
                0: BlockSnapshot(
                    serial=0,
                    block_type=3,
                    succs=(1,),
                    preds=(),
                    flags=0,
                    start_ea=0x1000,
                    insn_snapshots=(),
                    tail_opcode=2,
                ),
                1: BlockSnapshot(
                    serial=1,
                    block_type=3,
                    succs=(2,),
                    preds=(0,),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=2,
                ),
                2: BlockSnapshot(
                    serial=2,
                    block_type=2,
                    succs=(),
                    preds=(1,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                    tail_opcode=0,
                ),
            },
            entry_serial=0,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=2,
                    instructions=(),
                )
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[1].succs == (2,)
        assert projected.blocks[2].preds == (1,)
        assert projected.blocks[2].succs == (3,)
        assert projected.blocks[3].preds == (2,)

    def test_project_post_state_recomputes_existing_semantics_after_remove_edge(self):
        cfg = FlowGraph(
            blocks={
                10: BlockSnapshot(
                    serial=10,
                    block_type=4,
                    succs=(11, 12),
                    preds=(),
                    flags=0,
                    start_ea=0x1010,
                    insn_snapshots=(),
                    tail_opcode=7,
                    kind=BlockKind.TWO_WAY,
                    tail_kind=InsnKind.COND_JUMP,
                ),
                11: BlockSnapshot(
                    serial=11,
                    block_type=2,
                    succs=(),
                    preds=(10,),
                    flags=0,
                    start_ea=0x1020,
                    insn_snapshots=(),
                ),
                12: BlockSnapshot(
                    serial=12,
                    block_type=2,
                    succs=(),
                    preds=(10,),
                    flags=0,
                    start_ea=0x1030,
                    insn_snapshots=(),
                ),
            },
            entry_serial=10,
            func_ea=0x1000,
        )

        patch_plan = compile_patch_plan([RemoveEdge(from_serial=10, to_serial=12)], cfg)

        projected = project_post_state(cfg, patch_plan)

        assert projected.blocks[10].succs == (11,)
        assert projected.blocks[10].kind == BlockKind.ONE_WAY
        assert projected.blocks[10].tail_kind == InsnKind.GOTO
        assert CfgContract().check_projected(cfg, patch_plan) == []


class TestModificationProjection:
    def test_graph_modifications_to_simulated_edits(self):
        mods = [
            RedirectGoto(from_serial=1, old_target=2, new_target=3),
            ConvertToGoto(block_serial=4, goto_target=5),
            EdgeRedirectViaPredSplit(
                src_block=6, old_target=7, new_target=8, via_pred=9
            ),
            InsertBlock(
                pred_serial=14,
                succ_serial=15,
                instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
            ),
            RemoveEdge(from_serial=16, to_serial=17),
            CreateConditionalRedirect(
                source_block=10,
                ref_block=11,
                conditional_target=12,
                fallthrough_target=13,
            ),
        ]
        edits = graph_modifications_to_simulated_edits(mods)
        assert [e.kind for e in edits] == [
            "goto_redirect",
            "convert_to_goto",
            "edge_split_redirect",
            "insert_block",
            "remove_edge",
            "create_conditional_redirect",
        ]

    def test_patch_plan_edge_split_relocates_stop(self):
        cfg = FlowGraph(
            blocks={
                122: _block(122, (45,), ()),
                45: _block(45, (2,), (122,)),
                2: _block(2, (219,), (45,)),
                180: _block(180, (), ()),
                219: _block(219, (), (2,)),
            },
            entry_serial=122,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=45,
                    old_target=2,
                    new_target=180,
                    via_pred=122,
                    rule_priority=550,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[122] == [219]
        assert sim.adj[45] == [2]
        assert sim.adj[2] == [220]
        assert sim.adj[219] == [180]
        assert sim.adj[220] == []

    def test_edge_split_and_insert_block_can_share_source(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(
                    BlockKind.TWO_WAY
                    if len(succs) == 2
                    else BlockKind.ONE_WAY
                    if len(succs) == 1
                    else BlockKind.ZERO_WAY
                ),
                tail_kind=(
                    InsnKind.COND_JUMP
                    if len(succs) == 2
                    else InsnKind.GOTO
                    if len(succs) == 1
                    else InsnKind.NOP
                ),
            )

        cfg = FlowGraph(
            blocks={
                54: semantic_block(54, (), (98,)),
                98: semantic_block(98, (54, 100), ()),
                99: semantic_block(99, (100,), ()),
                100: semantic_block(100, (2,), (98, 99)),
                2: semantic_block(2, (), (100,)),
                75: semantic_block(75, (), ()),
                180: semantic_block(180, (), ()),
                219: semantic_block(219, (), ()),
            },
            entry_serial=98,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                EdgeRedirectViaPredSplit(
                    src_block=100,
                    old_target=2,
                    new_target=180,
                    via_pred=98,
                    rule_priority=550,
                ),
                InsertBlock(
                    pred_serial=100,
                    succ_serial=75,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                    old_target_serial=2,
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        edge_split_serial = patch_plan.steps[0].assigned_serial
        insert_serial = patch_plan.steps[1].assigned_serial

        assert projected.blocks[98].succs == (54, edge_split_serial)
        assert projected.blocks[100].succs == (insert_serial,)
        assert projected.blocks[edge_split_serial].succs == (180,)
        assert projected.blocks[insert_serial].succs == (75,)
        assert CfgContract().check_projected(cfg, patch_plan) == []

    def test_direct_terminal_lowering_and_private_suffix_can_share_return_family(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(
                    BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY
                ),
                tail_kind=(InsnKind.GOTO if len(succs) == 1 else InsnKind.NOP),
            )

        cfg = FlowGraph(
            blocks={
                26: semantic_block(26, (27,), ()),
                27: semantic_block(27, (218,), (26,)),
                206: semantic_block(206, (207,), ()),
                207: semantic_block(207, (218,), (206,)),
                218: semantic_block(218, (219,), (27, 207)),
                219: semantic_block(219, (), (218,)),
            },
            entry_serial=26,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DirectTerminalLoweringGroup(
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                    sites=(
                        DirectTerminalLoweringSite(
                            anchor_serial=207,
                            kind=DirectTerminalLoweringKind.CLONE_MATERIALIZER,
                            materializer_serials=(27, 218),
                        ),
                    ),
                ),
                PrivateTerminalSuffixGroup(
                    anchors=(27,),
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        dtl_step = patch_plan.steps[0]
        pts_step = patch_plan.steps[1]
        dtl_clones = dtl_step.per_site_clone_assigned_serials[207]
        pts_clones = pts_step.per_anchor_clone_assigned_serials[0]

        assert projected.blocks[207].succs == (dtl_clones[0],)
        assert projected.blocks[dtl_clones[0]].succs == (dtl_clones[1],)
        assert projected.blocks[dtl_clones[1]].succs == ()
        assert projected.blocks[27].succs == (pts_clones[0],)
        assert CfgContract().check_projected(cfg, patch_plan) == []

    def test_return_const_direct_terminal_lowering_rewrites_anchor_without_clone(self):
        def semantic_block(
            serial: int,
            succs: tuple[int, ...],
            preds: tuple[int, ...],
        ) -> BlockSnapshot:
            return BlockSnapshot(
                serial=serial,
                block_type=1 if succs else 0,
                succs=succs,
                preds=preds,
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                kind=(
                    BlockKind.ONE_WAY if len(succs) == 1 else BlockKind.ZERO_WAY
                ),
                tail_kind=(InsnKind.GOTO if len(succs) == 1 else InsnKind.NOP),
            )

        cfg = FlowGraph(
            blocks={
                26: semantic_block(26, (27,), ()),
                27: semantic_block(27, (218,), (26,)),
                218: semantic_block(218, (219,), (27,)),
                219: semantic_block(219, (), (218,)),
            },
            entry_serial=26,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                DirectTerminalLoweringGroup(
                    shared_entry_serial=218,
                    return_block_serial=219,
                    suffix_serials=(218, 219),
                    sites=(
                        DirectTerminalLoweringSite(
                            anchor_serial=27,
                            kind=DirectTerminalLoweringKind.RETURN_CONST,
                            const_value=0x5644FD01B1049C4B,
                        ),
                    ),
                ),
            ],
            cfg,
        )

        projected = project_post_state(cfg, patch_plan)
        dtl_step = patch_plan.steps[0]

        assert dtl_step.per_site_clone_assigned_serials[27] == ()
        assert projected.blocks[27].succs == (219,)
        assert len(projected.blocks) == len(cfg.blocks)
        assert CfgContract().check_projected(cfg, patch_plan) == []

    def test_patch_plan_insert_block_updates_sink_reasoning(self):
        cfg = FlowGraph(
            blocks={
                1: _block(1, (2,), ()),
                2: _block(2, (), (1,)),
            },
            entry_serial=1,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=2,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[1] == [2]
        assert sim.adj[2] == [3]
        assert sim.adj[3] == []
        assert prove_terminal_sink(2, sim.adj, exits={3}, forbidden=set()).ok

    def test_patch_plan_insert_block_replaces_explicit_old_target(self):
        cfg = FlowGraph(
            blocks={
                1: _block(1, (2,), ()),
                2: _block(2, (), (1,)),
                4: _block(4, (), ()),
            },
            entry_serial=1,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                InsertBlock(
                    pred_serial=1,
                    succ_serial=4,
                    instructions=(InsnSnapshot(opcode=0x90, ea=0x1000, operands=()),),
                    old_target_serial=2,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[1] == [4]
        assert sim.adj[2] == []
        assert sim.adj[4] == [5]
        assert sim.adj[5] == []

    def test_patch_plan_conditional_redirect_relocates_stop(self):
        cfg = FlowGraph(
            blocks={
                0: _block(0, (1,), ()),
                1: _block(1, (2, 5), (0,)),
                2: _block(2, (), (1,)),
                5: _block(5, (), (1,)),
            },
            entry_serial=0,
            func_ea=0,
        )

        patch_plan = compile_patch_plan(
            [
                CreateConditionalRedirect(
                    source_block=0,
                    ref_block=1,
                    conditional_target=5,
                    fallthrough_target=2,
                )
            ],
            cfg,
        )

        sim = simulate_edits(
            cfg.as_adjacency_dict(), patch_plan_to_simulated_edits(patch_plan)
        )

        assert sim.adj[0] == [5]
        assert sim.adj[5] == [6, 7]
        assert sim.adj[6] == [2]
        assert sim.adj[7] == []

    def test_remove_edge_is_simulated(self):
        sim = simulate_edits(
            {1: [2, 3], 2: [], 3: []},
            graph_modifications_to_simulated_edits(
                [RemoveEdge(from_serial=1, to_serial=3)]
            ),
        )

        assert sim.adj[1] == [2]


class TestProjectCumulativeState:
    """Tests for project_cumulative_state -- cumulative CFG projection."""

    def _make_cfg(
        self, adj: dict[int, list[int]], entry: int = 0
    ) -> FlowGraph:
        """Build a FlowGraph from an adjacency dict."""
        blocks: dict[int, BlockSnapshot] = {}
        preds_map: dict[int, list[int]] = {s: [] for s in adj}
        for s, succs in adj.items():
            for succ in succs:
                if succ in preds_map:
                    preds_map[succ].append(s)
        for serial, succs in adj.items():
            blocks[serial] = BlockSnapshot(
                serial=serial,
                block_type=3 if len(succs) == 1 else (4 if len(succs) == 2 else 0),
                succs=tuple(succs),
                preds=tuple(preds_map.get(serial, ())),
                flags=0,
                start_ea=0,
                insn_snapshots=(),
                tail_opcode=2 if succs else 0,
            )
        return FlowGraph(blocks=blocks, entry_serial=entry, func_ea=0)

    def test_cumulative_is_same_as_project_post_state(self):
        """project_cumulative_state produces the same result as project_post_state
        when called with the same inputs."""
        cfg = self._make_cfg({0: [1], 1: [2], 2: []})
        modifications = [RedirectGoto(from_serial=0, old_target=1, new_target=2)]
        plan = compile_patch_plan(modifications, cfg)

        result_standard = project_post_state(cfg, plan)
        result_cumulative = project_cumulative_state(cfg, plan)

        assert result_standard.as_adjacency_dict() == result_cumulative.as_adjacency_dict()
        assert result_standard.entry_serial == result_cumulative.entry_serial

    def test_cumulative_chaining_two_plans(self):
        """Two sequential plans applied cumulatively produce correct topology."""
        cfg = self._make_cfg({0: [1], 1: [2], 2: [3], 3: []})

        plan1 = compile_patch_plan(
            [RedirectGoto(from_serial=0, old_target=1, new_target=2)], cfg,
        )
        cumulative1 = project_cumulative_state(cfg, plan1)

        adj1 = cumulative1.as_adjacency_dict()
        assert adj1[0] == [2]
        assert adj1[1] == [2]

        plan2 = compile_patch_plan(
            [RedirectGoto(from_serial=1, old_target=2, new_target=3)], cumulative1,
        )
        cumulative2 = project_cumulative_state(cumulative1, plan2)

        adj2 = cumulative2.as_adjacency_dict()
        assert adj2[0] == [2]
        assert adj2[1] == [3]
        assert adj2[2] == [3]

    def test_cumulative_preserves_metadata(self):
        """Cumulative projection preserves base CFG metadata."""
        cfg = self._make_cfg({0: [1], 1: []})
        cfg = FlowGraph(
            blocks=cfg.blocks,
            entry_serial=cfg.entry_serial,
            func_ea=cfg.func_ea,
            metadata={"custom_key": "value"},
        )
        plan = compile_patch_plan([], cfg)
        result = project_cumulative_state(cfg, plan)
        assert result.metadata.get("custom_key") == "value"
        assert result.metadata.get("projected_from_patch_plan") is True
