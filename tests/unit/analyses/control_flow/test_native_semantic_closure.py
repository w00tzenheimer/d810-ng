from __future__ import annotations

import pytest

from d810.analyses.control_flow import native_semantic_closure as nsc


def _internal_edge_tuples(result):
    assert "proven_internal_edges" in type(result).__dataclass_fields__
    return {
        (edge.source_ea, edge.target_ea, edge.kind)
        for edge in result.proven_internal_edges
    }


def _abstention_tuples(result):
    return {
        (
            abstention.reason,
            abstention.source_block_ea,
            abstention.target_ea,
            abstention.dependency_ea,
        )
        for abstention in result.abstentions
    }


def _boundary_edge_tuples(result):
    return {
        (
            edge.source_ea,
            edge.source_instruction_ea,
            edge.target_ea,
            edge.kind,
            edge.provenance,
        )
        for edge in result.proven_import_boundary_edges
    }


def test_closure_includes_native_cfg_edges_and_merges_overlapping_seed_ranges():
    block = nsc.NativeBlock
    edge = nsc.NativeEdge
    kind = nsc.NativeEdgeKind

    cfg = nsc.NativeCfg(
        {
            0x1000: block(
                0x1000,
                0x1010,
                outgoing_edges=(edge(kind.DIRECT_JUMP, 0x1010),),
            ),
            0x1010: block(
                0x1010,
                0x1020,
                outgoing_edges=(
                    edge(kind.CONDITIONAL_TRUE, 0x1020),
                    edge(kind.CONDITIONAL_FALSE, 0x1030),
                ),
            ),
            0x1020: block(
                0x1020,
                0x1030,
                outgoing_edges=(edge(kind.FALLTHROUGH, 0x1040),),
            ),
            0x1030: block(
                0x1030,
                0x1040,
                outgoing_edges=(
                    edge(kind.CALL, 0x9000),
                    edge(kind.FALLTHROUGH, 0x1040),
                ),
            ),
            0x1040: block(
                0x1040,
                0x1050,
                terminal=nsc.NativeTerminalKind.RETURN,
            ),
            0x9000: block(
                0x9000,
                0x9010,
                terminal=nsc.NativeTerminalKind.RETURN,
            ),
        }
    )
    first_seed = nsc.ResolverProvenHandlerEntry(0x1000, "table row 4")
    overlapping_seed = nsc.ResolverProvenHandlerEntry(0x1040, "table row 7")

    result = nsc.plan_native_semantic_closure(
        cfg,
        (first_seed, overlapping_seed),
    )

    assert result.included_block_eas == (0x1000, 0x1010, 0x1020, 0x1030, 0x1040)
    assert result.native_ranges == (nsc.NativeRange(0x1000, 0x1050),)
    assert _internal_edge_tuples(result) == {
        (0x1000, 0x1010, kind.DIRECT_JUMP),
        (0x1010, 0x1020, kind.CONDITIONAL_TRUE),
        (0x1010, 0x1030, kind.CONDITIONAL_FALSE),
        (0x1020, 0x1040, kind.FALLTHROUGH),
        (0x1030, 0x1040, kind.FALLTHROUGH),
    }
    assert result.abstentions == ()
    assert result.seed_provenance == (first_seed, overlapping_seed)


def test_closure_exports_only_resolver_proven_indirect_targets_as_ports():
    block = nsc.NativeBlock
    edge = nsc.NativeEdge
    kind = nsc.NativeEdgeKind

    cfg = nsc.NativeCfg(
        {
            0x2000: block(
                0x2000,
                0x2010,
                outgoing_edges=(
                    edge(
                        kind.INDIRECT,
                        0x2010,
                        resolver_proven=True,
                        provenance="resolver table row 2",
                    ),
                    edge(kind.INDIRECT, 0x2F00),
                ),
            ),
            0x2010: block(
                0x2010,
                0x2020,
                terminal=nsc.NativeTerminalKind.RETURN,
            ),
            0x2F00: block(
                0x2F00,
                0x2F10,
                terminal=nsc.NativeTerminalKind.RETURN,
            ),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (
            nsc.ResolverProvenHandlerEntry(0x2000, "resolver site 1"),
            nsc.ResolverProvenHandlerEntry(0x2010, "resolved handler"),
        ),
    )

    assert result.included_block_eas == (0x2000, 0x2010)
    assert _internal_edge_tuples(result) == set()
    assert _boundary_edge_tuples(result) == {
        (0x2000, None, 0x2010, kind.INDIRECT, "resolver table row 2"),
    }
    assert _abstention_tuples(result) == {
        (
            nsc.ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET,
            0x2000,
            0x2F00,
            None,
        ),
    }


@pytest.mark.parametrize(
    "terminal_kind",
    (
        "RETURN",
        "TAIL_CALL",
        "STOP",
    ),
)
def test_terminal_blocks_are_hard_cfg_cut_points(terminal_kind: str):
    block = nsc.NativeBlock
    edge = nsc.NativeEdge
    kind = nsc.NativeEdgeKind

    cfg = nsc.NativeCfg(
        {
            0x4000: block(
                0x4000,
                0x4010,
                outgoing_edges=(edge(kind.DIRECT_JUMP, 0x4010),),
                terminal=nsc.NativeTerminalKind[terminal_kind],
            ),
            0x4010: block(0x4010, 0x4020),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(0x4000, "terminal seed"),),
    )

    assert result.included_block_eas == (0x4000,)
    assert _internal_edge_tuples(result) == set()


def test_closure_separates_internal_edges_from_import_boundary_edges():
    block = nsc.NativeBlock
    edge = nsc.NativeEdge
    kind = nsc.NativeEdgeKind

    cfg = nsc.NativeCfg(
        {
            0x5000: block(
                0x5000,
                0x5010,
                outgoing_edges=(edge(kind.DIRECT_JUMP, 0x5010),),
            ),
            0x5010: block(0x5010, 0x5020),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(0x5000, "internal edge seed"),),
    )

    fields = nsc.NativeSemanticClosure.__dataclass_fields__
    assert "proven_internal_edges" in fields
    assert (
        "proven_import_boundary_edges"
        in fields
    )
    assert "proven_boundary_edges" not in fields
    assert _internal_edge_tuples(result) == {
        (0x5000, 0x5010, kind.DIRECT_JUMP),
    }
    assert result.proven_import_boundary_edges == ()


def test_closure_exports_resolver_proven_stop_edge_to_live_import_boundary():
    source_ea = 0x5100
    resolver_ea = 0x510E
    live_target_ea = 0x9000
    cfg = nsc.NativeCfg(
        {
            source_ea: nsc.NativeBlock(
                source_ea,
                0x5110,
                outgoing_edges=(
                    nsc.NativeEdge(
                        nsc.NativeEdgeKind.INDIRECT,
                        live_target_ea,
                        resolver_proven=True,
                        provenance="static_fixpoint",
                        source_instruction_ea=resolver_ea,
                    ),
                ),
                terminal=nsc.NativeTerminalKind.STOP,
            ),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(source_ea, "handler seed"),),
        import_boundary_target_eas=frozenset({live_target_ea}),
    )

    assert result.included_block_eas == (source_ea,)
    assert result.proven_internal_edges == ()
    assert _boundary_edge_tuples(result) == {
        (
            source_ea,
            resolver_ea,
            live_target_ea,
            nsc.NativeEdgeKind.INDIRECT,
            "static_fixpoint",
        )
    }
    assert result.abstentions == ()


@pytest.mark.parametrize(
    "edge_kind",
    ("DIRECT_JUMP", "FALLTHROUGH"),
)
def test_closure_exports_native_edge_to_allowlisted_live_boundary(
    edge_kind: str,
):
    source_ea = 0x5200
    live_target_ea = 0xA000
    kind = nsc.NativeEdgeKind[edge_kind]
    cfg = nsc.NativeCfg(
        {
            source_ea: nsc.NativeBlock(
                source_ea,
                0x5210,
                outgoing_edges=(
                    nsc.NativeEdge(
                        kind,
                        live_target_ea,
                        provenance="native_cfg",
                    ),
                ),
            ),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(source_ea, "handler seed"),),
        import_boundary_target_eas=frozenset({live_target_ea}),
    )

    assert _boundary_edge_tuples(result) == {
        (source_ea, None, live_target_ea, kind, "native_cfg")
    }
    assert result.abstentions == ()


def test_closure_abstains_on_unproven_indirect_boundary():
    source_ea = 0x5300
    live_target_ea = 0xB000
    cfg = nsc.NativeCfg(
        {
            source_ea: nsc.NativeBlock(
                source_ea,
                0x5310,
                outgoing_edges=(
                    nsc.NativeEdge(
                        nsc.NativeEdgeKind.INDIRECT,
                        live_target_ea,
                        source_instruction_ea=0x530E,
                    ),
                ),
                terminal=nsc.NativeTerminalKind.STOP,
            ),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(source_ea, "handler seed"),),
        import_boundary_target_eas=frozenset({live_target_ea}),
    )

    assert result.proven_import_boundary_edges == ()
    assert _abstention_tuples(result) == {
        (
            nsc.ClosureAbstentionReason.UNPROVEN_INDIRECT_TARGET,
            source_ea,
            live_target_ea,
            None,
        )
    }


def test_closure_merges_overlapping_and_adjacent_native_ranges():
    block = nsc.NativeBlock
    edge = nsc.NativeEdge
    kind = nsc.NativeEdgeKind

    cfg = nsc.NativeCfg(
        {
            0x6000: block(
                0x6000,
                0x6020,
                outgoing_edges=(edge(kind.DIRECT_JUMP, 0x6010),),
            ),
            0x6010: block(
                0x6010,
                0x6030,
                outgoing_edges=(edge(kind.FALLTHROUGH, 0x6030),),
            ),
            0x6030: block(0x6030, 0x6040),
        }
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(0x6000, "range seed"),),
    )

    assert result.native_ranges == (nsc.NativeRange(0x6000, 0x6040),)


def test_closure_adds_only_unique_resolver_proven_backward_dependencies():
    block = nsc.NativeBlock

    cfg = nsc.NativeCfg(
        {
            0x3000: block(0x3000, 0x3010, dependency_eas=(0xA0, 0xB0, 0xC0)),
            0x3100: block(0x3100, 0x3110, dependency_eas=(0xD0,)),
            0x3120: block(0x3120, 0x3130),
            0x3130: block(0x3130, 0x3140),
            0x3140: block(0x3140, 0x3150),
        }
    )
    definitions = (
        nsc.ResolverProvenDependencyDefinition(0xA0, 0x3100, "state write A"),
        nsc.ResolverProvenDependencyDefinition(0xC0, 0x3120, "state write C1"),
        nsc.ResolverProvenDependencyDefinition(0xC0, 0x3130, "state write C2"),
        nsc.ResolverProvenDependencyDefinition(0xD0, 0x3140, "predicate D"),
    )

    result = nsc.plan_native_semantic_closure(
        cfg,
        (nsc.ResolverProvenHandlerEntry(0x3000, "resolver site 3"),),
        definitions,
    )

    assert result.included_block_eas == (0x3000, 0x3100, 0x3140)
    assert result.native_ranges == (
        nsc.NativeRange(0x3000, 0x3010),
        nsc.NativeRange(0x3100, 0x3110),
        nsc.NativeRange(0x3140, 0x3150),
    )
    assert _abstention_tuples(result) == {
        (
            nsc.ClosureAbstentionReason.UNRESOLVED_DEPENDENCY,
            0x3000,
            None,
            0xB0,
        ),
        (
            nsc.ClosureAbstentionReason.AMBIGUOUS_DEPENDENCY,
            0x3000,
            None,
            0xC0,
        ),
    }


def test_generation_ranges_enclose_fragments_joined_by_direct_jump():
    closure = nsc.NativeSemanticClosure(
        included_block_eas=(0x1000, 0x2000),
        native_ranges=(
            nsc.NativeRange(0x1000, 0x1010),
            nsc.NativeRange(0x2000, 0x2010),
        ),
        proven_internal_edges=(
            nsc.ProvenInternalEdge(
                0x1000,
                0x2000,
                nsc.NativeEdgeKind.DIRECT_JUMP,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )

    assert nsc.plan_native_generation_ranges(closure) == (
        nsc.NativeRange(0x1000, 0x2010),
    )


def test_generation_ranges_leave_conditional_only_fragments_disjoint():
    closure = nsc.NativeSemanticClosure(
        included_block_eas=(0x1000, 0x2000),
        native_ranges=(
            nsc.NativeRange(0x1000, 0x1010),
            nsc.NativeRange(0x2000, 0x2010),
        ),
        proven_internal_edges=(
            nsc.ProvenInternalEdge(
                0x1000,
                0x2000,
                nsc.NativeEdgeKind.CONDITIONAL_TRUE,
            ),
        ),
        abstentions=(),
        seed_provenance=(),
    )

    assert nsc.plan_native_generation_ranges(closure) == closure.native_ranges


def test_generation_ranges_prioritize_required_detached_entry_root():
    closure = nsc.NativeSemanticClosure(
        included_block_eas=(0x1000, 0x1020),
        native_ranges=(nsc.NativeRange(0x1000, 0x1030),),
        proven_internal_edges=(),
        abstentions=(),
        seed_provenance=(),
    )

    assert nsc.plan_native_generation_ranges(
        closure,
        required_entry_eas=(0x1020,),
    ) == (
        nsc.NativeRange(0x1020, 0x1030),
        nsc.NativeRange(0x1000, 0x1020),
    )
