from __future__ import annotations

from pathlib import Path

from d810.backends.llvm import (
    LlvmLowerBackBlock,
    LlvmLowerBackFunction,
    LlvmLowerBackInstruction,
    LlvmLowerBackStatus,
    LlvmLowerBackTerminator,
    LlvmLowerBackTerminatorKind,
    LlvmLowerBackUnsupportedKind,
    LlvmPhiIncoming,
    LlvmPhiNode,
    LlvmValueRef,
    plan_lower_back,
)


_FIXTURE = (
    Path(__file__).parents[4]
    / "tools"
    / "llvm_m3_lowerback"
    / "fixtures"
    / "tiny_phi.ll"
)


def _value(name: str, type_name: str = "i32") -> LlvmValueRef:
    return LlvmValueRef(name=name, type=type_name)


def _term(kind: LlvmLowerBackTerminatorKind, *targets: str) -> LlvmLowerBackTerminator:
    return LlvmLowerBackTerminator(kind=kind, targets=tuple(targets))


def _tiny_phi_function() -> LlvmLowerBackFunction:
    return LlvmLowerBackFunction(
        name="tiny_phi",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "then", "else"),
            ),
            LlvmLowerBackBlock(
                label="then",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="else",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("then", "else"),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="then", value=_value("a")),
                            LlvmPhiIncoming(predecessor="else", value=_value("b")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )


def _kinds(result) -> tuple[LlvmLowerBackUnsupportedKind, ...]:
    return tuple(reason.kind for reason in result.unsupported)


def test_tiny_phi_fixture_documents_hand_authored_contract_shape():
    text = _FIXTURE.read_text(encoding="utf-8")

    assert "%x = phi i32 [ %a, %then ], [ %b, %else ]" in text
    assert "br label %merge" in text
    assert "ret i32 %x" in text


def test_plans_diamond_phi_as_ordered_edge_moves():
    result = plan_lower_back(_tiny_phi_function())

    assert result.status is LlvmLowerBackStatus.PLANNED
    assert result.plan is not None
    assert result.plan.block_order == ("entry", "then", "else", "merge")
    assert tuple(
        (move.predecessor, move.successor, move.insertion_block, move.target.name, move.value.name)
        for move in result.plan.edge_moves
    ) == (
        ("then", "merge", "then", "x", "a"),
        ("else", "merge", "else", "x", "b"),
    )
    assert tuple(
        (group.predecessor, group.successor, group.insertion_block, len(group.moves))
        for group in result.plan.parallel_copies
    ) == (
        ("then", "merge", "then", 1),
        ("else", "merge", "else", 1),
    )


def test_unknown_terminator_target_fails_closed():
    fn = LlvmLowerBackFunction(
        name="bad_target",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "missing"),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert result.plan is None
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.UNKNOWN_BLOCK_TARGET,)


def test_phi_incoming_must_name_a_real_predecessor():
    fn = _tiny_phi_function()
    merge = fn.blocks[-1]
    bad_merge = LlvmLowerBackBlock(
        label=merge.label,
        predecessors=merge.predecessors,
        phis=(
            LlvmPhiNode(
                result=_value("x"),
                incoming=(
                    LlvmPhiIncoming(predecessor="then", value=_value("a")),
                    LlvmPhiIncoming(predecessor="ghost", value=_value("b")),
                ),
            ),
        ),
        terminator=merge.terminator,
    )
    bad = LlvmLowerBackFunction(name=fn.name, entry=fn.entry, blocks=(*fn.blocks[:-1], bad_merge))

    result = plan_lower_back(bad)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert LlvmLowerBackUnsupportedKind.PHI_PREDECESSOR_MISMATCH in _kinds(result)


def test_phi_incoming_predecessor_must_have_real_edge_to_phi_block():
    fn = LlvmLowerBackFunction(
        name="bad_edge",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "other"),
            ),
            LlvmLowerBackBlock(
                label="other",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("entry",),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(LlvmPhiIncoming(predecessor="entry", value=_value("a")),),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert result.plan is None
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.PHI_PREDECESSOR_MISMATCH,)


def test_non_scalar_phi_fails_closed():
    fn = _tiny_phi_function()
    merge = fn.blocks[-1]
    bad_merge = LlvmLowerBackBlock(
        label=merge.label,
        predecessors=merge.predecessors,
        phis=(
            LlvmPhiNode(
                result=_value("x", "{ i32, i32 }"),
                incoming=merge.phis[0].incoming,
            ),
        ),
        terminator=merge.terminator,
    )
    bad = LlvmLowerBackFunction(name=fn.name, entry=fn.entry, blocks=(*fn.blocks[:-1], bad_merge))

    result = plan_lower_back(bad)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.NON_SCALAR_PHI,)


def test_plans_loop_carried_phi_backedge_move():
    fn = LlvmLowerBackFunction(
        name="loop_phi",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "header"),
            ),
            LlvmLowerBackBlock(
                label="header",
                predecessors=("entry", "body"),
                phis=(
                    LlvmPhiNode(
                        result=_value("i"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="entry", value=_value("zero")),
                            LlvmPhiIncoming(predecessor="body", value=_value("i.next")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "body", "exit"),
            ),
            LlvmLowerBackBlock(
                label="body",
                predecessors=("header",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "header"),
            ),
            LlvmLowerBackBlock(
                label="exit",
                predecessors=("header",),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.PLANNED
    assert result.plan is not None
    assert tuple(
        (move.predecessor, move.successor, move.insertion_block, move.target.name, move.value.name)
        for move in result.plan.edge_moves
    ) == (
        ("entry", "header", "entry", "i", "zero"),
        ("body", "header", "body", "i", "i.next"),
    )


def test_critical_edge_phi_move_plans_bridge_block():
    fn = LlvmLowerBackFunction(
        name="critical_phi",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "merge", "side"),
            ),
            LlvmLowerBackBlock(
                label="side",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("entry", "side"),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="entry", value=_value("a")),
                            LlvmPhiIncoming(predecessor="side", value=_value("b")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.PLANNED
    assert result.plan is not None
    assert tuple(
        (bridge.label, bridge.predecessor, bridge.successor)
        for bridge in result.plan.bridge_blocks
    ) == (("m3_split__entry__merge", "entry", "merge"),)
    assert tuple(
        (rewrite.predecessor, rewrite.successor, rewrite.bridge)
        for rewrite in result.plan.edge_rewrites
    ) == (("entry", "merge", "m3_split__entry__merge"),)
    assert result.plan.block_order == ("entry", "m3_split__entry__merge", "side", "merge")
    assert tuple(
        (group.predecessor, group.successor, group.insertion_block, len(group.moves))
        for group in result.plan.parallel_copies
    ) == (
        ("entry", "merge", "m3_split__entry__merge", 1),
        ("side", "merge", "side", 1),
    )


def test_critical_edge_bridge_label_must_not_collide_with_existing_block():
    fn = LlvmLowerBackFunction(
        name="bridge_collision",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "merge", "side"),
            ),
            LlvmLowerBackBlock(
                label="side",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="m3_split__entry__merge",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("entry", "side"),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="entry", value=_value("a")),
                            LlvmPhiIncoming(predecessor="side", value=_value("b")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert result.plan is None
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.BRIDGE_LABEL_CONFLICT,)


def test_critical_edge_generated_bridge_labels_must_be_unique_after_sanitizing():
    fn = LlvmLowerBackFunction(
        name="bridge_generated_collision",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "a/b", "a_b"),
            ),
            LlvmLowerBackBlock(
                label="a/b",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "merge", "exit"),
            ),
            LlvmLowerBackBlock(
                label="a_b",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "merge", "exit"),
            ),
            LlvmLowerBackBlock(
                label="exit",
                predecessors=("a/b", "a_b"),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("a/b", "a_b"),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="a/b", value=_value("a")),
                            LlvmPhiIncoming(predecessor="a_b", value=_value("b")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert result.plan is None
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.BRIDGE_LABEL_CONFLICT,)


def test_multiple_phis_plan_ordered_parallel_copies_on_same_edge():
    fn = LlvmLowerBackFunction(
        name="parallel_phi",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.COND_BRANCH, "then", "else"),
            ),
            LlvmLowerBackBlock(
                label="then",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="else",
                predecessors=("entry",),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("then", "else"),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="then", value=_value("a")),
                            LlvmPhiIncoming(predecessor="else", value=_value("c")),
                        ),
                    ),
                    LlvmPhiNode(
                        result=_value("y"),
                        incoming=(
                            LlvmPhiIncoming(predecessor="then", value=_value("b")),
                            LlvmPhiIncoming(predecessor="else", value=_value("d")),
                        ),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.PLANNED
    assert result.plan is not None
    assert tuple(
        (group.predecessor, tuple((move.target.name, move.value.name) for move in group.moves))
        for group in result.plan.parallel_copies
    ) == (
        ("then", (("x", "a"), ("y", "b"))),
        ("else", (("x", "c"), ("y", "d"))),
    )


def test_parallel_copy_cycle_fails_closed_until_temp_plan_exists():
    fn = LlvmLowerBackFunction(
        name="copy_cycle",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                terminator=_term(LlvmLowerBackTerminatorKind.BRANCH, "merge"),
            ),
            LlvmLowerBackBlock(
                label="merge",
                predecessors=("entry",),
                phis=(
                    LlvmPhiNode(
                        result=_value("x"),
                        incoming=(LlvmPhiIncoming(predecessor="entry", value=_value("y")),),
                    ),
                    LlvmPhiNode(
                        result=_value("y"),
                        incoming=(LlvmPhiIncoming(predecessor="entry", value=_value("x")),),
                    ),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert result.plan is None
    assert _kinds(result) == (LlvmLowerBackUnsupportedKind.PARALLEL_COPY_CONFLICT,)


def test_unsupported_memory_and_call_are_diagnostics_not_plans():
    fn = LlvmLowerBackFunction(
        name="effects",
        entry="entry",
        blocks=(
            LlvmLowerBackBlock(
                label="entry",
                predecessors=(),
                instructions=(
                    LlvmLowerBackInstruction(opcode="load", result=_value("x"), operands=(_value("p", "ptr"),)),
                    LlvmLowerBackInstruction(opcode="call", result=_value("y"), operands=(_value("x"),)),
                ),
                terminator=_term(LlvmLowerBackTerminatorKind.RETURN),
            ),
        ),
    )

    result = plan_lower_back(fn)

    assert result.status is LlvmLowerBackStatus.UNSUPPORTED
    assert _kinds(result) == (
        LlvmLowerBackUnsupportedKind.UNSUPPORTED_MEMORY,
        LlvmLowerBackUnsupportedKind.UNSUPPORTED_CALL,
    )


def test_unsupported_control_shapes_are_diagnostics():
    for kind in (
        LlvmLowerBackTerminatorKind.INDIRECTBR,
        LlvmLowerBackTerminatorKind.INVOKE,
        LlvmLowerBackTerminatorKind.LANDINGPAD,
    ):
        fn = LlvmLowerBackFunction(
            name=kind.value,
            entry="entry",
            blocks=(
                LlvmLowerBackBlock(
                    label="entry",
                    predecessors=(),
                    terminator=_term(kind),
                ),
            ),
        )

        result = plan_lower_back(fn)

        assert result.status is LlvmLowerBackStatus.UNSUPPORTED
        assert _kinds(result) == (LlvmLowerBackUnsupportedKind.UNSUPPORTED_CONTROL,)
