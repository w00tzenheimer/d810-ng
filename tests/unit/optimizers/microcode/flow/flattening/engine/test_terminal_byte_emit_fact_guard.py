"""Tests for the executor terminal-byte-emit fact guard."""
from __future__ import annotations

from types import SimpleNamespace

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph, InsnSnapshot
from d810.cfg.graph_modification import (
    DirectTerminalLoweringGroup,
    DirectTerminalLoweringKind,
    DirectTerminalLoweringSite,
    PrivateTerminalSuffixGroup,
    RedirectBranch,
    RedirectGoto,
)
from d810.optimizers.microcode.flow.flattening.engine import (
    terminal_byte_emit_fact_guard,
)
from d810.optimizers.microcode.flow.flattening.engine.terminal_byte_emit_fact_guard import (
    append_protected_non_carrier_return_writer_direct_lowerings,
    filter_terminal_byte_emit_fact_redirects,
)
from d810.analyses.control_flow.return_frontier_artifacts import (
    ReturnFrontierCarrierClassification,
)
from d810.analyses.value_flow.facts import FactObservation, ValidatedFactView


def _terminal_byte_emit_fact(
    fact_id: str,
    *,
    destination_block: int = 143,
    byte_index: int = 1,
    source_ea: int = 0x180015906,
) -> FactObservation:
    return FactObservation(
        fact_id=fact_id,
        kind="TerminalByteEmitterFact",
        semantic_key=f"{fact_id}:semantic",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=source_ea,
        payload={
            "corridor_role": "terminal_tail",
            "byte_index": byte_index,
            "destination_block": destination_block,
            "block_serial": destination_block,
        },
    )


def _zero_guard_fact(
    fact_id: str,
    *,
    guard_block: int = 206,
    return_edge: int = 207,
    continuation_edge: int = 208,
    source_ea: int = 0x180016451,
) -> FactObservation:
    return FactObservation(
        fact_id=fact_id,
        kind="TerminalByteEmitterFact",
        semantic_key=f"{fact_id}:semantic",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=source_ea,
        payload={
            "corridor_role": "terminal_tail",
            "emitter_role": "guard_only",
            "byte_index": 0,
            "destination_block": guard_block,
            "block_serial": guard_block,
            "return_edge": return_edge,
            "continuation_edge": continuation_edge,
        },
    )


def _patch_state_const_refs(monkeypatch, refs: frozenset[str]) -> None:
    monkeypatch.setattr(
        terminal_byte_emit_fact_guard,
        "collect_const_var_refs_in_block",
        lambda _mba, _block_serial, **_kwargs: refs,
    )


def _mop_stack(stkoff: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=int(terminal_byte_emit_fact_guard.ida_hexrays.mop_S),
        stkoff=stkoff,
        size=8,
    )


def _mop_const(value: int) -> SimpleNamespace:
    return SimpleNamespace(
        t=int(terminal_byte_emit_fact_guard.ida_hexrays.mop_n),
        nnn=SimpleNamespace(value=value),
        size=8,
    )


def _mov_const_to_stack(value: int, stkoff: int) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=int(terminal_byte_emit_fact_guard.ida_hexrays.m_mov),
        l=_mop_const(value),
        d=_mop_stack(stkoff),
        next=None,
    )


def _xdu_state_to_stack(dst_stkoff: int) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=int(terminal_byte_emit_fact_guard.ida_hexrays.m_xdu),
        l=SimpleNamespace(
            t=int(terminal_byte_emit_fact_guard.ida_hexrays.mop_S),
            stkoff=100,
            dstr="%var_7BC.4{6}",
            size=4,
        ),
        d=_mop_stack(dst_stkoff),
        next=None,
    )


def _fake_mba(blocks: dict[int, SimpleNamespace]) -> SimpleNamespace:
    return SimpleNamespace(get_mblock=lambda serial: blocks[int(serial)])


def _fake_insn_snapshots(head: SimpleNamespace | None) -> tuple[InsnSnapshot, ...]:
    snapshots: list[InsnSnapshot] = []
    insn = head
    while insn is not None:
        slots = tuple(
            (name, getattr(insn, name))
            for name in ("l", "r", "d")
            if getattr(insn, name, None) is not None
        )
        snapshots.append(
            InsnSnapshot(
                opcode=int(getattr(insn, "opcode", -1)),
                ea=0,
                operands=tuple(operand for _name, operand in slots),
                operand_slots=slots,
                l=getattr(insn, "l", None),
                r=getattr(insn, "r", None),
                d=getattr(insn, "d", None),
            )
        )
        insn = getattr(insn, "next", None)
    return tuple(snapshots)


def _fake_flow_graph(blocks: dict[int, SimpleNamespace]) -> FlowGraph:
    serials = set(blocks)
    for block in blocks.values():
        serials.update(int(serial) for serial in getattr(block, "predset", ()) or ())
        serials.update(int(serial) for serial in getattr(block, "succset", ()) or ())

    snapshots = {}
    for serial in serials:
        block = blocks.get(serial, SimpleNamespace(predset=(), succset=(), head=None))
        snapshots[int(serial)] = BlockSnapshot(
            serial=int(serial),
            block_type=0,
            succs=tuple(int(succ) for succ in getattr(block, "succset", ()) or ()),
            preds=tuple(int(pred) for pred in getattr(block, "predset", ()) or ()),
            flags=0,
            start_ea=int(serial),
            insn_snapshots=_fake_insn_snapshots(getattr(block, "head", None)),
        )
    return FlowGraph(
        blocks=snapshots,
        entry_serial=min(serials) if serials else 0,
        func_ea=0,
    )


def test_state_flow_source_into_terminal_byte_emit_target_rejects(monkeypatch) -> None:
    """Source block 108 has ``mov #0x393685BA, %var_7BC`` -- the byte-emit
    target 143 is a known ``terminal_tail`` with byte_index=1.  The
    redirect must be filtered out and recorded."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    fact = _terminal_byte_emit_fact("byte_emit:active", destination_block=143)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    redirect_goto = RedirectGoto(from_serial=39, old_target=2, new_target=161)
    fact_target_161 = _terminal_byte_emit_fact(
        "byte_emit:byte3", destination_block=161, byte_index=3
    )
    view_with_both = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(fact, fact_target_161),
    )

    redirect_branch_108 = RedirectBranch(
        from_serial=108, old_target=110, new_target=143
    )
    redirect_branch_129 = RedirectBranch(
        from_serial=129, old_target=131, new_target=143
    )

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect_goto, redirect_branch_108, redirect_branch_129],
        mba=object(),
        fact_view=view_with_both,
        dispatcher_serial=2,
    )

    assert filtered == []
    assert len(rejections) == 3
    rejected_targets = {r.target_block for r in rejections}
    assert rejected_targets == {143, 161}
    rejected_sources = {r.source_block for r in rejections}
    assert rejected_sources == {39, 108, 129}
    assert all("7bc" in r.state_const_writes for r in rejections)


def test_dag_frontier_override_keeps_exact_terminal_byte_redirect(monkeypatch) -> None:
    """DAG-authoritative frontier closure may prove that a state-flow
    scaffold is the required predecessor for a terminal byte emitter.  The
    terminal guard accepts only that exact redirect key."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    fact = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))
    redirect = RedirectGoto(from_serial=100, old_target=2, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
        dag_frontier_override_keys=frozenset({(100, 2, 217)}),
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_dag_frontier_override_is_exact_keyed(monkeypatch) -> None:
    """A DAG-frontier override is not a blanket bypass for nearby terminal
    byte redirects."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    fact = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))
    redirect = RedirectGoto(from_serial=100, old_target=2, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
        dag_frontier_override_keys=frozenset({(100, 3, 217)}),
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].source_block == 100
    assert rejections[0].target_block == 217


def test_zero_guard_return_successor_into_terminal_byte_emit_rejects(monkeypatch) -> None:
    """The residual-zero fallthrough is a return path.  Redirecting it to a
    terminal byte-emitter block turns ``v53 == 0`` into a byte6 emit; reject
    that even when the source block has no state-const write."""
    _patch_state_const_refs(monkeypatch, frozenset())
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].source_block == 207
    assert rejections[0].target_block == 217
    assert rejections[0].fact_id == "byte_emit:zero_guard"
    assert rejections[0].reason == "terminal_zero_guard_return_redirect"
    assert rejections[0].replacement_target is None


def test_zero_guard_return_successor_retargets_to_constant_materializer(
    monkeypatch,
) -> None:
    """When the return suffix has a unique constant-return sibling, keep the
    zero-residual return path live by replacing the rejected byte-emitter
    target with that sibling materializer."""
    _patch_state_const_refs(monkeypatch, frozenset())
    monkeypatch.setattr(
        terminal_byte_emit_fact_guard,
        "_constant_terminal_return_materializer_for_successor",
        lambda _mba, old_target, source_block: 27,
    )
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [RedirectGoto(from_serial=207, old_target=218, new_target=27)]
    assert len(rejections) == 1
    assert rejections[0].source_block == 207
    assert rejections[0].target_block == 217
    assert rejections[0].replacement_target == 27


def test_zero_guard_return_successor_with_private_suffix_retargets_to_materializer(
    monkeypatch,
) -> None:
    """Private suffix plans do not change the executor guard behavior.

    The guard only rejects the unsafe byte-emitter target and retargets the
    redirect to the proven constant sibling.  Direct terminal lowering is a
    separate proof path and is not inferred here.
    """
    _patch_state_const_refs(monkeypatch, frozenset())
    monkeypatch.setattr(
        terminal_byte_emit_fact_guard,
        "_constant_terminal_return_materializer_for_successor",
        lambda _mba, old_target, source_block: 27,
    )
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)
    private_suffix = PrivateTerminalSuffixGroup(
        anchors=(27,),
        shared_entry_serial=218,
        return_block_serial=219,
        suffix_serials=(218, 219),
        reason="terminal_family_split",
    )

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect, private_suffix],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered[0] == RedirectGoto(from_serial=207, old_target=218, new_target=27)
    assert filtered[1] == private_suffix
    assert len(rejections) == 1
    assert rejections[0].replacement_target == 27


def test_zero_guard_return_successor_retarget_ignores_literal_lowering(
    monkeypatch,
) -> None:
    """A literal sibling materializer still produces a plain retarget.

    The literal value is useful for a future direct-lowering proof, but the
    fact guard's behavior is limited to replacing the unsafe byte-emitter
    target with the proven constant sibling.
    """
    _patch_state_const_refs(monkeypatch, frozenset())
    monkeypatch.setattr(
        terminal_byte_emit_fact_guard,
        "_constant_terminal_return_materializer_for_successor",
        lambda _mba, old_target, source_block: 27,
    )
    blocks = {
        27: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x5644FD01B1049C4B, 2072),
        ),
        207: SimpleNamespace(predset=(), succset=(218,), head=None),
        218: SimpleNamespace(predset=(27, 207), succset=(219,), head=None),
        219: SimpleNamespace(predset=(218,), succset=(), head=None),
    }
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)
    private_suffix = PrivateTerminalSuffixGroup(
        anchors=(27,),
        shared_entry_serial=218,
        return_block_serial=219,
        suffix_serials=(218, 219),
        reason="terminal_family_split",
    )

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect, private_suffix],
        mba=_fake_mba(blocks),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered[0] == RedirectGoto(from_serial=207, old_target=218, new_target=27)
    assert filtered[1] == private_suffix
    assert len(rejections) == 1
    assert rejections[0].replacement_target == 27


def test_zero_guard_retargeter_falls_back_to_unique_constant_sibling(
    monkeypatch,
) -> None:
    """The live zero-residual artifact may not expose its return-slot carrier
    at executor-filter time.  In that already fact-proven zero-guard case,
    the unique constant-return sibling of the shared suffix is still enough to
    retarget the artifact away from the byte6 emitter."""
    _patch_state_const_refs(monkeypatch, frozenset())
    blocks = {
        27: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x5644FD01B1049C4B, 2032),
        ),
        207: SimpleNamespace(predset=(), succset=(218,), head=None),
        218: SimpleNamespace(predset=(27, 207), succset=(219,), head=None),
    }
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=_fake_mba(blocks),
        flow_graph=_fake_flow_graph(blocks),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [RedirectGoto(from_serial=207, old_target=218, new_target=27)]
    assert len(rejections) == 1
    assert rejections[0].replacement_target == 27


def test_zero_guard_retargeter_matches_display_named_state_var(
    monkeypatch,
) -> None:
    """Live microcode may name the state slot ``%var_7BC`` while the physical
    stack offset is unrelated.  Match the display token so the source return
    slot can disambiguate the constant sibling."""
    _patch_state_const_refs(monkeypatch, frozenset())
    blocks = {
        27: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x5644FD01B1049C4B, 2072),
        ),
        41: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x1111, 1800),
        ),
        207: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_xdu_state_to_stack(2072),
        ),
        218: SimpleNamespace(predset=(27, 41, 207), succset=(219,), head=None),
    }
    byte6 = _terminal_byte_emit_fact(
        "byte_emit:byte6",
        destination_block=217,
        byte_index=6,
    )
    zero_guard = _zero_guard_fact("byte_emit:zero_guard")
    view = ValidatedFactView(
        maturity="MMAT_LOCOPT",
        observations=(byte6, zero_guard),
    )
    redirect = RedirectGoto(from_serial=207, old_target=218, new_target=217)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=_fake_mba(blocks),
        flow_graph=_fake_flow_graph(blocks),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [RedirectGoto(from_serial=207, old_target=218, new_target=27)]
    assert len(rejections) == 1
    assert rejections[0].replacement_target == 27


def test_protected_non_carrier_return_writer_fact_stays_observational() -> None:
    blocks = {
        27: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x5644FD01B1049C4B, 2072),
        ),
        41: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_xdu_state_to_stack(2072),
        ),
        218: SimpleNamespace(predset=(27, 41), succset=(219,), head=None),
        219: SimpleNamespace(predset=(218,), succset=(), head=None),
    }
    fact = SimpleNamespace(
        classification=(
            ReturnFrontierCarrierClassification
            .PROTECTED_NON_CARRIER_RETURN_WRITER
        ),
        ret_block=219,
        writer_block=41,
        walk_path=(219, 218, 41),
    )

    filtered = append_protected_non_carrier_return_writer_direct_lowerings(
        [],
        mba=_fake_mba(blocks),
        carrier_facts=(fact,),
    )

    assert filtered == []


def test_protected_non_carrier_return_writer_fact_does_not_duplicate_existing_lowering() -> None:
    blocks = {
        27: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_mov_const_to_stack(0x5644FD01B1049C4B, 2072),
        ),
        41: SimpleNamespace(
            predset=(),
            succset=(218,),
            head=_xdu_state_to_stack(2072),
        ),
        218: SimpleNamespace(predset=(27, 41), succset=(219,), head=None),
        219: SimpleNamespace(predset=(218,), succset=(), head=None),
    }
    fact = SimpleNamespace(
        classification=(
            ReturnFrontierCarrierClassification
            .PROTECTED_NON_CARRIER_RETURN_WRITER
        ),
        ret_block=219,
        writer_block=41,
        walk_path=(219, 218, 41),
    )
    existing = DirectTerminalLoweringGroup(
        shared_entry_serial=218,
        return_block_serial=219,
        suffix_serials=(218, 219),
        sites=(
            DirectTerminalLoweringSite(
                anchor_serial=41,
                kind=DirectTerminalLoweringKind.CLONE_MATERIALIZER,
                materializer_serials=(27, 218),
            ),
        ),
        reason="existing",
    )

    filtered = append_protected_non_carrier_return_writer_direct_lowerings(
        [existing],
        mba=_fake_mba(blocks),
        carrier_facts=(fact,),
    )

    assert filtered == [existing]


def test_non_state_flow_source_permits_redirect(monkeypatch) -> None:
    """Source has only data-var writes (no ``%var_7BC`` constant write)
    -- the redirect must pass through unchanged because the source is
    not state-flow scaffolding."""
    _patch_state_const_refs(monkeypatch, frozenset({"650", "228"}))
    fact = _terminal_byte_emit_fact("byte_emit:active", destination_block=143)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    redirect = RedirectGoto(from_serial=42, old_target=2, new_target=143)

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_no_fact_view_is_noop(monkeypatch) -> None:
    """When the validated fact view is absent, the guard must be a no-op
    even for sources that do contain ``%var_7BC`` writes."""
    _patch_state_const_refs(monkeypatch, frozenset({"7bc"}))
    redirects: list = [
        RedirectGoto(from_serial=39, old_target=2, new_target=161),
        RedirectBranch(from_serial=108, old_target=110, new_target=143),
    ]

    filtered, rejections = filter_terminal_byte_emit_fact_redirects(
        list(redirects),
        mba=object(),
        fact_view=None,
        dispatcher_serial=2,
    )

    assert filtered == redirects
    assert rejections == ()
