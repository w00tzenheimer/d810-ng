"""Tests for the executor return-carrier fact guard."""
from __future__ import annotations

from d810.cfg.flowgraph import BlockSnapshot, FlowGraph
from d810.cfg.graph_modification import RedirectGoto
from d810.optimizers.microcode.flow.flattening.engine import return_carrier_fact_guard
from d810.optimizers.microcode.flow.flattening.engine.return_carrier_fact_guard import (
    filter_return_carrier_fact_redirects,
)
from d810.recon.facts import FactMapping, FactObservation, FactStatus, ValidatedFactView


def _flow_graph(succs_by_block: dict[int, tuple[int, ...]]) -> FlowGraph:
    serials = set(succs_by_block)
    for succs in succs_by_block.values():
        serials.update(int(succ) for succ in succs)
    preds_by_block = {int(serial): set() for serial in serials}
    for serial, succs in succs_by_block.items():
        for succ in succs:
            preds_by_block.setdefault(int(succ), set()).add(int(serial))
    blocks = {
        int(serial): BlockSnapshot(
            serial=int(serial),
            block_type=0,
            succs=tuple(int(succ) for succ in succs_by_block.get(int(serial), ())),
            preds=tuple(sorted(preds_by_block.get(int(serial), ()))),
            flags=0,
            start_ea=int(serial),
            insn_snapshots=(),
        )
        for serial in serials
    }
    return FlowGraph(blocks=blocks, entry_serial=min(serials or {0}), func_ea=0)


def _return_carrier_fact(
    fact_id: str,
    *,
    block_serial: int = 93,
    return_writer_block_serial: int | None = None,
    refs: tuple[str, ...] = ("228", "650"),
) -> FactObservation:
    if return_writer_block_serial is None:
        return_writer_block_serial = block_serial
    return FactObservation(
        fact_id=fact_id,
        kind="ReturnCarrierFact",
        semantic_key=f"{fact_id}:semantic",
        maturity="MMAT_LOCOPT",
        phase="pre_d810",
        confidence=0.9,
        source_ea=0x401000,
        payload={
            "return_slot_stkoff": 8,
            "carrier_dst_stkoff": 0x30,
            "block_serial": return_writer_block_serial,
            "upstream_writer_block_serial": block_serial,
            "upstream_writer_ea": 0x401020,
            "upstream_writer_dest_stkoff": 0x30,
            "upstream_writer_var_refs": list(refs),
        },
    )


def _patch_const_refs(monkeypatch, refs: frozenset[str]) -> None:
    monkeypatch.setattr(
        return_carrier_fact_guard,
        "collect_const_var_refs_in_block",
        lambda _mba, _block_serial, **_kwargs: refs,
    )


def test_active_return_carrier_fact_rejects_redirect(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"228"}))
    fact = _return_carrier_fact("return:active")
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    filtered, rejections = filter_return_carrier_fact_redirects(
        [RedirectGoto(from_serial=132, old_target=2, new_target=93)],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].fact_status == "active"
    assert rejections[0].overlap == ("228",)


def test_carrier_writer_bypass_requires_explicit_loop_recovery_gate(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset())
    fact = _return_carrier_fact("return:active")
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_carrier_writer_bypass_rejects_loop_recovery_without_const_feed(
    monkeypatch,
) -> None:
    _patch_const_refs(monkeypatch, frozenset())
    fact = _return_carrier_fact("return:active")
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    filtered, rejections = filter_return_carrier_fact_redirects(
        [RedirectGoto(from_serial=132, old_target=2, new_target=93)],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
        reject_carrier_writer_bypass=True,
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].reason == "carrier_writer_bypass"
    assert rejections[0].fact_status == "active"
    assert rejections[0].overlap == ()
    assert rejections[0].const_written == ()


def test_carrier_writer_bypass_uses_return_slot_writer_block(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset())
    fact = _return_carrier_fact(
        "return:active",
        block_serial=41,
        return_writer_block_serial=93,
    )
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    filtered, rejections = filter_return_carrier_fact_redirects(
        [RedirectGoto(from_serial=132, old_target=2, new_target=93)],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
        reject_carrier_writer_bypass=True,
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].reason == "carrier_writer_bypass"
    assert rejections[0].fact_status == "active_writer"
    assert rejections[0].hazard_block == 93


def test_identity_lost_fact_without_target_block_is_ignored(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"650"}))
    fact = _return_carrier_fact("return:stale")
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(fact,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_stale_hazard_on_immediate_successor_rejects_redirect(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"650"}))
    fact = _return_carrier_fact("return:stale", block_serial=254)
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(fact,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
                target_block=94,
            ),
        ),
    )

    filtered, rejections = filter_return_carrier_fact_redirects(
        [RedirectGoto(from_serial=132, old_target=2, new_target=93)],
        mba=object(),
        flow_graph=_flow_graph({93: (94, 95)}),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].fact_status == "stale_hazard"
    assert rejections[0].hazard_block == 94


def test_dag_frontier_override_bypasses_only_matching_stale_hazard(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"650"}))
    fact = _return_carrier_fact("return:stale", block_serial=254)
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(fact,),
        mappings=(
            FactMapping(
                source_fact_id="return:stale",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
                target_block=94,
            ),
        ),
    )

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        flow_graph=_flow_graph({93: (94, 95)}),
        fact_view=view,
        dispatcher_serial=2,
        stale_hazard_override_keys=frozenset({(132, 2, 93)}),
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_dag_frontier_override_does_not_bypass_active_hazard(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"228"}))
    fact = _return_carrier_fact("return:active")
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(maturity="MMAT_LOCOPT", observations=(fact,))

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
        stale_hazard_override_keys=frozenset({(132, 2, 93)}),
    )

    assert filtered == []
    assert len(rejections) == 1
    assert rejections[0].fact_status == "active"


def test_contradicted_stale_hazard_is_ignored(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"228"}))
    fact = _return_carrier_fact("return:contradicted")
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(fact,),
        mappings=(
            FactMapping(
                source_fact_id="return:contradicted",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
            FactMapping(
                source_fact_id="return:contradicted",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.CONTRADICTED,
                confidence=1.0,
            ),
        ),
    )

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_unrelated_lost_fact_is_ignored(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"228"}))
    fact = _return_carrier_fact("return:unrelated", block_serial=94)
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)
    view = ValidatedFactView(
        maturity="MMAT_GLBOPT1",
        observations=(fact,),
        mappings=(
            FactMapping(
                source_fact_id="return:unrelated",
                source_maturity="MMAT_LOCOPT",
                target_maturity="MMAT_GLBOPT1",
                status=FactStatus.IDENTITY_LOST,
                confidence=1.0,
            ),
        ),
    )

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=view,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()


def test_no_fact_view_is_noop(monkeypatch) -> None:
    _patch_const_refs(monkeypatch, frozenset({"228"}))
    redirect = RedirectGoto(from_serial=132, old_target=2, new_target=93)

    filtered, rejections = filter_return_carrier_fact_redirects(
        [redirect],
        mba=object(),
        fact_view=None,
        dispatcher_serial=2,
    )

    assert filtered == [redirect]
    assert rejections == ()
