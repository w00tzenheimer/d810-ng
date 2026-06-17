from __future__ import annotations

from types import SimpleNamespace

from d810.transforms.residual_dispatcher_handoff_emission import _normalize_residual_handoff


def test_normalize_residual_handoff_prefers_effective_target_entry_for_matching_path_tail():
    state_value = 0x4C77464F
    edge = SimpleNamespace(
        target_state=state_value,
        ordered_path=(15, 16),
        source_anchor=SimpleNamespace(block_serial=15),
    )
    context = SimpleNamespace(
        dag=SimpleNamespace(edges=(edge,)),
        resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=66),
        analysis_mba=object(),
        condition_chain_blocks=frozenset({71}),
        state_var_stkoff=None,
        dispatcher_lookup=None,
        dispatcher=None,
    )

    normalized = _normalize_residual_handoff(
        context,
        source_block=16,
        handoff=(state_value, 68),
    )

    assert normalized == (state_value, 66)


def test_normalize_residual_handoff_leaves_raw_target_when_no_matching_edge_exists():
    context = SimpleNamespace(
        dag=SimpleNamespace(edges=()),
        resolve_effective_target_entry=lambda *args, **kwargs: SimpleNamespace(target_entry=66),
        analysis_mba=object(),
        condition_chain_blocks=frozenset(),
        state_var_stkoff=None,
        dispatcher_lookup=None,
        dispatcher=None,
    )

    normalized = _normalize_residual_handoff(
        context,
        source_block=16,
        handoff=(0x4C77464F, 68),
    )

    assert normalized == (0x4C77464F, 68)
