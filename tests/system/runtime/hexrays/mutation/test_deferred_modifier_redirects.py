"""Contracts for production redirect lowering.

``DeferredGraphModifier._apply_goto_change`` is a thin 1-way-only guard: it
inspects ``blk.nsucc()``/``blk.serial`` and then delegates ALL redirect
mechanics (mba/succset/tail rewriting) to the module-level
``change_1way_block_successor`` primitive imported from
``d810.hexrays.mutation.cfg_mutations`` -- it never reimplements the
redirect inline and never routes through ``_apply_create_and_redirect``
(that primitive builds a standalone intermediate block, a different
operation entirely).  Because the redirect mechanics live inside the
monkeypatched primitive, a bare stub block -- exposing only the two
attributes ``_apply_goto_change`` itself reads -- is a faithful exercise of
the real code path; a real ``mblock_t``/``mba_t`` would add fixture
machinery without touching any code this test verifies.
"""

from types import SimpleNamespace

from d810.hexrays.mutation import deferred_modifier as dm


def test_goto_redirect_uses_existing_change_1way_block_successor_primitive(
    monkeypatch,
):
    calls = []
    block = SimpleNamespace(serial=3, nsucc=lambda: 1)
    modifier = dm.DeferredGraphModifier.__new__(dm.DeferredGraphModifier)

    def fake_change_1way_block_successor(blk, new_target, verify=True):
        calls.append((blk, new_target, verify))
        return True

    monkeypatch.setattr(
        dm, "change_1way_block_successor", fake_change_1way_block_successor
    )

    assert modifier._apply_goto_change(block, 11) is True
    assert calls == [(block, 11, False)]


def test_goto_redirect_rejects_non_1way_block_without_calling_primitive(
    monkeypatch,
):
    """BLOCK_GOTO_CHANGE must never coerce a non-1-way block into a goto by
    falling through to the redirect primitive."""
    calls = []
    block = SimpleNamespace(serial=3, nsucc=lambda: 2)
    modifier = dm.DeferredGraphModifier.__new__(dm.DeferredGraphModifier)

    monkeypatch.setattr(
        dm,
        "change_1way_block_successor",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    assert modifier._apply_goto_change(block, 11) is False
    assert calls == []
