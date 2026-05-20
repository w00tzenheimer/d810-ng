"""Tests for new GraphModification dataclasses."""
from dataclasses import FrozenInstanceError

import pytest

from d810.cfg import graph_modification as gm


def test_new_graph_modification_types_exported():
    assert "EdgeRedirectViaPredSplit" in gm.__all__
    assert "CreateConditionalRedirect" in gm.__all__
    assert "DuplicateBlock" in gm.__all__
    assert "CloneConditionalAsGoto" in gm.__all__


def test_edge_redirect_via_pred_split_is_frozen():
    mod = gm.EdgeRedirectViaPredSplit(
        src_block=10,
        old_target=11,
        new_target=12,
        via_pred=9,
    )
    with pytest.raises(FrozenInstanceError):
        mod.new_target = 99  # type: ignore[misc]


def test_create_conditional_redirect_fields():
    mod = gm.CreateConditionalRedirect(
        source_block=20,
        ref_block=21,
        conditional_target=30,
        fallthrough_target=31,
    )
    assert mod.source_block == 20
    assert mod.ref_block == 21
    assert mod.conditional_target == 30
    assert mod.fallthrough_target == 31


def test_duplicate_block_defaults():
    mod = gm.DuplicateBlock(source_block=33, target_block=None)
    assert mod.pred_serial is None
    assert mod.patch_kind == ""


def test_clone_conditional_as_goto_fields_and_frozen():
    mod = gm.CloneConditionalAsGoto(
        source_block=10,
        pred_serial=8,
        goto_target=12,
        reason="fix predecessor",
    )

    assert mod.source_block == 10
    assert mod.pred_serial == 8
    assert mod.goto_target == 12
    assert mod.reason == "fix predecessor"
    with pytest.raises(FrozenInstanceError):
        mod.goto_target = 99  # type: ignore[misc]
