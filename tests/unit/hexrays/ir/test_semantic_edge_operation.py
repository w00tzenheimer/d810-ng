"""Serial-free semantic edge mutation intents."""

from __future__ import annotations

from dataclasses import fields

import pytest

from d810.hexrays.ir.logical_block_proxy import LogicalBlockProxy
from d810.hexrays.ir.semantic_edge import (
    LogicalSemanticEdge,
    LogicalSemanticEdgeOperation,
)
from d810.ir.block_identity import MbaBlockHandle
from d810.ir.semantic_edge import SemanticEdgeRole


def _proxy(token: str) -> LogicalBlockProxy:
    return LogicalBlockProxy.with_published(
        proxy_token=f"logical:{token}",
        handle=MbaBlockHandle.synthetic(
            session_id="semantic-edge-session",
            token=f"physical:{token}",
        ),
        generation=4,
    )


def test_semantic_edge_operation_contains_no_mba_serial_coordinate() -> None:
    assert "serial" not in {field.name for field in fields(LogicalSemanticEdge)}
    assert "serial" not in {
        field.name for field in fields(LogicalSemanticEdgeOperation)
    }


def test_direct_edge_operation_has_one_explicit_role() -> None:
    operation = LogicalSemanticEdgeOperation(
        source=_proxy("source"),
        edges=(
            LogicalSemanticEdge(
                role=SemanticEdgeRole.DIRECT,
                target=_proxy("target"),
            ),
        ),
    )

    assert operation.roles == frozenset({SemanticEdgeRole.DIRECT})


def test_conditional_reconstruction_requires_both_roles_and_predicate() -> None:
    source = _proxy("source")
    taken = _proxy("taken")
    fallthrough = _proxy("fallthrough")

    with pytest.raises(ValueError, match="both conditional roles"):
        LogicalSemanticEdgeOperation(
            source=source,
            edges=(
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target=taken,
                ),
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.DIRECT,
                    target=fallthrough,
                ),
            ),
            predicate_anchor_ea=0x40C12C,
        )

    with pytest.raises(ValueError, match="predicate anchor"):
        LogicalSemanticEdgeOperation(
            source=source,
            edges=(
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target=taken,
                ),
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                    target=fallthrough,
                ),
            ),
        )


def test_conditional_reconstruction_rejects_duplicate_roles_and_targets() -> None:
    source = _proxy("source")
    target = _proxy("target")

    with pytest.raises(ValueError, match="unique semantic edge roles"):
        LogicalSemanticEdgeOperation(
            source=source,
            edges=(
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target=target,
                ),
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target=_proxy("other"),
                ),
            ),
            predicate_anchor_ea=0x40C12C,
        )

    with pytest.raises(ValueError, match="distinct targets"):
        LogicalSemanticEdgeOperation(
            source=source,
            edges=(
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                    target=target,
                ),
                LogicalSemanticEdge(
                    role=SemanticEdgeRole.CONDITIONAL_FALLTHROUGH,
                    target=target,
                ),
            ),
            predicate_anchor_ea=0x40C12C,
        )


def test_single_conditional_arm_is_a_redirect_not_a_reconstruction() -> None:
    expected = _proxy("old-taken")
    operation = LogicalSemanticEdgeOperation(
        source=_proxy("source"),
        edges=(
            LogicalSemanticEdge(
                role=SemanticEdgeRole.CONDITIONAL_TAKEN,
                expected_target=expected,
                target=_proxy("new-taken"),
            ),
        ),
    )

    assert operation.predicate_anchor_ea is None
    assert operation.edges[0].expected_target is expected
