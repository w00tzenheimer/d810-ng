"""LS12 C3: every tagged lowering strategy exposes the correct ``lowering_mode``.

Asserts the mode->strategy map from the execution playbook, the explicit
``SemanticStructuredRegionStrategy`` override (else it would inherit DIRECT_GRAPH
from its ``LinearizedFlowGraphStrategy`` base), the inherited tag on
``SemanticExactNodeAllPlannableEdgesStrategy``, and the orthogonality of
lowering_mode vs family (TopologicalSort & HandlerChainComposer share a family
yet lower differently). ``lowering_mode`` is a class attribute, so we read it off
the class without constructing instances.
"""
from __future__ import annotations

import pytest

# IDA-dependent collection guard: the strategy + ``prototypes`` bridge imports
# below transitively ``import ida_hexrays`` (the bridge lives in the IDA-coupled
# ``optimizers/microcode`` layer, where a top-level IDA import is correct and a
# lazy import is disallowed). Skip cleanly when IDA is absent so this file does
# not break the no-IDA ``pytest tests/unit/`` collection -- the cold-import
# failure is ``ModuleNotFoundError: ida_hexrays``, NOT the cycle noted below.
pytest.importorskip("ida_hexrays")

# NOTE: import the ``strategies`` package modules BEFORE the ``prototypes`` bridge.
# ``prototypes`` and ``strategies`` form a (pre-existing) bidirectional import
# cycle that only errors when ``prototypes`` is the COLD entry point; loading a
# strategies module first establishes the safe order so this test is collectable
# in isolation, not just inside the full suite.
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_alias import (
    ExactConditionalAliasNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_fork import (
    ExactConditionalForkNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.exact_conditional_node import (
    ExactConditionalNodeLoweringStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.handler_chain_composer import (
    HandlerChainComposerStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.linearized_flow_graph import (
    LinearizedFlowGraphStrategy,
    SemanticStructuredRegionStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.semantic_exact_node import (
    SemanticExactNodeAllPlannableEdgesStrategy,
    _SemanticExactNodeExperimentStrategy,
)
from d810.optimizers.microcode.flow.flattening.hodur.strategies.topological_sort import (
    TopologicalSortStrategy,
)
# prototypes LAST (see cold-entry cycle note above)
from d810.optimizers.microcode.flow.flattening.hodur.prototypes.exact_conditional_bridge import (
    ExactConditionalBridgeNodeLoweringStrategy,
)
from d810.transforms.lowering import LoweringMode

# The 8 tagged classes (+ the inheriting subclass) and their expected mode.
MODE_MAP = {
    LinearizedFlowGraphStrategy: LoweringMode.DIRECT_GRAPH,
    _SemanticExactNodeExperimentStrategy: LoweringMode.DIRECT_GRAPH,
    SemanticExactNodeAllPlannableEdgesStrategy: LoweringMode.DIRECT_GRAPH,  # inherited
    ExactConditionalNodeLoweringStrategy: LoweringMode.DIRECT_GRAPH,
    ExactConditionalAliasNodeLoweringStrategy: LoweringMode.DIRECT_GRAPH,
    ExactConditionalForkNodeLoweringStrategy: LoweringMode.DIRECT_GRAPH,
    ExactConditionalBridgeNodeLoweringStrategy: LoweringMode.DIRECT_GRAPH,
    SemanticStructuredRegionStrategy: LoweringMode.STRUCTURED_REGION,
    HandlerChainComposerStrategy: LoweringMode.REGION_COMPOSITION,
    TopologicalSortStrategy: LoweringMode.DAG_LINEARIZATION,
}


@pytest.mark.parametrize("cls, expected", list(MODE_MAP.items()), ids=lambda v: getattr(v, "__name__", str(v)))
def test_strategy_has_expected_lowering_mode(cls, expected) -> None:
    assert cls.lowering_mode is expected


def test_every_tagged_class_has_a_lowering_mode() -> None:
    for cls in MODE_MAP:
        assert isinstance(cls.lowering_mode, LoweringMode)


def test_structured_region_override_is_not_inherited_direct_graph() -> None:
    # SemanticStructuredRegionStrategy subclasses LinearizedFlowGraphStrategy
    # (DIRECT_GRAPH); without the explicit override it would inherit that.
    assert issubclass(SemanticStructuredRegionStrategy, LinearizedFlowGraphStrategy)
    assert SemanticStructuredRegionStrategy.lowering_mode is LoweringMode.STRUCTURED_REGION
    assert LinearizedFlowGraphStrategy.lowering_mode is LoweringMode.DIRECT_GRAPH


def test_all_plannable_edges_inherits_base_tag() -> None:
    assert issubclass(
        SemanticExactNodeAllPlannableEdgesStrategy, _SemanticExactNodeExperimentStrategy
    )
    assert SemanticExactNodeAllPlannableEdgesStrategy.lowering_mode is LoweringMode.DIRECT_GRAPH


def test_lowering_mode_is_orthogonal_to_family() -> None:
    # Both are family=direct in the engine, yet lower differently.
    assert TopologicalSortStrategy.lowering_mode is LoweringMode.DAG_LINEARIZATION
    assert HandlerChainComposerStrategy.lowering_mode is LoweringMode.REGION_COMPOSITION
