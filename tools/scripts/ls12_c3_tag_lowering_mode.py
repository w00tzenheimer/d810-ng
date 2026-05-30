#!/usr/bin/env python3
"""LS12 C3: tag the 8 lowering strategy classes with a read-only ``lowering_mode``
class attribute (ticket d81-wgqz). Behavior-neutral: adds an import + a class-level
constant; these are plain classes (not dataclasses), so no field/__init__ change.
Idempotent + anchored (exactly-one match asserted). --apply to write."""
from __future__ import annotations

import argparse
from pathlib import Path

ROOT = Path("src/d810/optimizers/microcode/flow/flattening/hodur")
IMPORT = "from d810.transforms.lowering import LoweringMode"

# (relpath, import_anchor, [(attr_old, attr_new), ...])
EDITS: tuple[tuple[str, str, list[tuple[str, str]]], ...] = (
    ("strategies/topological_sort.py", "from d810.core import logging", [(
        '    Must run AFTER LinearizedFlowGraphStrategy (prerequisites guard).\n    """\n\n    prerequisites: list[str] = ["linearized_flow_graph"]',
        '    Must run AFTER LinearizedFlowGraphStrategy (prerequisites guard).\n    """\n\n    lowering_mode = LoweringMode.DAG_LINEARIZATION\n    prerequisites: list[str] = ["linearized_flow_graph"]',
    )]),
    ("strategies/handler_chain_composer.py", "from d810.core.typing import TYPE_CHECKING", [(
        '    regression isolation.\n    """\n\n    # CLASS-LEVEL GATE: HCC is the default live Hodur reconstruction path.',
        '    regression isolation.\n    """\n\n    lowering_mode = LoweringMode.REGION_COMPOSITION\n    # CLASS-LEVEL GATE: HCC is the default live Hodur reconstruction path.',
    )]),
    ("strategies/exact_conditional_node.py", "from d810.core import logging", [(
        'class ExactConditionalNodeLoweringStrategy:\n    """Lower exact conditional sites by owning both exits together."""\n\n    prerequisites: list[str] = []',
        'class ExactConditionalNodeLoweringStrategy:\n    """Lower exact conditional sites by owning both exits together."""\n\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    prerequisites: list[str] = []',
    )]),
    ("strategies/exact_conditional_alias.py", "from d810.core import logging", [(
        'class ExactConditionalAliasNodeLoweringStrategy:\n    prerequisites: list[str] = []',
        'class ExactConditionalAliasNodeLoweringStrategy:\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    prerequisites: list[str] = []',
    )]),
    ("strategies/exact_conditional_fork.py", "from d810.core import logging", [(
        'class ExactConditionalForkNodeLoweringStrategy:\n    prerequisites: list[str] = []',
        'class ExactConditionalForkNodeLoweringStrategy:\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    prerequisites: list[str] = []',
    )]),
    ("prototypes/exact_conditional_bridge.py", "from d810.core import logging", [(
        'class ExactConditionalBridgeNodeLoweringStrategy:\n    """Prototype strategy for mixed-shape exact conditional bridge sites."""\n\n    prerequisites: list[str] = []',
        'class ExactConditionalBridgeNodeLoweringStrategy:\n    """Prototype strategy for mixed-shape exact conditional bridge sites."""\n\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    prerequisites: list[str] = []',
    )]),
    ("strategies/semantic_exact_node.py", "from d810.core import logging", [(
        'class _SemanticExactNodeExperimentStrategy:\n    """Emit DAG redirects for selected semantic edges."""\n\n    prerequisites: list[str] = []',
        'class _SemanticExactNodeExperimentStrategy:\n    """Emit DAG redirects for selected semantic edges."""\n\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    prerequisites: list[str] = []',
    )]),
    ("strategies/linearized_flow_graph.py",
     "from d810.hexrays.utils.hexrays_formatters import maturity_to_string", [
        (
            'class LinearizedFlowGraphStrategy:\n    """Emit DAG-selected redirect edits for branch-anchored handler exits."""\n\n    _MAX_PROJECTED_PLANNING_ROUNDS = 4',
            'class LinearizedFlowGraphStrategy:\n    """Emit DAG-selected redirect edits for branch-anchored handler exits."""\n\n    lowering_mode = LoweringMode.DIRECT_GRAPH\n    _MAX_PROJECTED_PLANNING_ROUNDS = 4',
        ),
        (
            'class SemanticStructuredRegionStrategy(LinearizedFlowGraphStrategy):\n    """Region-first variant of LFG that disables raw plannable-edge lowering."""\n\n    @property\n    def name(self) -> str:',
            'class SemanticStructuredRegionStrategy(LinearizedFlowGraphStrategy):\n    """Region-first variant of LFG that disables raw plannable-edge lowering."""\n\n    lowering_mode = LoweringMode.STRUCTURED_REGION\n\n    @property\n    def name(self) -> str:',
        ),
    ]),
)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    ok = True
    for rel, import_anchor, attrs in EDITS:
        path = ROOT / rel
        text = path.read_text(encoding="utf-8")
        orig = text
        # import (idempotent)
        if IMPORT not in text:
            if text.count(import_anchor) != 1:
                print(f"  FAIL {rel}: import anchor count != 1"); ok = False; continue
            text = text.replace(import_anchor, f"{import_anchor}\n{IMPORT}", 1)
        # class attrs
        for old, new in attrs:
            if new in text:
                print(f"  SKIP {rel}: attr already present"); continue
            if text.count(old) != 1:
                print(f"  FAIL {rel}: attr anchor count={text.count(old)} != 1"); ok = False; continue
            text = text.replace(old, new, 1)
        if text == orig:
            print(f"  noop {rel}"); continue
        print(f"  {'tag' if args.apply else 'would tag'} {rel}")
        if args.apply:
            path.write_text(text, encoding="utf-8")
    print("OK" if ok else "SOME FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
