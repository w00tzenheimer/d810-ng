"""DEFFAI: k-switch context-sensitive abstract interpretation over a set domain.

Portable implementation of the DEFFAI control-flow-flattening deobfuscation
analysis (Baek & Lee, *Deobfuscation of CFF Based on Abstract Interpretation*,
IEEE TSE 52(3) 2026): a SET/powerset value domain + k-switch context sensitivity,
producing the Context-to-CFG Map (CCM, Algorithm 1) and Context Transition Graph
(CTG, Algorithm 2).

This subpackage is the **portable DEFFAI core** (P3 plan Steps 1-7): the abstract
domain, context representation, set-valued transfer, preprocessing (slicing +
prune blocks), the context-sensitive fixpoint, and CCM/CTG.  It has **zero**
dependency on the P1 ``RecoveredMachine`` contract and **no IDA imports** -- it
runs on the portable :class:`d810.ir.flowgraph.FlowGraph`, exactly as DEFFAI runs
on LLVM bitcode.

The conversion to ``RecoveredMachine`` (``to_recovered_machine``), the engine
(``engine``), the resolver (``resolver``), and k-escalation (``escalation``) are
the P1-gated wiring layers and are added in later steps -- they are intentionally
absent here.

Reuses, rather than re-mints:
* :class:`d810.analyses.control_flow.state_transition_domain.StateValue` -- the
  per-cell powerset (union join, ⊤/⊥, finite-height cap);
* :func:`d810.analyses.data_flow.run_fixpoint` -- the proven monotone worklist
  (widening, convergence guard, per-edge ``assume`` seam).
"""
from __future__ import annotations

from d810.analyses.control_flow.deffai.analysis import (
    AnalysisResult,
    ProductNode,
    analyze_kswitch,
)
from d810.analyses.control_flow.deffai.ccm import CCM, PartialCFG, build_ccm
from d810.analyses.control_flow.deffai.context import ContextPolicy, KContext
from d810.analyses.control_flow.deffai.ctg import CTG, build_ctg, possible_successors
from d810.analyses.control_flow.deffai.powerset_store import PowersetStore
from d810.analyses.control_flow.deffai.preprocess import (
    condvar_cells_of,
    insert_prune_blocks,
    slice_on_condvars,
)
from d810.analyses.control_flow.deffai.transfer import (
    mop_cell,
    scalar_block_evaluator,
    transfer_block_set,
)

__all__ = [
    # domain + context
    "PowersetStore",
    "KContext",
    "ContextPolicy",
    # transfer
    "transfer_block_set",
    "mop_cell",
    "scalar_block_evaluator",
    # preprocess
    "slice_on_condvars",
    "insert_prune_blocks",
    "condvar_cells_of",
    # analysis
    "analyze_kswitch",
    "AnalysisResult",
    "ProductNode",
    # CCM / CTG
    "build_ccm",
    "CCM",
    "PartialCFG",
    "build_ctg",
    "CTG",
    "possible_successors",
]
