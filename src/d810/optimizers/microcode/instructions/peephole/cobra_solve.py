"""Solver-backed MBA simplification as a d810 instruction rule.

Why a rule rather than a block walk
-----------------------------------
An earlier version walked the blocks itself and installed replacements with
``ins.swap()`` + ``mark_lists_dirty()``.  That passes ``mba.verify(True)`` on a
standalone ``mba`` from ``gen_microcode``, but a *live* decompilation with the
same rewrites returns ``None``: a structurally valid mba is not the same thing
as one the decompiler will consume.

The framework contract avoids the whole class of problem -- ``check_and_replace``
**returns** a replacement and the optimizer installs it, so Hex-Rays owns the
swap, the invalidation and the maturity scheduling.

What this costs
---------------
The rule sees one instruction at a time, so the cross-instruction def-use
inlining the standalone detector used is not available here.  Nested ``mop_d``
sub-trees are still followed, which is where Hex-Rays has already folded
sub-expressions, so the reach is narrower but not nothing.  Measure before
assuming which matters more.
"""

from __future__ import annotations

import ida_hexrays

from d810.backends.cobra.convert import ReconstructionError, build_replacement
from d810.backends.cobra.detect import (
    DEFAULT_MAX_LEAVES,
    MbaCandidate,
    UnsupportedMicrocode,
    _TreeBuilder,
    _walk,
)
from d810.backends.cobra.expr import accept_rewrite, node_count
from d810.backends.cobra.prove import ProofResult, prove_equivalent
from d810.backends.cobra.solve import (
    SolveStatus,
    binding_available,
    solve_signature,
)
from d810.core import getLogger
from d810.optimizers.microcode.instructions.peephole.handler import (
    PeepholeSimplificationRule,
)

logger = getLogger(__name__)

_BOOL_OPS = frozenset({"~", "|", "&", "^"})
_ARITH_OPS = frozenset({"-", "+", "*"})
_LEAF_TYPES = frozenset(
    {ida_hexrays.mop_r, ida_hexrays.mop_l, ida_hexrays.mop_S, ida_hexrays.mop_v}
)


class CobraSolveRule(PeepholeSimplificationRule):
    """Simplify an MBA expression with the CoBRA solver, gated on a Z3 proof."""

    DESCRIPTION = "Solve MBA expressions with CoBRA (proof-gated)"
    CATEGORY = "MBA Solving"

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        # GLBOPT1 is where the candidates were measured; by GLBOPT2 Hex-Rays
        # has already folded much of what this targets (55 candidates at
        # GLBOPT1 versus 10 at GLBOPT2).
        #
        # MMAT_CALLS is a MEASURED PROBLEM, not a free extra maturity.  On
        # VM_DecryptPacket it applied 61 rewrites but consumed 87.6 minutes
        # without finishing, so GLBOPT1 was never reached at all -- every one
        # of those 61 was at MMAT_CALLS.  The cost is the inline Z3 proof
        # (prove.DEFAULT_TIMEOUT_MS is 120s and 24 of 78 accepted rewrites did
        # not come back PROVED).  Do not treat this list as tuned until proving
        # is off the critical path.
        self.maturities = [
            ida_hexrays.MMAT_CALLS,
            ida_hexrays.MMAT_GLBOPT1,
        ]
        self.max_leaves = DEFAULT_MAX_LEAVES
        self.require_proof = True

    def configure(self, kwargs) -> None:
        super().configure(kwargs)
        self.max_leaves = int(self.config.get("max_leaves", DEFAULT_MAX_LEAVES))
        self.require_proof = bool(self.config.get("require_proof", True))

    def check_and_replace(self, blk, ins):
        if not binding_available():
            return None

        builder = _TreeBuilder()
        try:
            tree = builder.instruction(ins)
        except UnsupportedMicrocode:
            return None
        if tree["kind"] not in ("bin", "un"):
            return None

        names: list[str] = []
        ops: list[str] = []
        _walk(tree, names, ops)
        if not any(o in _BOOL_OPS for o in ops) or not any(
            o in _ARITH_OPS for o in ops
        ):
            return None
        if not names or len(names) > self.max_leaves:
            return None

        dest_size = ins.d.size if ins.d is not None else 0
        if dest_size not in (1, 2, 4, 8):
            return None
        # Uniform widths only: a leaf narrower than the destination produces
        # mixed operand sizes that IDA's verifier rejects.
        if any(builder.snapshots[n].size != dest_size for n in names):
            return None

        candidate = MbaCandidate(
            ea=ins.ea,
            block_serial=blk.serial if blk is not None else 0,
            tree=tree,
            leaf_names=tuple(names),
            leaf_snapshots={n: builder.snapshots[n] for n in names},
            dest_size=dest_size,
        )

        result = solve_signature(
            candidate.tree, candidate.leaf_names, candidate.bitwidth
        )
        if getattr(result.status, "value", None) != SolveStatus.SOLVED.value \
                or result.tree is None:
            return None

        # Accept before proving: a rejected rewrite is never used, so proving
        # it first is pure waste.
        if not accept_rewrite(candidate.tree, result.tree):
            return None

        if self.require_proof:
            verdict = prove_equivalent(
                candidate.tree,
                result.tree,
                candidate.leaf_names,
                candidate.bitwidth,
            )
            # Compare by value: d810's reload machinery can leave two distinct
            # ProofResult classes in one process, and `is` then fails for a
            # verdict that really is PROVED.
            if getattr(verdict, "value", None) != ProofResult.PROVED.value:
                if getattr(verdict, "value", None) == ProofResult.REFUTED.value:
                    logger.warning(
                        "cobra-solve REFUTED a rewrite at %#x; not applying", ins.ea
                    )
                return None

        try:
            out = build_replacement(candidate, result.tree, ins)
            logger.info(
                "cobra-solve applied @ %#x  %d -> %d nodes",
                ins.ea, candidate.node_count, node_count(result.tree),
            )
            return out
        except ReconstructionError as exc:
            logger.debug("cobra-solve could not rebuild %#x: %s", ins.ea, exc)
            return None
