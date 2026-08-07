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
from d810.backends.cobra.escalate import EscalationProver
from d810.backends.cobra.expr import accept_rewrite, node_count
from d810.backends.cobra.prove import (
    INLINE_TIMEOUT_MS,
    ProofResult,
    prove_equivalent,
)
from d810.backends.cobra.table import Outcome, RewriteTable
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
        # One table and one escalator per rule instance. Both are pure-data and
        # carry no IDA reference, so the worker thread never reaches Hex-Rays.
        #
        # NOT started here. d810's reload machinery leaves several distinct
        # copies of a class in one process, and rules are constructed whether
        # or not a project activates them -- starting in __init__ would spawn a
        # worker thread per dead copy.
        self.table = RewriteTable()
        self.escalator = EscalationProver(self.table)

    def configure(self, kwargs) -> None:
        super().configure(kwargs)
        self.max_leaves = int(self.config.get("max_leaves", DEFAULT_MAX_LEAVES))
        self.require_proof = bool(self.config.get("require_proof", True))
        # Only an activated rule gets configured, so this is the first point at
        # which a worker is known to be wanted. start() is idempotent.
        self.escalator.start()

    def log_stats(self) -> None:
        """Report table accounting.

        The intra-run hit rate is the number this whole design was missing: the
        0% tree reuse measured earlier came from a single-pass offline
        detection, which by construction cannot repeat.  The live rule is
        re-invoked on the same addresses as Hex-Rays re-optimises (61
        applications across 44 EAs), so this is where reuse actually shows up.
        """
        s = self.table.stats
        logger.info(
            "cobra-solve table: lookups=%d hits=%d negative=%d pending=%d "
            "misses=%d balanced=%s",
            s.lookups, s.hits, s.negative_hits, s.pending_hits, s.misses,
            s.balanced,
        )

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

        # --- tier 1: the table. A hit skips BOTH solving and proving. -------
        entry = self.table.lookup(candidate.tree, candidate.bitwidth)
        if entry is not None:
            outcome = getattr(entry.outcome, "value", None)
            if outcome != Outcome.PROVED.value:
                # NO_REWRITE: settled, nothing better exists.
                # PENDING: the escalation prover owns it; asking again this
                # pass would just re-solve work already in flight.
                return None
            return self._install(candidate, entry.rewrite, ins)

        # --- tier 2: solve, then accept, then a BOUNDED proof ---------------
        result = solve_signature(
            candidate.tree, candidate.leaf_names, candidate.bitwidth
        )
        if getattr(result.status, "value", None) != SolveStatus.SOLVED.value \
                or result.tree is None:
            # Negative caching is what stops this candidate being re-solved on
            # every pass; 46 of 60 measured candidates end here.
            self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
            return None

        # Accept before proving: a rejected rewrite is never used, so proving
        # it first is pure waste.
        if not accept_rewrite(candidate.tree, result.tree):
            self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
            return None

        if self.require_proof:
            verdict = prove_equivalent(
                candidate.tree,
                result.tree,
                candidate.leaf_names,
                candidate.bitwidth,
                timeout_ms=INLINE_TIMEOUT_MS,
            )
            # Compare by value: d810's reload machinery can leave two distinct
            # ProofResult classes in one process, and `is` then fails for a
            # verdict that really is PROVED.
            value = getattr(verdict, "value", None)
            if value == ProofResult.REFUTED.value:
                logger.warning(
                    "cobra-solve REFUTED a rewrite at %#x; not applying", ins.ea
                )
                self.table.record_no_rewrite(candidate.tree, candidate.bitwidth)
                return None
            if value != ProofResult.PROVED.value:
                # --- tier 3: starved, not disproved. Hand it to the off-path
                # prover and skip it this pass. Measured, this is where the
                # expensive minority goes: 98% of proof time sat in 4 of 14
                # proofs, the worst at 93.6s.
                self.escalator.submit(
                    candidate.tree,
                    candidate.bitwidth,
                    result.tree,
                    candidate.leaf_names,
                )
                return None

        self.table.record_proved(candidate.tree, candidate.bitwidth, result.tree)
        return self._install(candidate, result.tree, ins)

    def _install(self, candidate, rewrite, ins):
        if rewrite is None:
            return None
        try:
            out = build_replacement(candidate, rewrite, ins)
            logger.info(
                "cobra-solve applied @ %#x  %d -> %d nodes",
                ins.ea, candidate.node_count, node_count(rewrite),
            )
            return out
        except ReconstructionError as exc:
            logger.debug("cobra-solve could not rebuild %#x: %s", ins.ea, exc)
            return None
