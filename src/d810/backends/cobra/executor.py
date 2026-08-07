"""Run the whole mba-solve pipeline over one function's microcode.

    detect -> solve -> accept -> prove -> reconstruct -> install

Every stage can refuse, and refusing is always safe: the instruction is left
exactly as it was. The pipeline never trades correctness for yield.

The gates, and why each exists:

* **prove** -- sampling is a filter, not a proof, and the solver cannot be its
  own oracle: a bug that cripples CoBRA's internal verification is invisible to
  it by construction. Measured -- passing a null input expression produced 49
  wrong rewrites that ``mba.verify()`` accepted, CoBRA's own spot-check passed,
  and only Z3 refused. With ``require_proof`` an UNKNOWN verdict is treated as
  failure, so the solver timeout is a yield control rather than a soundness
  risk.

  Proving runs AFTER accept, because a rejected rewrite is never applied and
  proving it is pure waste.
* **accept** -- CoBRA is a canonicaliser, not a shrinker: 26 of 55 rewrites
  measured LARGER than their input. Taking the smaller of the two makes
  regression impossible by construction.
* **install** -- invalidates the block's cached dataflow lists, without which
  ``mba.verify()`` fails with INTERR 50877 "wrong dnu".
"""

from __future__ import annotations

import collections
import dataclasses

from d810.backends.cobra.convert import (
    ReconstructionError,
    build_replacement,
    install_rewrite,
)
from d810.backends.cobra.detect import DEFAULT_MAX_LEAVES, detect_candidates
from d810.backends.cobra.expr import accept_rewrite, node_count
from d810.backends.cobra.probe import CobraProbe, find_cobra_cli
from d810.backends.cobra.prove import ProofResult, prove_equivalent
from d810.backends.cobra.solve import (
    SolveStatus,
    binding_available,
    solve_expression,
    solve_signature,
)
from d810.core import getLogger

logger = getLogger(__name__)


@dataclasses.dataclass
class SolveReport:
    """What happened, in enough detail to tell a miss from a refusal."""

    candidates: int = 0
    solved: int = 0
    unchanged: int = 0
    solver_failed: int = 0
    proved: int = 0
    refuted: int = 0
    proof_unknown: int = 0
    rejected_not_smaller: int = 0
    reconstruct_failed: int = 0
    applied: int = 0
    solver: str = "none"
    nodes_before: int = 0
    nodes_after: int = 0
    detect_reasons: collections.Counter = dataclasses.field(
        default_factory=collections.Counter
    )

    @property
    def node_reduction(self) -> float:
        if not self.nodes_before:
            return 0.0
        return 100.0 * (self.nodes_before - self.nodes_after) / self.nodes_before

    def summary(self) -> str:
        return (
            f"solver={self.solver} candidates={self.candidates} solved={self.solved} "
            f"proved={self.proved} applied={self.applied} "
            f"nodes {self.nodes_before}->{self.nodes_after} "
            f"({self.node_reduction:+.1f}%)"
        )


def run_mba_solve(
    mba,
    *,
    max_leaves: int = DEFAULT_MAX_LEAVES,
    require_proof: bool = True,
    probe: CobraProbe | None = None,
    apply_changes: bool = True,
) -> SolveReport:
    """Solve and (optionally) apply MBA simplifications across *mba*."""
    report = SolveReport()

    # Prefer the in-process binding. It is not merely faster (~0.04 ms/solve
    # versus a process spawn): it takes a signature rather than rendered text,
    # returns an Expr tree rather than text to re-parse, and can express shifts,
    # which cobra-cli's tokenizer cannot. The CLI stays reachable as a fallback
    # and as an independent oracle for parity tests.
    use_binding = binding_available()
    active_probe = probe if probe is not None else find_cobra_cli()
    if not use_binding and not active_probe.available:
        logger.info("mba-solve skipped: %s", active_probe.reason)
        return report
    report.solver = "binding" if use_binding else "cli"

    candidates, reasons = detect_candidates(mba, max_leaves=max_leaves)
    report.candidates = len(candidates)
    report.detect_reasons = reasons
    if not candidates:
        logger.debug("mba-solve found no candidates")
        return report

    # Index instructions by ea so a candidate can be matched back to the
    # instruction it came from without holding a borrowed reference.
    for candidate in candidates:
        block = mba.get_mblock(candidate.block_serial)
        target = _find_instruction(block, candidate.ea)
        if target is None:
            continue

        if use_binding:
            result = solve_signature(
                candidate.tree, candidate.leaf_names, candidate.bitwidth
            )
        else:
            result = solve_expression(
                active_probe,
                candidate.render(),
                candidate.bitwidth,
                candidate.leaf_names,
            )
        if result.status is SolveStatus.UNCHANGED:
            report.unchanged += 1
            continue
        if not result.solved or result.tree is None:
            report.solver_failed += 1
            logger.debug("mba-solve solver failed at %#x: %s", candidate.ea,
                         result.reason)
            continue
        report.solved += 1

        # Accept BEFORE proving. Proving is the expensive gate and a rejected
        # rewrite is never applied, so proving first pays for verdicts that are
        # then thrown away -- on VM_DecryptPacket that was 21 of 33 proofs
        # wasted. Reordering changes nothing about what gets applied.
        if not accept_rewrite(candidate.tree, result.tree):
            report.rejected_not_smaller += 1
            continue

        if require_proof:
            verdict = prove_equivalent(
                candidate.tree,
                result.tree,
                candidate.leaf_names,
                candidate.bitwidth,
            )
            if verdict is ProofResult.PROVED:
                report.proved += 1
            elif verdict is ProofResult.REFUTED:
                # The solver returned something that is not equivalent. Loud,
                # because it means a modelling bug on one side or the other.
                report.refuted += 1
                logger.warning(
                    "mba-solve REFUTED a rewrite at %#x; not applying", candidate.ea
                )
                continue
            else:
                report.proof_unknown += 1
                logger.debug(
                    "mba-solve proof %s at %#x; not applying",
                    verdict.value,
                    candidate.ea,
                )
                continue

        try:
            replacement = build_replacement(candidate, result.tree, target)
        except ReconstructionError as exc:
            report.reconstruct_failed += 1
            logger.debug("mba-solve could not rebuild %#x: %s", candidate.ea, exc)
            continue

        report.nodes_before += candidate.node_count
        report.nodes_after += node_count(result.tree)

        if apply_changes:
            install_rewrite(block, target, replacement)
        report.applied += 1

    if report.applied:
        logger.info("mba-solve: %s", report.summary())
    return report


def _find_instruction(block, ea: int):
    ins = block.head
    while ins is not None:
        if ins.ea == ea:
            return ins
        ins = ins.next
    return None
