"""Mine portable MBA residuals into reviewable, proof-certified artifacts.

This command is deliberately offline.  It consumes only the versioned portable
residual corpus and never loads a native provider or registers generated code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from d810.mba.bounded_synthesis import (
    MbaSynthesisBudget,
    MbaSynthesisResult,
    synthesize_residual,
)
from d810.mba.residual_corpus import MbaResidualCorpus, MbaResidualGroup
from d810.mba.rule_proposal import MbaRuleProposal, render_rule_source
from d810.mba.subterm_atomization import AtomizedMbaTerm, atomize_repeated_subterms
from d810.mba.term_codec import typed_term_to_dict


def _nonnegative_int(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if result < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--max-groups", type=_nonnegative_int)
    parser.add_argument("--max-atoms", type=_nonnegative_int, default=4)
    parser.add_argument("--max-variables", type=_nonnegative_int, default=3)
    parser.add_argument("--max-candidate-operator-nodes", type=_nonnegative_int, default=4)
    parser.add_argument("--max-generated-terms", type=_nonnegative_int, default=50_000)
    parser.add_argument("--max-candidate-attempts", type=_nonnegative_int, default=100_000)
    parser.add_argument("--witness-count", type=_nonnegative_int, default=96)
    parser.add_argument("--force", action="store_true")
    return parser


def _read_corpus(path: Path) -> MbaResidualCorpus:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read residual corpus: {exc}") from exc
    if not isinstance(raw, dict):
        raise TypeError("residual corpus must contain a JSON object")
    return MbaResidualCorpus.from_dict(raw)


def _budget(args: argparse.Namespace) -> MbaSynthesisBudget:
    return MbaSynthesisBudget(
        max_atoms=args.max_atoms,
        max_variables=args.max_variables,
        max_candidate_operator_nodes=args.max_candidate_operator_nodes,
        max_generated_terms=args.max_generated_terms,
        max_candidate_attempts=args.max_candidate_attempts,
        witness_count=args.witness_count,
    )


def _synthesis_dict(result: MbaSynthesisResult, budget: MbaSynthesisBudget) -> dict[str, object]:
    exhaustion = result.exhaustion
    return {
        "source_cost": list(result.source_cost),
        "replacement_cost": None if result.replacement_cost is None else list(result.replacement_cost),
        "exhaustion": None
        if exhaustion is None
        else {
            "reason": exhaustion.reason,
            "generated_terms": exhaustion.generated_terms,
            "budget": {
                "max_atoms": budget.max_atoms,
                "max_variables": budget.max_variables,
                "max_candidate_operator_nodes": budget.max_candidate_operator_nodes,
                "max_generated_terms": budget.max_generated_terms,
                "max_candidate_attempts": budget.max_candidate_attempts,
                "witness_count": budget.witness_count,
            },
        },
        "width_relative_all_ones": [
            {
                "origin": item.origin,
                "occurrence_path": list(item.occurrence_path),
                "source_width": item.source_width,
                "terminal_fingerprint": item.terminal_fingerprint,
            }
            for item in result.width_relative_all_ones
        ],
        "fixed_operation_descriptors": [list(item) for item in result.fixed_operation_descriptors],
        "attempt_provenance": {
            "budget": {
                "max_atoms": budget.max_atoms,
                "max_variables": budget.max_variables,
                "max_candidate_operator_nodes": budget.max_candidate_operator_nodes,
                "max_generated_terms": budget.max_generated_terms,
                "max_candidate_attempts": budget.max_candidate_attempts,
                "witness_count": budget.witness_count,
            },
            "certification_widths": [8, 16, 32, 64],
        },
    }


def _proposal_for(
    group: MbaResidualGroup,
    atomized: AtomizedMbaTerm,
    result: MbaSynthesisResult,
    budget: MbaSynthesisBudget,
) -> tuple[MbaRuleProposal, dict[str, object]]:
    if result.replacement is None or not result.certified:
        raise ValueError("cannot create proposal from uncertified synthesis")
    restored = atomized.restore(result.replacement)
    provenance = {
        f"provider:{outcome.provider.value}:{outcome.status.value}"
        for observation in group.observations
        for outcome in observation.outcomes
    }
    provenance.update(f"source:{observation.source.identity}" for observation in group.observations)
    family = "or"
    class_name = "MbaResidualRule_" + hashlib.sha256(group.fingerprint.encode("ascii")).hexdigest()[:12]
    fixture = {
        "source_fingerprint": group.fingerprint,
        "expected_restored_replacement": typed_term_to_dict(restored),
    }
    proposal = MbaRuleProposal(
        proposal_fingerprint=None,
        source_fingerprints=(group.fingerprint,),
        occurrence_count=group.occurrence_count,
        pattern=result.source,
        replacement=result.replacement,
        source_cost=result.source_cost,
        replacement_cost=result.replacement_cost,
        atomization_bindings=atomized.bindings,
        proof_receipts=result.proof_receipts,
        class_name=class_name,
        family=family,
        description="Proof-certified simplification discovered from an MBA residual",
        provenance=tuple(provenance),
        fixture=fixture,
        fixed_operation_descriptors=result.fixed_operation_descriptors,
        synthesis_result=result,
    )
    artifact = {
        "original": typed_term_to_dict(atomized.original_term),
        "atomized": typed_term_to_dict(atomized.atomized_term),
        "certified_atomized_replacement": typed_term_to_dict(result.replacement),
        "restored_replacement": typed_term_to_dict(restored),
        "atomization_bindings": [
            {
                "leaf_key": list(binding.leaf_key),
                "original_subterm": typed_term_to_dict(binding.original_subterm),
                "occurrence_count": binding.occurrence_count,
                "saved_operator_nodes": binding.saved_operator_nodes,
            }
            for binding in atomized.bindings
        ],
        "proof_widths": [receipt.width for receipt in result.proof_receipts],
    }
    manifest = proposal.to_dict()
    # Wall-clock solver timings are intentionally excluded from proposal
    # identity.  Keep the receipt fields present while making this persisted
    # review artifact reproducible across clean runs.
    manifest["proof_receipts"] = [
        {**receipt, "elapsed_ms": 0.0} for receipt in manifest["proof_receipts"]
    ]
    manifest["synthesis"] = _synthesis_dict(result, budget)
    manifest["exhaustion"] = None
    return proposal, {"manifest": manifest, "fixture": artifact}


def _atomic_write(path: Path, content: str) -> None:
    """Write one artifact through a sibling temporary file and replace."""

    fd, raw_tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(raw_tmp)
    try:
        with open(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(content)
            stream.flush()
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)


def _render_outputs(
    output_dir: Path,
    outputs: Sequence[tuple[MbaRuleProposal, dict[str, object]]],
    *,
    force: bool,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    names = []
    for proposal, payload in sorted(outputs, key=lambda item: item[0].fingerprint):
        stem = proposal.fingerprint
        names.extend((f"{stem}.proposal.json", f"{stem}.rule.py", f"{stem}.fixture.json"))
    if not force:
        existing = [name for name in names if (output_dir / name).exists()]
        if existing:
            raise FileExistsError("output already exists; use --force")
    for proposal, payload in sorted(outputs, key=lambda item: item[0].fingerprint):
        stem = proposal.fingerprint
        _atomic_write(output_dir / f"{stem}.proposal.json", json.dumps(payload["manifest"], ensure_ascii=True, indent=2, sort_keys=True) + "\n")
        _atomic_write(output_dir / f"{stem}.rule.py", render_rule_source(proposal))
        _atomic_write(output_dir / f"{stem}.fixture.json", json.dumps(payload["fixture"], ensure_ascii=True, indent=2, sort_keys=True) + "\n")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    output_was_present = args.output_dir.exists()
    try:
        corpus = _read_corpus(args.input)
        budget = _budget(args)
        groups = corpus.groups_for_mining()
        if args.max_groups is not None:
            groups = groups[: args.max_groups]
        outputs: list[tuple[MbaRuleProposal, dict[str, object]]] = []
        for group in groups:
            atomized = atomize_repeated_subterms(group.canonical_term, max_atoms=budget.max_atoms)
            result = synthesize_residual(atomized, budget=budget)
            if result.replacement is None and any(
                receipt.error is not None
                and any(
                    marker in receipt.error.lower()
                    for marker in ("importerror", "modulenotfounderror", "z3")
                )
                for receipt in result.proof_receipts
            ):
                raise RuntimeError("proof backend unavailable")
            if result.certified:
                outputs.append(_proposal_for(group, atomized, result, budget))
        if not outputs:
            return 1
        output_dir = args.output_dir
        _render_outputs(output_dir, outputs, force=args.force)
        return 0
    except (ValueError, TypeError, OSError, RuntimeError, ImportError) as exc:
        if args.output_dir.exists() and not output_was_present:
            try:
                shutil.rmtree(args.output_dir)
            except OSError:
                pass
        print(f"mba residual miner: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
