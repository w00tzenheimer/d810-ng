#!/usr/bin/env python3
"""Offline SQLite MBA discovery miner and explicit materializer."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from d810.mba.bounded_synthesis import MbaSynthesisBudget
from d810.mba.discovery_miner import DiscoveryMiner, materialize_proposal
from d810.mba.discovery_store import MbaDiscoveryStore


def _nonnegative(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if result < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return result


def _budget(args: argparse.Namespace) -> MbaSynthesisBudget:
    return MbaSynthesisBudget(
        max_atoms=args.max_atoms,
        max_variables=args.max_variables,
        max_candidate_operator_nodes=args.max_candidate_operator_nodes,
        max_generated_terms=args.max_generated_terms,
        max_candidate_attempts=args.max_candidate_attempts,
        witness_count=args.witness_count,
    )


def _add_budget_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--max-atoms", type=_nonnegative, default=4)
    parser.add_argument("--max-variables", type=_nonnegative, default=3)
    parser.add_argument("--max-candidate-operator-nodes", type=_nonnegative, default=4)
    parser.add_argument("--max-generated-terms", type=_nonnegative, default=50_000)
    parser.add_argument("--max-candidate-attempts", type=_nonnegative, default=100_000)
    parser.add_argument("--witness-count", type=_nonnegative, default=96)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    mine = commands.add_parser("mine")
    mine.add_argument("--db", required=True, type=Path)
    mine.add_argument("--limit", type=_nonnegative, default=None)
    _add_budget_flags(mine)
    status = commands.add_parser("status")
    status.add_argument("--db", required=True, type=Path)
    materialize = commands.add_parser("materialize")
    materialize.add_argument("--db", required=True, type=Path)
    materialize.add_argument("--proposal", required=True)
    materialize.add_argument("--output-dir", required=True, type=Path)
    return parser


def _status_json(status: object) -> dict[str, object]:
    return {
        "groups": {state.value: count for state, count in status.group_counts},
        "runs": {state.value: count for state, count in status.run_counts},
        "proposals": {state.value: count for state, count in status.proposal_counts},
        "outstanding_leases": status.outstanding_leases,
        "expired_leases": status.expired_leases,
    }


def _mine(store: MbaDiscoveryStore, args: argparse.Namespace) -> int:
    if args.limit == 0:
        print(json.dumps({"published": 0, "no_proposal": 0, "refused": 0, "errors": 0}, sort_keys=True))
        return 0
    budget = _budget(args)
    miner = DiscoveryMiner(store, budget=budget)
    counts = {"published": 0, "no_proposal": 0, "refused": 0, "errors": 0}
    completed = 0
    while args.limit is None or completed < args.limit:
        claim_receipt = miner.claim()
        if claim_receipt.claim is None:
            if claim_receipt.reason == "no_eligible_group":
                break
            counts["refused"] += 1
            break
        outcome = miner.mine_claim(claim_receipt.claim, budget)
        counts[outcome.status if outcome.status in counts else "errors"] += 1
        completed += 1
    print(json.dumps(counts, sort_keys=True))
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    store: MbaDiscoveryStore | None = None
    try:
        store = MbaDiscoveryStore(args.db)
        if args.command == "mine":
            return _mine(store, args)
        if args.command == "status":
            print(json.dumps(_status_json(store.status_counts()), sort_keys=True))
            return 0
        path, digest = materialize_proposal(store, args.proposal, args.output_dir)
        print(json.dumps({"path": path, "digest": digest}, sort_keys=True))
        return 0
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"mba residual miner: {exc}", file=sys.stderr)
        return 2
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    raise SystemExit(main())
