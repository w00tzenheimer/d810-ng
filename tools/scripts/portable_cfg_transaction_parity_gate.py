#!/usr/bin/env python3
"""Validate the executable donor-to-integration CFG transaction parity ledger."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import NamedTuple


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LEDGER = Path(__file__).with_name("portable_cfg_transaction_parity_ledger.json")
VALID_STATUSES = frozenset({"accepted", "partial", "missing"})
REQUIRED_GUARANTEE_IDS = (
    "nominal_plan_block_identity",
    "attempt_authority_scope",
    "participant_protocol_complete",
    "plan_neutral_cfg_projection",
    "synthetic_focus_full_graph_validation",
    "production_cfg_contract_projection",
    "synthetic_reservation_prewrite",
    "exact_sdk_return_binding",
    "creation_receipt_atomicity",
    "abort_replay_identity",
    "observed_ephemeral_separation",
    "immutable_fragment_snapshot",
    "pure_preflight_zero_write",
    "exact_single_use_preflight_authority",
    "prepared_payload_shape_authority",
    "production_fragment_participant",
    "partial_write_poison",
    "shared_generation_poison_latch",
    "lifecycle_poison_restart",
    "poison_budget_exhaustion",
    "changed_facts_new_epoch",
    "transaction_phase_events",
    "cfg_transaction_attempt_persistence",
    "cfg_creation_witness_persistence",
    "first_failure_monotonicity",
    "typed_patch_block_refs",
    "final_boundary_binding",
    "prewrite_binding_cleanup",
    "no_serial_compatibility_channels",
    "helper_creation_witnesses",
    "compiler_snapshot_authority",
    "fragment_to_patch_lowering",
    "shared_transaction_coordinator",
    "observed_postroot_contract",
    "sole_mutation_entrypoint",
    "no_snapshot_block_ref",
    "exact_transaction_authority",
    "terminal_tail_preflight_parity",
    "focused_transaction_gate",
    "creation_witness_c5_canary",
    "protected_family_behavior_preserved",
)


class AuditReport(NamedTuple):
    errors: tuple[str, ...]
    pending_ids: tuple[str, ...]
    passed: bool


def load_ledger(path: Path = DEFAULT_LEDGER) -> dict[str, object]:
    """Load one ledger without mutating either checkout."""
    return json.loads(path.read_text(encoding="utf-8"))


def _reference_parts(reference: object, *, field: str) -> tuple[str, str]:
    if not isinstance(reference, str) or "::" not in reference:
        raise ValueError(f"{field} must use path::anchor syntax")
    path, anchor = reference.split("::", 1)
    if not path.strip() or not anchor.strip():
        raise ValueError(f"{field} must contain a nonblank path and anchor")
    return path, anchor


def _git_show(repo_root: Path, commit: str, path: str) -> str:
    result = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=repo_root,
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or "git show failed"
        raise ValueError(f"{commit}:{path}: {detail}")
    return result.stdout


def _check_reference(
    reference: object,
    *,
    field: str,
    text_loader,
) -> str | None:
    try:
        path, anchor = _reference_parts(reference, field=field)
        text = text_loader(path)
    except (OSError, ValueError) as exc:
        return f"{field}: {exc}"
    if anchor not in text:
        return f"{field}: anchor {anchor!r} is absent from {path}"
    return None


def _validate_diagnostic_proof(value: object, *, guarantee_id: str) -> list[str]:
    if not isinstance(value, dict):
        return [f"{guarantee_id}: diagnostic_proof must be an object"]
    errors: list[str] = []
    tables = value.get("tables")
    events = value.get("events")
    assertion = value.get("assertion")
    if (
        not isinstance(tables, list)
        or not tables
        or not all(isinstance(item, str) and item.strip() for item in tables)
    ):
        errors.append(f"{guarantee_id}: diagnostic_proof.tables must be nonempty")
    if (
        not isinstance(events, list)
        or not events
        or not all(isinstance(item, str) and item.strip() for item in events)
    ):
        errors.append(f"{guarantee_id}: diagnostic_proof.events must be nonempty")
    if not isinstance(assertion, str) or not assertion.strip():
        errors.append(f"{guarantee_id}: diagnostic_proof.assertion must be nonblank")
    return errors


def audit_ledger(
    ledger: dict[str, object],
    *,
    repo_root: Path = REPO_ROOT,
    require_integrated: bool = False,
) -> AuditReport:
    """Validate schema, donor authority, live seams, and acceptance anchors."""
    errors: list[str] = []
    pending: list[str] = []
    donor = ledger.get("donor")
    if not isinstance(donor, dict):
        return AuditReport(("donor must be an object",), (), False)
    commit = donor.get("commit")
    if not isinstance(commit, str) or len(commit) != 40:
        return AuditReport(("donor.commit must be a full 40-character SHA",), (), False)

    guarantees = ledger.get("guarantees")
    if not isinstance(guarantees, list):
        return AuditReport(("guarantees must be a list",), (), False)

    current_loader = lambda path: (repo_root / path).read_text(encoding="utf-8")
    donor_loader = lambda path: _git_show(repo_root, commit, path)
    seen: set[str] = set()

    for index, entry in enumerate(guarantees):
        prefix = f"guarantees[{index}]"
        if not isinstance(entry, dict):
            errors.append(f"{prefix} must be an object")
            continue
        guarantee_id = entry.get("id")
        if not isinstance(guarantee_id, str) or not guarantee_id.strip():
            errors.append(f"{prefix}.id must be nonblank")
            continue
        if guarantee_id in seen:
            errors.append(f"duplicate guarantee id: {guarantee_id}")
        seen.add(guarantee_id)

        status = entry.get("current_status")
        if status not in VALID_STATUSES:
            errors.append(
                f"{guarantee_id}: current_status must be one of "
                f"{sorted(VALID_STATUSES)}"
            )
        if status != "accepted":
            pending.append(guarantee_id)

        for field in ("required_port",):
            value = entry.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{guarantee_id}: {field} must be nonblank")

        for field in ("donor_source", "donor_test"):
            error = _check_reference(
                entry.get(field),
                field=f"{guarantee_id}.{field}",
                text_loader=donor_loader,
            )
            if error is not None:
                errors.append(error)

        error = _check_reference(
            entry.get("current_production_seam"),
            field=f"{guarantee_id}.current_production_seam",
            text_loader=current_loader,
        )
        if error is not None:
            errors.append(error)

        acceptance = entry.get("acceptance_test")
        if not isinstance(acceptance, dict):
            errors.append(f"{guarantee_id}: acceptance_test must be an object")
        else:
            donor_error = _check_reference(
                acceptance.get("donor"),
                field=f"{guarantee_id}.acceptance_test.donor",
                text_loader=donor_loader,
            )
            if donor_error is not None:
                errors.append(donor_error)
            current_ref = acceptance.get("current")
            try:
                _reference_parts(
                    current_ref,
                    field=f"{guarantee_id}.acceptance_test.current",
                )
            except ValueError as exc:
                errors.append(str(exc))
            else:
                if status == "accepted":
                    current_error = _check_reference(
                        current_ref,
                        field=f"{guarantee_id}.acceptance_test.current",
                        text_loader=current_loader,
                    )
                    if current_error is not None:
                        errors.append(current_error)

        errors.extend(
            _validate_diagnostic_proof(
                entry.get("diagnostic_proof"),
                guarantee_id=guarantee_id,
            )
        )

    required = set(REQUIRED_GUARANTEE_IDS)
    missing = sorted(required - seen)
    unexpected = sorted(seen - required)
    if missing:
        errors.append(f"required guarantee ids missing: {', '.join(missing)}")
    if unexpected:
        errors.append(f"unexpected guarantee ids: {', '.join(unexpected)}")

    passed = not errors and (not require_integrated or not pending)
    return AuditReport(tuple(errors), tuple(pending), passed)


def _json_payload(report: AuditReport) -> dict[str, object]:
    return {
        "errors": list(report.errors),
        "pending_ids": list(report.pending_ids),
        "passed": report.passed,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--require-integrated", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    try:
        ledger = load_ledger(args.ledger)
        report = audit_ledger(
            ledger,
            repo_root=args.repo_root,
            require_integrated=args.require_integrated,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(_json_payload(report), indent=2, sort_keys=True))
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        if report.pending_ids:
            print("Pending runtime guarantees:")
            for guarantee_id in report.pending_ids:
                print(f"  {guarantee_id}")
        if report.passed:
            print("Portable CFG transaction parity ledger: PASS")
        elif not report.errors:
            print("Portable CFG transaction parity ledger: INCOMPLETE")
    return 0 if report.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
