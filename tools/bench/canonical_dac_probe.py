"""Observation-only pytest plugin for the exact DAC/Reference qualification leg."""

from __future__ import annotations

import hashlib
import contextlib
import functools
import importlib
import json
import os
from pathlib import Path
import time

import pytest

BASE_PROJECT = "eidolon_v4_const_simplify_solve.json"


def capture_project_names(environ=None):
    """Return the explicitly routed original and actual capture projects."""
    source = os.environ if environ is None else environ
    original = source.get("D810_CANONICAL_DAC_ORIGINAL_PROJECT", BASE_PROJECT)
    target = source.get("D810_CANONICAL_DAC_PROJECT", original)
    return original, target


PROJECT = capture_project_names()[1]
NODE = "tests/system/e2e/test_libdeobfuscated_dsl.py::TestDacMasmFixtures::test_dac_masm_fixtures[range_leaf_isolated_state]"
POSITIVE_NODE = "tests/system/e2e/test_canonical_reference_qualification.py::TestCanonicalReferenceQualification::test_positive_xor"
POSITIVE_XOR_RETAINED = """__int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
{
    *a4 = a2 ^ a1;
    a4[1] = (a2 - 3) ^ (a3 * a1);
    return (unsigned int)(a4[1] + *a4);
}"""
POSITIVE_XOR_ALTERNATIVE = """__int64 __fastcall test_xor(int a1, int a2, int a3, int *a4)
{
    *a4 = a2 ^ a1;
    a4[1] = (a3 * a1) ^ (a2 - 3);
    return (unsigned int)(a4[1] + *a4);
}"""
LEDGER_FIELDS = (
    "observation_count",
    "legacy_match_count",
    "legacy_rule_mismatches",
    "legacy_binding_mismatches",
    "legacy_binding_unknown",
    "new_safe_coverage_pending",
    "new_safe_coverage_proved",
    "unsafe_mutations",
    "unproved_structural_replacements",
)
FEASIBILITY_FIELDS = (
    "candidate_fact_constructions",
    "candidate_fact_operands",
    "template_fact_constructions",
    "template_fact_requirements",
    "predicate_comparisons",
    "rejected_candidates",
    "surviving_candidates",
    "unknown_candidates",
)
WIDENED_BOOLEAN_WITNESS_EA = 0x180013423
WIDENED_BOOLEAN_WITNESS_RULES = frozenset(
    {"BnotXor_FactorRule_1", "Bnot_FactorRule_5"}
)
WIDENED_BOOLEAN_CAPTURE_CAPACITY = 8


def routed_project_name(requested, environ=None):
    """Route only the explicitly named original project in measurement mode."""
    source = os.environ if environ is None else environ
    original, target = capture_project_names(source)
    return (
        target
        if source.get("D810_CANONICAL_DAC_PROJECT") and requested == original
        else requested
    )


def new_activation_summary():
    return {
        "call_count": 0,
        "match_count": 0,
        "comparison_count": 0,
        "exhaustion_count": 0,
        "stop_reason_counts": {},
        "counter_scope": {
            "denominator": "canonical_iterator_invocation",
            "comparison_count": "sum_per_invocation",
            "exhaustion_count": "invocations_stopped_by_comparison_budget",
            "shared_instruction_budget": (
                "multiple invocations may belong to one instruction attempt"
            ),
        },
    }


def accumulate_activation_summary(summary, *, comparisons, stop_reason, matched):
    if type(comparisons) is not int or comparisons < 0:
        raise ValueError("invalid canonical comparison count")
    reason = "none" if stop_reason is None else str(stop_reason)
    summary["call_count"] += 1
    summary["match_count"] += matched is True
    summary["comparison_count"] += comparisons
    summary["exhaustion_count"] += stop_reason == "comparison_budget"
    counts = summary["stop_reason_counts"]
    counts[reason] = counts.get(reason, 0) + 1


def positive_xor_outputs_equivalent(actual, expected):
    """Accept only the independently proved, full-output XOR operand swap."""
    return actual == expected or (
        actual == POSITIVE_XOR_ALTERNATIVE and expected == POSITIVE_XOR_RETAINED
    )


def accepted_enrolled_receipt(adapter, outcome, *, input_ea):
    matcher = getattr(outcome, "matcher", None)
    selection = getattr(getattr(matcher, "selection", None), "value", None)
    return {
        "rule": adapter.name,
        "rule_id": getattr(adapter, "_certified_catalogue_rule_id", None),
        "route": (
            "canonical_fallback"
            if selection == "canonical_fallback"
            else "raw_base"
            if selection == "raw"
            else "unknown"
        ),
        "candidate_count": len(adapter.pattern_candidates),
        "outcome_status": getattr(getattr(outcome, "status", None), "value", None),
        "matcher_selection": selection,
        "input_ea": input_ea,
        "provider_fingerprint": getattr(outcome, "fingerprint", None),
    }


def candidate_ea_patch_methods(
    *,
    adapter_type,
    original_set_pending,
    original_accepted,
    original_rejected,
    record_accepted,
):
    """Carry one scalar candidate EA across native context release."""
    retained = {}

    @functools.wraps(original_set_pending)
    def observed_set_pending(optimizer, rule, *args, **kwargs):
        retained.pop(id(optimizer), None)
        result = original_set_pending(optimizer, rule, *args, **kwargs)
        outcome = getattr(rule, "_last_provider_outcome", None)
        if (
            isinstance(rule, adapter_type)
            and getattr(optimizer, "_pending_replacement_rule", None) is rule
            and getattr(getattr(outcome, "status", None), "value", None)
            == "improved"
        ):
            ea = getattr(getattr(rule, "_attempt_instruction", None), "ea", None)
            retained[id(optimizer)] = (
                id(rule),
                ea if type(ea) is int else None,
            )
        return result

    @functools.wraps(original_accepted)
    def observed_accepted(optimizer, *args, **kwargs):
        rule = getattr(optimizer, "_pending_replacement_rule", None)
        correlated = retained.pop(id(optimizer), None)
        input_ea = (
            correlated[1]
            if correlated is not None
            and rule is not None
            and correlated[0] == id(rule)
            else None
        )
        result = original_accepted(optimizer, *args, **kwargs)
        if isinstance(rule, adapter_type):
            record_accepted(
                rule,
                getattr(rule, "_last_provider_outcome", None),
                input_ea,
            )
        return result

    @functools.wraps(original_rejected)
    def observed_rejected(optimizer, *args, **kwargs):
        retained.pop(id(optimizer), None)
        return original_rejected(optimizer, *args, **kwargs)

    return observed_set_pending, observed_accepted, observed_rejected, retained


def canonical_fallback_feasibility_snapshot(
    state, *, optimizer_type, retained_occurrences
):
    """Copy one cumulative POD snapshot from the live manager-owned optimizer."""
    manager = getattr(state, "manager", None)
    instruction_manager = getattr(manager, "instruction_optimizer", None)
    optimizers = getattr(instruction_manager, "instruction_optimizers", ())
    matches = [optimizer for optimizer in optimizers if isinstance(optimizer, optimizer_type)]
    if len(matches) != 1:
        return {
            "status": "unavailable",
            "reason": f"expected one live PatternOptimizer, found {len(matches)}",
            "optimizer_occurrence": None,
            "optimizer_generation": None,
            "counts": None,
        }
    optimizer = matches[0]
    occurrence = next(
        (
            token
            for token, retained in retained_occurrences.items()
            if retained is optimizer
        ),
        None,
    )
    if occurrence is None:
        occurrence = f"pattern-optimizer-{len(retained_occurrences) + 1}"
        retained_occurrences[occurrence] = optimizer
    generation = getattr(optimizer, "_generation", None)
    if type(generation) is not int or generation < 0:
        raise ValueError("live PatternOptimizer generation is unavailable")
    raw = optimizer.canonical_fallback_feasibility_counts
    if not isinstance(raw, dict) or set(raw) != set(FEASIBILITY_FIELDS):
        raise ValueError("live feasibility counters do not have the fixed key set")
    counts = {}
    for name in FEASIBILITY_FIELDS:
        value = raw[name]
        if type(value) is not int or value < 0:
            raise ValueError("live feasibility counters must be non-negative integers")
        counts[name] = value
    return {
        "status": "available",
        "optimizer_occurrence": occurrence,
        "optimizer_generation": generation,
        "counts": counts,
    }


def schedule_diagnostic_requested(environ=None):
    source = os.environ if environ is None else environ
    return source.get("D810_CANONICAL_DAC_SCHEDULE_DIAGNOSTIC") == "1"


def summarize_schedule_diagnostics(schedules, calls, target="Xor_HackersDelightRule_3"):
    summaries = []
    for schedule in schedules:
        token = schedule["attempt_token"]
        relevant = [call for call in calls if call.get("attempt_token") == token]
        names = [row.get("name") for row in schedule["ordered_bucket"]]
        target_called = any(call.get("rule") == target for call in relevant)
        remaining = None
        if relevant:
            last = relevant[-1]
            requested = last.get("requested_comparison_budget")
            consumed = last.get("comparisons")
            if type(requested) is int and type(consumed) is int:
                remaining = max(0, requested - consumed)
        reason = (
            "target_absent_from_bucket"
            if target not in names
            else "target_called"
            if target_called
            else "budget_exhausted_before_target"
            if remaining == 0
            or any(call.get("stop_reason") == "comparison_budget" for call in relevant)
            else "target_unreached_unknown"
        )
        summaries.append(
            {
                **schedule,
                "calls": relevant,
                "remaining_comparison_budget": remaining,
                "break_reason": reason,
            }
        )
    return summaries


@contextlib.contextmanager
def temporary_method_patch(owner, name, replacement):
    original = getattr(owner, name)
    setattr(owner, name, replacement)
    try:
        yield
    finally:
        setattr(owner, name, original)


@contextlib.contextmanager
def temporary_method_patches(patches):
    """Install a patch set atomically with teardown on partial setup."""
    with contextlib.ExitStack() as stack:
        for owner, name, replacement in patches:
            stack.enter_context(temporary_method_patch(owner, name, replacement))
        yield


def _structural_diagnostic_repr(value):
    try:
        return repr(value)
    except Exception as exc:
        return f"<repr failed: {type(exc).__name__}>"


def _structural_diagnostic_getattr(value, name, default=None):
    try:
        return getattr(value, name, default)
    except Exception:
        return default


def new_structural_diagnostic_attempt(adapter, test_ast, comparison_budget):
    """Retain context without inspecting arbitrary objects before an event."""
    return {
        "requested_comparison_budget": comparison_budget,
        "events": [],
        "_diagnostic_adapter": adapter,
        "_diagnostic_source": test_ast,
    }


def _materialize_structural_diagnostic_attempt(attempt):
    missing = object()
    adapter = attempt.pop("_diagnostic_adapter", missing)
    source = attempt.pop("_diagnostic_source", missing)
    if adapter is missing and source is missing:
        return
    instruction = _structural_diagnostic_getattr(
        None if adapter is missing else adapter, "_attempt_instruction"
    )
    instruction_ea = _structural_diagnostic_getattr(instruction, "ea")
    source_ea = _structural_diagnostic_getattr(
        None if source is missing else source, "ea"
    )
    attempt.update(
        {
            "rule": _structural_diagnostic_getattr(
                None if adapter is missing else adapter, "name"
            ),
            "rule_id": _structural_diagnostic_getattr(
                None if adapter is missing else adapter,
                "_certified_catalogue_rule_id",
            ),
            "input_ea": (
                instruction_ea if instruction_ea is not None else source_ea
            ),
            "input_ea_source": (
                "attempt_instruction"
                if instruction_ea is not None
                else "test_ast"
                if source_ea is not None
                else None
            ),
            "source": _structural_diagnostic_repr(
                None if source is missing else source
            ),
        }
    )


def lowering_diagnostic_reason(lowering):
    if lowering is None:
        return "returned_none"
    if _structural_diagnostic_getattr(lowering, "term") is None:
        return "term_unavailable"
    if _structural_diagnostic_getattr(lowering, "raw_term") is None:
        return "raw_term_unavailable"
    return None


def matcher_diagnostic_reason(report):
    comparisons = _structural_diagnostic_getattr(report, "comparisons")
    if type(comparisons) is not int or comparisons < 0:
        return "invalid_comparison_count"
    return None


def _record_structural_diagnostic(current_attempt, event):
    """Keep diagnostic failures inert with respect to the wrapped call."""
    try:
        attempt = current_attempt()
        if attempt is not None:
            attempt["events"].append(event)
            _materialize_structural_diagnostic_attempt(attempt)
    except Exception:
        return


def structural_diagnostic_receipt_fields(enabled, diagnostics):
    return {"structural_diagnostics": diagnostics} if enabled else {}


def structural_diagnostic_boundary(
    stage, function, current_attempt, *, classify_result=None
):
    """Observe one swallowed structural boundary without changing its behavior."""

    @functools.wraps(function)
    def observed(*args, **kwargs):
        try:
            result = function(*args, **kwargs)
        except Exception as exc:
            try:
                event = {
                    "stage": stage,
                    "reason": "exception",
                    "exception_type": type(exc).__name__,
                    "exception_message": str(exc),
                }
                _record_structural_diagnostic(current_attempt, event)
            except Exception:
                pass
            raise
        if classify_result is not None:
            try:
                reason = classify_result(result)
                if reason is not None:
                    _record_structural_diagnostic(
                        current_attempt, {"stage": stage, "reason": reason}
                    )
            except Exception:
                pass
        return result

    return observed


def new_widened_boolean_capture_store(*, capacity=WIDENED_BOOLEAN_CAPTURE_CAPACITY):
    if type(capacity) is not int or capacity <= 0:
        raise ValueError("widened Boolean capture capacity must be positive")
    return {
        "capacity": capacity,
        "next_sequence": 0,
        "evicted": 0,
        "entries": [],
    }


def _diagnostic_call_bool(value, name):
    method = _structural_diagnostic_getattr(value, name)
    if not callable(method):
        return None
    try:
        result = method()
    except Exception:
        return None
    return result if type(result) is bool else None


def _diagnostic_json_pod(value):
    if value is None or type(value) in {bool, int, float, str}:
        return value
    if isinstance(value, dict) or hasattr(value, "items"):
        return {
            str(key): _diagnostic_json_pod(item)
            for key, item in value.items()
        }
    if type(value) in {tuple, list}:
        return [_diagnostic_json_pod(item) for item in value]
    raise TypeError(f"unsupported diagnostic POD value: {type(value).__name__}")


def _diagnostic_owned_native_pod(mop, owned_mop_identity):
    try:
        return _diagnostic_json_pod(owned_mop_identity(mop))
    except Exception as exc:
        return {
            "status": "error",
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }


def _diagnostic_owned_mop_identity(mop):
    snapshot_module = importlib.import_module("d810.hexrays.ir.mop_snapshot")
    snapshot_type = snapshot_module.MopSnapshot
    if isinstance(mop, snapshot_type):
        if _structural_diagnostic_getattr(mop, "owned_mop") is None:
            raise ValueError("MopSnapshot has no owned native mop")
        native = mop.to_mop()
    else:
        ida_hexrays = importlib.import_module("ida_hexrays")
        if not isinstance(mop, ida_hexrays.mop_t):
            raise TypeError("visible AST mop is neither MopSnapshot nor mop_t")
        native = ida_hexrays.mop_t()
        native.assign(mop)
    return snapshot_module.raw_mop_identity(native)


def _diagnostic_visible_node(value, owned_mop_identity):
    mop = _structural_diagnostic_getattr(value, "mop")
    owned_pod = _diagnostic_owned_native_pod(mop, owned_mop_identity)
    snapshot_owned = _structural_diagnostic_getattr(mop, "owned_mop")
    return {
        "class": type(value).__name__,
        "is_node": _diagnostic_call_bool(value, "is_node"),
        "is_leaf": _diagnostic_call_bool(value, "is_leaf"),
        "is_constant": _diagnostic_call_bool(value, "is_constant"),
        "opcode": _structural_diagnostic_getattr(value, "opcode"),
        "dest_size": _structural_diagnostic_getattr(value, "dest_size"),
        "size": _structural_diagnostic_getattr(value, "size"),
        "value": _structural_diagnostic_getattr(value, "value"),
        "right_present": _structural_diagnostic_getattr(value, "right") is not None,
        "proof_origin": _structural_diagnostic_repr(
            _structural_diagnostic_getattr(value, "proof_origin")
        ),
        "mop": {
            "class": type(mop).__name__,
            "snapshot_owned": snapshot_owned is not None,
            "type": owned_pod.get("type") if type(owned_pod) is dict else None,
            "size": owned_pod.get("size") if type(owned_pod) is dict else None,
        },
        "owned_native_pod": owned_pod,
    }


def _diagnostic_unwrap_proxy(value, *, max_depth=4):
    current = value
    depth = 0
    seen = set()
    while depth < max_depth and type(current).__name__.endswith("Proxy"):
        identity = id(current)
        if identity in seen:
            break
        seen.add(identity)
        target = _structural_diagnostic_getattr(current, "_target")
        if target is None:
            break
        current = target
        depth += 1
    return current, depth


def _diagnostic_native_destination(pod):
    if type(pod) is not dict:
        return None
    instruction = pod.get("instruction")
    if type(instruction) is not dict:
        return None
    destination = instruction.get("d")
    if type(destination) is not dict:
        return None
    return {"type": destination.get("type"), "size": destination.get("size")}


def _diagnostic_instruction_operand(pod, name):
    if type(pod) is not dict:
        return None
    instruction = pod.get("instruction")
    return instruction.get(name) if type(instruction) is dict else None


def _diagnostic_widened_candidate(
    node, *, path, proxy_depth, owned_mop_identity
):
    visible = _diagnostic_visible_node(node, owned_mop_identity)
    setnz, setnz_proxy_depth = _diagnostic_unwrap_proxy(
        _structural_diagnostic_getattr(node, "left")
    )
    setnz_visible = _diagnostic_visible_node(setnz, owned_mop_identity)
    lhs, lhs_proxy_depth = _diagnostic_unwrap_proxy(
        _structural_diagnostic_getattr(setnz, "left")
    )
    rhs, rhs_proxy_depth = _diagnostic_unwrap_proxy(
        _structural_diagnostic_getattr(setnz, "right")
    )
    dst, dst_proxy_depth = _diagnostic_unwrap_proxy(
        _structural_diagnostic_getattr(setnz, "dst")
    )
    lhs_visible = _diagnostic_visible_node(lhs, owned_mop_identity)
    rhs_visible = _diagnostic_visible_node(rhs, owned_mop_identity)
    dst_visible = _diagnostic_visible_node(dst, owned_mop_identity)
    xdu_pod = visible["owned_native_pod"]
    setnz_pod = setnz_visible["owned_native_pod"]
    lhs_pod = lhs_visible["owned_native_pod"]
    rhs_pod = rhs_visible["owned_native_pod"]
    dst_pod = dst_visible["owned_native_pod"]
    return {
        "path": list(path),
        "proxy_depth": proxy_depth,
        "visible": {
            key: value
            for key, value in visible.items()
            if key != "owned_native_pod"
        },
        "owned_native_pod": xdu_pod,
        "setnz": {
            "proxy_depth": setnz_proxy_depth,
            "visible": {
                key: value
                for key, value in setnz_visible.items()
                if key != "owned_native_pod"
            },
            "owned_native_pod": setnz_pod,
            "lhs": {
                "proxy_depth": lhs_proxy_depth,
                "visible": {
                    key: value
                    for key, value in lhs_visible.items()
                    if key != "owned_native_pod"
                },
                "owned_native_pod": lhs_pod,
            },
            "rhs": {
                "proxy_depth": rhs_proxy_depth,
                "visible": {
                    key: value
                    for key, value in rhs_visible.items()
                    if key != "owned_native_pod"
                },
                "owned_native_pod": rhs_pod,
            },
            "dst": {
                "proxy_depth": dst_proxy_depth,
                "visible": {
                    key: value
                    for key, value in dst_visible.items()
                    if key != "owned_native_pod"
                },
                "owned_native_pod": dst_pod,
            },
        },
        "native_destinations": {
            "xdu": _diagnostic_native_destination(xdu_pod),
            "setnz": _diagnostic_native_destination(setnz_pod),
        },
        "identity_equalities": {
            "xdu_l_equals_visible_setnz": (
                _diagnostic_instruction_operand(xdu_pod, "l") == setnz_pod
            ),
            "setnz_l_equals_visible_lhs": (
                _diagnostic_instruction_operand(setnz_pod, "l") == lhs_pod
            ),
            "setnz_r_equals_visible_rhs": (
                _diagnostic_instruction_operand(setnz_pod, "r") == rhs_pod
            ),
            "setnz_d_equals_visible_dst": (
                _diagnostic_instruction_operand(setnz_pod, "d") == dst_pod
            ),
        },
    }


def _capture_widened_boolean_source(
    source,
    destination_size,
    *,
    input_ea,
    xdu_opcode,
    owned_mop_identity,
    max_nodes=64,
):
    pending = [(source, (), 0)]
    seen = set()
    candidates = []
    visited = 0
    truncated = False
    while pending:
        if visited >= max_nodes:
            truncated = True
            break
        value, path, inherited_proxy_depth = pending.pop()
        node, proxy_depth = _diagnostic_unwrap_proxy(value)
        identity = id(node)
        if identity in seen:
            continue
        seen.add(identity)
        visited += 1
        total_proxy_depth = inherited_proxy_depth + proxy_depth
        opcode = _structural_diagnostic_getattr(node, "opcode")
        if opcode == xdu_opcode:
            candidates.append(
                _diagnostic_widened_candidate(
                    node,
                    path=path,
                    proxy_depth=total_proxy_depth,
                    owned_mop_identity=owned_mop_identity,
                )
            )
            continue
        if _diagnostic_call_bool(node, "is_node") is not True:
            continue
        right = _structural_diagnostic_getattr(node, "right")
        left = _structural_diagnostic_getattr(node, "left")
        if right is not None:
            pending.append((right, path + (1,), 0))
        if left is not None:
            pending.append((left, path + (0,), 0))
    return {
        "status": "captured" if candidates else "no_xdu_candidate",
        "input_ea": input_ea,
        "destination_size": destination_size,
        "visited_nodes": visited,
        "truncated": truncated,
        "xdu_candidates": candidates,
    }


def capture_widened_boolean_lowering_result(
    store,
    source,
    destination_size,
    lowering,
    *,
    input_ea=None,
    xdu_opcode,
    owned_mop_identity,
):
    """Cache one exact failed-lowering occurrence without changing its result."""
    if lowering_diagnostic_reason(lowering) != "term_unavailable":
        return lowering
    if input_ea is None:
        input_ea = _structural_diagnostic_getattr(source, "ea")
    if input_ea != WIDENED_BOOLEAN_WITNESS_EA:
        return lowering
    store["next_sequence"] += 1
    sequence = store["next_sequence"]
    try:
        capture = _capture_widened_boolean_source(
            source,
            destination_size,
            input_ea=input_ea,
            xdu_opcode=xdu_opcode,
            owned_mop_identity=owned_mop_identity,
        )
    except Exception as exc:
        capture = {
            "status": "error",
            "input_ea": input_ea,
            "destination_size": destination_size,
            "error_type": type(exc).__name__,
            "error_message": str(exc),
        }
    capture["lowering_sequence"] = sequence
    store["entries"].append(
        {
            "source": source,
            "lowering": lowering,
            "lowering_sequence": sequence,
            "capture": capture,
        }
    )
    while len(store["entries"]) > store["capacity"]:
        store["entries"].pop(0)
        store["evicted"] += 1
    return lowering


def widened_boolean_capture_for_source(store, source, lowering):
    for entry in reversed(store["entries"]):
        if entry["source"] is source and entry["lowering"] is lowering:
            return json.loads(json.dumps(entry["capture"]))
    source_was_captured = any(
        entry["source"] is source for entry in store["entries"]
    )
    return {
        "status": "missing",
        "reason": (
            "lowering_occurrence_unavailable"
            if source_was_captured
            else "capture_evicted_or_unavailable"
        ),
        "capacity": store["capacity"],
        "evicted": store["evicted"],
    }


def attach_widened_boolean_capture(attempt, adapter, source, lowering, store):
    if (
        _structural_diagnostic_getattr(adapter, "name")
        not in WIDENED_BOOLEAN_WITNESS_RULES
        or attempt.get("input_ea") != WIDENED_BOOLEAN_WITNESS_EA
        or not any(
            event.get("stage") == "lowering"
            and event.get("reason") == "term_unavailable"
            for event in attempt.get("events", ())
            if type(event) is dict
        )
    ):
        return
    attempt["widened_boolean_lowering"] = widened_boolean_capture_for_source(
        store, source, lowering
    )


def call_with_inert_structural_diagnostic(
    diagnostic, observer, *, attempt, diagnostic_name
):
    try:
        diagnostic()
    except Exception as exc:
        try:
            attempt[diagnostic_name] = {
                "status": "error",
                "error_type": type(exc).__name__,
                "error_message": str(exc),
            }
        except Exception:
            pass
    return observer()


def widened_boolean_active_lowering_boundary(
    function,
    store,
    current_attempt,
    *,
    xdu_opcode,
    owned_mop_identity,
):
    @functools.wraps(function)
    def observed(*args, **kwargs):
        source = args[0] if args else kwargs.get("ast")
        attempt = current_attempt()
        source_matches = (
            attempt is not None and attempt.get("_diagnostic_source") is source
        )
        adapter = (
            attempt.get("_diagnostic_adapter") if source_matches else None
        )
        result = function(*args, **kwargs)

        def attachment():
            if (
                not source_matches
                or current_attempt() is not attempt
                or attempt.get("rule") not in WIDENED_BOOLEAN_WITNESS_RULES
                or attempt.get("input_ea") != WIDENED_BOOLEAN_WITNESS_EA
                or not any(
                    event.get("stage") == "lowering"
                    and event.get("reason") == "term_unavailable"
                    for event in attempt.get("events", ())
                    if type(event) is dict
                )
            ):
                return
            destination_size = kwargs.get("destination_size")
            if destination_size is None and len(args) > 1:
                destination_size = args[1]
            capture_widened_boolean_lowering_result(
                store,
                source,
                destination_size,
                result,
                input_ea=attempt["input_ea"],
                xdu_opcode=xdu_opcode,
                owned_mop_identity=owned_mop_identity,
            )
            attach_widened_boolean_capture(
                attempt, adapter, source, result, store
            )

        return call_with_inert_structural_diagnostic(
            attachment,
            lambda: result,
            attempt=attempt if attempt is not None else {},
            diagnostic_name="widened_boolean_lowering",
        )

    return observed


def write_json(path, document):
    Path(path).write_text(
        json.dumps(document, sort_keys=True, indent=2, allow_nan=False) + "\n"
    )


def workload_segments(*, diagnostic=False):
    positive = ("positive-xor", POSITIVE_NODE)
    return (positive,) if diagnostic else (("dac", NODE), positive)


def select_evidence(records, *, project=None):
    """One state publishes cumulative observations: select latest, never sum."""
    expected_project = PROJECT if project is None else project
    selected = [
        item
        for item in records
        if item.get("project") == expected_project
        and item.get("snapshot") is not None
        and item.get("ledger") is not None
    ]
    if not selected:
        raise ValueError("no real DAC shadow evidence captured")
    fingerprints = {item["snapshot"]["fingerprint"] for item in selected}
    if len(fingerprints) != 1:
        raise ValueError("snapshot changed within bounded qualification")
    occurrences = {item.get("ledger_occurrence") for item in selected}
    if len(occurrences) != 1 or None in occurrences:
        raise ValueError("ledger occurrence changed within bounded qualification")
    for previous, current in zip(selected, selected[1:]):
        for name in LEDGER_FIELDS:
            before, after = previous["ledger"][name], current["ledger"][name]
            if (
                type(before) is not int
                or type(after) is not int
                or before < 0
                or after < before
            ):
                raise ValueError("invalid or reset cumulative ledger counter: " + name)
        if "enrollment" in previous or "enrollment" in current:
            if "enrollment" not in previous or "enrollment" not in current:
                raise ValueError("missing cumulative partition")
            if _validated_partition(previous) != _validated_partition(current):
                raise ValueError("partition changed within cumulative segment")
            for before_adapter, after_adapter in zip(
                previous["adapters"], current["adapters"]
            ):
                for name in (
                    "legacy_only_observation_count",
                    "legacy_only_match_count",
                ):
                    before, after = before_adapter[name], after_adapter[name]
                    if (
                        type(before) is not int
                        or type(after) is not int
                        or before < 0
                        or after < before
                    ):
                        raise ValueError("invalid or reset cumulative excluded counter")
    return selected[-1]


def validate_run(receipt):
    if (
        receipt.get("exit") != 0
        or receipt.get("passed") != 1
        or receipt.get("skipped") != 0
    ):
        raise ValueError("bounded node did not pass exactly once without skips")
    decompiles = receipt.get("decompiles", [])
    if len(decompiles) != 2 or any(
        item.get("error") or len(item.get("sha256", "")) != 64 for item in decompiles
    ):
        raise ValueError("missing successful before/after native decompile receipts")


def combine_evidence(receipts, *, project=None, run_validator=None):
    """Combine independent processes, not repeated snapshots of one ledger.

    Each segment must use precisely the same catalogue and toolchain. The
    certificate builder still owns admission, including the positive-match gate.
    """
    if not receipts:
        raise ValueError("no qualification segments")
    segment_ids = [item.get("segment_id") for item in receipts]
    if any(type(item) is not str or not item for item in segment_ids) or len(
        set(segment_ids)
    ) != len(segment_ids):
        raise ValueError("duplicate or missing qualification segment identity")
    validate = validate_run if run_validator is None else run_validator
    selected = []
    for receipt in receipts:
        validate(receipt)
        selected.append(select_evidence(receipt["records"], project=project))
    snapshot = selected[0]["snapshot"]
    toolchain = receipts[0]["toolchain"]
    if any(item["snapshot"] != snapshot for item in selected):
        raise ValueError("snapshot changed across qualification segments")
    if any(item["toolchain"] != toolchain for item in receipts):
        raise ValueError("toolchain changed across qualification segments")
    partitions = [_validated_partition(item) for item in selected]
    if any(item != partitions[0] for item in partitions):
        raise ValueError("partition changed across qualification segments")
    excluded_observations = excluded_matches = 0
    for item in selected:
        for adapter in item["adapters"]:
            observations = adapter["legacy_only_observation_count"]
            matches = adapter["legacy_only_match_count"]
            if any(
                type(value) is not int or value < 0 for value in (observations, matches)
            ):
                raise ValueError("invalid excluded counters")
            if matches > observations or (
                adapter["canonical_eligible"] and observations
            ):
                raise ValueError("inconsistent excluded counters")
            excluded_observations += observations
            excluded_matches += matches
    ledger = {name: 0 for name in LEDGER_FIELDS}
    for item in selected:
        for name in LEDGER_FIELDS:
            value = item["ledger"].get(name)
            if type(value) is not int or value < 0:
                raise ValueError("invalid qualification ledger counter: " + name)
            ledger[name] += value
    return {
        "snapshot": snapshot,
        "ledger": ledger,
        "snapshot_widths": selected[0]["snapshot_widths"],
        "enrollment": selected[0]["enrollment"],
        "canonical_status_by_rule_width": selected[0]["canonical_status_by_rule_width"],
        "legacy_only_observation_count": excluded_observations,
        "legacy_only_match_count": excluded_matches,
        "segments": segment_ids,
        "toolchain": toolchain,
    }


def _validated_partition(record):
    enrollment = record["enrollment"]
    adapters = record["adapters"]
    statuses = record["canonical_status_by_rule_width"]
    widths = record["snapshot_widths"]
    if (
        not widths
        or any(type(width) is not int or width <= 0 for width in widths)
        or len(set(widths)) != len(widths)
    ):
        raise ValueError("invalid partition widths")
    status_keys = set()
    for entry in statuses:
        rule_id, width = entry["rule_id"], entry["width"]
        if (
            type(rule_id) is not int
            or type(width) is not int
            or entry["status"] not in {"eligible", "unsupported", "opaque"}
            or (rule_id, width) in status_keys
        ):
            raise ValueError("invalid partition status matrix")
        status_keys.add((rule_id, width))
    if status_keys != {
        (index, width) for index in range(len(adapters)) for width in widths
    }:
        raise ValueError("incomplete partition status matrix")
    counts = [
        enrollment[name]
        for name in (
            "selected_rule_count",
            "canonical_eligible_rule_count",
            "legacy_only_rule_count",
        )
    ]
    if any(type(value) is not int or value < 0 for value in counts):
        raise ValueError("invalid partition counts")
    if any(type(adapter["canonical_eligible"]) is not bool for adapter in adapters):
        raise ValueError("invalid partition eligibility")
    eligible = sum(adapter["canonical_eligible"] for adapter in adapters)
    if counts != [len(adapters), eligible, len(adapters) - eligible]:
        raise ValueError("inconsistent partition denominator")
    if enrollment["snapshot_fingerprint"] != record["snapshot"]["fingerprint"]:
        raise ValueError("partition snapshot mismatch")
    for rule_id, adapter in enumerate(adapters):
        if type(adapter["rule_id"]) is not int or adapter["rule_id"] != rule_id:
            raise ValueError("partition adapter identity/order mismatch")
        rule_statuses = [
            entry["status"] for entry in statuses if entry["rule_id"] == rule_id
        ]
        if not rule_statuses or adapter["canonical_eligible"] != all(
            status == "eligible" for status in rule_statuses
        ):
            raise ValueError("partition eligibility disagrees with snapshot")
    return (
        enrollment,
        statuses,
        widths,
        [
            (item["rule_id"], item["name"], item["canonical_eligible"])
            for item in adapters
        ],
    )


_reports = {"passed": 0, "skipped": 0, "failed": 0}


def shadow_witness(adapter, verdict, *, diagnostic=None):
    """Diagnostic-only snapshots; never reconstruct or change a match decision."""
    lowering = getattr(adapter, "_shadow_lowering", None)
    source = getattr(adapter, "_shadow_source_ast", None)
    diagnostic = None if diagnostic is None else dict(diagnostic)
    return {
        "rule": adapter.name,
        "rule_id": getattr(adapter, "_certified_catalogue_rule_id", None),
        "verdict": dict(verdict),
        "legacy_binding_paths": repr(getattr(adapter, "_legacy_binding_paths", None)),
        "structural_native_paths": repr(
            getattr(adapter, "_shadow_structural_native_paths", None)
        ),
        "match_report": repr(getattr(adapter, "_shadow_match_report", None)),
        "source": (
            diagnostic.get("source")
            if source is None and diagnostic is not None
            else repr(source)
        ),
        "input_ea": (
            diagnostic.get("input_ea")
            if diagnostic is not None
            else getattr(source, "ea", None)
        ),
        "requested_comparison_budget": (
            None
            if diagnostic is None
            else diagnostic.get("requested_comparison_budget")
        ),
        "structural_diagnostic": diagnostic,
        "provenance_rejections": getattr(adapter, "_provenance_rejection_count", 0),
        "native_path_unavailable": getattr(
            adapter, "_shadow_native_path_unavailable", False
        ),
        "native_equivalence": getattr(
            adapter, "_shadow_native_equivalence_verdict", None
        ),
        "templates": repr(getattr(adapter, "_shadow_canonical_templates", None)),
        "canonical_term": repr(getattr(lowering, "term", None)),
        "raw_term": repr(getattr(lowering, "raw_term", None)),
    }


def pytest_runtest_logreport(report):
    if report.skipped:
        _reports["skipped"] += 1
    if report.failed:
        _reports["failed"] += 1
    if report.when == "call" and report.passed:
        _reports["passed"] += 1


@pytest.fixture(scope="session", autouse=True)
def canonical_dac_capture():
    # Load native modules only after system conftest initializes IDA.
    from d810.manager import D810State
    from d810.testing import runner as testing_runner
    from d810.optimizers.microcode.instructions.pattern_matching.handler import (
        PatternOptimizer,
    )
    from d810.backends.mba.ida import (
        IDAPatternAdapter,
        _snapshot_rule_widths_are_structurally_eligible,
    )
    from d810.mba import certified_catalogue
    from d810.mba import ac_matching, canonical_pattern
    from d810.backends.mba import hexrays_island
    import idaapi
    import ida_hexrays

    output = Path(os.environ["D810_CANONICAL_DAC_OUT"])
    engine_info = importlib.import_module(
        "d810.optimizers.microcode.instructions.pattern_matching.engine"
    ).get_engine_info()
    d810_file = importlib.import_module("d810").__file__
    if engine_info["backend"] != "cython":
        raise RuntimeError("qualification requires the requested native Cython backend")
    if not Path(d810_file).resolve().is_relative_to(Path("/work/src")):
        raise RuntimeError("qualification did not load exact /work/src source")
    records, decompiles, witnesses = [], [], []
    original_metadata = IDAPatternAdapter._shadow_metadata
    original_project_resolver = testing_runner._resolve_test_project_index
    capture_witnesses = os.environ.get("D810_CANONICAL_DAC_WITNESSES") == "1"
    capture_activation = os.environ.get("D810_CANONICAL_DAC_ACTIVATION_PROOF") == "1"
    aggregate_only = os.environ.get("D810_CANONICAL_DAC_AGGREGATE_ONLY") == "1"
    original_structural_match = IDAPatternAdapter.match_structural_and_replace
    original_structural_observer = IDAPatternAdapter.observe_structural_match
    original_lowering = hexrays_island.lower_hexrays_island
    original_canonical_match = ac_matching.match_canonical_term_pattern
    original_constraint_evaluator = canonical_pattern.evaluate_frozen_constraints
    original_path_resolver = canonical_pattern.resolve_canonical_match_paths
    original_set_pending = PatternOptimizer._set_pending_replacement
    original_mutation_accepted = PatternOptimizer.record_mutation_accepted
    original_mutation_rejected = PatternOptimizer.record_mutation_rejected
    original_prepare_fallback = PatternOptimizer._prepare_canonical_fallback
    activation_calls = []
    activation_summary = new_activation_summary()
    accepted_enrolled = []
    accepted_enrolled_summary = {"count": 0, "route_counts": {}}
    schedule_diagnostics = []
    active_schedule_tokens = {}
    schedule_attempt_index = 0
    capture_schedule = schedule_diagnostic_requested()
    structural_diagnostics = []
    latest_structural_diagnostic = {}
    active_structural_diagnostics = []
    widened_boolean_captures = (
        new_widened_boolean_capture_store() if capture_witnesses else None
    )

    def current_structural_diagnostic():
        return (
            active_structural_diagnostics[-1]
            if active_structural_diagnostics
            else None
        )

    @functools.wraps(original_structural_observer)
    def observed_structural_observer(adapter, test_ast, *args, **kwargs):
        diagnostic = new_structural_diagnostic_attempt(
            adapter, test_ast, kwargs.get("comparison_budget", 64)
        )
        latest_structural_diagnostic.pop(id(adapter), None)
        active_structural_diagnostics.append(diagnostic)
        try:
            should_attach = False
            if kwargs.get("lowering_provided"):
                lowering = kwargs.get("lowering")
                reason = lowering_diagnostic_reason(lowering)
                if reason is not None:
                    _record_structural_diagnostic(
                        current_structural_diagnostic,
                        {"stage": "lowering", "reason": reason},
                    )
                    if widened_boolean_captures is not None:
                        should_attach = True

            def observer():
                return original_structural_observer(
                    adapter, test_ast, *args, **kwargs
                )

            if not should_attach:
                return observer()

            def attachment():
                attach_widened_boolean_capture(
                    diagnostic,
                    adapter,
                    test_ast,
                    lowering,
                    widened_boolean_captures,
                )

            return call_with_inert_structural_diagnostic(
                attachment,
                observer,
                attempt=diagnostic,
                diagnostic_name="widened_boolean_lowering",
            )
        finally:
            active_structural_diagnostics.pop()
            if diagnostic["events"]:
                structural_diagnostics.append(diagnostic)
                latest_structural_diagnostic[id(adapter)] = diagnostic

    observed_lowering = structural_diagnostic_boundary(
        "lowering",
        original_lowering,
        current_structural_diagnostic,
        classify_result=lowering_diagnostic_reason,
    )
    if widened_boolean_captures is not None:
        observed_lowering = widened_boolean_active_lowering_boundary(
            observed_lowering,
            widened_boolean_captures,
            current_structural_diagnostic,
            xdu_opcode=ida_hexrays.m_xdu,
            owned_mop_identity=_diagnostic_owned_mop_identity,
        )
    observed_canonical_match = structural_diagnostic_boundary(
        "matcher",
        original_canonical_match,
        current_structural_diagnostic,
        classify_result=matcher_diagnostic_reason,
    )
    observed_constraint_evaluator = structural_diagnostic_boundary(
        "constraint", original_constraint_evaluator, current_structural_diagnostic
    )
    observed_path_resolver = structural_diagnostic_boundary(
        "provenance", original_path_resolver, current_structural_diagnostic
    )

    def observed_structural_match(adapter, *args, **kwargs):
        instruction_ea = getattr(
            getattr(adapter, "_attempt_instruction", None), "ea", None
        )
        attempt_token = active_schedule_tokens.get(id(adapter))
        result = original_structural_match(adapter, *args, **kwargs)
        comparisons = adapter.canonical_fallback_comparisons
        stop_reason = getattr(adapter, "_canonical_fallback_stop_reason", None)
        accumulate_activation_summary(
            activation_summary,
            comparisons=comparisons,
            stop_reason=stop_reason,
            matched=result is not None,
        )
        if not aggregate_only:
            provider_outcome = getattr(adapter, "_last_provider_outcome", None)
            activation_calls.append(
                {
                    "rule": adapter.name,
                    "attempt_token": attempt_token,
                    "input_ea": instruction_ea,
                    "bucket_size": kwargs.get("bucket_size"),
                    "attempted_rule_count": kwargs.get("attempted_rule_count"),
                    "requested_comparison_budget": kwargs.get("comparison_budget"),
                    "comparisons": comparisons,
                    "stop_reason": stop_reason,
                    "matched": result is not None,
                    "provider_outcome": repr(provider_outcome),
                    "provider_fingerprint": getattr(
                        provider_outcome, "fingerprint", None
                    ),
                }
            )
        return result

    def observed_prepare_fallback(optimizer, test_ast, ins, **kwargs):
        nonlocal schedule_attempt_index
        result = original_prepare_fallback(optimizer, test_ast, ins, **kwargs)
        instruction_ea = getattr(ins, "ea", None)
        lowering, selected = result
        schedule_attempt_index += 1
        attempt_token = f"schedule-{schedule_attempt_index}"
        active_schedule_tokens.clear()
        for rule in selected:
            active_schedule_tokens[id(rule)] = attempt_token
        if instruction_ea in {0x18000E088, 0x18000E0B7}:
            term = getattr(lowering, "term", None)
            root_shape = None
            if term is not None:
                from d810.mba.certified_catalogue import root_shape_for_term

                root_shape = root_shape_for_term(term)
            schedule_diagnostics.append(
                {
                    "input_ea": instruction_ea,
                    "attempt_token": attempt_token,
                    "maturity": getattr(optimizer, "cur_maturity", None),
                    "root_shape": root_shape,
                    "ordered_bucket": [
                        {
                            "rule_id": getattr(
                                rule, "_certified_catalogue_rule_id", None
                            ),
                            "name": getattr(rule, "name", None),
                        }
                        for rule in selected
                    ],
                }
            )
        return result

    def record_accepted_candidate(adapter, outcome, input_ea):
        if adapter.canonical_fallback_enabled and getattr(
            adapter, "_canonical_shadow_eligible", False
        ):
            receipt = accepted_enrolled_receipt(
                adapter, outcome, input_ea=input_ea
            )
            accepted_enrolled_summary["count"] += 1
            routes = accepted_enrolled_summary["route_counts"]
            route = receipt["route"]
            routes[route] = routes.get(route, 0) + 1
            if not aggregate_only:
                accepted_enrolled.append(receipt)

    (
        observed_set_pending,
        observed_mutation_accepted,
        observed_mutation_rejected,
        pending_candidate_eas,
    ) = candidate_ea_patch_methods(
        adapter_type=IDAPatternAdapter,
        original_set_pending=original_set_pending,
        original_accepted=original_mutation_accepted,
        original_rejected=original_mutation_rejected,
        record_accepted=record_accepted_candidate,
    )

    def measurement_project_resolver(state, project_name):
        return original_project_resolver(state, routed_project_name(project_name))

    def observed_metadata(adapter, *, legacy_match):
        verdict = original_metadata(adapter, legacy_match=legacy_match)
        if legacy_match or verdict.get("structural_match"):
            witnesses.append(
                shadow_witness(
                    adapter,
                    verdict,
                    diagnostic=latest_structural_diagnostic.get(id(adapter)),
                )
            )
            write_json(output.with_suffix(".witnesses.json"), witnesses)
        return verdict

    # Retain strong references until the fixture closes so occurrence tokens
    # cannot be recycled after a manager-owned optimizer is replaced.
    retained_ledgers = {}
    retained_optimizers = {}
    original = idaapi.decompile
    start = time.perf_counter()

    def capture():
        state = D810State()
        project = getattr(state, "current_project", None)
        if project is None or project.path.name != PROJECT:
            return
        snapshot = getattr(state, "current_certified_catalogue_snapshot", None)
        ledger = getattr(state, "current_shadow_matcher_parity_ledger", None)
        if ledger is not None:
            retained_ledgers[id(ledger)] = ledger
        adapters = [
            rule
            for rule in state.current_ins_rules
            if isinstance(rule, IDAPatternAdapter)
        ]
        eligible = [
            snapshot is not None
            and _snapshot_rule_widths_are_structurally_eligible(
                snapshot,
                rule._certified_catalogue_rule_id,
                rule.rule,
            )
            for rule in adapters
        ]
        record = {
            "project": project.path.name,
            "runtime_paths": {
                "state_log_dir": str(getattr(state, "log_dir", "")),
                "tmpdir": os.environ.get("TMPDIR"),
                "idalog": os.environ.get("IDALOG"),
            },
            "ledger_occurrence": None if ledger is None else id(ledger),
            "snapshot": None
            if snapshot is None
            else {
                name: getattr(snapshot, name)
                for name in (
                    "fingerprint",
                    "structural_authorizable",
                    "canonicalizer_schema_version",
                    "runtime_semantics_digest",
                )
            },
            "ledger": None
            if ledger is None
            else {name: getattr(ledger, name) for name in LEDGER_FIELDS},
            "canonical_fallback_feasibility": (
                canonical_fallback_feasibility_snapshot(
                    state,
                    optimizer_type=PatternOptimizer,
                    retained_occurrences=retained_optimizers,
                )
            ),
            "canonical_status_by_rule_width": []
            if snapshot is None
            else [
                {"rule_id": key[0], "width": key[1], "status": value}
                for key, value in snapshot.canonical_status_by_rule_width.items()
            ],
            "enrollment": {
                "snapshot_fingerprint": None
                if snapshot is None
                else snapshot.fingerprint,
                "selected_rule_count": len(adapters),
                "canonical_eligible_rule_count": sum(eligible),
                "legacy_only_rule_count": len(adapters) - sum(eligible),
            },
            "snapshot_widths": []
            if snapshot is None
            else sorted({shape[1] for shape in snapshot.rule_ids_by_root_shape}),
            "adapters": [
                {
                    "name": rule.name,
                    "rule_id": rule._certified_catalogue_rule_id,
                    "canonical_eligible": is_eligible,
                    "legacy_only_observation_count": rule.legacy_only_observation_count,
                    "legacy_only_match_count": rule.legacy_only_match_count,
                    "uses_structural_matching": rule.uses_structural_matching,
                    "canonical_fallback_enabled": rule.canonical_fallback_enabled,
                    "canonical_fallback_comparisons": rule.canonical_fallback_comparisons,
                    "canonical_fallback_stop_reason": getattr(
                        rule, "_canonical_fallback_stop_reason", None
                    ),
                    "provider_outcome": repr(
                        getattr(rule, "_last_provider_outcome", None)
                    ),
                    "candidate_count": None
                    if rule._pattern_candidates_cache is None
                    else len(rule._pattern_candidates_cache),
                }
                for rule, is_eligible in zip(adapters, eligible)
            ],
            "coverage_limit": "Canonical-eligible live ledger only; legacy-only observations separate; no per-rule qualification claim.",
        }
        records.append(record)
        # Persist immediately, before singleton teardown or another decompile.
        write_json(output.with_suffix(".capture.json"), records)

    def observed_decompile(*args, **kwargs):
        stamp = time.perf_counter()
        try:
            result = original(*args, **kwargs)
            if result is None:
                raise RuntimeError("native decompile returned None")
            decompiles.append(
                {
                    "seconds": time.perf_counter() - stamp,
                    "sha256": hashlib.sha256(str(result).encode()).hexdigest(),
                }
            )
            return result
        except BaseException as exc:
            decompiles.append(
                {"seconds": time.perf_counter() - stamp, "error": repr(exc)}
            )
            raise
        finally:
            capture()

    patches = [
        (idaapi, "decompile", observed_decompile),
        (
            testing_runner,
            "_resolve_test_project_index",
            measurement_project_resolver,
        ),
    ]
    if capture_witnesses:
        patches.extend(
            (
                (IDAPatternAdapter, "_shadow_metadata", observed_metadata),
                (
                    IDAPatternAdapter,
                    "observe_structural_match",
                    observed_structural_observer,
                ),
                (hexrays_island, "lower_hexrays_island", observed_lowering),
                (
                    ac_matching,
                    "match_canonical_term_pattern",
                    observed_canonical_match,
                ),
                (
                    canonical_pattern,
                    "evaluate_frozen_constraints",
                    observed_constraint_evaluator,
                ),
                (
                    canonical_pattern,
                    "resolve_canonical_match_paths",
                    observed_path_resolver,
                ),
            )
        )
    if capture_activation:
        patches.extend(
            (
                (
                    IDAPatternAdapter,
                    "match_structural_and_replace",
                    observed_structural_match,
                ),
                (
                    PatternOptimizer,
                    "_set_pending_replacement",
                    observed_set_pending,
                ),
                (
                    PatternOptimizer,
                    "record_mutation_accepted",
                    observed_mutation_accepted,
                ),
                (
                    PatternOptimizer,
                    "record_mutation_rejected",
                    observed_mutation_rejected,
                ),
            )
        )
    if capture_schedule:
        patches.append(
            (
                PatternOptimizer,
                "_prepare_canonical_fallback",
                observed_prepare_fallback,
            )
        )
    try:
        with temporary_method_patches(patches):
            yield
    finally:
        pending_candidate_eas.clear()
        write_json(
            output,
            {
                **_reports,
                "decompiles": decompiles,
                "records": records,
                "project": PROJECT,
                "expected_project": PROJECT,
                "activation_calls": activation_calls,
                "activation_summary": activation_summary,
                "accepted_enrolled": accepted_enrolled,
                "accepted_enrolled_summary": accepted_enrolled_summary,
                "schedule_diagnostics": summarize_schedule_diagnostics(
                    schedule_diagnostics, activation_calls
                ),
                "shadow_witnesses": witnesses,
                **structural_diagnostic_receipt_fields(
                    capture_witnesses, structural_diagnostics
                ),
                "session_seconds": time.perf_counter() - start,
                "toolchain": {
                    "python": os.sys.version,
                    "ida_sdk": idaapi.IDA_SDK_VERSION,
                    "hexrays_version": ida_hexrays.get_hexrays_version(),
                    "matcher_backend": engine_info,
                    "catalogue_module": certified_catalogue.__file__,
                    "d810_file": d810_file,
                },
            },
        )
