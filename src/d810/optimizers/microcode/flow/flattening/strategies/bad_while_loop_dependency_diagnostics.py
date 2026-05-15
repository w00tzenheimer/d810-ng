"""Dependency diagnostics for BadWhileLoop copied side effects."""
from __future__ import annotations

from collections.abc import Mapping, Sequence

from d810.core.typing import Any
from d810.evaluator.hexrays_microcode.definition_rescue_backend import (
    DefinitionRescueBackend,
    HexRaysDefinitionRescueBackend,
)


BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY = (
    "bad_while_loop_dependency_diagnostics"
)

BadWhileLoopDependencyDiagnostic = dict[str, object]


def build_bad_while_loop_dependency_diagnostic(
    *,
    mba: object,
    rule: object,
    source_blk: object,
    dispatcher_entry: int,
    source_serial: int,
    target_serial: int | None,
    category: str,
    reason: str,
    copied_instructions: Sequence[object],
    dependency_safe_copies: Sequence[object],
    definition_backend: DefinitionRescueBackend | None = None,
) -> BadWhileLoopDependencyDiagnostic:
    """Build JSON-friendly diagnostics for dependency-unsafe copied instructions."""
    raw_instructions = tuple(copied_instructions)
    safe_instructions = tuple(dependency_safe_copies)
    source_liveins, source_defs = _collect_block_liveins_and_defs(rule, source_blk)
    available = list(source_liveins) + [
        mop for mop in source_defs if not _mop_in_list(mop, source_liveins)
    ]
    safe_ids = {id(ins) for ins in safe_instructions}
    backend = definition_backend or HexRaysDefinitionRescueBackend()
    sccp = _LazySccp(mba, backend)

    copied_instruction_rows: list[dict[str, object]] = []
    missing_use_rows: list[dict[str, object]] = []
    saw_call_or_invalid_payload = False

    for index, ins in enumerate(raw_instructions):
        ins_uses, ins_defs = _collect_instruction_uses_defs(rule, ins)
        missing_uses = [
            used for used in ins_uses if not _mop_in_list(used, available)
        ]
        missing_rows = [
            _build_missing_use_row(
                mba=mba,
                backend=backend,
                sccp=sccp,
                source_serial=source_serial,
                mop=missing,
            )
            for missing in missing_uses
        ]
        missing_use_rows.extend(missing_rows)

        opcode = _optional_int(getattr(ins, "opcode", None))
        if opcode in _call_opcodes():
            saw_call_or_invalid_payload = True
        if opcode is None:
            saw_call_or_invalid_payload = True

        accepted = id(ins) in safe_ids
        copied_instruction_rows.append(
            {
                "index": index,
                "opcode": opcode,
                "opcode_name": _opcode_name(opcode),
                "ea": _optional_int(getattr(ins, "ea", None)),
                "display": _format_instruction(ins),
                "uses": [_serialize_mop(mop, mba=mba) for mop in ins_uses],
                "defs": [_serialize_mop(mop, mba=mba) for mop in ins_defs],
                "missing_uses": missing_rows,
                "accepted_by_current_filter": accepted,
            }
        )
        if accepted:
            for ins_def in ins_defs:
                if not _mop_in_list(ins_def, available):
                    available.append(ins_def)

    bucket, bucket_reason = _classify_bucket(
        raw_instruction_count=len(raw_instructions),
        dependency_safe_count=len(safe_instructions),
        missing_uses=missing_use_rows,
        source_blk=source_blk,
        saw_call_or_invalid_payload=saw_call_or_invalid_payload,
    )
    return {
        "dispatcher_entry": int(dispatcher_entry),
        "source_serial": int(source_serial),
        "target_serial": int(target_serial) if target_serial is not None else None,
        "category": str(category),
        "reason": str(reason),
        "raw_instruction_count": len(raw_instructions),
        "dependency_safe_instruction_count": len(safe_instructions),
        "source_liveins": [_serialize_mop(mop, mba=mba) for mop in source_liveins],
        "source_defs": [_serialize_mop(mop, mba=mba) for mop in source_defs],
        "copied_instructions": copied_instruction_rows,
        "missing_uses": missing_use_rows,
        "final_bucket": bucket,
        "bucket_reason": bucket_reason,
    }


def serialize_bad_while_loop_dependency_diagnostics(
    diagnostics: Sequence[Mapping[str, object]],
) -> list[dict[str, object]]:
    """Return JSON-friendly diagnostic metadata rows."""
    return [
        _json_sanitize(dict(row))
        for row in diagnostics
        if isinstance(row, Mapping)
    ]


def extract_bad_while_loop_dependency_diagnostics(
    flow_graph: object | None,
) -> tuple[BadWhileLoopDependencyDiagnostic, ...]:
    """Read BadWhileLoop dependency diagnostics from FlowGraph metadata."""
    if flow_graph is None:
        return ()
    metadata = getattr(flow_graph, "metadata", None)
    if not isinstance(metadata, Mapping):
        return ()
    raw = metadata.get(BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY)
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes, bytearray)):
        return ()
    return tuple(
        _json_sanitize(dict(row))
        for row in raw
        if isinstance(row, Mapping)
    )


def _collect_block_liveins_and_defs(
    rule: object,
    source_blk: object,
) -> tuple[list[object], list[object]]:
    collector = getattr(rule, "_collect_block_liveins_and_defs", None)
    if callable(collector):
        try:
            liveins, defs = collector(source_blk)
            return list(liveins or ()), list(defs or ())
        except Exception:
            pass
    return (
        list(getattr(source_blk, "liveins", ()) or ()),
        list(getattr(source_blk, "defs", ()) or ()),
    )


def _collect_instruction_uses_defs(
    rule: object,
    ins: object,
) -> tuple[list[object], list[object]]:
    collector = getattr(rule, "_collect_instruction_uses_defs", None)
    if callable(collector):
        try:
            uses, defs = collector(ins)
            return list(uses or ()), list(defs or ())
        except Exception:
            pass
    return (
        list(getattr(ins, "uses", ()) or ()),
        list(getattr(ins, "defs", ()) or ()),
    )


def _build_missing_use_row(
    *,
    mba: object,
    backend: DefinitionRescueBackend,
    sccp: "_LazySccp",
    source_serial: int,
    mop: object,
) -> dict[str, object]:
    serialized = _serialize_mop(mop, mba=mba)
    kind = serialized.get("kind")
    reaching_sites: tuple[object, ...] = ()
    sccp_value: object | None = None
    capture_status = "unknown"

    stack = serialized.get("stack")
    if isinstance(stack, Mapping):
        stkoff = _optional_int(stack.get("stkoff"))
        size = _optional_int(stack.get("size"))
        if stkoff is not None and size is not None:
            try:
                reaching_sites = backend.reaching_defs_for_stkvar(
                    mba,
                    int(source_serial),
                    stkoff,
                    size,
                )
            except Exception:
                reaching_sites = ()
            try:
                overlay = sccp.value()
                if overlay is not None:
                    sccp_value = backend.lookup_sccp_stkvar(
                        overlay,
                        stkoff=stkoff,
                        size=size,
                    )
            except Exception:
                sccp_value = None
            if len(reaching_sites) == 1:
                capture_status = "capturable"
            elif len(reaching_sites) > 1:
                capture_status = "ambiguous_defs"
            else:
                capture_status = "external_or_no_reaching_def"
    elif kind in {"mop_r", "mop_l"}:
        capture_status = "needs_capture"
    elif kind in {
        "mop_a",
        "mop_b",
        "mop_c",
        "mop_d",
        "mop_f",
        "mop_p",
        "mop_sc",
        "mop_v",
    }:
        capture_status = "alias_unknown"

    return {
        "mop": serialized,
        "reaching_def_count": len(reaching_sites),
        "reaching_def_sites": [
            {
                "block_serial": _optional_int(getattr(site, "block_serial", None)),
                "insn_ea": _optional_int(getattr(site, "insn_ea", None)),
            }
            for site in reaching_sites
        ],
        "sccp_value": _serialize_value(sccp_value),
        "capture_status": capture_status,
    }


def _classify_bucket(
    *,
    raw_instruction_count: int,
    dependency_safe_count: int,
    missing_uses: Sequence[Mapping[str, object]],
    source_blk: object,
    saw_call_or_invalid_payload: bool,
) -> tuple[str, str]:
    if raw_instruction_count > 0 and dependency_safe_count == raw_instruction_count:
        return "already_dependency_safe", "current filter accepted every raw copy"
    if 0 < dependency_safe_count < raw_instruction_count:
        return "partial_dependency_safe", "current filter accepted only some copies"
    if saw_call_or_invalid_payload:
        return "call_or_payload_invalid", "copied instruction is call-like or invalid"

    stack_statuses = _capture_statuses(missing_uses, "stack")
    if stack_statuses:
        if all(status == "capturable" for status in stack_statuses):
            return (
                "stack_unique_def_chain_capturable",
                "each missing stack use has one reaching definition",
            )
        if any(status == "ambiguous_defs" for status in stack_statuses):
            return (
                "stack_ambiguous_defs",
                "at least one missing stack use has multiple reaching definitions",
            )
        return (
            "stack_external_or_no_reaching_def",
            "missing stack use is external or has no reaching definition",
        )

    missing_kinds = {
        str(row.get("mop", {}).get("kind"))
        for row in missing_uses
        if isinstance(row.get("mop"), Mapping)
    }
    memory_kinds = {
        "mop_a",
        "mop_b",
        "mop_c",
        "mop_d",
        "mop_f",
        "mop_p",
        "mop_sc",
        "mop_v",
    }
    if missing_kinds & memory_kinds:
        return "memory_or_alias_unknown", "missing use is memory or alias-sensitive"
    if missing_kinds <= {"mop_r"} and missing_kinds:
        predset = getattr(source_blk, "predset", None)
        try:
            pred_count = len(list(predset or ()))
        except Exception:
            pred_count = 0
        if pred_count == 1:
            return "reg_single_pred_def", "missing register use has one predecessor"
        return "reg_or_lvar_needs_capture", "missing register use needs capture"
    if missing_kinds & {"mop_l", "mop_r"}:
        return "reg_or_lvar_needs_capture", "missing register/local use needs capture"
    return "mixed_unknown", "dependency gap is mixed or lacks operand evidence"


def _capture_statuses(
    missing_uses: Sequence[Mapping[str, object]],
    identity_key: str,
) -> list[str]:
    statuses: list[str] = []
    for row in missing_uses:
        mop = row.get("mop")
        if not isinstance(mop, Mapping) or identity_key not in mop:
            continue
        statuses.append(str(row.get("capture_status")))
    return statuses


class _LazySccp:
    def __init__(self, mba: object, backend: DefinitionRescueBackend) -> None:
        self._mba = mba
        self._backend = backend
        self._loaded = False
        self._value: object | None = None

    def value(self) -> object | None:
        if not self._loaded:
            self._loaded = True
            try:
                self._value = self._backend.run_sccp_overlay(self._mba)
            except Exception:
                self._value = None
        return self._value


def _serialize_mop(mop: object, *, mba: object | None = None) -> dict[str, object]:
    mop_type = _optional_int(getattr(mop, "t", None))
    size = _optional_int(getattr(mop, "size", None))
    result: dict[str, object] = {
        "kind": _mop_kind(mop_type),
        "type": mop_type,
        "size": size,
        "format": _format_mop(mop),
    }
    constants = _mop_constants()
    if mop_type == constants.get("mop_S"):
        stack = {
            "stkoff": _optional_int(getattr(getattr(mop, "s", None), "off", None)),
            "size": size,
        }
        start_ea = _optional_int(
            getattr(getattr(mop, "s", None), "start_ea", None)
        )
        if start_ea is not None:
            stack["start_ea"] = start_ea
        result["stack"] = stack
    elif mop_type == constants.get("mop_r"):
        result["register"] = {"number": _optional_int(getattr(mop, "r", None))}
    elif mop_type == constants.get("mop_l"):
        idx = _optional_int(getattr(getattr(mop, "l", None), "idx", None))
        lvar: dict[str, object] = {"idx": idx}
        stkoff = _lvar_stkoff(mba, idx)
        if stkoff is not None:
            lvar["stkoff"] = stkoff
        result["lvar"] = lvar
    elif mop_type == constants.get("mop_v"):
        result["global"] = {"ea": _optional_int(getattr(mop, "g", None))}
    return result


def _format_instruction(ins: object) -> str | None:
    display = getattr(ins, "display", None)
    if display is not None:
        return str(display)
    try:
        from d810.hexrays.utils.hexrays_formatters import format_minsn_t

        return str(format_minsn_t(ins))
    except Exception:
        try:
            return str(ins)
        except Exception:
            return None


def _format_mop(mop: object) -> str | None:
    try:
        from d810.hexrays.utils.hexrays_formatters import format_mop_t

        return str(format_mop_t(mop))
    except Exception:
        try:
            dstr = getattr(mop, "dstr", None)
            if callable(dstr):
                return str(dstr())
            return str(mop)
        except Exception:
            return None


def _opcode_name(opcode: int | None) -> str | None:
    if opcode is None:
        return None
    try:
        from d810.hexrays.utils.hexrays_formatters import opcode_to_string

        return str(opcode_to_string(opcode))
    except Exception:
        return None


def _mop_in_list(mop: object, mop_list: Sequence[object]) -> bool:
    try:
        from d810.hexrays.utils.hexrays_helpers import get_mop_index

        return get_mop_index(mop, list(mop_list)) != -1
    except Exception:
        key = _fallback_mop_key(mop)
        return any(_fallback_mop_key(candidate) == key for candidate in mop_list)


def _fallback_mop_key(mop: object) -> tuple[object, ...]:
    mop_type = _optional_int(getattr(mop, "t", None))
    size = _optional_int(getattr(mop, "size", None))
    constants = _mop_constants()
    if mop_type == constants.get("mop_S"):
        return (
            mop_type,
            _optional_int(getattr(getattr(mop, "s", None), "off", None)),
        )
    if mop_type == constants.get("mop_r"):
        return (mop_type, _optional_int(getattr(mop, "r", None)))
    if mop_type == constants.get("mop_l"):
        return (
            mop_type,
            _optional_int(getattr(getattr(mop, "l", None), "idx", None)),
        )
    if mop_type == constants.get("mop_v"):
        return (mop_type, _optional_int(getattr(mop, "g", None)))
    return (mop_type, size, _format_mop(mop))


def _mop_kind(mop_type: int | None) -> str:
    for name, value in _mop_constants().items():
        if mop_type == value:
            return name
    return f"unknown_{mop_type}"


def _mop_constants() -> dict[str, int]:
    names = (
        "mop_a",
        "mop_b",
        "mop_c",
        "mop_d",
        "mop_f",
        "mop_fn",
        "mop_h",
        "mop_l",
        "mop_n",
        "mop_p",
        "mop_r",
        "mop_S",
        "mop_sc",
        "mop_str",
        "mop_v",
        "mop_z",
    )
    try:
        import ida_hexrays

        return {
            name: int(getattr(ida_hexrays, name))
            for name in names
            if hasattr(ida_hexrays, name)
        }
    except Exception:
        return {}


def _call_opcodes() -> set[int]:
    try:
        import ida_hexrays

        return {
            int(getattr(ida_hexrays, name))
            for name in ("m_call", "m_icall")
            if hasattr(ida_hexrays, name)
        }
    except Exception:
        return set()


def _lvar_stkoff(mba: object | None, idx: int | None) -> int | None:
    if mba is None or idx is None:
        return None
    try:
        var = getattr(mba, "vars")[idx]
        location = getattr(var, "location", None)
        stkoff = getattr(location, "stkoff", None)
        if callable(stkoff):
            return _optional_int(stkoff())
    except Exception:
        return None
    return None


def _optional_int(value: object | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def _serialize_value(value: object | None) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_serialize_value(item) for item in value]
    return {"type": type(value).__name__, "repr": repr(value)}


def _json_sanitize(value: object) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _json_sanitize(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_sanitize(item) for item in value]
    return repr(value)


__all__ = [
    "BAD_WHILE_LOOP_DEPENDENCY_DIAGNOSTICS_METADATA_KEY",
    "BadWhileLoopDependencyDiagnostic",
    "build_bad_while_loop_dependency_diagnostic",
    "extract_bad_while_loop_dependency_diagnostics",
    "serialize_bad_while_loop_dependency_diagnostics",
]
