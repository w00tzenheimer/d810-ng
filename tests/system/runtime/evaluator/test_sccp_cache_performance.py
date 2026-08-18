"""Explicit, phase-isolated SCCP/cache performance evidence gate.

The IDA work in this module is opt-in.  Every selected phase runs once in the
current IDA process and writes one atomic fragment; orchestration belongs to
the caller (normally one Docker invocation per phase plus the verifier's
merge command).  The ordinary unit tests below exercise receipt construction
and adversarial verification without importing IDA objects.
"""

from __future__ import annotations

from dataclasses import asdict
import ctypes
import hashlib
import importlib
import json
import gc
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
from d810.core.typing import Any

import pytest

_RUNTIME_DIR = Path(__file__).resolve().parents[1]
if str(_RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_DIR))
_EVALUATOR_DIR = Path(__file__).resolve().parent
if str(_EVALUATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALUATOR_DIR))
from verify_sccp_perf_receipt import (  # noqa: E402
    PHASE_INDEX,
    PHASE_ORDER,
    FixtureAttestationError,
    copy_fixture_with_attestation,
    load_fixture_attestation,
    merge_phase_fragments,
    phase_fragment_path,
    _process_start_evidence,
    _rows_by_label,
    _validate_cache_matrix,
    _validate_full_rows,
    verify,
    write_phase_fragment,
)


_SHA = "a" * 64
_EXPECTED_BINARY = "MMORPG_loader-115.9.6910.9-devirt.dll.i64"
_SHORT_BINARY = "libobfuscated.dll"
_DEFAULT_FUNCTION_EA = 0x7FF8560D8AE0
_MATURITY_LABEL = "GLBOPT1"
_SOURCE_IDB = str(Path("/Volumes/code/re/eid/115.9.6910.9") / _EXPECTED_BINARY)
_SCCP_COUNTERS = (
    "requests",
    "executions",
    "reuses",
    "fallbacks",
    "converged",
    "work_limit",
    "block_limit",
    "errors",
    "python_runs",
    "cython_runs",
    "cfg_events",
    "value_events",
    "adapter_seconds",
    "solver_seconds",
    "constants_exposed",
    "edges_exposed",
)

# This is deliberately computed once from the running process.  A caller may
# choose the phase label, but may not inject a marker that pretends to be a
# fresh process.
_PROCESS_IDENTITY: dict[str, Any] | None = None


def _phase_process_id(phase: str) -> str:
    """Identify the current fresh invocation, not only its container PID."""

    identity = _phase_process_identity()
    return f"{phase}:pid-{identity['pid']}:{identity['process_start_at_utc']}"


def _phase_process_identity() -> dict[str, Any]:
    global _PROCESS_IDENTITY
    if _PROCESS_IDENTITY is None:
        _PROCESS_IDENTITY = _process_start_evidence()
    return dict(_PROCESS_IDENTITY)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_hash(value: Any) -> str:
    return _sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )


def _default_binary() -> str:
    if os.environ.get("D810_PERF_SMOKE") == "1":
        return os.environ.get("D810_TEST_BINARY", _SHORT_BINARY)
    return os.environ.get("D810_TEST_BINARY", _EXPECTED_BINARY)


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[4]


def _fixture_input_path(binary_name: str) -> Path | None:
    for relative in ("samples/bins", "tests/_resources/bin", "tests/system/bins"):
        candidate = _repo_root() / relative / binary_name
        if candidate.is_file():
            return candidate
    return None


def _phase() -> str:
    phase = os.environ.get("D810_PERF_PHASE")
    if phase not in PHASE_INDEX:
        pytest.fail(
            "D810_PERF_PHASE must select exactly one of " + ", ".join(PHASE_ORDER),
            pytrace=False,
        )
    return phase


def _run_id() -> str:
    run_id = os.environ.get("D810_PERF_RUN_ID")
    if not run_id:
        pytest.fail(
            "D810_PERF_RUN_ID is required for isolated performance evidence",
            pytrace=False,
        )
    return run_id


def _receipt_dir() -> Path:
    configured = os.environ.get("D810_SCCP_RECEIPT_DIR")
    if not configured:
        pytest.fail(
            "D810_SCCP_RECEIPT_DIR is required for phase evidence", pytrace=False
        )
    return Path(configured)


def _binary_path() -> Path:
    path = _fixture_input_path(_default_binary())
    if path is None:
        pytest.fail(
            "BLOCKED: selected disposable fixture is unavailable: "
            f"{_repo_root() / 'samples' / 'bins' / _default_binary()}",
            pytrace=False,
        )
    return path


def _fixture_attestation() -> tuple[Path, dict[str, Any]]:
    configured = os.environ.get("D810_FIXTURE_ATTESTATION")
    if not configured:
        pytest.fail(
            "BLOCKED: D810_FIXTURE_ATTESTATION is required for every phase",
            pytrace=False,
        )
    path = Path(configured)
    try:
        return path, load_fixture_attestation(path)
    except Exception as exc:
        pytest.fail(f"BLOCKED: invalid fixture attestation: {exc}", pytrace=False)


def _function_ea() -> int:
    configured = os.environ.get("D810_SCCP_FUNCTION_EA")
    if configured:
        return int(configured, 0)
    if os.environ.get("D810_PERF_SMOKE") == "1":
        import idc

        for name in ("test_xor", "_test_xor", "test_chained_add"):
            ea = int(idc.get_name_ea_simple(name))
            if ea != 0xFFFFFFFFFFFFFFFF:
                return ea
        pytest.fail(
            "BLOCKED: short fixture has no configured smoke function", pytrace=False
        )
    return int(os.environ.get("D810_SCCP_FUNCTION_EA", hex(_DEFAULT_FUNCTION_EA)), 0)


def _require_compiled_backend(*, full: bool = False) -> dict[str, Any]:
    """Return live compiled-extension provenance; never silently fallback."""

    try:
        c_sccp = importlib.import_module("d810.speedups.evaluator.c_sccp")
        c_dataflow = importlib.import_module(
            "d810.speedups.optimizers.microcode.flow.constant_prop.c_dataflow"
        )
    except Exception as exc:
        pytest.fail(
            f"BLOCKED: compiled SCCP/dataflow extensions could not be imported: {exc}",
            pytrace=False,
        )
    c_solve = getattr(c_sccp, "solve", None)
    dataflow = getattr(c_dataflow, "run_dataflow_cython", None)
    if not callable(c_solve) or not callable(dataflow):
        pytest.fail(
            "BLOCKED: required compiled c_sccp.solve and "
            "c_dataflow.run_dataflow_cython are not callable",
            pytrace=False,
        )
    if full and os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1":
        from d810.core import CythonMode

        if not CythonMode().is_enabled():
            pytest.fail(
                "BLOCKED: D810_REQUIRE_COMPILED_SCCP=1 but CythonMode is disabled",
                pytrace=False,
            )

    def item(
        module: object,
        source_path: Path,
        callable_name: str,
    ) -> dict[str, Any]:
        module_file = Path(str(getattr(module, "__file__", ""))).resolve()
        if not module_file.is_file():
            pytest.fail(
                f"BLOCKED: compiled module has no live file: {module_file}",
                pytrace=False,
            )
        if not source_path.is_file():
            pytest.fail(
                "BLOCKED: compiled source attestation is unavailable", pytrace=False
            )
        if module_file.suffix not in {".so", ".dylib", ".pyd"}:
            pytest.fail(
                f"BLOCKED: {module_file} is not a compiled extension", pytrace=False
            )
        if not callable(getattr(module, callable_name, None)):
            pytest.fail(
                f"BLOCKED: compiled module is missing callable {callable_name}",
                pytrace=False,
            )
        return {
            "module_file": str(module_file),
            "module_sha256": _sha256_file(module_file),
            "module_mtime_ns": int(module_file.stat().st_mtime_ns),
            "build_abi": f"python-{platform.python_version()}-{platform.machine()}",
            "source_path": str(source_path),
            "source_hash": _sha256_file(source_path),
            "callable": True,
        }

    repo_root = Path(__file__).resolve().parents[4]
    c_item = item(
        c_sccp,
        repo_root / "src/d810/speedups/evaluator/c_sccp.pyx",
        "solve",
    )
    dataflow_item = item(
        c_dataflow,
        repo_root
        / "src/d810/speedups/optimizers/microcode/flow/constant_prop/c_dataflow.pyx",
        "run_dataflow_cython",
    )
    source_sha = _canonical_hash(
        {
            "c_sccp": c_item["source_hash"],
            "c_dataflow": dataflow_item["source_hash"],
        }
    )
    return {
        "c_sccp": c_item,
        "c_dataflow": dataflow_item,
        "source_sha256_at_build": source_sha,
        "source_tree_sha256": source_sha,
    }


def _metadata_base(
    function_name: str,
    program: dict[str, Any],
    blocks: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    counts: dict[str, int],
    fixture: Path,
    *,
    capture_lifecycle_events: int = 0,
    capture_optimizer_attempts: int = 0,
) -> dict[str, Any]:
    fixture_sha = _sha256_file(fixture)
    attestation_path, attestation = _fixture_attestation()
    if fixture_sha != attestation["fixture_sha256"]:
        pytest.fail(
            "BLOCKED: mounted fixture does not match attested fixture SHA256",
            pytrace=False,
        )
    if int(fixture.stat().st_size) != int(attestation["fixture_size_bytes"]):
        pytest.fail(
            "BLOCKED: mounted fixture does not match attested fixture size",
            pytrace=False,
        )
    workload_fingerprint = _canonical_hash({"blocks": blocks, "operations": operations})
    workload_hash = _canonical_hash(
        {"blocks": blocks, "operations": operations, "counts": counts}
    )
    build = _require_compiled_backend()
    return {
        "run_id": _run_id(),
        "gate_mode": "smoke" if os.environ.get("D810_PERF_SMOKE") == "1" else "exact",
        "binary": fixture.name,
        "binary_sha256": fixture_sha,
        "function_ea": _function_ea(),
        "function_name": function_name,
        "maturity": _MATURITY_LABEL,
        "platform": f"{platform.system()}-{platform.machine()}",
        "python": platform.python_version(),
        "ida_version": str(__import__("idaapi").get_kernel_version()),
        "source_path": attestation["source_path"],
        "fixture_source": attestation["source_path"],
        "source_sha256_at_copy": attestation["source_sha256_at_copy"],
        "source_sha256_before": attestation["source_sha256_before"],
        "source_sha256_after": attestation["source_sha256_after"],
        "source_size_bytes": attestation["source_size_bytes"],
        "fixture_path": str(fixture.resolve()),
        "fixture_copy": str(fixture.resolve()),
        "fixture_sha256": attestation["fixture_sha256"],
        "fixture_size_bytes": int(fixture.stat().st_size),
        "fixture_copied_at_utc": attestation["fixture_copied_at_utc"],
        "fixture_attestation_path": str(attestation_path.resolve()),
        "attestation_fixture_path": attestation["fixture_path"],
        "capture_method": "one hook-free GLBOPT1 MBA; detached primitive SCCP snapshot and live-coordinate cache replay",
        "capture_hooks_stopped": True,
        "capture_lifecycle_events": capture_lifecycle_events,
        "capture_optimizer_attempts": capture_optimizer_attempts,
        "workload_operations": len(operations),
        "workload_fingerprint": workload_fingerprint,
        "workload_hash": workload_hash,
        "workload_blocks_fingerprint": _canonical_hash(blocks),
        "snapshot_fingerprint": program["fingerprint"],
        "program_fingerprint": program["fingerprint"],
        "warmup": 3,
        "iterations": 10,
        "build_source_sha256": build["source_tree_sha256"],
        "build_provenance": build,
        "workload_lifetime": "capture-only-MBA; cache phase rehydrates live coordinates in its own hook-free MBA",
    }


def _assert_capture_hooks_stopped() -> int:
    """Assert no D810State lifecycle or optimizer context exists for capture."""

    try:
        from d810.manager import D810State

        state = D810State()
        if state.manager.started:
            pytest.fail(
                "BLOCKED: capture started with D810 hooks installed", pytrace=False
            )
        return int(bool(state.manager.started))
    except ImportError:
        return 0


def _gen_mba(function_ea: int) -> object:
    import ida_hexrays
    import idaapi

    function = idaapi.get_func(function_ea)
    if function is None:
        pytest.fail(f"BLOCKED: no function at 0x{function_ea:x}", pytrace=False)
    mba = ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(function),
        ida_hexrays.hexrays_failure_t(),
        None,
        ida_hexrays.DECOMP_NO_WAIT,
        ida_hexrays.MMAT_GLBOPT1,
    )
    if mba is None:
        pytest.fail(
            f"BLOCKED: could not generate MBA at 0x{function_ea:x}", pytrace=False
        )
    return mba


def _operand_to_dict(operand: object | None) -> dict[str, Any] | None:
    if operand is None:
        return None
    from d810.hexrays.diagnostics.microcode_capture import mop_to_dict

    return mop_to_dict(operand)


def _snapshot_descriptor(snapshot: object) -> dict[str, Any]:
    """Return every scalar field of a MopSnapshot, excluding its owned clone."""

    return {
        field: getattr(snapshot, field)
        for field in (
            "t",
            "size",
            "valnum",
            "value",
            "reg",
            "stkoff",
            "gaddr",
            "lvar_idx",
            "lvar_off",
            "block_num",
            "helper_name",
            "const_str",
            "pair_lo_t",
            "pair_hi_t",
        )
    }


def _mop_descriptor(mop: object | None) -> dict[str, Any] | None:
    if mop is None:
        return None
    from d810.hexrays.ir.mop_snapshot import MopSnapshot

    snapshot = MopSnapshot.from_mop(mop)
    return {
        "snapshot": _snapshot_descriptor(snapshot),
        "mop": _operand_to_dict(mop),
    }


def _instruction_descriptor(
    block_index: int,
    block: object,
    instruction_index: int,
    instruction: object,
) -> dict[str, Any]:
    return {
        "block_index": block_index,
        "block_serial": int(getattr(block, "serial", block_index)),
        "instruction_index": instruction_index,
        "opcode": int(getattr(instruction, "opcode", -1)),
        "ea": int(getattr(instruction, "ea", 0)),
        "size": int(getattr(instruction, "size", 0)),
        "text": str(instruction._print())
        if hasattr(instruction, "_print")
        else str(instruction),
        "operands": {
            attribute: _mop_descriptor(getattr(instruction, attribute, None))
            for attribute in ("l", "r", "d")
        },
    }


def _block_descriptor(
    block_index: int, block: object, instructions: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "index": block_index,
        "serial": int(getattr(block, "serial", block_index)),
        "start_ea": int(getattr(block, "start_ea", 0)),
        "end_ea": int(getattr(block, "end_ea", 0)),
        "type": int(getattr(block, "type", -1)),
        "flags": int(getattr(block, "flags", 0)),
        "predecessors": sorted(int(serial) for serial in list(block.predset)),
        "successors": sorted(int(serial) for serial in list(block.succset)),
        "instructions": instructions,
    }


def _mba_workload_descriptors(mba: object) -> list[dict[str, Any]]:
    """Capture all blocks/instructions and their complete l/r/d descriptors."""

    blocks: list[dict[str, Any]] = []
    for block_index in range(int(mba.qty)):
        block = mba.get_mblock(block_index)
        if block is None:
            continue
        instructions: list[dict[str, Any]] = []
        instruction = block.head
        instruction_index = 0
        while instruction is not None:
            instructions.append(
                _instruction_descriptor(
                    block_index, block, instruction_index, instruction
                )
            )
            instruction = instruction.next
            instruction_index += 1
        blocks.append(_block_descriptor(block_index, block, instructions))
    if not blocks or not any(block["instructions"] for block in blocks):
        raise RuntimeError("captured MBA has no blocks/instructions")
    return blocks


def _operation_outcome(value: object) -> str:
    return "none" if value is None else "value"


def _capture_real_workload(
    function_ea: int, fixture: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture one real MBA before D810State and persist only primitives."""

    lifecycle_before = _assert_capture_hooks_stopped()
    from d810.evaluator.hexrays_microcode.sccp_snapshot import snapshot_from_mba
    from d810.hexrays.expr.p_ast import get_constant_mop
    from d810.hexrays.ir.minsn_utils import minsn_to_ast
    from d810.hexrays.ir.mop_utils import mop_to_ast
    import ida_hexrays
    import idaapi

    mba = _gen_mba(function_ea)
    program = snapshot_from_mba(mba)
    blocks = _mba_workload_descriptors(mba)
    operations: list[dict[str, Any]] = []
    counts = {
        "l": 0,
        "r": 0,
        "d": 0,
        "minsn_to_ast": 0,
        "reconstructed_instruction_mops": 0,
        "mop_to_ast": 0,
        "get_constant_mop": 0,
        # Compatibility aliases retained, but they are derived from the
        # captured stream rather than estimated constants.
        "p_ast": 0,
        "mop_utils": 0,
    }

    for block in blocks:
        block_index = int(block["index"])
        live_block = mba.get_mblock(block_index)
        instruction = live_block.head
        for descriptor in block["instructions"]:
            instruction_index = int(descriptor["instruction_index"])
            location = {
                "block_index": block_index,
                "block_serial": int(block["serial"]),
                "instruction_index": instruction_index,
            }
            try:
                result = minsn_to_ast(instruction)
                outcome = _operation_outcome(result)
            except Exception as exc:
                outcome = f"exception:{type(exc).__name__}"
            operations.append({**location, "kind": "minsn_to_ast", "outcome": outcome})
            counts["minsn_to_ast"] += 1
            counts["mop_utils"] += 1

            reconstructed = ida_hexrays.mop_t()
            try:
                reconstructed.create_from_insn(instruction)
            except Exception as exc:
                operations.append(
                    {
                        **location,
                        "kind": "reconstructed_instruction_mop",
                        "outcome": f"exception:{type(exc).__name__}",
                        "descriptor": None,
                    }
                )
                counts["reconstructed_instruction_mops"] += 1
            else:
                reconstructed_descriptor = _mop_descriptor(reconstructed)
                operations.append(
                    {
                        **location,
                        "kind": "reconstructed_instruction_mop",
                        "outcome": "value",
                        "descriptor": reconstructed_descriptor,
                    }
                )
                counts["reconstructed_instruction_mops"] += 1
                try:
                    result = mop_to_ast(reconstructed)
                    outcome = _operation_outcome(result)
                except Exception as exc:
                    outcome = f"exception:{type(exc).__name__}"
                operations.append(
                    {
                        **location,
                        "kind": "reconstructed_mop_to_ast",
                        "outcome": outcome,
                        "descriptor": reconstructed_descriptor,
                    }
                )
                counts["mop_to_ast"] += 1
                counts["p_ast"] += 1

            for attribute in ("l", "r", "d"):
                mop = getattr(instruction, attribute, None)
                if mop is None or int(getattr(mop, "t", ida_hexrays.mop_z)) == int(
                    ida_hexrays.mop_z
                ):
                    continue
                counts[attribute] += 1
                descriptor_value = _mop_descriptor(mop)
                operations.append(
                    {
                        **location,
                        "kind": "mop_to_ast",
                        "attribute": attribute,
                        "outcome": "pending",
                        "descriptor": descriptor_value,
                    }
                )
                operation = operations[-1]
                try:
                    result = mop_to_ast(mop)
                    operation["outcome"] = _operation_outcome(result)
                except Exception as exc:
                    operation["outcome"] = f"exception:{type(exc).__name__}"
                counts["mop_to_ast"] += 1
                counts["p_ast"] += 1
                if int(getattr(mop, "t", -1)) == int(ida_hexrays.mop_n):
                    value = getattr(getattr(mop, "nnn", None), "value", None)
                    if value is not None:
                        constant_operation = {
                            **location,
                            "kind": "get_constant_mop",
                            "attribute": attribute,
                            "value": int(value),
                            "size": int(getattr(mop, "size", 0)),
                            "outcome": "pending",
                        }
                        try:
                            result = get_constant_mop(
                                int(value), int(getattr(mop, "size", 0))
                            )
                            constant_operation["outcome"] = _operation_outcome(result)
                        except Exception as exc:
                            constant_operation["outcome"] = (
                                f"exception:{type(exc).__name__}"
                            )
                        operations.append(constant_operation)
                        counts["get_constant_mop"] += 1
            instruction = instruction.next

    if not operations:
        pytest.fail("BLOCKED: real MBA produced no helper operations", pytrace=False)
    function_name = idaapi.get_name(function_ea) or f"sub_{function_ea:x}"
    lifecycle_after = _assert_capture_hooks_stopped()
    metadata = _metadata_base(
        function_name,
        {"fingerprint": program.fingerprint},
        blocks,
        operations,
        counts,
        fixture,
        capture_lifecycle_events=lifecycle_before + lifecycle_after,
        capture_optimizer_attempts=lifecycle_before + lifecycle_after,
    )
    metadata["capture_operation_counts"] = counts
    payload = {
        "metadata": metadata,
        "program": _program_to_dict(program),
        "blocks": blocks,
        "operations": operations,
        "operation_counts": counts,
    }
    return payload, metadata


def _program_to_dict(program: object) -> dict[str, Any]:
    def operand(value: object | None) -> dict[str, Any] | None:
        if value is None:
            return None
        return {
            "kind": value.kind.value,
            "size": value.size,
            "constant": value.constant,
            "value_id": value.value_id,
        }

    return {
        "fingerprint": program.fingerprint,
        "blocks": [
            {
                "index": block.index,
                "successors": list(block.successors),
                "instruction_indices": list(block.instruction_indices),
            }
            for block in program.blocks
        ],
        "instructions": [
            {
                "index": instruction.index,
                "block_index": instruction.block_index,
                "opcode": instruction.opcode,
                "ea": instruction.ea,
                "size": instruction.size,
                "left": operand(instruction.left),
                "right": operand(instruction.right),
                "destination_value_id": instruction.destination_value_id,
            }
            for instruction in program.instructions
        ],
        "mop_keys_by_value": {
            str(key): value for key, value in program.mop_keys_by_value.items()
        },
    }


def _program_from_dict(payload: dict[str, Any]) -> object:
    from d810.evaluator.hexrays_microcode.sccp_model import (
        OperandKind,
        SccpBlock,
        SccpInstruction,
        SccpOperand,
        SccpProgram,
    )

    def operand(value: dict[str, Any] | None) -> SccpOperand | None:
        if value is None:
            return None
        return SccpOperand(
            kind=OperandKind(value["kind"]),
            size=int(value["size"]),
            constant=value.get("constant"),
            value_id=value.get("value_id"),
        )

    blocks = [
        SccpBlock(
            index=int(item["index"]),
            successors=tuple(item["successors"]),
            instruction_indices=tuple(item["instruction_indices"]),
        )
        for item in payload["blocks"]
    ]
    instructions = [
        SccpInstruction(
            index=int(item["index"]),
            block_index=int(item["block_index"]),
            opcode=item["opcode"],
            ea=int(item["ea"]),
            size=int(item["size"]),
            left=operand(item.get("left")),
            right=operand(item.get("right")),
            destination_value_id=item.get("destination_value_id"),
        )
        for item in payload["instructions"]
    ]
    keys = {
        int(key): value for key, value in payload.get("mop_keys_by_value", {}).items()
    }
    program = SccpProgram.from_parts(
        blocks, instructions, keys, fingerprint_seed="sccp-snapshot-v1"
    )
    if program.fingerprint != payload["fingerprint"]:
        raise RuntimeError(
            "captured SCCP snapshot fingerprint changed during rehydration"
        )
    return program


def _load_capture() -> dict[str, Any]:
    path = phase_fragment_path(_receipt_dir(), _run_id(), "capture")
    if not path.is_file():
        pytest.fail(
            f"BLOCKED: capture phase fragment is missing: {path}", pytrace=False
        )
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        pytest.fail(
            f"BLOCKED: capture phase fragment is unreadable: {exc}", pytrace=False
        )
    if envelope.get("phase") != "capture" or envelope.get("run_id") != _run_id():
        pytest.fail(
            "BLOCKED: capture phase fragment has the wrong identity", pytrace=False
        )
    return envelope["payload"]


def _current_rss_bytes() -> int:
    """Read current resident RSS, avoiding ru_maxrss high-water semantics."""

    if platform.system() == "Linux":
        try:
            resident_pages = int(Path("/proc/self/statm").read_text().split()[1])
            return resident_pages * int(os.sysconf("SC_PAGE_SIZE"))
        except (OSError, ValueError, IndexError):
            pass
    if platform.system() == "Darwin":
        try:
            result = subprocess.run(
                ["ps", "-o", "rss=", "-p", str(os.getpid())],
                check=True,
                capture_output=True,
                text=True,
            )
            return int(result.stdout.strip()) * 1024
        except (OSError, ValueError, subprocess.SubprocessError):
            pass
    try:
        import resource

        value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
        return value * 1024
    except (ImportError, OSError, ValueError):
        return 0


def _parity_projection(result: object) -> dict[str, Any]:
    constants = [
        [repr(key), value]
        for key, value in sorted(
            result.constants.items(), key=lambda item: repr(item[0])
        )
    ]
    return {
        "status": result.status.value,
        "constants": constants,
        "executable_edges": [list(edge) for edge in sorted(result.executable_edges)],
        "reachable_blocks": sorted(result.reachable_blocks),
        "program_fingerprint": result.program_fingerprint,
        "cfg_events": int(result.cfg_events),
        "value_events": int(result.value_events),
        "peak_cfg_queue": int(result.peak_cfg_queue),
        "peak_value_queue": int(result.peak_value_queue),
    }


def _zero_summary() -> dict[str, int | float]:
    return {field: 0 for field in _SCCP_COUNTERS}


def _solver_summary(
    results: list[object], backend: str, *, adapter_seconds: float = 0.0
) -> dict[str, int | float]:
    summary = _zero_summary()
    summary["requests"] = len(results)
    summary["executions"] = len(results)
    summary["adapter_seconds"] = float(adapter_seconds)
    for result in results:
        status = result.status.value
        summary["converged"] += int(status == "converged")
        summary["work_limit"] += int(status == "work_limit")
        summary["block_limit"] += int(status == "block_limit")
        summary["errors"] += int(status == "error")
        actual_backend = str(result.backend).lower()
        summary["python_runs"] += int(actual_backend.startswith("python"))
        summary["cython_runs"] += int(actual_backend.startswith("cython"))
        summary["fallbacks"] += int(
            "fallback" in actual_backend or bool(result.fallback_reason)
        )
        summary["cfg_events"] += int(result.cfg_events)
        summary["value_events"] += int(result.value_events)
        summary["solver_seconds"] += float(result.solver_seconds)
        summary["constants_exposed"] += len(result.constants)
        summary["edges_exposed"] += len(result.executable_edges)
    return summary


def _solver_phase(backend: str) -> dict[str, Any]:
    capture = _load_capture()
    program = _program_from_dict(capture["program"])
    if backend == "python":
        from d810.evaluator.hexrays_microcode import p_sccp

        solver = p_sccp.solve
    else:
        build = _require_compiled_backend()
        del build
        from d810.core import CythonMode
        from d810.evaluator.hexrays_microcode import _fast_sccp

        CythonMode().enable()
        solver = _fast_sccp.solve
    warmup = 3
    iterations = 10
    replay_results: list[object] = []
    for _ in range(warmup):
        replay_results.append(solver(program))
    samples: list[float] = []
    measured_results: list[object] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = solver(program)
        samples.append(time.perf_counter() - started)
        measured_results.append(result)
    replay_results.extend(measured_results)
    first = measured_results[0]
    if any(
        _parity_projection(result) != _parity_projection(first)
        for result in replay_results[1:]
    ):
        raise RuntimeError(
            f"{backend} solver changed semantics across measured replays"
        )
    if any(result.status.value != "converged" for result in replay_results):
        pytest.fail(
            f"BLOCKED: {backend} solver replay did not converge for every call",
            pytrace=False,
        )
    if any(str(result.backend).lower() != backend for result in replay_results):
        pytest.fail(
            f"BLOCKED: {backend} solver phase selected a fallback",
            pytrace=False,
        )
    projection = _parity_projection(first)
    row = {
        "phase": f"solver_{backend}",
        "run_id": _run_id(),
        "process_id": _phase_process_id(f"solver_{backend}"),
        "process_identity": _phase_process_identity(),
        "database_marker": f"{Path(__file__).name}:{_phase_process_id(f'solver_{backend}')}",
        "fresh_process": True,
        "kind": "solver_replay",
        "label": f"solver_{backend}",
        "function_ea": capture["metadata"]["function_ea"],
        "maturity": _MATURITY_LABEL,
        "overlay": "replay",
        "backend": backend,
        "status": first.status.value,
        "program_fingerprint": first.program_fingerprint,
        "program_identity_group": "capture_snapshot",
        "snapshot_fingerprint": capture["metadata"]["snapshot_fingerprint"],
        "workload_fingerprint": capture["metadata"]["workload_fingerprint"],
        "wall_seconds": float(sum(samples)),
        "sccp_summary": _solver_summary(replay_results, backend),
        "parity_projection": projection,
        "parity_sha256": _canonical_hash(projection),
        "samples_seconds": samples,
        "median_seconds": statistics.median(samples),
        "p95_seconds": statistics.quantiles(samples, n=20, method="inclusive")[18],
        "warmup": warmup,
        "iterations": iterations,
    }
    return {"row": row}


def _live_cfg_sha256(function_ea: int) -> str:
    import idaapi

    function = idaapi.get_func(function_ea)
    if function is None:
        raise RuntimeError(f"no live function at 0x{function_ea:x}")
    blocks = []
    for block in idaapi.FlowChart(function):
        blocks.append(
            (
                int(block.start_ea),
                int(block.end_ea),
                tuple(sorted(int(successor.start_ea) for successor in block.succs())),
            )
        )
    if not blocks:
        raise RuntimeError("live CFG has no blocks")
    return _canonical_hash(sorted(blocks))


def _pseudocode_sha256(cfunc: object) -> str:
    import idaapi

    lines = getattr(cfunc, "get_pseudocode", lambda: ())()
    rendered = "\n".join(idaapi.tag_remove(line.line) for line in lines)
    if not rendered:
        raise RuntimeError("decompilation returned no pseudocode")
    return _sha256_text(rendered)


def _cache_stat_dict(
    cache: object,
    *,
    memory_delta: int,
    rss_before: int,
    rss_after: int,
    rss_current: int,
    rss_peak: int,
    real_api_calls: int,
) -> dict[str, Any]:
    stats = asdict(cache.stats)
    stats["memory_delta_bytes"] = int(memory_delta)
    stats["rss_before_bytes"] = int(rss_before)
    stats["rss_after_bytes"] = int(rss_after)
    stats["rss_current_bytes"] = int(rss_current)
    stats["rss_peak_bytes"] = int(rss_peak)
    stats["real_api_calls"] = int(real_api_calls)
    return stats


def _cache_stats(
    *,
    memory_delta: int,
    rss_before: int,
    rss_after: int,
    rss_current: int,
    rss_peak: int,
) -> dict[str, Any]:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE

    constant = _cache_stat_dict(
        MOP_CONSTANT_CACHE,
        memory_delta=memory_delta,
        rss_before=rss_before,
        rss_after=rss_after,
        rss_current=rss_current,
        rss_peak=rss_peak,
        real_api_calls=int(MOP_CONSTANT_CACHE.stats.lookups),
    )
    ast = _cache_stat_dict(
        MOP_TO_AST_CACHE,
        memory_delta=memory_delta,
        rss_before=rss_before,
        rss_after=rss_after,
        rss_current=rss_current,
        rss_peak=rss_peak,
        real_api_calls=int(MOP_TO_AST_CACHE.stats.lookups),
    )
    return {
        "MOP_CONSTANT_CACHE": constant,
        "MOP_TO_AST_CACHE": ast,
        "total_evictions": int(
            constant["capacity_evictions"] + ast["capacity_evictions"]
        ),
        "memory_delta_bytes": int(memory_delta),
        "rss_before_bytes": int(rss_before),
        "rss_after_bytes": int(rss_after),
        "rss_current_bytes": int(rss_current),
        "rss_peak_bytes": int(rss_peak),
        "real_api_calls": int(constant["real_api_calls"] + ast["real_api_calls"]),
    }


def _reset_runtime_state() -> None:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
    from d810.evaluator.hexrays_microcode.sccp import reset_sccp_session

    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    reset_sccp_session()


def _live_instruction(mba: object, operation: dict[str, Any]) -> object:
    block = mba.get_mblock(int(operation["block_index"]))
    if block is None:
        raise RuntimeError(f"workload block {operation['block_index']} disappeared")
    instruction = block.head
    for _ in range(int(operation["instruction_index"])):
        if instruction is None:
            raise RuntimeError("workload instruction coordinate disappeared")
        instruction = instruction.next
    if instruction is None:
        raise RuntimeError("workload instruction coordinate resolved to null")
    return instruction


def _replay_operation(
    mba: object,
    operation: dict[str, Any],
    *,
    minsn_to_ast: object,
    mop_to_ast: object,
    get_constant_mop: object,
    ida_hexrays: object,
) -> str:
    instruction = _live_instruction(mba, operation)
    kind = operation["kind"]
    try:
        if kind == "minsn_to_ast":
            result = minsn_to_ast(instruction)
        elif kind == "reconstructed_instruction_mop":
            mop = ida_hexrays.mop_t()
            mop.create_from_insn(instruction)
            result = mop
        elif kind == "reconstructed_mop_to_ast":
            mop = ida_hexrays.mop_t()
            mop.create_from_insn(instruction)
            result = mop_to_ast(mop)
        elif kind == "mop_to_ast":
            mop = getattr(instruction, operation["attribute"])
            result = mop_to_ast(mop)
        elif kind == "get_constant_mop":
            result = get_constant_mop(int(operation["value"]), int(operation["size"]))
        else:
            raise RuntimeError(f"unknown captured workload operation {kind!r}")
    except Exception as exc:
        outcome = f"exception:{type(exc).__name__}"
    else:
        outcome = _operation_outcome(result)
    if outcome != operation["outcome"]:
        raise RuntimeError(
            "captured workload operation result changed: "
            f"{kind} at block={operation['block_index']} "
            f"instruction={operation['instruction_index']} "
            f"{operation['outcome']!r} != {outcome!r}"
        )
    return outcome


def _replay_operation_counts(operations: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "l": 0,
        "r": 0,
        "d": 0,
        "minsn_to_ast": 0,
        "reconstructed_instruction_mops": 0,
        "mop_to_ast": 0,
        "get_constant_mop": 0,
        "p_ast": 0,
        "mop_utils": 0,
    }
    for operation in operations:
        kind = operation["kind"]
        if kind == "minsn_to_ast":
            counts["minsn_to_ast"] += 1
            counts["mop_utils"] += 1
        elif kind == "reconstructed_instruction_mop":
            counts["reconstructed_instruction_mops"] += 1
        elif kind in {"reconstructed_mop_to_ast", "mop_to_ast"}:
            counts["mop_to_ast"] += 1
            counts["p_ast"] += 1
            if kind == "mop_to_ast":
                counts[str(operation["attribute"])] += 1
        elif kind == "get_constant_mop":
            counts["get_constant_mop"] += 1
    return counts


def _configure_policy(state: object, backend: str, overlay: str) -> None:
    from d810.core import CythonMode

    if backend == "cython":
        CythonMode().enable()
        if (
            os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1"
            and not CythonMode().is_enabled()
        ):
            pytest.fail("BLOCKED: CythonMode did not enable", pytrace=False)
    elif backend == "python":
        CythonMode().disable()
    else:
        raise ValueError(f"unsupported backend {backend!r}")
    found = False
    for rule in list(getattr(state, "current_blk_rules", ())):
        name = str(getattr(rule, "name", rule.__class__.__name__)).lower()
        if name == "forwardconstantpropagationrule":
            rule.cython_enabled = backend == "cython"
            rule.sccp_overlay = overlay
            found = True
    if not found:
        pytest.fail(
            "BLOCKED: ForwardConstantPropagationRule is not active", pytrace=False
        )


def _full_fcp_evidence(
    state: object, result: object, session: dict[str, Any]
) -> tuple[dict[str, Any], list[str]]:
    """Project the live FCP usage and SCCP consumer outcome into the row."""

    stats = getattr(state, "stats", None)
    usage_map = getattr(stats, "cfg_rule_usages", {}) if stats is not None else {}
    raw_counts = list(usage_map.get("ForwardConstantPropagationRule", ()))
    patch_counts: list[int] = []
    for index, count in enumerate(raw_counts):
        if type(count) is not int or count < 0:
            pytest.fail(
                "BLOCKED: invalid live ForwardConstantPropagationRule patch count "
                f"at index {index}: {count!r}",
                pytrace=False,
            )
        patch_counts.append(count)

    abstention_reasons: list[str] = []
    consumer_status = str(result.status.value)
    fallback_reason = str(getattr(result, "fallback_reason", "") or "")
    if consumer_status != "converged":
        abstention_reasons.append(f"sccp_status:{consumer_status}")
    if fallback_reason:
        abstention_reasons.append(f"sccp_fallback:{fallback_reason}")
    for field in ("fallbacks", "work_limit", "block_limit", "errors"):
        count = int(session.get(field, 0))
        if count:
            abstention_reasons.append(f"sccp_{field}:{count}")
    consumer_outcome = "converged" if not abstention_reasons else "abstained"
    evidence = {
        "rule": "ForwardConstantPropagationRule",
        "patch_counts": patch_counts,
        "patch_total": sum(patch_counts),
        "consumer_status": consumer_status,
        "consumer_backend": str(result.backend),
        "consumer_outcome": consumer_outcome,
        "fallback_reason": fallback_reason,
        "abstention_reasons": list(abstention_reasons),
    }
    return evidence, abstention_reasons


def _full_phase(
    state: object, label: str, backend: str, overlay: str
) -> dict[str, Any]:
    import idaapi
    from d810.core import temporary_mop_cache_policy
    from d810.evaluator.hexrays_microcode.sccp import run_sccp_ex, sccp_session_stats
    from d810.evaluator.hexrays_microcode.sccp_snapshot import snapshot_from_mba

    capture = _load_capture()
    function_ea = int(capture["metadata"]["function_ea"])
    _configure_policy(state, backend, overlay)
    _reset_runtime_state()
    if getattr(state, "stats", None) is not None:
        state.stats.reset()
    capacity = None
    if label == "winner":
        cache_phase = json.loads(
            phase_fragment_path(_receipt_dir(), _run_id(), "cache").read_text(
                encoding="utf-8"
            )
        )["payload"]["cache_matrix"]
        winner = min(
            cache_phase,
            key=lambda row: (
                row["wall_seconds"],
                row["constant_capacity"],
                row["ast_capacity"],
            ),
        )
        capacity = (int(winner["constant_capacity"]), int(winner["ast_capacity"]))
    rss_before = _current_rss_bytes()
    cache_stats: dict[str, Any] | None = None
    if capacity is None:
        started = time.perf_counter()
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        wall_seconds = time.perf_counter() - started
        rss_after = _current_rss_bytes()
    else:
        with temporary_mop_cache_policy(*capacity):
            started = time.perf_counter()
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            wall_seconds = time.perf_counter() - started
            rss_after = _current_rss_bytes()
            cache_stats = _cache_stats(
                memory_delta=rss_after - rss_before,
                rss_before=rss_before,
                rss_after=rss_after,
                rss_current=rss_after,
                rss_peak=rss_after,
            )
    rss_peak = max(rss_before, rss_after, _current_rss_bytes())
    if cfunc is None:
        pytest.fail(
            f"BLOCKED: full decompilation failed for 0x{function_ea:x}", pytrace=False
        )
    if cache_stats is None:
        cache_stats = _cache_stats(
            memory_delta=rss_after - rss_before,
            rss_before=rss_before,
            rss_after=rss_after,
            rss_current=rss_after,
            rss_peak=rss_peak,
        )
    memory_delta = rss_after - rss_before
    cache_stats["rss_peak_bytes"] = rss_peak
    cache_stats["MOP_CONSTANT_CACHE"]["rss_peak_bytes"] = rss_peak
    cache_stats["MOP_TO_AST_CACHE"]["rss_peak_bytes"] = rss_peak
    pseudocode_sha = _pseudocode_sha256(cfunc)
    live_pseudocode_sha = _pseudocode_sha256(cfunc)
    cfg_sha = _live_cfg_sha256(function_ea)
    live_cfg_sha = _live_cfg_sha256(function_ea)
    live_program = snapshot_from_mba(cfunc.mba)
    # Baseline/off still records a real SCCP session summary.  This request is
    # outside the one timed full decomp and gives every full row the same proof
    # contract without adding a second decompilation.
    result = run_sccp_ex(cfunc.mba)
    if result is None:
        pytest.fail("BLOCKED: live SCCP facade returned no result", pytrace=False)
    if getattr(result, "backend", None) != backend:
        pytest.fail(
            "BLOCKED: selected full phase backend was not exercised: "
            f"expected {backend}, got {getattr(result, 'backend', None)!r}",
            pytrace=False,
        )
    session = sccp_session_stats().as_dict()
    if session["requests"] <= 0 or session["executions"] <= 0:
        pytest.fail(
            "BLOCKED: full phase emitted no real SCCP request/execution", pytrace=False
        )
    fcp_evidence, abstention_reasons = _full_fcp_evidence(state, result, session)
    build = (
        _require_compiled_backend(full=backend == "cython")
        if backend == "cython"
        else _require_compiled_backend()
    )
    row = {
        "phase": label,
        "run_id": _run_id(),
        "process_id": _phase_process_id(label),
        "process_identity": _phase_process_identity(),
        "database_marker": f"{Path(__file__).name}:{_phase_process_id(label)}",
        "fresh_process": True,
        "kind": "full_decomp",
        "label": label,
        "function_ea": function_ea,
        "maturity": _MATURITY_LABEL,
        "overlay": overlay,
        "backend": backend,
        "status": result.status.value,
        "program_fingerprint": live_program.fingerprint,
        "program_identity_group": "full_decomp",
        "wall_seconds": wall_seconds,
        "adapter_seconds": float(session["adapter_seconds"]),
        "solver_seconds": float(session["solver_seconds"]),
        "sccp_summary": session,
        "fcp_patches": int(fcp_evidence["patch_total"]),
        "fcp_evidence": fcp_evidence,
        "abstentions": abstention_reasons,
        "cache_stats": cache_stats,
        "memory_delta_bytes": memory_delta,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": rss_after,
        "rss_current_bytes": rss_after,
        "rss_peak_bytes": rss_peak,
        "pseudocode_sha256": pseudocode_sha,
        "live_pseudocode_sha256": live_pseudocode_sha,
        "cfg_sha256": cfg_sha,
        "live_cfg_sha256": live_cfg_sha,
        "evidence_origin": {
            "pseudocode": "live_cfunc",
            "cfg": "live_flowchart",
            "program": "live_mba",
        },
        "parity_projection": _parity_projection(result),
        "parity_sha256": _canonical_hash(_parity_projection(result)),
        "compiled_provenance": build,
        "capacity": {"constant": capacity[0], "ast": capacity[1]}
        if capacity
        else {"constant": 4096, "ast": 40960},
    }
    return {"row": row}


def _cache_phase() -> dict[str, Any]:
    """Replay one captured workload through nine real cache policies exactly once."""

    capture = _load_capture()
    captured_blocks = capture["blocks"]
    operations = capture["operations"]
    counts = capture["operation_counts"]
    function_ea = int(capture["metadata"]["function_ea"])
    import ida_hexrays
    from d810.core import (
        MOP_CONSTANT_CACHE,
        MOP_TO_AST_CACHE,
        temporary_mop_cache_policy,
    )
    from d810.hexrays.expr.p_ast import get_constant_mop
    from d810.hexrays.ir.minsn_utils import minsn_to_ast
    from d810.hexrays.ir.mop_utils import mop_to_ast

    rows = []
    for constant_capacity in (1000, 4096, 8192):
        for ast_capacity in (20480, 40960, 81920):
            gc.collect()
            _reset_runtime_state()
            mba = _gen_mba(function_ea)
            fresh_blocks = _mba_workload_descriptors(mba)
            expected_blocks_hash = capture["metadata"]["workload_blocks_fingerprint"]
            if _canonical_hash(fresh_blocks) != expected_blocks_hash:
                raise RuntimeError(
                    "fresh MBA block/instruction descriptors differ from capture"
                )
            expected_workload = capture["metadata"]["workload_fingerprint"]
            if (
                _canonical_hash({"blocks": fresh_blocks, "operations": operations})
                != expected_workload
            ):
                raise RuntimeError(
                    "fresh MBA workload fingerprint differs from capture"
                )
            if captured_blocks != fresh_blocks and _canonical_hash(
                captured_blocks
            ) != _canonical_hash(fresh_blocks):
                raise RuntimeError("captured and fresh block descriptors are not equal")
            rss_before = _current_rss_bytes()
            rss_peak = rss_before
            replay_counts = {name: 0 for name in counts}
            with temporary_mop_cache_policy(constant_capacity, ast_capacity):
                started = time.perf_counter()
                for operation in operations:
                    _replay_operation(
                        mba,
                        operation,
                        minsn_to_ast=minsn_to_ast,
                        mop_to_ast=mop_to_ast,
                        get_constant_mop=get_constant_mop,
                        ida_hexrays=ida_hexrays,
                    )
                    kind = operation["kind"]
                    if kind == "minsn_to_ast":
                        replay_counts["minsn_to_ast"] += 1
                        replay_counts["mop_utils"] += 1
                    elif kind == "reconstructed_instruction_mop":
                        replay_counts["reconstructed_instruction_mops"] += 1
                    elif kind in {"mop_to_ast", "reconstructed_mop_to_ast"}:
                        replay_counts["mop_to_ast"] += 1
                        replay_counts["p_ast"] += 1
                        if kind == "mop_to_ast":
                            replay_counts[str(operation["attribute"])] += 1
                    elif kind == "get_constant_mop":
                        replay_counts["get_constant_mop"] += 1
                    rss_peak = max(rss_peak, _current_rss_bytes())
                if replay_counts != counts:
                    raise RuntimeError(
                        "cache replay operation counts differ from capture: "
                        f"{replay_counts!r} != {counts!r}"
                    )
                replayed_operations = len(operations)
                rss_after = _current_rss_bytes()
                rss_peak = max(rss_peak, rss_after)
                wall_seconds = time.perf_counter() - started
                cache_stats = _cache_stats(
                    memory_delta=rss_after - rss_before,
                    rss_before=rss_before,
                    rss_after=rss_after,
                    rss_current=rss_after,
                    rss_peak=rss_peak,
                )
                rebuilds = int(
                    MOP_CONSTANT_CACHE.stats.insertions
                    + MOP_TO_AST_CACHE.stats.insertions
                )
                evictions = int(cache_stats["total_evictions"])
                peak_weight = float(
                    MOP_CONSTANT_CACHE.stats.max_weight_ever
                    + MOP_TO_AST_CACHE.stats.max_weight_ever
                )
            memory_delta = rss_after - rss_before
            rows.append(
                {
                    "phase": "cache",
                    "run_id": _run_id(),
                    "process_id": _phase_process_id("cache"),
                    "process_identity": _phase_process_identity(),
                    "database_marker": f"{Path(__file__).name}:{_phase_process_id('cache')}:{constant_capacity}:{ast_capacity}",
                    "fresh_process": True,
                    "kind": "cache_replay",
                    "label": f"cache_{constant_capacity}_{ast_capacity}",
                    "function_ea": function_ea,
                    "maturity": _MATURITY_LABEL,
                    "overlay": "replay",
                    "backend": "runtime",
                    "status": "converged",
                    "wall_seconds": wall_seconds,
                    "workload_fingerprint": capture["metadata"]["workload_fingerprint"],
                    "workload_hash": capture["metadata"]["workload_hash"],
                    "workload_operations": len(operations),
                    "replayed_operations": replayed_operations,
                    "operation_counts": counts,
                    "cache_stats": cache_stats,
                    "constant_capacity": constant_capacity,
                    "ast_capacity": ast_capacity,
                    "rebuilds": rebuilds,
                    "evictions": evictions,
                    "peak_weight": peak_weight,
                    "memory_delta_bytes": memory_delta,
                    "rss_before_bytes": rss_before,
                    "rss_after_bytes": rss_after,
                    "rss_current_bytes": rss_after,
                    "rss_peak_bytes": rss_peak,
                    "real_api_calls": int(cache_stats["real_api_calls"]),
                }
            )
    if len(rows) != 9:
        raise AssertionError(f"cache phase generated {len(rows)} rows, expected nine")
    return {
        "cache_matrix": rows,
        "workload_lifetime": "live MBA rehydrated from captured block/instruction/attribute coordinates; no detached mop claimed",
    }


def _write_phase(phase: str, payload: dict[str, Any]) -> None:
    write_phase_fragment(
        _receipt_dir(),
        _run_id(),
        phase,
        payload,
        process_id=_phase_process_id(phase),
        database_marker=f"{Path(__file__).name}:{_phase_process_id(phase)}",
        process_identity=_phase_process_identity(),
    )


@pytest.fixture(scope="session", autouse=True)
def _perf_gate_session_prerequisite() -> None:
    """Fail explicitly before IDA fixtures can skip or substitute input."""

    if os.environ.get("D810_PERF_GATE") != "1":
        return
    binary_name = _default_binary()
    smoke = os.environ.get("D810_PERF_SMOKE") == "1"
    if not smoke and binary_name != _EXPECTED_BINARY:
        pytest.fail(
            f"BLOCKED: exact performance gate requires {_EXPECTED_BINARY}, got {binary_name!r}",
            pytrace=False,
        )
    fixture = _fixture_input_path(binary_name)
    if fixture is None:
        pytest.fail(f"BLOCKED: fixture is unavailable: {binary_name}", pytrace=False)
    _attestation_path, attestation = _fixture_attestation()
    expected = os.environ.get("D810_EXPECTED_FIXTURE_SHA256")
    if not expected:
        pytest.fail("BLOCKED: D810_EXPECTED_FIXTURE_SHA256 is required", pytrace=False)
    actual = _sha256_file(fixture)
    if expected != actual:
        pytest.fail(
            "BLOCKED: mounted fixture SHA256 does not match D810_EXPECTED_FIXTURE_SHA256",
            pytrace=False,
        )
    if actual != attestation["fixture_sha256"] or int(fixture.stat().st_size) != int(
        attestation["fixture_size_bytes"]
    ):
        pytest.fail(
            "BLOCKED: mounted fixture does not match D810_FIXTURE_ATTESTATION",
            pytrace=False,
        )
    if (
        not smoke
        and os.environ.get("D810_SCCP_FUNCTION_EA", hex(_DEFAULT_FUNCTION_EA)).lower()
        != hex(_DEFAULT_FUNCTION_EA).lower()
    ):
        pytest.fail(
            "BLOCKED: exact gate received a substituted function EA", pytrace=False
        )
    if os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1":
        _require_compiled_backend()


@pytest.fixture(scope="class")
def perf_gate_prerequisite(
    _perf_gate_session_prerequisite, libobfuscated_setup
) -> None:
    if os.environ.get("D810_PERF_GATE") != "1":
        pytest.skip(
            "SCCP performance collection is opt-in; set D810_PERF_GATE=1",
        )
    import idaapi

    if idaapi.get_func(_function_ea()) is None:
        pytest.fail(
            f"BLOCKED: selected database has no function 0x{_function_ea():x}",
            pytrace=False,
        )


class TestSccpCachePerformance:
    """Run exactly the selected phase; never orchestrate sibling phases."""

    binary_name = _default_binary()

    @pytest.mark.ida_required
    def test_one_explicit_fresh_phase(
        self,
        perf_gate_prerequisite,
        libobfuscated_setup,
        d810_state_all_rules,
    ) -> None:
        phase = _phase()
        fixture = _binary_path()
        if phase == "capture":
            payload, _metadata = _capture_real_workload(_function_ea(), fixture)
            _write_phase(phase, payload)
            return
        if phase == "solver_python":
            _write_phase(phase, _solver_phase("python"))
            return
        if phase == "solver_cython":
            _write_phase(phase, _solver_phase("cython"))
            return
        if phase == "cache":
            _write_phase(phase, _cache_phase())
            return
        with d810_state_all_rules() as state:
            _write_phase(
                phase,
                _full_phase(
                    state,
                    phase,
                    "python" if phase == "baseline" else "cython",
                    "off"
                    if phase == "baseline"
                    else "on"
                    if phase == "candidate"
                    else "auto",
                ),
            )

    @pytest.mark.ida_required
    @pytest.mark.profile
    def test_bounded_post_preopt_profile(
        self,
        perf_gate_prerequisite,
        libobfuscated_setup,
        d810_state_all_rules,
    ) -> None:
        """Capture a bounded compiled profile without running receipt phases."""

        import idaapi
        from d810.core import CythonMode, temporary_mop_cache_policy
        from d810.optimizers.microcode.instructions.pattern_matching.engine import (
            get_engine_info,
        )

        overlay = os.environ.get("D810_PROFILE_SCCP_OVERLAY", "on")
        if overlay not in {"on", "off"}:
            pytest.fail("D810_PROFILE_SCCP_OVERLAY must be on or off", pytrace=False)
        duration = float(os.environ.get("D810_PROFILE_SECONDS", "180"))
        if not (1.0 <= duration <= 300.0):
            pytest.fail("D810_PROFILE_SECONDS must be between 1 and 300", pytrace=False)
        label = os.environ.get("D810_PROFILE_LABEL", f"compiled-overlay-{overlay}")
        if not label or Path(label).name != label:
            pytest.fail("D810_PROFILE_LABEL must be a basename", pytrace=False)
        output_dir = Path(".tmp/profiles") / label
        output_dir.mkdir(parents=True, exist_ok=True)
        controller_mode = os.environ.get("D810_PROFILE_CONTROLLER", "on")
        if controller_mode not in {"on", "off"}:
            pytest.fail("D810_PROFILE_CONTROLLER must be on or off", pytrace=False)

        class ProfileWindowExpired(BaseException):
            pass

        timed_out = False
        interrupted = threading.Event()
        main_thread_id = threading.get_ident()

        def expire_profile_window() -> None:
            if interrupted.wait(duration):
                return
            result = ctypes.pythonapi.PyThreadState_SetAsyncExc(
                ctypes.c_ulong(main_thread_id), ctypes.py_object(ProfileWindowExpired)
            )
            if result != 1:
                (output_dir / "watchdog-error.txt").write_text(
                    f"PyThreadState_SetAsyncExc returned {result}\n", encoding="utf-8"
                )

        with d810_state_all_rules() as state:
            CythonMode().enable()
            pattern_engine = get_engine_info()
            if pattern_engine.get("backend") != "cython":
                pytest.fail(
                    "BLOCKED: bounded compiled profile requires the Cython pattern "
                    f"engine, observed {pattern_engine}",
                    pytrace=False,
                )
            _configure_policy(state, "cython", overlay)
            _reset_runtime_state()
            state.stats.reset()
            controller = state.manager.profiling
            controller.log_dir = output_dir
            if controller.profiler is None or controller.cprofiler is None:
                pytest.fail(
                    "BLOCKED: ProfilingController lacks pyinstrument or cProfile",
                    pytrace=False,
                )
            if controller_mode == "on":
                controller.enable()
            watchdog = threading.Thread(
                target=expire_profile_window,
                name="d810-bounded-profile-watchdog",
                daemon=True,
            )
            watchdog.start()
            started = time.perf_counter()
            try:
                with temporary_mop_cache_policy(4096, 40960):
                    idaapi.decompile(_function_ea(), flags=idaapi.DECOMP_NO_CACHE)
            except ProfileWindowExpired:
                timed_out = True
            finally:
                elapsed = time.perf_counter() - started
                interrupted.set()
                watchdog.join(timeout=1.0)
                if controller_mode == "on" and controller.cprofiler.is_running:
                    controller.cprofiler.disable()
                    controller.cprofiler.profiler.dump_stats(
                        str(output_dir / "d810_cprofile.prof")
                    )
                if controller_mode == "on" and getattr(
                    controller.profiler, "is_running", False
                ):
                    controller.profiler.stop()
                    (output_dir / "d810_profile.html").write_text(
                        controller.profiler.output_html(), encoding="utf-8"
                    )
                    (output_dir / "d810_profile.txt").write_text(
                        controller.profiler.output_text(
                            unicode=False, color=False, show_all=True
                        ),
                        encoding="utf-8",
                    )
                metadata = {
                    "duration_limit_seconds": duration,
                    "elapsed_seconds": elapsed,
                    "timed_out": timed_out,
                    "function_ea": _function_ea(),
                    "backend": "cython",
                    "pattern_engine": pattern_engine,
                    "sccp_overlay": overlay,
                    "constant_cache_capacity": 4096,
                    "ast_cache_capacity": 40960,
                    "cython_profile": os.environ.get("D810_CYTHON_PROFILE", "0"),
                    "native_profile": os.environ.get("D810_NATIVE_PROFILE", "0"),
                    "profiling_controller": controller_mode,
                    "runtime_image": os.environ.get("D810_TEST_RUNTIME_IMAGE", ""),
                    "runtime_image_id": os.environ.get(
                        "D810_TEST_RUNTIME_IMAGE_ID", ""
                    ),
                    "pid": os.getpid(),
                }
                (output_dir / "metadata.json").write_text(
                    json.dumps(metadata, indent=2, sort_keys=True), encoding="utf-8"
                )

        assert timed_out or (output_dir / "d810_cprofile.prof").stat().st_size > 0


def _sample_cache_stat(
    capacity: int, *, calls: int = 4, evictions: int = 0
) -> dict[str, Any]:
    return {
        "seq": 1,
        "size": 1,
        "weight": 1.0,
        "hits": 1,
        "misses": 1,
        "max_size_ever": 1,
        "max_weight_ever": 1.0,
        "lookups": calls,
        "insertions": 1,
        "replacements": 0,
        "capacity_evictions": evictions,
        "expirations": 0,
        "explicit_removals": 0,
        "weak_reference_removals": 0,
        "configured_max_size": capacity,
        "configured_max_weight": None,
        "memory_delta_bytes": 10,
        "rss_before_bytes": 100,
        "rss_after_bytes": 110,
        "rss_current_bytes": 110,
        "rss_peak_bytes": 110,
        "real_api_calls": calls,
    }


def _sample_cache_stats(evictions: int = 0, memory_delta: int = 10) -> dict[str, Any]:
    constant = _sample_cache_stat(4096, evictions=evictions)
    ast = _sample_cache_stat(40960, evictions=evictions)
    for item in (constant, ast):
        item["memory_delta_bytes"] = memory_delta
        item["rss_after_bytes"] = 100 + memory_delta
        item["rss_current_bytes"] = 100 + memory_delta
        item["rss_peak_bytes"] = 100 + memory_delta
    return {
        "MOP_CONSTANT_CACHE": constant,
        "MOP_TO_AST_CACHE": ast,
        "total_evictions": evictions * 2,
        "memory_delta_bytes": memory_delta,
        "rss_before_bytes": 100,
        "rss_after_bytes": 100 + memory_delta,
        "rss_current_bytes": 100 + memory_delta,
        "rss_peak_bytes": 100 + memory_delta,
        "real_api_calls": 8,
    }


def _sample_sccp_summary(*, backend: str, requests: int = 1) -> dict[str, Any]:
    summary = _zero_summary()
    summary.update(
        {
            "requests": requests,
            "executions": requests,
            "converged": requests,
            "python_runs": requests if backend == "python" else 0,
            "cython_runs": requests if backend == "cython" else 0,
            "cfg_events": 2,
            "value_events": 3,
            "adapter_seconds": 0.001,
            "solver_seconds": 0.001,
            "constants_exposed": 1,
            "edges_exposed": 1,
        }
    )
    return summary


def _sample_fcp_evidence(backend: str) -> dict[str, Any]:
    return {
        "rule": "ForwardConstantPropagationRule",
        "patch_counts": [1],
        "patch_total": 1,
        "consumer_status": "converged",
        "consumer_backend": backend,
        "consumer_outcome": "converged",
        "fallback_reason": "",
        "abstention_reasons": [],
    }


def _sample_projection() -> dict[str, Any]:
    return {
        "status": "converged",
        "constants": [["r", 1]],
        "executable_edges": [[0, 1]],
        "reachable_blocks": [0, 1],
        "program_fingerprint": _SHA,
        "cfg_events": 2,
        "value_events": 3,
        "peak_cfg_queue": 1,
        "peak_value_queue": 1,
    }


def _sample_process_identity(label: str) -> dict[str, Any]:
    return {
        "pid": 1000 + len(label),
        "process_start_at_utc": "2026-08-16T00:00:00+00:00",
        "process_start_source": "unit",
        "hostname": f"unit-{label}",
        "boot_id": f"boot-{label}",
    }


def _sample_build() -> dict[str, Any]:
    item = {
        "module_file": "/tmp/compiled.so",
        "module_sha256": _SHA,
        "module_mtime_ns": 1,
        "build_abi": "unit",
        "source_path": "/src/d810/speedups/evaluator/c_sccp.pyx",
        "source_hash": _SHA,
        "callable": True,
    }
    dataflow_item = dict(item)
    dataflow_item["module_file"] = "/tmp/c_dataflow.so"
    dataflow_item["source_path"] = (
        "/src/d810/speedups/optimizers/microcode/flow/constant_prop/c_dataflow.pyx"
    )
    source_tree = _canonical_hash(
        {"c_sccp": item["source_hash"], "c_dataflow": dataflow_item["source_hash"]}
    )
    return {
        "c_sccp": dict(item),
        "c_dataflow": dataflow_item,
        "source_sha256_at_build": source_tree,
        "source_tree_sha256": source_tree,
    }


def _sample_row(
    label: str,
    *,
    backend: str,
    overlay: str,
    wall: float,
    phase: str | None = None,
    memory_delta: int = 10,
    evictions: int = 0,
) -> dict[str, Any]:
    projection = _sample_projection()
    summary = _sample_sccp_summary(
        backend=backend, requests=13 if label.startswith("solver_") else 1
    )
    if label.startswith("solver_"):
        samples = [wall / 10] * 10
        return {
            "phase": phase or label,
            "run_id": "unit-run",
            "process_id": f"pid-{label}",
            "process_identity": _sample_process_identity(label),
            "database_marker": f"db-{label}",
            "fresh_process": True,
            "kind": "solver_replay",
            "label": label,
            "function_ea": _DEFAULT_FUNCTION_EA,
            "maturity": _MATURITY_LABEL,
            "overlay": "replay",
            "backend": backend,
            "status": "converged",
            "program_fingerprint": _SHA,
            "program_identity_group": "capture_snapshot",
            "snapshot_fingerprint": _SHA,
            "workload_fingerprint": _SHA,
            "wall_seconds": wall,
            "sccp_summary": summary,
            "parity_projection": projection,
            "parity_sha256": _canonical_hash(projection),
            "samples_seconds": samples,
            "median_seconds": wall / 10,
            "p95_seconds": wall / 10,
            "warmup": 3,
            "iterations": 10,
        }
    row = {
        "phase": phase or label,
        "run_id": "unit-run",
        "process_id": f"pid-{label}",
        "process_identity": _sample_process_identity(label),
        "database_marker": f"db-{label}",
        "fresh_process": True,
        "kind": "full_decomp",
        "label": label,
        "function_ea": _DEFAULT_FUNCTION_EA,
        "maturity": _MATURITY_LABEL,
        "overlay": overlay,
        "backend": backend,
        "status": "converged",
        "program_fingerprint": _SHA,
        "program_identity_group": "full_decomp",
        "wall_seconds": wall,
        "adapter_seconds": 0.001,
        "solver_seconds": 0.001,
        "sccp_summary": summary,
        "fcp_patches": 1,
        "fcp_evidence": _sample_fcp_evidence(backend),
        "abstentions": [],
        "cache_stats": _sample_cache_stats(evictions, memory_delta),
        "memory_delta_bytes": memory_delta,
        "rss_before_bytes": 100,
        "rss_after_bytes": 100 + memory_delta,
        "rss_current_bytes": 100 + memory_delta,
        "rss_peak_bytes": 100 + memory_delta,
        "pseudocode_sha256": _SHA,
        "live_pseudocode_sha256": _SHA,
        "cfg_sha256": _SHA,
        "live_cfg_sha256": _SHA,
        "evidence_origin": {
            "pseudocode": "live_cfunc",
            "cfg": "live_flowchart",
            "program": "live_mba",
        },
        "parity_projection": projection,
        "parity_sha256": _canonical_hash(projection),
        "compiled_provenance": _sample_build(),
        "capacity": {
            "constant": 1000 if label == "winner" else 4096,
            "ast": 20480 if label == "winner" else 40960,
        },
    }
    row["cache_stats"]["MOP_CONSTANT_CACHE"]["configured_max_size"] = row["capacity"][
        "constant"
    ]
    row["cache_stats"]["MOP_TO_AST_CACHE"]["configured_max_size"] = row["capacity"][
        "ast"
    ]
    return row


def _sample_cache_row(constant: int, ast: int, wall: float = 2.0) -> dict[str, Any]:
    stats = _sample_cache_stats()
    stats["MOP_CONSTANT_CACHE"]["configured_max_size"] = constant
    stats["MOP_TO_AST_CACHE"]["configured_max_size"] = ast
    return {
        "phase": "cache",
        "run_id": "unit-run",
        "process_id": "pid-cache",
        "process_identity": _sample_process_identity("cache"),
        "database_marker": f"db-cache-{constant}-{ast}",
        "fresh_process": True,
        "kind": "cache_replay",
        "label": f"cache_{constant}_{ast}",
        "function_ea": _DEFAULT_FUNCTION_EA,
        "maturity": _MATURITY_LABEL,
        "overlay": "replay",
        "backend": "runtime",
        "status": "converged",
        "wall_seconds": wall,
        "workload_fingerprint": _SHA,
        "workload_hash": _SHA,
        "workload_operations": 13,
        "replayed_operations": 13,
        "operation_counts": {
            "l": 1,
            "r": 1,
            "d": 1,
            "minsn_to_ast": 3,
            "reconstructed_instruction_mops": 3,
            "mop_to_ast": 6,
            "get_constant_mop": 1,
            "p_ast": 6,
            "mop_utils": 3,
        },
        "cache_stats": stats,
        "constant_capacity": constant,
        "ast_capacity": ast,
        "rebuilds": 2,
        "evictions": 0,
        "peak_weight": 2.0,
        "memory_delta_bytes": 10,
        "rss_before_bytes": 100,
        "rss_after_bytes": 110,
        "rss_current_bytes": 110,
        "rss_peak_bytes": 110,
        "real_api_calls": stats["real_api_calls"],
    }


def _sample_receipt() -> dict[str, Any]:
    solver_python = _sample_row(
        "solver_python", backend="python", overlay="replay", wall=0.2
    )
    solver_cython = _sample_row(
        "solver_cython", backend="cython", overlay="replay", wall=0.05
    )
    rows = [
        solver_python,
        solver_cython,
        _sample_row(
            "baseline",
            backend="python",
            overlay="off",
            wall=2.0,
            memory_delta=100,
            evictions=3,
        ),
        _sample_row(
            "candidate",
            backend="cython",
            overlay="on",
            wall=1.5,
            memory_delta=50,
            evictions=1,
        ),
        _sample_row("auto", backend="cython", overlay="auto", wall=1.6),
        _sample_row("winner", backend="cython", overlay="auto", wall=1.4),
    ]
    cache_matrix = []
    for constant in (1000, 4096, 8192):
        for ast in (20480, 40960, 81920):
            cache_matrix.append(
                _sample_cache_row(
                    constant, ast, 1.0 if (constant, ast) == (1000, 20480) else 2.0
                )
            )
    summary = _zero_summary()
    for row in rows:
        for field in _SCCP_COUNTERS:
            summary[field] += row["sccp_summary"][field]
    metadata = {
        "run_id": "unit-run",
        "gate_mode": "unit",
        "binary": "fixture.i64",
        "binary_sha256": _SHA,
        "function_ea": _DEFAULT_FUNCTION_EA,
        "function_name": "target",
        "maturity": _MATURITY_LABEL,
        "platform": "unit",
        "python": "3.13",
        "ida_version": "9.4",
        "source_path": "/source/fixture.i64",
        "fixture_source": "/source/fixture.i64",
        "source_sha256_at_copy": _SHA,
        "source_sha256_before": _SHA,
        "source_sha256_after": _SHA,
        "source_size_bytes": 1,
        "fixture_path": "/work/fixture.i64",
        "fixture_copy": "/work/fixture.i64",
        "fixture_attestation_path": "/work/fixture-attestation.json",
        "attestation_fixture_path": "/source/fixture.i64",
        "fixture_sha256": _SHA,
        "fixture_size_bytes": 1,
        "fixture_copied_at_utc": "2026-08-16T00:00:00+00:00",
        "capture_method": "unit real-operation-shaped fixture",
        "capture_hooks_stopped": True,
        "capture_lifecycle_events": 0,
        "capture_optimizer_attempts": 0,
        "workload_operations": 13,
        "workload_fingerprint": _SHA,
        "workload_hash": _SHA,
        "workload_blocks_fingerprint": _SHA,
        "snapshot_fingerprint": _SHA,
        "program_fingerprint": _SHA,
        "capture_operation_counts": {
            "l": 1,
            "r": 1,
            "d": 1,
            "minsn_to_ast": 3,
            "reconstructed_instruction_mops": 3,
            "mop_to_ast": 6,
            "get_constant_mop": 1,
            "p_ast": 6,
            "mop_utils": 3,
        },
        "warmup": 3,
        "iterations": 10,
        "build_source_sha256": _sample_build()["source_tree_sha256"],
        "build_provenance": _sample_build(),
    }
    fragments = [
        {
            "phase": phase,
            "phase_index": index,
            "run_id": "unit-run",
            "process_id": f"pid-{phase}",
            "process_identity": _sample_process_identity(phase),
            "database_marker": f"db-{phase}",
            "created_at_utc": "2026-08-16T00:00:01+00:00",
            "payload_sha256": _SHA,
        }
        for index, phase in enumerate(PHASE_ORDER)
    ]
    return {
        "schema_version": 2,
        "metadata": metadata,
        "phase_order": list(PHASE_ORDER),
        "phase_fragments": fragments,
        "runs": rows,
        "cache_matrix": cache_matrix,
        "sccp_summary": summary,
    }


def test_verifier_rejects_receipt_without_metadata(tmp_path: Path) -> None:
    receipt = tmp_path / "missing-metadata.json"
    receipt.write_text(json.dumps({"schema_version": 2}), encoding="utf-8")
    with pytest.raises(ValueError, match="metadata"):
        verify(receipt)


def test_verifier_accepts_complete_receipt(tmp_path: Path) -> None:
    receipt = tmp_path / "complete.json"
    receipt.write_text(json.dumps(_sample_receipt()), encoding="utf-8")
    verify(receipt)


def test_verifier_rejects_solver_parity_mismatch(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][1]["parity_projection"]["value_events"] = 99
    receipt = tmp_path / "parity.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="parity"):
        verify(receipt)


def test_verifier_rejects_missing_capacity_pair(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["cache_matrix"].pop()
    receipt = tmp_path / "capacity.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="too few"):
        verify(receipt)


def test_verifier_rejects_nonconverged_sccp_summary(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["sccp_summary"]["work_limit"] = 1
    receipt = tmp_path / "abstained.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="abstained|bound"):
        verify(receipt)


def test_verifier_rejects_cache_row_without_real_api_telemetry(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["cache_matrix"][0]["cache_stats"]["MOP_CONSTANT_CACHE"]["lookups"] = 0
    receipt = tmp_path / "synthetic-cache.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="did not exercise"):
        verify(receipt)


def test_verifier_rejects_non_hash_pseudocode_evidence(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["pseudocode_sha256"] = 123
    receipt = tmp_path / "bad-hash.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="invalid type|SHA256"):
        verify(receipt)


def test_verifier_rejects_cache_row_from_another_function(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["cache_matrix"][0]["function_ea"] += 1
    receipt = tmp_path / "wrong-function.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="function_ea"):
        verify(receipt)


def test_phase_fragment_path_has_ordered_run_identity() -> None:
    assert (
        phase_fragment_path(Path("/tmp/receipt"), "run-7", "capture").name
        == "run-7.00.capture.json"
    )
    assert (
        phase_fragment_path(Path("/tmp/receipt"), "run-7", "winner").name
        == "run-7.07.winner.json"
    )


def test_merge_rejects_missing_duplicate_and_out_of_order_fragments(
    tmp_path: Path,
) -> None:
    for phase in ("capture", "solver_python"):
        path = phase_fragment_path(tmp_path, "run-7", phase)
        path.write_text(
            json.dumps({"run_id": "run-7", "phase": phase, "phase_index": 0}),
            encoding="utf-8",
        )
    with pytest.raises(ValueError, match="missing|duplicate|out-of-order"):
        merge_phase_fragments(tmp_path, "run-7")


def test_merge_assembles_exact_order_and_verifies_rows(tmp_path: Path) -> None:
    sample = _sample_receipt()
    capture_blocks = [
        {
            "index": 1,
            "serial": 1,
            "start_ea": 0,
            "end_ea": 3,
            "type": 0,
            "flags": 0,
            "predecessors": [],
            "successors": [],
            "instructions": [],
        }
    ]
    capture_operations = [
        {
            "block_index": 1,
            "block_serial": 1,
            "instruction_index": 0,
            "kind": "minsn_to_ast",
            "outcome": "none",
        },
        {
            "block_index": 1,
            "block_serial": 1,
            "instruction_index": 0,
            "kind": "reconstructed_instruction_mop",
            "outcome": "value",
            "descriptor": None,
        },
        {
            "block_index": 1,
            "block_serial": 1,
            "instruction_index": 0,
            "kind": "reconstructed_mop_to_ast",
            "outcome": "none",
            "descriptor": None,
        },
    ]
    capture_counts = {
        "l": 0,
        "r": 0,
        "d": 0,
        "minsn_to_ast": 1,
        "reconstructed_instruction_mops": 1,
        "mop_to_ast": 1,
        "get_constant_mop": 0,
        "p_ast": 1,
        "mop_utils": 1,
    }
    capture_metadata = dict(sample["metadata"])
    capture_metadata["workload_operations"] = len(capture_operations)
    capture_metadata["workload_blocks_fingerprint"] = _canonical_hash(capture_blocks)
    capture_metadata["workload_fingerprint"] = _canonical_hash(
        {"blocks": capture_blocks, "operations": capture_operations}
    )
    capture_metadata["workload_hash"] = _canonical_hash(
        {
            "blocks": capture_blocks,
            "operations": capture_operations,
            "counts": capture_counts,
        }
    )
    capture_metadata["capture_operation_counts"] = capture_counts
    for row in sample["runs"]:
        if row["kind"] == "solver_replay":
            row["workload_fingerprint"] = capture_metadata["workload_fingerprint"]
        else:
            row["workload_fingerprint"] = capture_metadata["workload_fingerprint"]
    for row in sample["cache_matrix"]:
        row["workload_fingerprint"] = capture_metadata["workload_fingerprint"]
        row["workload_hash"] = capture_metadata["workload_hash"]
        row["workload_operations"] = len(capture_operations)
        row["replayed_operations"] = len(capture_operations)
        row["operation_counts"] = dict(capture_counts)
    for row, phase_index in zip(sample["runs"][:5], range(1, 6), strict=True):
        row["process_id"] = f"pid-{phase_index}"
        row["process_identity"] = _sample_process_identity(f"phase-{phase_index}")
    for row in sample["cache_matrix"]:
        row["process_id"] = "pid-6"
        row["process_identity"] = _sample_process_identity("phase-6")
    sample["runs"][5]["process_id"] = "pid-7"
    sample["runs"][5]["process_identity"] = _sample_process_identity("phase-7")
    payloads: dict[str, dict[str, Any]] = {
        "capture": {
            "metadata": capture_metadata,
            "program": {},
            "blocks": capture_blocks,
            "operations": capture_operations,
            "operation_counts": capture_counts,
        },
        "solver_python": {"row": sample["runs"][0]},
        "solver_cython": {"row": sample["runs"][1]},
        "baseline": {"row": sample["runs"][2]},
        "candidate": {"row": sample["runs"][3]},
        "auto": {"row": sample["runs"][4]},
        "cache": {"cache_matrix": sample["cache_matrix"]},
        "winner": {"row": sample["runs"][5]},
    }
    for index, phase in enumerate(PHASE_ORDER):
        write_phase_fragment(
            tmp_path,
            "unit-run",
            phase,
            payloads[phase],
            process_id=f"pid-{index}",
            database_marker=f"db-{index}",
            process_identity=_sample_process_identity(f"phase-{index}"),
        )
    output = tmp_path / "merged.json"
    merged = merge_phase_fragments(tmp_path, "unit-run", output)
    assert merged["phase_order"] == list(PHASE_ORDER)
    verify(output)


def test_fixture_attestation_rejects_source_mutation_during_copy(
    tmp_path: Path,
) -> None:
    source = tmp_path / "source.i64"
    destination = tmp_path / "samples" / "copy.i64"
    source.write_bytes(b"fixture")
    with pytest.raises(FixtureAttestationError):
        copy_fixture_with_attestation(source, destination, mutate_source=True)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("source_sha256_at_copy", "source-at-copy"),
        ("fixture_sha256", "fixture SHA256"),
        ("build_source_sha256", "build sources"),
    ],
)
def test_verifier_rejects_provenance_mutations(
    tmp_path: Path, mutation: str, message: str
) -> None:
    payload = _sample_receipt()
    payload["metadata"][mutation] = "b" * 64
    receipt = tmp_path / f"provenance-{mutation}.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match=message):
        verify(receipt)


def test_verifier_rejects_phase_order_and_reused_process(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["phase_fragments"][1]["phase_index"] = 0
    receipt = tmp_path / "phase-order.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="order|mismatch"):
        verify(receipt)

    payload = _sample_receipt()
    payload["phase_fragments"][1]["process_id"] = payload["phase_fragments"][0][
        "process_id"
    ]
    receipt = tmp_path / "phase-process.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="independent|process"):
        verify(receipt)


def test_verifier_rejects_python_dispatcher_as_compiled_dataflow(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["metadata"]["build_provenance"]["c_dataflow"]["module_file"] = (
        "/work/src/d810/analyses/data_flow/constant_prop_dataflow/_fast_dataflow.py"
    )
    receipt = tmp_path / "python-dataflow-wrapper.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="compiled|extension|dataflow|pattern"):
        verify(receipt)


def test_verifier_rejects_stale_c_dataflow_source_hash(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["metadata"]["build_provenance"]["c_dataflow"]["source_hash"] = "b" * 64
    for row in payload["runs"]:
        if row["kind"] == "full_decomp":
            row["compiled_provenance"]["c_dataflow"]["source_hash"] = "b" * 64
    receipt = tmp_path / "stale-c-dataflow-source.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="aggregate|source|build"):
        verify(receipt)


def test_verifier_rejects_missing_fixture_attestation(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["metadata"]["fixture_attestation_path"] = ""
    receipt = tmp_path / "missing-attestation.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="attestation"):
        verify(receipt)


def test_verifier_rejects_nonexistent_source_during_host_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fixture = tmp_path / "fixture.i64"
    fixture.write_bytes(b"fixture")
    fixture_sha = _sha256_file(fixture)
    attestation = tmp_path / "attestation.json"
    attestation.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source_path": str(tmp_path / "missing-source.i64"),
                "source_sha256_before": fixture_sha,
                "source_sha256_after": fixture_sha,
                "source_sha256_at_copy": fixture_sha,
                "fixture_path": str(fixture),
                "fixture_sha256": fixture_sha,
                "fixture_size_bytes": fixture.stat().st_size,
                "source_size_bytes": fixture.stat().st_size,
                "fixture_copied_at_utc": "2026-08-16T00:00:00+00:00",
            }
        ),
        encoding="utf-8",
    )
    payload = _sample_receipt()
    payload["metadata"].update(
        {
            "gate_mode": "smoke",
            "binary_sha256": fixture_sha,
            "source_path": str(tmp_path / "missing-source.i64"),
            "fixture_source": str(tmp_path / "missing-source.i64"),
            "source_sha256_at_copy": fixture_sha,
            "source_sha256_before": fixture_sha,
            "source_sha256_after": fixture_sha,
            "fixture_sha256": fixture_sha,
            "fixture_size_bytes": fixture.stat().st_size,
            "source_size_bytes": fixture.stat().st_size,
            "fixture_path": str(fixture),
            "fixture_copy": str(fixture),
            "fixture_attestation_path": str(attestation),
            "attestation_fixture_path": str(fixture),
        }
    )
    receipt = tmp_path / "missing-source.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("D810_PERF_HOST_VERIFY", "1")
    monkeypatch.setenv("D810_EXPECTED_FIXTURE_SHA256", fixture_sha)
    with pytest.raises(ValueError, match="source path does not exist"):
        verify(receipt)


def test_verifier_rejects_cache_capacity_and_workload_count_drift(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["cache_matrix"][0]["cache_stats"]["MOP_CONSTANT_CACHE"][
        "configured_max_size"
    ] += 1
    receipt = tmp_path / "cache-capacity-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="capacity"):
        verify(receipt)

    payload = _sample_receipt()
    payload["cache_matrix"][0]["operation_counts"]["mop_utils"] += 1
    receipt = tmp_path / "cache-workload-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="workload|operation"):
        verify(receipt)


def test_verifier_rejects_full_program_identity_drift_even_with_projection_update(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    winner = payload["runs"][-1]
    winner["program_fingerprint"] = "b" * 64
    winner["parity_projection"]["program_fingerprint"] = "b" * 64
    winner["parity_sha256"] = _canonical_hash(winner["parity_projection"])
    receipt = tmp_path / "full-program-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="program|identity"):
        verify(receipt)


def test_verifier_rejects_reused_process_start_identity(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["phase_fragments"][1]["process_identity"] = payload["phase_fragments"][0][
        "process_identity"
    ]
    receipt = tmp_path / "process-start-reuse.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="process|identity|fresh"):
        verify(receipt)


def test_verifier_rejects_impossible_current_rss(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["rss_current_bytes"] = 1
    receipt = tmp_path / "rss-current.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="RSS|memory|current"):
        verify(receipt)


def test_replay_contract_counts_all_three_block_one_instructions() -> None:
    operations = [
        {
            "block_index": 1,
            "instruction_index": index,
            "kind": "minsn_to_ast",
            "outcome": "none",
        }
        for index in range(3)
    ]
    counts = _replay_operation_counts(operations)
    assert counts["minsn_to_ast"] == 3
    assert counts["mop_utils"] == 3
    assert {
        (operation["block_index"], operation["instruction_index"])
        for operation in operations
    } == {(1, 0), (1, 1), (1, 2)}


def test_full_fcp_evidence_aggregates_all_live_usage_entries() -> None:
    state = SimpleNamespace(
        stats=SimpleNamespace(
            cfg_rule_usages={"ForwardConstantPropagationRule": [2, 0, 3]}
        )
    )
    result = SimpleNamespace(
        status=SimpleNamespace(value="converged"),
        backend="python",
        fallback_reason="",
    )
    evidence, abstentions = _full_fcp_evidence(state, result, _zero_summary())
    assert evidence["patch_counts"] == [2, 0, 3]
    assert evidence["patch_total"] == 5
    assert evidence["consumer_outcome"] == "converged"
    assert evidence["abstention_reasons"] == []
    assert abstentions == []


def test_full_fcp_evidence_derives_sccp_abstention() -> None:
    state = SimpleNamespace(stats=SimpleNamespace(cfg_rule_usages={}))
    result = SimpleNamespace(
        status=SimpleNamespace(value="error"),
        backend="python",
        fallback_reason="snapshot failed",
    )
    session = _zero_summary()
    session["errors"] = 1
    evidence, abstentions = _full_fcp_evidence(state, result, session)
    expected = ["sccp_status:error", "sccp_fallback:snapshot failed", "sccp_errors:1"]
    assert evidence["consumer_outcome"] == "abstained"
    assert evidence["abstention_reasons"] == expected
    assert abstentions == expected


def test_verifier_rejects_solver_cache_telemetry_and_nonfinite_timing(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["runs"][0]["cache_stats"] = _sample_cache_stats()
    receipt = tmp_path / "solver-cache.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="cache|telemetry"):
        verify(receipt)

    payload = _sample_receipt()
    payload["runs"][0]["samples_seconds"][0] = float("nan")
    receipt = tmp_path / "solver-nan.json"
    receipt.write_text(json.dumps(payload, allow_nan=True), encoding="utf-8")
    with pytest.raises(ValueError, match="finite|oneOf"):
        verify(receipt)


def test_verifier_rejects_full_zero_sccp_and_rss_mismatch(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["sccp_summary"]["requests"] = 0
    receipt = tmp_path / "zero-sccp.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="positive|bound"):
        verify(receipt)

    payload = _sample_receipt()
    payload["runs"][2]["memory_delta_bytes"] = 999
    receipt = tmp_path / "rss-mismatch.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="memory"):
        verify(receipt)


@pytest.mark.parametrize(
    "field", ("requests", "executions", "converged", "python_runs")
)
def test_verifier_rejects_solver_zero_telemetry(tmp_path: Path, field: str) -> None:
    payload = _sample_receipt()
    payload["runs"][0]["sccp_summary"][field] = 0
    payload["sccp_summary"][field] = sum(
        row["sccp_summary"][field] for row in payload["runs"]
    )
    receipt = tmp_path / f"solver-zero-{field}.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="solver|positive|replay|counter"):
        verify(receipt)


def test_verifier_rejects_solver_execution_count_not_bound_to_replay(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["runs"][0]["sccp_summary"]["requests"] = 1
    payload["runs"][0]["sccp_summary"]["executions"] = 1
    for field in ("requests", "executions"):
        payload["sccp_summary"][field] = sum(
            row["sccp_summary"][field] for row in payload["runs"]
        )
    receipt = tmp_path / "solver-replay-count.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="replay|warmup|execution|request"):
        verify(receipt)


def test_verifier_rejects_fcp_patch_total_drift(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["fcp_evidence"] = {
        "rule": "ForwardConstantPropagationRule",
        "patch_counts": [2, 3],
        "patch_total": 5,
        "consumer_status": "converged",
        "consumer_backend": "python",
        "consumer_outcome": "converged",
        "fallback_reason": "",
        "abstention_reasons": [],
    }
    receipt = tmp_path / "fcp-patch-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="FCP|fcp|patch"):
        _validate_full_rows(_rows_by_label(payload), payload["metadata"])


def test_verifier_rejects_fcp_abstention_projection_drift(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["fcp_evidence"] = {
        "rule": "ForwardConstantPropagationRule",
        "patch_counts": [1],
        "patch_total": 1,
        "consumer_status": "converged",
        "consumer_backend": "python",
        "consumer_outcome": "converged",
        "fallback_reason": "",
        "abstention_reasons": ["fabricated-abstention"],
    }
    receipt = tmp_path / "fcp-abstention-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="abstention|consumer|FCP|fcp"):
        _validate_full_rows(_rows_by_label(payload), payload["metadata"])


def test_verifier_rejects_full_row_abstention_drift(tmp_path: Path) -> None:
    payload = _sample_receipt()
    payload["runs"][2]["abstentions"] = ["fabricated-abstention"]
    receipt = tmp_path / "full-abstention-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="abstention|consumer|FCP|fcp"):
        _validate_full_rows(_rows_by_label(payload), payload["metadata"])


def test_verifier_requires_exact_cache_evictions_but_not_smoke_or_unit() -> None:
    payload = _sample_receipt()
    exact_metadata = {**payload["metadata"], "gate_mode": "exact"}
    with pytest.raises(ValueError, match="eviction"):
        _validate_cache_matrix(payload["cache_matrix"], exact_metadata)
    _validate_cache_matrix(
        payload["cache_matrix"], {**payload["metadata"], "gate_mode": "smoke"}
    )
    _validate_cache_matrix(
        payload["cache_matrix"], {**payload["metadata"], "gate_mode": "unit"}
    )


def test_verifier_rejects_cache_workload_and_winner_capacity_mutations(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["cache_matrix"][0]["workload_hash"] = "b" * 64
    receipt = tmp_path / "workload.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="workload"):
        verify(receipt)

    payload = _sample_receipt()
    payload["runs"][5]["capacity"] = {"constant": 8192, "ast": 81920}
    receipt = tmp_path / "winner.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="winner"):
        verify(receipt)


def test_verifier_rejects_capture_contamination_and_summary_drift(
    tmp_path: Path,
) -> None:
    payload = _sample_receipt()
    payload["metadata"]["capture_lifecycle_events"] = 1
    receipt = tmp_path / "capture-contamination.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="capture"):
        verify(receipt)

    payload = _sample_receipt()
    payload["sccp_summary"]["requests"] += 1
    receipt = tmp_path / "summary-drift.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ValueError, match="bound"):
        verify(receipt)
