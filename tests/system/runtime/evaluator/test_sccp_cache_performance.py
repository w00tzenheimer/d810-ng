"""Explicit, phase-isolated SCCP/cache performance evidence gate.

The IDA work in this module is opt-in.  Every selected phase runs once in the
current IDA process and writes one atomic fragment; orchestration belongs to
the caller (normally one Docker invocation per phase plus the verifier's
merge command).  The ordinary unit tests below exercise receipt construction
and adversarial verification without importing IDA objects.
"""

from __future__ import annotations

from dataclasses import asdict
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import resource
import statistics
import sys
import time
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
    merge_phase_fragments,
    phase_fragment_path,
    verify,
    write_phase_fragment,
)


_SHA = "a" * 64
_EXPECTED_BINARY = "WowClassic_loader-115.9.6910.9-devirt.dll.i64"
_SHORT_BINARY = "libobfuscated.dll"
_DEFAULT_FUNCTION_EA = 0x7FF8560D8AE0
_MATURITY_LABEL = "GLBOPT1"
_SOURCE_IDB = str(Path("/Volumes/code/re/eidolon/115.9.6910.9") / _EXPECTED_BINARY)
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
_PROCESS_MARKER = f"{os.getpid()}-{time.time_ns()}"


def _phase_process_id(phase: str) -> str:
    """Identify the current fresh invocation, not only its container PID."""

    configured = os.environ.get("D810_PERF_PROCESS_MARKER")
    return f"{phase}:{configured or _PROCESS_MARKER}"


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
        fast_dataflow = importlib.import_module(
            "d810.analyses.data_flow.constant_prop_dataflow._fast_dataflow"
        )
    except Exception as exc:
        pytest.fail(
            f"BLOCKED: compiled SCCP/dataflow extensions could not be imported: {exc}",
            pytrace=False,
        )
    c_solve = getattr(c_sccp, "solve", None)
    dataflow = getattr(fast_dataflow, "run_dataflow_cython", None)
    if not callable(c_solve) or not callable(dataflow):
        pytest.fail(
            "BLOCKED: required compiled c_sccp.solve and "
            "_fast_dataflow.run_dataflow_cython are not callable",
            pytrace=False,
        )
    if full and os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1":
        from d810.core import CythonMode

        if not CythonMode().is_enabled():
            pytest.fail(
                "BLOCKED: D810_REQUIRE_COMPILED_SCCP=1 but CythonMode is disabled",
                pytrace=False,
            )

    def item(module: object, source_names: tuple[str, ...]) -> dict[str, Any]:
        module_file = Path(str(getattr(module, "__file__", ""))).resolve()
        if not module_file.is_file():
            pytest.fail(
                f"BLOCKED: compiled module has no live file: {module_file}",
                pytrace=False,
            )
        source_hashes = []
        for source_name in source_names:
            source_path = Path(__file__).resolve().parents[4] / source_name
            if source_path.is_file():
                source_hashes.append(_sha256_file(source_path))
        if not source_hashes:
            pytest.fail(
                "BLOCKED: compiled source attestation is unavailable", pytrace=False
            )
        return {
            "module_file": str(module_file),
            "module_sha256": _sha256_file(module_file),
            "module_mtime_ns": int(module_file.stat().st_mtime_ns),
            "build_abi": f"python-{platform.python_version()}-{platform.machine()}",
            "source_hash": _sha256_bytes("".join(source_hashes).encode("ascii")),
            "callable": True,
        }

    c_item = item(c_sccp, ("src/d810/speedups/evaluator/c_sccp.pyx",))
    dataflow_item = item(
        fast_dataflow,
        ("src/d810/analyses/data_flow/constant_prop_dataflow/_fast_dataflow.py",),
    )
    source_sha = _canonical_hash(
        {
            "c_sccp": c_item["source_hash"],
            "_fast_dataflow": dataflow_item["source_hash"],
        }
    )
    return {
        "c_sccp": c_item,
        "_fast_dataflow": dataflow_item,
        "source_sha256_at_build": source_sha,
        "source_tree_sha256": source_sha,
    }


def _metadata_base(
    function_name: str,
    program: dict[str, Any],
    operations: list[dict[str, Any]],
    counts: dict[str, int],
    fixture: Path,
    *,
    capture_lifecycle_events: int = 0,
    capture_optimizer_attempts: int = 0,
) -> dict[str, Any]:
    fixture_sha = _sha256_file(fixture)
    workload_fingerprint = _canonical_hash(operations)
    workload_hash = _canonical_hash({"operations": operations, "counts": counts})
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
        "source_path": _SOURCE_IDB,
        "fixture_source": _SOURCE_IDB,
        "source_sha256_at_copy": fixture_sha,
        "fixture_path": str(fixture.resolve()),
        "fixture_copy": str(fixture.resolve()),
        "fixture_sha256": fixture_sha,
        "fixture_size_bytes": int(fixture.stat().st_size),
        "fixture_copied_at_utc": os.environ.get(
            "D810_FIXTURE_COPIED_AT_UTC", "1970-01-01T00:00:00+00:00"
        ),
        "capture_method": "one hook-free GLBOPT1 MBA; detached primitive SCCP snapshot and live-coordinate cache replay",
        "capture_hooks_stopped": True,
        "capture_lifecycle_events": capture_lifecycle_events,
        "capture_optimizer_attempts": capture_optimizer_attempts,
        "workload_operations": len(operations),
        "workload_fingerprint": workload_fingerprint,
        "workload_hash": workload_hash,
        "snapshot_fingerprint": program["fingerprint"],
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


def _capture_real_workload(
    function_ea: int, fixture: Path
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Capture one real MBA before D810State and persist only primitives."""

    lifecycle_before = _assert_capture_hooks_stopped()
    from d810.evaluator.hexrays_microcode.sccp_snapshot import snapshot_from_mba
    from d810.hexrays.expr.p_ast import get_constant_mop
    from d810.hexrays.ir.minsn_utils import minsn_to_ast
    from d810.hexrays.ir.mop_utils import mop_to_ast
    from d810.hexrays.ir.mop_snapshot import MopSnapshot
    import ida_hexrays
    import idaapi

    mba = _gen_mba(function_ea)
    program = snapshot_from_mba(mba)
    operations: list[dict[str, Any]] = []
    counts = {
        "l": 0,
        "r": 0,
        "d": 0,
        "reconstructed_instruction_mops": 0,
        "p_ast": 0,
        "mop_utils": 0,
    }
    for block_index in range(int(mba.qty)):
        block = mba.get_mblock(block_index)
        if block is None:
            continue
        instruction = block.head
        instruction_index = 0
        while instruction is not None:
            try:
                minsn_to_ast(instruction)
                counts["mop_utils"] += 1
            except Exception:
                # The production helper is attempted for every instruction;
                # unsupported diagnostics remain part of the real stream.
                pass
            for attribute in ("l", "r", "d"):
                mop = getattr(instruction, attribute, None)
                if mop is None or int(getattr(mop, "t", ida_hexrays.mop_z)) == int(
                    ida_hexrays.mop_z
                ):
                    continue
                counts[attribute] += 1
                try:
                    snapshot = MopSnapshot.from_mop(mop)
                    descriptor = _operand_to_dict(mop)
                    mop_to_ast(mop)
                    counts["p_ast"] += 1
                    if int(getattr(mop, "t", -1)) == int(ida_hexrays.mop_n):
                        value = getattr(getattr(mop, "nnn", None), "value", None)
                        if value is not None:
                            get_constant_mop(int(value), int(getattr(mop, "size", 0)))
                except Exception as exc:
                    raise RuntimeError(
                        f"real MOP operation capture failed block={block_index} instruction={instruction_index} attribute={attribute}: {exc}"
                    ) from exc
                operations.append(
                    {
                        "block_index": block_index,
                        "block_serial": int(getattr(block, "serial", block_index)),
                        "instruction_index": instruction_index,
                        "attribute": attribute,
                        "snapshot": {
                            "t": int(snapshot.t),
                            "size": int(snapshot.size),
                            "value": snapshot.value,
                            "reg": snapshot.reg,
                            "stkoff": snapshot.stkoff,
                            "gaddr": snapshot.gaddr,
                            "lvar_idx": snapshot.lvar_idx,
                            "lvar_off": snapshot.lvar_off,
                            "block_num": snapshot.block_num,
                            "helper_name": snapshot.helper_name,
                            "const_str": snapshot.const_str,
                            "pair_lo_t": snapshot.pair_lo_t,
                            "pair_hi_t": snapshot.pair_hi_t,
                        },
                        "mop": descriptor,
                    }
                )
            counts["reconstructed_instruction_mops"] += 3
            instruction = instruction.next
            instruction_index += 1
    if not operations:
        pytest.fail("BLOCKED: real MBA produced no l/r/d MOP operations", pytrace=False)
    function_name = idaapi.get_name(function_ea) or f"sub_{function_ea:x}"
    lifecycle_after = _assert_capture_hooks_stopped()
    metadata = _metadata_base(
        function_name,
        {"fingerprint": program.fingerprint},
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


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if platform.system() == "Darwin" else value * 1024


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
    result: object, backend: str, *, adapter_seconds: float = 0.0
) -> dict[str, int | float]:
    summary = _zero_summary()
    summary.update(
        {
            "requests": 1,
            "executions": 1,
            "converged": 1 if result.status.value == "converged" else 0,
            "work_limit": 1 if result.status.value == "work_limit" else 0,
            "block_limit": 1 if result.status.value == "block_limit" else 0,
            "errors": 1 if result.status.value == "error" else 0,
            "python_runs": 1 if backend == "python" else 0,
            "cython_runs": 1 if backend == "cython" else 0,
            "cfg_events": int(result.cfg_events),
            "value_events": int(result.value_events),
            "adapter_seconds": float(adapter_seconds),
            "solver_seconds": float(result.solver_seconds),
            "constants_exposed": len(result.constants),
            "edges_exposed": len(result.executable_edges),
        }
    )
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
    for _ in range(warmup):
        solver(program)
    samples: list[float] = []
    results: list[object] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = solver(program)
        samples.append(time.perf_counter() - started)
        results.append(result)
    first = results[0]
    if any(
        _parity_projection(result) != _parity_projection(first)
        for result in results[1:]
    ):
        raise RuntimeError(
            f"{backend} solver changed semantics across measured replays"
        )
    if backend == "cython" and first.backend != "cython":
        pytest.fail("BLOCKED: compiled solver phase selected a fallback", pytrace=False)
    projection = _parity_projection(first)
    row = {
        "phase": f"solver_{backend}",
        "run_id": _run_id(),
        "process_id": _phase_process_id(f"solver_{backend}"),
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
        "snapshot_fingerprint": capture["metadata"]["snapshot_fingerprint"],
        "workload_fingerprint": capture["metadata"]["workload_fingerprint"],
        "wall_seconds": float(sum(samples)),
        "sccp_summary": _solver_summary(first, backend),
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
    cache: object, *, memory_delta: int, real_api_calls: int
) -> dict[str, Any]:
    stats = asdict(cache.stats)
    stats["memory_delta_bytes"] = int(memory_delta)
    stats["real_api_calls"] = int(real_api_calls)
    return stats


def _cache_stats(*, memory_delta: int) -> dict[str, Any]:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE

    constant = _cache_stat_dict(
        MOP_CONSTANT_CACHE,
        memory_delta=memory_delta,
        real_api_calls=int(MOP_CONSTANT_CACHE.stats.lookups),
    )
    ast = _cache_stat_dict(
        MOP_TO_AST_CACHE,
        memory_delta=memory_delta,
        real_api_calls=int(MOP_TO_AST_CACHE.stats.lookups),
    )
    return {
        "MOP_CONSTANT_CACHE": constant,
        "MOP_TO_AST_CACHE": ast,
        "total_evictions": int(
            constant["capacity_evictions"] + ast["capacity_evictions"]
        ),
        "memory_delta_bytes": int(memory_delta),
        "real_api_calls": int(constant["real_api_calls"] + ast["real_api_calls"]),
    }


def _reset_runtime_state() -> None:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
    from d810.evaluator.hexrays_microcode.sccp import reset_sccp_session

    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    reset_sccp_session()


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
    rss_before = _rss_bytes()
    started = time.perf_counter()
    cache_stats: dict[str, Any] | None = None
    if capacity is None:
        cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
    else:
        with temporary_mop_cache_policy(*capacity):
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
            cache_stats = _cache_stats(memory_delta=0)
    wall_seconds = time.perf_counter() - started
    rss_after = _rss_bytes()
    rss_peak = max(rss_before, rss_after, _rss_bytes())
    if cfunc is None:
        pytest.fail(
            f"BLOCKED: full decompilation failed for 0x{function_ea:x}", pytrace=False
        )
    if cache_stats is None:
        cache_stats = _cache_stats(memory_delta=0)
    memory_delta = rss_after - rss_before
    cache_stats["memory_delta_bytes"] = memory_delta
    cache_stats["MOP_CONSTANT_CACHE"]["memory_delta_bytes"] = memory_delta
    cache_stats["MOP_TO_AST_CACHE"]["memory_delta_bytes"] = memory_delta
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
    build = (
        _require_compiled_backend(full=backend == "cython")
        if backend == "cython"
        else _require_compiled_backend()
    )
    row = {
        "phase": label,
        "run_id": _run_id(),
        "process_id": _phase_process_id(label),
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
        "wall_seconds": wall_seconds,
        "adapter_seconds": float(session["adapter_seconds"]),
        "solver_seconds": float(session["solver_seconds"]),
        "sccp_summary": session,
        "fcp_patches": int(
            getattr(getattr(state, "stats", None), "cfg_rule_usages", {}).get(
                "ForwardConstantPropagationRule", [0]
            )[-1]
            if getattr(getattr(state, "stats", None), "cfg_rule_usages", {}).get(
                "ForwardConstantPropagationRule"
            )
            else 0
        ),
        "abstentions": [],
        "cache_stats": cache_stats,
        "memory_delta_bytes": memory_delta,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": rss_after,
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
            _reset_runtime_state()
            mba = _gen_mba(function_ea)
            rss_before = _rss_bytes()
            started = time.perf_counter()
            with temporary_mop_cache_policy(constant_capacity, ast_capacity):
                for operation in operations:
                    block = mba.get_mblock(int(operation["block_index"]))
                    instruction = block.head
                    for _ in range(int(operation["instruction_index"])):
                        instruction = instruction.next
                    mop = getattr(instruction, operation["attribute"])
                    mop_to_ast(mop)
                    if int(operation["snapshot"]["t"]) == int(ida_hexrays.mop_n):
                        value = operation["snapshot"].get("value")
                        if value is not None:
                            get_constant_mop(
                                int(value), int(operation["snapshot"]["size"])
                            )
                # Exercise the production instruction/MOP helper surface too.
                block = mba.get_mblock(0)
                instruction = block.head if block is not None else None
                while instruction is not None:
                    try:
                        minsn_to_ast(instruction)
                    except Exception:
                        pass
                    instruction = instruction.next
                wall_seconds = time.perf_counter() - started
                cache_stats = _cache_stats(memory_delta=0)
                rebuilds = int(
                    MOP_CONSTANT_CACHE.stats.insertions
                    + MOP_TO_AST_CACHE.stats.insertions
                )
                evictions = int(cache_stats["total_evictions"])
                peak_weight = float(
                    MOP_CONSTANT_CACHE.stats.max_weight_ever
                    + MOP_TO_AST_CACHE.stats.max_weight_ever
                )
            rss_after = _rss_bytes()
            rss_peak = max(rss_before, rss_after, _rss_bytes())
            memory_delta = rss_after - rss_before
            cache_stats["memory_delta_bytes"] = memory_delta
            cache_stats["MOP_CONSTANT_CACHE"]["memory_delta_bytes"] = memory_delta
            cache_stats["MOP_TO_AST_CACHE"]["memory_delta_bytes"] = memory_delta
            rows.append(
                {
                    "phase": "cache",
                    "run_id": _run_id(),
                    "process_id": _phase_process_id("cache"),
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
    expected = os.environ.get("D810_EXPECTED_FIXTURE_SHA256")
    if not expected:
        pytest.fail("BLOCKED: D810_EXPECTED_FIXTURE_SHA256 is required", pytrace=False)
    actual = _sha256_file(fixture)
    if expected != actual:
        pytest.fail(
            "BLOCKED: mounted fixture SHA256 does not match D810_EXPECTED_FIXTURE_SHA256",
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
        pytest.fail(
            "D810_PERF_GATE=1 is required for SCCP performance collection",
            pytrace=False,
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
        "real_api_calls": calls,
    }


def _sample_cache_stats(evictions: int = 0, memory_delta: int = 10) -> dict[str, Any]:
    constant = _sample_cache_stat(4096, evictions=evictions)
    ast = _sample_cache_stat(40960, evictions=evictions)
    constant["memory_delta_bytes"] = memory_delta
    ast["memory_delta_bytes"] = memory_delta
    return {
        "MOP_CONSTANT_CACHE": constant,
        "MOP_TO_AST_CACHE": ast,
        "total_evictions": evictions * 2,
        "memory_delta_bytes": memory_delta,
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


def _sample_build() -> dict[str, Any]:
    item = {
        "module_file": "/tmp/compiled.so",
        "module_sha256": _SHA,
        "module_mtime_ns": 1,
        "build_abi": "unit",
        "source_hash": _SHA,
        "callable": True,
    }
    return {
        "c_sccp": dict(item),
        "_fast_dataflow": dict(item),
        "source_sha256_at_build": _SHA,
        "source_tree_sha256": _SHA,
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
    summary = _sample_sccp_summary(backend=backend)
    if label.startswith("solver_"):
        samples = [wall / 10] * 10
        return {
            "phase": phase or label,
            "run_id": "unit-run",
            "process_id": f"pid-{label}",
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
        "wall_seconds": wall,
        "adapter_seconds": 0.001,
        "solver_seconds": 0.001,
        "sccp_summary": summary,
        "fcp_patches": 1,
        "abstentions": [],
        "cache_stats": _sample_cache_stats(evictions, memory_delta),
        "memory_delta_bytes": memory_delta,
        "rss_before_bytes": 100,
        "rss_after_bytes": 100 + memory_delta,
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
        "capacity": {"constant": 1000, "ast": 20480},
    }
    return row


def _sample_cache_row(constant: int, ast: int, wall: float = 2.0) -> dict[str, Any]:
    stats = _sample_cache_stats()
    stats["MOP_CONSTANT_CACHE"]["configured_max_size"] = constant
    stats["MOP_TO_AST_CACHE"]["configured_max_size"] = ast
    return {
        "phase": "cache",
        "run_id": "unit-run",
        "process_id": f"pid-cache-{constant}-{ast}",
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
        "workload_operations": 10,
        "operation_counts": {
            "l": 2,
            "r": 2,
            "d": 2,
            "reconstructed_instruction_mops": 3,
            "p_ast": 4,
            "mop_utils": 5,
        },
        "cache_stats": stats,
        "constant_capacity": constant,
        "ast_capacity": ast,
        "rebuilds": 2,
        "evictions": 0,
        "peak_weight": 1.0,
        "memory_delta_bytes": 0,
        "rss_before_bytes": 100,
        "rss_after_bytes": 100,
        "rss_peak_bytes": 100,
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
        "fixture_path": "/work/fixture.i64",
        "fixture_copy": "/work/fixture.i64",
        "fixture_sha256": _SHA,
        "fixture_size_bytes": 1,
        "fixture_copied_at_utc": "2026-08-16T00:00:00+00:00",
        "capture_method": "unit real-operation-shaped fixture",
        "capture_hooks_stopped": True,
        "capture_lifecycle_events": 0,
        "capture_optimizer_attempts": 0,
        "workload_operations": 10,
        "workload_fingerprint": _SHA,
        "workload_hash": _SHA,
        "snapshot_fingerprint": _SHA,
        "warmup": 3,
        "iterations": 10,
        "build_source_sha256": _SHA,
        "build_provenance": _sample_build(),
    }
    fragments = [
        {
            "phase": phase,
            "phase_index": index,
            "run_id": "unit-run",
            "process_id": f"pid-{phase}",
            "database_marker": f"db-{phase}",
            "payload_sha256": _SHA,
        }
        for index, phase in enumerate(PHASE_ORDER)
    ]
    rows[5]["capacity"] = {"constant": 1000, "ast": 20480}
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
    payloads: dict[str, dict[str, Any]] = {
        "capture": {
            "metadata": sample["metadata"],
            "program": {},
            "operations": [],
            "operation_counts": {},
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
