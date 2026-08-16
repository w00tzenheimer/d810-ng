"""Explicit SCCP/cache performance evidence gate.

The IDA-backed benchmark is intentionally opt-in via ``D810_PERF_GATE=1``.
The small receipt contract tests in this module remain runnable without IDA so
the verifier is developed test-first.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib
import json
import os
from pathlib import Path
import platform
import statistics
import sys
import time
import tracemalloc

import pytest

# ``bench_utils`` is a sibling of the runtime tests.  Keep this import local to
# the test tree so the verifier-only tests can run with ``--noconftest``.
_RUNTIME_DIR = Path(__file__).resolve().parents[1]
if str(_RUNTIME_DIR) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_DIR))
_EVALUATOR_DIR = Path(__file__).resolve().parent
if str(_EVALUATOR_DIR) not in sys.path:
    sys.path.insert(0, str(_EVALUATOR_DIR))
from bench_utils import save_baseline, timed_run  # noqa: E402
from verify_sccp_perf_receipt import verify  # noqa: E402


_SHA = "a" * 64
_EXPECTED_BINARY = "WowClassic_loader-115.9.6910.9-devirt.dll.i64"
_DEFAULT_FUNCTION_EA = 0x7FF8560D8AE0
_MATURITY_LABEL = "GLBOPT1"


@dataclass
class _CapturedWorkload:
    function_ea: int
    function_name: str
    mba: object
    program: object
    operations: tuple[object, ...]
    adapter_seconds: float
    capture_api_calls: int
    cfg_sha256: str
    pseudocode_sha256: str = ""
    binary_sha256: str = ""


_CAPTURE: _CapturedWorkload | None = None
_ACTIVE_STATE: object | None = None
_SCCP_SUMMARY: dict[str, int | float] = {}


def _sample_cache_stats(
    evictions: int,
    memory_delta: int,
    real_api_calls: int = 2,
    constant_capacity: int = 4096,
    ast_capacity: int = 40960,
) -> dict:
    def one(capacity: int) -> dict:
        return {
            "seq": 1,
            "size": 1,
            "weight": 1.0,
            "hits": 1,
            "misses": 1,
            "max_size_ever": 1,
            "max_weight_ever": 1.0,
            "lookups": 2,
            "insertions": 1,
            "replacements": 0,
            "capacity_evictions": evictions,
            "expirations": 0,
            "explicit_removals": 0,
            "weak_reference_removals": 0,
            "configured_max_size": capacity,
            "configured_max_weight": None,
            "memory_delta_bytes": memory_delta,
            "real_api_calls": real_api_calls,
        }

    return {
        "MOP_CONSTANT_CACHE": one(constant_capacity),
        "MOP_TO_AST_CACHE": one(ast_capacity),
        "total_evictions": evictions,
        "memory_delta_bytes": memory_delta,
        "real_api_calls": real_api_calls,
    }


def _parity() -> dict:
    return {
        "status": "converged",
        "constants": [["r", 1]],
        "executable_edges": [[0, 1]],
        "reachable_blocks": [0, 1],
        "program_fingerprint": "program-fingerprint",
        "cfg_events": 2,
        "value_events": 3,
        "peak_cfg_queue": 1,
        "peak_value_queue": 1,
    }


def _run(
    *,
    kind: str,
    label: str,
    backend: str,
    overlay: str,
    wall_seconds: float,
    evictions: int = 0,
    memory_delta: int = 0,
    real_api_calls: int = 2,
    solver_seconds: float = 0.001,
    constant_capacity: int = 4096,
    ast_capacity: int = 40960,
) -> dict:
    return {
        "kind": kind,
        "label": label,
        "function_ea": 0x7FF8560D8AE0,
        "maturity": "GLBOPT1",
        "overlay": overlay,
        "backend": backend,
        "status": "converged",
        "program_fingerprint": "program-fingerprint",
        "wall_seconds": wall_seconds,
        "adapter_seconds": 0.001,
        "solver_seconds": solver_seconds,
        "cfg_events": 2,
        "value_events": 3,
        "constants_exposed": 1,
        "edges_exposed": 1,
        "fcp_patches": 0,
        "cache_stats": _sample_cache_stats(
            evictions,
            memory_delta,
            real_api_calls,
            constant_capacity,
            ast_capacity,
        ),
        "pseudocode_sha256": _SHA,
        "cfg_sha256": _SHA,
        "parity_projection": _parity(),
        "parity_sha256": _SHA,
        "real_api_calls": real_api_calls,
    }


def _sample_receipt() -> dict:
    solver_python = _run(
        kind="solver_replay",
        label="solver_python",
        backend="python",
        overlay="replay",
        wall_seconds=0.02,
    )
    solver_python.update(
        {"median_seconds": 0.02, "p95_seconds": 0.025, "warmup": 3, "iterations": 10}
    )
    solver_cython = _run(
        kind="solver_replay",
        label="solver_cython",
        backend="cython",
        overlay="replay",
        wall_seconds=0.005,
    )
    solver_cython.update(
        {"median_seconds": 0.005, "p95_seconds": 0.006, "warmup": 3, "iterations": 10}
    )
    baseline = _run(
        kind="full_decomp",
        label="baseline",
        backend="python",
        overlay="off",
        wall_seconds=2.0,
        evictions=10,
        memory_delta=100,
    )
    candidate = _run(
        kind="full_decomp",
        label="candidate",
        backend="cython",
        overlay="on",
        wall_seconds=1.5,
        evictions=5,
        memory_delta=50,
    )
    auto = _run(
        kind="full_decomp",
        label="auto",
        backend="cython",
        overlay="auto",
        wall_seconds=1.6,
    )
    winner = _run(
        kind="full_decomp",
        label="winner",
        backend="cython",
        overlay="auto",
        wall_seconds=1.0,
    )
    winner.update({"constant_capacity": 1000, "ast_capacity": 20480})
    cache_matrix = []
    for constant_capacity in (1000, 4096, 8192):
        for ast_capacity in (20480, 40960, 81920):
            row = _run(
                kind="cache_replay",
                label=f"cache_{constant_capacity}_{ast_capacity}",
                backend="cython",
                overlay="replay",
                wall_seconds=1.0
                if (constant_capacity, ast_capacity) == (1000, 20480)
                else 2.0,
                real_api_calls=10,
                constant_capacity=constant_capacity,
                ast_capacity=ast_capacity,
            )
            row.update(
                {
                    "constant_capacity": constant_capacity,
                    "ast_capacity": ast_capacity,
                    "workload_operations": 10,
                    "rebuilds": 2,
                    "evictions": 0,
                    "peak_weight": 1.0,
                    "memory_delta_bytes": 0,
                }
            )
            row.pop("parity_projection")
            row.pop("parity_sha256")
            cache_matrix.append(row)
    return {
        "schema_version": 1,
        "metadata": {
            "binary": "fixture.i64",
            "binary_sha256": _SHA,
            "function_ea": 0x7FF8560D8AE0,
            "function_name": "target",
            "maturity": "GLBOPT1",
            "platform": "test",
            "python": "3.13",
            "ida_version": "9.4",
            "fixture_source": "/source/fixture.i64",
            "fixture_copy": "samples/bins/fixture.i64",
            "fixture_sha256": _SHA,
            "capture_method": "real MOP snapshots",
            "workload_operations": 10,
            "real_api_calls": 10,
            "warmup": 3,
            "iterations": 10,
        },
        "runs": [solver_python, solver_cython, baseline, candidate, auto, winner],
        "cache_matrix": cache_matrix,
        "sccp_summary": {
            "requests": 2,
            "executions": 2,
            "reuses": 0,
            "fallbacks": 0,
            "converged": 2,
            "work_limit": 0,
            "block_limit": 0,
            "errors": 0,
            "python_runs": 1,
            "cython_runs": 1,
            "cfg_events": 4,
            "value_events": 6,
            "adapter_seconds": 0.002,
            "solver_seconds": 0.006,
            "constants_exposed": 2,
            "edges_exposed": 2,
        },
    }


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _default_binary() -> str:
    configured = os.environ.get("D810_TEST_BINARY")
    return configured or _EXPECTED_BINARY


def _fixture_input_path(binary_name: str) -> Path | None:
    root = Path(__file__).resolve().parents[4]
    for relative in ("samples/bins", "tests/_resources/bin", "tests/system/bins"):
        candidate = root / relative / binary_name
        if candidate.is_file():
            return candidate
    return None


@pytest.fixture(scope="session", autouse=True)
def _perf_gate_session_prerequisite() -> None:
    """Fail explicitly before IDA fixtures can skip or substitute input."""

    if os.environ.get("D810_PERF_GATE") != "1":
        return
    binary_name = _default_binary()
    if binary_name != _EXPECTED_BINARY:
        pytest.fail(
            "BLOCKED: performance gate requires the exact fixture "
            f"{_EXPECTED_BINARY}, got D810_TEST_BINARY={binary_name!r}",
            pytrace=False,
        )
    fixture_path = _fixture_input_path(binary_name)
    if fixture_path is None:
        pytest.fail(
            "BLOCKED: exact disposable IDB is unavailable: "
            f"{Path(__file__).resolve().parents[4] / 'samples' / 'bins' / binary_name}",
            pytrace=False,
        )
    if os.environ.get("D810_REQUIRE_COMPILED_SCCP") == "1":
        try:
            compiled = importlib.import_module("d810.speedups.evaluator.c_sccp")
        except Exception as exc:
            pytest.fail(
                "BLOCKED: D810_REQUIRE_COMPILED_SCCP=1 but the compiled SCCP "
                f"extension could not be imported: {exc}",
                pytrace=False,
            )
        if not callable(getattr(compiled, "solve", None)):
            pytest.fail(
                "BLOCKED: D810_REQUIRE_COMPILED_SCCP=1 but c_sccp.solve "
                "is not callable",
                pytrace=False,
            )
        from d810.core import CythonMode

        if not CythonMode().is_enabled():
            pytest.fail(
                "BLOCKED: D810_REQUIRE_COMPILED_SCCP=1 but CythonMode is disabled",
                pytrace=False,
            )


@pytest.fixture(scope="class")
def perf_gate_prerequisite(
    _perf_gate_session_prerequisite, libobfuscated_setup
) -> None:
    """Require the explicit opt-in when the performance test is requested."""

    if os.environ.get("D810_PERF_GATE") != "1":
        pytest.fail(
            "D810_PERF_GATE=1 is required for SCCP performance collection",
            pytrace=False,
        )
    try:
        import idaapi
    except ImportError:
        # The system conftest owns the IDA availability prerequisite.  This
        # branch is only reached under unusual direct collection and remains a
        # hard failure, never a skip/substitution.
        pytest.fail("BLOCKED: IDA runtime is unavailable", pytrace=False)
    function_ea = int(
        os.environ.get("D810_SCCP_FUNCTION_EA", hex(_DEFAULT_FUNCTION_EA)), 0
    )
    if idaapi.get_func(function_ea) is None:
        pytest.fail(
            f"BLOCKED: exact disposable database has no function 0x{function_ea:x}",
            pytrace=False,
        )


def _function_ea() -> int:
    return int(
        os.environ.get("D810_SCCP_FUNCTION_EA", hex(_DEFAULT_FUNCTION_EA)),
        0,
    )


def _gen_mba(function_ea: int):
    import ida_hexrays
    import idaapi

    function = idaapi.get_func(function_ea)
    if function is None:
        pytest.fail(f"BLOCKED: no function at 0x{function_ea:x}", pytrace=False)
    return ida_hexrays.gen_microcode(
        ida_hexrays.mba_ranges_t(function),
        ida_hexrays.hexrays_failure_t(),
        None,
        ida_hexrays.DECOMP_NO_WAIT,
        ida_hexrays.MMAT_GLBOPT1,
    )


def _live_cfg_sha256(function_ea: int) -> str:
    """Capture an independent live IDA flow graph hash."""

    import idaapi

    function = idaapi.get_func(function_ea)
    if function is None:
        raise RuntimeError(f"no live function at 0x{function_ea:x}")
    try:
        flow = idaapi.FlowChart(function)
    except Exception as exc:
        raise RuntimeError(f"could not capture live CFG: {exc}") from exc
    blocks: list[tuple[int, int, tuple[int, ...]]] = []
    for block in flow:
        successors = tuple(
            sorted(int(getattr(successor, "start_ea")) for successor in block.succs())
        )
        blocks.append((int(block.start_ea), int(block.end_ea), successors))
    if not blocks:
        raise RuntimeError("live CFG has no blocks")
    return _sha256_text(repr(tuple(sorted(blocks))))


def _pseudocode_sha256(cfunc: object) -> str:
    import idaapi

    pseudocode = getattr(cfunc, "get_pseudocode", lambda: ())()
    rendered = "\n".join(idaapi.tag_remove(line.line) for line in pseudocode)
    if not rendered:
        raise RuntimeError("decompilation returned no pseudocode lines")
    return _sha256_text(rendered)


def _cache_stat_dict(cache: object, *, real_api_calls: int, memory_delta: int) -> dict:
    from dataclasses import asdict

    stats = asdict(cache.stats)
    stats["memory_delta_bytes"] = int(memory_delta)
    stats["real_api_calls"] = int(real_api_calls)
    return stats


def _cache_stats(
    *,
    real_api_calls: int,
    memory_delta: int = 0,
    constant_calls: int | None = None,
    ast_calls: int | None = None,
) -> dict:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE

    if constant_calls is None:
        constant_calls = real_api_calls
    if ast_calls is None:
        ast_calls = real_api_calls
    constant = _cache_stat_dict(
        MOP_CONSTANT_CACHE,
        real_api_calls=constant_calls,
        memory_delta=memory_delta,
    )
    ast = _cache_stat_dict(
        MOP_TO_AST_CACHE,
        real_api_calls=ast_calls,
        memory_delta=memory_delta,
    )
    return {
        "MOP_CONSTANT_CACHE": constant,
        "MOP_TO_AST_CACHE": ast,
        "total_evictions": int(
            constant["capacity_evictions"] + ast["capacity_evictions"]
        ),
        "memory_delta_bytes": int(memory_delta),
        "real_api_calls": int(real_api_calls),
    }


def _reset_session_state() -> None:
    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
    from d810.evaluator.hexrays_microcode.sccp import reset_sccp_session

    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    reset_sccp_session()


def _configure_policy(backend: str, overlay: str) -> None:
    if _ACTIVE_STATE is None:
        raise RuntimeError("D810 state is not active")
    from d810.core import CythonMode

    mode = CythonMode()
    if backend == "cython":
        mode.enable()
        if not mode.is_enabled():
            pytest.fail(
                "D810_REQUIRE_COMPILED_SCCP=1 but CythonMode is disabled",
                pytrace=False,
            )
    elif backend == "python":
        mode.disable()
    else:
        raise ValueError(f"unsupported benchmark backend {backend!r}")

    state = _ACTIVE_STATE
    rules = list(getattr(state, "current_blk_rules", ()))
    found = False
    for rule in rules:
        name = str(getattr(rule, "name", rule.__class__.__name__)).lower()
        if name != "forwardconstantpropagationrule":
            continue
        found = True
        rule.cython_enabled = backend == "cython"
        rule.sccp_overlay = overlay
    if not found:
        pytest.fail(
            "BLOCKED: active D810 project does not contain "
            "ForwardConstantPropagationRule",
            pytrace=False,
        )


def _sccp_status_from_stats(stats: dict[str, int | float]) -> str:
    if stats["errors"]:
        return "error"
    if stats["work_limit"]:
        return "work_limit"
    if stats["block_limit"]:
        return "block_limit"
    return "converged"


def _add_sccp_summary(stats: dict[str, int | float]) -> None:
    global _SCCP_SUMMARY
    if not _SCCP_SUMMARY:
        _SCCP_SUMMARY = {key: 0 for key in stats}
    for key, value in stats.items():
        _SCCP_SUMMARY[key] += value


def _patch_count() -> int:
    if _ACTIVE_STATE is None:
        return 0
    stats = getattr(_ACTIVE_STATE, "stats", None)
    if stats is None:
        return 0
    maturity = getattr(stats, "maturity_cfg_rule_usages", {}).get(
        "ForwardConstantPropagationRule", {}
    )
    if maturity:
        return sum(sum(int(item) for item in values) for values in maturity.values())
    return sum(
        int(item)
        for item in getattr(stats, "cfg_rule_usages", {}).get(
            "ForwardConstantPropagationRule", []
        )
    )


def _result_projection(result: object) -> dict:
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


def _parity_digest(projection: dict) -> str:
    return _sha256_text(json.dumps(projection, sort_keys=True, separators=(",", ":")))


def _common_row(
    *,
    kind: str,
    label: str,
    backend: str,
    overlay: str,
    status: str,
    wall_seconds: float,
    stats: dict[str, int | float],
    cache_stats: dict,
    fcp_patches: int,
    parity_projection: dict,
    real_api_calls: int,
) -> dict:
    if _CAPTURE is None:
        raise RuntimeError("real workload has not been captured")
    return {
        "kind": kind,
        "label": label,
        "function_ea": _CAPTURE.function_ea,
        "maturity": _MATURITY_LABEL,
        "overlay": overlay,
        "backend": backend,
        "status": status,
        "program_fingerprint": _CAPTURE.program.fingerprint,
        "wall_seconds": float(wall_seconds),
        "adapter_seconds": float(stats["adapter_seconds"]),
        "solver_seconds": float(stats["solver_seconds"]),
        "cfg_events": int(stats["cfg_events"]),
        "value_events": int(stats["value_events"]),
        "constants_exposed": int(stats["constants_exposed"]),
        "edges_exposed": int(stats["edges_exposed"]),
        "fcp_patches": int(fcp_patches),
        "cache_stats": cache_stats,
        "pseudocode_sha256": _CAPTURE.pseudocode_sha256,
        "cfg_sha256": _CAPTURE.cfg_sha256,
        "parity_projection": parity_projection,
        "parity_sha256": _parity_digest(parity_projection),
        "real_api_calls": int(real_api_calls),
    }


def replay_solver(
    function_ea: int, backend: str, warmup: int, iterations: int
) -> dict[str, object]:
    """Replay one immutable real MBA snapshot and measure solver-only time."""

    if _CAPTURE is None or function_ea != _CAPTURE.function_ea:
        raise RuntimeError(
            "solver replay requested a function other than the captured MBA"
        )
    if warmup != 3 or iterations != 10:
        raise ValueError("SCCP solver replay requires warmup=3 and iterations=10")
    from d810.evaluator.hexrays_microcode import p_sccp
    from d810.evaluator.hexrays_microcode import _fast_sccp

    if backend == "python":
        solver = p_sccp.solve
    elif backend == "cython":
        _configure_policy("cython", "on")
        solver = _fast_sccp.solve
    else:
        raise ValueError(f"unsupported solver backend {backend!r}")

    program = _CAPTURE.program
    # timed_run is used for the prescribed three warmups; the ten measured
    # calls below are individually sampled for median/p95 without adding
    # another unreported measurement pass.
    timed_run(lambda: solver(program), iterations=0, warmup=warmup)
    samples: list[float] = []
    results: list[object] = []
    for _ in range(iterations):
        started = time.perf_counter()
        result = solver(program)
        samples.append(time.perf_counter() - started)
        results.append(result)
    if not results:
        raise RuntimeError("solver replay produced no measured results")
    first = results[0]
    projection = _result_projection(first)
    if any(_result_projection(result) != projection for result in results[1:]):
        raise RuntimeError(
            f"{backend} solver changed semantics across replay iterations"
        )
    if backend == "cython" and first.backend != "cython":
        pytest.fail(
            "D810_REQUIRE_COMPILED_SCCP=1 but solver replay selected "
            f"{first.backend!r}",
            pytrace=False,
        )
    p95 = statistics.quantiles(samples, n=20, method="inclusive")[18]
    row = _common_row(
        kind="solver_replay",
        label=f"solver_{backend}",
        backend=first.backend,
        overlay="replay",
        status=first.status.value,
        wall_seconds=sum(samples),
        stats={
            "adapter_seconds": _CAPTURE.adapter_seconds,
            "solver_seconds": float(first.solver_seconds),
            "cfg_events": first.cfg_events,
            "value_events": first.value_events,
            "constants_exposed": len(first.constants),
            "edges_exposed": len(first.executable_edges),
        },
        cache_stats=_cache_stats(real_api_calls=_CAPTURE.capture_api_calls),
        fcp_patches=0,
        parity_projection=projection,
        real_api_calls=_CAPTURE.capture_api_calls,
    )
    row.update(
        {
            "median_seconds": statistics.median(samples),
            "p95_seconds": p95,
            "warmup": warmup,
            "iterations": iterations,
        }
    )
    return row


def run_one_full_decomp(
    function_ea: int,
    label: str,
    backend: str,
    overlay: str,
    constant_capacity: int | None = None,
    ast_capacity: int | None = None,
) -> dict[str, object]:
    """Run exactly one real ``idaapi.decompile`` for one semantic variant."""

    if _CAPTURE is None or function_ea != _CAPTURE.function_ea:
        raise RuntimeError(
            "full decomp requested a function other than the captured MBA"
        )
    import idaapi
    from d810.core import (
        MOP_CONSTANT_CACHE,
        MOP_TO_AST_CACHE,
        temporary_mop_cache_policy,
    )
    from d810.evaluator.hexrays_microcode.sccp import sccp_session_stats

    _configure_policy(backend, overlay)
    _reset_session_state()
    if _ACTIVE_STATE is not None:
        getattr(_ACTIVE_STATE, "stats").reset()
    tracemalloc.start()
    started = time.perf_counter()
    context = (
        temporary_mop_cache_policy(constant_capacity, ast_capacity)
        if constant_capacity is not None and ast_capacity is not None
        else None
    )
    try:
        if context is None:
            cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
        else:
            with context:
                cfunc = idaapi.decompile(function_ea, flags=idaapi.DECOMP_NO_CACHE)
                memory_current, _ = tracemalloc.get_traced_memory()
                cache_stats = _cache_stats(
                    real_api_calls=(
                        MOP_CONSTANT_CACHE.stats.lookups
                        + MOP_TO_AST_CACHE.stats.lookups
                    ),
                    memory_delta=memory_current,
                    constant_calls=MOP_CONSTANT_CACHE.stats.lookups,
                    ast_calls=MOP_TO_AST_CACHE.stats.lookups,
                )
        if context is None:
            memory_current, _ = tracemalloc.get_traced_memory()
            cache_stats = _cache_stats(
                real_api_calls=(
                    MOP_CONSTANT_CACHE.stats.lookups + MOP_TO_AST_CACHE.stats.lookups
                ),
                memory_delta=memory_current,
                constant_calls=MOP_CONSTANT_CACHE.stats.lookups,
                ast_calls=MOP_TO_AST_CACHE.stats.lookups,
            )
    finally:
        _, memory_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    wall_seconds = time.perf_counter() - started
    if cfunc is None:
        pytest.fail(
            f"BLOCKED: full decompilation failed for 0x{function_ea:x}", pytrace=False
        )
    pseudocode_sha = _pseudocode_sha256(cfunc)
    if not _CAPTURE.pseudocode_sha256:
        _CAPTURE.pseudocode_sha256 = pseudocode_sha
    elif _CAPTURE.pseudocode_sha256 != pseudocode_sha:
        pytest.fail(
            f"semantic parity failure: {label} pseudocode hash differs from baseline",
            pytrace=False,
        )
    if _CAPTURE.cfg_sha256 != _live_cfg_sha256(function_ea):
        pytest.fail(
            f"semantic parity failure: {label} live CFG hash differs from capture",
            pytrace=False,
        )
    session_stats = sccp_session_stats().as_dict()
    _add_sccp_summary(session_stats)
    row = _common_row(
        kind="full_decomp",
        label=label,
        backend=backend,
        overlay=overlay,
        status=_sccp_status_from_stats(session_stats),
        wall_seconds=wall_seconds,
        stats=session_stats,
        cache_stats=cache_stats,
        fcp_patches=_patch_count(),
        parity_projection={
            "status": _sccp_status_from_stats(session_stats),
            "constants": [],
            "executable_edges": [],
            "reachable_blocks": [],
            "program_fingerprint": _CAPTURE.program.fingerprint,
            "cfg_events": int(session_stats["cfg_events"]),
            "value_events": int(session_stats["value_events"]),
            "peak_cfg_queue": 0,
            "peak_value_queue": 0,
        },
        real_api_calls=int(cache_stats["real_api_calls"]),
    )
    # Keep the measured peak visible in the row without inventing a second
    # timing measurement; ``memory_delta_bytes`` is the traced allocation
    # delta while ``max_weight_ever`` remains cache-owned telemetry.
    row["cache_stats"]["memory_delta_bytes"] = int(memory_peak)
    for cache_name in ("MOP_CONSTANT_CACHE", "MOP_TO_AST_CACHE"):
        row["cache_stats"][cache_name]["memory_delta_bytes"] = int(memory_peak)
    return row


def _capture_real_workload(function_ea: int) -> _CapturedWorkload:
    """Detach one real MBA and its MOP/AST operation stream."""

    from d810.core import MOP_CONSTANT_CACHE, MOP_TO_AST_CACHE
    from d810.hexrays.expr.p_ast import get_constant_mop
    from d810.hexrays.ir.mop_snapshot import MopSnapshot
    from d810.hexrays.ir.mop_utils import mop_to_ast
    from d810.evaluator.hexrays_microcode.sccp_snapshot import snapshot_from_mba
    import ida_hexrays
    import idaapi

    mba = _gen_mba(function_ea)
    if mba is None:
        pytest.fail(
            f"BLOCKED: could not generate the exact real MBA at 0x{function_ea:x}",
            pytrace=False,
        )
    _reset_session_state()
    started = time.perf_counter()
    program = snapshot_from_mba(mba)
    adapter_seconds = time.perf_counter() - started
    operations: list[MopSnapshot] = []
    api_calls = 0
    for block_index in range(int(mba.qty)):
        block = mba.get_mblock(block_index)
        if block is None:
            continue
        instruction = block.head
        while instruction is not None:
            for attribute in ("l", "r"):
                mop = getattr(instruction, attribute, None)
                if mop is None or int(getattr(mop, "t", ida_hexrays.mop_z)) == int(
                    ida_hexrays.mop_z
                ):
                    continue
                snapshot = MopSnapshot.from_mop(mop)
                operations.append(snapshot)
                try:
                    mop_to_ast(mop)
                    api_calls += 1
                except Exception as exc:
                    raise RuntimeError(
                        "real MOP/AST capture failed at "
                        f"block={block_index} attribute={attribute}: {exc}"
                    ) from exc
                if snapshot.t == ida_hexrays.mop_n and snapshot.value is not None:
                    get_constant_mop(snapshot.value, snapshot.size)
                    api_calls += 1
            instruction = instruction.next
    if not operations:
        pytest.fail("BLOCKED: real MBA produced no MOP/AST operations", pytrace=False)
    capture_api_calls = int(
        MOP_CONSTANT_CACHE.stats.lookups + MOP_TO_AST_CACHE.stats.lookups
    )
    if MOP_TO_AST_CACHE.stats.lookups <= 0 or MOP_TO_AST_CACHE.stats.insertions <= 0:
        pytest.fail(
            "BLOCKED: capture did not exercise the real MOP_TO_AST_CACHE API",
            pytrace=False,
        )
    if MOP_CONSTANT_CACHE.stats.lookups <= 0:
        pytest.fail(
            "BLOCKED: capture did not exercise the real MOP_CONSTANT_CACHE API",
            pytrace=False,
        )
    function_name = idaapi.get_name(function_ea) or f"sub_{function_ea:x}"
    binary_path = _fixture_input_path(_default_binary())
    binary_sha = ""
    if binary_path is not None:
        binary_sha = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    cfg_sha = _live_cfg_sha256(function_ea)
    capture = _CapturedWorkload(
        function_ea=function_ea,
        function_name=function_name,
        mba=mba,
        program=program,
        operations=tuple(operations),
        adapter_seconds=adapter_seconds,
        capture_api_calls=max(capture_api_calls, api_calls),
        cfg_sha256=cfg_sha,
        binary_sha256=binary_sha,
    )
    MOP_CONSTANT_CACHE.clear(reset_stats=True)
    MOP_TO_AST_CACHE.clear(reset_stats=True)
    return capture


def _replay_captured_operations(
    constant_capacity: int,
    ast_capacity: int,
) -> dict[str, object]:
    if _CAPTURE is None:
        raise RuntimeError("real workload has not been captured")
    from d810.core import (
        MOP_CONSTANT_CACHE,
        MOP_TO_AST_CACHE,
        temporary_mop_cache_policy,
    )
    from d810.hexrays.expr.p_ast import get_constant_mop
    from d810.hexrays.ir.mop_utils import mop_to_ast
    import ida_hexrays

    _reset_session_state()
    calls = 0
    cache_stats: dict[str, object] | None = None
    memory_current = 0
    memory_peak = 0
    rebuilds = 0
    evictions = 0
    peak_weight = 0.0
    tracemalloc.start()
    started = time.perf_counter()
    with temporary_mop_cache_policy(constant_capacity, ast_capacity):
        for snapshot in _CAPTURE.operations:
            mop = snapshot.to_mop(_CAPTURE.mba)
            mop_to_ast(mop)
            calls += 1
            if snapshot.t == ida_hexrays.mop_n and snapshot.value is not None:
                get_constant_mop(snapshot.value, snapshot.size)
                calls += 1
        memory_current, memory_peak = tracemalloc.get_traced_memory()
        cache_stats = _cache_stats(
            real_api_calls=calls,
            memory_delta=memory_current,
            constant_calls=MOP_CONSTANT_CACHE.stats.lookups,
            ast_calls=MOP_TO_AST_CACHE.stats.lookups,
        )
        rebuilds = int(
            MOP_CONSTANT_CACHE.stats.insertions + MOP_TO_AST_CACHE.stats.insertions
        )
        evictions = int(
            MOP_CONSTANT_CACHE.stats.capacity_evictions
            + MOP_TO_AST_CACHE.stats.capacity_evictions
        )
        peak_weight = float(
            MOP_CONSTANT_CACHE.stats.max_weight_ever
            + MOP_TO_AST_CACHE.stats.max_weight_ever
        )
    wall_seconds = time.perf_counter() - started
    tracemalloc.stop()
    if cache_stats is None:
        raise RuntimeError("cache replay completed without cache telemetry")
    stats = {
        "adapter_seconds": _CAPTURE.adapter_seconds,
        "solver_seconds": 0.0,
        "cfg_events": 0,
        "value_events": 0,
        "constants_exposed": 0,
        "edges_exposed": 0,
    }
    return {
        "wall_seconds": wall_seconds,
        "memory_delta_bytes": int(memory_peak),
        "cache_stats": cache_stats,
        "workload_operations": len(_CAPTURE.operations),
        "rebuilds": rebuilds,
        "evictions": evictions,
        "peak_weight": peak_weight,
        "real_api_calls": calls,
        "stats": stats,
    }


def cache_capacity_matrix(function_ea: int) -> list[dict[str, object]]:
    """Replay the one captured real MOP/AST workload for nine capacity pairs."""

    if _CAPTURE is None or function_ea != _CAPTURE.function_ea:
        raise RuntimeError(
            "cache replay requested a function other than the captured MBA"
        )
    rows: list[dict[str, object]] = []
    for constant_capacity in (1000, 4096, 8192):
        for ast_capacity in (20480, 40960, 81920):
            measured = _replay_captured_operations(constant_capacity, ast_capacity)
            row = _common_row(
                kind="cache_replay",
                label=f"cache_{constant_capacity}_{ast_capacity}",
                backend="cython",
                overlay="replay",
                status="converged",
                wall_seconds=float(measured["wall_seconds"]),
                stats=measured["stats"],
                cache_stats=measured["cache_stats"],
                fcp_patches=0,
                parity_projection={
                    "status": "converged",
                    "constants": [],
                    "executable_edges": [],
                    "reachable_blocks": [],
                    "program_fingerprint": _CAPTURE.program.fingerprint,
                    "cfg_events": 0,
                    "value_events": 0,
                    "peak_cfg_queue": 0,
                    "peak_value_queue": 0,
                },
                real_api_calls=int(measured["real_api_calls"]),
            )
            row.pop("parity_projection")
            row.pop("parity_sha256")
            row.update(
                {
                    "constant_capacity": constant_capacity,
                    "ast_capacity": ast_capacity,
                    "workload_operations": int(measured["workload_operations"]),
                    "rebuilds": int(measured["rebuilds"]),
                    "evictions": int(measured["evictions"]),
                    "peak_weight": float(measured["peak_weight"]),
                    "memory_delta_bytes": int(measured["memory_delta_bytes"]),
                }
            )
            rows.append(row)
    if len(rows) != 9:
        raise AssertionError(f"cache matrix generated {len(rows)} rows, expected nine")
    return rows


def _metadata() -> dict[str, object]:
    if _CAPTURE is None:
        raise RuntimeError("real workload has not been captured")
    source = Path(
        "/Volumes/code/re/eidolon/115.9.6910.9/"
        "WowClassic_loader-115.9.6910.9-devirt.dll.i64"
    )
    destination = (
        Path(__file__).resolve().parents[4] / "samples" / "bins" / _EXPECTED_BINARY
    )
    return {
        "binary": _EXPECTED_BINARY,
        "binary_sha256": _CAPTURE.binary_sha256,
        "function_ea": _CAPTURE.function_ea,
        "function_name": _CAPTURE.function_name,
        "maturity": _MATURITY_LABEL,
        "platform": f"{platform.system()}-{platform.machine()}",
        "python": platform.python_version(),
        "ida_version": str(__import__("idaapi").get_kernel_version()),
        "fixture_source": str(source),
        "fixture_copy": str(destination),
        "fixture_sha256": _CAPTURE.binary_sha256,
        "capture_method": (
            "one real GLBOPT1 mba_t; MOP/AST operands detached with MopSnapshot; "
            "replayed through mop_to_ast/get_constant_mop under "
            "temporary_mop_cache_policy"
        ),
        "workload_operations": len(_CAPTURE.operations),
        "real_api_calls": _CAPTURE.capture_api_calls,
        "warmup": 3,
        "iterations": 10,
    }


class TestSccpCachePerformance:
    """The opt-in real-IDB performance receipt collection gate."""

    binary_name = _EXPECTED_BINARY

    @pytest.mark.ida_required
    def test_receipt_has_semantic_and_cache_evidence(
        self,
        perf_gate_prerequisite,
        libobfuscated_setup,
        d810_state_all_rules,
    ) -> None:
        global _ACTIVE_STATE, _CAPTURE, _SCCP_SUMMARY
        function_ea = _function_ea()
        _SCCP_SUMMARY = {}
        original_mode = None
        try:
            from d810.core import CythonMode

            original_mode = CythonMode().is_enabled()
            with d810_state_all_rules() as state:
                _ACTIVE_STATE = state
                _CAPTURE = _capture_real_workload(function_ea)

                # The semantic baseline runs first so all detached solver and
                # cache rows can carry its independently rendered hash.
                baseline = run_one_full_decomp(function_ea, "baseline", "python", "off")
                candidate = run_one_full_decomp(
                    function_ea, "candidate", "cython", "on"
                )
                auto = run_one_full_decomp(function_ea, "auto", "cython", "auto")
                cache_matrix = cache_capacity_matrix(function_ea)
                winning_matrix_row = min(
                    cache_matrix,
                    key=lambda row: (
                        float(row["wall_seconds"]),
                        int(row["constant_capacity"]),
                        int(row["ast_capacity"]),
                    ),
                )
                winner = run_one_full_decomp(
                    function_ea,
                    "winner",
                    "cython",
                    "auto",
                    int(winning_matrix_row["constant_capacity"]),
                    int(winning_matrix_row["ast_capacity"]),
                )
                winner["constant_capacity"] = int(
                    winning_matrix_row["constant_capacity"]
                )
                winner["ast_capacity"] = int(winning_matrix_row["ast_capacity"])
                solver_python = replay_solver(
                    function_ea, "python", warmup=3, iterations=10
                )
                solver_cython = replay_solver(
                    function_ea, "cython", warmup=3, iterations=10
                )
                rows = [
                    solver_python,
                    solver_cython,
                    baseline,
                    candidate,
                    auto,
                    winner,
                ]
                for row in rows:
                    assert row["status"] in {
                        "converged",
                        "work_limit",
                        "block_limit",
                        "error",
                    }
                    assert row["program_fingerprint"]
                    assert set(row["cache_stats"]) == {
                        "MOP_CONSTANT_CACHE",
                        "MOP_TO_AST_CACHE",
                        "total_evictions",
                        "memory_delta_bytes",
                        "real_api_calls",
                    }
                receipt = Path(
                    os.environ.get("D810_SCCP_RECEIPT", ".tmp/sccp_cache_perf.json")
                )
                payload = {
                    "schema_version": 1,
                    "metadata": _metadata(),
                    "runs": rows,
                    "cache_matrix": cache_matrix,
                    "sccp_summary": dict(_SCCP_SUMMARY),
                }
                save_baseline(payload, receipt, "SCCP and MOP cache performance")
                assert receipt.is_file()
                assert receipt.with_suffix(".md").is_file()
                assert rows
        finally:
            if original_mode is not None:
                from d810.core import CythonMode

                if original_mode:
                    CythonMode().enable()
                else:
                    CythonMode().disable()
            _ACTIVE_STATE = None
            _CAPTURE = None


def test_verifier_rejects_receipt_without_metadata(tmp_path: Path) -> None:
    """A malformed receipt must fail schema validation before thresholds."""

    receipt = tmp_path / "missing-metadata.json"
    receipt.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")

    with pytest.raises(ValueError, match="metadata"):
        verify(receipt)


def test_verifier_accepts_complete_receipt(tmp_path: Path) -> None:
    """A complete hand-built receipt reaches the threshold checks."""

    receipt = tmp_path / "complete.json"
    receipt.write_text(json.dumps(_sample_receipt()), encoding="utf-8")

    verify(receipt)


def test_verifier_rejects_solver_parity_mismatch(tmp_path: Path) -> None:
    """A semantic drift between Python and Cython cannot pass the gate."""

    payload = _sample_receipt()
    payload["runs"][1]["parity_projection"]["value_events"] = 99
    receipt = tmp_path / "parity.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="parity"):
        verify(receipt)


def test_verifier_rejects_missing_capacity_pair(tmp_path: Path) -> None:
    """The capacity matrix must be exactly the nine requested real replays."""

    payload = _sample_receipt()
    payload["cache_matrix"].pop()
    receipt = tmp_path / "capacity.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="too few"):
        verify(receipt)


def test_verifier_rejects_nonconverged_sccp_summary(tmp_path: Path) -> None:
    """Any abstained proof consumer blocks performance acceptance."""

    payload = _sample_receipt()
    payload["sccp_summary"]["work_limit"] = 1
    receipt = tmp_path / "abstained.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="abstained"):
        verify(receipt)


def test_verifier_rejects_cache_row_without_real_api_telemetry(tmp_path: Path) -> None:
    """A synthetic capacity row cannot claim a real cache replay."""

    payload = _sample_receipt()
    payload["cache_matrix"][0]["cache_stats"]["MOP_CONSTANT_CACHE"]["lookups"] = 0
    receipt = tmp_path / "synthetic-cache.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="did not exercise"):
        verify(receipt)


def test_verifier_rejects_non_hash_pseudocode_evidence(tmp_path: Path) -> None:
    """Hash fields remain typed evidence, not merely optional text."""

    payload = _sample_receipt()
    payload["runs"][0]["pseudocode_sha256"] = 123
    receipt = tmp_path / "bad-hash.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="invalid type"):
        verify(receipt)


def test_verifier_rejects_cache_row_from_another_function(tmp_path: Path) -> None:
    """A real cache replay must belong to the same captured function."""

    payload = _sample_receipt()
    payload["cache_matrix"][0]["function_ea"] += 1
    receipt = tmp_path / "wrong-function.json"
    receipt.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValueError, match="function_ea"):
        verify(receipt)
