"""Manual repro harness for the OLLVM rand()%3 helper ``sub_1815C8C30``.

The reference (golden) source for this function is::

    __int64 sub_1815C8C30()
    {
        return rand() % 3u;
    }

It lives in the same user-supplied ``dac.dll`` sample as the DimensionAPI
crash repro (issue #48), so it is opt-in for the same reasons (the sample is
not part of the tracked corpus and the original report involved native
Hex-Rays INTERR behaviour).

Two distinct deobfuscation facts have to be recovered for the full golden:

1. **magic-modulo fold** — Hex-Rays leaves the divide-by-3 remainder as an
   unsigned magic-multiply ``x - 3*(high(zext(x)*MAGIC)>>1)`` where ``MAGIC``
   is an XOR-masked 128-bit constant.  ``UnsignedMagicModulo3Rule`` recognises
   this once the masked constant constant-folds to ``0xAAAAAAAB``.  This is
   covered as a hard assertion below (``% 3`` present, no ``while`` loop).

2. **rand() devirtualisation** — the call target is an obfuscated indirect
   call ``icall (*off_18210A360 + 0x64E2C558D421136)`` that resolves to
   ``rand``.  The branch-witness/liveness policy must preserve the dispatcher
   witness corridor that materializes the call target before the terminal
   indirect call, while still collapsing the terminal dispatcher back-edge.  The
   full ``rand() % 3u`` golden is now a hard assertion below.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import tempfile
from pathlib import Path

import pytest

import ida_segment
import idaapi
import idapro
import idc

from d810.testing.runner import _resolve_test_project_index
from d810.testing.skip_controls import (
    unskip_cases_enabled,
    unskip_dangerous_enabled,
)


RANDMOD_FUNCTION = "sub_1815C8C30"
RANDMOD_FALLBACK_EA = 0x1815C8C30
RANDMOD_DEFAULT_PROJECT = "default_unflattening_ollvm.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _randmod_sample_dir() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_SAMPLE_DIR")
    if override:
        return Path(override)
    return _repo_root() / "_gitless" / "issue48"


def _randmod_binary() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_BINARY")
    if override:
        return Path(override)
    return _randmod_sample_dir() / "dac.dll"


def _randmod_project() -> str:
    return os.environ.get("D810_OLLVM_FLA_BCF_PROJECT") or RANDMOD_DEFAULT_PROJECT


def _randmod_input() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_DATABASE")
    if override:
        return Path(override)
    sample_dir = _randmod_sample_dir()
    candidates = (
        sample_dir / "dac.dll.i64",
        sample_dir / "dac.i64",
        sample_dir / "dac.dll.idb",
        sample_dir / "dac.idb",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return _randmod_binary()


def _is_database_input(path: Path) -> bool:
    return path.suffix.lower() in {".i64", ".idb"}


def _copy_randmod_input(path: Path, tempdir: Path) -> Path:
    if not _is_database_input(path):
        temp_path = tempdir / path.name
        shutil.copy(path, temp_path)
        return temp_path

    copied_database = tempdir / path.name
    for sibling in path.parent.glob(f"{path.stem}.*"):
        if sibling.is_file():
            shutil.copy(sibling, tempdir / sibling.name)
    if not copied_database.exists():
        shutil.copy(path, copied_database)
    return copied_database


def _should_wait_for_auto_analysis(input_path: Path) -> bool:
    override = os.environ.get("D810_OLLVM_FLA_BCF_AUTO_WAIT")
    if override is not None:
        return override.strip().lower() in {"1", "true", "yes", "on"}
    return not _is_database_input(input_path)


def _randmod_enabled() -> None:
    if not unskip_cases_enabled():
        pytest.skip("randmod sample is manual; rerun with --unskip-research")
    if not unskip_dangerous_enabled():
        pytest.skip(
            "randmod sample shares the issue48 database which may trigger native "
            "Hex-Rays INTERR; rerun with --unskip-research --unskip-dangerous"
        )


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and idaapi.get_func(RANDMOD_FALLBACK_EA):
        ea = RANDMOD_FALLBACK_EA
    return ea


def _make_data_segment_readonly() -> tuple[int, int] | None:
    seg = ida_segment.get_segm_by_name(".data")
    if seg is None:
        return None
    old_perm = int(getattr(seg, "perm", 0) or 0)
    new_perm = (old_perm | ida_segment.SEGPERM_READ) & ~ida_segment.SEGPERM_WRITE
    if new_perm != old_perm:
        seg.perm = new_perm
        ida_segment.update_segm(seg)
    return old_perm, new_perm


def _print_pseudocode_dump(label: str, rendered: str | None) -> None:
    print(f"\n=== RANDMOD {label} PSEUDOCODE BEGIN ===", flush=True)
    if rendered is None:
        print("<decompile failed>", flush=True)
    else:
        print(rendered, flush=True)
    print(f"=== RANDMOD {label} PSEUDOCODE END ===", flush=True)


def _randmod_diag_paths() -> set[Path]:
    diag_dir = Path.home() / ".idapro" / "logs" / "d810_logs"
    return set(diag_dir.glob(f"{RANDMOD_FALLBACK_EA:016x}_*.diag.sqlite3"))


def _new_randmod_diag_path(before: set[Path]) -> Path | None:
    new_paths = _randmod_diag_paths() - before
    if not new_paths:
        return None
    return max(new_paths, key=lambda path: path.stat().st_mtime)


def _diag_rows(diag_path: Path, sql: str) -> list[sqlite3.Row]:
    with sqlite3.connect(diag_path) as conn:
        conn.row_factory = sqlite3.Row
        return list(conn.execute(sql))


@pytest.fixture(scope="module")
def randmod_database():
    _randmod_enabled()
    sample_input = _randmod_input()
    if not sample_input.exists():
        pytest.skip(f"randmod sample input not found: {sample_input}")

    tempdir = Path(tempfile.mkdtemp(prefix="d810_randmod_"))
    temp_input = _copy_randmod_input(sample_input, tempdir)
    print(f"\n[randmod] copied sample input to {temp_input}", flush=True)

    result = idapro.open_database(str(temp_input), False)
    print(f"[randmod] idapro.open_database returned {result}", flush=True)
    if result != 0:
        shutil.rmtree(tempdir)
        pytest.skip(f"Failed to open randmod database: {result}")

    if _should_wait_for_auto_analysis(sample_input):
        print("[randmod] waiting for IDA auto-analysis", flush=True)
        idaapi.auto_wait()
        print("[randmod] IDA auto-analysis finished", flush=True)
    else:
        print("[randmod] using pre-analyzed database; skipping auto_wait()", flush=True)
    data_perms = _make_data_segment_readonly()
    print(f"[randmod] .data permissions old/new: {data_perms}", flush=True)
    yield {"input": temp_input, "data_perms": data_perms}

    idapro.close_database()
    shutil.rmtree(tempdir, ignore_errors=True)


@pytest.fixture
def randmod_rendered(randmod_database, configure_hexrays, d810_state, pseudocode_to_string):
    """Decompile ``sub_1815C8C30`` with the OLLVM project and return the text.

    Function scoped because it composes the function-scoped ``d810_state`` /
    ``pseudocode_to_string`` fixtures (a wider scope would raise
    ``ScopeMismatch``).  The heavy database open is shared via the
    module-scoped ``randmod_database`` fixture.
    """
    if not idaapi.init_hexrays_plugin():
        pytest.skip("Hex-Rays decompiler plugin not available")

    func_ea = _get_func_ea(RANDMOD_FUNCTION)
    if func_ea == idaapi.BADADDR:
        pytest.fail(f"randmod target function not found: {RANDMOD_FUNCTION}")
    print(f"[randmod] target function ea=0x{func_ea:x}", flush=True)

    baseline_cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
    baseline_rendered = None
    if baseline_cfunc is not None:
        baseline_rendered = pseudocode_to_string(baseline_cfunc.get_pseudocode())
    _print_pseudocode_dump("BASELINE", baseline_rendered)

    with d810_state() as state:
        project_name = _randmod_project()
        project_index = _resolve_test_project_index(state, project_name)
        state.load_project(project_index)
        with state.for_project(project_name):
            state.stats.reset()
            state.start_d810()
            print(f"[randmod] decompiling with {project_name}", flush=True)
            diag_before = _randmod_diag_paths()
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
            diag_path = _new_randmod_diag_path(diag_before)
            print(f"[randmod] decompile result: {cfunc is not None}", flush=True)
            fired_rules = set(state.stats.get_fired_rule_names())

    assert cfunc is not None, (
        f"{RANDMOD_FUNCTION} decompile returned None under {project_name}"
    )
    rendered = pseudocode_to_string(cfunc.get_pseudocode())
    _print_pseudocode_dump("AFTER", rendered)
    assert rendered.strip(), (
        f"{RANDMOD_FUNCTION} produced empty pseudocode under {project_name}"
    )
    return {"rendered": rendered, "fired_rules": fired_rules, "diag_path": diag_path}


@pytest.mark.e2e
@pytest.mark.manual
class TestOllvmRandModSub1815C8C30:
    def test_magic_modulo_recovered_and_loop_removed(self, randmod_rendered) -> None:
        """The magic-modulo fold + unflattening recover ``% 3`` with no loop.

        Golden shape is ``return rand() % 3u;``.  The divide-by-3 remainder
        must surface as a real ``% 3`` modulo (not the unsigned magic-multiply
        ``- 3 * (... >> ...)`` residue), and the obfuscated dispatch loop must
        be gone.
        """
        rendered = randmod_rendered["rendered"]
        fired_rules = randmod_rendered["fired_rules"]

        # No dispatcher loop survives.
        assert "while (" not in rendered, (
            f"{RANDMOD_FUNCTION} still contains a while loop:\n{rendered}"
        )

        # The remainder is recovered as a genuine modulo by 3.
        assert re.search(r"%\s*3[uU]?\b", rendered), (
            f"{RANDMOD_FUNCTION} did not recover '% 3':\n{rendered}"
        )

        # The unsigned magic-multiply residue must NOT remain in the output.
        assert "3 * (" not in rendered, (
            f"{RANDMOD_FUNCTION} still shows the unfolded magic-multiply:\n{rendered}"
        )
        assert "0xE82C47E0AC934AE" not in rendered, (
            f"{RANDMOD_FUNCTION} still references the masked magic constant:\n{rendered}"
        )

        # The rule responsible for the fold actually fired.
        assert "UnsignedMagicModulo3Rule" in fired_rules, (
            "UnsignedMagicModulo3Rule did not fire; magic-modulo recovery "
            f"regressed. Fired rules: {sorted(fired_rules)}"
        )

    def test_entry_projection_preserves_rand_call_exit_path(self, randmod_rendered) -> None:
        """Entry bridge must not shortcut over the live rand()-call exit path.

        The recovered function must include the real ``rand`` call (or the
        current devirtualization stub ``v0()``) and the magic-modulo result.
        The important regression guard is that projection did not emit an
        invalid ``blk1 -> blk5`` provenance shortcut across the live ``rax``
        definition in the dispatcher witness exit path.
        """
        rendered = randmod_rendered["rendered"]

        # Golden/acceptable shape still contains rand (or its devirtualization
        # stub) and the modulo.
        has_rand = re.search(r"\brand\s*\(\s*\)", rendered) is not None
        has_v0_stub = re.search(r"\bv\d+\s*\(\s*\)", rendered) is not None
        assert has_rand or has_v0_stub, (
            f"{RANDMOD_FUNCTION} lost the call target entirely:\n{rendered}"
        )
        assert re.search(r"%\s*3[uU]?\b", rendered), (
            f"{RANDMOD_FUNCTION} did not recover '% 3':\n{rendered}"
        )

        diag_path = randmod_rendered["diag_path"]
        if diag_path is None:
            pytest.skip("randmod diagnostic DB was not captured")

        exit_path_rows = _diag_rows(
            diag_path,
            """
            SELECT s.maturity, s.phase, i.block_serial, i.insn_index, i.dstr
            FROM instructions i
            JOIN snapshots s ON s.id = i.snapshot_id
            WHERE s.maturity IN ('MMAT_CALLS', 'MMAT_GLBOPT1')
              AND s.phase = 'pre_d810'
              AND i.block_serial IN (2, 3, 8)
            ORDER BY s.id, i.block_serial, i.insn_index
            """,
        )
        assert any(
            row["block_serial"] == 2 and "&($rand).8, rax.8" in row["dstr"]
            for row in exit_path_rows
        ), f"{diag_path} does not show blk2 defining rax = &rand"
        assert any(
            row["block_serial"] == 3
            and "&($sub_18010A890).8, rax.8" in row["dstr"]
            for row in exit_path_rows
        ), f"{diag_path} does not show blk3 defining the rejected call target"
        assert any(
            row["block_serial"] == 8 and "icall cs.2,rax.8" in row["dstr"]
            for row in exit_path_rows
        ), f"{diag_path} does not show blk8 consuming rax in the indirect call"

        liveness_rows = _diag_rows(
            diag_path,
            """
            SELECT source_block, old_target, shortcut_target, outcome, reason,
                   exit_path_blocks_json, live_definitions_json
            FROM exit_path_shortcut_decisions
            WHERE source_block = 1
              AND old_target = 2
              AND shortcut_target = 5
            """,
        )
        assert any(
            row["outcome"] == "rejected"
            and row["reason"] == "exit_path_liveness_unsafe"
            and json.loads(row["exit_path_blocks_json"]) == [2, 4]
            and json.loads(row["live_definitions_json"]) == [
                {"kind": "reg", "value": 8}
            ]
            for row in liveness_rows
        ), f"{diag_path} does not explain the rejected blk1 -> blk5 exit-path shortcut"

        bad_entry_projection = _diag_rows(
            diag_path,
            """
            SELECT c.snapshot_id, c.seq, c.reason, c.extra_json
            FROM cfg_provenance c
            WHERE c.action = 'REDIRECT_EDGE'
              AND c.block_serial = 1
              AND c.target_serial = 5
            """,
        )
        assert not bad_entry_projection, (
            f"{diag_path} contains the invalid blk1 -> blk5 projection: "
            f"{[dict(row) for row in bad_entry_projection]}"
        )

        terminal_projection = _diag_rows(
            diag_path,
            """
            SELECT c.snapshot_id, c.seq, c.reason, c.extra_json
            FROM cfg_provenance c
            WHERE c.action = 'REDIRECT_EDGE'
              AND c.block_serial = 8
              AND c.target_serial = 9
              AND c.reason = 'make_2way_block_goto'
            """,
        )
        assert terminal_projection, (
            f"{diag_path} does not contain the exact terminal blk8 -> blk9 rewrite"
        )
        assert any(
            json.loads(row["extra_json"]).get("old_succs") == [9, 2]
            for row in terminal_projection
        ), f"{diag_path} terminal rewrite did not preserve old blk8 successors"

    def test_rand_devirtualized_full_golden(self, randmod_rendered) -> None:
        """Full golden: ``return rand() % 3u;`` with a real ``rand`` call.

        Regression guard for witness-preserving entry projection: the call
        target definition on the dispatcher exit path must survive to the call.
        """
        rendered = randmod_rendered["rendered"]

        assert re.search(r"\brand\s*\(\s*\)", rendered), (
            f"{RANDMOD_FUNCTION} did not devirtualize the call to rand():\n{rendered}"
        )
        # No uninitialized function-pointer call should remain.
        assert not re.search(r"\bv\d+\s*\(\s*\)", rendered), (
            f"{RANDMOD_FUNCTION} still calls through an uninitialized pointer:\n{rendered}"
        )
