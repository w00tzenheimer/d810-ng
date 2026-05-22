"""Manual repro harness for OLLVM FLA+BCF DimensionAPI sample.

The sample is user-supplied and lives outside the tracked test corpus.  Keep
this opt-in because the original report involved native Hex-Rays INTERR/crash
behavior.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import tempfile

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


OLLVM_FLA_BCF_FUNCTION = "Java_dimension_DimensionAPI_getHuzpsbPY"
OLLVM_FLA_BCF_FALLBACK_EA = 0x1815A1670
OLLVM_FLA_BCF_DEFAULT_PROJECT = "default_unflattening_ollvm.json"


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _ollvm_fla_bcf_sample_dir() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_SAMPLE_DIR")
    if override:
        return Path(override)
    return _repo_root() / "_gitless" / "issue48"


def _ollvm_fla_bcf_binary() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_BINARY")
    if override:
        return Path(override)
    return _ollvm_fla_bcf_sample_dir() / "dac.dll"


def _ollvm_fla_bcf_project() -> str:
    return os.environ.get("D810_OLLVM_FLA_BCF_PROJECT") or OLLVM_FLA_BCF_DEFAULT_PROJECT


def _ollvm_fla_bcf_input() -> Path:
    override = os.environ.get("D810_OLLVM_FLA_BCF_DATABASE")
    if override:
        return Path(override)
    sample_dir = _ollvm_fla_bcf_sample_dir()
    candidates = (
        sample_dir / "dac.dll.i64",
        sample_dir / "dac.i64",
        sample_dir / "dac.dll.idb",
        sample_dir / "dac.idb",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return _ollvm_fla_bcf_binary()


def _is_database_input(path: Path) -> bool:
    return path.suffix.lower() in {".i64", ".idb"}


def _copy_ollvm_fla_bcf_input(path: Path, tempdir: Path) -> Path:
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


def _ollvm_fla_bcf_enabled() -> None:
    if not unskip_cases_enabled():
        pytest.skip("ollvm_fla_bcf sample is manual; rerun with --unskip-research")
    if not unskip_dangerous_enabled():
        pytest.skip(
            "ollvm_fla_bcf sample may trigger native Hex-Rays INTERR; rerun with "
            "--unskip-research --unskip-dangerous for local crash triage"
        )


def _get_func_ea(name: str) -> int:
    ea = idc.get_name_ea_simple(name)
    if ea == idaapi.BADADDR:
        ea = idc.get_name_ea_simple("_" + name)
    if ea == idaapi.BADADDR and idaapi.get_func(OLLVM_FLA_BCF_FALLBACK_EA):
        ea = OLLVM_FLA_BCF_FALLBACK_EA
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
    print(f"\n=== OLLVM_FLA_BCF {label} PSEUDOCODE BEGIN ===", flush=True)
    if rendered is None:
        print("<decompile failed>", flush=True)
    else:
        print(rendered, flush=True)
    print(f"=== OLLVM_FLA_BCF {label} PSEUDOCODE END ===", flush=True)


def _print_selected_microcode_blocks(cfunc, block_serials: tuple[int, ...]) -> None:
    if not block_serials:
        return
    try:
        from d810.recon.microcode_dump import mba_to_dict
    except Exception as exc:
        print(f"[ollvm_fla_bcf] microcode dump unavailable: {exc}", flush=True)
        return
    data = mba_to_dict(cfunc.mba, func_name=OLLVM_FLA_BCF_FUNCTION)
    wanted = {int(serial) for serial in block_serials}
    print("\n=== OLLVM_FLA_BCF SELECTED MICROCODE BEGIN ===", flush=True)
    print(f"maturity={data.get('maturity')} blocks={data.get('num_blocks')}", flush=True)
    for blk in data.get("blocks", ()):
        serial = int(blk["serial"])
        if serial not in wanted:
            continue
        print(
            f"--- blk[{serial}] type={blk.get('type_name')} "
            f"preds={blk.get('predecessors')} succs={blk.get('successors')} ---",
            flush=True,
        )
        for insn in blk.get("instructions", ()):
            parts = [f"  {insn.get('opcode')}"]
            if insn.get("d"):
                parts.append(f"{insn['d']} =")
            if insn.get("l"):
                parts.append(str(insn["l"]))
            if insn.get("r"):
                parts.append(str(insn["r"]))
            print(" ".join(parts), flush=True)
    print("=== OLLVM_FLA_BCF SELECTED MICROCODE END ===", flush=True)


def _debug_block_serials() -> tuple[int, ...]:
    raw = os.environ.get("D810_OLLVM_FLA_BCF_DUMP_BLOCKS", "")
    serials: list[int] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        serials.append(int(part, 0))
    return tuple(serials)


@pytest.fixture(scope="module")
def ollvm_fla_bcf_database():
    _ollvm_fla_bcf_enabled()
    sample_input = _ollvm_fla_bcf_input()
    if not sample_input.exists():
        pytest.skip(f"ollvm_fla_bcf sample input not found: {sample_input}")

    tempdir = Path(tempfile.mkdtemp(prefix="d810_ollvm_fla_bcf_"))
    temp_input = _copy_ollvm_fla_bcf_input(sample_input, tempdir)
    print(f"\n[ollvm_fla_bcf] copied sample input to {temp_input}", flush=True)

    result = idapro.open_database(str(temp_input), False)
    print(f"[ollvm_fla_bcf] idapro.open_database returned {result}", flush=True)
    if result != 0:
        shutil.rmtree(tempdir)
        pytest.skip(f"Failed to open ollvm_fla_bcf database: {result}")

    if _should_wait_for_auto_analysis(sample_input):
        print("[ollvm_fla_bcf] waiting for IDA auto-analysis", flush=True)
        idaapi.auto_wait()
        print("[ollvm_fla_bcf] IDA auto-analysis finished", flush=True)
    else:
        print("[ollvm_fla_bcf] using pre-analyzed database; skipping auto_wait()", flush=True)
    data_perms = _make_data_segment_readonly()
    print(f"[ollvm_fla_bcf] .data permissions old/new: {data_perms}", flush=True)
    yield {
        "input": temp_input,
        "data_perms": data_perms,
    }

    idapro.close_database()
    shutil.rmtree(tempdir, ignore_errors=True)


@pytest.mark.e2e
@pytest.mark.manual
class TestOllvmFlaBcfDimensionApi:
    def test_configured_ollvm_project_decompiles_dimension_api_without_interr(
        self,
        ollvm_fla_bcf_database,
        configure_hexrays,
        d810_state,
        pseudocode_to_string,
    ) -> None:
        if not idaapi.init_hexrays_plugin():
            pytest.skip("Hex-Rays decompiler plugin not available")

        func_ea = _get_func_ea(OLLVM_FLA_BCF_FUNCTION)
        if func_ea == idaapi.BADADDR:
            pytest.fail(
                f"ollvm_fla_bcf target function not found: {OLLVM_FLA_BCF_FUNCTION}"
            )
        print(f"[ollvm_fla_bcf] target function ea=0x{func_ea:x}", flush=True)

        baseline_cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
        baseline_rendered = None
        if baseline_cfunc is not None:
            baseline_rendered = pseudocode_to_string(baseline_cfunc.get_pseudocode())
        _print_pseudocode_dump("BASELINE", baseline_rendered)

        with d810_state() as state:
            project_name = _ollvm_fla_bcf_project()
            project_index = _resolve_test_project_index(state, project_name)
            state.load_project(project_index)
            with state.for_project(project_name):
                state.stats.reset()
                state.start_d810()
                print(f"[ollvm_fla_bcf] decompiling with {project_name}", flush=True)
                cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
                print(f"[ollvm_fla_bcf] decompile result: {cfunc is not None}", flush=True)
                fired_rules = set(state.stats.get_fired_rule_names())
                block_rules_fired = {
                    name
                    for name, counts in state.stats.cfg_rule_usages.items()
                    if any(count > 0 for count in counts)
                }

        assert cfunc is not None, (
            f"{OLLVM_FLA_BCF_FUNCTION} decompile returned None under {project_name}"
        )
        rendered = pseudocode_to_string(cfunc.get_pseudocode())
        _print_pseudocode_dump("AFTER", rendered)
        _print_selected_microcode_blocks(cfunc, _debug_block_serials())
        assert rendered.strip(), (
            f"{OLLVM_FLA_BCF_FUNCTION} produced empty pseudocode under {project_name}"
        )
        assert "while (" not in rendered
        for selector_const in (
            "0x62CE9A1C",
            "0xFCD789F",
            "0xE5BEDBCA",
            "0x2D02E08C",
            "0x139CD0CD",
            "0x472A0F40",
            "0x9B9BBB1B",
        ):
            assert selector_const not in rendered
        assert "invalid_parameter_noinfo_noreturn" in rendered
        assert "SimpleFlatteningCleanupUnflattener" in block_rules_fired
        assert "FoldReadonlyDataRule" in fired_rules
        assert "ConstantSubtreeFoldRule" in fired_rules
