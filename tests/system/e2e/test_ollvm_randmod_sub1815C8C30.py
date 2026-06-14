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
   ``rand``.  After unflattening this computation is split across multiple
   predecessor blocks (a join point), so the existing block-local
   ``IndirectCallResolver`` / ``FoldReadonlyDataRule`` cannot fold it.  This
   remaining gap is captured as an ``xfail`` so it is tracked without blocking
   the magic-modulo regression guard.
"""

from __future__ import annotations

import os
import re
import shutil
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
            cfunc = idaapi.decompile(func_ea, flags=idaapi.DECOMP_NO_CACHE)
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
    return {"rendered": rendered, "fired_rules": fired_rules}


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
        assert re.search(r"%\s*3\b", rendered), (
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

    @pytest.mark.xfail(
        reason=(
            "rand() devirtualisation: the icall target "
            "(*off_18210A360 + 0x64E2C558D421136 -> rand) is computed across "
            "multiple predecessor blocks after unflattening, so the block-local "
            "IndirectCallResolver / FoldReadonlyDataRule cannot fold it. "
            "Requires cross-block constant propagation of the readonly pointer "
            "into the call target (tracked, out of the additive magic-modulo scope)."
        ),
        strict=True,
    )
    def test_rand_devirtualized_full_golden(self, randmod_rendered) -> None:
        """Full golden: ``return rand() % 3u;`` with a real ``rand`` call.

        Currently xfail — the call target renders as an uninitialized function
        pointer (``v0()``) instead of ``rand`` because the target computation
        is split across CFG join points after unflattening.
        """
        rendered = randmod_rendered["rendered"]

        assert re.search(r"\brand\s*\(\s*\)", rendered), (
            f"{RANDMOD_FUNCTION} did not devirtualize the call to rand():\n{rendered}"
        )
        # No uninitialized function-pointer call should remain.
        assert not re.search(r"\bv\d+\s*\(\s*\)", rendered), (
            f"{RANDMOD_FUNCTION} still calls through an uninitialized pointer:\n{rendered}"
        )
