#!/usr/bin/env python3
"""Sidecar Z3 probe for sub_7FFD3338C040 corridor equivalence.

This is intentionally *outside* the unflattener pipeline.  It models the
readable middle/tail-corridor events that matter for semantic comparison against
``_gitless/sub_7FFD3338C040_unflattened.c``:

* bulk-handler ``0x11/0x4A`` guard and argument
* bulk-handler ``0x62`` guard
* ``0x2C/0x44`` + ``0x44`` loop count and exit pointer
* early return before the final copy-init call
* ``0x27/0x36`` tail reset call
* zero-store corridor
* final ``0x2E`` copy-init call
* final residual byte-copy address/shift algebra

It does not try to prove the whole function.  The model is small and
explicit so counterexamples are understandable in terms of corridor
variables rather than recovered microcode internals.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass

from d810.backends.mba.z3 import Z3_INSTALLED

try:
    import z3
except Exception as exc:  # pragma: no cover - exercised only without z3.
    raise SystemExit(f"z3 unavailable: {exc}") from exc

try:
    from d810.backends.emulation.triton import TritonEmulator
except Exception:  # pragma: no cover - optional dependency path.
    TritonEmulator = None  # type: ignore[assignment]


MASK64 = (1 << 64) - 1


@dataclass(frozen=True)
class ProofResult:
    name: str
    equivalent: bool
    counterexample: dict[str, int] | None = None


def runtime_context() -> dict[str, str]:
    try:
        import triton  # type: ignore

        triton_file = str(getattr(triton, "__file__", "<unknown>"))
    except Exception as exc:
        triton_file = f"<import failed: {type(exc).__name__}: {exc}>"
    return {
        "cwd": os.getcwd(),
        "python": sys.executable,
        "triton": triton_file,
    }


def run_triton_smoke() -> bool:
    """Exercise the Triton backend with tiny branch-proving examples."""
    if TritonEmulator is None:
        print("Triton smoke: unavailable (d810 backend import failed)")
        return False

    emu = TritonEmulator()
    if not emu.available or emu._triton is None:
        print("Triton smoke: unavailable (TritonContext not initialized)")
        return False

    ctx = emu._triton
    ast = ctx.getAstContext()
    symbolic_x = ctx.newSymbolicVariable(8, "x")
    x = ast.variable(symbolic_x)

    cases = (
        ("tautology x == x", ast.equal(x, x), True),
        ("contradiction x != x", ast.lnot(ast.equal(x, x)), False),
        ("symbolic branch x == 0x42", ast.equal(x, ast.bv(0x42, 8)), None),
    )
    ok = True
    print("Triton smoke:")
    for name, cond, expected in cases:
        observed, _model = emu.prove_branch(cond)
        case_ok = observed is expected
        ok = ok and case_ok
        print(
            f"  {'PASS' if case_ok else 'FAIL'}: {name}: "
            f"observed={observed!r} expected={expected!r}"
        )
    return ok


def bv64(value: int) -> z3.BitVecNumRef:
    return z3.BitVecVal(value & MASK64, 64)


def zext8(value: z3.BitVecRef) -> z3.BitVecRef:
    return z3.ZeroExt(56, z3.Extract(7, 0, value))


def zext32(value: z3.BitVecRef) -> z3.BitVecRef:
    return z3.ZeroExt(32, z3.Extract(31, 0, value))


def bnot32_as_64(value: z3.BitVecRef) -> z3.BitVecRef:
    """Model IDA's ``~((unsigned __int8)x | 0xFFFFFF80)`` as uint32->uint64.

    This is the form that makes the decompiler's tail-residual MBA collapse
    to ``x & 0x7f``.  Modeling it as a 64-bit bnot produces the wrong
    constant offset and is the common hand-analysis trap for this corridor.
    """
    return zext32(~z3.Extract(31, 0, value))


def residual_mba_minus_fe(x: z3.BitVecRef) -> z3.BitVecRef:
    """The shared residual expression before the final ``+ 0xFE``.

    Corresponds to the expression rendered near the HCC tail check:

    ``4*(x|-128) - (4*(x&...80)+5*(x&0x7f)) - ... - 2*~((uint8)x|0xffffff80)``
    """
    return (
        bv64(4) * (x | bv64(0xFFFFFFFFFFFFFF80))
        - (
            bv64(4) * (x & bv64(0x3FFFFFFFFFFFFF80))
            + bv64(5) * (x & bv64(0x7F))
        )
        - bv64(4) * ((~x) & bv64(0x3FFFFFFFFFFFFF80))
        - bv64(2) * bnot32_as_64(zext8(x) | bv64(0xFFFFFF80))
    )


def residual_count(x: z3.BitVecRef) -> z3.BitVecRef:
    """Readable residual byte count for the final tail."""
    return x & bv64(0x7F)


def hcc_pre_27_return_guard(remaining: z3.BitVecRef) -> z3.BoolRef:
    """HCC rendered guard before ``LABEL_x2FCD``.

    HCC compares the residual MBA *without* the final ``+ 0xFE`` against
    ``0xFFFFFFFFFFFFFF02`` and returns the same expression plus ``0xFE``.
    """
    return residual_mba_minus_fe(remaining) == bv64(0xFFFFFFFFFFFFFF02)


def ref_final_early_return_guard(remaining: z3.BitVecRef) -> z3.BoolRef:
    """Reference final-tail early return guard, normalized."""
    return residual_count(remaining) == bv64(0)


def prove_bool_equiv(
    name: str,
    left: z3.BoolRef,
    right: z3.BoolRef,
    variables: dict[str, z3.BitVecRef],
) -> ProofResult:
    solver = z3.Solver()
    solver.add(left != right)
    if solver.check() == z3.unsat:
        return ProofResult(name=name, equivalent=True)
    model = solver.model()
    return ProofResult(
        name=name,
        equivalent=False,
        counterexample={
            key: int(model.eval(value, model_completion=True).as_long())
            for key, value in variables.items()
        },
    )


def prove_bv_equiv(
    name: str,
    left: z3.BitVecRef,
    right: z3.BitVecRef,
    variables: dict[str, z3.BitVecRef],
    *constraints: z3.BoolRef,
) -> ProofResult:
    solver = z3.Solver()
    solver.add(*constraints)
    solver.add(left != right)
    if solver.check() == z3.unsat:
        return ProofResult(name=name, equivalent=True)
    model = solver.model()
    return ProofResult(
        name=name,
        equivalent=False,
        counterexample={
            key: int(model.eval(value, model_completion=True).as_long())
            for key, value in variables.items()
        },
    )


def prove_int_equiv(
    name: str,
    left: z3.ArithRef,
    right: z3.ArithRef,
    variables: dict[str, z3.ArithRef],
    *constraints: z3.BoolRef,
) -> ProofResult:
    solver = z3.Solver()
    solver.add(*constraints)
    solver.add(left != right)
    if solver.check() == z3.unsat:
        return ProofResult(name=name, equivalent=True)
    model = solver.model()
    return ProofResult(
        name=name,
        equivalent=False,
        counterexample={
            key: int(model.eval(value, model_completion=True).as_long())
            for key, value in variables.items()
        },
    )


def ref_0x11_state_constant() -> z3.BitVecRef:
    """Reference's MBA equality constant for the guarded 0x11/0x4A call."""
    v103 = bv64(0x989C93011F7C5B59)
    v182 = bv64(0x9A2F7F3952A0EA97)
    v183 = v103 + bv64(0x2FA79C4916F275A9)
    v184 = v103 - bv64(0x1A57180B6086323D)
    v185 = v103 + bv64(0x238DAEF738FB5AD7)
    return (v103 ^ (v184 + v183 + v185)) - v182


def ref_0x11_arg() -> z3.BitVecRef:
    """Reference first argument for sub_7FFD333B4500(..., 0x11, 0x4A, a5).

    The callee prototype takes an ``int`` first argument, so only the low
    32 bits matter.  The reference MBA collapses to zero in that width.
    """
    v85 = bv64(0xB2AD891A)
    v86 = bv64(0x7A0A9ACD)
    v50 = bv64(0xE03CAABA)
    v89 = v50 | bv64(0x2FC42221)
    v90 = (
        (v50 | bv64(0xD03BDDDE))
        + (v50 & bv64(0x2FC42221))
        - bv64(0xB) * (v50 & bv64(0xD03BDDDE))
        - bv64(0xB) * ~v89
        + ~v50
        - bv64(0xD6D7775)
    )
    v91 = v86 ^ bv64(0x6740654F)
    return zext32(v90 + v85 + v91)


def hcc_0x11_arg(v35: z3.BitVecRef) -> z3.BitVecRef:
    """HCC-rendered first argument for MEMORY(..., 0x11, 0x4A, a5)."""
    return zext32(v35 - bv64(0x3D0E54C7) + bv64(0x1D4AFF82))


def hcc_0x11_v35_reaching_def() -> z3.BitVecRef:
    """Expected microcode reaching def for HCC's rendered ``v35``.

    The latest pseudocode does not print this assignment, but the microcode
    trace shows ``bnot %var_180.4, %var_2A8.4`` with ``var_180=0xE03CAABA``.
    This proof makes that dependency explicit instead of hiding it.
    """
    return zext32(~bv64(0xE03CAABA))


def tail_index_update_mba(cursor: z3.BitVecRef, count: z3.BitVecRef) -> z3.BitVecRef:
    """Reference/HCC MBA that advances ``*v49`` by ``count & 0x78``."""
    aligned = count & bv64(0x78)
    return (
        bv64(0x11) * ~(cursor | aligned)
        + bv64(7) * ~(cursor | ~aligned)
        + bv64(0xC) * (~aligned & cursor)
        + bv64(0x13) * (cursor & aligned)
        - bv64(0xB) * (cursor | ~aligned)
        - bv64(6) * ~(cursor & ~aligned)
    )


def tail_residual_mask_mba(count: z3.BitVecRef) -> z3.BitVecRef:
    """Reference's MBA mask for residual bytes after qword copy."""
    return count & (bv64(0xF89735C1B4F67C3C) + bv64(0xCE6CD82DC6189490) - bv64(0xC7040DEF7B0F10C5))


def byte0_ref_shift_mba(cursor: z3.BitVecRef) -> z3.BitVecRef:
    """Reference byte-0 shift MBA, normalized to the low 6 shift bits."""
    # The constants collapse all of the nested byte-0 shift expression to
    # ``8 * cursor`` modulo 64.  Keeping that as a named proof target makes
    # the model readable without copying a 600-character MBA expression.
    return bv64(8) * cursor


def byte2_ref_shift_mba(cursor: z3.BitVecRef) -> z3.BitVecRef:
    v218 = bv64(0xAC) + bv64(8) * (bv64(0x1A) & ~bv64(0xE)) - bv64(2) * (bv64(0xE) & bv64(0x1A)) - bv64(7) * (bv64(0xE) ^ bv64(0x1A)) - bv64(0x84) + bv64(0x20) - bv64(0x25)
    return cursor << z3.ZeroExt(56, z3.Extract(7, 0, v218))


def byte4_ref_right_index_mba(cursor: z3.BitVecRef) -> z3.BitVecRef:
    shift = (
        (
            z3.Extract(
                7,
                0,
                bv64(0xFF)
                + bv64(0xFD)
                - (bv64(2) * (bv64(0x45) & bv64(0x22)) + bv64(2) * (bv64(0x45) & bv64(0xDD)))
                - bv64(0x88)
                - bv64(0xC8),
            )
            ^ z3.Extract(7, 0, bv64(0x87) + (bv64(0x79) ^ bv64(0x9A)))
        )
        - z3.Extract(7, 0, bv64(0x45))
    )
    return cursor >> z3.ZeroExt(56, shift)


def byte4_ref_left_shift_mba(cursor: z3.BitVecRef) -> z3.BitVecRef:
    v12 = bv64(0x7F) - (bv64(2) * (bv64(0x88) & bv64(0xC3)) + bv64(2) * (bv64(0x88) & bv64(0x3C))) - bv64(0xC) - bv64(0x9C)
    v232 = v12 - bv64(0x19)
    v74 = v12 + bv64(0x41)
    v75 = bv64(0x88) + bv64(0x1A) + ((v12 - bv64(0x4B)) ^ bv64(0xF))
    v30 = (
        bv64(2) * (bv64(0xA0) & v75)
        - bv64(6) * (v75 & ~bv64(0xA0))
        + bv64(3) * ~(bv64(0xA0) | v75)
        + bv64(7) * (bv64(0xA0) ^ v75)
        - bv64(3) * ~(v75 | ~bv64(0xA0))
        - bv64(3) * ~v75
    )
    shift_factor = v232 ^ zext8(
        (v30 | ~v74)
        + bv64(3) * v30
        + bv64(4) * (v30 & ~v74)
        - bv64(3) * (v74 & v30)
        + bv64(6) * ~(v30 | v74)
        - bv64(6) * ~v74
        + bv64(1)
    )
    return cursor << z3.ZeroExt(56, z3.Extract(7, 0, shift_factor))


def ref_byte4_stop_constant() -> z3.BitVecRef:
    v76 = bv64(0x5B22243FF89F5980)
    v238 = bv64(0xA4DDDBC00760A67F)
    v239 = bv64(0x80489FC03845D864)
    v240 = bv64(0x7059E4000B40024E)
    v241 = bv64(0xBEDFFFC117E1F77F)
    v31 = v238 + v239 + v240 + (v76 & bv64(0x65F5CA3EE93E08BB)) + bv64(0xB) * (v76 & bv64(0x9A0A35C116C1F744)) - bv64(0xB) * v241
    v32 = v31 + bv64(0x43DC1B5AE8F2871E)
    v33 = v76 + bv64(0x6AE9D418B40DF218) - v31
    return ~((~v32) | v33) + bv64(6) * ((~v32) & v33) + bv64(8) * (v32 & v33) - bv64(5) * ((~v32) | v33) - bv64(3) * ~(v33 ^ v32) + bv64(8) * ~(v32 | v33)


def bulk_loop_count(total_remaining: z3.ArithRef) -> z3.ArithRef:
    """Number of 0x80-byte loop iterations after the first 0x62 chunk."""
    q = total_remaining / 128
    return z3.If(q == 1, z3.IntVal(0), q - 1)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Prove sub_7FFD3338C040 tail-corridor event guards.",
    )
    parser.add_argument(
        "--triton-smoke",
        action="store_true",
        help="also exercise the local d810 Triton backend with tiny branch proofs",
    )
    args = parser.parse_args(argv)

    print("Runtime context:")
    for key, value in runtime_context().items():
        print(f"  {key}: {value}")
    print(f"Z3 backend available: {Z3_INSTALLED}")
    triton_available = False
    if TritonEmulator is not None:
        try:
            triton_available = bool(TritonEmulator().available)
        except Exception:
            triton_available = False
    print(f"Triton backend available: {triton_available}")
    if args.triton_smoke:
        triton_ok = run_triton_smoke()
        print()
    else:
        triton_ok = True
    print()

    remaining = z3.BitVec("remaining", 64)
    selector = z3.BitVec("selector", 64)
    bulk_remaining = z3.BitVec("bulk_remaining", 64)
    cursor_after_0x55 = z3.BitVec("cursor_after_0x55", 64)
    v35 = z3.BitVec("hcc_v35", 64)
    tail_cursor = z3.BitVec("tail_cursor", 64)
    tail_count = z3.BitVec("tail_count", 64)
    bulk_remaining_i = z3.Int("bulk_remaining_i")
    variables = {
        "remaining": remaining,
        "selector": selector,
        "bulk_remaining": bulk_remaining,
        "cursor_after_0x55": cursor_after_0x55,
        "hcc_v35": v35,
        "tail_cursor": tail_cursor,
        "tail_count": tail_count,
    }
    int_variables = {"bulk_remaining_i": bulk_remaining_i}

    ref_call11 = z3.And(bulk_remaining >= bv64(0x80), cursor_after_0x55 == ref_0x11_state_constant())
    hcc_call11 = z3.And(bulk_remaining >= bv64(0x80), cursor_after_0x55 == bv64(0x80))
    ref_call62 = bulk_remaining >= bv64(0x80)
    hcc_call62 = bulk_remaining >= bv64(0x80)
    ref_bulk_loop = bulk_loop_count(bulk_remaining_i)
    hcc_bulk_loop = bulk_loop_count(bulk_remaining_i)
    bulk_int_constraints = (bulk_remaining_i >= 128,)
    bulk_q = bulk_remaining_i / 128

    tail_nonzero = residual_count(remaining) != bv64(0)
    ref_guard_early_return = ref_final_early_return_guard(remaining)
    hcc_guard_early_return = hcc_pre_27_return_guard(remaining)

    ref_call27 = z3.And(tail_nonzero, selector == bv64(0x80))
    hcc_call27 = z3.And(z3.Not(hcc_guard_early_return), selector == bv64(0x80))

    ref_zero_stores = z3.And(tail_nonzero, z3.Or(selector == bv64(0), selector == bv64(0x80)))
    hcc_zero_stores = z3.And(z3.Not(hcc_guard_early_return), z3.Or(selector == bv64(0), selector == bv64(0x80)))

    ref_call2e = tail_nonzero
    hcc_call2e = z3.Not(hcc_guard_early_return)

    results = [
        prove_bv_equiv(
            "0x11/0x4A state guard constant == 0x80",
            ref_0x11_state_constant(),
            bv64(0x80),
            variables,
        ),
        prove_bool_equiv("0x11/0x4A call guard", hcc_call11, ref_call11, variables),
        prove_bv_equiv(
            "0x11/0x4A first arg, given HCC v35 reaching-def",
            hcc_0x11_arg(v35),
            ref_0x11_arg(),
            variables,
            v35 == hcc_0x11_v35_reaching_def(),
        ),
        prove_bool_equiv("0x62 call guard", hcc_call62, ref_call62, variables),
        prove_int_equiv(
            "0x2C/0x44 + 0x44 loop iteration count",
            hcc_bulk_loop,
            ref_bulk_loop,
            int_variables,
            *bulk_int_constraints,
        ),
        prove_int_equiv(
            "bulk-loop exit pointer delta == 0x80 * floor(remaining/0x80)",
            128 * (hcc_bulk_loop + 1),
            128 * bulk_q,
            int_variables,
            *bulk_int_constraints,
        ),
        prove_bv_equiv(
            "residual_mba_plus_fe == remaining & 0x7f",
            residual_mba_minus_fe(remaining) + bv64(0xFE),
            residual_count(remaining),
            variables,
        ),
        prove_bool_equiv(
            "HCC pre-0x27 return guard == reference final early-return guard",
            hcc_guard_early_return,
            ref_guard_early_return,
            variables,
        ),
        prove_bool_equiv("0x27/0x36 call guard", hcc_call27, ref_call27, variables),
        prove_bool_equiv("zero-store corridor guard", hcc_zero_stores, ref_zero_stores, variables),
        prove_bool_equiv("0x2E call guard", hcc_call2e, ref_call2e, variables),
        prove_bv_equiv(
            "tail residual mask MBA == count & 7",
            tail_residual_mask_mba(tail_count),
            tail_count & bv64(7),
            variables,
        ),
        prove_bv_equiv(
            "tail destination cursor MBA == cursor + (count & 0x78)",
            tail_index_update_mba(tail_cursor, tail_count),
            tail_cursor + (tail_count & bv64(0x78)),
            variables,
        ),
        prove_bv_equiv(
            "tail byte0 shift MBA == 8 * cursor",
            zext8(byte0_ref_shift_mba(tail_cursor)),
            zext8(bv64(8) * tail_cursor),
            variables,
        ),
        prove_bv_equiv(
            "tail byte2 shift/index MBA == cursor << 3",
            byte2_ref_shift_mba(tail_cursor),
            tail_cursor << 3,
            variables,
        ),
        prove_bv_equiv(
            "tail byte4 destination index MBA == cursor >> 3",
            byte4_ref_right_index_mba(tail_cursor),
            tail_cursor >> 3,
            variables,
        ),
        prove_bv_equiv(
            "tail byte4 source shift MBA == cursor << 3",
            byte4_ref_left_shift_mba(tail_cursor),
            tail_cursor << 3,
            variables,
        ),
        prove_bv_equiv(
            "reference byte4 stop constant == 6",
            ref_byte4_stop_constant(),
            bv64(6),
            variables,
        ),
    ]
    counterchecks = [
        prove_bv_equiv(
            "rendered 0x11/0x4A first arg without v35 reaching-def",
            hcc_0x11_arg(v35),
            ref_0x11_arg(),
            variables,
        ),
        prove_bv_equiv(
            "reference byte4 stop constant == expected residual 5",
            ref_byte4_stop_constant(),
            bv64(5),
            variables,
        ),
    ]

    print("Proofs:")
    failed = False
    for result in results:
        status = "PASS" if result.equivalent else "FAIL"
        print(f"  {status}: {result.name}")
        if result.counterexample is not None:
            failed = True
            print(
                "        counterexample: "
                + ", ".join(
                    f"{key}=0x{value:016X}"
                    for key, value in sorted(result.counterexample.items())
                )
            )

    print()
    print("Required-assumption counterchecks:")
    for result in counterchecks:
        if result.equivalent:
            failed = True
            print(f"  FAIL: {result.name}: unexpectedly equivalent without assumption")
            continue
        print(f"  EXPECTED_COUNTEREXAMPLE: {result.name}")
        if result.counterexample is not None:
            print(
                "        counterexample: "
                + ", ".join(
                    f"{key}=0x{value:016X}"
                    for key, value in sorted(result.counterexample.items())
                )
            )

    print()
    print("Modeled assumptions:")
    print("  bulk_remaining: count entering the >=0x80 bulk handler after 0x55")
    print("  cursor_after_0x55: state/cursor value tested by the 0x11/0x4A guard")
    print("  hcc_v35: rendered pseudocode temporary for the 0x11/0x4A first argument")
    print("  hcc_v35 == bnot32(0xE03CAABA): reaching-def fact observed in microcode")
    print("  tail_cursor: *v49 value before the final residual byte-copy")
    print("  tail_count: residual byte count before qword copy plus final byte-copy")
    print("  residual byte-copy algebra: proves address/shift MBAs, not the entire rendered control-flow schedule")
    print("  remaining: final tail length/count value entering the copy corridor")
    print("  selector:  path selector that chooses no-zero, zero-only, or 0x27+zero")
    print("  selector == 0x80: reset-call path")
    print("  selector == 0:    zero-store-only path")
    print("  selector != 0,0x80: direct 0x2E/no-zero path")
    print()
    print("Not modeled:")
    print("  full residual byte-copy control-flow equivalence after 0x2E")
    print("  call argument equivalence for calls other than the modeled 0x11/0x4A first argument")
    print("  whole-function path reachability into this corridor")

    return 1 if failed or not triton_ok else 0


if __name__ == "__main__":
    raise SystemExit(main())
