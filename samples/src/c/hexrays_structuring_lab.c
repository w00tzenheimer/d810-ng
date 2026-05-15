/**
 * Hex-Rays structuring lab fixtures.
 *
 * These functions are intentionally small and shape-focused. The lab does not
 * trust C source shape directly; every fixture must pass compiled-CFG validation
 * before its decompiler output is treated as evidence.
 */

#include "platform.h"
#include <stdint.h>

volatile int g_hexrays_lab_sink = 0;

#if defined(_MSC_VER)
#define HEXRAYS_LAB_NOINLINE __declspec(noinline)
#elif defined(__clang__) || defined(__GNUC__)
#define HEXRAYS_LAB_NOINLINE __attribute__((noinline))
#else
#define HEXRAYS_LAB_NOINLINE
#endif

EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_boundary_anchor_helper(volatile int *slot, int value)
{
    *slot = value;
    return *slot;
}

/*
 * Intended CFG:
 *   entry -> step1 -> step2 -> step3 -> done
 *
 * The labels are deliberately laid out out of execution order so at least one
 * edge requires an explicit jump even at -O0. Validation must prove the final
 * compiled microcode still contains the single-pred/single-succ chain.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_single_pred_chain_merge(int x)
{
    int result = x + 1;

    goto step1;

done:
    g_hexrays_lab_sink = result;
    return result;

step3:
    result = result - 7;
    g_hexrays_lab_sink = result;
    goto done;

step1:
    result = result * 3;
    g_hexrays_lab_sink = result;
    goto step2;

step2:
    result = result ^ 0x55AA;
    g_hexrays_lab_sink = result;
    goto step3;
}

/*
 * Intended CFG:
 *   entry -> step1 -> boundary -> step2 -> done
 *     \----------------^
 *
 * The volatile guard creates a genuine second predecessor for boundary. The
 * lab uses this to test whether a multi-pred boundary blocks Hex-Rays chain
 * coalescing across a handler-style edge.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_multi_pred_boundary_barrier(int x)
{
    int result = x + 1;

    if (g_hexrays_lab_sink == 0x13572468) {
        goto boundary;
    }
    goto step1;

done:
    g_hexrays_lab_sink = result;
    return result;

step2:
    result = result - 7;
    g_hexrays_lab_sink = result;
    goto done;

step1:
    result = result * 3;
    g_hexrays_lab_sink = result;
    goto boundary;

boundary:
    result = result ^ 0x55AA;
    g_hexrays_lab_sink = result;
    goto step2;
}

/*
 * Intended CFG:
 *   entry -> step1 -> boundary(anchor call) -> step2 -> done
 *     \--------------------------^
 *
 * This starts from the same multi-pred boundary shape as
 * hexrays_lab_multi_pred_boundary_barrier, but the boundary consumes its local
 * value through a noinline volatile helper before handing off to the successor.
 * The side effect is semantically real, so if Hex-Rays preserves it, that is
 * stronger evidence than predecessor topology alone.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_side_effect_boundary_anchor(int x)
{
    int result = x + 1;

    if (g_hexrays_lab_sink == 0x24681357) {
        goto boundary;
    }
    goto step1;

done:
    g_hexrays_lab_sink = result;
    return result;

step2:
    result = result - 7;
    g_hexrays_lab_sink = result;
    goto done;

step1:
    result = result * 3;
    g_hexrays_lab_sink = result;
    goto boundary;

boundary:
    result = result ^ 0x55AA;
    result = hexrays_lab_boundary_anchor_helper(
        &g_hexrays_lab_sink,
        result
    );
    goto step2;
}

/*
 * Intended CFG:
 *          /-> left  -\
 *   entry                -> join -> done
 *          \-> right -/
 *
 * This is the friendly baseline for a two-child fork with a single join. It
 * should tell the lab what Hex-Rays does when d810 emits a clean conditional
 * region instead of a flattened handler chain.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_clean_conditional_fork(int x)
{
    int result = x + 1;

    if ((g_hexrays_lab_sink & 1) != 0) {
        goto left;
    }
    goto right;

done:
    g_hexrays_lab_sink = result;
    return result;

join:
    result = result ^ 0x5A5A;
    g_hexrays_lab_sink = result;
    goto done;

right:
    result = result - 13;
    g_hexrays_lab_sink = result;
    goto join;

left:
    result = result + 11;
    g_hexrays_lab_sink = result;
    goto join;
}

/*
 * Intended CFG:
 *   entry -> step1 -> shell -> boundary -> step2 -> done
 *     \----------------^
 *                   \-> trace -/
 *
 * This tests whether a real opaque conditional shell around a handler boundary
 * changes Hex-Rays compaction behavior. The shell is not a fake barrier: the
 * trace arm performs an observable volatile store before rejoining the boundary
 * body.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_conditional_shell_boundary(int x)
{
    int result = x + 1;

    if (g_hexrays_lab_sink == 0x31415926) {
        goto shell;
    }
    goto step1;

done:
    g_hexrays_lab_sink = result;
    return result;

step2:
    result = result - 7;
    g_hexrays_lab_sink = result;
    goto done;

boundary:
    result = result ^ 0x55AA;
    g_hexrays_lab_sink = result;
    goto step2;

trace:
    g_hexrays_lab_sink = result;
    goto boundary;

step1:
    result = result * 3;
    g_hexrays_lab_sink = result;
    goto shell;

shell:
    if ((g_hexrays_lab_sink & 2) != 0) {
        goto trace;
    }
    goto boundary;
}

/*
 * Intended CFG:
 *   father -> dispatcher -> case_cond
 *      \--------------------^
 *   case_cond -> case_true/case_false -> done
 *
 * This isolates the BadWhileLoop "triangle into a conditional dispatcher case"
 * shape. The risky edge is father -> case_cond: it is direct, not a cleanup
 * trampoline, while dispatcher also reaches the same conditional case block.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_badwhile_direct_triangle_case(int x)
{
    int result = x + 3;
    int state = x & 3;

    goto father;

done:
    g_hexrays_lab_sink = result;
    return result;

case_true:
    result = result + 0x31;
    g_hexrays_lab_sink = result;
    goto done;

case_false:
    result = result ^ 0x2424;
    g_hexrays_lab_sink = result;
    goto done;

dispatcher_fallback:
    result = result - 0x17;
    g_hexrays_lab_sink = result;
    goto done;

father:
    result = result ^ 0x1111;
    g_hexrays_lab_sink = result;
    if ((g_hexrays_lab_sink & 4) != 0) {
        goto case_cond;
    }
    goto dispatcher;

dispatcher:
    if (state != 1) {
        goto dispatcher_fallback;
    }

case_cond:
    if ((g_hexrays_lab_sink + state) == 0x4101) {
        goto case_true;
    }
    goto case_false;
}

/*
 * Intended CFG:
 *   father -> tri_trampoline -> case_cond
 *      \-> dispatcher -----------^
 *   case_cond -> case_true/case_false -> done
 *
 * This is the trampoline variant of the same triangle. The father edge to the
 * conditional case is intentionally mediated by a minimal one-way label so the
 * compiled CFG can prove case_cond does not list father as a direct pred.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_badwhile_trampoline_triangle_case(int x)
{
    int result = x + 5;
    int state = x & 7;

    goto father;

done:
    g_hexrays_lab_sink = result;
    return result;

case_true:
    result = result + 0x43;
    g_hexrays_lab_sink = result;
    goto done;

case_false:
    result = result ^ 0x3535;
    g_hexrays_lab_sink = result;
    goto done;

dispatcher_fallback:
    result = result - 0x19;
    g_hexrays_lab_sink = result;
    goto done;

father:
    result = result ^ 0x2222;
    g_hexrays_lab_sink = result;
    if ((g_hexrays_lab_sink & 8) == 0) {
        goto dispatcher;
    }
    goto tri_trampoline;

tri_trampoline:
    goto case_cond;

dispatcher:
    if (state != 2) {
        goto dispatcher_fallback;
    }

case_cond:
    if ((g_hexrays_lab_sink ^ state) == 0x4202) {
        goto case_true;
    }
    goto case_false;
}

/*
 * Intended CFG:
 *   pred_a -> shared -> dispatcher -> case_cond
 *      \-----------------------------^
 *   pred_b -> shared
 *      \-----------------------------^
 *
 * This is the duplicate-group direct triangle lab row. Both per-pred arms can
 * resolve directly to the conditional dispatcher case, while their normal path
 * still joins through a shared body that flows into the dispatcher.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_badwhile_duplicate_group_triangle(int x)
{
    int result = x + 7;
    int state = x & 15;

    if ((g_hexrays_lab_sink & 1) != 0) {
        goto pred_a;
    }
    goto pred_b;

done:
    g_hexrays_lab_sink = result;
    return result;

case_true:
    result = result + 0x59;
    g_hexrays_lab_sink = result;
    goto done;

case_false:
    result = result ^ 0x4646;
    g_hexrays_lab_sink = result;
    goto done;

case_cond:
    if ((g_hexrays_lab_sink - state) == 0x4303) {
        goto case_true;
    }
    goto case_false;

dispatcher_fallback:
    result = result - 0x1D;
    g_hexrays_lab_sink = result;
    goto done;

dispatcher:
    if (state == 3) {
        goto case_cond;
    }
    goto dispatcher_fallback;

shared:
    result = result ^ 0x5151;
    g_hexrays_lab_sink = result;
    goto dispatcher;

pred_a:
    result = result + 0x0A;
    g_hexrays_lab_sink = result;
    if ((g_hexrays_lab_sink & 2) != 0) {
        goto case_cond;
    }
    goto shared;

pred_b:
    result = result - 0x0B;
    g_hexrays_lab_sink = result;
    if ((g_hexrays_lab_sink & 4) != 0) {
        goto case_cond;
    }
    goto shared;
}


#if defined(_WIN64) || defined(__MINGW32__) || defined(__MINGW64__)
/*
 * Hand-authored x64 lab rows for BadWhileLoop triangle topology. The C
 * versions above are useful source documentation, but clang intentionally
 * lowers conditional goto arms through one-way handoff blocks at -O0. These
 * assembly fixtures keep the exact direct/trampoline edges under validation.
 */
__asm__(
".text\n"
".globl hexrays_lab_badwhile_direct_triangle_case_asm\n"
".def hexrays_lab_badwhile_direct_triangle_case_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_direct_triangle_case_asm:\n"
"  leal 3(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $3, %r8d\n"
".Lbadwhile_direct_father:\n"
"  xorl $0x1111, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $4, %r9d\n"
"  jne .Lbadwhile_direct_case_cond\n"
".Lbadwhile_direct_dispatcher:\n"
"  cmpl $1, %r8d\n"
"  je .Lbadwhile_direct_case_cond\n"
".Lbadwhile_direct_dispatcher_fallback:\n"
"  subl $0x17, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_direct_done\n"
".Lbadwhile_direct_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  addl %r8d, %r9d\n"
"  cmpl $0x4101, %r9d\n"
"  je .Lbadwhile_direct_case_true\n"
".Lbadwhile_direct_case_false:\n"
"  xorl $0x2424, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_direct_done\n"
".Lbadwhile_direct_case_true:\n"
"  addl $0x31, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_direct_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);

__asm__(
".text\n"
".globl hexrays_lab_badwhile_trampoline_triangle_case_asm\n"
".def hexrays_lab_badwhile_trampoline_triangle_case_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_trampoline_triangle_case_asm:\n"
"  leal 5(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $7, %r8d\n"
".Lbadwhile_trampoline_father:\n"
"  xorl $0x2222, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $8, %r9d\n"
"  je .Lbadwhile_trampoline_dispatcher\n"
".Lbadwhile_tri_trampoline:\n"
"  jmp .Lbadwhile_trampoline_case_cond\n"
".Lbadwhile_trampoline_dispatcher:\n"
"  cmpl $2, %r8d\n"
"  je .Lbadwhile_trampoline_case_cond\n"
".Lbadwhile_trampoline_dispatcher_fallback:\n"
"  subl $0x19, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_trampoline_done\n"
".Lbadwhile_trampoline_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  xorl %r8d, %r9d\n"
"  cmpl $0x4202, %r9d\n"
"  je .Lbadwhile_trampoline_case_true\n"
".Lbadwhile_trampoline_case_false:\n"
"  xorl $0x3535, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_trampoline_done\n"
".Lbadwhile_trampoline_case_true:\n"
"  addl $0x43, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_trampoline_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);

__asm__(
".text\n"
".globl hexrays_lab_badwhile_duplicate_group_triangle_asm\n"
".def hexrays_lab_badwhile_duplicate_group_triangle_asm; .scl 2; .type 32; .endef\n"
"hexrays_lab_badwhile_duplicate_group_triangle_asm:\n"
"  leal 7(%ecx), %eax\n"
"  movl %ecx, %r8d\n"
"  andl $15, %r8d\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $1, %r9d\n"
"  jne .Lbadwhile_dup_pred_a\n"
"  jmp .Lbadwhile_dup_pred_b\n"
".Lbadwhile_dup_pred_a:\n"
"  addl $0x0A, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $2, %r9d\n"
"  jne .Lbadwhile_dup_case_cond\n"
".Lbadwhile_dup_shared:\n"
"  xorl $0x5151, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_dispatcher\n"
".Lbadwhile_dup_dispatcher:\n"
"  cmpl $3, %r8d\n"
"  je .Lbadwhile_dup_case_cond\n"
".Lbadwhile_dup_dispatcher_fallback:\n"
"  subl $0x1D, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_done\n"
".Lbadwhile_dup_pred_b:\n"
"  subl $0x0B, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  testl $4, %r9d\n"
"  je .Lbadwhile_dup_shared\n"
".Lbadwhile_dup_case_cond:\n"
"  movl g_hexrays_lab_sink(%rip), %r9d\n"
"  subl %r8d, %r9d\n"
"  cmpl $0x4303, %r9d\n"
"  je .Lbadwhile_dup_case_true\n"
".Lbadwhile_dup_case_false:\n"
"  xorl $0x4646, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  jmp .Lbadwhile_dup_done\n"
".Lbadwhile_dup_case_true:\n"
"  addl $0x59, %eax\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
".Lbadwhile_dup_done:\n"
"  movl %eax, g_hexrays_lab_sink(%rip)\n"
"  retq\n"
);
#endif

/*
 * Intended CFG:
 *   byte0 -> guard0 -> byte1 -> guard1 -> ... -> byte6 -> done
 *
 * This is the REF-like oracle for the terminal-byte tail. Each byte store is
 * followed by an early-return guard before the next byte is emitted. The lab
 * uses compiled-CFG validation to prove the stores and guards remain an
 * acyclic cascade before treating Hex-Rays output as evidence.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_terminal_tail_ref_cascade(volatile uint8_t *base, int token)
{
    int cursor = token;

byte0:
    base[0] = (uint8_t)(cursor + 0x10);
    cursor += 1;
    if ((g_hexrays_lab_sink ^ cursor) == 0x7010) {
        return 0;
    }

byte1:
    base[1] = (uint8_t)(cursor + 0x21);
    cursor += 3;
    if ((g_hexrays_lab_sink + cursor) == 0x7021) {
        return 1;
    }

byte2:
    base[2] = (uint8_t)(cursor + 0x32);
    cursor += 5;
    if ((g_hexrays_lab_sink - cursor) == 0x7032) {
        return 2;
    }

byte3:
    base[3] = (uint8_t)(cursor + 0x43);
    cursor += 7;
    if ((g_hexrays_lab_sink ^ cursor) == 0x7043) {
        return 3;
    }

byte4:
    base[4] = (uint8_t)(cursor + 0x54);
    cursor += 11;
    if ((g_hexrays_lab_sink + cursor) == 0x7054) {
        return 4;
    }

byte5:
    base[5] = (uint8_t)(cursor + 0x65);
    cursor += 13;
    if ((g_hexrays_lab_sink - cursor) == 0x7065) {
        return 5;
    }

byte6:
    base[6] = (uint8_t)(cursor + 0x76);
    g_hexrays_lab_sink = cursor;
    return 7;
}

/*
 * Intended CFG:
 *   byte[k] -> shared_guard -> byte[k + 1]
 *
 * This is the D810-like bad shape. The byte stores are distinct, but all
 * intermediate exits route through one convergence block that decides whether
 * to return early or continue to the next byte.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_terminal_tail_shared_convergence(
    volatile uint8_t *base,
    int token
)
{
    int cursor = token;
    int stage = 0;

    goto byte0;

shared_guard:
    if ((g_hexrays_lab_sink ^ cursor ^ stage) == 0x7100) {
        return stage;
    }
    if (stage == 0) {
        goto byte1;
    }
    if (stage == 1) {
        goto byte2;
    }
    if (stage == 2) {
        goto byte3;
    }
    if (stage == 3) {
        goto byte4;
    }
    if (stage == 4) {
        goto byte5;
    }
    if (stage == 5) {
        goto byte6;
    }
    g_hexrays_lab_sink = cursor;
    return 7;

byte0:
    base[0] = (uint8_t)(cursor + 0x10);
    cursor += 1;
    stage = 0;
    goto shared_guard;

byte1:
    base[1] = (uint8_t)(cursor + 0x21);
    cursor += 3;
    stage = 1;
    goto shared_guard;

byte2:
    base[2] = (uint8_t)(cursor + 0x32);
    cursor += 5;
    stage = 2;
    goto shared_guard;

byte3:
    base[3] = (uint8_t)(cursor + 0x43);
    cursor += 7;
    stage = 3;
    goto shared_guard;

byte4:
    base[4] = (uint8_t)(cursor + 0x54);
    cursor += 11;
    stage = 4;
    goto shared_guard;

byte5:
    base[5] = (uint8_t)(cursor + 0x65);
    cursor += 13;
    stage = 5;
    goto shared_guard;

byte6:
    base[6] = (uint8_t)(cursor + 0x76);
    stage = 6;
    goto shared_guard;
}

/*
 * Intended CFG:
 *   emit[k] -> check[k] -> return/emit[k + 1]
 *
 * This isolates the Track B v2 hypothesis: split each byte emission from its
 * guard so Hex-Rays sees explicit emit/check pairs instead of a shared tail.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_terminal_tail_split_guard(volatile uint8_t *base, int token)
{
    int cursor = token;

emit0:
    base[0] = (uint8_t)(cursor + 0x10);
    cursor += 1;
    goto check0;

check0:
    if ((g_hexrays_lab_sink ^ cursor) == 0x7200) {
        return 0;
    }
    goto emit1;

emit1:
    base[1] = (uint8_t)(cursor + 0x21);
    cursor += 3;
    goto check1;

check1:
    if ((g_hexrays_lab_sink + cursor) == 0x7201) {
        return 1;
    }
    goto emit2;

emit2:
    base[2] = (uint8_t)(cursor + 0x32);
    cursor += 5;
    goto check2;

check2:
    if ((g_hexrays_lab_sink - cursor) == 0x7202) {
        return 2;
    }
    goto emit3;

emit3:
    base[3] = (uint8_t)(cursor + 0x43);
    cursor += 7;
    goto check3;

check3:
    if ((g_hexrays_lab_sink ^ cursor) == 0x7203) {
        return 3;
    }
    goto emit4;

emit4:
    base[4] = (uint8_t)(cursor + 0x54);
    cursor += 11;
    goto check4;

check4:
    if ((g_hexrays_lab_sink + cursor) == 0x7204) {
        return 4;
    }
    goto emit5;

emit5:
    base[5] = (uint8_t)(cursor + 0x65);
    cursor += 13;
    goto check5;

check5:
    if ((g_hexrays_lab_sink - cursor) == 0x7205) {
        return 5;
    }
    goto emit6;

emit6:
    base[6] = (uint8_t)(cursor + 0x76);
    g_hexrays_lab_sink = cursor;
    return 7;
}

/*
 * Intended CFG:
 *   byte[k] -> continuation[k] -> shared_guard -> byte[k + 1]
 *
 * This tests topology-only tail distinction. Each byte emit has its own
 * trivial continuation before the shared guard, without adding helper calls or
 * volatile side-effect anchors beyond the byte store itself.
 */
EXPORT HEXRAYS_LAB_NOINLINE
int hexrays_lab_terminal_tail_unique_continuation(
    volatile uint8_t *base,
    int token
)
{
    int cursor = token;
    int stage = 0;
    int marker = token;

    goto byte0;

shared_guard:
    if ((g_hexrays_lab_sink + marker + stage) == 0x7300) {
        return stage;
    }
    if (stage == 0) {
        goto byte1;
    }
    if (stage == 1) {
        goto byte2;
    }
    if (stage == 2) {
        goto byte3;
    }
    if (stage == 3) {
        goto byte4;
    }
    if (stage == 4) {
        goto byte5;
    }
    if (stage == 5) {
        goto byte6;
    }
    g_hexrays_lab_sink = marker;
    return 7;

byte0:
    base[0] = (uint8_t)(cursor + 0x10);
    cursor += 1;
    stage = 0;
    goto cont0;
cont0:
    marker = cursor + stage;
    goto shared_guard;

byte1:
    base[1] = (uint8_t)(cursor + 0x21);
    cursor += 3;
    stage = 1;
    goto cont1;
cont1:
    marker = cursor + stage;
    goto shared_guard;

byte2:
    base[2] = (uint8_t)(cursor + 0x32);
    cursor += 5;
    stage = 2;
    goto cont2;
cont2:
    marker = cursor + stage;
    goto shared_guard;

byte3:
    base[3] = (uint8_t)(cursor + 0x43);
    cursor += 7;
    stage = 3;
    goto cont3;
cont3:
    marker = cursor + stage;
    goto shared_guard;

byte4:
    base[4] = (uint8_t)(cursor + 0x54);
    cursor += 11;
    stage = 4;
    goto cont4;
cont4:
    marker = cursor + stage;
    goto shared_guard;

byte5:
    base[5] = (uint8_t)(cursor + 0x65);
    cursor += 13;
    stage = 5;
    goto cont5;
cont5:
    marker = cursor + stage;
    goto shared_guard;

byte6:
    base[6] = (uint8_t)(cursor + 0x76);
    stage = 6;
    goto cont6;
cont6:
    marker = cursor + stage;
    goto shared_guard;
}
