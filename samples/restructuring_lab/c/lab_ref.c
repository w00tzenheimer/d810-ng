/*
 * Restructuring-lab ORACLE siblings: the non-flattened originals.
 *
 * Each lab_ref_X is the SAME computation as the flattened lab_flat_X, written
 * directly (no state machine). Decompiling lab_ref_X at BASELINE (no d810) is the
 * EXPECTED pseudocode -- the oracle a lowering primitive applied to lab_flat_X
 * must reproduce. This is the compiled-source oracle (project oracle-equivalence
 * gate): the lowered render must be semantically/structurally equal to the
 * sibling's baseline decompile.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

/* oracle for lab_flat_mini: a linear 3-handler chain. */
EXPORT D810_NOINLINE int lab_ref_mini(int token)
{
    int r = token;
    r += 0x11; g_hexrays_lab_sink = r;
    r ^= 0x22; g_hexrays_lab_sink = r;
    r -= 0x33; g_hexrays_lab_sink = r;
    return r;
}

/* oracle for lab_flat_loop: a counter do/while. */
EXPORT D810_NOINLINE int lab_ref_loop(int token)
{
    int r = token;
    int counter = 3;
    r += 0x11;
    do {
        r ^= 0x22; g_hexrays_lab_sink = r; counter -= 1;
    } while (counter != 0);
    r -= 0x33; g_hexrays_lab_sink = r;
    return r;
}

/* oracle for lab_flat_cond AND lab_flat_branchless: an if/else (same semantics). */
EXPORT D810_NOINLINE int lab_ref_cond(int token)
{
    int r = token;
    r += 0x11; g_hexrays_lab_sink = r;
    if (token & 1) { r ^= 0x22; g_hexrays_lab_sink = r; }
    else           { r -= 0x33; g_hexrays_lab_sink = r; }
    return r;
}

/* oracle for lab_flat_jtbl: a linear 5-handler chain. */
EXPORT D810_NOINLINE int lab_ref_jtbl(int token)
{
    int r = token;
    r += 0x11; g_hexrays_lab_sink = r;
    r ^= 0x22; g_hexrays_lab_sink = r;
    r -= 0x33; g_hexrays_lab_sink = r;
    r += 0x44; g_hexrays_lab_sink = r;
    r ^= 0x55; g_hexrays_lab_sink = r;
    return r;
}

/* oracle for lab_flat_region (join form): entry branch -> shared head -> tail. */
EXPORT D810_NOINLINE int lab_ref_region(int token)
{
    int r = token + 0x07;
    if (token & 1) { r += 0x11; g_hexrays_lab_sink = r; }
    else           { r ^= 0x55; g_hexrays_lab_sink = r; }
    r -= 0x22; g_hexrays_lab_sink = r;
    if (token & 2) { r ^= 0x33; g_hexrays_lab_sink = r; }
    return r;
}
