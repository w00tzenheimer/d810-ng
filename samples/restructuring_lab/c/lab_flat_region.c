/*
 * Restructuring-lab L7: a flattened host whose shared continuation is a 2-BLOCK
 * REGION with an internal branch (not a single shared block like P3).
 *
 * A single ENTRY handler conditionally routes to path A or B (two clean
 * immediate state writes -- no reg-resident entry selector, so L7 isolates the
 * multi-block region and does NOT drag in L2). Both A and B transition to the
 * SAME region head; the region head has an INTERNAL branch to a region tail (so
 * the region is irreducibly 2 blocks -- a straight sequence would merge in the
 * render). Reconstruction must preserve the region's internal structure.
 *
 * True CFG:
 *     entry: r+=7; if (token&1) -> A else -> B
 *     A: r+=0x11 ┐
 *     B: r^=0x55 ┴→ RH: r-=0x22; if (token&2) -> RT: r^=0x33 -> exit
 *                                else -> exit
 *     exit: return r
 *
 * Shared region = { RH (0x3C8960A9), RT (0x7D4E1F3A) }, reached from A and B.
 * Large 32-bit states clear the MIN_STATE_CONSTANT floor.
 */
#include "platform.h"
#include <stdint.h>

extern volatile int g_hexrays_lab_sink;   /* defined in badwhile_triangles_asm.c */

EXPORT D810_NOINLINE int lab_flat_region(int token)
{
    unsigned int state = 0xDEADBEEFu;            /* single entry handler */
    int r = token;
    for (;;) {
        switch (state) {
        case 0xDEADBEEFu:  /* ENTRY: route to A or B (clean immediate writes) */
            r += 0x07;
            if (token & 1) state = 0xC6685257u;   /* -> A */
            else           state = 0xB92456DEu;   /* -> B */
            break;
        case 0xC6685257u:  /* A (path 1) */
            r += 0x11; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break;  /* -> region head */
        case 0xB92456DEu:  /* B (path 2) */
            r ^= 0x55; g_hexrays_lab_sink = r; state = 0x3C8960A9u; break;  /* -> region head (SHARED) */
        case 0x3C8960A9u:  /* region HEAD (shared, 2 preds) */
            r -= 0x22; g_hexrays_lab_sink = r;
            if (token & 2) state = 0x7D4E1F3Au;   /* -> region TAIL */
            else           state = 0x1A2B3C4Du;   /* -> exit */
            break;
        case 0x7D4E1F3Au:  /* region TAIL */
            r ^= 0x33; g_hexrays_lab_sink = r; state = 0x1A2B3C4Du; break;  /* -> exit */
        default:           /* KT terminal */
            return r;
        }
    }
}
